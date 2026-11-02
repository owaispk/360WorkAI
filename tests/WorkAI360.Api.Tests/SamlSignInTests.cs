using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Web;
using WorkAI360.Api.Domain.Saml;
using WorkAI360.Api.Domain.Sso;
using WorkAI360.Api.Features.Sso;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>An API where the identity provider may not send responses unasked.</summary>
public sealed class SamlStrictFactory : SsoFactory
{
    protected override IEnumerable<KeyValuePair<string, string>> Settings => [.. base.Settings, new("Sso:SamlAllowIdpInitiated", "false")];
}

/// <summary>One workspace wired to a test SAML identity provider, built through the public API.</summary>
public sealed class SamlWorld(SsoFactory factory, SamlTestIdp idp)
{
    public HttpClient Http { get; } = factory.Plain();
    public string Domain { get; } = $"corp-{Guid.NewGuid():N}"[..14] + ".test";
    public string OrgId { get; private set; } = "";
    public string OwnerToken { get; private set; } = "";
    public string OwnerEmail { get; private set; } = "";
    public SamlTestIdp Idp => idp;
    public string ProviderId => $"openwork-sso-{OrgId}";
    public string AcsPath => $"/api/auth/sso/saml2/sp/acs/{ProviderId}";
    public string Acs => "http://localhost" + AcsPath;
    public string Sp => "http://localhost";

    public sealed record Started(string Url, string RequestId, string RelayState, string Xml);

    public static async Task<SamlWorld> CreateAsync(SsoFactory factory, SamlTestIdp idp)
    {
        var w = new SamlWorld(factory, idp);
        w.OwnerEmail = $"owner@{w.Domain}";
        var signUp = await w.Http.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "Owner Person", email = w.OwnerEmail, password = Password });
        signUp.EnsureSuccessStatusCode();
        w.OwnerToken = (await ReadJsonAsync(signUp)).GetProperty("token").GetString()!;
        var created = await w.Http.SendAsync(Bearer(HttpMethod.Post, "/v1/org", w.OwnerToken, new { name = "Saml Space" }));
        w.OrgId = (await ReadJsonAsync(created)).GetProperty("organization").GetProperty("id").GetString()!;
        return w;
    }

    public HttpRequestMessage As(string token, HttpMethod method, string url, object? body = null)
    {
        var r = Bearer(method, url, token, body);
        r.Headers.Add("x-openwork-org-id", OrgId);
        return r;
    }

    public Task<(HttpStatusCode Status, JsonElement Body)> Owner(HttpMethod method, string url, object? body = null) => Send(OwnerToken, method, url, body);

    public async Task<(HttpStatusCode Status, JsonElement Body)> Send(string token, HttpMethod method, string url, object? body = null)
    {
        var r = await Http.SendAsync(As(token, method, url, body));
        var text = await r.Content.ReadAsStringAsync();
        if (text.Length > 0 && text[0] is not ('{' or '[')) throw new InvalidOperationException($"{(int)r.StatusCode} {method} {url}: {text[..Math.Min(text.Length, 400)]}");
        return (r.StatusCode, string.IsNullOrEmpty(text) ? default : JsonDocument.Parse(text).RootElement.Clone());
    }

    public Task<(HttpStatusCode Status, JsonElement Body)> RegisterAsync(object? extra = null, string? domain = null, string? cert = null)
    {
        var body = new Dictionary<string, object?> { ["issuer"] = idp.EntityId, ["domain"] = domain ?? Domain, ["entryPoint"] = idp.SsoUrl, ["cert"] = cert ?? idp.CertificatePem };
        if (extra is not null) foreach (var p in extra.GetType().GetProperties()) body[p.Name] = p.GetValue(extra);
        return Owner(HttpMethod.Post, "/v1/sso/saml", body);
    }

    public async Task VerifyDomainAsync(FakeDns dns)
    {
        var token = await Owner(HttpMethod.Post, "/v1/sso/request-domain-verification", new { });
        Assert.Equal(HttpStatusCode.Created, token.Status);
        dns.Publish($"_better-auth-token-{ProviderId}.{Domain}", $"_better-auth-token-{ProviderId}={token.Body.GetProperty("domainVerificationToken").GetString()}");
        Assert.Equal(HttpStatusCode.NoContent, (await Owner(HttpMethod.Post, "/v1/sso/verify-domain", new { })).Status);
    }

    public static string PathAndQuery(string url) => new Uri(url).PathAndQuery;

    /// <summary>Starts a sign-in and plays the browser's first step: reads the AuthnRequest out of the identity provider URL.</summary>
    public async Task<Started> StartAsync(HttpClient browser, object? body = null)
    {
        var r = await browser.PostAsJsonAsync("/api/auth/sign-in/sso", body ?? new { organizationSlug = OrgId, callbackURL = "/dashboard" });
        var json = await ReadJsonAsync(r);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        return Parse(json.GetProperty("url").GetString()!);
    }

    /// <summary>The browser's first step whichever binding is used: the redirect URL carries the request, the POST binding serves a page that does.</summary>
    public async Task<Started> ResolveAsync(HttpClient browser, string url)
    {
        if (!url.Contains("/sp/login/")) return Parse(url);
        var html = await (await browser.GetAsync(PathAndQuery(url))).Content.ReadAsStringAsync();
        var encoded = System.Text.RegularExpressions.Regex.Match(html, "name=\"SAMLRequest\" value=\"([^\"]+)\"").Groups[1].Value;
        var xml = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
        return new Started(url, System.Xml.Linq.XDocument.Parse(xml).Root!.Attribute("ID")!.Value, HttpUtility.ParseQueryString(new Uri(url).Query)["relay"]!, xml);
    }

    public static Started Parse(string url)
    {
        var query = HttpUtility.ParseQueryString(new Uri(url).Query);
        var xml = SamlProtocol.InflateRequest(query["SAMLRequest"]!);
        var doc = new System.Xml.XmlDocument();
        doc.LoadXml(xml);
        return new Started(url, doc.DocumentElement!.GetAttribute("ID"), query["RelayState"]!, xml);
    }

    public Task<HttpResponseMessage> PostAcsAsync(HttpClient client, string samlResponse, string? relay) =>
        client.PostAsync(AcsPath, new FormUrlEncodedContent(new Dictionary<string, string> { ["SAMLResponse"] = samlResponse }.Concat(relay is null ? [] : [new KeyValuePair<string, string>("RelayState", relay)])));

    public string Response(Started started, SamlOptions? options = null) => idp.Build(Acs, Sp, (options ?? new SamlOptions()) with { InResponseTo = started.RequestId });

    /// <summary>The whole sign-in as the browser sees it: start, the provider's answer posted to the ACS, then the same-site continue. Returns the ACS answer and the final one.</summary>
    public async Task<(HttpResponseMessage Acs, HttpResponseMessage? Final)> SignInAsync(HttpClient browser, SamlOptions options, object? body = null)
    {
        var started = await StartAsync(browser, body);
        var acs = await PostAcsAsync(browser, Response(started, options), started.RelayState);
        if (acs.StatusCode != HttpStatusCode.SeeOther) return (acs, null);
        return (acs, await browser.GetAsync(PathAndQuery(acs.Headers.Location!.ToString())));
    }

    public async Task<(string Intent, HttpResponseMessage? Final)> RunTestAsync(HttpClient browser, SamlOptions options, string? token = null)
    {
        token ??= OwnerToken;
        var made = await Send(token, HttpMethod.Post, "/v1/sso/test", new { });
        Assert.Equal(HttpStatusCode.Created, made.Status);
        var intent = made.Body.GetProperty("intentId").GetString()!;
        var start = await browser.SendAsync(As(token, HttpMethod.Post, $"/v1/sso/test/{intent}/start", new { }));
        Assert.Equal(HttpStatusCode.OK, start.StatusCode);
        var started = await ResolveAsync(browser, (await ReadJsonAsync(start)).GetProperty("url").GetString()!);
        var acs = await PostAcsAsync(browser, Response(started, options), started.RelayState);
        return (intent, acs.StatusCode == HttpStatusCode.SeeOther ? await browser.GetAsync(PathAndQuery(acs.Headers.Location!.ToString())) : acs);
    }

    public async Task VerifiedTestedAndEnabledAsync(SsoFactory f, FakeDns dns)
    {
        Assert.Equal(HttpStatusCode.Created, (await RegisterAsync()).Status);
        await VerifyDomainAsync(dns);
        await RunTestAsync(f.Browser(), new SamlOptions { NameId = OwnerEmail, Email = OwnerEmail });
        Assert.Equal(HttpStatusCode.NoContent, (await Owner(HttpMethod.Post, "/v1/sso/enable", new { })).Status);
    }

    public T Db<T>(Func<WorkAI360.Api.Data.DenDbContext, T> read) => factory.WithDb(read);
    public int UsersWithEmail(string email) => Db(db => db.Users.Count(u => u.Email == email));

    public static string Query(HttpResponseMessage r, string name) => HttpUtility.ParseQueryString(r.Headers.Location!.Query)[name] ?? "";
}

public abstract class SamlBase : IAsyncLifetime
{
    protected abstract SsoFactory Factory { get; }
    protected SamlTestIdp Idp = null!;
    protected SamlWorld W = null!;

    public virtual async Task InitializeAsync()
    {
        Idp = new SamlTestIdp();
        W = await SamlWorld.CreateAsync(Factory, Idp);
    }

    public Task DisposeAsync()
    {
        Idp.Dispose();
        return Task.CompletedTask;
    }

    protected string Person(string local = "new.person") => $"{local}@{W.Domain}";
    protected SamlOptions For(string email, string? subject = null, string name = "Some One") => new() { NameId = subject ?? email, Email = email, DisplayName = name };
    protected static async Task<int> MeStatus(HttpClient browser) => (int)(await browser.GetAsync("/v1/me")).StatusCode;
    protected static async Task<string> MeEmail(HttpClient browser) => (await ReadJsonAsync(await browser.GetAsync("/v1/me"))).GetProperty("user").GetProperty("email").GetString()!;
}

/// <summary>Saving, reading and publishing a SAML connection.</summary>
public sealed class SamlConnectionTests(SsoFactory factory) : SamlBase, IClassFixture<SsoFactory>
{
    protected override SsoFactory Factory => factory;

    [Fact]
    public async Task Saving_answers_in_the_references_shape()
    {
        var r = await W.RegisterAsync();
        Assert.Equal(HttpStatusCode.Created, r.Status);
        var c = r.Body.GetProperty("connection");
        Assert.Equal("saml", c.GetProperty("kind").GetString());
        Assert.Equal(Idp.EntityId, c.GetProperty("issuer").GetString());
        Assert.Equal("disabled", c.GetProperty("status").GetString());
        Assert.Equal("untested", c.GetProperty("testStatus").GetString());
        Assert.False(c.GetProperty("domainVerified").GetBoolean());
        Assert.Equal(JsonValueKind.Null, c.GetProperty("oidc").ValueKind);
        var saml = c.GetProperty("saml");
        Assert.Equal(Idp.SsoUrl, saml.GetProperty("entryPoint").GetString());
        Assert.Equal("http://localhost", saml.GetProperty("audience").GetString());
        Assert.True(saml.GetProperty("wantAssertionsSigned").GetBoolean());
        Assert.Equal("redirect", saml.GetProperty("binding").GetString());
        Assert.Equal(W.Acs, c.GetProperty("acsUrl").GetString());
        Assert.Equal($"http://localhost/api/auth/sso/saml2/sp/metadata?providerId={W.ProviderId}", c.GetProperty("metadataUrl").GetString());
        Assert.EndsWith($"/api/auth/sso/callback/{W.ProviderId}", c.GetProperty("redirectUrl").GetString());
        Assert.Equal(JsonValueKind.String, r.Body.GetProperty("domainVerificationToken").ValueKind);
        // The certificate is public, yet the read model does not repeat it.
        Assert.DoesNotContain("BEGIN CERTIFICATE", r.Body.ToString());
        Assert.Equal(c.GetProperty("id").GetString(), (await W.Owner(HttpMethod.Get, "/v1/sso")).Body.GetProperty("connection").GetProperty("id").GetString());
    }

    [Fact]
    public async Task An_audience_can_be_chosen_and_becomes_the_service_provider_entity_id()
    {
        var r = await W.RegisterAsync(new { audience = "https://sp.example.test/entity" });
        Assert.Equal("https://sp.example.test/entity", r.Body.GetProperty("connection").GetProperty("saml").GetProperty("audience").GetString());
        Assert.Contains("entityID=\"https://sp.example.test/entity\"", await (await W.Http.GetAsync($"/api/auth/sso/saml2/sp/metadata?providerId={W.ProviderId}")).Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Saving_validates_the_body_in_the_references_words()
    {
        var empty = await W.Owner(HttpMethod.Post, "/v1/sso/saml", new { });
        Assert.Equal(HttpStatusCode.BadRequest, empty.Status);
        Assert.Equal("invalid_request", empty.Body.GetProperty("error").GetString());
        Assert.Equal(["issuer", "domain", "entryPoint", "cert"], empty.Body.GetProperty("details").EnumerateArray().Select(d => d.GetProperty("path")[0].GetString()!));
        var bad = await W.Owner(HttpMethod.Post, "/v1/sso/saml", new { issuer = "x", domain = "", entryPoint = "nope", cert = "", audience = "no", binding = "carrier-pigeon" });
        Assert.Equal(HttpStatusCode.BadRequest, bad.Status);
        var messages = bad.Body.GetProperty("details").EnumerateArray().Select(d => d.GetProperty("message").GetString()!).ToArray();
        Assert.Equal("Invalid URL", messages[0]);
        Assert.Contains("Too small", messages[1]);
        Assert.Contains("Invalid option", messages[^1]);
    }

    [Fact]
    public async Task A_certificate_that_is_not_one_is_refused_and_the_sign_in_url_must_be_a_web_address()
    {
        var cert = await W.RegisterAsync(cert: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----");
        Assert.Equal(HttpStatusCode.BadRequest, cert.Status);
        Assert.Contains("not a valid X.509 certificate", cert.Body.GetProperty("details")[0].GetProperty("message").GetString());
        var script = await W.RegisterAsync(new { entryPoint = "javascript:alert(1)" });
        Assert.Equal(HttpStatusCode.BadRequest, script.Status);
        var userinfo = await W.RegisterAsync(new { entryPoint = "https://user:pw@idp.example.test/sso" });
        Assert.Equal(HttpStatusCode.BadRequest, userinfo.Status);
    }

    [Fact]
    public async Task A_bare_base64_certificate_is_accepted()
    {
        var r = await W.RegisterAsync(cert: Convert.ToBase64String(Idp.Certificate.RawData));
        Assert.Equal(HttpStatusCode.Created, r.Status);
        var stored = W.Db(db => db.Set<SsoConnection>().Single(c => c.OrganizationId == W.OrgId));
        Assert.Equal([Convert.ToBase64String(Idp.Certificate.RawData)], SsoService.SamlSettingsOf(stored)!.Certificates);
    }

    [Fact]
    public async Task Only_people_with_the_permission_can_save_or_read_it()
    {
        var (email, token, _) = await Factory.SignUpAsync(W.Http, "Plain Member");
        var invite = await W.Owner(HttpMethod.Post, "/v1/invitations", new { email, role = "member" });
        await W.Http.SendAsync(Bearer(HttpMethod.Post, "/v1/orgs/invitations/accept", token, new { id = invite.Body.GetProperty("invitationId").GetString() }));
        var write = await W.Send(token, HttpMethod.Post, "/v1/sso/saml", new { });
        Assert.Equal(HttpStatusCode.Forbidden, write.Status);
        Assert.Equal("sso.manage", write.Body.GetProperty("requiredPermission").GetString());
        var meta = await W.Send(token, HttpMethod.Get, "/v1/sso/metadata");
        Assert.Equal("sso.view", meta.Body.GetProperty("requiredPermission").GetString());
        Assert.Equal(HttpStatusCode.Unauthorized, (await W.Http.PostAsJsonAsync("/v1/sso/saml", new { })).StatusCode);
    }

    [Fact]
    public async Task Saving_again_replaces_everything_and_may_change_the_kind()
    {
        await W.RegisterAsync();
        var oidc = await W.Owner(HttpMethod.Post, "/v1/sso/oidc", new { issuer = "http://127.0.0.1:1", domain = W.Domain, clientId = "c", clientSecret = "s", skipDiscovery = true, authorizationEndpoint = "http://127.0.0.1:1/a", tokenEndpoint = "http://127.0.0.1:1/t", jwksEndpoint = "http://127.0.0.1:1/j" });
        Assert.Equal(HttpStatusCode.Created, oidc.Status);
        Assert.Equal("oidc", oidc.Body.GetProperty("connection").GetProperty("kind").GetString());
        Assert.Equal(JsonValueKind.Null, oidc.Body.GetProperty("connection").GetProperty("saml").ValueKind);
        Assert.Equal(JsonValueKind.Null, oidc.Body.GetProperty("connection").GetProperty("acsUrl").ValueKind);
        var back = await W.RegisterAsync();
        Assert.Equal("saml", back.Body.GetProperty("connection").GetProperty("kind").GetString());
        var stored = W.Db(db => db.Set<SsoConnection>().Single(c => c.OrganizationId == W.OrgId));
        Assert.Null(stored.OidcConfigJson);
        Assert.Null(stored.ClientSecretProtected);
        Assert.Equal(1, W.Db(db => db.Set<SsoConnection>().Count(c => c.OrganizationId == W.OrgId)));
    }

    [Fact]
    public async Task Saving_two_at_once_leaves_one_connection_and_never_a_server_error()
    {
        var results = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => W.RegisterAsync()));
        Assert.All(results, r => Assert.Equal(HttpStatusCode.Created, r.Status));
        Assert.Equal(1, W.Db(db => db.Set<SsoConnection>().Count(c => c.OrganizationId == W.OrgId)));
    }

    [Fact]
    public async Task The_service_provider_metadata_names_the_entity_and_the_acs_address()
    {
        Assert.Equal(HttpStatusCode.NotFound, (await W.Owner(HttpMethod.Get, "/v1/sso/metadata")).Status);
        await W.RegisterAsync();
        var response = await W.Http.SendAsync(W.As(W.OwnerToken, HttpMethod.Get, "/v1/sso/metadata"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.StartsWith("application/xml", response.Content.Headers.ContentType!.ToString());
        var xml = await response.Content.ReadAsStringAsync();
        var doc = new System.Xml.XmlDocument();
        doc.LoadXml(xml);
        Assert.Equal("http://localhost", doc.DocumentElement!.GetAttribute("entityID"));
        Assert.Contains("WantAssertionsSigned=\"true\"", xml);
        Assert.Contains("AuthnRequestsSigned=\"false\"", xml);
        Assert.Contains($"Location=\"{W.Acs}\"", xml);
        Assert.Contains("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", xml);
        // The reference validates `format` and answers the XML either way.
        Assert.Equal(xml, await (await W.Http.SendAsync(W.As(W.OwnerToken, HttpMethod.Get, "/v1/sso/metadata?format=json"))).Content.ReadAsStringAsync());
        var bad = await W.Owner(HttpMethod.Get, "/v1/sso/metadata?format=yaml");
        Assert.Equal(HttpStatusCode.BadRequest, bad.Status);
        Assert.Equal("format", bad.Body.GetProperty("details")[0].GetProperty("path")[0].GetString());
    }

    [Fact]
    public async Task A_connection_that_is_not_saml_has_no_metadata()
    {
        await W.Owner(HttpMethod.Post, "/v1/sso/oidc", new { issuer = "http://127.0.0.1:1", domain = W.Domain, clientId = "c", clientSecret = "s", skipDiscovery = true, authorizationEndpoint = "http://127.0.0.1:1/a", tokenEndpoint = "http://127.0.0.1:1/t", jwksEndpoint = "http://127.0.0.1:1/j" });
        Assert.Equal(HttpStatusCode.NotFound, (await W.Owner(HttpMethod.Get, "/v1/sso/metadata")).Status);
        var publicMeta = await W.Http.GetAsync($"/api/auth/sso/saml2/sp/metadata?providerId={W.ProviderId}");
        Assert.Equal(HttpStatusCode.BadRequest, publicMeta.StatusCode);
    }

    [Fact]
    public async Task The_public_metadata_route_needs_no_sign_in_and_knows_its_errors()
    {
        await W.RegisterAsync();
        var ok = await W.Http.GetAsync($"/api/auth/sso/saml2/sp/metadata?providerId={W.ProviderId}");
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await W.Http.GetAsync("/api/auth/sso/saml2/sp/metadata?providerId=nope")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await W.Http.GetAsync("/api/auth/sso/saml2/sp/metadata")).StatusCode);
    }

    [Fact]
    public async Task Deleting_the_connection_removes_what_was_in_flight()
    {
        await W.RegisterAsync();
        await W.VerifyDomainAsync(Factory.Dns);
        await W.RunTestAsync(Factory.Browser(), For(W.OwnerEmail));
        await W.Owner(HttpMethod.Post, "/v1/sso/enable", new { });
        await W.StartAsync(Factory.Browser());
        Assert.Equal(2, W.Db(db => db.Set<SamlAuthRequest>().Count(r => r.ProviderId == W.ProviderId)));
        Assert.Equal(HttpStatusCode.NoContent, (await W.Owner(HttpMethod.Delete, "/v1/sso")).Status);
        Assert.Equal(0, W.Db(db => db.Set<SamlAuthRequest>().Count(r => r.ProviderId == W.ProviderId)));
    }
}

/// <summary>Signing in through a workspace's SAML SSO, start to finish.</summary>
public sealed class SamlSignInTests(SsoFactory factory) : SamlBase, IClassFixture<SsoFactory>
{
    protected override SsoFactory Factory => factory;

    public override async Task InitializeAsync()
    {
        await base.InitializeAsync();
        await W.VerifiedTestedAndEnabledAsync(factory, factory.Dns);
    }

    [Fact]
    public async Task Starting_sends_a_real_authn_request_to_the_identity_provider()
    {
        var browser = Factory.Browser();
        var r = await browser.PostAsJsonAsync("/api/auth/sign-in/sso", new { organizationSlug = W.OrgId, callbackURL = "/dashboard" });
        var json = await ReadJsonAsync(r);
        Assert.True(json.GetProperty("redirect").GetBoolean());
        var started = SamlWorld.Parse(json.GetProperty("url").GetString()!);
        Assert.StartsWith(Idp.SsoUrl + "?", started.Url);
        Assert.Matches("^_[0-9a-f]{32}$", started.RequestId);
        Assert.Contains("Version=\"2.0\"", started.Xml);
        Assert.Contains($"AssertionConsumerServiceURL=\"{W.Acs}\"", started.Xml);
        Assert.Contains($"Destination=\"{Idp.SsoUrl}\"", started.Xml);
        Assert.Contains("<saml:Issuer>http://localhost</saml:Issuer>", started.Xml);
        Assert.Contains("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", started.Xml);
        Assert.True(started.RelayState.Length >= 32);
        Assert.Contains(r.Headers.GetValues("Set-Cookie"), c => c.StartsWith("openwork-den.saml_state=") && c.Contains("httponly", StringComparison.OrdinalIgnoreCase) && c.Contains("samesite=lax", StringComparison.OrdinalIgnoreCase));
        // Only hashes are stored: neither the request id nor the relay state.
        var row = W.Db(db => db.Set<SamlAuthRequest>().Single(x => x.ProviderId == W.ProviderId && x.TestIntentId == null));
        Assert.DoesNotContain(started.RequestId, row.Id);
        Assert.DoesNotContain(started.RelayState, row.RelayStateHash);
        Assert.Null(row.RequestXml);
    }

    [Fact]
    public async Task A_new_person_signs_in_and_joins_as_a_member()
    {
        var email = Person();
        var browser = Factory.Browser();
        var (acs, final) = await W.SignInAsync(browser, For(email, "name-id-1", "Newly Hired"));
        Assert.Equal(HttpStatusCode.SeeOther, acs.StatusCode);
        Assert.Equal(HttpStatusCode.Redirect, final!.StatusCode);
        Assert.Equal("http://localhost/dashboard", final.Headers.Location!.ToString());
        Assert.Equal(200, await MeStatus(browser));
        Assert.Equal(email, await MeEmail(browser));

        var user = W.Db(db => db.Users.Single(u => u.Email == email));
        Assert.True(user.EmailVerified);
        Assert.Equal("Newly Hired", user.Name);
        Assert.Equal(SsoProvisioning.UnusablePassword, user.PasswordHash);
        Assert.Equal("member", W.Db(db => db.Members.Single(m => m.UserId == user.Id && m.OrganizationId == W.OrgId).Role));
        var identity = W.Db(db => db.Set<ExternalIdentity>().Single(i => i.UserId == user.Id));
        Assert.Equal("sso", identity.Source);
        Assert.Equal("name-id-1", identity.RemoteId);
        Assert.Equal("sso", W.Db(db => db.Sessions.Single(s => s.UserId == user.Id).Method));
        // The request is spent.
        Assert.NotNull(W.Db(db => db.Set<SamlAuthRequest>().Single(r => r.ProviderId == W.ProviderId && r.TestIntentId == null)).ConsumedAt);
    }

    [Fact]
    public async Task Nobody_is_signed_in_by_the_acs_post_alone()
    {
        var browser = Factory.Browser();
        var started = await W.StartAsync(browser);
        var acs = await W.PostAcsAsync(browser, W.Response(started, For(Person("early"))), started.RelayState);
        Assert.Equal(HttpStatusCode.SeeOther, acs.StatusCode);
        Assert.StartsWith($"http://localhost/api/auth/sso/saml2/sp/continue/{W.ProviderId}?id=", acs.Headers.Location!.ToString());
        Assert.DoesNotContain(acs.Headers, h => h.Key == "Set-Cookie" && h.Value.Any(v => v.Contains("session_token")));
        Assert.Equal(401, await MeStatus(browser));
        Assert.Equal(0, W.UsersWithEmail(Person("early")));
    }

    [Fact]
    public async Task A_returning_person_is_recognised_by_the_name_id_not_by_email()
    {
        var first = Factory.Browser();
        await W.SignInAsync(first, For(Person("first"), "stable-subject"));
        var userId = W.Db(db => db.Users.Single(u => u.Email == Person("first")).Id);
        var again = Factory.Browser();
        var (_, final) = await W.SignInAsync(again, For(Person("renamed"), "stable-subject"));
        Assert.Equal(HttpStatusCode.Redirect, final!.StatusCode);
        Assert.Equal(Person("first"), await MeEmail(again));
        Assert.Equal(0, W.UsersWithEmail(Person("renamed")));
        Assert.Equal(1, W.Db(db => db.Set<ExternalAccount>().Count(a => a.UserId == userId)));
    }

    [Fact]
    public async Task A_transient_name_id_is_matched_by_the_address()
    {
        var email = Person("transient");
        var one = Factory.Browser();
        await W.SignInAsync(one, new SamlOptions { NameId = "_t1", NameIdFormat = SamlValidator.TransientNameId, Email = email });
        var two = Factory.Browser();
        await W.SignInAsync(two, new SamlOptions { NameId = "_t2", NameIdFormat = SamlValidator.TransientNameId, Email = email });
        Assert.Equal(1, W.UsersWithEmail(email));
        Assert.Equal(email, await MeEmail(two));
    }

    [Fact]
    public async Task An_invited_person_joins_with_the_invitations_role()
    {
        var email = Person("invited");
        Assert.Equal(HttpStatusCode.Created, (await W.Owner(HttpMethod.Post, "/v1/invitations", new { email, role = "admin" })).Status);
        await W.SignInAsync(Factory.Browser(), For(email));
        var userId = W.Db(db => db.Users.Single(u => u.Email == email).Id);
        Assert.Equal("admin", W.Db(db => db.Members.Single(m => m.UserId == userId && m.OrganizationId == W.OrgId).Role));
    }

    [Fact]
    public async Task An_account_nobody_verified_is_taken_over_by_the_verified_domain_identity()
    {
        var email = Person("alice");
        var squatter = await W.Http.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "Squatter", email, password = Password });
        var oldToken = (await ReadJsonAsync(squatter)).GetProperty("token").GetString()!;
        var browser = Factory.Browser();
        await W.SignInAsync(browser, For(email, "sub-alice", "Alice"));
        Assert.Equal(1, W.UsersWithEmail(email));
        Assert.Equal(HttpStatusCode.Unauthorized, (await W.Http.SendAsync(Bearer(HttpMethod.Get, "/v1/me", oldToken))).StatusCode);
        Assert.Equal(email, await MeEmail(browser));
    }

    [Fact]
    public async Task An_address_outside_the_verified_domain_signs_nobody_in()
    {
        var browser = Factory.Browser();
        var (acs, final) = await W.SignInAsync(browser, For("someone@elsewhere.test"));
        Assert.Equal(HttpStatusCode.Redirect, final!.StatusCode);
        Assert.Equal("email_outside_sso_domain", SamlWorld.Query(final, "error"));
        Assert.Equal("/dashboard", final.Headers.Location!.AbsolutePath);
        Assert.Equal(401, await MeStatus(browser));
        Assert.Equal(0, W.UsersWithEmail("someone@elsewhere.test"));
        Assert.Equal(HttpStatusCode.SeeOther, acs.StatusCode);
    }

    [Fact]
    public async Task A_look_alike_domain_is_not_the_verified_one()
    {
        var (_, final) = await W.SignInAsync(Factory.Browser(), For($"x@{W.Domain}.evil.test"));
        Assert.Equal("email_outside_sso_domain", SamlWorld.Query(final!, "error"));
        Assert.Equal(0, W.UsersWithEmail($"x@{W.Domain}.evil.test"));
    }

    [Fact]
    public async Task A_response_with_no_usable_email_signs_nobody_in()
    {
        var browser = Factory.Browser();
        var started = await W.StartAsync(browser);
        var acs = await W.PostAcsAsync(browser, W.Response(started, new SamlOptions { NameId = "opaque-id", NameIdFormat = null, Email = null }), started.RelayState);
        Assert.Equal(HttpStatusCode.Redirect, acs.StatusCode);
        Assert.Equal("invalid_saml_response", SamlWorld.Query(acs, "error"));
        Assert.Contains("Unable to extract", SamlWorld.Query(acs, "error_description"));
    }

    // ---------------------------------------------------------------- what the ACS refuses

    [Fact]
    public async Task A_replayed_response_is_refused_and_signs_nobody_in()
    {
        var first = Factory.Browser();
        var started = await W.StartAsync(first);
        var response = W.Response(started, For(Person("replay")));
        Assert.Equal(HttpStatusCode.SeeOther, (await W.PostAcsAsync(first, response, started.RelayState)).StatusCode);
        // The attacker posts the captured response again, from anywhere.
        var attacker = Factory.Browser();
        var again = await W.PostAcsAsync(attacker, response, started.RelayState);
        Assert.Equal(HttpStatusCode.Redirect, again.StatusCode);
        Assert.Equal("invalid_state", SamlWorld.Query(again, "error"));
        Assert.Equal(401, await MeStatus(attacker));
        // Even with a fresh request of the attacker's own the old assertion answers the old request only.
        var second = await W.StartAsync(attacker);
        var forged = await W.PostAcsAsync(attacker, response, second.RelayState);
        Assert.Equal(HttpStatusCode.Redirect, forged.StatusCode);
        Assert.Equal(401, await MeStatus(attacker));
    }

    [Fact]
    public async Task The_assertion_id_is_remembered_even_for_unsolicited_responses()
    {
        var response = Idp.Build(W.Acs, W.Sp, new SamlOptions { OmitInResponseTo = true, NameId = Person("idp1"), Email = Person("idp1") });
        var one = Factory.Browser();
        var first = await W.PostAcsAsync(one, response, null);
        Assert.Equal(HttpStatusCode.Redirect, first.StatusCode);
        Assert.Equal("http://localhost/dashboard", first.Headers.Location!.ToString());
        Assert.Equal(200, await MeStatus(one));
        var other = Factory.Browser();
        var again = await W.PostAcsAsync(other, response, null);
        Assert.Equal("replay_detected", SamlWorld.Query(again, "error"));
        Assert.Contains("already been used", SamlWorld.Query(again, "error_description"));
        Assert.Equal(401, await MeStatus(other));
    }

    [Fact]
    public async Task The_replay_cache_keeps_the_id_until_the_assertion_would_have_expired()
    {
        var assertionId = "_fixed-" + Guid.NewGuid().ToString("N");
        var response = Idp.Build(W.Acs, W.Sp, new SamlOptions { OmitInResponseTo = true, NameId = Person("idp2"), Email = Person("idp2"), AssertionId = assertionId });
        await W.PostAcsAsync(Factory.Browser(), response, null);
        var key = WorkAI360.Api.Features.Replay.ReplayGuard.KeyFor("saml-assertion", $"{W.ProviderId}\n{Idp.EntityId}\n{assertionId}");
        var mine = W.Db(db => db.Set<WorkAI360.Api.Domain.Replay.ReplayReservation>().Single(r => r.Id == key));
        Assert.True(mine.ExpiresAt > DateTime.UtcNow.AddMinutes(4));
        Assert.Matches("^[0-9a-f]{64}$", mine.Id);
    }

    [Fact]
    public async Task The_same_response_posted_at_once_is_accepted_exactly_once()
    {
        var response = Idp.Build(W.Acs, W.Sp, new SamlOptions { OmitInResponseTo = true, NameId = Person("race"), Email = Person("race") });
        var results = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => W.PostAcsAsync(Factory.Browser(), response, null)));
        Assert.All(results, r => Assert.Equal(HttpStatusCode.Redirect, r.StatusCode));
        var winners = results.Where(r => r.Headers.Location!.AbsolutePath == "/dashboard" && string.IsNullOrEmpty(r.Headers.Location.Query)).ToList();
        Assert.Single(winners);
        Assert.Equal(5, results.Count(r => SamlWorld.Query(r, "error") == "replay_detected"));
        Assert.Equal(1, W.UsersWithEmail(Person("race")));
    }

    [Fact]
    public async Task A_response_that_answers_an_unknown_request_is_refused()
    {
        var browser = Factory.Browser();
        var started = await W.StartAsync(browser);
        var acs = await W.PostAcsAsync(browser, W.Response(started with { RequestId = "_never-sent" }, For(Person("x"))), started.RelayState);
        Assert.Equal("invalid_saml_response", SamlWorld.Query(acs, "error"));
        Assert.Equal("Unknown or expired request ID", SamlWorld.Query(acs, "error_description"));
    }

    [Fact]
    public async Task A_request_can_be_answered_only_once_even_by_a_different_assertion()
    {
        var browser = Factory.Browser();
        var started = await W.StartAsync(browser);
        Assert.Equal(HttpStatusCode.SeeOther, (await W.PostAcsAsync(browser, W.Response(started, For(Person("one"))), started.RelayState)).StatusCode);
        var second = await W.PostAcsAsync(browser, W.Response(started, For(Person("two"))), started.RelayState);
        Assert.Equal("invalid_state", SamlWorld.Query(second, "error"));
        Assert.Equal("request_already_answered", SamlWorld.Query(second, "error_description"));
    }

    [Fact]
    public async Task A_response_that_does_not_answer_the_request_is_refused()
    {
        var browser = Factory.Browser();
        var started = await W.StartAsync(browser);
        var unasked = Idp.Build(W.Acs, W.Sp, new SamlOptions { OmitInResponseTo = true, NameId = Person("unasked"), Email = Person("unasked") });
        var acs = await W.PostAcsAsync(browser, unasked, started.RelayState);
        Assert.Equal("invalid_saml_response", SamlWorld.Query(acs, "error"));
        Assert.Contains("InResponseTo is missing", SamlWorld.Query(acs, "error_description"));
    }

    [Fact]
    public async Task An_expired_or_unknown_relay_state_is_refused()
    {
        var browser = Factory.Browser();
        var started = await W.StartAsync(browser);
        var unknown = await W.PostAcsAsync(browser, W.Response(started, For(Person("rs"))), "not-a-state");
        Assert.Equal("invalid_state", SamlWorld.Query(unknown, "error"));
        W.Db(db => { db.Set<SamlAuthRequest>().Where(r => r.ProviderId == W.ProviderId).ToList().ForEach(r => r.ExpiresAt = DateTime.UtcNow.AddMinutes(-1)); db.SaveChanges(); return 0; });
        var expired = await W.PostAcsAsync(browser, W.Response(started, For(Person("rs"))), started.RelayState);
        Assert.Equal("invalid_state", SamlWorld.Query(expired, "error"));
        Assert.Equal(0, W.UsersWithEmail(Person("rs")));
    }

    [Fact]
    public async Task A_request_started_before_the_configuration_changed_is_refused()
    {
        var browser = Factory.Browser();
        var started = await W.StartAsync(browser);
        // The administrator saves the connection again: requests of the old configuration are gone.
        await W.RegisterAsync();
        await W.VerifyDomainAsync(Factory.Dns);
        await W.RunTestAsync(Factory.Browser(), For(W.OwnerEmail));
        await W.Owner(HttpMethod.Post, "/v1/sso/enable", new { });
        var acs = await W.PostAcsAsync(browser, W.Response(started, For(Person("stale"))), started.RelayState);
        Assert.Equal("invalid_state", SamlWorld.Query(acs, "error"));
        Assert.Equal(0, W.UsersWithEmail(Person("stale")));
    }

    [Fact]
    public async Task Bad_responses_are_refused_with_a_reason_and_a_redirect_to_the_error_page_of_the_request()
    {
        var browser = Factory.Browser();
        var started = await W.StartAsync(browser, new { organizationSlug = W.OrgId, callbackURL = "/dashboard", errorCallbackURL = "/connect/error?from=saml" });
        var bad = await W.PostAcsAsync(browser, W.Response(started, For(Person("bad")) with { UseOtherKey = true }), started.RelayState);
        Assert.Equal(HttpStatusCode.Redirect, bad.StatusCode);
        Assert.Equal("/connect/error", bad.Headers.Location!.AbsolutePath);
        Assert.Equal("saml", SamlWorld.Query(bad, "from"));
        Assert.Equal("invalid_saml_response", SamlWorld.Query(bad, "error"));
        Assert.Contains("could not be verified", SamlWorld.Query(bad, "error_description"));
        Assert.Equal(401, await MeStatus(browser));
        Assert.Equal(0, W.UsersWithEmail(Person("bad")));
        // A failed response does not spend the request: the right one still works.
        Assert.Equal(HttpStatusCode.SeeOther, (await W.PostAcsAsync(browser, W.Response(started, For(Person("bad"))), started.RelayState)).StatusCode);
    }

    [Theory]
    [InlineData("Unsigned", "signed by the identity provider")]
    [InlineData("OtherKey", "could not be verified")]
    [InlineData("Sha1", "deprecated algorithm")]
    [InlineData("Audience", "audience does not match")]
    [InlineData("Destination", "Destination does not match")]
    [InlineData("Recipient", "Recipient does not match")]
    [InlineData("Expired", "expired")]
    [InlineData("Issuer", "different identity provider")]
    [InlineData("Failed", "did not authenticate")]
    public async Task Each_kind_of_bad_response_is_refused_and_named(string fault, string reason)
    {
        var o = fault switch
        {
            "Unsigned" => new SamlOptions { Unsigned = true },
            "OtherKey" => new SamlOptions { UseOtherKey = true },
            "Sha1" => new SamlOptions { Sha1 = true },
            "Audience" => new SamlOptions { Audience = "https://other.example.test" },
            "Destination" => new SamlOptions { Destination = "https://evil.example.test/acs" },
            "Recipient" => new SamlOptions { Recipient = "https://evil.example.test/acs" },
            "Expired" => new SamlOptions { NotOnOrAfterSeconds = -900, ConfirmationNotOnOrAfterSeconds = -900 },
            "Issuer" => new SamlOptions { Issuer = "https://other.example.test" },
            _ => new SamlOptions { Status = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed" },
        };
        var browser = Factory.Browser();
        var (acs, _) = await W.SignInAsync(browser, o with { NameId = Person("f"), Email = Person("f") });
        Assert.Equal(HttpStatusCode.Redirect, acs.StatusCode);
        Assert.Equal("invalid_saml_response", SamlWorld.Query(acs, "error"));
        Assert.Contains(reason, SamlWorld.Query(acs, "error_description"));
        Assert.Equal(401, await MeStatus(browser));
        Assert.Equal(0, W.UsersWithEmail(Person("f")));
    }

    [Fact]
    public async Task A_response_that_is_too_big_or_not_xml_is_refused_politely()
    {
        var browser = Factory.Browser();
        var started = await W.StartAsync(browser);
        var big = await W.PostAcsAsync(browser, new string('A', SamlValidator.MaxEncodedLength + 8), started.RelayState);
        Assert.Contains("maximum allowed size", SamlWorld.Query(big, "error_description"));
        var junk = await W.PostAcsAsync(browser, Convert.ToBase64String("just words"u8.ToArray()), started.RelayState);
        Assert.Equal("invalid_saml_response", SamlWorld.Query(junk, "error"));
    }

    [Fact]
    public async Task A_doctype_in_a_posted_response_is_refused_before_any_entity_is_read()
    {
        var browser = Factory.Browser();
        var started = await W.StartAsync(browser);
        var xml = "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">&xxe;</samlp:Response>";
        var acs = await W.PostAcsAsync(browser, SamlTestIdp.Encode(xml), started.RelayState);
        Assert.Equal("invalid_saml_response", SamlWorld.Query(acs, "error"));
        Assert.Contains("DTD", SamlWorld.Query(acs, "error_description"));
        Assert.DoesNotContain("root:", acs.Headers.Location!.ToString());
    }

    [Fact]
    public async Task The_acs_answers_the_references_errors_for_unknown_providers_and_empty_posts()
    {
        var unknown = await W.Http.PostAsync("/api/auth/sso/saml2/sp/acs/nope", new FormUrlEncodedContent(new Dictionary<string, string> { ["SAMLResponse"] = "x" }));
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
        Assert.Equal("No SAML provider found", (await ReadJsonAsync(unknown)).GetProperty("message").GetString());
        var empty = await W.Http.PostAsync(W.AcsPath, new FormUrlEncodedContent(new Dictionary<string, string>()));
        Assert.Equal(HttpStatusCode.BadRequest, empty.StatusCode);
        Assert.Equal("SAMLResponse is required for POST requests", (await ReadJsonAsync(empty)).GetProperty("message").GetString());
        var json = await W.Http.PostAsync(W.AcsPath, new StringContent("{\"SAMLResponse\":\"x\"}", System.Text.Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.Redirect, json.StatusCode);
    }

    [Fact]
    public async Task A_browser_that_opens_the_acs_without_a_response_is_sent_on()
    {
        var anonymous = await W.Http.GetAsync(W.AcsPath);
        Assert.Equal(HttpStatusCode.Redirect, anonymous.StatusCode);
        Assert.Equal("invalid_request", SamlWorld.Query(anonymous, "error"));
        var browser = Factory.Browser();
        await W.SignInAsync(browser, For(Person("bookmark")));
        var signedIn = await browser.GetAsync(W.AcsPath);
        Assert.Equal("http://localhost/", signedIn.Headers.Location!.ToString());
    }

    // ---------------------------------------------------------------- the same-browser rule

    [Fact]
    public async Task A_response_obtained_in_one_browser_cannot_sign_in_another()
    {
        // Login CSRF: the attacker starts and finishes the exchange in their own browser, then makes the victim's browser follow the last step.
        var attacker = Factory.Browser();
        var started = await W.StartAsync(attacker);
        var acs = await W.PostAcsAsync(Factory.Plain(), W.Response(started, For(Person("attacker"))), started.RelayState);
        Assert.Equal(HttpStatusCode.SeeOther, acs.StatusCode);
        var victim = Factory.Browser();
        var landed = await victim.GetAsync(SamlWorld.PathAndQuery(acs.Headers.Location!.ToString()));
        Assert.Equal(HttpStatusCode.Redirect, landed.StatusCode);
        Assert.Equal("/connect/error", landed.Headers.Location!.AbsolutePath);
        Assert.Equal("state_mismatch", SamlWorld.Query(landed, "error"));
        Assert.Equal(401, await MeStatus(victim));
        // The victim's try did not burn it: the real browser still completes.
        var real = await attacker.GetAsync(SamlWorld.PathAndQuery(acs.Headers.Location!.ToString()));
        Assert.Equal("http://localhost/dashboard", real.Headers.Location!.ToString());
        Assert.Equal(200, await MeStatus(attacker));
    }

    [Fact]
    public async Task The_last_step_works_once_and_only_after_the_response_was_accepted()
    {
        var browser = Factory.Browser();
        var started = await W.StartAsync(browser);
        var early = await browser.GetAsync($"/api/auth/sso/saml2/sp/continue/{W.ProviderId}?id={started.RequestId}");
        Assert.Equal("state_mismatch", SamlWorld.Query(early, "error"));
        var acs = await W.PostAcsAsync(browser, W.Response(started, For(Person("once"))), started.RelayState);
        var path = SamlWorld.PathAndQuery(acs.Headers.Location!.ToString());
        Assert.Equal("http://localhost/dashboard", (await browser.GetAsync(path)).Headers.Location!.ToString());
        var twice = await browser.GetAsync(path);
        Assert.Equal("state_mismatch", SamlWorld.Query(twice, "error"));
        Assert.Equal("state_mismatch", SamlWorld.Query(await browser.GetAsync($"/api/auth/sso/saml2/sp/continue/{W.ProviderId}"), "error"));
        Assert.Equal("state_mismatch", SamlWorld.Query(await browser.GetAsync($"/api/auth/sso/saml2/sp/continue/nope?id={started.RequestId}"), "error"));
    }

    [Fact]
    public async Task A_new_person_goes_to_the_new_user_address_when_one_was_given()
    {
        var browser = Factory.Browser();
        var (_, final) = await W.SignInAsync(browser, For(Person("welcome")), new { organizationSlug = W.OrgId, callbackURL = "/dashboard", newUserCallbackURL = "/organization" });
        Assert.Equal("http://localhost/organization", final!.Headers.Location!.ToString());
        var again = Factory.Browser();
        var (_, second) = await W.SignInAsync(again, For(Person("welcome")) with { AssertionId = "_another-assertion" }, new { organizationSlug = W.OrgId, callbackURL = "/dashboard", newUserCallbackURL = "/organization" });
        Assert.Equal("http://localhost/dashboard", second!.Headers.Location!.ToString());
    }

    [Fact]
    public async Task Return_addresses_must_be_this_site()
    {
        var evil = await W.Http.PostAsJsonAsync("/api/auth/sign-in/sso", new { organizationSlug = W.OrgId, callbackURL = "https://evil.example.test/" });
        Assert.Equal(HttpStatusCode.Forbidden, evil.StatusCode);
        Assert.Equal("INVALID_CALLBACK_URL", (await ReadJsonAsync(evil)).GetProperty("code").GetString());
    }

    [Fact]
    public async Task Members_of_a_workspace_with_saml_cannot_use_a_password()
    {
        var response = await W.Http.PostAsJsonAsync("/api/auth/sign-in/email", new { email = W.OwnerEmail, password = Password });
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains("managed by an organization", await response.Content.ReadAsStringAsync());
        var options = await ReadJsonAsync(await W.Http.GetAsync($"/v1/auth/login-options?email=someone@{W.Domain}"));
        Assert.Equal("sso", options.GetProperty("nextStep").GetString());
    }

    // ---------------------------------------------------------------- not on / the test

    [Fact]
    public async Task A_disabled_connection_signs_nobody_in()
    {
        var browser = Factory.Browser();
        var started = await W.StartAsync(browser);
        await W.Owner(HttpMethod.Post, "/v1/sso/disable", new { });
        var acs = await W.PostAcsAsync(browser, W.Response(started, For(Person("off"))), started.RelayState);
        Assert.Equal(HttpStatusCode.Forbidden, acs.StatusCode);
        Assert.Equal("sso_not_enabled", (await ReadJsonAsync(acs)).GetProperty("error").GetString());
        Assert.Equal(HttpStatusCode.Forbidden, (await W.Http.PostAsJsonAsync("/api/auth/sign-in/sso", new { organizationSlug = W.OrgId, callbackURL = "/dashboard" })).StatusCode);
        var unsolicited = await W.PostAcsAsync(Factory.Browser(), Idp.Build(W.Acs, W.Sp, new SamlOptions { OmitInResponseTo = true, NameId = Person("off2"), Email = Person("off2") }), null);
        Assert.Equal(HttpStatusCode.Forbidden, unsolicited.StatusCode);
        Assert.Equal(0, W.UsersWithEmail(Person("off")));
    }

    [Fact]
    public async Task A_disabled_connection_is_signed_into_only_by_the_administrators_test()
    {
        await W.Owner(HttpMethod.Post, "/v1/sso/disable", new { });
        var browser = Factory.Browser();
        var (intent, final) = await W.RunTestAsync(browser, For(W.OwnerEmail));
        Assert.Equal(HttpStatusCode.Redirect, final!.StatusCode);
        Assert.StartsWith("http://localhost/sso/test/complete", final.Headers.Location!.ToString());
        Assert.Contains(intent, final.Headers.Location.ToString());
        var connection = (await W.Owner(HttpMethod.Get, "/v1/sso")).Body.GetProperty("connection");
        Assert.Equal("succeeded", connection.GetProperty("testStatus").GetString());
        // A test signs nobody in.
        Assert.Equal(401, await MeStatus(browser));
    }
}

/// <summary>The administrator's connection test with SAML.</summary>
public sealed class SamlTestFlowTests(SsoFactory factory) : SamlBase, IClassFixture<SsoFactory>
{
    protected override SsoFactory Factory => factory;

    [Fact]
    public async Task Enabling_needs_a_successful_test_and_the_test_must_authenticate_the_administrator()
    {
        await W.RegisterAsync();
        await W.VerifyDomainAsync(Factory.Dns);
        Assert.Equal(HttpStatusCode.Conflict, (await W.Owner(HttpMethod.Post, "/v1/sso/enable", new { })).Status);

        // Someone else authenticates: the test fails.
        var (_, wrong) = await W.RunTestAsync(Factory.Browser(), For(Person("not.the.admin")));
        Assert.Contains("error=", wrong!.Headers.Location!.Query);
        var failed = (await W.Owner(HttpMethod.Get, "/v1/sso")).Body.GetProperty("connection");
        Assert.Equal("failed", failed.GetProperty("testStatus").GetString());
        Assert.Equal(HttpStatusCode.Conflict, (await W.Owner(HttpMethod.Post, "/v1/sso/enable", new { })).Status);

        // The administrator authenticates: it passes, and nobody was created.
        var (_, right) = await W.RunTestAsync(Factory.Browser(), For(W.OwnerEmail));
        Assert.StartsWith("http://localhost/sso/test/complete", right!.Headers.Location!.ToString());
        Assert.Equal("succeeded", (await W.Owner(HttpMethod.Get, "/v1/sso")).Body.GetProperty("connection").GetProperty("testStatus").GetString());
        Assert.Equal(0, W.UsersWithEmail(Person("not.the.admin")));
        Assert.Equal(HttpStatusCode.NoContent, (await W.Owner(HttpMethod.Post, "/v1/sso/enable", new { })).Status);
    }

    [Fact]
    public async Task A_test_with_a_bad_signature_fails_and_says_so()
    {
        await W.RegisterAsync();
        await W.VerifyDomainAsync(Factory.Dns);
        var (_, final) = await W.RunTestAsync(Factory.Browser(), For(W.OwnerEmail) with { UseOtherKey = true });
        Assert.Contains("error=invalid_saml_response", final!.Headers.Location!.Query);
        var connection = (await W.Owner(HttpMethod.Get, "/v1/sso")).Body.GetProperty("connection");
        Assert.Equal("failed", connection.GetProperty("testStatus").GetString());
        Assert.Equal(HttpStatusCode.Conflict, (await W.Owner(HttpMethod.Post, "/v1/sso/enable", new { })).Status);
    }

    [Fact]
    public async Task A_test_needs_the_domain_to_be_proven_first()
    {
        await W.RegisterAsync();
        var made = await W.Owner(HttpMethod.Post, "/v1/sso/test", new { });
        Assert.Equal(HttpStatusCode.Conflict, made.Status);
    }

    [Fact]
    public async Task The_post_binding_serves_a_page_that_submits_the_request_only_to_its_own_browser()
    {
        await W.RegisterAsync(new { binding = "post" });
        await W.VerifyDomainAsync(Factory.Dns);
        await W.RunTestAsync(Factory.Browser(), For(W.OwnerEmail));
        await W.Owner(HttpMethod.Post, "/v1/sso/enable", new { });
        var browser = Factory.Browser();
        var r = await browser.PostAsJsonAsync("/api/auth/sign-in/sso", new { organizationSlug = W.OrgId, callbackURL = "/dashboard" });
        var url = (await ReadJsonAsync(r)).GetProperty("url").GetString()!;
        Assert.StartsWith($"http://localhost/api/auth/sso/saml2/sp/login/{W.ProviderId}?relay=", url);
        var page = await browser.GetAsync(SamlWorld.PathAndQuery(url));
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        var html = await page.Content.ReadAsStringAsync();
        Assert.Contains($"action=\"{Idp.SsoUrl}\"", html);
        Assert.Contains("name=\"SAMLRequest\"", html);
        var csp = page.Headers.GetValues("Content-Security-Policy").Single();
        Assert.Contains("form-action https://idp.example.test", csp);
        Assert.Contains("script-src 'sha256-", csp);
        var encoded = System.Text.RegularExpressions.Regex.Match(html, "name=\"SAMLRequest\" value=\"([^\"]+)\"").Groups[1].Value;
        var xml = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
        var id = System.Xml.Linq.XDocument.Parse(xml).Root!.Attribute("ID")!.Value;
        // The same page, asked for by another browser, is refused.
        var other = await Factory.Browser().GetAsync(SamlWorld.PathAndQuery(url));
        Assert.Equal("state_mismatch", SamlWorld.Query(other, "error"));
        // The response to that request signs the person in.
        var relay = HttpUtility.ParseQueryString(new Uri(url).Query)["relay"]!;
        var acs = await W.PostAcsAsync(browser, Idp.Build(W.Acs, W.Sp, new SamlOptions { InResponseTo = id, NameId = Person("post"), Email = Person("post") }), relay);
        Assert.Equal(HttpStatusCode.SeeOther, acs.StatusCode);
        Assert.Equal("http://localhost/dashboard", (await browser.GetAsync(SamlWorld.PathAndQuery(acs.Headers.Location!.ToString()))).Headers.Location!.ToString());
        Assert.Equal(200, await MeStatus(browser));
        // Once answered, the page is gone.
        Assert.Equal("state_mismatch", SamlWorld.Query(await browser.GetAsync(SamlWorld.PathAndQuery(url)), "error"));
    }
}

/// <summary>With unsolicited responses switched off only sign-ins this service started are accepted.</summary>
public sealed class SamlStrictSignInTests(SamlStrictFactory factory) : SamlBase, IClassFixture<SamlStrictFactory>
{
    protected override SsoFactory Factory => factory;

    [Fact]
    public async Task An_unsolicited_response_is_refused_when_idp_initiated_sign_in_is_off()
    {
        await W.VerifiedTestedAndEnabledAsync(factory, factory.Dns);
        var response = Idp.Build(W.Acs, W.Sp, new SamlOptions { OmitInResponseTo = true, NameId = Person("u"), Email = Person("u") });
        var browser = Factory.Browser();
        var acs = await W.PostAcsAsync(browser, response, null);
        Assert.Equal("unsolicited_response", SamlWorld.Query(acs, "error"));
        Assert.Equal("IdP-initiated SSO not allowed", SamlWorld.Query(acs, "error_description"));
        Assert.Equal(401, await MeStatus(browser));
        // Sign-ins started here still work.
        var (_, final) = await W.SignInAsync(Factory.Browser(), For(Person("u")));
        Assert.Equal("http://localhost/dashboard", final!.Headers.Location!.ToString());
    }
}
