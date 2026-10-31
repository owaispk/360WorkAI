using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.Sso;
using WorkAI360.Api.Features.Sso;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>An API where domains are proven through a fake DNS (loopback issuers are NOT auto-verified, so the real path runs).</summary>
public class SsoFactory : ApiFactory
{
    public FakeDns Dns { get; } = new();

    protected override IEnumerable<KeyValuePair<string, string>> Settings =>
    [
        new("Sso:DevLoopbackIssuerIsVerified", "false"),
        new("Auth:PrivilegedSessionMinutes", "100000"),
    ];

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureServices(s => s.AddSingleton<IDnsTxtResolver>(Dns));
    }
}

/// <summary>An API like production for outbound traffic: no private addresses, no plain http.</summary>
public sealed class StrictSsoFactory : SsoFactory
{
    protected override IEnumerable<KeyValuePair<string, string>> Settings => [.. base.Settings, new("Sso:AllowPrivateNetworks", "false")];
}

/// <summary>An API in development where loopback issuers count as verified.</summary>
public sealed class LoopbackSsoFactory : ApiFactory
{
    protected override IEnumerable<KeyValuePair<string, string>> Settings => [new("Auth:PrivilegedSessionMinutes", "100000")];
}

/// <summary>One workspace wired to a fake identity provider, built through the public API.</summary>
public sealed class SsoWorld(ApiFactory factory, FakeIdp idp, FakeDns? dns)
{
    public HttpClient Http { get; } = factory.Plain();
    public string Domain { get; } = $"corp-{Guid.NewGuid():N}"[..14] + ".test";
    public string OrgId { get; private set; } = "";
    public string OrgSlug => OrgId;
    public string OwnerToken { get; private set; } = "";
    public string OwnerEmail { get; private set; } = "";
    public string OwnerId { get; private set; } = "";
    public FakeIdp Idp => idp;
    public string ProviderId => $"openwork-sso-{OrgId}";
    public static readonly HttpClient Direct = new(new HttpClientHandler { AllowAutoRedirect = false });

    public static async Task<SsoWorld> CreateAsync(ApiFactory factory, FakeIdp idp, FakeDns? dns)
    {
        var w = new SsoWorld(factory, idp, dns);
        w.OwnerEmail = $"owner@{w.Domain}";
        var signUp = await w.Http.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "Owner Person", email = w.OwnerEmail, password = Password });
        signUp.EnsureSuccessStatusCode();
        var json = await ReadJsonAsync(signUp);
        w.OwnerToken = json.GetProperty("token").GetString()!;
        w.OwnerId = json.GetProperty("user").GetProperty("id").GetString()!;
        var created = await w.Http.SendAsync(Bearer(HttpMethod.Post, "/v1/org", w.OwnerToken, new { name = "Sso Space" }));
        w.OrgId = (await ReadJsonAsync(created)).GetProperty("organization").GetProperty("id").GetString()!;
        idp.Identity = ("owner-sub", w.OwnerEmail, "Owner Person");
        return w;
    }

    public HttpRequestMessage As(string token, HttpMethod method, string url, object? body = null)
    {
        var r = Bearer(method, url, token, body);
        r.Headers.Add("x-openwork-org-id", OrgId);
        return r;
    }

    public async Task<(HttpStatusCode Status, JsonElement Body)> Owner(HttpMethod method, string url, object? body = null) => await Send(OwnerToken, method, url, body);

    public async Task<(HttpStatusCode Status, JsonElement Body)> Send(string token, HttpMethod method, string url, object? body = null)
    {
        var r = await Http.SendAsync(As(token, method, url, body));
        var text = await r.Content.ReadAsStringAsync();
        if (text.Length > 0 && text[0] is not ('{' or '[')) throw new InvalidOperationException($"{(int)r.StatusCode} {method} {url}: {text[..Math.Min(text.Length, 600)]}");
        return (r.StatusCode, string.IsNullOrEmpty(text) ? default : JsonDocument.Parse(text).RootElement.Clone());
    }

    public Task<(HttpStatusCode Status, JsonElement Body)> RegisterAsync(object? extra = null, string? domain = null, string? clientSecret = null)
    {
        var body = new Dictionary<string, object?>
        {
            ["issuer"] = idp.Issuer, ["domain"] = domain ?? Domain, ["clientId"] = FakeIdp.ClientId, ["clientSecret"] = clientSecret ?? FakeIdp.ClientSecret,
        };
        if (extra is not null) foreach (var p in extra.GetType().GetProperties()) body[p.Name] = p.GetValue(extra);
        return Owner(HttpMethod.Post, "/v1/sso/oidc", body);
    }

    public async Task VerifyDomainAsync()
    {
        var token = await Owner(HttpMethod.Post, "/v1/sso/request-domain-verification", new { });
        Assert.Equal(HttpStatusCode.Created, token.Status);
        dns!.Publish($"_better-auth-token-{ProviderId}.{Domain}", $"_better-auth-token-{ProviderId}={token.Body.GetProperty("domainVerificationToken").GetString()}");
        var verified = await Owner(HttpMethod.Post, "/v1/sso/verify-domain", new { });
        Assert.Equal(HttpStatusCode.NoContent, verified.Status);
    }

    public static string PathAndQuery(string url) => new Uri(url).PathAndQuery;

    /// <summary>The identity provider's step: the browser opens the authorization URL and is sent back with a code.</summary>
    public static async Task<string> AtIdpAsync(string authorizationUrl)
    {
        var r = await Direct.GetAsync(authorizationUrl);
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        return r.Headers.Location!.ToString();
    }

    /// <summary>An administrator's connection test, start to finish. Returns the intent, the redirect the callback answered with, and the browser.</summary>
    public async Task<(string Intent, string Location)> RunTestAsync(HttpClient? browser = null, string? token = null)
    {
        browser ??= factory.Browser();
        token ??= OwnerToken;
        var made = await Send(token, HttpMethod.Post, "/v1/sso/test", new { });
        Assert.Equal(HttpStatusCode.Created, made.Status);
        var intent = made.Body.GetProperty("intentId").GetString()!;
        var start = await browser.SendAsync(As(token, HttpMethod.Post, $"/v1/sso/test/{intent}/start", new { }));
        Assert.Equal(HttpStatusCode.OK, start.StatusCode);
        var url = (await ReadJsonAsync(start)).GetProperty("url").GetString()!;
        var back = await AtIdpAsync(url);
        var callback = await browser.GetAsync(PathAndQuery(back));
        Assert.Equal(HttpStatusCode.Redirect, callback.StatusCode);
        return (intent, callback.Headers.Location!.ToString());
    }

    public async Task VerifiedTestedAndEnabledAsync()
    {
        var reg = await RegisterAsync();
        Assert.Equal(HttpStatusCode.Created, reg.Status);
        await VerifyDomainAsync();
        await RunTestAsync();
        var enabled = await Owner(HttpMethod.Post, "/v1/sso/enable", new { });
        Assert.Equal(HttpStatusCode.NoContent, enabled.Status);
    }

    public async Task<(HttpResponseMessage Response, JsonElement Body)> StartSignInAsync(HttpClient browser, object? body = null)
    {
        var r = await browser.PostAsJsonAsync("/api/auth/sign-in/sso", body ?? new { organizationSlug = OrgSlug, callbackURL = "/dashboard" });
        var text = await r.Content.ReadAsStringAsync();
        return (r, string.IsNullOrEmpty(text) ? default : JsonDocument.Parse(text).RootElement.Clone());
    }

    /// <summary>The whole sign-in: the sign-in page asks for the URL, the provider signs the person in, the callback answers.</summary>
    public async Task<HttpResponseMessage> SignInAsync(HttpClient browser, object? body = null)
    {
        var (_, started) = await StartSignInAsync(browser, body);
        var back = await AtIdpAsync(started.GetProperty("url").GetString()!);
        return await browser.GetAsync(PathAndQuery(back));
    }

    public T Db<T>(Func<WorkAI360.Api.Data.DenDbContext, T> read) => factory.WithDb(read);
    public int UsersWithEmail(string email) => Db(db => db.Users.Count(u => u.Email == email));
    public int SessionsFor(string email) => Db(db => (from u in db.Users where u.Email == email join s in db.Sessions on u.Id equals s.UserId select s).Count());
}

public sealed class SsoConnectionTests : IClassFixture<SsoFactory>, IAsyncLifetime
{
    private readonly SsoFactory _factory;
    private FakeIdp _idp = null!;
    private SsoWorld W = null!;

    public SsoConnectionTests(SsoFactory factory) => _factory = factory;
    public async Task InitializeAsync()
    {
        _idp = await FakeIdp.StartAsync();
        W = await SsoWorld.CreateAsync(_factory, _idp, _factory.Dns);
    }
    public async Task DisposeAsync() => await _idp.DisposeAsync();

    [Fact]
    public async Task Nothing_is_configured_at_first()
    {
        var r = await W.Owner(HttpMethod.Get, "/v1/sso");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal(JsonValueKind.Null, r.Body.GetProperty("connection").ValueKind);
        Assert.Equal(HttpStatusCode.NotFound, (await W.Owner(HttpMethod.Post, "/v1/sso/test", new { })).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await W.Owner(HttpMethod.Post, "/v1/sso/disable", new { })).Status);
        Assert.Equal(HttpStatusCode.Conflict, (await W.Owner(HttpMethod.Post, "/v1/sso/enable", new { })).Status);
        Assert.Equal(HttpStatusCode.NoContent, (await W.Owner(HttpMethod.Delete, "/v1/sso")).Status);
    }

    [Fact]
    public async Task Saving_validates_the_body_in_the_references_words()
    {
        var empty = await W.Owner(HttpMethod.Post, "/v1/sso/oidc", new { });
        Assert.Equal(HttpStatusCode.BadRequest, empty.Status);
        Assert.Equal("invalid_request", SsoWorld_Error(empty.Body));
        var paths = empty.Body.GetProperty("details").EnumerateArray().Select(d => d.GetProperty("path")[0].GetString()!).ToArray();
        Assert.Equal(["issuer", "domain", "clientId", "clientSecret"], paths);
        var bad = await W.Owner(HttpMethod.Post, "/v1/sso/oidc", new { issuer = "x", domain = "", clientId = "a", clientSecret = "", tokenEndpointAuthentication = "none" });
        var messages = bad.Body.GetProperty("details").EnumerateArray().Select(d => d.GetProperty("message").GetString()!).ToArray();
        Assert.Equal(["Invalid URL", "Too small: expected string to have >=1 characters", "Too small: expected string to have >=1 characters", "Invalid option: expected one of \"client_secret_basic\"|\"client_secret_post\""], messages);
    }

    private static string SsoWorld_Error(JsonElement body) => body.GetProperty("error").GetString()!;

    [Fact]
    public async Task Only_people_with_the_permission_can_read_or_change_it()
    {
        var (email, token, userId) = await _factory.SignUpAsync(W.Http, "Plain Member");
        var invite = await W.Owner(HttpMethod.Post, "/v1/invitations", new { email, role = "member" });
        await W.Http.SendAsync(Bearer(HttpMethod.Post, "/v1/orgs/invitations/accept", token, new { id = invite.Body.GetProperty("invitationId").GetString() }));
        var read = await W.Send(token, HttpMethod.Get, "/v1/sso");
        Assert.Equal(HttpStatusCode.Forbidden, read.Status);
        Assert.Equal("sso.view", read.Body.GetProperty("requiredPermission").GetString());
        var write = await W.Send(token, HttpMethod.Post, "/v1/sso/oidc", new { });
        Assert.Equal("sso.manage", write.Body.GetProperty("requiredPermission").GetString());
        Assert.Equal(HttpStatusCode.Forbidden, (await W.Send(token, HttpMethod.Post, "/v1/sso/enable", new { })).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await W.Http.GetAsync("/v1/sso")).StatusCode);
        Assert.NotEmpty(userId);
    }

    [Fact]
    public async Task A_saved_connection_is_unverified_disabled_and_never_shows_the_secret()
    {
        var r = await W.RegisterAsync();
        Assert.Equal(HttpStatusCode.Created, r.Status);
        var c = r.Body.GetProperty("connection");
        Assert.False(c.GetProperty("domainVerified").GetBoolean());
        Assert.Equal("disabled", c.GetProperty("status").GetString());
        Assert.Equal("untested", c.GetProperty("testStatus").GetString());
        Assert.Equal($"_better-auth-token-{W.ProviderId}.{W.Domain}", c.GetProperty("domainVerificationDnsName").GetString());
        Assert.Equal(JsonValueKind.String, r.Body.GetProperty("domainVerificationToken").ValueKind);
        Assert.EndsWith($"/api/auth/sso/callback/{W.ProviderId}", c.GetProperty("redirectUrl").GetString());
        Assert.Equal("client_secret_basic", c.GetProperty("oidc").GetProperty("tokenEndpointAuthentication").GetString());
        Assert.DoesNotContain(FakeIdp.ClientSecret, r.Body.ToString());
        Assert.DoesNotContain(FakeIdp.ClientSecret, (await W.Owner(HttpMethod.Get, "/v1/sso")).Body.ToString());

        // At rest only an encrypted copy exists, and it decrypts to the secret.
        var stored = W.Db(db => db.Set<SsoConnection>().Single(x => x.OrganizationId == W.OrgId));
        Assert.DoesNotContain(FakeIdp.ClientSecret, stored.ClientSecretProtected);
        Assert.DoesNotContain(FakeIdp.ClientSecret, stored.OidcConfigJson);
        Assert.Equal(FakeIdp.ClientSecret, new SecretProtector(Microsoft.Extensions.Options.Options.Create(new AuthOptions { Secret = Secret })).Unprotect(stored.ClientSecretProtected!));
    }

    [Fact]
    public async Task Discovery_fills_in_the_endpoints_and_a_wrong_issuer_is_refused()
    {
        var ok = await W.RegisterAsync();
        Assert.Equal(_idp.Url + "/token", ok.Body.GetProperty("connection").GetProperty("oidc").GetProperty("tokenEndpoint").GetString());
        var manual = await W.RegisterAsync(new { skipDiscovery = true });
        Assert.Equal(HttpStatusCode.BadRequest, manual.Status);
        Assert.Contains("Manual OIDC configuration requires", manual.Body.GetProperty("details")[0].GetProperty("message").GetString());
        var explicitEndpoints = await W.RegisterAsync(new { skipDiscovery = true, authorizationEndpoint = _idp.Url + "/authorize", tokenEndpoint = _idp.Url + "/token", jwksEndpoint = _idp.Url + "/jwks", tokenEndpointAuthentication = "client_secret_post" });
        Assert.Equal(HttpStatusCode.Created, explicitEndpoints.Status);
        Assert.Equal("client_secret_post", explicitEndpoints.Body.GetProperty("connection").GetProperty("oidc").GetProperty("tokenEndpointAuthentication").GetString());
        var wrong = await W.Owner(HttpMethod.Post, "/v1/sso/oidc", new { issuer = _idp.Url + "/other", domain = W.Domain, clientId = "c", clientSecret = "s" });
        Assert.Equal(HttpStatusCode.BadRequest, wrong.Status);
    }

    [Fact]
    public async Task The_domain_must_be_proven_in_DNS_before_it_counts()
    {
        await W.RegisterAsync();
        // Saving hands out the token to publish; once it has lapsed there is nothing pending.
        _factory.WithDb(db => { db.Set<SsoConnection>().Where(c => c.OrganizationId == W.OrgId).ExecuteUpdate(s => s.SetProperty(c => c.DomainVerificationExpiresAt, DateTime.UtcNow.AddMinutes(-1))); return 0; });
        var noToken = await W.Owner(HttpMethod.Post, "/v1/sso/verify-domain", new { });
        Assert.Equal(HttpStatusCode.BadRequest, noToken.Status);
        Assert.Equal("No pending domain verification exists", noToken.Body.GetProperty("details")[0].GetProperty("message").GetString());

        var token = (await W.Owner(HttpMethod.Post, "/v1/sso/request-domain-verification", new { })).Body.GetProperty("domainVerificationToken").GetString()!;
        var again = (await W.Owner(HttpMethod.Post, "/v1/sso/request-domain-verification", new { })).Body.GetProperty("domainVerificationToken").GetString();
        Assert.Equal(token, again);

        // No record, a wrong record, and a record on the wrong name all fail.
        var nothing = await W.Owner(HttpMethod.Post, "/v1/sso/verify-domain", new { });
        Assert.Equal(HttpStatusCode.BadRequest, nothing.Status);
        Assert.Contains("Unable to verify domain ownership", nothing.Body.GetProperty("details")[0].GetProperty("message").GetString());
        var host = $"_better-auth-token-{W.ProviderId}";
        _factory.Dns.Publish($"{host}.{W.Domain}", $"{host}=not-the-token");
        Assert.Equal(HttpStatusCode.BadRequest, (await W.Owner(HttpMethod.Post, "/v1/sso/verify-domain", new { })).Status);
        _factory.Dns.Publish($"elsewhere.{W.Domain}", $"{host}={token}");
        Assert.Equal(HttpStatusCode.BadRequest, (await W.Owner(HttpMethod.Post, "/v1/sso/verify-domain", new { })).Status);
        Assert.False(W.Db(db => db.Set<SsoConnection>().Single(c => c.OrganizationId == W.OrgId).DomainVerified));

        // The bare token and the prefixed form are both accepted.
        _factory.Dns.Publish($"{host}.{W.Domain}", "something else", token);
        Assert.Equal(HttpStatusCode.NoContent, (await W.Owner(HttpMethod.Post, "/v1/sso/verify-domain", new { })).Status);
        Assert.Contains(_factory.Dns.Lookups, l => l == $"{host}.{W.Domain}");
        Assert.True((await W.Owner(HttpMethod.Get, "/v1/sso")).Body.GetProperty("connection").GetProperty("domainVerified").GetBoolean());
        Assert.Equal(HttpStatusCode.BadRequest, (await W.Owner(HttpMethod.Post, "/v1/sso/verify-domain", new { })).Status);
    }

    [Fact]
    public async Task Saving_again_forgets_the_proof_and_the_test()
    {
        await W.RegisterAsync();
        await W.VerifyDomainAsync();
        await W.RunTestAsync();
        Assert.Equal("succeeded", (await W.Owner(HttpMethod.Get, "/v1/sso")).Body.GetProperty("connection").GetProperty("testStatus").GetString());
        await W.RegisterAsync(clientSecret: "fake-secret");
        var c = (await W.Owner(HttpMethod.Get, "/v1/sso")).Body.GetProperty("connection");
        Assert.False(c.GetProperty("domainVerified").GetBoolean());
        Assert.Equal("untested", c.GetProperty("testStatus").GetString());
        var enable = await W.Owner(HttpMethod.Post, "/v1/sso/enable", new { });
        Assert.Equal("Verify the SSO domain before enabling SSO.", enable.Body.GetProperty("message").GetString());
    }

    [Fact]
    public async Task A_domain_one_workspace_proved_cannot_be_proved_by_another()
    {
        await W.RegisterAsync();
        await W.VerifyDomainAsync();
        var other = await SsoWorld.CreateAsync(_factory, _idp, _factory.Dns);
        await other.RegisterAsync(domain: W.Domain);
        var token = (await other.Owner(HttpMethod.Post, "/v1/sso/request-domain-verification", new { })).Body.GetProperty("domainVerificationToken").GetString();
        _factory.Dns.Publish($"_better-auth-token-{other.ProviderId}.{W.Domain}", $"_better-auth-token-{other.ProviderId}={token}");
        var claim = await other.Owner(HttpMethod.Post, "/v1/sso/verify-domain", new { });
        Assert.Equal(HttpStatusCode.BadRequest, claim.Status);
        Assert.Contains("already verified", claim.Body.GetProperty("details")[0].GetProperty("message").GetString());
    }

    [Fact]
    public async Task Testing_and_enabling_follow_the_lifecycle()
    {
        await W.RegisterAsync();
        Assert.Equal("Verify the SSO domain before testing this configuration.", (await W.Owner(HttpMethod.Post, "/v1/sso/test", new { })).Body.GetProperty("message").GetString());
        await W.VerifyDomainAsync();
        Assert.Equal("Test the current SSO configuration successfully before enabling SSO.", (await W.Owner(HttpMethod.Post, "/v1/sso/enable", new { })).Body.GetProperty("message").GetString());

        var (intent, location) = await W.RunTestAsync();
        Assert.Contains($"/sso/test/complete?openworkSsoTest={intent}", location);
        Assert.DoesNotContain("error=", location);
        var c = (await W.Owner(HttpMethod.Get, "/v1/sso")).Body.GetProperty("connection");
        Assert.Equal("succeeded", c.GetProperty("testStatus").GetString());
        Assert.NotEqual(JsonValueKind.Null, c.GetProperty("lastTestedAt").ValueKind);
        // The test signs nobody in.
        Assert.Equal(0, W.SessionsFor(W.OwnerEmail) - 1);

        Assert.Equal(HttpStatusCode.NoContent, (await W.Owner(HttpMethod.Post, "/v1/sso/enable", new { })).Status);
        Assert.Equal("enabled", (await W.Owner(HttpMethod.Get, "/v1/sso")).Body.GetProperty("connection").GetProperty("status").GetString());
        // Testing is for a disabled connection; changing the configuration needs it off first.
        Assert.Equal("Disable SSO before testing a replacement configuration.", (await W.Owner(HttpMethod.Post, "/v1/sso/test", new { })).Body.GetProperty("message").GetString());
        Assert.Equal(HttpStatusCode.NoContent, (await W.Owner(HttpMethod.Post, "/v1/sso/disable", new { })).Status);
        Assert.Equal("disabled", (await W.Owner(HttpMethod.Get, "/v1/sso")).Body.GetProperty("connection").GetProperty("status").GetString());
    }

    [Fact]
    public async Task A_configuration_changed_after_its_test_cannot_be_enabled()
    {
        await W.RegisterAsync();
        await W.VerifyDomainAsync();
        await W.RunTestAsync();
        // Simulate an edit that slipped in after the test (the revision no longer matches what was tested).
        _factory.WithDb(db => { db.Set<SsoConnection>().Where(c => c.OrganizationId == W.OrgId).ExecuteUpdate(s => s.SetProperty(c => c.ConfigRevision, "changed")); return 0; });
        var enable = await W.Owner(HttpMethod.Post, "/v1/sso/enable", new { });
        Assert.Equal(HttpStatusCode.Conflict, enable.Status);
        Assert.Equal("Test the current SSO configuration successfully before enabling SSO.", enable.Body.GetProperty("message").GetString());
    }

    [Fact]
    public async Task A_test_works_once_for_the_administrator_who_made_it()
    {
        await W.RegisterAsync();
        await W.VerifyDomainAsync();
        var browser = _factory.Browser();
        var made = await W.Owner(HttpMethod.Post, "/v1/sso/test", new { });
        var intent = made.Body.GetProperty("intentId").GetString()!;
        Assert.Contains($"/sso/test?intentId={intent}&organizationId={W.OrgId}", made.Body.GetProperty("testUrl").GetString());

        // Someone else (an admin without the SSO permission) cannot start it.
        var (email, token, _) = await _factory.SignUpAsync(W.Http, "Another Admin");
        var invite = await W.Owner(HttpMethod.Post, "/v1/invitations", new { email, role = "admin" });
        await W.Http.SendAsync(Bearer(HttpMethod.Post, "/v1/orgs/invitations/accept", token, new { id = invite.Body.GetProperty("invitationId").GetString() }));
        var stolen = await W.Send(token, HttpMethod.Post, $"/v1/sso/test/{intent}/start", new { });
        Assert.Equal(HttpStatusCode.Forbidden, stolen.Status);

        var first = await browser.SendAsync(W.As(W.OwnerToken, HttpMethod.Post, $"/v1/sso/test/{intent}/start", new { }));
        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        var second = await W.Owner(HttpMethod.Post, $"/v1/sso/test/{intent}/start", new { });
        Assert.Equal(HttpStatusCode.Conflict, second.Status);
        Assert.Equal("sso_lifecycle_error", second.Body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task A_test_expires_after_five_minutes_and_can_be_cancelled()
    {
        await W.RegisterAsync();
        await W.VerifyDomainAsync();
        var intent = (await W.Owner(HttpMethod.Post, "/v1/sso/test", new { })).Body.GetProperty("intentId").GetString()!;
        _factory.WithDb(db => { db.Set<SsoConnection>().Where(c => c.OrganizationId == W.OrgId).ExecuteUpdate(s => s.SetProperty(c => c.ActiveTestExpiresAt, DateTime.UtcNow.AddMinutes(-1))); return 0; });
        Assert.Equal("failed", (await W.Owner(HttpMethod.Get, "/v1/sso")).Body.GetProperty("connection").GetProperty("testStatus").GetString());
        var late = await W.Owner(HttpMethod.Post, $"/v1/sso/test/{intent}/start", new { });
        Assert.Equal(HttpStatusCode.Conflict, late.Status);
        Assert.Contains("expired", late.Body.GetProperty("message").GetString());

        var intent2 = (await W.Owner(HttpMethod.Post, "/v1/sso/test", new { })).Body.GetProperty("intentId").GetString()!;
        Assert.Equal(HttpStatusCode.NoContent, (await W.Owner(HttpMethod.Post, $"/v1/sso/test/{intent2}/cancel", new { })).Status);
        Assert.Equal("failed", (await W.Owner(HttpMethod.Get, "/v1/sso")).Body.GetProperty("connection").GetProperty("testStatus").GetString());
        Assert.Equal(HttpStatusCode.Conflict, (await W.Owner(HttpMethod.Post, $"/v1/sso/test/{intent2}/start", new { })).Status);
        // Unknown intents are ignored.
        Assert.Equal(HttpStatusCode.NoContent, (await W.Owner(HttpMethod.Post, "/v1/sso/test/unknown/cancel", new { })).Status);
    }

    [Fact]
    public async Task A_test_signed_in_as_someone_else_fails_and_creates_nothing()
    {
        await W.RegisterAsync();
        await W.VerifyDomainAsync();
        _idp.Identity = ("someone-else", $"stranger@{W.Domain}", "Stranger");
        var (_, location) = await W.RunTestAsync();
        Assert.Contains("error=access_denied", location);
        var c = (await W.Owner(HttpMethod.Get, "/v1/sso")).Body.GetProperty("connection");
        Assert.Equal("failed", c.GetProperty("testStatus").GetString());
        Assert.Equal(0, W.UsersWithEmail($"stranger@{W.Domain}"));
        Assert.Equal(HttpStatusCode.Conflict, (await W.Owner(HttpMethod.Post, "/v1/sso/enable", new { })).Status);
    }

    [Fact]
    public async Task A_test_the_provider_refuses_fails_with_an_explanation()
    {
        await W.RegisterAsync();
        await W.VerifyDomainAsync();
        _idp.Fault = "error";
        var (_, location) = await W.RunTestAsync();
        Assert.Contains("error=access_denied", location);
        var c = (await W.Owner(HttpMethod.Get, "/v1/sso")).Body.GetProperty("connection");
        Assert.Equal("failed", c.GetProperty("testStatus").GetString());
        Assert.Contains("did not complete", c.GetProperty("lastError").GetString());
    }

    [Fact]
    public async Task Deleting_removes_the_connection_and_its_links()
    {
        await W.VerifiedTestedAndEnabledAsync();
        var browser = _factory.Browser();
        _idp.Identity = ("member-sub", $"new.person@{W.Domain}", "New Person");
        Assert.Equal(HttpStatusCode.Redirect, (await W.SignInAsync(browser)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await W.Owner(HttpMethod.Delete, "/v1/sso")).Status);
        Assert.Equal(JsonValueKind.Null, (await W.Owner(HttpMethod.Get, "/v1/sso")).Body.GetProperty("connection").ValueKind);
        Assert.Equal(0, W.Db(db => db.Set<ExternalAccount>().Count(a => a.ProviderId == W.ProviderId)));
        Assert.False(W.Db(db => db.Set<ExternalIdentity>().Single(i => i.OrganizationId == W.OrgId && i.Email == $"new.person@{W.Domain}").Active));
    }
}
