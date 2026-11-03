using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.OAuth;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

public sealed class OAuthTests : IClassFixture<ApiFactory>
{
    private const string Redirect = "http://127.0.0.1:9999/callback";
    private const string Resource = "http://localhost/mcp/agent";
    private readonly ApiFactory _factory;
    public OAuthTests(ApiFactory factory) => _factory = factory;

    // ---------- helpers ----------

    private static string B64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static (string Verifier, string Challenge) Pkce()
    {
        var verifier = B64(RandomNumberGenerator.GetBytes(32));
        return (verifier, B64(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))));
    }

    private static async Task<(string ClientId, string? Secret)> RegisterAsync(HttpClient http, string method = "none", string redirect = Redirect, string name = "Test Agent")
    {
        var response = await http.PostAsJsonAsync("/register", new { client_name = name, redirect_uris = new[] { redirect }, token_endpoint_auth_method = method, grant_types = new[] { "authorization_code", "refresh_token" }, response_types = new[] { "code" } });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var json = await ReadJsonAsync(response);
        return (json.GetProperty("client_id").GetString()!, json.TryGetProperty("client_secret", out var s) ? s.GetString() : null);
    }

    /// <summary>A browser with a cookie session and an active workspace.</summary>
    private async Task<(HttpClient Browser, string Email, string UserId, string OrgId)> SignedInBrowserAsync(bool withOrg = true)
    {
        var browser = _factory.Browser();
        var (email, token, userId) = await _factory.SignUpAsync(browser, "Agent Owner");
        var orgId = "";
        if (withOrg)
        {
            var created = await browser.SendAsync(Bearer(HttpMethod.Post, "/v1/org", token, new { name = "Agent Workspace" }));
            orgId = (await ReadJsonAsync(created)).GetProperty("organization").GetProperty("id").GetString()!;
        }
        return (browser, email, userId, orgId);
    }

    private static Dictionary<string, string> Query(string location)
    {
        var uri = new Uri(location, UriKind.RelativeOrAbsolute);
        var q = uri.IsAbsoluteUri ? uri.Query : location[(location.IndexOf('?') + 1)..];
        return Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(q.TrimStart('?')).ToDictionary(p => p.Key, p => p.Value.ToString());
    }

    private static string AuthorizeUrl(string clientId, string challenge, string scope = "mcp:read mcp:write offline_access", string state = "st", string redirect = Redirect, string? extra = null) =>
        $"/api/auth/oauth2/authorize?response_type=code&client_id={clientId}&redirect_uri={Uri.EscapeDataString(redirect)}&scope={Uri.EscapeDataString(scope)}&state={state}&code_challenge={challenge}&code_challenge_method=S256&resource={Uri.EscapeDataString(Resource)}{extra}";

    /// <summary>Drives authorize → consent and returns the authorization code.</summary>
    private static async Task<(string Code, string OauthQuery)> GetCodeAsync(HttpClient browser, string clientId, string challenge, string scope = "mcp:read mcp:write offline_access", string redirect = Redirect)
    {
        var authorize = await browser.GetAsync(AuthorizeUrl(clientId, challenge, scope, redirect: redirect));
        Assert.Equal(HttpStatusCode.Redirect, authorize.StatusCode);
        var location = authorize.Headers.Location!.ToString();
        Assert.Contains("/mcp/consent?", location);
        var query = location[(location.IndexOf('?') + 1)..];
        var consent = await browser.PostAsJsonAsync("/api/auth/oauth2/consent", new { accept = true, scope, oauth_query = query });
        Assert.Equal(HttpStatusCode.OK, consent.StatusCode);
        var code = Query((await ReadJsonAsync(consent)).GetProperty("url").GetString()!)["code"];
        return (code, query);
    }

    private static Task<HttpResponseMessage> TokenAsync(HttpClient http, Dictionary<string, string> form, string? basic = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/oauth2/token") { Content = new FormUrlEncodedContent(form) };
        if (basic is not null) request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", basic);
        return http.SendAsync(request);
    }

    private static Dictionary<string, string> CodeForm(string clientId, string code, string verifier, string? resource = Resource)
    {
        var form = new Dictionary<string, string> { ["grant_type"] = "authorization_code", ["code"] = code, ["redirect_uri"] = Redirect, ["client_id"] = clientId, ["code_verifier"] = verifier };
        if (resource is not null) form["resource"] = resource;
        return form;
    }

    private async Task<(JsonElement Tokens, string ClientId, HttpClient Browser, string UserId, string OrgId, string Email)> FullFlowAsync(string scope = "mcp:read mcp:write offline_access")
    {
        var (browser, email, userId, orgId) = await SignedInBrowserAsync();
        var (clientId, _) = await RegisterAsync(browser);
        var (verifier, challenge) = Pkce();
        var (code, _) = await GetCodeAsync(browser, clientId, challenge, scope);
        var token = await TokenAsync(browser, CodeForm(clientId, code, verifier));
        Assert.Equal(HttpStatusCode.OK, token.StatusCode);
        return (await ReadJsonAsync(token), clientId, browser, userId, orgId, email);
    }

    private static async Task<JsonElement> McpAsync(HttpClient http, string token, object body, HttpStatusCode expected = HttpStatusCode.OK)
    {
        var request = Bearer(HttpMethod.Post, "/mcp/agent", token, body);
        var response = await http.SendAsync(request);
        Assert.Equal(expected, response.StatusCode);
        return expected == HttpStatusCode.OK ? await ReadJsonAsync(response) : default;
    }

    // ---------- metadata & registration ----------

    [Fact]
    public async Task Discovery_documents_describe_a_PKCE_only_authorization_server_on_the_web_origin()
    {
        var http = _factory.Plain();
        foreach (var path in new[] { "/.well-known/oauth-authorization-server", "/.well-known/oauth-authorization-server/api/auth", "/api/auth/.well-known/oauth-authorization-server", "/.well-known/openid-configuration/api/auth" })
        {
            var doc = await ReadJsonAsync(await http.GetAsync(path));
            Assert.Equal("http://localhost/api/auth", doc.GetProperty("issuer").GetString());
            Assert.Equal("http://localhost/api/auth/oauth2/token", doc.GetProperty("token_endpoint").GetString());
            Assert.Equal(["S256"], doc.GetProperty("code_challenge_methods_supported").EnumerateArray().Select(e => e.GetString()!).ToArray());
            Assert.DoesNotContain("implicit", doc.GetRawText());
            Assert.DoesNotContain("password", doc.GetProperty("grant_types_supported").GetRawText());
        }

        var resource = await ReadJsonAsync(await http.GetAsync("/.well-known/oauth-protected-resource/mcp/agent"));
        Assert.Equal(Resource, resource.GetProperty("resource").GetString());
        Assert.Equal("http://localhost/api/auth", resource.GetProperty("authorization_servers")[0].GetString());
    }

    [Fact]
    public async Task Registration_enforces_the_redirect_policy_and_stores_secrets_hashed()
    {
        var http = _factory.Plain();
        async Task<HttpStatusCode> TryAsync(params string[] redirects) =>
            (await http.PostAsJsonAsync("/register", new { client_name = "x", redirect_uris = redirects, token_endpoint_auth_method = "none" })).StatusCode;

        Assert.Equal(HttpStatusCode.Created, await TryAsync("http://127.0.0.1:1234/cb"));
        Assert.Equal(HttpStatusCode.Created, await TryAsync("http://localhost/cb"));
        Assert.Equal(HttpStatusCode.Created, await TryAsync("https://agent.example/callback"));
        Assert.Equal(HttpStatusCode.Created, await TryAsync("cursor://anysphere.cursor-mcp/oauth/callback"));
        Assert.Equal(HttpStatusCode.BadRequest, await TryAsync("http://attacker.example/cb"));
        Assert.Equal(HttpStatusCode.BadRequest, await TryAsync("https://agent.example/cb#frag"));
        Assert.Equal(HttpStatusCode.BadRequest, await TryAsync("javascript:alert(1)"));
        Assert.Equal(HttpStatusCode.BadRequest, await TryAsync("evil://app/cb"));
        Assert.Equal(HttpStatusCode.BadRequest, await TryAsync());

        var bad = await http.PostAsJsonAsync("/register", new { redirect_uris = new[] { Redirect }, grant_types = new[] { "password" } });
        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
        var scope = await http.PostAsJsonAsync("/register", new { redirect_uris = new[] { Redirect }, scope = "mcp:read admin" });
        Assert.Equal(HttpStatusCode.BadRequest, scope.StatusCode);

        var (clientId, secret) = await RegisterAsync(http, "client_secret_basic", "https://agent.example/callback");
        Assert.StartsWith("ow_mcp_cs_", secret);
        Assert.DoesNotContain(secret!, _factory.WithDb(db => db.OAuthClients.Select(c => c.SecretHash).ToList()));
        Assert.Contains(Ids.Sha256Hex(secret!), _factory.WithDb(db => db.OAuthClients.Where(c => c.Id == clientId).Select(c => c.SecretHash).ToList()));
    }

    // ---------- authorize ----------

    [Fact]
    public async Task Authorize_refuses_untrusted_requests_before_redirecting_and_reports_the_rest_to_the_client()
    {
        var (browser, _, _, _) = await SignedInBrowserAsync();
        var (clientId, _) = await RegisterAsync(browser);
        var (_, challenge) = Pkce();

        var unknown = await browser.GetAsync(AuthorizeUrl("nope", challenge));
        Assert.Equal(HttpStatusCode.BadRequest, unknown.StatusCode);
        var wrongRedirect = await browser.GetAsync(AuthorizeUrl(clientId, challenge, redirect: "http://127.0.0.1:9999/other"));
        Assert.Equal(HttpStatusCode.BadRequest, wrongRedirect.StatusCode);
        var otherHost = await browser.GetAsync(AuthorizeUrl(clientId, challenge, redirect: "http://attacker.example/callback"));
        Assert.Equal(HttpStatusCode.BadRequest, otherHost.StatusCode);

        var noResource = await browser.GetAsync(AuthorizeUrl(clientId, challenge).Replace($"&resource={Uri.EscapeDataString(Resource)}", ""));
        Assert.Equal(HttpStatusCode.BadRequest, noResource.StatusCode);
        Assert.Equal("invalid_target", (await ReadJsonAsync(noResource)).GetProperty("error").GetString());
        var foreign = await browser.GetAsync(AuthorizeUrl(clientId, challenge).Replace(Uri.EscapeDataString(Resource), Uri.EscapeDataString("https://other.example/mcp")));
        Assert.Equal("invalid_target", (await ReadJsonAsync(foreign)).GetProperty("error").GetString());

        // The redirect URI is trusted now, so these come back to the client with state.
        async Task<Dictionary<string, string>> ErrorRedirectAsync(string url)
        {
            var response = await browser.GetAsync(url);
            Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
            Assert.StartsWith(Redirect, response.Headers.Location!.ToString());
            return Query(response.Headers.Location!.ToString());
        }
        Assert.Equal("invalid_request", (await ErrorRedirectAsync(AuthorizeUrl(clientId, challenge).Replace("code_challenge_method=S256", "code_challenge_method=plain")))["error"]);
        Assert.Equal("invalid_request", (await ErrorRedirectAsync(AuthorizeUrl(clientId, challenge).Replace($"&code_challenge={challenge}", "")))["error"]);
        var badScope = await ErrorRedirectAsync(AuthorizeUrl(clientId, challenge, scope: "mcp:read admin"));
        Assert.Equal("invalid_scope", badScope["error"]);
        Assert.Equal("st", badScope["state"]);
        Assert.Equal("unsupported_response_type", (await ErrorRedirectAsync(AuthorizeUrl(clientId, challenge).Replace("response_type=code", "response_type=token")))["error"]);
    }

    [Fact]
    public async Task A_registered_loopback_redirect_matches_on_any_port_but_not_any_path()
    {
        var (browser, _, _, _) = await SignedInBrowserAsync();
        var (clientId, _) = await RegisterAsync(browser);
        var (_, challenge) = Pkce();
        var anyPort = await browser.GetAsync(AuthorizeUrl(clientId, challenge, redirect: "http://127.0.0.1:54321/callback"));
        Assert.Equal(HttpStatusCode.Redirect, anyPort.StatusCode);
        Assert.Contains("/mcp/consent?", anyPort.Headers.Location!.ToString());
        var otherPath = await browser.GetAsync(AuthorizeUrl(clientId, challenge, redirect: "http://127.0.0.1:54321/steal"));
        Assert.Equal(HttpStatusCode.BadRequest, otherPath.StatusCode);
        var otherHost = await browser.GetAsync(AuthorizeUrl(clientId, challenge, redirect: "http://localhost:9999/callback"));
        Assert.Equal(HttpStatusCode.BadRequest, otherHost.StatusCode);
    }

    [Fact]
    public async Task Without_a_session_the_person_is_sent_to_sign_in_and_without_a_workspace_to_choose_one()
    {
        var anonymous = _factory.Plain();
        var (clientId, _) = await RegisterAsync(anonymous);
        var (_, challenge) = Pkce();
        var toLogin = await anonymous.GetAsync(AuthorizeUrl(clientId, challenge));
        Assert.Equal(HttpStatusCode.Redirect, toLogin.StatusCode);
        var loginLocation = toLogin.Headers.Location!.ToString();
        Assert.StartsWith("http://localhost/?", loginLocation);
        Assert.Contains("sig=", loginLocation);

        var (browser, _, _, _) = await SignedInBrowserAsync(withOrg: false);
        var toOrg = await browser.GetAsync(AuthorizeUrl(clientId, challenge));
        Assert.StartsWith("http://localhost/mcp/select-organization?", toOrg.Headers.Location!.ToString());
    }

    [Fact]
    public async Task The_signed_query_cannot_be_altered_forged_or_replayed_after_it_expires()
    {
        var (browser, _, _, _) = await SignedInBrowserAsync();
        var (clientId, _) = await RegisterAsync(browser, name: "Honest Agent");
        var (_, challenge) = Pkce();
        var location = (await browser.GetAsync(AuthorizeUrl(clientId, challenge))).Headers.Location!.ToString();
        var query = location[(location.IndexOf('?') + 1)..];

        async Task<HttpStatusCode> PreloginAsync(string q) =>
            (await browser.PostAsJsonAsync("/api/auth/oauth2/public-client-prelogin", new { client_id = clientId, oauth_query = q })).StatusCode;
        Assert.Equal(HttpStatusCode.OK, await PreloginAsync(query));
        Assert.Equal(HttpStatusCode.BadRequest, await PreloginAsync(query.Replace("scope=", "scope=mcp%3Awrite%20")));
        Assert.Equal(HttpStatusCode.BadRequest, await PreloginAsync(query.Replace("sig=", "sig=A")));
        Assert.Equal(HttpStatusCode.BadRequest, await PreloginAsync(query + "&state=extra"));
        Assert.Equal(HttpStatusCode.BadRequest, await PreloginAsync(""));

        var consent = await browser.PostAsJsonAsync("/api/auth/oauth2/consent", new { accept = true, oauth_query = query.Replace("redirect_uri=", "x=1&redirect_uri=") });
        Assert.Equal(HttpStatusCode.BadRequest, consent.StatusCode);
        Assert.Equal("invalid_signature", (await ReadJsonAsync(consent)).GetProperty("error").GetString());

        var signer = new SignedQuery(Options.Create(new AuthOptions { Secret = Secret }));
        var expired = signer.Sign([new("a", "b")], TimeSpan.FromSeconds(-1));
        Assert.Null(signer.Verify(expired));
        Assert.NotNull(signer.Verify(signer.Sign([new("a", "b")], TimeSpan.FromMinutes(1))));
        // A different secret produces a different signature.
        var other = new SignedQuery(Options.Create(new AuthOptions { Secret = "another-secret-0123456789-abcdefghijklmnop" }));
        Assert.Null(other.Verify(signer.Sign([new("a", "b")], TimeSpan.FromMinutes(1))));
    }

    [Fact]
    public async Task Consent_needs_a_session_and_can_be_denied()
    {
        var (browser, _, _, _) = await SignedInBrowserAsync();
        var (clientId, _) = await RegisterAsync(browser);
        var (_, challenge) = Pkce();
        var location = (await browser.GetAsync(AuthorizeUrl(clientId, challenge, state: "deny-state"))).Headers.Location!.ToString();
        var query = location[(location.IndexOf('?') + 1)..];

        var anonymous = await _factory.Plain().PostAsJsonAsync("/api/auth/oauth2/consent", new { accept = true, oauth_query = query });
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

        var denied = await browser.PostAsJsonAsync("/api/auth/oauth2/consent", new { accept = false, oauth_query = query });
        var url = (await ReadJsonAsync(denied)).GetProperty("url").GetString()!;
        Assert.StartsWith(Redirect, url);
        var q = Query(url);
        Assert.Equal("access_denied", q["error"]);
        Assert.Equal("deny-state", q["state"]);
        Assert.False(q.ContainsKey("code"));

        var tooMuch = await browser.PostAsJsonAsync("/api/auth/oauth2/consent", new { accept = true, scope = "mcp:read mcp:write offline_access openid", oauth_query = query });
        Assert.Equal(HttpStatusCode.BadRequest, tooMuch.StatusCode);
    }

    [Fact]
    public async Task A_second_authorization_skips_consent_unless_the_client_asks_to_prompt()
    {
        var (browser, _, _, _) = await SignedInBrowserAsync();
        var (clientId, _) = await RegisterAsync(browser);
        var (_, c1) = Pkce();
        await GetCodeAsync(browser, clientId, c1);

        var (_, c2) = Pkce();
        var again = await browser.GetAsync(AuthorizeUrl(clientId, c2));
        Assert.StartsWith(Redirect + "?", again.Headers.Location!.ToString());
        Assert.False(string.IsNullOrEmpty(Query(again.Headers.Location.ToString())["code"]));

        var prompted = await browser.GetAsync(AuthorizeUrl(clientId, c2, extra: "&prompt=consent"));
        Assert.Contains("/mcp/consent?", prompted.Headers.Location!.ToString());
    }

    // ---------- tokens ----------

    [Fact]
    public async Task The_access_token_is_a_signed_JWT_that_verifies_against_the_published_JWKS()
    {
        var (tokens, clientId, browser, userId, orgId, _) = await FullFlowAsync();
        var jwt = tokens.GetProperty("access_token").GetString()!;
        Assert.Equal("Bearer", tokens.GetProperty("token_type").GetString());
        Assert.Equal(2700, tokens.GetProperty("expires_in").GetInt32());
        Assert.StartsWith("ow_mcp_rt_", tokens.GetProperty("refresh_token").GetString());

        // Verify with nothing but the public JWKS, the way a third party would.
        var parts = jwt.Split('.');
        var header = JsonDocument.Parse(Convert.FromBase64String(Pad(parts[0]))).RootElement;
        var jwks = await ReadJsonAsync(await browser.GetAsync("/api/auth/jwks"));
        Assert.DoesNotContain("\"d\"", jwks.GetRawText());
        var jwk = jwks.GetProperty("keys").EnumerateArray().Single(k => k.GetProperty("kid").GetString() == header.GetProperty("kid").GetString());
        Assert.Equal("ES256", header.GetProperty("alg").GetString());
        using var ecdsa = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = Convert.FromBase64String(Pad(jwk.GetProperty("x").GetString()!)), Y = Convert.FromBase64String(Pad(jwk.GetProperty("y").GetString()!)) } });
        Assert.True(ecdsa.VerifyData(Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"), Convert.FromBase64String(Pad(parts[2])), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

        var claims = JsonDocument.Parse(Convert.FromBase64String(Pad(parts[1]))).RootElement;
        Assert.Equal("http://localhost/api/auth", claims.GetProperty("iss").GetString());
        Assert.Equal(Resource, claims.GetProperty("aud").GetString());
        Assert.Equal(userId, claims.GetProperty("sub").GetString());
        Assert.Equal(clientId, claims.GetProperty("azp").GetString());
        Assert.Equal(orgId, claims.GetProperty("org_id").GetString());
        Assert.Equal("mcp:read mcp:write offline_access", claims.GetProperty("scope").GetString());
        var lifetime = claims.GetProperty("exp").GetInt64() - claims.GetProperty("iat").GetInt64();
        Assert.Equal(2700, lifetime);
    }

    private static string Pad(string b64url) { var s = b64url.Replace('-', '+').Replace('_', '/'); return s.PadRight(s.Length + (4 - s.Length % 4) % 4, '='); }

    [Fact]
    public async Task PKCE_is_enforced_and_codes_are_bound_to_their_client_and_redirect()
    {
        var (browser, _, _, _) = await SignedInBrowserAsync();
        var (clientId, _) = await RegisterAsync(browser);
        var (otherClient, _) = await RegisterAsync(browser);
        var (verifier, challenge) = Pkce();
        var (code, _) = await GetCodeAsync(browser, clientId, challenge);

        async Task<string?> ErrorOf(Dictionary<string, string> form) => (await ReadJsonAsync(await TokenAsync(browser, form))).GetProperty("error").GetString();
        Assert.Equal("invalid_grant", await ErrorOf(CodeForm(clientId, code, B64(RandomNumberGenerator.GetBytes(32)))));   // wrong verifier
        Assert.Equal("invalid_grant", await ErrorOf(CodeForm(clientId, code, "short")));                                      // malformed verifier
        Assert.Equal("invalid_grant", await ErrorOf(CodeForm(otherClient, code, verifier)));                                  // another client
        var wrongRedirect = CodeForm(clientId, code, verifier); wrongRedirect["redirect_uri"] = "http://127.0.0.1:9999/else";
        Assert.Equal("invalid_grant", await ErrorOf(wrongRedirect));
        Assert.Equal("invalid_target", await ErrorOf(CodeForm(clientId, code, verifier, resource: "https://other.example/mcp")));
        var noVerifier = CodeForm(clientId, code, verifier); noVerifier.Remove("code_verifier");
        Assert.Equal("invalid_grant", await ErrorOf(noVerifier));

        Assert.Equal(HttpStatusCode.OK, (await TokenAsync(browser, CodeForm(clientId, code, verifier))).StatusCode);
        Assert.Equal("unsupported_grant_type", await ErrorOf(new() { ["grant_type"] = "password", ["client_id"] = clientId, ["username"] = "a", ["password"] = "b" }));
    }

    [Fact]
    public async Task Replaying_a_code_fails_and_revokes_the_tokens_it_produced()
    {
        var (browser, _, _, _) = await SignedInBrowserAsync();
        var (clientId, _) = await RegisterAsync(browser);
        var (verifier, challenge) = Pkce();
        var (code, _) = await GetCodeAsync(browser, clientId, challenge);
        var first = await ReadJsonAsync(await TokenAsync(browser, CodeForm(clientId, code, verifier)));
        var refresh = first.GetProperty("refresh_token").GetString()!;

        var replay = await TokenAsync(browser, CodeForm(clientId, code, verifier));
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);

        var refreshed = await TokenAsync(browser, new() { ["grant_type"] = "refresh_token", ["refresh_token"] = refresh, ["client_id"] = clientId });
        Assert.Equal(HttpStatusCode.BadRequest, refreshed.StatusCode);
    }

    [Fact]
    public async Task Refresh_tokens_rotate_and_late_reuse_ends_the_whole_family()
    {
        var (tokens, clientId, browser, _, _, _) = await FullFlowAsync();
        var first = tokens.GetProperty("refresh_token").GetString()!;
        Task<HttpResponseMessage> Refresh(string t) =>
            TokenAsync(browser, new Dictionary<string, string> { ["grant_type"] = "refresh_token", ["refresh_token"] = t, ["client_id"] = clientId, ["resource"] = Resource });

        var second = await ReadJsonAsync(await Refresh(first));
        var secondRefresh = second.GetProperty("refresh_token").GetString()!;
        Assert.NotEqual(first, secondRefresh);
        Assert.NotEqual(tokens.GetProperty("access_token").GetString(), second.GetProperty("access_token").GetString());

        // Presenting the first token again after the reuse window means it leaked: everything from this grant is revoked.
        _factory.WithDb(db => { db.Database.ExecuteSqlRaw("UPDATE RefreshTokens SET RotatedAt = {0} WHERE Id = {1}", DateTime.UtcNow.AddMinutes(-5), Ids.Sha256Hex(first)); return 0; });
        Assert.Equal(HttpStatusCode.BadRequest, (await Refresh(first)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Refresh(secondRefresh)).StatusCode);
    }

    [Fact]
    public async Task A_refresh_can_narrow_scopes_but_never_add_them()
    {
        var (tokens, clientId, browser, _, _, _) = await FullFlowAsync("mcp:read offline_access");
        var refresh = tokens.GetProperty("refresh_token").GetString()!;
        Task<HttpResponseMessage> Refresh(string t, string scope) =>
            TokenAsync(browser, new() { ["grant_type"] = "refresh_token", ["refresh_token"] = t, ["client_id"] = clientId, ["scope"] = scope });

        Assert.Equal(HttpStatusCode.BadRequest, (await Refresh(refresh, "mcp:read mcp:write")).StatusCode);
        var narrowed = await ReadJsonAsync(await Refresh(refresh, "mcp:read"));
        Assert.Contains("mcp:read", narrowed.GetProperty("scope").GetString());
        Assert.DoesNotContain("mcp:write", narrowed.GetProperty("scope").GetString());
    }

    [Fact]
    public async Task Confidential_clients_must_authenticate_and_revocation_never_reveals_anything()
    {
        var (browser, _, _, _) = await SignedInBrowserAsync();
        var (clientId, secret) = await RegisterAsync(browser, "client_secret_basic", Redirect);
        var (verifier, challenge) = Pkce();
        var (code, _) = await GetCodeAsync(browser, clientId, challenge);
        var form = CodeForm(clientId, code, verifier);

        Assert.Equal(HttpStatusCode.Unauthorized, (await TokenAsync(browser, form)).StatusCode);
        var wrong = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{clientId}:wrong"));
        Assert.Equal(HttpStatusCode.Unauthorized, (await TokenAsync(browser, form, wrong)).StatusCode);
        var right = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{clientId}:{secret}"));
        var tokens = await ReadJsonAsync(await TokenAsync(browser, form, right));
        var refresh = tokens.GetProperty("refresh_token").GetString()!;

        var revoke = await browser.PostAsync("/api/auth/oauth2/revoke", new FormUrlEncodedContent(new Dictionary<string, string> { ["token"] = refresh, ["client_id"] = clientId, ["client_secret"] = secret! }));
        Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);
        var after = await TokenAsync(browser, new() { ["grant_type"] = "refresh_token", ["refresh_token"] = refresh }, right);
        Assert.Equal(HttpStatusCode.BadRequest, after.StatusCode);

        var garbage = await browser.PostAsync("/api/auth/oauth2/revoke", new FormUrlEncodedContent(new Dictionary<string, string> { ["token"] = "not-a-token", ["client_id"] = clientId, ["client_secret"] = secret! }));
        Assert.Equal(HttpStatusCode.OK, garbage.StatusCode);
    }

    // ---------- the MCP endpoint ----------

    [Fact]
    public async Task Mcp_requires_a_valid_token_and_tells_clients_where_to_sign_in()
    {
        var http = _factory.Plain();
        var anonymous = await http.PostAsJsonAsync("/mcp/agent", new { jsonrpc = "2.0", id = 1, method = "initialize" });
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        var challenge = anonymous.Headers.WwwAuthenticate.ToString();
        Assert.Contains("resource_metadata=\"http://localhost/.well-known/oauth-protected-resource/mcp/agent\"", challenge);

        var (tokens, _, browser, _, _, _) = await FullFlowAsync();
        var jwt = tokens.GetProperty("access_token").GetString()!;
        var ping = new { jsonrpc = "2.0", id = 1, method = "ping" };
        await McpAsync(browser, jwt, ping);

        // A flipped signature byte, an unsigned token, and a session token are all refused.
        var parts = jwt.Split('.');
        await McpAsync(browser, $"{parts[0]}.{parts[1]}.{(parts[2][0] == 'A' ? 'B' : 'A')}{parts[2][1..]}", ping, HttpStatusCode.Unauthorized);
        var none = B64(Encoding.UTF8.GetBytes("""{"alg":"none","typ":"at+jwt"}"""));
        await McpAsync(browser, $"{none}.{parts[1]}.", ping, HttpStatusCode.Unauthorized);
        var tampered = B64(Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(Convert.FromBase64String(Pad(parts[1]))).Replace("mcp:read", "mcp:admin")));
        await McpAsync(browser, $"{parts[0]}.{tampered}.{parts[2]}", ping, HttpStatusCode.Unauthorized);
        var (_, sessionToken, _) = await _factory.SignUpAsync(_factory.Plain());
        await McpAsync(browser, sessionToken, ping, HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task Mcp_speaks_the_protocol_and_runs_real_capabilities()
    {
        var (tokens, _, browser, userId, orgId, email) = await FullFlowAsync();
        var jwt = tokens.GetProperty("access_token").GetString()!;

        var init = await McpAsync(browser, jwt, new { jsonrpc = "2.0", id = 1, method = "initialize", @params = new { protocolVersion = "2025-03-26", capabilities = new { }, clientInfo = new { name = "t", version = "1" } } });
        Assert.Equal("2025-03-26", init.GetProperty("result").GetProperty("protocolVersion").GetString());
        Assert.Equal("openwork-agent", init.GetProperty("result").GetProperty("serverInfo").GetProperty("name").GetString());
        var unknownVersion = await McpAsync(browser, jwt, new { jsonrpc = "2.0", id = 2, method = "initialize", @params = new { protocolVersion = "1999-01-01" } });
        Assert.Equal("2025-06-18", unknownVersion.GetProperty("result").GetProperty("protocolVersion").GetString());

        var list = await McpAsync(browser, jwt, new { jsonrpc = "2.0", id = 3, method = "tools/list" });
        Assert.Equal(["search_capabilities", "execute_capability", "execute_capability_script"], list.GetProperty("result").GetProperty("tools").EnumerateArray().Select(t => t.GetProperty("name").GetString()!).ToArray());

        var search = await McpAsync(browser, jwt, new { jsonrpc = "2.0", id = 4, method = "tools/call", @params = new { name = "search_capabilities", arguments = new { query = "members" } } });
        var found = search.GetProperty("result").GetProperty("structuredContent").GetProperty("capabilities").EnumerateArray().Select(c => c.GetProperty("id").GetString()!).ToArray();
        Assert.Equal(["openwork.workspace.members"], found);

        var who = await McpAsync(browser, jwt, new { jsonrpc = "2.0", id = 5, method = "tools/call", @params = new { name = "execute_capability", arguments = new { capability_id = "openwork.whoami" } } });
        var result = who.GetProperty("result").GetProperty("structuredContent");
        Assert.False(who.GetProperty("result").GetProperty("isError").GetBoolean());
        Assert.Equal(email, result.GetProperty("user").GetProperty("email").GetString());
        Assert.Equal(orgId, result.GetProperty("organization").GetProperty("id").GetString());
        Assert.Equal("owner", result.GetProperty("role").GetString());
        Assert.Equal(userId, result.GetProperty("user").GetProperty("id").GetString());

        var unknown = await McpAsync(browser, jwt, new { jsonrpc = "2.0", id = 6, method = "tools/call", @params = new { name = "execute_capability", arguments = new { capability_id = "nope" } } });
        Assert.True(unknown.GetProperty("result").GetProperty("isError").GetBoolean());
        var missing = await McpAsync(browser, jwt, new { jsonrpc = "2.0", id = 7, method = "nope" });
        Assert.Equal(-32601, missing.GetProperty("error").GetProperty("code").GetInt32());

        // Notifications get no reply; a batch answers only the requests in it; GET is not offered.
        await McpAsync(browser, jwt, new { jsonrpc = "2.0", method = "notifications/initialized" }, HttpStatusCode.Accepted);
        var batch = await McpAsync(browser, jwt, new object[] { new { jsonrpc = "2.0", id = 8, method = "ping" }, new { jsonrpc = "2.0", method = "notifications/initialized" } });
        Assert.Equal(1, batch.GetArrayLength());
        var get = await browser.SendAsync(Bearer(HttpMethod.Get, "/mcp/agent", jwt));
        Assert.Equal(HttpStatusCode.MethodNotAllowed, get.StatusCode);
    }

    [Fact]
    public async Task Mcp_enforces_scopes_origins_and_current_membership()
    {
        var (tokens, _, browser, userId, orgId, _) = await FullFlowAsync("mcp:write offline_access");
        var writeOnly = tokens.GetProperty("access_token").GetString()!;
        var search = await McpAsync(browser, writeOnly, new { jsonrpc = "2.0", id = 1, method = "tools/call", @params = new { name = "search_capabilities", arguments = new { query = "" } } });
        Assert.True(search.GetProperty("result").GetProperty("isError").GetBoolean());
        Assert.Contains("insufficient_scope", search.GetProperty("result").GetProperty("content")[0].GetProperty("text").GetString());

        var (readTokens, _, readBrowser, readUser, readOrg, _) = await FullFlowAsync("mcp:read");
        Assert.DoesNotContain("refresh_token", readTokens.GetRawText()); // no offline_access, no refresh token
        var read = readTokens.GetProperty("access_token").GetString()!;

        var evil = Bearer(HttpMethod.Post, "/mcp/agent", read, new { jsonrpc = "2.0", id = 1, method = "ping" });
        evil.Headers.Add("Origin", "https://evil.example");
        Assert.Equal(HttpStatusCode.Forbidden, (await readBrowser.SendAsync(evil)).StatusCode);
        var loopback = Bearer(HttpMethod.Post, "/mcp/agent", read, new { jsonrpc = "2.0", id = 1, method = "ping" });
        loopback.Headers.Add("Origin", "http://localhost:6274");
        Assert.Equal(HttpStatusCode.OK, (await readBrowser.SendAsync(loopback)).StatusCode);

        // Leaving the workspace ends access immediately, even though the token has not expired.
        _factory.WithDb(db => { db.Database.ExecuteSqlRaw("DELETE FROM Members WHERE UserId = {0} AND OrganizationId = {1}", readUser, readOrg); return 0; });
        await McpAsync(readBrowser, read, new { jsonrpc = "2.0", id = 1, method = "ping" }, HttpStatusCode.Unauthorized);
        _ = (userId, orgId);
    }

    // ---------- first-party tokens ----------

    [Fact]
    public async Task First_party_tokens_are_minted_for_members_only_stored_hashed_and_work_on_mcp()
    {
        var browser = _factory.Plain();
        var (_, token, _) = await _factory.SignUpAsync(browser);
        var orgId = (await ReadJsonAsync(await browser.SendAsync(Bearer(HttpMethod.Post, "/v1/org", token, new { name = "Mint Org" })))).GetProperty("organization").GetProperty("id").GetString()!;

        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.PostAsJsonAsync("/v1/mcp/token", new { scopes = new[] { "mcp:read" } })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await browser.SendAsync(Bearer(HttpMethod.Post, "/v1/mcp/token", token, new { scopes = new[] { "admin" } }))).StatusCode);

        var (_, outsider, _) = await _factory.SignUpAsync(browser, "Outsider");
        var foreign = Bearer(HttpMethod.Post, "/v1/mcp/token", outsider, new { scopes = new[] { "mcp:read" } });
        foreign.Headers.Add("x-openwork-org-id", orgId);
        Assert.Equal(HttpStatusCode.Forbidden, (await browser.SendAsync(foreign)).StatusCode);

        var minted = await ReadJsonAsync(await browser.SendAsync(Bearer(HttpMethod.Post, "/v1/mcp/token", token, new { scopes = new[] { "mcp:read", "mcp:write" } })));
        var opaque = minted.GetProperty("token").GetString()!;
        Assert.StartsWith("ow_mcp_at_", opaque);
        Assert.StartsWith("ow_mcp_at_", minted.GetProperty("appHostToken").GetString());
        Assert.DoesNotContain(opaque, _factory.WithDb(db => db.McpAccessTokens.Select(t => t.Id).ToList()));

        var who = await McpAsync(browser, opaque, new { jsonrpc = "2.0", id = 1, method = "tools/call", @params = new { name = "execute_capability", arguments = new { capability_id = "openwork.whoami" } } });
        Assert.Equal(orgId, who.GetProperty("result").GetProperty("structuredContent").GetProperty("organization").GetProperty("id").GetString());
        // It is an MCP credential only: it is not a web session.
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.SendAsync(Bearer(HttpMethod.Get, "/v1/me", opaque))).StatusCode);
    }
}
