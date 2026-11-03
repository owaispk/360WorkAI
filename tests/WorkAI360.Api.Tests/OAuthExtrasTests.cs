using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using WorkAI360.Api.Domain.OAuthExtras;
using WorkAI360.Api.OAuth;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>A tiny server that publishes JWK Sets, so a client's <c>jwks_uri</c> can be fetched for real.</summary>
public sealed class FakeJwksServer : IAsyncDisposable
{
    private readonly WebApplication _app;
    public string Origin { get; private set; } = "";
    public Dictionary<string, JsonNode> Sets { get; } = [];
    public bool Down { get; set; }
    public string ContentType { get; set; } = "application/json";
    public int Calls;

    private FakeJwksServer(WebApplication app) => _app = app;

    public static FakeJwksServer Start()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        var app = builder.Build();
        var server = new FakeJwksServer(app);
        app.MapGet("/jwks/{name}", (string name, HttpContext ctx) =>
        {
            Interlocked.Increment(ref server.Calls);
            if (server.Down) return Results.StatusCode(500);
            return server.Sets.TryGetValue(name, out var set) ? Results.Content(set.ToJsonString(), server.ContentType) : Results.NotFound();
        });
        app.StartAsync().GetAwaiter().GetResult();
        server.Origin = app.Urls.First();
        return server;
    }

    public string Uri(string name) => $"{Origin}/jwks/{name}";
    public ValueTask DisposeAsync() => _app.DisposeAsync();
}

/// <summary>An API with a platform administrator, private JWKS addresses allowed and the fake JWKS server's origin trusted.</summary>
public class OAuthExtrasFactory : ApiFactory
{
    public const string AdminEmail = "oauth.admin@example.com";
    public FakeJwksServer Jwks { get; } = FakeJwksServer.Start();
    private readonly SemaphoreSlim _adminLock = new(1, 1);
    private string? _adminToken;

    protected override IEnumerable<KeyValuePair<string, string>> Settings =>
    [
        new("OAuth:ClientMetadata:AllowPrivateUrls", "true"),
        new("Auth:TrustedOrigins:0", Jwks.Origin),
        new("PlatformAdmin:BootstrapEmails", AdminEmail),
    ];

    /// <summary>The platform administrator's session token (the account is made once).</summary>
    public async Task<string> AdminTokenAsync()
    {
        await _adminLock.WaitAsync();
        try
        {
            if (_adminToken is not null) return _adminToken;
            var response = await Plain().PostAsJsonAsync("/api/auth/sign-up/email", new { name = "Platform Admin", email = AdminEmail, password = Password });
            response.EnsureSuccessStatusCode();
            return _adminToken = (await ReadJsonAsync(response)).GetProperty("token").GetString()!;
        }
        finally { _adminLock.Release(); }
    }

    public override async ValueTask DisposeAsync()
    {
        await Jwks.DisposeAsync();
        await base.DisposeAsync();
    }
}

public abstract class OAuthExtrasBase(OAuthExtrasFactory factory)
{
    protected const string Redirect = "http://127.0.0.1:9999/callback";
    protected const string Resource = "http://localhost/mcp/agent";
    protected const string TokenUrl = "http://localhost/api/auth/oauth2/token";
    protected const string Issuer = "http://localhost/api/auth";
    protected readonly OAuthExtrasFactory Factory = factory;

    protected static (string Verifier, string Challenge) Pkce()
    {
        var verifier = TestKey.B64(RandomNumberGenerator.GetBytes(32));
        return (verifier, TestKey.B64(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))));
    }

    protected async Task<(HttpClient Browser, string Token, string UserId, string OrgId)> SignedInAsync()
    {
        var browser = Factory.Browser();
        var (_, token, userId) = await Factory.SignUpAsync(browser, "Extras Person");
        var created = await browser.SendAsync(Bearer(HttpMethod.Post, "/v1/org", token, new { name = "Extras Space" }));
        return (browser, token, userId, (await ReadJsonAsync(created)).GetProperty("organization").GetProperty("id").GetString()!);
    }

    /// <summary>Registers a client (signed in when a browser is given) and returns the response.</summary>
    protected static async Task<(HttpStatusCode Status, JsonElement Body)> RegisterAsync(HttpClient http, object body)
    {
        var response = await http.PostAsJsonAsync("/register", body);
        return (response.StatusCode, await ReadJsonAsync(response));
    }

    protected static async Task<(string Id, string? Secret)> ClientCredentialsClientAsync(HttpClient signedIn, string method = "client_secret_basic", string[]? grants = null)
    {
        var (status, body) = await RegisterAsync(signedIn, new { client_name = "Machine", token_endpoint_auth_method = method, grant_types = grants ?? ["client_credentials"] });
        Assert.Equal(HttpStatusCode.Created, status);
        return (body.GetProperty("client_id").GetString()!, body.TryGetProperty("client_secret", out var s) ? s.GetString() : null);
    }

    protected async Task GrantAsync(string clientId, params string[] scopes)
    {
        var request = Bearer(HttpMethod.Put, $"/v1/admin/oauth-clients/{clientId}/client-credentials-scopes", await Factory.AdminTokenAsync(), new { scopes });
        var response = await Factory.Plain().SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    protected static string Basic(string id, string secret) => Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Uri.EscapeDataString(id)}:{Uri.EscapeDataString(secret)}"));

    protected static async Task<(HttpStatusCode Status, JsonElement Body, HttpResponseMessage Response)> TokenAsync(HttpClient http, Dictionary<string, string> form, string? basic = null, string? dpop = null, string[]? dpops = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/oauth2/token") { Content = new FormUrlEncodedContent(form) };
        if (basic is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Basic", basic);
        if (dpop is not null) request.Headers.Add("DPoP", dpop);
        if (dpops is not null) foreach (var d in dpops) request.Headers.Add("DPoP", d);
        var response = await http.SendAsync(request);
        return (response.StatusCode, await ReadJsonAsync(response), response);
    }

    protected static string Err(JsonElement body) => body.GetProperty("error").GetString()!;
    protected static string Desc(JsonElement body) => body.GetProperty("error_description").GetString()!;

    protected static JsonElement Payload(string jwt) => JsonDocument.Parse(Convert.FromBase64String(jwt.Split('.')[1].Replace('-', '+').Replace('_', '/').PadRight((jwt.Split('.')[1].Length + 3) / 4 * 4, '='))).RootElement.Clone();

    // ---------------------------------------------------------------- authorization code flow

    protected static string AuthorizeUrl(string clientId, string challenge, string scope = "mcp:read mcp:write offline_access", string? extra = null) =>
        $"/api/auth/oauth2/authorize?response_type=code&client_id={clientId}&redirect_uri={Uri.EscapeDataString(Redirect)}&scope={Uri.EscapeDataString(scope)}&state=st&code_challenge={challenge}&code_challenge_method=S256&resource={Uri.EscapeDataString(Resource)}{extra}";

    protected static async Task<string> GetCodeAsync(HttpClient browser, string clientId, string challenge, string scope = "mcp:read mcp:write offline_access", string? extra = null)
    {
        var authorize = await browser.GetAsync(AuthorizeUrl(clientId, challenge, scope, extra));
        Assert.Equal(HttpStatusCode.Redirect, authorize.StatusCode);
        var location = authorize.Headers.Location!.ToString();
        if (!location.Contains("/mcp/consent?"))
        {
            // Already consented: the code is in the redirect. Anything else is an error redirect, for the caller to inspect.
            var returned = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(new Uri(location).Query);
            return returned.TryGetValue("code", out var existing) ? existing.ToString() : location;
        }
        var query = location[(location.IndexOf('?') + 1)..];
        var consent = await browser.PostAsJsonAsync("/api/auth/oauth2/consent", new { accept = true, scope, oauth_query = query });
        Assert.Equal(HttpStatusCode.OK, consent.StatusCode);
        var url = (await ReadJsonAsync(consent)).GetProperty("url").GetString()!;
        return Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(new Uri(url).Query)["code"].ToString();
    }

    protected static Dictionary<string, string> CodeForm(string clientId, string code, string verifier) =>
        new() { ["grant_type"] = "authorization_code", ["code"] = code, ["redirect_uri"] = Redirect, ["client_id"] = clientId, ["code_verifier"] = verifier, ["resource"] = Resource };

    protected static async Task<string> PublicClientAsync(HttpClient browser, object? extra = null)
    {
        var body = new Dictionary<string, object?> { ["client_name"] = "Public", ["redirect_uris"] = new[] { Redirect }, ["token_endpoint_auth_method"] = "none" };
        if (extra is not null) foreach (var p in extra.GetType().GetProperties()) body[p.Name] = p.GetValue(extra);
        var (status, json) = await RegisterAsync(browser, body);
        Assert.Equal(HttpStatusCode.Created, status);
        return json.GetProperty("client_id").GetString()!;
    }

    /// <summary>Public client and a full authorization code exchange, optionally with a DPoP proof. Returns the token response.</summary>
    protected async Task<(JsonElement Tokens, string ClientId, HttpClient Browser)> BoundFlowAsync(TestKey? key, object? clientExtra = null)
    {
        var (browser, _, _, _) = await SignedInAsync();
        var clientId = await PublicClientAsync(browser, clientExtra);
        var (verifier, challenge) = Pkce();
        var code = await GetCodeAsync(browser, clientId, challenge);
        var (status, body, _) = await TokenAsync(browser, CodeForm(clientId, code, verifier), dpop: key?.DpopProof("POST", TokenUrl));
        Assert.Equal(HttpStatusCode.OK, status);
        return (body, clientId, browser);
    }

    protected static async Task<(HttpStatusCode Status, HttpResponseMessage Response)> McpAsync(HttpClient http, string token, string scheme = "Bearer", string? dpop = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/mcp/agent") { Content = JsonContent.Create(new { jsonrpc = "2.0", id = 1, method = "ping" }) };
        request.Headers.Authorization = new AuthenticationHeaderValue(scheme, token);
        if (dpop is not null) request.Headers.Add("DPoP", dpop);
        var response = await http.SendAsync(request);
        return (response.StatusCode, response);
    }
}

/// <summary>Registering clients for the extra grants and authentication methods, and what discovery says.</summary>
public sealed class OAuthExtrasRegistrationTests(OAuthExtrasFactory factory) : OAuthExtrasBase(factory), IClassFixture<OAuthExtrasFactory>
{
    [Fact]
    public async Task Discovery_lists_the_extras()
    {
        var doc = await ReadJsonAsync(await Factory.Plain().GetAsync("/.well-known/oauth-authorization-server"));
        string[] List(string name) => doc.GetProperty(name).EnumerateArray().Select(e => e.GetString()!).ToArray();
        Assert.Equal(["authorization_code", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer"], List("grant_types_supported"));
        Assert.Contains("private_key_jwt", List("token_endpoint_auth_methods_supported"));
        Assert.Contains("private_key_jwt", List("introspection_endpoint_auth_methods_supported"));
        Assert.Contains("private_key_jwt", List("revocation_endpoint_auth_methods_supported"));
        Assert.Equal(["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"], List("token_endpoint_auth_signing_alg_values_supported"));
        Assert.Equal(["ES256", "ES512", "PS256", "RS256"], List("dpop_signing_alg_values_supported"));
        var oidc = await ReadJsonAsync(await Factory.Plain().GetAsync("/.well-known/openid-configuration"));
        Assert.Contains("client_credentials", oidc.GetProperty("grant_types_supported").EnumerateArray().Select(e => e.GetString()));
    }

    [Fact]
    public async Task Only_a_signed_in_person_may_register_a_client_that_acts_as_itself()
    {
        var anonymous = await RegisterAsync(Factory.Plain(), new { client_name = "Machine", token_endpoint_auth_method = "client_secret_basic", grant_types = new[] { "client_credentials" } });
        Assert.Equal(HttpStatusCode.BadRequest, anonymous.Status);
        Assert.Equal("invalid_client_metadata", Err(anonymous.Body));
        Assert.Equal("client_credentials grant requires authenticated registration", Desc(anonymous.Body));

        var (browser, _, _, _) = await SignedInAsync();
        var signedIn = await RegisterAsync(browser, new { client_name = "Machine", token_endpoint_auth_method = "client_secret_basic", grant_types = new[] { "client_credentials" } });
        Assert.Equal(HttpStatusCode.Created, signedIn.Status);
        Assert.Equal(["client_credentials"], signedIn.Body.GetProperty("grant_types").EnumerateArray().Select(e => e.GetString()));
        Assert.Equal(0, signedIn.Body.GetProperty("response_types").GetArrayLength());
        Assert.StartsWith("ow_mcp_cs_", signedIn.Body.GetProperty("client_secret").GetString());
    }

    [Fact]
    public async Task Redirect_addresses_are_needed_only_for_the_authorization_code_grant()
    {
        var (browser, _, _, _) = await SignedInAsync();
        var none = await RegisterAsync(browser, new { client_name = "Code", token_endpoint_auth_method = "none", grant_types = new[] { "authorization_code" } });
        Assert.Equal(HttpStatusCode.BadRequest, none.Status);
        Assert.Equal("invalid_redirect_uri", Err(none.Body));
        var machine = await RegisterAsync(browser, new { client_name = "Machine", token_endpoint_auth_method = "client_secret_post", grant_types = new[] { "client_credentials" }, redirect_uris = Array.Empty<string>() });
        Assert.Equal(HttpStatusCode.Created, machine.Status);
        var bad = await RegisterAsync(browser, new { client_name = "Machine", token_endpoint_auth_method = "client_secret_post", grant_types = new[] { "client_credentials" }, redirect_uris = new[] { "javascript:alert(1)" } });
        Assert.Equal("invalid_redirect_uri", Err(bad.Body));
    }

    [Fact]
    public async Task Grants_the_reference_does_not_offer_and_inconsistent_response_types_are_refused()
    {
        var (browser, _, _, _) = await SignedInAsync();
        var implicitGrant = await RegisterAsync(browser, new { client_name = "X", redirect_uris = new[] { Redirect }, grant_types = new[] { "implicit" } });
        Assert.Equal("invalid_client_metadata", Err(implicitGrant.Body));
        Assert.Equal("unsupported grant_type implicit", Desc(implicitGrant.Body));
        var mismatch = await RegisterAsync(browser, new { client_name = "X", token_endpoint_auth_method = "client_secret_basic", grant_types = new[] { "client_credentials" }, response_types = new[] { "code" } });
        Assert.Equal("invalid_client_metadata", Err(mismatch.Body));
        Assert.Contains("'authorization_code' grant type must be included", Desc(mismatch.Body));
    }

    [Fact]
    public async Task A_private_key_jwt_client_needs_keys_inline_or_by_address_never_both()
    {
        using var key = TestKey.Ec();
        var (browser, _, _, _) = await SignedInAsync();
        var none = await RegisterAsync(browser, new { client_name = "K", token_endpoint_auth_method = "private_key_jwt", grant_types = new[] { "client_credentials" } });
        Assert.Equal("private_key_jwt requires either jwks or jwks_uri", Desc(none.Body));
        var both = await RegisterAsync(browser, new { client_name = "K", token_endpoint_auth_method = "private_key_jwt", grant_types = new[] { "client_credentials" }, jwks = key.Jwks(), jwks_uri = Factory.Jwks.Uri("x") });
        Assert.Equal("jwks and jwks_uri are mutually exclusive", Desc(both.Body));
        var ok = await RegisterAsync(browser, new { client_name = "K", token_endpoint_auth_method = "private_key_jwt", grant_types = new[] { "client_credentials" }, jwks = key.Jwks() });
        Assert.Equal(HttpStatusCode.Created, ok.Status);
        Assert.Equal("private_key_jwt", ok.Body.GetProperty("token_endpoint_auth_method").GetString());
        Assert.False(ok.Body.TryGetProperty("client_secret", out _));
        Assert.Equal(key.Kid, ok.Body.GetProperty("jwks").GetProperty("keys")[0].GetProperty("kid").GetString());
        // No secret is stored for such a client, only its public keys.
        var id = ok.Body.GetProperty("client_id").GetString()!;
        Assert.Null(Factory.WithDb(db => db.OAuthClients.Single(c => c.Id == id).SecretHash));
    }

    [Fact]
    public async Task Bad_key_sets_are_refused_with_the_references_reasons()
    {
        using var ec = TestKey.Ec();
        using var small = TestKey.Rsa(bits: 1024);
        var (browser, _, _, _) = await SignedInAsync();
        async Task<string> Reason(object jwks) => Desc((await RegisterAsync(browser, new { client_name = "K", token_endpoint_auth_method = "private_key_jwt", grant_types = new[] { "client_credentials" }, jwks })).Body);

        Assert.Equal("jwks must be an RFC 7517 JWK Set object with a non-empty keys array", await Reason(new { keys = Array.Empty<object>() }));
        Assert.Equal("jwks must be an RFC 7517 JWK Set object with a non-empty keys array", await Reason(new { other = 1 }));
        var withPrivate = ec.Jwk(); withPrivate["d"] = "AAAA";
        Assert.Equal("jwks must contain only public asymmetric keys", await Reason(new { keys = new[] { withPrivate } }));
        Assert.Equal("jwks must contain only public asymmetric keys", await Reason(new { keys = new[] { new { kty = "oct", k = "AAAA" } } }));
        Assert.Equal("jwks keys must be supported public JWKs with required key parameters", await Reason(new { keys = new[] { new { kty = "EC", crv = "secp256k1", x = "AAAA", y = "AAAA" } } }));
        Assert.Equal("jwks keys must be supported public JWKs with required key parameters", await Reason(new { keys = new[] { new { kty = "OKP", crv = "Ed25519", x = "AAAA" } } }));
        var wrongAlg = ec.Jwk(); wrongAlg["alg"] = "RS256";
        Assert.Contains("alg must be supported", await Reason(new { keys = new[] { wrongAlg } }));
        Assert.Contains("at least 2048", await Reason(new { keys = new[] { small.Jwk() } }));
        var offCurve = ec.Jwk(); offCurve["y"] = TestKey.B64(new byte[32]);
        Assert.Equal("jwks keys must be supported public JWKs with required key parameters", await Reason(new { keys = new[] { offCurve } }));
    }

    [Fact]
    public async Task A_jwks_uri_must_be_https_public_and_trusted()
    {
        var (browser, _, _, _) = await SignedInAsync();
        async Task<string> Reason(string uri) => Desc((await RegisterAsync(browser, new { client_name = "K", token_endpoint_auth_method = "private_key_jwt", grant_types = new[] { "client_credentials" }, jwks_uri = uri })).Body);
        Assert.Equal("jwks_uri must be a valid URL", await Reason("not a url"));
        Assert.Equal("jwks_uri must not contain credentials", await Reason("http://user:pw@127.0.0.1/jwks"));
        Assert.Equal("jwks_uri must not include a fragment component", await Reason(Factory.Jwks.Uri("a") + "#frag"));
        Assert.Equal("jwks_uri must belong to a trusted origin", await Reason("http://127.0.0.1:1/jwks"));
        Assert.Equal("jwks_uri must use HTTPS", await Reason("ftp://example.test/jwks"));
        using var key = TestKey.Ec();
        Factory.Jwks.Sets["reg"] = key.Jwks();
        var ok = await RegisterAsync(browser, new { client_name = "K", token_endpoint_auth_method = "private_key_jwt", grant_types = new[] { "client_credentials" }, jwks_uri = Factory.Jwks.Uri("reg") });
        Assert.Equal(HttpStatusCode.Created, ok.Status);
        Assert.Equal(Factory.Jwks.Uri("reg"), ok.Body.GetProperty("jwks_uri").GetString());
    }

    [Fact]
    public async Task A_client_may_ask_for_dpop_bound_tokens_and_must_say_so_with_a_boolean()
    {
        var (browser, _, _, _) = await SignedInAsync();
        var bad = await RegisterAsync(browser, new { client_name = "D", redirect_uris = new[] { Redirect }, dpop_bound_access_tokens = "yes" });
        Assert.Equal("dpop_bound_access_tokens must be a boolean", Desc(bad.Body));
        var ok = await RegisterAsync(browser, new { client_name = "D", redirect_uris = new[] { Redirect }, dpop_bound_access_tokens = true });
        Assert.True(ok.Body.GetProperty("dpop_bound_access_tokens").GetBoolean());
        var plain = await RegisterAsync(browser, new { client_name = "D", redirect_uris = new[] { Redirect } });
        Assert.False(plain.Body.TryGetProperty("dpop_bound_access_tokens", out _));
    }

    [Fact]
    public async Task Clients_registered_the_old_way_keep_the_old_grants()
    {
        var (browser, _, _, _) = await SignedInAsync();
        var id = await PublicClientAsync(browser);
        // A signed-in registration records its owner, but no grant list: the defaults (code and refresh) apply.
        Assert.Null(Factory.WithDb(db => db.Set<OAuthClientExtras>().Single(e => e.ClientId == id).GrantTypesJson));
        var machine = await TokenAsync(Factory.Plain(), new() { ["grant_type"] = "client_credentials", ["client_id"] = id });
        Assert.Equal("unauthorized_client", Err(machine.Body));
        Assert.Equal("client is not authorized to use grant type client_credentials", Desc(machine.Body));
        var unknown = await TokenAsync(Factory.Plain(), new() { ["grant_type"] = "password", ["client_id"] = id });
        Assert.Equal("unsupported_grant_type", Err(unknown.Body));
    }
}

/// <summary>The <c>client_credentials</c> grant.</summary>
public sealed class ClientCredentialsTests(OAuthExtrasFactory factory) : OAuthExtrasBase(factory), IClassFixture<OAuthExtrasFactory>
{
    [Fact]
    public async Task A_client_nobody_gave_scopes_is_refused_as_in_the_reference()
    {
        var (browser, _, _, _) = await SignedInAsync();
        var (id, secret) = await ClientCredentialsClientAsync(browser);
        var r = await TokenAsync(Factory.Plain(), new() { ["grant_type"] = "client_credentials" }, Basic(id, secret!));
        Assert.Equal(HttpStatusCode.BadRequest, r.Status);
        Assert.Equal("unauthorized_client", Err(r.Body));
        Assert.Equal("client has no authorized client_credentials scopes", Desc(r.Body));
        Assert.Equal("no-store", r.Response.Headers.CacheControl?.ToString());
    }

    [Fact]
    public async Task With_scopes_granted_the_client_gets_a_token_that_speaks_for_itself()
    {
        var (browser, _, _, _) = await SignedInAsync();
        var (id, secret) = await ClientCredentialsClientAsync(browser);
        await GrantAsync(id, "mcp:read", "mcp:write");
        var r = await TokenAsync(Factory.Plain(), new() { ["grant_type"] = "client_credentials" }, Basic(id, secret!));
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal("Bearer", r.Body.GetProperty("token_type").GetString());
        Assert.Equal("mcp:read mcp:write", r.Body.GetProperty("scope").GetString());
        Assert.Equal(2700, r.Body.GetProperty("expires_in").GetInt32());
        Assert.True(r.Body.TryGetProperty("expires_at", out _));
        Assert.False(r.Body.TryGetProperty("refresh_token", out _));
        Assert.False(r.Body.TryGetProperty("id_token", out _));
        var claims = Payload(r.Body.GetProperty("access_token").GetString()!);
        Assert.Equal(id, claims.GetProperty("sub").GetString());
        Assert.Equal(id, claims.GetProperty("azp").GetString());
        Assert.Equal(id, claims.GetProperty("client_id").GetString());
        Assert.Equal(Issuer, claims.GetProperty("iss").GetString());
        Assert.Equal(Resource, claims.GetProperty("aud").GetString());
        Assert.False(claims.TryGetProperty("org_id", out _));
        Assert.False(claims.TryGetProperty("token_use", out _));
        Assert.False(claims.TryGetProperty("cnf", out _));
    }

    [Fact]
    public async Task The_client_may_ask_for_fewer_scopes_but_never_more_or_a_persons()
    {
        var (browser, _, _, _) = await SignedInAsync();
        var (id, secret) = await ClientCredentialsClientAsync(browser);
        await GrantAsync(id, "mcp:read");
        var basic = Basic(id, secret!);
        Assert.Equal("mcp:read", (await TokenAsync(Factory.Plain(), new() { ["grant_type"] = "client_credentials", ["scope"] = "mcp:read" }, basic)).Body.GetProperty("scope").GetString());
        var more = await TokenAsync(Factory.Plain(), new() { ["grant_type"] = "client_credentials", ["scope"] = "mcp:read mcp:write" }, basic);
        Assert.Equal("invalid_scope", Err(more.Body));
        Assert.Equal("The following scopes are invalid: mcp:write", Desc(more.Body));
        var person = await TokenAsync(Factory.Plain(), new() { ["grant_type"] = "client_credentials", ["scope"] = "openid" }, basic);
        Assert.Equal("invalid_scope", Err(person.Body));
        Assert.Equal("mcp:read", (await TokenAsync(Factory.Plain(), new() { ["grant_type"] = "client_credentials", ["scope"] = "" }, basic)).Body.GetProperty("scope").GetString());
    }

    [Fact]
    public async Task The_client_authenticates_with_its_secret_in_the_header_or_the_form_and_nothing_else_does()
    {
        var (browser, _, _, _) = await SignedInAsync();
        var (id, secret) = await ClientCredentialsClientAsync(browser, "client_secret_post");
        await GrantAsync(id, "mcp:read");
        var post = await TokenAsync(Factory.Plain(), new() { ["grant_type"] = "client_credentials", ["client_id"] = id, ["client_secret"] = secret! });
        Assert.Equal(HttpStatusCode.OK, post.Status);
        var wrong = await TokenAsync(Factory.Plain(), new() { ["grant_type"] = "client_credentials", ["client_id"] = id, ["client_secret"] = secret + "x" });
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.Status);
        Assert.Equal("invalid_client", Err(wrong.Body));
        var none = await TokenAsync(Factory.Plain(), new() { ["grant_type"] = "client_credentials", ["client_id"] = id });
        Assert.Equal(HttpStatusCode.Unauthorized, none.Status);
    }

    [Fact]
    public async Task A_public_client_cannot_use_it_even_if_it_asks_for_the_grant()
    {
        var (browser, _, _, _) = await SignedInAsync();
        var (id, _) = await ClientCredentialsClientAsync(browser, "none");
        var r = await TokenAsync(Factory.Plain(), new() { ["grant_type"] = "client_credentials", ["client_id"] = id });
        Assert.Equal("unauthorized_client", Err(r.Body));
        Assert.Equal("public clients cannot use the client_credentials grant", Desc(r.Body));
    }

    [Fact]
    public async Task A_client_uses_only_the_grants_it_registered_for()
    {
        var (browser, _, _, _) = await SignedInAsync();
        var (id, secret) = await ClientCredentialsClientAsync(browser);
        var code = await TokenAsync(Factory.Plain(), new() { ["grant_type"] = "authorization_code", ["code"] = "x", ["code_verifier"] = new string('a', 43) }, Basic(id, secret!));
        Assert.Equal("unauthorized_client", Err(code.Body));
        Assert.Equal("client is not authorized to use grant type authorization_code", Desc(code.Body));
        var refresh = await TokenAsync(Factory.Plain(), new() { ["grant_type"] = "refresh_token", ["refresh_token"] = "x" }, Basic(id, secret!));
        Assert.Equal("unauthorized_client", Err(refresh.Body));
    }

    [Fact]
    public async Task A_resource_must_be_this_servers_and_defaults_to_it()
    {
        var (browser, _, _, _) = await SignedInAsync();
        var (id, secret) = await ClientCredentialsClientAsync(browser);
        await GrantAsync(id, "mcp:read");
        var basic = Basic(id, secret!);
        var ok = await TokenAsync(Factory.Plain(), new() { ["grant_type"] = "client_credentials", ["resource"] = "http://localhost/mcp" }, basic);
        Assert.Equal(Resource, Payload(ok.Body.GetProperty("access_token").GetString()!).GetProperty("aud").GetString());
        var foreign = await TokenAsync(Factory.Plain(), new() { ["grant_type"] = "client_credentials", ["resource"] = "https://elsewhere.example.test/api" }, basic);
        Assert.Equal("invalid_target", Err(foreign.Body));
    }

    [Fact]
    public async Task A_machine_token_is_no_way_into_the_mcp_endpoint_or_userinfo_but_its_client_can_introspect_it()
    {
        var (browser, _, _, _) = await SignedInAsync();
        var (id, secret) = await ClientCredentialsClientAsync(browser);
        await GrantAsync(id, "mcp:read");
        var token = (await TokenAsync(Factory.Plain(), new() { ["grant_type"] = "client_credentials" }, Basic(id, secret!))).Body.GetProperty("access_token").GetString()!;
        Assert.Equal(HttpStatusCode.Unauthorized, (await McpAsync(Factory.Plain(), token)).Status);
        var userinfo = await Factory.Plain().SendAsync(Bearer(HttpMethod.Get, "/api/auth/oauth2/userinfo", token));
        Assert.Equal(HttpStatusCode.Unauthorized, userinfo.StatusCode);

        async Task<JsonElement> Introspect(string clientId, string clientSecret)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/oauth2/introspect") { Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["token"] = token }) };
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Basic(clientId, clientSecret));
            return await ReadJsonAsync(await Factory.Plain().SendAsync(request));
        }
        var own = await Introspect(id, secret!);
        Assert.True(own.GetProperty("active").GetBoolean());
        Assert.Equal(id, own.GetProperty("client_id").GetString());
        Assert.Equal("Bearer", own.GetProperty("token_type").GetString());
        Assert.Equal("mcp:read", own.GetProperty("scope").GetString());
        var (otherId, otherSecret) = await ClientCredentialsClientAsync(browser);
        Assert.False((await Introspect(otherId, otherSecret!)).GetProperty("active").GetBoolean());
    }

    [Fact]
    public async Task A_person_token_is_not_taken_for_a_machine_token()
    {
        var (tokens, clientId, _) = await BoundFlowAsync(null);
        // The access token of a person's grant introspects through the person path with its own client only; the machine path never claims it.
        Assert.False(Payload(tokens.GetProperty("access_token").GetString()!).TryGetProperty("client_id", out _));
        Assert.NotEmpty(clientId);
    }

    [Fact]
    public async Task Only_a_platform_administrator_can_grant_scopes_and_the_request_is_checked()
    {
        var (browser, token, _, _) = await SignedInAsync();
        var (id, _) = await ClientCredentialsClientAsync(browser);
        var path = $"/v1/admin/oauth-clients/{id}/client-credentials-scopes";
        Assert.Equal(HttpStatusCode.Unauthorized, (await Factory.Plain().SendAsync(new HttpRequestMessage(HttpMethod.Put, path) { Content = JsonContent.Create(new { scopes = new[] { "mcp:read" } }) })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await Factory.Plain().SendAsync(Bearer(HttpMethod.Put, path, token, new { scopes = new[] { "mcp:read" } }))).StatusCode);

        var admin = await Factory.AdminTokenAsync();
        async Task<(HttpStatusCode, JsonElement)> Put(string url, object body) { var r = await Factory.Plain().SendAsync(Bearer(HttpMethod.Put, url, admin, body)); return (r.StatusCode, await ReadJsonAsync(r)); }
        Assert.Equal(HttpStatusCode.BadRequest, (await Put(path, new { scopes = "mcp:read" })).Item1);
        Assert.Equal("Unrecognized key: \"other\"", (await Put(path, new { scopes = new[] { "mcp:read" }, other = 1 })).Item2.GetProperty("message").GetString());
        var invalid = await Put(path, new { scopes = new[] { "openid", "bogus" } });
        Assert.Equal("invalid_scope", invalid.Item2.GetProperty("error").GetString());
        Assert.Contains("openid, bogus", invalid.Item2.GetProperty("message").GetString());
        Assert.Equal(HttpStatusCode.NotFound, (await Put("/v1/admin/oauth-clients/nope/client-credentials-scopes", new { scopes = new[] { "mcp:read" } })).Item1);

        var set = await Put(path, new { scopes = new[] { "mcp:read", "mcp:write", "mcp:read" } });
        Assert.Equal(HttpStatusCode.OK, set.Item1);
        Assert.Equal(["mcp:read", "mcp:write"], set.Item2.GetProperty("scopes").EnumerateArray().Select(e => e.GetString()));
        Assert.Equal("mcp:read mcp:write", Factory.WithDb(db => db.Set<OAuthClientExtras>().Single(e => e.ClientId == id).ClientCredentialsScope));
        Assert.Equal(HttpStatusCode.OK, (await Put(path, new { scopes = Array.Empty<string>() })).Item1);
        Assert.Null(Factory.WithDb(db => db.Set<OAuthClientExtras>().Single(e => e.ClientId == id).ClientCredentialsScope));
    }

    [Fact]
    public async Task Scopes_can_go_only_to_a_confidential_client_that_has_the_grant()
    {
        var (browser, _, _, _) = await SignedInAsync();
        var admin = await Factory.AdminTokenAsync();
        async Task<(HttpStatusCode, JsonElement)> Put(string id) { var r = await Factory.Plain().SendAsync(Bearer(HttpMethod.Put, $"/v1/admin/oauth-clients/{id}/client-credentials-scopes", admin, new { scopes = new[] { "mcp:read" } })); return (r.StatusCode, await ReadJsonAsync(r)); }
        var (publicId, _) = await ClientCredentialsClientAsync(browser, "none");
        Assert.Equal("public clients cannot be assigned client_credentials scopes", (await Put(publicId)).Item2.GetProperty("message").GetString());
        var codeOnly = await PublicClientAsync(browser);
        Assert.Equal("client_credentials_scopes requires the client_credentials grant", (await Put(codeOnly)).Item2.GetProperty("message").GetString());
    }
}

/// <summary><c>private_key_jwt</c> client authentication.</summary>
public sealed class PrivateKeyJwtTests(OAuthExtrasFactory factory) : OAuthExtrasBase(factory), IClassFixture<OAuthExtrasFactory>
{
    private async Task<(string Id, TestKey Key)> KeyClientAsync(TestKey? key = null, bool withKid = true)
    {
        key ??= TestKey.Ec();
        var (browser, _, _, _) = await SignedInAsync();
        var jwks = new JsonObject { ["keys"] = new JsonArray(key.Jwk(withKid)) };
        var (status, body) = await RegisterAsync(browser, new { client_name = "Signer", token_endpoint_auth_method = "private_key_jwt", grant_types = new[] { "client_credentials" }, jwks });
        Assert.Equal(HttpStatusCode.Created, status);
        var id = body.GetProperty("client_id").GetString()!;
        await GrantAsync(id, "mcp:read");
        return (id, key);
    }

    private static Dictionary<string, string> Form(string assertion, string? clientId = null, string type = ClientAssertionVerifier.AssertionType)
    {
        var form = new Dictionary<string, string> { ["grant_type"] = "client_credentials", ["client_assertion_type"] = type, ["client_assertion"] = assertion };
        if (clientId is not null) form["client_id"] = clientId;
        return form;
    }

    [Theory]
    [InlineData("ES256")]
    [InlineData("ES384")]
    [InlineData("ES512")]
    [InlineData("RS256")]
    [InlineData("RS384")]
    [InlineData("RS512")]
    [InlineData("PS256")]
    [InlineData("PS384")]
    [InlineData("PS512")]
    public async Task A_signed_assertion_authenticates_the_client_under_every_allowed_algorithm(string alg)
    {
        using var key = alg.StartsWith("ES", StringComparison.Ordinal) ? TestKey.Ec(alg) : TestKey.Rsa(alg);
        var (id, _) = await KeyClientAsync(key);
        var r = await TokenAsync(Factory.Plain(), Form(key.ClientAssertion(id, TokenUrl)));
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal(id, Payload(r.Body.GetProperty("access_token").GetString()!).GetProperty("sub").GetString());
    }

    [Fact]
    public async Task The_audience_may_be_the_endpoint_or_the_issuer_and_client_id_may_be_left_out_or_repeated()
    {
        using var key = TestKey.Ec();
        var (id, _) = await KeyClientAsync(key);
        Assert.Equal(HttpStatusCode.OK, (await TokenAsync(Factory.Plain(), Form(key.ClientAssertion(id, Issuer)))).Status);
        Assert.Equal(HttpStatusCode.OK, (await TokenAsync(Factory.Plain(), Form(key.ClientAssertion(id, TokenUrl), id))).Status);
        var wrongId = await TokenAsync(Factory.Plain(), Form(key.ClientAssertion(id, TokenUrl), "someone-else"));
        Assert.Equal("invalid_client", Err(wrongId.Body));
        Assert.Equal("client_id in body does not match assertion sub/iss", Desc(wrongId.Body));
    }

    [Fact]
    public async Task A_signature_by_another_key_is_refused()
    {
        using var key = TestKey.Ec();
        using var other = TestKey.Ec();
        var (id, _) = await KeyClientAsync(key);
        var r = await TokenAsync(Factory.Plain(), Form(other.ClientAssertion(id, TokenUrl, withKid: false)));
        Assert.Equal(HttpStatusCode.Unauthorized, r.Status);
        Assert.Equal("invalid_client", Err(r.Body));
        Assert.Equal("client assertion signature verification failed", Desc(r.Body));
        // Even carrying the right key's id does not help.
        Assert.Equal(HttpStatusCode.Unauthorized, (await TokenAsync(Factory.Plain(), Form(other.ClientAssertion(id, TokenUrl, header: h => h["kid"] = key.Kid)))).Status);
    }

    [Fact]
    public async Task An_unknown_key_id_and_a_tampered_assertion_are_refused()
    {
        using var key = TestKey.Ec();
        var (id, _) = await KeyClientAsync(key);
        Assert.Equal(HttpStatusCode.Unauthorized, (await TokenAsync(Factory.Plain(), Form(key.ClientAssertion(id, TokenUrl, header: h => h["kid"] = "nope")))).Status);
        var good = key.ClientAssertion(id, TokenUrl);
        var parts = good.Split('.');
        var forged = $"{parts[0]}.{TestKey.B64(JsonSerializer.Serialize(new { iss = id, sub = id, aud = TokenUrl, jti = "x", exp = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 100 }))}.{parts[2]}";
        Assert.Equal(HttpStatusCode.Unauthorized, (await TokenAsync(Factory.Plain(), Form(forged))).Status);
    }

    [Fact]
    public async Task Each_claim_is_checked_and_named()
    {
        using var key = TestKey.Ec();
        var (id, _) = await KeyClientAsync(key);
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        async Task<(HttpStatusCode, string)> Try(string assertion) { var r = await TokenAsync(Factory.Plain(), Form(assertion)); return (r.Status, Desc(r.Body)); }

        Assert.Equal((HttpStatusCode.BadRequest, "client assertion has expired"), await Try(key.ClientAssertion(id, TokenUrl, exp: now - 10)));
        Assert.Equal((HttpStatusCode.BadRequest, "client assertion exp is too far in the future (max 300s)"), await Try(key.ClientAssertion(id, TokenUrl, exp: now + 3600)));
        Assert.Equal((HttpStatusCode.BadRequest, "client assertion iat is too far in the past (max 300s)"), await Try(key.ClientAssertion(id, TokenUrl, iat: now - 3600)));
        Assert.Equal((HttpStatusCode.BadRequest, "client assertion must include exp claim"), await Try(key.ClientAssertion(id, TokenUrl, claims: c => c.Remove("exp"))));
        Assert.Equal((HttpStatusCode.BadRequest, "client assertion must include jti claim"), await Try(key.ClientAssertion(id, TokenUrl, claims: c => c.Remove("jti"))));
        Assert.Equal((HttpStatusCode.Unauthorized, "client assertion signature verification failed"), await Try(key.ClientAssertion(id, "https://elsewhere.example.test/token")));
        Assert.Equal((HttpStatusCode.Unauthorized, "client assertion signature verification failed"), await Try(key.ClientAssertion(id, TokenUrl, claims: c => c["iss"] = "another")));
        Assert.Equal((HttpStatusCode.BadRequest, "client assertion is not yet valid"), await Try(key.ClientAssertion(id, TokenUrl, claims: c => c["nbf"] = now + 3600)));
    }

    [Fact]
    public async Task An_assertion_works_once()
    {
        using var key = TestKey.Ec();
        var (id, _) = await KeyClientAsync(key);
        var assertion = key.ClientAssertion(id, TokenUrl);
        Assert.Equal(HttpStatusCode.OK, (await TokenAsync(Factory.Plain(), Form(assertion))).Status);
        var again = await TokenAsync(Factory.Plain(), Form(assertion));
        Assert.Equal(HttpStatusCode.BadRequest, again.Status);
        Assert.Equal("client assertion jti has already been used", Desc(again.Body));
        // A different assertion with a fresh jti still works.
        Assert.Equal(HttpStatusCode.OK, (await TokenAsync(Factory.Plain(), Form(key.ClientAssertion(id, TokenUrl)))).Status);
    }

    [Fact]
    public async Task The_same_assertion_sent_at_once_is_accepted_exactly_once()
    {
        using var key = TestKey.Ec();
        var (id, _) = await KeyClientAsync(key);
        var assertion = key.ClientAssertion(id, TokenUrl);
        var results = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => TokenAsync(Factory.Plain(), Form(assertion))));
        Assert.Equal(1, results.Count(r => r.Status == HttpStatusCode.OK));
        Assert.Equal(5, results.Count(r => r.Status == HttpStatusCode.BadRequest && Desc(r.Body).Contains("already been used")));
    }

    [Fact]
    public async Task Algorithms_that_are_not_asymmetric_or_not_allowed_are_refused_before_anything_is_looked_up()
    {
        using var key = TestKey.Ec();
        var (id, _) = await KeyClientAsync(key);
        var none = $"{TestKey.B64("{\"alg\":\"none\"}")}.{TestKey.B64(JsonSerializer.Serialize(new { iss = id, sub = id }))}.AAAA";
        Assert.Equal("unsupported assertion signing algorithm: none", Desc((await TokenAsync(Factory.Plain(), Form(none))).Body));
        var hmac = $"{TestKey.B64("{\"alg\":\"HS256\"}")}.{TestKey.B64(JsonSerializer.Serialize(new { iss = id, sub = id }))}.AAAA";
        Assert.Equal("unsupported assertion signing algorithm: HS256", Desc((await TokenAsync(Factory.Plain(), Form(hmac))).Body));
        var eddsa = $"{TestKey.B64("{\"alg\":\"EdDSA\"}")}.{TestKey.B64(JsonSerializer.Serialize(new { iss = id, sub = id }))}.AAAA";
        Assert.Equal("unsupported assertion signing algorithm: EdDSA", Desc((await TokenAsync(Factory.Plain(), Form(eddsa))).Body));
        Assert.Equal("malformed client assertion: invalid JWT header", Desc((await TokenAsync(Factory.Plain(), Form("not.a.jwt"))).Body));
    }

    [Fact]
    public async Task The_assertion_type_and_the_pairing_of_fields_are_checked()
    {
        using var key = TestKey.Ec();
        var (id, _) = await KeyClientAsync(key);
        var assertion = key.ClientAssertion(id, TokenUrl);
        Assert.Equal("unsupported client_assertion_type", Desc((await TokenAsync(Factory.Plain(), Form(assertion, type: "urn:other"))).Body));
        var typeOnly = await TokenAsync(Factory.Plain(), new() { ["grant_type"] = "client_credentials", ["client_assertion_type"] = ClientAssertionVerifier.AssertionType });
        Assert.Equal("client_assertion and client_assertion_type must both be provided", Desc(typeOnly.Body));
    }

    [Fact]
    public async Task Only_one_way_of_authenticating_is_allowed_per_request()
    {
        using var key = TestKey.Ec();
        var (id, _) = await KeyClientAsync(key);
        var withBasic = await TokenAsync(Factory.Plain(), Form(key.ClientAssertion(id, TokenUrl)), Basic(id, "secret"));
        Assert.Equal("invalid_request", Err(withBasic.Body));
        Assert.Equal("A request must use only one client authentication method", Desc(withBasic.Body));
        var withSecret = Form(key.ClientAssertion(id, TokenUrl));
        withSecret["client_secret"] = "secret";
        Assert.Equal("invalid_request", Err((await TokenAsync(Factory.Plain(), withSecret)).Body));
    }

    [Fact]
    public async Task A_client_must_use_the_method_it_registered_for()
    {
        using var key = TestKey.Ec();
        var (keyId, _) = await KeyClientAsync(key);
        var secretFlow = await TokenAsync(Factory.Plain(), new() { ["grant_type"] = "client_credentials", ["client_id"] = keyId, ["client_secret"] = "guess" });
        Assert.Equal("invalid_client", Err(secretFlow.Body));
        Assert.Equal("client registered for private_key_jwt must use client_assertion", Desc(secretFlow.Body));

        var (browser, _, _, _) = await SignedInAsync();
        var (secretId, _) = await ClientCredentialsClientAsync(browser);
        var assertionFlow = await TokenAsync(Factory.Plain(), Form(key.ClientAssertion(secretId, TokenUrl)));
        Assert.Equal("client is not registered for private_key_jwt authentication", Desc(assertionFlow.Body));
        var unknown = await TokenAsync(Factory.Plain(), Form(key.ClientAssertion("no-such-client", TokenUrl)));
        Assert.Equal("unknown client", Desc(unknown.Body));
    }

    [Fact]
    public async Task A_client_with_two_keys_is_found_by_key_id_or_by_trying_both()
    {
        using var first = TestKey.Ec();
        using var second = TestKey.Rsa("PS256");
        var (browser, _, _, _) = await SignedInAsync();
        var jwks = new JsonObject { ["keys"] = new JsonArray(first.Jwk(withKid: true), second.Jwk(withKid: true)) };
        var (_, body) = await RegisterAsync(browser, new { client_name = "Two", token_endpoint_auth_method = "private_key_jwt", grant_types = new[] { "client_credentials" }, jwks });
        var id = body.GetProperty("client_id").GetString()!;
        await GrantAsync(id, "mcp:read");
        Assert.Equal(HttpStatusCode.OK, (await TokenAsync(Factory.Plain(), Form(first.ClientAssertion(id, TokenUrl)))).Status);
        Assert.Equal(HttpStatusCode.OK, (await TokenAsync(Factory.Plain(), Form(second.ClientAssertion(id, TokenUrl)))).Status);
        Assert.Equal(HttpStatusCode.OK, (await TokenAsync(Factory.Plain(), Form(second.ClientAssertion(id, TokenUrl, withKid: false)))).Status);
    }

    [Fact]
    public async Task A_key_that_names_its_algorithm_signs_only_that_one()
    {
        using var key = TestKey.Rsa("RS256");
        var (browser, _, _, _) = await SignedInAsync();
        var jwk = key.Jwk(withKid: true, withAlg: true);
        var (_, body) = await RegisterAsync(browser, new { client_name = "Pinned", token_endpoint_auth_method = "private_key_jwt", grant_types = new[] { "client_credentials" }, jwks = new { keys = new[] { jwk } } });
        var id = body.GetProperty("client_id").GetString()!;
        await GrantAsync(id, "mcp:read");
        Assert.Equal(HttpStatusCode.OK, (await TokenAsync(Factory.Plain(), Form(key.ClientAssertion(id, TokenUrl)))).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await TokenAsync(Factory.Plain(), Form(key.ClientAssertion(id, TokenUrl, alg: "PS256")))).Status);
    }

    [Fact]
    public async Task Keys_published_at_a_jwks_uri_are_fetched_cached_and_refetched_on_rotation()
    {
        using var first = TestKey.Ec();
        using var second = TestKey.Ec();
        var name = "rot-" + Guid.NewGuid().ToString("N")[..8];
        Factory.Jwks.Sets[name] = first.Jwks();
        var (browser, _, _, _) = await SignedInAsync();
        var (_, body) = await RegisterAsync(browser, new { client_name = "Remote", token_endpoint_auth_method = "private_key_jwt", grant_types = new[] { "client_credentials" }, jwks_uri = Factory.Jwks.Uri(name) });
        var id = body.GetProperty("client_id").GetString()!;
        await GrantAsync(id, "mcp:read");

        Assert.Equal(HttpStatusCode.OK, (await TokenAsync(Factory.Plain(), Form(first.ClientAssertion(id, TokenUrl)))).Status);
        var calls = Factory.Jwks.Calls;
        Assert.Equal(HttpStatusCode.OK, (await TokenAsync(Factory.Plain(), Form(first.ClientAssertion(id, TokenUrl)))).Status);
        Assert.Equal(calls, Factory.Jwks.Calls);   // cached

        // The client rotates its key: the new one is not in the cache, so the keys are fetched again.
        Factory.Jwks.Sets[name] = second.Jwks();
        Assert.Equal(HttpStatusCode.OK, (await TokenAsync(Factory.Plain(), Form(second.ClientAssertion(id, TokenUrl)))).Status);
        Assert.True(Factory.Jwks.Calls > calls);
        // And the old key no longer verifies once the new set is cached.
        Assert.Equal(HttpStatusCode.Unauthorized, (await TokenAsync(Factory.Plain(), Form(first.ClientAssertion(id, TokenUrl)))).Status);
    }

    [Fact]
    public async Task A_jwks_uri_that_cannot_be_read_gives_no_keys()
    {
        using var key = TestKey.Ec();
        var name = "bad-" + Guid.NewGuid().ToString("N")[..8];
        Factory.Jwks.Sets[name] = key.Jwks();
        var (browser, _, _, _) = await SignedInAsync();
        var (_, body) = await RegisterAsync(browser, new { client_name = "Remote", token_endpoint_auth_method = "private_key_jwt", grant_types = new[] { "client_credentials" }, jwks_uri = Factory.Jwks.Uri(name) });
        var id = body.GetProperty("client_id").GetString()!;
        await GrantAsync(id, "mcp:read");
        Factory.Jwks.ContentType = "text/html";
        try
        {
            var r = await TokenAsync(Factory.Plain(), Form(key.ClientAssertion(id, TokenUrl)));
            Assert.Equal("failed to fetch client JWKS", Desc(r.Body));
        }
        finally { Factory.Jwks.ContentType = "application/json"; }
        Factory.Jwks.Sets.Remove(name);
        Assert.Equal("failed to fetch client JWKS", Desc((await TokenAsync(Factory.Plain(), Form(key.ClientAssertion(id, TokenUrl)))).Body));
    }

    [Fact]
    public async Task The_same_authentication_works_at_introspection_and_revocation()
    {
        using var key = TestKey.Ec();
        var (id, _) = await KeyClientAsync(key);
        var token = (await TokenAsync(Factory.Plain(), Form(key.ClientAssertion(id, TokenUrl)))).Body.GetProperty("access_token").GetString()!;
        var introspect = await Factory.Plain().PostAsync("/api/auth/oauth2/introspect", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = token, ["client_assertion_type"] = ClientAssertionVerifier.AssertionType, ["client_assertion"] = key.ClientAssertion(id, "http://localhost/api/auth/oauth2/introspect"),
        }));
        var body = await ReadJsonAsync(introspect);
        Assert.True(body.GetProperty("active").GetBoolean());
        Assert.Equal(id, body.GetProperty("client_id").GetString());
        // An assertion made for the token endpoint is not good at another endpoint.
        var wrong = await Factory.Plain().PostAsync("/api/auth/oauth2/introspect", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = token, ["client_assertion_type"] = ClientAssertionVerifier.AssertionType, ["client_assertion"] = key.ClientAssertion(id, TokenUrl),
        }));
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        var revoke = await Factory.Plain().PostAsync("/api/auth/oauth2/revoke", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = token, ["client_assertion_type"] = ClientAssertionVerifier.AssertionType, ["client_assertion"] = key.ClientAssertion(id, "http://localhost/api/auth/oauth2/revoke"),
        }));
        Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);
    }

    [Fact]
    public async Task A_client_with_a_secret_still_cannot_introspect_with_someone_elses_assertion()
    {
        using var key = TestKey.Ec();
        var (id, _) = await KeyClientAsync(key);
        using var other = TestKey.Ec();
        var response = await Factory.Plain().PostAsync("/api/auth/oauth2/introspect", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["token"] = "x", ["client_assertion_type"] = ClientAssertionVerifier.AssertionType, ["client_assertion"] = other.ClientAssertion(id, "http://localhost/api/auth/oauth2/introspect", withKid: false),
        }));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Assertions_with_the_authorization_code_grant_work_for_a_client_that_has_it()
    {
        using var key = TestKey.Ec();
        var (browser, _, _, _) = await SignedInAsync();
        var jwks = new { keys = new[] { key.Jwk(withKid: true) } };
        var (_, body) = await RegisterAsync(browser, new { client_name = "Web", redirect_uris = new[] { Redirect }, token_endpoint_auth_method = "private_key_jwt", jwks });
        var id = body.GetProperty("client_id").GetString()!;
        var (verifier, challenge) = Pkce();
        var code = await GetCodeAsync(browser, id, challenge);
        var form = CodeForm(id, code, verifier);
        form.Remove("client_id");
        form["client_assertion_type"] = ClientAssertionVerifier.AssertionType;
        form["client_assertion"] = key.ClientAssertion(id, TokenUrl);
        var r = await TokenAsync(Factory.Plain(), form);
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.True(r.Body.TryGetProperty("refresh_token", out _));
    }
}
