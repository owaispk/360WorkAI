using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>
/// OpenID Connect on top of the OAuth provider: ID tokens, userinfo, introspection and RP-initiated logout, with an attack on each rule
/// (nonce binding, audience, scope-dependent claims, introspection as an oracle, forged tokens, who may log people out).
/// </summary>
public sealed class OidcTests : IClassFixture<ApiFactory>
{
    private const string Redirect = "http://127.0.0.1:9999/callback";
    private const string Bye = "http://127.0.0.1:9999/bye";
    private const string Resource = "http://localhost/mcp/agent";
    private const string Full = "openid profile email offline_access mcp:read";
    private readonly ApiFactory _factory;
    public OidcTests(ApiFactory factory) => _factory = factory;

    // ---------- helpers ----------

    private static string B64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static byte[] FromB64(string value) { var s = value.Replace('-', '+').Replace('_', '/'); return Convert.FromBase64String(s.PadRight(s.Length + (4 - s.Length % 4) % 4, '=')); }
    private static (string Verifier, string Challenge) Pkce() { var v = B64(RandomNumberGenerator.GetBytes(32)); return (v, B64(SHA256.HashData(Encoding.ASCII.GetBytes(v)))); }
    private static JsonElement Part(string jwt, int index) { using var doc = JsonDocument.Parse(FromB64(jwt.Split('.')[index])); return doc.RootElement.Clone(); }
    private static string Basic(string id, string secret) => Convert.ToBase64String(Encoding.UTF8.GetBytes($"{id}:{secret}"));

    private sealed record Client(string Id, string Secret)
    {
        public string BasicValue => Basic(Id, Secret);
    }

    private async Task<(HttpClient Browser, string Email, string UserId, string OrgId, string Token)> SignedInAsync(string name = "Ada Lovelace")
    {
        var browser = _factory.Browser();
        var (email, token, userId) = await _factory.SignUpAsync(browser, name);
        var created = await browser.SendAsync(Bearer(HttpMethod.Post, "/v1/org", token, new { name = "OIDC Workspace" }));
        return (browser, email, userId, (await ReadJsonAsync(created)).GetProperty("organization").GetProperty("id").GetString()!, token);
    }

    private static async Task<Client> RegisterAsync(HttpClient http, string method = "client_secret_basic", object? extra = null, string? bearer = null)
    {
        var body = new Dictionary<string, object?>
        {
            ["client_name"] = "OIDC Test Client", ["redirect_uris"] = new[] { Redirect }, ["token_endpoint_auth_method"] = method,
            ["grant_types"] = new[] { "authorization_code", "refresh_token" }, ["scope"] = "openid profile email offline_access mcp:read mcp:write",
        };
        if (extra is not null) foreach (var p in JsonSerializer.SerializeToElement(extra).EnumerateObject()) body[p.Name] = p.Value;
        var request = new HttpRequestMessage(HttpMethod.Post, "/register") { Content = JsonContent.Create(body) };
        if (bearer is not null) request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", bearer);
        var response = await http.SendAsync(request);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var json = await ReadJsonAsync(response);
        return new Client(json.GetProperty("client_id").GetString()!, json.TryGetProperty("client_secret", out var s) ? s.GetString()! : "");
    }

    private static async Task<(string Code, string Verifier, Uri Redirected)> AuthorizeAsync(HttpClient browser, Client client, string scope, string? nonce = "n-1")
    {
        var (verifier, challenge) = Pkce();
        var url = $"/api/auth/oauth2/authorize?response_type=code&client_id={client.Id}&redirect_uri={Uri.EscapeDataString(Redirect)}&scope={Uri.EscapeDataString(scope)}&state=st&code_challenge={challenge}&code_challenge_method=S256&resource={Uri.EscapeDataString(Resource)}"
            + (nonce is null ? "" : $"&nonce={Uri.EscapeDataString(nonce)}") + "&prompt=consent";
        var authorize = await browser.GetAsync(url);
        Assert.Equal(HttpStatusCode.Redirect, authorize.StatusCode);
        var location = authorize.Headers.Location!.ToString();
        var consent = await browser.PostAsJsonAsync("/api/auth/oauth2/consent", new { accept = true, scope, oauth_query = location[(location.IndexOf('?') + 1)..] });
        Assert.Equal(HttpStatusCode.OK, consent.StatusCode);
        var redirected = new Uri((await ReadJsonAsync(consent)).GetProperty("url").GetString()!);
        return (QueryHelpers.ParseQuery(redirected.Query)["code"].ToString(), verifier, redirected);
    }

    private static Task<HttpResponseMessage> TokenAsync(HttpClient http, Client client, Dictionary<string, string> form)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/oauth2/token") { Content = new FormUrlEncodedContent(form) };
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", client.BasicValue);
        return http.SendAsync(request);
    }

    private async Task<(JsonElement Tokens, HttpClient Browser, string UserId, string Email, Client Client)> FlowAsync(string scope = Full, string? nonce = "n-1", Client? client = null, (HttpClient Browser, string Email, string UserId, string OrgId, string Token)? person = null)
    {
        var p = person ?? await SignedInAsync();
        client ??= await RegisterAsync(p.Browser);
        var (code, verifier, _) = await AuthorizeAsync(p.Browser, client, scope, nonce);
        var token = await TokenAsync(p.Browser, client, new() { ["grant_type"] = "authorization_code", ["code"] = code, ["redirect_uri"] = Redirect, ["code_verifier"] = verifier, ["resource"] = Resource });
        Assert.Equal(HttpStatusCode.OK, token.StatusCode);
        return (await ReadJsonAsync(token), p.Browser, p.UserId, p.Email, client);
    }

    private static HttpRequestMessage Introspection(Client client, string token, bool viaBody = false)
    {
        var form = new Dictionary<string, string> { ["token"] = token };
        if (viaBody) { form["client_id"] = client.Id; form["client_secret"] = client.Secret; }
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/oauth2/introspect") { Content = new FormUrlEncodedContent(form) };
        if (!viaBody) request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", client.BasicValue);
        return request;
    }

    private async Task<(HttpStatusCode Status, JsonElement Body)> UserInfoAsync(string token)
    {
        var response = await _factory.Plain().SendAsync(Bearer(HttpMethod.Get, "/api/auth/oauth2/userinfo", token));
        return (response.StatusCode, await ReadJsonAsync(response));
    }

    private async Task<JsonElement> JwksAsync() => (await ReadJsonAsync(await _factory.Plain().GetAsync("/api/auth/jwks"))).GetProperty("keys");

    private static bool SignatureValid(string jwt, JsonElement jwks)
    {
        var parts = jwt.Split('.');
        var kid = Part(jwt, 0).GetProperty("kid").GetString();
        foreach (var key in jwks.EnumerateArray())
        {
            if (key.GetProperty("kid").GetString() != kid) continue;
            using var ecdsa = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = FromB64(key.GetProperty("x").GetString()!), Y = FromB64(key.GetProperty("y").GetString()!) } });
            return ecdsa.VerifyData(Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"), FromB64(parts[2]), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        return false;
    }

    // ---------- discovery ----------

    [Fact]
    public async Task Discovery_advertises_the_OIDC_endpoints_scopes_and_the_ID_token_algorithm()
    {
        foreach (var path in new[] { "/.well-known/openid-configuration/api/auth", "/.well-known/oauth-authorization-server", "/api/auth/.well-known/openid-configuration" })
        {
            var doc = await ReadJsonAsync(await _factory.Plain().GetAsync(path));
            Assert.Equal("http://localhost/api/auth/oauth2/userinfo", doc.GetProperty("userinfo_endpoint").GetString());
            Assert.Equal("http://localhost/api/auth/oauth2/introspect", doc.GetProperty("introspection_endpoint").GetString());
            Assert.Equal("http://localhost/api/auth/oauth2/end-session", doc.GetProperty("end_session_endpoint").GetString());
            Assert.Equal("public", Assert.Single(doc.GetProperty("subject_types_supported").EnumerateArray()).GetString());
            Assert.Equal("ES256", Assert.Single(doc.GetProperty("id_token_signing_alg_values_supported").EnumerateArray()).GetString());
            Assert.Contains("openid", doc.GetProperty("scopes_supported").EnumerateArray().Select(e => e.GetString()));
            Assert.DoesNotContain("none", doc.GetProperty("introspection_endpoint_auth_methods_supported").EnumerateArray().Select(e => e.GetString()));
            Assert.Contains("email_verified", doc.GetProperty("claims_supported").EnumerateArray().Select(e => e.GetString()));
        }
    }

    // ---------- ID token ----------

    [Fact]
    public async Task The_ID_token_is_signed_with_the_published_key_and_carries_the_reference_claims()
    {
        var flow = await FlowAsync(nonce: "nonce-xyz");
        var idToken = flow.Tokens.GetProperty("id_token").GetString()!;
        var header = Part(idToken, 0);
        Assert.Equal("ES256", header.GetProperty("alg").GetString());
        Assert.False(header.TryGetProperty("typ", out _));   // an ID token carries no "at+jwt" type
        Assert.True(SignatureValid(idToken, await JwksAsync()));

        var claims = Part(idToken, 1);
        Assert.Equal("http://localhost/api/auth", claims.GetProperty("iss").GetString());
        Assert.Equal(flow.UserId, claims.GetProperty("sub").GetString());
        Assert.Equal(flow.Client.Id, claims.GetProperty("aud").GetString());   // a string, the client id and nothing else
        Assert.Equal("nonce-xyz", claims.GetProperty("nonce").GetString());
        Assert.Equal("0", claims.GetProperty("acr").GetString());
        Assert.Equal(36000, claims.GetProperty("exp").GetInt64() - claims.GetProperty("iat").GetInt64());
        Assert.True(claims.GetProperty("auth_time").GetInt64() <= claims.GetProperty("iat").GetInt64());
        Assert.False(claims.TryGetProperty("email", out _));
        Assert.False(claims.TryGetProperty("name", out _));
        Assert.False(claims.TryGetProperty("sid", out _));   // only for clients that may log people out

        var digest = SHA256.HashData(Encoding.ASCII.GetBytes(flow.Tokens.GetProperty("access_token").GetString()!));
        Assert.Equal(B64(digest[..16]), claims.GetProperty("at_hash").GetString());
    }

    [Fact]
    public async Task The_nonce_comes_from_the_authorization_request_and_nothing_a_caller_adds_later_can_replace_it()
    {
        var person = await SignedInAsync();
        var client = await RegisterAsync(person.Browser);
        var (code, verifier, _) = await AuthorizeAsync(person.Browser, client, Full, "the-real-nonce");
        var token = await TokenAsync(person.Browser, client, new() { ["grant_type"] = "authorization_code", ["code"] = code, ["redirect_uri"] = Redirect, ["code_verifier"] = verifier, ["resource"] = Resource, ["nonce"] = "attacker-nonce" });
        Assert.Equal("the-real-nonce", Part((await ReadJsonAsync(token)).GetProperty("id_token").GetString()!, 1).GetProperty("nonce").GetString());
    }

    [Fact]
    public async Task A_request_without_a_nonce_gets_an_ID_token_without_one_and_a_request_without_openid_gets_no_ID_token()
    {
        var noNonce = await FlowAsync("openid mcp:read", nonce: null);
        Assert.False(Part(noNonce.Tokens.GetProperty("id_token").GetString()!, 1).TryGetProperty("nonce", out _));
        var noOpenId = await FlowAsync("mcp:read offline_access");
        Assert.False(noOpenId.Tokens.TryGetProperty("id_token", out _));
    }

    [Fact]
    public async Task A_refresh_re_issues_the_ID_token_for_the_same_sign_in_without_a_nonce()
    {
        var flow = await FlowAsync(nonce: "n-first");
        var first = Part(flow.Tokens.GetProperty("id_token").GetString()!, 1);
        var refreshed = await TokenAsync(flow.Browser, flow.Client, new() { ["grant_type"] = "refresh_token", ["refresh_token"] = flow.Tokens.GetProperty("refresh_token").GetString()!, ["resource"] = Resource });
        var again = Part((await ReadJsonAsync(refreshed)).GetProperty("id_token").GetString()!, 1);
        Assert.Equal(first.GetProperty("auth_time").GetInt64(), again.GetProperty("auth_time").GetInt64());
        Assert.Equal(flow.Client.Id, again.GetProperty("aud").GetString());
        Assert.False(again.TryGetProperty("nonce", out _));
    }

    [Fact]
    public async Task An_ID_token_is_never_audienced_to_another_client_even_for_the_same_person()
    {
        var person = await SignedInAsync();
        var a = await FlowAsync(person: person); var b = await FlowAsync(person: person);
        Assert.NotEqual(Part(a.Tokens.GetProperty("id_token").GetString()!, 1).GetProperty("aud").GetString(), Part(b.Tokens.GetProperty("id_token").GetString()!, 1).GetProperty("aud").GetString());
    }

    // ---------- userinfo ----------

    [Theory]
    [InlineData("openid", "sub")]
    [InlineData("openid email", "sub,email,email_verified")]
    [InlineData("openid profile", "sub,name,given_name,family_name")]
    [InlineData("openid profile email", "sub,name,given_name,family_name,email,email_verified")]
    public async Task Userinfo_returns_only_the_claims_the_granted_scopes_allow(string scope, string expectedClaims)
    {
        var flow = await FlowAsync(scope);
        var (status, body) = await UserInfoAsync(flow.Tokens.GetProperty("access_token").GetString()!);
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal(expectedClaims, string.Join(',', body.EnumerateObject().Select(p => p.Name)));
        Assert.Equal(flow.UserId, body.GetProperty("sub").GetString());
        if (expectedClaims.Contains("email")) Assert.Equal(flow.Email, body.GetProperty("email").GetString());
    }

    [Fact]
    public async Task Userinfo_needs_the_openid_scope()
    {
        var flow = await FlowAsync("mcp:read profile email");
        var (status, body) = await UserInfoAsync(flow.Tokens.GetProperty("access_token").GetString()!);
        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("invalid_scope", body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Userinfo_refuses_ID_tokens_forged_tokens_unsigned_tokens_and_tokens_signed_by_another_key()
    {
        var flow = await FlowAsync();
        var access = flow.Tokens.GetProperty("access_token").GetString()!;
        var parts = access.Split('.');

        // An ID token is for the client, not for the resource server.
        Assert.Equal(HttpStatusCode.Unauthorized, (await UserInfoAsync(flow.Tokens.GetProperty("id_token").GetString()!)).Status);
        // A payload with more scope or another subject: the signature no longer matches.
        var widened = JsonSerializer.Serialize(JsonSerializer.Deserialize<Dictionary<string, object>>(FromB64(parts[1]))!.ToDictionary(p => p.Key, p => p.Key == "sub" ? "usr_someone_else" : p.Value));
        Assert.Equal(HttpStatusCode.Unauthorized, (await UserInfoAsync($"{parts[0]}.{B64(Encoding.UTF8.GetBytes(widened))}.{parts[2]}")).Status);
        // alg "none".
        var none = $"{B64(Encoding.UTF8.GetBytes("{\"alg\":\"none\",\"kid\":\"x\"}"))}.{parts[1]}.";
        Assert.Equal(HttpStatusCode.Unauthorized, (await UserInfoAsync(none)).Status);
        // A well-formed token signed by a key the server never published.
        using var stranger = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var header = Part(access, 0);
        var signingInput = $"{B64(Encoding.UTF8.GetBytes(header.GetRawText()))}.{parts[1]}";
        var forged = $"{signingInput}.{B64(stranger.SignData(Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))}";
        Assert.Equal(HttpStatusCode.Unauthorized, (await UserInfoAsync(forged)).Status);
        // And the real one still works.
        Assert.Equal(HttpStatusCode.OK, (await UserInfoAsync(access)).Status);
    }

    [Fact]
    public async Task Userinfo_stops_answering_once_the_person_has_left_the_workspace()
    {
        var person = await SignedInAsync();
        var flow = await FlowAsync(person: person);
        _factory.WithDb(db => { db.Members.Where(m => m.UserId == person.UserId).ExecuteDelete(); return 0; });
        Assert.Equal(HttpStatusCode.Unauthorized, (await UserInfoAsync(flow.Tokens.GetProperty("access_token").GetString()!)).Status);
    }

    // ---------- introspection ----------

    [Fact]
    public async Task Introspection_tells_a_client_about_its_own_tokens()
    {
        var flow = await FlowAsync();
        var http = _factory.Plain();
        var access = await ReadJsonAsync(await http.SendAsync(Introspection(flow.Client, flow.Tokens.GetProperty("access_token").GetString()!)));
        Assert.True(access.GetProperty("active").GetBoolean());
        Assert.Equal(flow.Client.Id, access.GetProperty("client_id").GetString());
        Assert.Equal(flow.UserId, access.GetProperty("sub").GetString());
        Assert.Equal(Full, access.GetProperty("scope").GetString());
        Assert.Equal("Bearer", access.GetProperty("token_type").GetString());
        var refresh = await ReadJsonAsync(await http.SendAsync(Introspection(flow.Client, flow.Tokens.GetProperty("refresh_token").GetString()!)));
        Assert.True(refresh.GetProperty("active").GetBoolean());
        Assert.Equal(Full, refresh.GetProperty("scope").GetString());
        Assert.False(refresh.TryGetProperty("org_id", out _));   // nothing beyond what RFC 7662 lists
    }

    [Fact]
    public async Task Introspection_is_not_an_oracle_for_the_tokens_of_other_clients()
    {
        var person = await SignedInAsync();
        var victim = await FlowAsync(person: person);
        var attacker = await RegisterAsync(person.Browser);
        var http = _factory.Plain();
        foreach (var token in new[] { victim.Tokens.GetProperty("access_token").GetString()!, victim.Tokens.GetProperty("refresh_token").GetString()!, "garbage", victim.Tokens.GetProperty("id_token").GetString()! })
        {
            var response = await http.SendAsync(Introspection(attacker, token));
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("{\"active\":false}", await response.Content.ReadAsStringAsync());   // byte for byte the answer for a token that does not exist
        }
    }

    [Fact]
    public async Task Introspection_needs_a_confidential_client_with_the_right_secret_and_the_registered_method()
    {
        var person = await SignedInAsync();
        var flow = await FlowAsync(person: person);
        var token = flow.Tokens.GetProperty("access_token").GetString()!;
        var http = _factory.Plain();
        var publicClient = await RegisterAsync(person.Browser, "none");

        Assert.Equal(HttpStatusCode.Unauthorized, (await http.PostAsync("/api/auth/oauth2/introspect", new FormUrlEncodedContent(new Dictionary<string, string> { ["token"] = token }))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await http.PostAsync("/api/auth/oauth2/introspect", new FormUrlEncodedContent(new Dictionary<string, string> { ["token"] = token, ["client_id"] = publicClient.Id }))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await http.SendAsync(Introspection(flow.Client with { Secret = "wrong" }, token))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await http.SendAsync(Introspection(new Client("no-such-client", "x"), token))).StatusCode);
        // Registered for client_secret_basic: the secret in the body is not accepted.
        Assert.Equal(HttpStatusCode.Unauthorized, (await http.SendAsync(Introspection(flow.Client, token, viaBody: true))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await http.SendAsync(Introspection(flow.Client, token))).StatusCode);
        // The failures reveal nothing: a wrong secret and an unknown client read the same.
        var a = await (await http.SendAsync(Introspection(flow.Client with { Secret = "wrong" }, token))).Content.ReadAsStringAsync();
        var b = await (await http.SendAsync(Introspection(new Client("no-such-client", "x"), token))).Content.ReadAsStringAsync();
        Assert.Equal(a, b);
    }

    [Fact]
    public async Task Introspection_reports_revoked_and_rotated_refresh_tokens_and_departed_people_as_inactive()
    {
        var person = await SignedInAsync();
        var flow = await FlowAsync(person: person);
        var http = _factory.Plain();
        var refresh = flow.Tokens.GetProperty("refresh_token").GetString()!;
        var rotated = await ReadJsonAsync(await TokenAsync(http, flow.Client, new() { ["grant_type"] = "refresh_token", ["refresh_token"] = refresh, ["resource"] = Resource }));
        Assert.False((await ReadJsonAsync(await http.SendAsync(Introspection(flow.Client, refresh)))).GetProperty("active").GetBoolean());   // already exchanged
        Assert.True((await ReadJsonAsync(await http.SendAsync(Introspection(flow.Client, rotated.GetProperty("refresh_token").GetString()!)))).GetProperty("active").GetBoolean());

        var revoke = new HttpRequestMessage(HttpMethod.Post, "/api/auth/oauth2/revoke") { Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["token"] = rotated.GetProperty("refresh_token").GetString()! }) };
        revoke.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", flow.Client.BasicValue);
        await http.SendAsync(revoke);
        Assert.False((await ReadJsonAsync(await http.SendAsync(Introspection(flow.Client, rotated.GetProperty("refresh_token").GetString()!)))).GetProperty("active").GetBoolean());

        var access = rotated.GetProperty("access_token").GetString()!;
        Assert.True((await ReadJsonAsync(await http.SendAsync(Introspection(flow.Client, access)))).GetProperty("active").GetBoolean());
        _factory.WithDb(db => { db.Members.Where(m => m.UserId == person.UserId).ExecuteDelete(); return 0; });
        Assert.False((await ReadJsonAsync(await http.SendAsync(Introspection(flow.Client, access)))).GetProperty("active").GetBoolean());
    }

    [Fact]
    public async Task Introspection_only_takes_form_bodies()
    {
        var flow = await FlowAsync();
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/oauth2/introspect") { Content = JsonContent.Create(new { token = "x" }) };
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", flow.Client.BasicValue);
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, (await _factory.Plain().SendAsync(request)).StatusCode);
    }

    // ---------- end-session ----------

    private async Task<(HttpClient Browser, Client Client, string IdToken, string RefreshToken, string SessionId)> LogoutClientAsync()
    {
        var person = await SignedInAsync();
        // A registration made while signed in may enable logout; its ID token then carries the browser's session id.
        var client = await RegisterAsync(person.Browser, extra: new { enable_end_session = true, post_logout_redirect_uris = new[] { Bye } }, bearer: person.Token);
        var flow = await FlowAsync(person: person, client: client);
        var sid = Part(flow.Tokens.GetProperty("id_token").GetString()!, 1).GetProperty("sid").GetString()!;
        return (person.Browser, client, flow.Tokens.GetProperty("id_token").GetString()!, flow.Tokens.GetProperty("refresh_token").GetString()!, sid);
    }

    private static HttpRequestMessage EndSession(string query, bool navigation = false)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, $"/api/auth/oauth2/end-session?{query}");
        if (navigation) { request.Headers.Accept.ParseAdd("text/html"); request.Headers.Add("Sec-Fetch-Mode", "navigate"); }
        return request;
    }

    [Fact]
    public async Task A_client_that_may_log_people_out_ends_the_matching_session_and_the_browser_goes_to_the_registered_address()
    {
        var (browser, client, idToken, refresh, sid) = await LogoutClientAsync();
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/api/auth/get-session")).StatusCode);
        var response = await browser.SendAsync(EndSession($"id_token_hint={idToken}&client_id={client.Id}&post_logout_redirect_uri={Uri.EscapeDataString(Bye)}&state=bye-1"));
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal($"{Bye}?state=bye-1", response.Headers.Location!.ToString());
        Assert.False(_factory.WithDb(db => db.Sessions.Any(s => s.Id == sid)));
        // Tokens that were issued during that session stop refreshing.
        var refused = await TokenAsync(_factory.Plain(), client, new() { ["grant_type"] = "refresh_token", ["refresh_token"] = refresh, ["resource"] = Resource });
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
    }

    [Fact]
    public async Task A_post_logout_address_must_match_a_registered_one_exactly()
    {
        var (browser, client, idToken, _, _) = await LogoutClientAsync();
        foreach (var evil in new[] { "http://127.0.0.1:9999/bye/../evil", "http://127.0.0.1:9999/bye2", "http://evil.example/bye", "http://127.0.0.1:9999/bye?x=1", "http://127.0.0.1:9998/bye" })
        {
            var (b, c, hint, _, _) = await LogoutClientAsync();
            var response = await b.SendAsync(EndSession($"id_token_hint={hint}&client_id={c.Id}&post_logout_redirect_uri={Uri.EscapeDataString(evil)}"));
            Assert.NotEqual(HttpStatusCode.Redirect, response.StatusCode);   // no redirect anywhere, the session still ended
        }
        Assert.NotNull(browser); Assert.NotNull(client); Assert.NotNull(idToken);
    }

    [Fact]
    public async Task A_client_registered_without_signing_in_cannot_enable_logout_even_if_it_asks()
    {
        var person = await SignedInAsync();
        var client = await RegisterAsync(_factory.Plain(), extra: new { enable_end_session = true, post_logout_redirect_uris = new[] { Bye } });
        var flow = await FlowAsync(person: person, client: client);
        Assert.False(Part(flow.Tokens.GetProperty("id_token").GetString()!, 1).TryGetProperty("sid", out _));
        var response = await flow.Browser.SendAsync(EndSession($"id_token_hint={flow.Tokens.GetProperty("id_token").GetString()}&client_id={client.Id}"));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await flow.Browser.GetAsync("/api/auth/get-session")).StatusCode);   // still signed in
    }

    [Fact]
    public async Task A_hint_from_another_client_or_another_session_or_a_forged_hint_never_ends_the_session_silently()
    {
        var (browser, client, idToken, _, _) = await LogoutClientAsync();
        var (_, otherClient, otherHint, _, _) = await LogoutClientAsync();   // someone else's client and ID token

        // The hint was issued to another client: it does not verify for this one.
        var wrongAudience = await browser.SendAsync(EndSession($"id_token_hint={otherHint}&client_id={client.Id}"));
        Assert.Equal(HttpStatusCode.Unauthorized, wrongAudience.StatusCode);
        // A hint for another person's session: the person at this browser must confirm.
        var otherSession = await browser.SendAsync(EndSession($"id_token_hint={otherHint}&client_id={otherClient.Id}"));
        Assert.Equal(HttpStatusCode.BadRequest, otherSession.StatusCode);
        Assert.Equal("invalid_request", (await ReadJsonAsync(otherSession)).GetProperty("error").GetString());
        // A forged hint (payload edited).
        var parts = idToken.Split('.');
        var edited = JsonSerializer.Serialize(JsonSerializer.Deserialize<Dictionary<string, object>>(FromB64(parts[1]))!.ToDictionary(p => p.Key, p => p.Key == "sid" ? "ses_forged" : p.Value));
        var forged = await browser.SendAsync(EndSession($"id_token_hint={parts[0]}.{B64(Encoding.UTF8.GetBytes(edited))}.{parts[2]}&client_id={client.Id}"));
        Assert.Equal(HttpStatusCode.Unauthorized, forged.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/api/auth/get-session")).StatusCode);
    }

    [Fact]
    public async Task Logout_without_a_hint_needs_the_persons_confirmation_on_a_page_tied_to_their_browser()
    {
        var (browser, client, _, _, sid) = await LogoutClientAsync();
        var query = $"client_id={client.Id}&post_logout_redirect_uri={Uri.EscapeDataString(Bye)}&state=s9";
        // A script (not a navigation) cannot confirm for the person.
        Assert.Equal(HttpStatusCode.BadRequest, (await browser.SendAsync(EndSession(query))).StatusCode);
        // The browser is shown the confirmation page, with no scripts allowed.
        var page = await browser.SendAsync(EndSession(query, navigation: true));
        Assert.Equal(HttpStatusCode.OK, page.StatusCode);
        Assert.Contains("data-oidc-logout-confirmation", await page.Content.ReadAsStringAsync());
        Assert.Contains("default-src 'none'", page.Headers.GetValues("Content-Security-Policy").Single());
        Assert.True(_factory.WithDb(db => db.Sessions.Any(s => s.Id == sid)));   // showing the page ended nothing
        var confirm = await browser.PostAsync("/api/auth/oauth2/end-session/confirm", new FormUrlEncodedContent(new Dictionary<string, string> { ["action"] = "confirm" }));
        Assert.Equal(HttpStatusCode.Redirect, confirm.StatusCode);
        Assert.Equal($"{Bye}?state=s9", confirm.Headers.Location!.ToString());
        Assert.False(_factory.WithDb(db => db.Sessions.Any(s => s.Id == sid)));
    }

    [Fact]
    public async Task The_confirmation_does_nothing_without_the_cookie_the_page_set_and_a_tampered_cookie_is_refused()
    {
        var (browser, client, _, _, sid) = await LogoutClientAsync();
        await browser.SendAsync(EndSession($"client_id={client.Id}", navigation: true));

        // A forged cross-site form post carries no confirmation cookie (a different cookie jar).
        var stranger = _factory.Browser();
        var noCookie = await stranger.PostAsync("/api/auth/oauth2/end-session/confirm", new FormUrlEncodedContent(new Dictionary<string, string> { ["action"] = "confirm" }));
        Assert.Equal(HttpStatusCode.BadRequest, noCookie.StatusCode);

        // A tampered cookie value.
        var tampered = new HttpRequestMessage(HttpMethod.Post, "/api/auth/oauth2/end-session/confirm") { Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["action"] = "confirm" }) };
        tampered.Headers.Add("Cookie", "openwork-den.session_token.oauth_logout_confirmation=purpose%3Dend_session%26exp%3D9999999999%26sig%3Dnope");
        Assert.Equal(HttpStatusCode.BadRequest, (await _factory.Plain().SendAsync(tampered)).StatusCode);

        // Without the explicit action nothing happens either.
        var noAction = await browser.PostAsync("/api/auth/oauth2/end-session/confirm", new FormUrlEncodedContent(new Dictionary<string, string>()));
        Assert.Equal(HttpStatusCode.BadRequest, noAction.StatusCode);
        Assert.True(_factory.WithDb(db => db.Sessions.Any(s => s.Id == sid)));
    }

    [Fact]
    public async Task A_confirmation_issued_for_one_session_cannot_end_another()
    {
        var (first, client, _, _, firstSid) = await LogoutClientAsync();
        var page = await first.SendAsync(EndSession($"client_id={client.Id}", navigation: true));
        var cookie = page.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith("openwork-den.session_token.oauth_logout_confirmation=")).Split(';')[0];
        var second = await SignedInAsync("Someone Else");
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/oauth2/end-session/confirm") { Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["action"] = "confirm" }) };
        request.Headers.Add("Cookie", cookie);
        var response = await second.Browser.SendAsync(request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await second.Browser.GetAsync("/api/auth/get-session")).StatusCode);
        Assert.True(_factory.WithDb(db => db.Sessions.Any(s => s.Id == firstSid)));
    }

    // ---------- limits ----------

    private sealed class RateLimitedFactory : ApiFactory
    {
        protected override IEnumerable<KeyValuePair<string, string>> Settings => [new("Auth:RateLimitsEnabled", "true")];
    }

    [Fact]
    public async Task Introspection_has_the_token_endpoints_failure_budget_and_its_own_buckets()
    {
        await using var factory = new RateLimitedFactory();
        var http = factory.Plain();
        Task<HttpResponseMessage> Wrong() => http.SendAsync(Introspection(new Client("some-client", "wrong"), "t"));
        for (var i = 0; i < 15; i++) Assert.Equal(HttpStatusCode.Unauthorized, (await Wrong()).StatusCode);
        var refused = await Wrong();
        Assert.Equal(HttpStatusCode.TooManyRequests, refused.StatusCode);
        Assert.True(int.Parse(refused.Headers.GetValues("Retry-After").Single()) > 0);
        // The token endpoint is not affected by the introspection failures of that client.
        var token = await http.PostAsync("/api/auth/oauth2/token", new FormUrlEncodedContent(new Dictionary<string, string> { ["grant_type"] = "authorization_code", ["client_id"] = "some-client", ["code"] = "x" }));
        Assert.NotEqual(HttpStatusCode.TooManyRequests, token.StatusCode);
    }
}
