using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using WorkAI360.Api.Domain.OAuthExtras;
using WorkAI360.Api.OAuth;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>The DPoP proof checks (RFC 9449 section 4.3 as the reference applies them), in isolation.</summary>
public sealed class DpopVerifierTests(OAuthExtrasFactory factory) : OAuthExtrasBase(factory), IClassFixture<OAuthExtrasFactory>
{
    private async Task<DpopProof> Verify(string proof, string method = "POST", string url = TokenUrl, string? token = null, string? jkt = null)
    {
        using var scope = Factory.Services.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<DpopVerifier>().VerifyAsync(proof, method, [url], token, jkt);
    }

    private async Task<string> Refused(string proof, string method = "POST", string url = TokenUrl, string? token = null, string? jkt = null) =>
        (await Assert.ThrowsAsync<DpopException>(() => Verify(proof, method, url, token, jkt))).Message;

    [Theory]
    [InlineData("ES256")]
    [InlineData("ES512")]
    [InlineData("RS256")]
    [InlineData("PS256")]
    public async Task A_proof_by_an_allowed_algorithm_is_accepted_and_names_the_key(string alg)
    {
        using var key = alg.StartsWith("ES", StringComparison.Ordinal) ? TestKey.Ec(alg) : TestKey.Rsa(alg);
        var proof = await Verify(key.DpopProof("POST", TokenUrl));
        Assert.Equal(key.Thumbprint, proof.Jkt);
        Assert.Equal("POST", proof.Method);
        Assert.Equal(TokenUrl, proof.Url);
    }

    [Fact]
    public async Task The_thumbprint_is_the_rfc_7638_one()
    {
        // The RFC's own example key and thumbprint.
        var jwk = JsonDocument.Parse("{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\"e\":\"AQAB\"}").RootElement;
        Assert.Equal("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", Jose.Thumbprint(jwk));
    }

    [Fact]
    public void A_key_verifies_only_the_algorithms_the_caller_allows_and_never_a_foreign_family()
    {
        using var p384 = TestKey.Ec("ES384");
        using var rsa = TestKey.Rsa("RS256");
        var jwk = JsonDocument.Parse(p384.Jwk().ToJsonString()).RootElement;
        var token = Jose.Parse(p384.Jwt(new() { ["alg"] = "ES384" }, new() { ["a"] = 1 }))!;
        Assert.True(Jose.Verify(token, jwk, ["ES384"]));
        Assert.False(Jose.Verify(token, jwk, ["ES256", "RS256"]));
        // An RSA key cannot verify an EC algorithm and the reverse; the key's own alg member must agree.
        var rsaJwk = JsonDocument.Parse(rsa.Jwk().ToJsonString()).RootElement;
        Assert.False(Jose.Verify(token, rsaJwk, ["ES384"]));
        var pinned = rsa.Jwk(); pinned["alg"] = "PS256";
        Assert.False(Jose.Verify(Jose.Parse(rsa.Jwt(new() { ["alg"] = "RS256" }, new() { ["a"] = 1 }))!, JsonDocument.Parse(pinned.ToJsonString()).RootElement, ["RS256", "PS256"]));
        // A symmetric algorithm never verifies, even if the caller lists it.
        var hs = Jose.Parse(rsa.Jwt(new() { ["alg"] = "HS256" }, new() { ["a"] = 1 }, alg: "RS256"))!;
        Assert.False(Jose.Verify(hs, rsaJwk, ["HS256"]));
    }

    [Fact]
    public async Task The_type_and_algorithm_are_checked()
    {
        using var key = TestKey.Ec();
        Assert.Equal("DPoP proof typ must be \"dpop+jwt\"", await Refused(key.DpopProof("POST", TokenUrl, typ: "JWT")));
        Assert.Equal("DPoP proof must use an asymmetric JWS algorithm", await Refused(key.DpopProof("POST", TokenUrl, header: h => h["alg"] = "none")));
        Assert.Equal("DPoP proof must use an asymmetric JWS algorithm", await Refused(key.DpopProof("POST", TokenUrl, header: h => h["alg"] = "HS256")));
        Assert.Equal("DPoP proof uses an unsupported JWS algorithm", await Refused(key.DpopProof("POST", TokenUrl, header: h => h["alg"] = "ES384")));
        using var p384 = TestKey.Ec("ES384");
        Assert.Equal("DPoP proof uses an unsupported JWS algorithm", await Refused(p384.DpopProof("POST", TokenUrl)));
        Assert.Equal("DPoP proof must be a compact JWT", await Refused("a.b"));
        Assert.Equal("DPoP proof must be a compact JWT", await Refused(""));
    }

    [Fact]
    public async Task The_key_in_the_header_must_be_a_public_asymmetric_key_and_must_have_signed()
    {
        using var key = TestKey.Ec();
        using var other = TestKey.Ec();
        Assert.Equal("DPoP proof header must include a public jwk", await Refused(key.DpopProof("POST", TokenUrl, header: h => h.Remove("jwk"))));
        Assert.Equal("DPoP proof jwk must be asymmetric", await Refused(key.DpopProof("POST", TokenUrl, header: h => h["jwk"] = new JsonObject { ["kty"] = "oct", ["k"] = "AAAA" })));
        Assert.Equal("DPoP proof jwk must not contain private key material", await Refused(key.DpopProof("POST", TokenUrl, header: h => ((JsonObject)h["jwk"]!)["d"] = "AAAA")));
        // The header advertises another key than the one that signed.
        Assert.Equal("DPoP proof signature is invalid", await Refused(key.DpopProof("POST", TokenUrl, header: h => h["jwk"] = other.Jwk())));
        // A key whose type does not fit the algorithm in the header.
        using var rsa = TestKey.Rsa();
        Assert.Equal("DPoP proof signature is invalid", await Refused(key.DpopProof("POST", TokenUrl, header: h => h["jwk"] = rsa.Jwk())));
    }

    [Fact]
    public async Task The_claims_must_be_there_and_say_this_request()
    {
        using var key = TestKey.Ec();
        Assert.Equal("DPoP proof must include htm, htu, jti, and iat claims", await Refused(key.DpopProof("POST", TokenUrl, claims: c => c.Remove("jti"))));
        Assert.Equal("DPoP proof must include htm, htu, jti, and iat claims", await Refused(key.DpopProof("POST", TokenUrl, claims: c => c.Remove("iat"))));
        Assert.Equal("DPoP proof must include htm, htu, jti, and iat claims", await Refused(key.DpopProof("POST", TokenUrl, claims: c => c["htu"] = "")));
        Assert.Equal("DPoP proof jti is too large", await Refused(key.DpopProof("POST", TokenUrl, jti: new string('j', 513))));
        Assert.Equal("DPoP proof htm does not match the request method", await Refused(key.DpopProof("GET", TokenUrl)));
        Assert.Equal("DPoP proof htu does not match the request URL", await Refused(key.DpopProof("POST", "https://elsewhere.example.test/api/auth/oauth2/token")));
        Assert.Equal("DPoP proof htu does not match the request URL", await Refused(key.DpopProof("POST", "http://localhost/api/auth/oauth2/other")));
        Assert.Equal("DPoP proof htu is invalid", await Refused(key.DpopProof("POST", "not a url")));
        Assert.Equal("DPoP proof htu is invalid", await Refused(key.DpopProof("POST", TokenUrl + "#frag")));
    }

    [Fact]
    public async Task The_method_is_compared_ignoring_case_and_the_url_ignoring_query_default_port_and_host_case()
    {
        using var key = TestKey.Ec();
        await Verify(key.DpopProof("post", TokenUrl));
        await Verify(key.DpopProof("POST", TokenUrl + "?a=b"));
        await Verify(key.DpopProof("POST", "http://LOCALHOST:80/api/auth/oauth2/token"));
        await Verify(key.DpopProof("POST", TokenUrl), url: "http://localhost:80/api/auth/oauth2/token");
    }

    [Fact]
    public async Task The_time_must_be_recent()
    {
        using var key = TestKey.Ec();
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        Assert.Equal("DPoP proof iat is outside the accepted window", await Refused(key.DpopProof("POST", TokenUrl, iat: now - 400)));
        Assert.Equal("DPoP proof iat is outside the accepted window", await Refused(key.DpopProof("POST", TokenUrl, iat: now + 30)));
        await Verify(key.DpopProof("POST", TokenUrl, iat: now - 250));
        await Verify(key.DpopProof("POST", TokenUrl, iat: now + 3));
        Assert.Equal("DPoP proof has expired", await Refused(key.DpopProof("POST", TokenUrl, claims: c => c["exp"] = now - 5)));
        Assert.Equal("DPoP proof is not yet valid", await Refused(key.DpopProof("POST", TokenUrl, claims: c => c["nbf"] = now + 600)));
    }

    [Fact]
    public async Task At_a_resource_the_proof_must_cover_the_token_and_use_the_bound_key()
    {
        using var key = TestKey.Ec();
        using var other = TestKey.Ec();
        const string token = "the.access.token";
        await Verify(key.DpopProof("GET", Resource, token), "GET", Resource, token, key.Thumbprint);
        Assert.Equal("DPoP proof must include an ath claim", await Refused(key.DpopProof("GET", Resource), "GET", Resource, token));
        Assert.Equal("DPoP proof ath does not match the access token", await Refused(key.DpopProof("GET", Resource, "another.token"), "GET", Resource, token));
        Assert.Equal("DPoP proof key does not match the bound token", await Refused(other.DpopProof("GET", Resource, token), "GET", Resource, token, key.Thumbprint));
    }

    [Fact]
    public async Task A_proof_works_once()
    {
        using var key = TestKey.Ec();
        var proof = key.DpopProof("POST", TokenUrl);
        await Verify(proof);
        Assert.Equal("DPoP proof jti has already been used", await Refused(proof));
        // The same jti for another address or method is another proof.
        var jti = Guid.NewGuid().ToString("N");
        await Verify(key.DpopProof("POST", TokenUrl, jti: jti));
        await Verify(key.DpopProof("POST", Resource, jti: jti), "POST", Resource);
        // The same jti from another key too.
        using var other = TestKey.Ec();
        await Verify(other.DpopProof("POST", TokenUrl, jti: jti));
    }

    [Fact]
    public async Task The_same_proof_presented_at_once_is_accepted_exactly_once()
    {
        using var key = TestKey.Ec();
        var proof = key.DpopProof("POST", TokenUrl);
        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(async _ =>
        {
            try { await Verify(proof); return true; }
            catch (DpopException e) when (e.Message.Contains("already been used")) { return false; }
        }));
        Assert.Equal(1, results.Count(r => r));
    }

    [Fact]
    public async Task The_replay_record_is_kept_until_the_proof_would_have_gone_stale_and_stores_only_a_hash()
    {
        using var key = TestKey.Ec();
        var jti = "jti-" + Guid.NewGuid().ToString("N");
        await Verify(key.DpopProof("POST", TokenUrl, jti: jti));
        var id = WorkAI360.Api.Features.Replay.ReplayGuard.KeyFor("dpop-proof", $"{key.Thumbprint}\nPOST\n{TokenUrl}\n{jti}");
        var row = Factory.WithDb(db => db.Set<WorkAI360.Api.Domain.Replay.ReplayReservation>().Single(r => r.Id == id));
        Assert.True(row.ExpiresAt > DateTime.UtcNow.AddMinutes(4));
        Assert.Equal("dpop-proof", row.Kind);
        Assert.DoesNotContain(jti, row.Id);
    }
}

/// <summary>DPoP at the token endpoint.</summary>
public sealed class DpopTokenTests(OAuthExtrasFactory factory) : OAuthExtrasBase(factory), IClassFixture<OAuthExtrasFactory>
{
    [Fact]
    public async Task Without_a_proof_tokens_are_plain_bearer_tokens()
    {
        var (tokens, _, _) = await BoundFlowAsync(null);
        Assert.Equal("Bearer", tokens.GetProperty("token_type").GetString());
        Assert.False(Payload(tokens.GetProperty("access_token").GetString()!).TryGetProperty("cnf", out _));
    }

    [Fact]
    public async Task A_proof_binds_the_access_token_and_the_refresh_token_to_its_key()
    {
        using var key = TestKey.Ec();
        var (tokens, clientId, _) = await BoundFlowAsync(key);
        Assert.Equal("DPoP", tokens.GetProperty("token_type").GetString());
        var claims = Payload(tokens.GetProperty("access_token").GetString()!);
        Assert.Equal(key.Thumbprint, claims.GetProperty("cnf").GetProperty("jkt").GetString());
        Assert.True(tokens.TryGetProperty("refresh_token", out _));
        // The refresh family is bound, and only its key is stored (not the proof).
        var bindings = Factory.WithDb(db => db.Set<OAuthDpopBinding>().Where(b => b.Jkt == key.Thumbprint).ToList());
        Assert.Single(bindings);
        Assert.StartsWith("fam_", bindings[0].Id);
        Assert.NotEmpty(clientId);
    }

    [Fact]
    public async Task A_code_asked_for_with_dpop_jkt_can_be_exchanged_only_by_that_key()
    {
        using var key = TestKey.Ec();
        using var other = TestKey.Ec();
        var (browser, _, _, _) = await SignedInAsync();
        var clientId = await PublicClientAsync(browser);
        var (verifier, challenge) = Pkce();
        var code = await GetCodeAsync(browser, clientId, challenge, extra: $"&dpop_jkt={key.Thumbprint}");
        var form = CodeForm(clientId, code, verifier);

        var none = await TokenAsync(browser, form);
        Assert.Equal(HttpStatusCode.BadRequest, none.Status);
        Assert.Equal("invalid_dpop_proof", Err(none.Body));
        Assert.Equal("DPoP proof header is required", Desc(none.Body));
        var wrong = await TokenAsync(browser, form, dpop: other.DpopProof("POST", TokenUrl));
        Assert.Equal("DPoP proof key does not match the bound token", Desc(wrong.Body));
        // None of that spent the code.
        var ok = await TokenAsync(browser, form, dpop: key.DpopProof("POST", TokenUrl));
        Assert.Equal(HttpStatusCode.OK, ok.Status);
        Assert.Equal("DPoP", ok.Body.GetProperty("token_type").GetString());
        Assert.Equal(key.Thumbprint, Payload(ok.Body.GetProperty("access_token").GetString()!).GetProperty("cnf").GetProperty("jkt").GetString());
    }

    [Fact]
    public async Task A_malformed_dpop_jkt_is_refused_when_authorizing()
    {
        var (browser, _, _, _) = await SignedInAsync();
        var clientId = await PublicClientAsync(browser);
        var (_, challenge) = Pkce();
        var location = await GetCodeAsync(browser, clientId, challenge, extra: "&dpop_jkt=short");
        Assert.Contains("error=invalid_request", location);
        Assert.Contains("dpop_jkt", location);
    }

    [Fact]
    public async Task A_client_that_wants_bound_tokens_must_send_a_proof()
    {
        using var key = TestKey.Ec();
        var (browser, _, _, _) = await SignedInAsync();
        var clientId = await PublicClientAsync(browser, new { dpop_bound_access_tokens = true });
        var (verifier, challenge) = Pkce();
        var code = await GetCodeAsync(browser, clientId, challenge);
        var form = CodeForm(clientId, code, verifier);
        var without = await TokenAsync(browser, form);
        Assert.Equal("invalid_dpop_proof", Err(without.Body));
        Assert.Equal("DPoP proof header is required", Desc(without.Body));
        var with = await TokenAsync(browser, form, dpop: key.DpopProof("POST", TokenUrl));
        Assert.Equal("DPoP", with.Body.GetProperty("token_type").GetString());
    }

    [Fact]
    public async Task A_bad_proof_is_refused_with_its_reason_and_never_downgrades_to_a_bearer_token()
    {
        using var key = TestKey.Ec();
        var (browser, _, _, _) = await SignedInAsync();
        var clientId = await PublicClientAsync(browser);
        var (verifier, challenge) = Pkce();
        var code = await GetCodeAsync(browser, clientId, challenge);
        var form = CodeForm(clientId, code, verifier);
        var get = await TokenAsync(browser, form, dpop: key.DpopProof("GET", TokenUrl));
        Assert.Equal(HttpStatusCode.BadRequest, get.Status);
        Assert.Equal("invalid_dpop_proof", Err(get.Body));
        Assert.Equal("DPoP proof htm does not match the request method", Desc(get.Body));
        Assert.Equal("DPoP proof htu does not match the request URL", Desc((await TokenAsync(browser, form, dpop: key.DpopProof("POST", "http://localhost/api/auth/oauth2/revoke"))).Body));
        var proof = key.DpopProof("POST", TokenUrl);
        Assert.Equal(HttpStatusCode.OK, (await TokenAsync(browser, form, dpop: proof)).Status);
        // The proof (and the code) are spent: presenting the proof again is its own error.
        var (verifier2, challenge2) = Pkce();
        var form2 = CodeForm(clientId, await GetCodeAsync(browser, clientId, challenge2), verifier2);
        Assert.Equal("DPoP proof jti has already been used", Desc((await TokenAsync(browser, form2, dpop: proof)).Body));
    }

    [Fact]
    public async Task Two_proofs_in_one_request_are_refused()
    {
        using var key = TestKey.Ec();
        var (browser, _, _, _) = await SignedInAsync();
        var clientId = await PublicClientAsync(browser);
        var (verifier, challenge) = Pkce();
        var form = CodeForm(clientId, await GetCodeAsync(browser, clientId, challenge), verifier);
        var r = await TokenAsync(browser, form, dpops: [key.DpopProof("POST", TokenUrl), key.DpopProof("POST", TokenUrl)]);
        Assert.Equal("Multiple DPoP proofs are not allowed", Desc(r.Body));
    }

    [Fact]
    public async Task The_proof_may_name_the_advertised_address_or_the_apis_own_and_ignores_the_query()
    {
        using var key = TestKey.Ec();
        var (browser, _, _, _) = await SignedInAsync();
        var clientId = await PublicClientAsync(browser);
        foreach (var url in new[] { TokenUrl + "?x=1", "http://localhost/api/auth/oauth2/token" })
        {
            var (verifier, challenge) = Pkce();
            var r = await TokenAsync(browser, CodeForm(clientId, await GetCodeAsync(browser, clientId, challenge), verifier), dpop: key.DpopProof("POST", url));
            Assert.Equal(HttpStatusCode.OK, r.Status);
        }
    }

    [Fact]
    public async Task A_bound_refresh_token_needs_a_proof_by_the_same_key_and_stays_bound()
    {
        using var key = TestKey.Ec();
        using var other = TestKey.Ec();
        var (tokens, clientId, browser) = await BoundFlowAsync(key);
        var refresh = tokens.GetProperty("refresh_token").GetString()!;
        Dictionary<string, string> Form(string token) => new() { ["grant_type"] = "refresh_token", ["refresh_token"] = token, ["client_id"] = clientId, ["resource"] = Resource };

        var none = await TokenAsync(browser, Form(refresh));
        Assert.Equal("invalid_dpop_proof", Err(none.Body));
        Assert.Equal("DPoP proof header is required", Desc(none.Body));
        var wrong = await TokenAsync(browser, Form(refresh), dpop: other.DpopProof("POST", TokenUrl));
        Assert.Equal("DPoP proof key does not match the bound token", Desc(wrong.Body));
        var ok = await TokenAsync(browser, Form(refresh), dpop: key.DpopProof("POST", TokenUrl));
        Assert.Equal(HttpStatusCode.OK, ok.Status);
        Assert.Equal("DPoP", ok.Body.GetProperty("token_type").GetString());
        Assert.Equal(key.Thumbprint, Payload(ok.Body.GetProperty("access_token").GetString()!).GetProperty("cnf").GetProperty("jkt").GetString());
        // The rotated token is still bound.
        var next = ok.Body.GetProperty("refresh_token").GetString()!;
        Assert.Equal("invalid_dpop_proof", Err((await TokenAsync(browser, Form(next))).Body));
        Assert.Equal(HttpStatusCode.OK, (await TokenAsync(browser, Form(next), dpop: key.DpopProof("POST", TokenUrl))).Status);
        Assert.Single(Factory.WithDb(db => db.Set<OAuthDpopBinding>().Where(b => b.Jkt == key.Thumbprint).ToList()));
    }

    [Fact]
    public async Task An_unbound_refresh_token_presented_with_a_proof_is_bound_from_then_on()
    {
        using var key = TestKey.Ec();
        var (tokens, clientId, browser) = await BoundFlowAsync(null);
        Dictionary<string, string> Form(string token) => new() { ["grant_type"] = "refresh_token", ["refresh_token"] = token, ["client_id"] = clientId, ["resource"] = Resource };
        var upgraded = await TokenAsync(browser, Form(tokens.GetProperty("refresh_token").GetString()!), dpop: key.DpopProof("POST", TokenUrl));
        Assert.Equal("DPoP", upgraded.Body.GetProperty("token_type").GetString());
        var again = await TokenAsync(browser, Form(upgraded.Body.GetProperty("refresh_token").GetString()!));
        Assert.Equal("invalid_dpop_proof", Err(again.Body));
    }

    [Fact]
    public async Task A_refresh_without_any_proof_keeps_giving_bearer_tokens_for_an_unbound_family()
    {
        var (tokens, clientId, browser) = await BoundFlowAsync(null);
        var r = await TokenAsync(browser, new() { ["grant_type"] = "refresh_token", ["refresh_token"] = tokens.GetProperty("refresh_token").GetString()!, ["client_id"] = clientId, ["resource"] = Resource });
        Assert.Equal("Bearer", r.Body.GetProperty("token_type").GetString());
    }

    [Fact]
    public async Task A_machine_token_can_be_bound_too()
    {
        using var key = TestKey.Ec();
        var (browser, _, _, _) = await SignedInAsync();
        var (id, secret) = await ClientCredentialsClientAsync(browser);
        await GrantAsync(id, "mcp:read");
        var r = await TokenAsync(Factory.Plain(), new() { ["grant_type"] = "client_credentials" }, Basic(id, secret!), key.DpopProof("POST", TokenUrl));
        Assert.Equal("DPoP", r.Body.GetProperty("token_type").GetString());
        Assert.Equal(key.Thumbprint, Payload(r.Body.GetProperty("access_token").GetString()!).GetProperty("cnf").GetProperty("jkt").GetString());
        // And the client's own introspection says so.
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/oauth2/introspect") { Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["token"] = r.Body.GetProperty("access_token").GetString()! }) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Basic(id, secret!));
        var introspected = await ReadJsonAsync(await Factory.Plain().SendAsync(request));
        Assert.Equal("DPoP", introspected.GetProperty("token_type").GetString());
        Assert.Equal(key.Thumbprint, introspected.GetProperty("cnf").GetProperty("jkt").GetString());
    }
}

/// <summary>Using a bound token: the DPoP scheme and a proof for this very request.</summary>
public sealed class DpopResourceTests(OAuthExtrasFactory factory) : OAuthExtrasBase(factory), IClassFixture<OAuthExtrasFactory>
{
    private static string Challenge(HttpResponseMessage r) => string.Join(" ", r.Headers.WwwAuthenticate.Select(h => $"{h.Scheme} {h.Parameter}"));

    [Fact]
    public async Task A_bound_token_works_only_with_the_dpop_scheme_and_a_proof_for_it()
    {
        using var key = TestKey.Ec();
        var (tokens, _, _) = await BoundFlowAsync(key);
        var token = tokens.GetProperty("access_token").GetString()!;
        var http = Factory.Plain();

        var bearer = await McpAsync(http, token);
        Assert.Equal(HttpStatusCode.Unauthorized, bearer.Status);
        Assert.StartsWith("DPoP error=\"invalid_token\"", Challenge(bearer.Response));
        Assert.Contains("algs=\"ES256 ES512 PS256 RS256 EdDSA\"", Challenge(bearer.Response));

        var noProof = await McpAsync(http, token, "DPoP");
        Assert.Equal(HttpStatusCode.Unauthorized, noProof.Status);
        Assert.Contains("error=\"invalid_dpop_proof\"", Challenge(noProof.Response));

        var ok = await McpAsync(http, token, "DPoP", key.DpopProof("POST", Resource, token));
        Assert.Equal(HttpStatusCode.OK, ok.Status);
    }

    [Fact]
    public async Task The_proof_is_checked_against_the_token_the_key_the_method_the_address_and_replay()
    {
        using var key = TestKey.Ec();
        using var other = TestKey.Ec();
        var (tokens, _, _) = await BoundFlowAsync(key);
        var token = tokens.GetProperty("access_token").GetString()!;
        var (tokens2, _, _) = await BoundFlowAsync(key);
        var token2 = tokens2.GetProperty("access_token").GetString()!;
        var http = Factory.Plain();

        Assert.Equal(HttpStatusCode.Unauthorized, (await McpAsync(http, token, "DPoP", key.DpopProof("POST", Resource, token2))).Status);   // covers another token
        Assert.Equal(HttpStatusCode.Unauthorized, (await McpAsync(http, token, "DPoP", other.DpopProof("POST", Resource, token))).Status);   // another key
        Assert.Equal(HttpStatusCode.Unauthorized, (await McpAsync(http, token, "DPoP", key.DpopProof("GET", Resource, token))).Status);   // another method
        Assert.Equal(HttpStatusCode.Unauthorized, (await McpAsync(http, token, "DPoP", key.DpopProof("POST", "http://localhost/mcp/other", token))).Status);   // another address
        Assert.Equal(HttpStatusCode.Unauthorized, (await McpAsync(http, token, "DPoP", key.DpopProof("POST", Resource))).Status);   // no ath
        var proof = key.DpopProof("POST", Resource, token);
        Assert.Equal(HttpStatusCode.OK, (await McpAsync(http, token, "DPoP", proof)).Status);
        var replay = await McpAsync(http, token, "DPoP", proof);
        Assert.Equal(HttpStatusCode.Unauthorized, replay.Status);
        Assert.Contains("already been used", Challenge(replay.Response));
        // Each call needs its own proof, and any number of them work.
        Assert.Equal(HttpStatusCode.OK, (await McpAsync(http, token, "DPoP", key.DpopProof("POST", Resource, token))).Status);
    }

    [Fact]
    public async Task A_token_that_is_not_bound_cannot_be_used_under_the_dpop_scheme()
    {
        using var key = TestKey.Ec();
        var (tokens, _, _) = await BoundFlowAsync(null);
        var token = tokens.GetProperty("access_token").GetString()!;
        var http = Factory.Plain();
        var r = await McpAsync(http, token, "DPoP", key.DpopProof("POST", Resource, token));
        Assert.Equal(HttpStatusCode.Unauthorized, r.Status);
        Assert.Contains("error=\"invalid_token\"", Challenge(r.Response));
        Assert.Equal(HttpStatusCode.OK, (await McpAsync(http, token)).Status);
        // A first-party opaque token is a plain bearer too.
        Assert.Equal(HttpStatusCode.Unauthorized, (await McpAsync(http, "ow_mcp_at_unknown", "DPoP", key.DpopProof("POST", Resource, "ow_mcp_at_unknown"))).Status);
    }

    [Fact]
    public async Task Userinfo_asks_the_same_of_a_bound_token()
    {
        using var key = TestKey.Ec();
        var (browser, _, _, _) = await SignedInAsync();
        var clientId = await PublicClientAsync(browser, new { scope = "openid email mcp:read offline_access" });
        var (verifier, challenge) = Pkce();
        var scope = "openid email mcp:read offline_access";
        var code = await GetCodeAsync(browser, clientId, challenge, scope);
        var tokens = (await TokenAsync(browser, CodeForm(clientId, code, verifier), dpop: key.DpopProof("POST", TokenUrl))).Body;
        var token = tokens.GetProperty("access_token").GetString()!;
        const string userinfo = "http://localhost/api/auth/oauth2/userinfo";

        var bearer = await Factory.Plain().SendAsync(Bearer(HttpMethod.Get, "/api/auth/oauth2/userinfo", token));
        Assert.Equal(HttpStatusCode.Unauthorized, bearer.StatusCode);
        Assert.StartsWith("DPoP error=\"invalid_token\"", Challenge(bearer));

        var request = new HttpRequestMessage(HttpMethod.Get, "/api/auth/oauth2/userinfo");
        request.Headers.Authorization = new AuthenticationHeaderValue("DPoP", token);
        request.Headers.Add("DPoP", key.DpopProof("GET", userinfo, token));
        var ok = await Factory.Plain().SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.True((await ReadJsonAsync(ok)).TryGetProperty("sub", out _));

        var missing = new HttpRequestMessage(HttpMethod.Get, "/api/auth/oauth2/userinfo");
        missing.Headers.Authorization = new AuthenticationHeaderValue("DPoP", token);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Factory.Plain().SendAsync(missing)).StatusCode);
    }

    [Fact]
    public async Task Introspection_reports_the_binding()
    {
        using var key = TestKey.Ec();
        var (browser, _, _, _) = await SignedInAsync();
        var (_, body) = await RegisterAsync(browser, new { client_name = "Confidential", redirect_uris = new[] { Redirect }, token_endpoint_auth_method = "client_secret_basic" });
        var id = body.GetProperty("client_id").GetString()!;
        var secret = body.GetProperty("client_secret").GetString()!;
        var (verifier, challenge) = Pkce();
        var code = await GetCodeAsync(browser, id, challenge);
        var form = CodeForm(id, code, verifier);
        form.Remove("client_id");
        var tokens = (await TokenAsync(browser, form, Basic(id, secret), key.DpopProof("POST", TokenUrl))).Body;
        var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/oauth2/introspect") { Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["token"] = tokens.GetProperty("access_token").GetString()! }) };
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", Basic(id, secret));
        var introspected = await ReadJsonAsync(await Factory.Plain().SendAsync(request));
        Assert.True(introspected.GetProperty("active").GetBoolean());
        Assert.Equal("DPoP", introspected.GetProperty("token_type").GetString());
        Assert.Equal(key.Thumbprint, introspected.GetProperty("cnf").GetProperty("jkt").GetString());
    }
}
