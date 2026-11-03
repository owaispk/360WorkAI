using System.Net;
using System.Text.Json;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>A deployment that requires server-provided DPoP nonces (OAuth:DpopNonceRequired=true).</summary>
public sealed class DpopNonceFactory : OAuthExtrasFactory
{
    protected override IEnumerable<KeyValuePair<string, string>> Settings => [.. base.Settings, new("OAuth:DpopNonceRequired", "true")];
}

/// <summary>RFC 9449 sections 8 and 9: server nonces at the token endpoint and at the MCP endpoint.</summary>
public sealed class DpopNonceTests(DpopNonceFactory factory) : OAuthExtrasBase(factory), IClassFixture<DpopNonceFactory>
{
    private static string? Nonce(HttpResponseMessage r) => r.Headers.TryGetValues("DPoP-Nonce", out var v) ? v.Single() : null;

    [Fact]
    public async Task The_token_endpoint_asks_for_a_nonce_then_accepts_the_retry_without_spending_the_code()
    {
        using var key = TestKey.Ec();
        var (browser, _, _, _) = await SignedInAsync();
        var clientId = await PublicClientAsync(browser);
        var (verifier, challenge) = Pkce();
        var code = await GetCodeAsync(browser, clientId, challenge);

        var (status, body, response) = await TokenAsync(browser, CodeForm(clientId, code, verifier), dpop: key.DpopProof("POST", TokenUrl));
        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Equal("use_dpop_nonce", Err(body));
        Assert.Equal("Authorization server requires nonce in DPoP proof", Desc(body));
        var nonce = Nonce(response);
        Assert.False(string.IsNullOrEmpty(nonce));

        var (retryStatus, tokens, retry) = await TokenAsync(browser, CodeForm(clientId, code, verifier), dpop: key.DpopProof("POST", TokenUrl, claims: c => c["nonce"] = nonce));
        Assert.Equal(HttpStatusCode.OK, retryStatus);
        Assert.Equal("DPoP", tokens.GetProperty("token_type").GetString());
        Assert.NotNull(Nonce(retry));
    }

    [Fact]
    public async Task The_mcp_endpoint_challenges_for_a_nonce_and_accepts_one()
    {
        using var key = TestKey.Ec();
        var (browser, _, _, _) = await SignedInAsync();
        var clientId = await PublicClientAsync(browser);
        var (verifier, challenge) = Pkce();
        var code = await GetCodeAsync(browser, clientId, challenge);
        var (_, first, firstResponse) = await TokenAsync(browser, CodeForm(clientId, code, verifier), dpop: key.DpopProof("POST", TokenUrl));
        Assert.Equal("use_dpop_nonce", Err(first));
        var (_, tokens, _) = await TokenAsync(browser, CodeForm(clientId, code, verifier), dpop: key.DpopProof("POST", TokenUrl, claims: c => c["nonce"] = Nonce(firstResponse)));
        var access = tokens.GetProperty("access_token").GetString()!;

        var (status, response) = await McpAsync(Factory.Plain(), access, "DPoP", key.DpopProof("POST", Resource, access));
        Assert.Equal(HttpStatusCode.Unauthorized, status);
        Assert.Contains("error=\"use_dpop_nonce\"", response.Headers.WwwAuthenticate.ToString());
        var nonce = Nonce(response);
        Assert.NotNull(nonce);

        var (okStatus, ok) = await McpAsync(Factory.Plain(), access, "DPoP", key.DpopProof("POST", Resource, access, claims: c => c["nonce"] = nonce));
        Assert.Equal(HttpStatusCode.OK, okStatus);
        Assert.NotNull(Nonce(ok));
    }

    [Fact]
    public async Task Made_up_nonces_are_refused()
    {
        using var key = TestKey.Ec();
        var (browser, _, _, _) = await SignedInAsync();
        var clientId = await PublicClientAsync(browser);
        var (verifier, challenge) = Pkce();
        var code = await GetCodeAsync(browser, clientId, challenge);
        foreach (var bad in new[] { "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "nonce", new string('x', 100) })
        {
            var (status, body, _) = await TokenAsync(browser, CodeForm(clientId, code, verifier), dpop: key.DpopProof("POST", TokenUrl, claims: c => c["nonce"] = bad));
            Assert.Equal(HttpStatusCode.BadRequest, status);
            Assert.Equal("use_dpop_nonce", Err(body));
        }
    }
}

/// <summary>Nonces are off by default (the reference does not use them): no header, no requirement.</summary>
public sealed class DpopNonceOffTests(OAuthExtrasFactory factory) : OAuthExtrasBase(factory), IClassFixture<OAuthExtrasFactory>
{
    [Fact]
    public async Task By_default_no_nonce_is_asked_for_or_sent()
    {
        using var key = TestKey.Ec();
        var (browser, _, _, _) = await SignedInAsync();
        var clientId = await PublicClientAsync(browser);
        var (verifier, challenge) = Pkce();
        var code = await GetCodeAsync(browser, clientId, challenge);
        var (status, _, response) = await TokenAsync(browser, CodeForm(clientId, code, verifier), dpop: key.DpopProof("POST", TokenUrl));
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.False(response.Headers.Contains("DPoP-Nonce"));
    }
}
