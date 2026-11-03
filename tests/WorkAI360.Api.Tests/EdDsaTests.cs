using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Tests;

/// <summary>EdDSA (Ed25519, OKP keys) for client assertions and DPoP proofs, as the reference allows.</summary>
public sealed class EdDsaTests(OAuthExtrasFactory factory) : OAuthExtrasBase(factory), IClassFixture<OAuthExtrasFactory>
{
    private static JsonElement El(JsonObject o) => JsonDocument.Parse(o.ToJsonString()).RootElement.Clone();

    [Fact]
    public void Rfc8037_thumbprint_and_signature_checks()
    {
        // RFC 8037 appendix A.3.
        var rfcKey = El(new JsonObject { ["kty"] = "OKP", ["crv"] = "Ed25519", ["x"] = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" });
        Assert.Equal("kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k", Jose.Thumbprint(rfcKey));
        Assert.Null(Jose.ValidatePublicKey(rfcKey));

        using var key = TestKey.Ed();
        using var other = TestKey.Ed();
        using var ec = TestKey.Ec();
        var jwt = key.Jwt(new JsonObject { ["alg"] = "EdDSA" }, new JsonObject { ["sub"] = "x" });
        var parsed = Jose.Parse(jwt)!;
        Assert.True(Jose.Verify(parsed, El(key.Jwk()), Jose.AssertionAlgorithms));
        Assert.False(Jose.Verify(parsed, El(other.Jwk()), Jose.AssertionAlgorithms));                 // another key
        Assert.False(Jose.Verify(parsed, El(ec.Jwk()), Jose.AssertionAlgorithms));                    // an EC key cannot verify EdDSA
        Assert.False(Jose.Verify(Jose.Parse(jwt[..^4] + "AAAA")!, El(key.Jwk()), Jose.AssertionAlgorithms)); // altered signature
        var tampered = jwt.Split('.');
        Assert.False(Jose.Verify(Jose.Parse($"{tampered[0]}.{TestKey.B64("{\"sub\":\"y\"}")}.{tampered[2]}")!, El(key.Jwk()), Jose.AssertionAlgorithms));
        Assert.False(Jose.Verify(parsed, El(key.Jwk()), ["ES256"]));                                   // not on the allow-list
        // The same bytes labelled as an X25519 (key agreement) key never verify a signature.
        var relabelled = key.Jwk(); relabelled["crv"] = "X25519";
        Assert.False(Jose.Verify(parsed, El(relabelled), Jose.AssertionAlgorithms));
        Assert.Empty(Jose.AlgorithmsFor(El(relabelled)));
        // An EC signature labelled EdDSA does not verify against an OKP key either.
        var mislabelled = ec.Jwt(new JsonObject { ["alg"] = "EdDSA" }, new JsonObject { ["sub"] = "x" }, alg: "ES256");
        Assert.False(Jose.Verify(Jose.Parse(mislabelled)!, El(key.Jwk()), Jose.AssertionAlgorithms));
        // Shape checks.
        Assert.NotNull(Jose.ValidatePublicKey(El(new JsonObject { ["kty"] = "OKP", ["crv"] = "X25519", ["x"] = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" })));
        Assert.NotNull(Jose.ValidatePublicKey(El(new JsonObject { ["kty"] = "OKP", ["crv"] = "Ed25519", ["x"] = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo", ["d"] = "AAAA" })));
    }

    [Fact]
    public async Task A_client_with_an_ed25519_key_authenticates_with_an_eddsa_assertion()
    {
        using var key = TestKey.Ed();
        var (browser, _, _, _) = await SignedInAsync();
        var (status, body) = await RegisterAsync(browser, new
        {
            client_name = "Ed Signer", token_endpoint_auth_method = "private_key_jwt", grant_types = new[] { "client_credentials" },
            jwks = new JsonObject { ["keys"] = new JsonArray(key.Jwk(withKid: true)) },
        });
        Assert.Equal(HttpStatusCode.Created, status);
        var id = body.GetProperty("client_id").GetString()!;
        await GrantAsync(id, "mcp:read");

        Dictionary<string, string> Form(string assertion) => new()
        {
            ["grant_type"] = "client_credentials", ["client_assertion_type"] = ClientAssertionVerifier.AssertionType, ["client_assertion"] = assertion,
        };
        var (ok, tokens, _) = await TokenAsync(Factory.Plain(), Form(key.ClientAssertion(id, TokenUrl)));
        Assert.Equal(HttpStatusCode.OK, ok);
        Assert.Equal(id, Payload(tokens.GetProperty("access_token").GetString()!).GetProperty("sub").GetString());

        using var stranger = TestKey.Ed();
        var (refused, _, _) = await TokenAsync(Factory.Plain(), Form(stranger.ClientAssertion(id, TokenUrl, withKid: false)));
        Assert.Equal(HttpStatusCode.Unauthorized, refused);
    }

    [Fact]
    public async Task An_eddsa_dpop_proof_binds_tokens_and_is_accepted_at_the_mcp_endpoint()
    {
        using var key = TestKey.Ed();
        var (tokens, _, _) = await BoundFlowAsync(key);
        Assert.Equal("DPoP", tokens.GetProperty("token_type").GetString());
        var access = tokens.GetProperty("access_token").GetString()!;
        Assert.Equal(key.Thumbprint, Payload(access).GetProperty("cnf").GetProperty("jkt").GetString());
        Assert.Equal(HttpStatusCode.OK, (await McpAsync(Factory.Plain(), access, "DPoP", key.DpopProof("POST", Resource, access))).Status);
        using var other = TestKey.Ed();
        Assert.Equal(HttpStatusCode.Unauthorized, (await McpAsync(Factory.Plain(), access, "DPoP", other.DpopProof("POST", Resource, access))).Status);
    }

    [Fact]
    public void Discovery_lists_eddsa_for_assertions_and_proofs()
    {
        Assert.Contains("EdDSA", Jose.AssertionAlgorithms);
        Assert.Contains("EdDSA", DpopVerifier.SigningAlgorithms);
    }
}
