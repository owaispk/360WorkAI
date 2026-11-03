using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Tests;

/// <summary>A signing key for tests (EC or RSA) with its public JWK, thumbprint, and a way to sign compact JWTs under any algorithm and any header or claims.</summary>
public sealed class TestKey : IDisposable
{
    private readonly ECDsa? _ec;
    private readonly RSA? _rsa;
    public string Alg { get; }
    public string Kid { get; }

    private TestKey(ECDsa? ec, RSA? rsa, string alg)
    {
        _ec = ec; _rsa = rsa; Alg = alg; Kid = "k-" + Guid.NewGuid().ToString("N")[..8];
    }

    public static TestKey Ec(string alg = "ES256") => new(ECDsa.Create(alg switch { "ES384" => ECCurve.NamedCurves.nistP384, "ES512" => ECCurve.NamedCurves.nistP521, _ => ECCurve.NamedCurves.nistP256 }), null, alg);
    public static TestKey Rsa(string alg = "RS256", int bits = 2048) => new(null, RSA.Create(bits), alg);
    public void Dispose() { _ec?.Dispose(); _rsa?.Dispose(); }

    public static string B64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    public static string B64(string text) => B64(Encoding.UTF8.GetBytes(text));

    /// <summary>The public key as a JWK; <paramref name="withKid"/> and <paramref name="withAlg"/> add those members.</summary>
    public JsonObject Jwk(bool withKid = false, bool withAlg = false)
    {
        var jwk = new JsonObject();
        if (_ec is not null)
        {
            var p = _ec.ExportParameters(false);
            jwk["kty"] = "EC";
            jwk["crv"] = Alg switch { "ES384" => "P-384", "ES512" => "P-521", _ => "P-256" };
            jwk["x"] = B64(p.Q.X!);
            jwk["y"] = B64(p.Q.Y!);
        }
        else
        {
            var p = _rsa!.ExportParameters(false);
            jwk["kty"] = "RSA";
            jwk["n"] = B64(p.Modulus!);
            jwk["e"] = B64(p.Exponent!);
        }
        if (withKid) jwk["kid"] = Kid;
        if (withAlg) jwk["alg"] = Alg;
        return jwk;
    }

    public JsonObject Jwks(bool withKid = true) => new() { ["keys"] = new JsonArray(Jwk(withKid)) };

    public string Thumbprint => Jose.Thumbprint(JsonDocument.Parse(Jwk().ToJsonString()).RootElement)!;

    public byte[] Sign(string signingInput, string? alg = null)
    {
        alg ??= Alg;
        var data = Encoding.ASCII.GetBytes(signingInput);
        var hash = alg[^3..] switch { "256" => HashAlgorithmName.SHA256, "384" => HashAlgorithmName.SHA384, _ => HashAlgorithmName.SHA512 };
        if (_ec is not null) return _ec.SignData(data, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return _rsa!.SignData(data, hash, alg.StartsWith("PS", StringComparison.Ordinal) ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);
    }

    /// <summary>A compact JWT signed by this key. The header and claims are exactly what is passed.</summary>
    public string Jwt(JsonObject header, JsonObject claims, string? alg = null)
    {
        var signingInput = $"{B64(header.ToJsonString())}.{B64(claims.ToJsonString())}";
        return $"{signingInput}.{B64(Sign(signingInput, alg))}";
    }

    // ---------------------------------------------------------------- DPoP proofs (RFC 9449)

    /// <summary>A DPoP proof. Everything can be overridden to make a bad one.</summary>
    public string DpopProof(string method, string url, string? accessToken = null, string? jti = null, long? iat = null, string typ = "dpop+jwt", Action<JsonObject>? header = null, Action<JsonObject>? claims = null, string? alg = null)
    {
        var h = new JsonObject { ["typ"] = typ, ["alg"] = alg ?? Alg, ["jwk"] = Jwk() };
        var c = new JsonObject { ["htm"] = method, ["htu"] = url, ["jti"] = jti ?? Guid.NewGuid().ToString("N"), ["iat"] = iat ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds() };
        if (accessToken is not null) c["ath"] = DpopVerifier.AccessTokenHash(accessToken);
        header?.Invoke(h);
        claims?.Invoke(c);
        return Jwt(h, c, alg);
    }

    // ---------------------------------------------------------------- client assertions (RFC 7523)

    public string ClientAssertion(string clientId, string audience, string? jti = null, long? exp = null, long? iat = null, bool withKid = true, Action<JsonObject>? claims = null, Action<JsonObject>? header = null, string? alg = null)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var h = new JsonObject { ["alg"] = alg ?? Alg, ["typ"] = "JWT" };
        if (withKid) h["kid"] = Kid;
        var c = new JsonObject { ["iss"] = clientId, ["sub"] = clientId, ["aud"] = audience, ["jti"] = jti ?? Guid.NewGuid().ToString("N"), ["iat"] = iat ?? now, ["exp"] = exp ?? now + 120 };
        header?.Invoke(h);
        claims?.Invoke(c);
        return Jwt(h, c, alg);
    }
}
