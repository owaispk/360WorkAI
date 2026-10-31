using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WorkAI360.Api.Features.Sso;

public sealed class OidcException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

/// <summary>
/// Validates an OpenID Connect ID token the way the spec and the security BCP ask: only asymmetric algorithms (never "none", never HMAC, which
/// is how a public key gets turned into a secret), the signature against the provider's own published keys, and then issuer, audience
/// (and authorized party), expiry, not-before, nonce and subject.
/// </summary>
public static class IdTokenValidator
{
    private static readonly HashSet<string> Algorithms = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"];
    public static readonly TimeSpan Skew = TimeSpan.FromSeconds(60);

    /// <summary>The nonce is kept only as a SHA-256 hex hash; the token's nonce is hashed the same way to compare.</summary>
    public sealed record Expected(string Issuer, string ClientId, string NonceHash, DateTimeOffset Now);

    public static JsonElement Validate(string token, string jwksJson, Expected expected)
    {
        var parts = token.Split('.');
        if (parts.Length != 3 || parts[2].Length == 0) throw new OidcException("invalid_token", "The ID token is not a signed JWT.");

        JsonElement header, payload;
        byte[] signature;
        try
        {
            header = JsonDocument.Parse(Decode(parts[0])).RootElement.Clone();
            payload = JsonDocument.Parse(Decode(parts[1])).RootElement.Clone();
            signature = Decode(parts[2]);
        }
        catch (Exception e) when (e is FormatException or JsonException) { throw new OidcException("invalid_token", "The ID token could not be read."); }
        if (header.ValueKind != JsonValueKind.Object || payload.ValueKind != JsonValueKind.Object) throw new OidcException("invalid_token", "The ID token could not be read.");

        var alg = Str(header, "alg");
        if (alg is null || !Algorithms.Contains(alg)) throw new OidcException("invalid_token", "The ID token uses an algorithm that is not allowed.");
        var kid = Str(header, "kid");

        var signed = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);
        if (!VerifySignature(alg, kid, signed, signature, jwksJson)) throw new OidcException("invalid_token", "The ID token signature is not valid.");

        if (Str(payload, "iss") != expected.Issuer) throw new OidcException("invalid_token", "The ID token was issued by someone else.");

        var audiences = new List<string>();
        if (payload.TryGetProperty("aud", out var aud))
        {
            if (aud.ValueKind == JsonValueKind.String) audiences.Add(aud.GetString()!);
            else if (aud.ValueKind == JsonValueKind.Array) audiences.AddRange(aud.EnumerateArray().Where(a => a.ValueKind == JsonValueKind.String).Select(a => a.GetString()!));
        }
        if (!audiences.Contains(expected.ClientId, StringComparer.Ordinal)) throw new OidcException("invalid_token", "The ID token was not issued for this application.");
        if (audiences.Count > 1 && Str(payload, "azp") != expected.ClientId) throw new OidcException("invalid_token", "The ID token's authorized party is not this application.");
        if (payload.TryGetProperty("azp", out _) && Str(payload, "azp") != expected.ClientId) throw new OidcException("invalid_token", "The ID token's authorized party is not this application.");

        var now = expected.Now;
        if (Number(payload, "exp") is not { } exp) throw new OidcException("invalid_token", "The ID token has no expiry.");
        if (DateTimeOffset.FromUnixTimeSeconds(exp) + Skew <= now) throw new OidcException("invalid_token", "The ID token has expired.");
        if (Number(payload, "nbf") is { } nbf && DateTimeOffset.FromUnixTimeSeconds(nbf) - Skew > now) throw new OidcException("invalid_token", "The ID token is not valid yet.");
        if (Number(payload, "iat") is { } iat && DateTimeOffset.FromUnixTimeSeconds(iat) - Skew > now) throw new OidcException("invalid_token", "The ID token was issued in the future.");

        var nonce = Str(payload, "nonce");
        if (nonce is null || !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(nonce)))), Encoding.UTF8.GetBytes(expected.NonceHash)))
            throw new OidcException("invalid_token", "The ID token does not belong to this sign-in (nonce).");

        if (string.IsNullOrEmpty(Str(payload, "sub"))) throw new OidcException("invalid_token", "The ID token has no subject.");
        return payload;
    }

    private static bool VerifySignature(string alg, string? kid, byte[] data, byte[] signature, string jwksJson)
    {
        JsonElement keys;
        try
        {
            keys = JsonDocument.Parse(jwksJson).RootElement.GetProperty("keys").Clone();
        }
        catch (Exception e) when (e is JsonException or KeyNotFoundException or InvalidOperationException) { throw new OidcException("invalid_provider", "The provider's key set could not be read."); }
        if (keys.ValueKind != JsonValueKind.Array) throw new OidcException("invalid_provider", "The provider's key set could not be read.");

        var wantType = alg.StartsWith("ES", StringComparison.Ordinal) ? "EC" : "RSA";
        var candidates = keys.EnumerateArray().Where(k => k.ValueKind == JsonValueKind.Object
            && Str(k, "kty") == wantType
            && (Str(k, "use") is null or "sig")
            && (Str(k, "alg") is null || Str(k, "alg") == alg)
            && (kid is null || Str(k, "kid") == kid)).ToList();
        // Without a key id in the header only a single matching key is unambiguous.
        if (kid is null && candidates.Count != 1) return false;
        foreach (var key in candidates)
        {
            try { if (VerifyWith(alg, key, data, signature)) return true; }
            catch (Exception e) when (e is CryptographicException or FormatException or ArgumentException) { }
        }
        return false;
    }

    private static bool VerifyWith(string alg, JsonElement jwk, byte[] data, byte[] signature)
    {
        var hash = alg[^3..] switch { "256" => HashAlgorithmName.SHA256, "384" => HashAlgorithmName.SHA384, _ => HashAlgorithmName.SHA512 };
        if (alg.StartsWith("ES", StringComparison.Ordinal))
        {
            var curve = Str(jwk, "crv") switch { "P-256" => ECCurve.NamedCurves.nistP256, "P-384" => ECCurve.NamedCurves.nistP384, "P-521" => ECCurve.NamedCurves.nistP521, _ => throw new ArgumentException("curve") };
            var expectedCurve = alg switch { "ES256" => "P-256", "ES384" => "P-384", _ => "P-521" };
            if (Str(jwk, "crv") != expectedCurve) return false;
            using var ec = ECDsa.Create(new ECParameters { Curve = curve, Q = new ECPoint { X = Decode(Str(jwk, "x")!), Y = Decode(Str(jwk, "y")!) } });
            return ec.VerifyData(data, signature, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        using var rsa = RSA.Create(new RSAParameters { Modulus = Decode(Str(jwk, "n")!), Exponent = Decode(Str(jwk, "e")!) });
        if (rsa.KeySize < 2048) return false;
        return rsa.VerifyData(data, signature, hash, alg.StartsWith("PS", StringComparison.Ordinal) ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);
    }

    private static string? Str(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static long? Number(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetDouble(out var d) ? (long)Math.Floor(d) : null;

    private static byte[] Decode(string value)
    {
        var s = value.Replace('-', '+').Replace('_', '/');
        s = s.PadRight(s.Length + (4 - s.Length % 4) % 4, '=');
        return Convert.FromBase64String(s);
    }
}
