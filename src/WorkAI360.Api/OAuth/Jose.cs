using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WorkAI360.Api.OAuth;

/// <summary>A compact JWS taken apart, signature not yet checked.</summary>
public sealed record ParsedJwt(JsonElement Header, JsonElement Payload, string SigningInput, byte[] Signature)
{
    public string? HeaderString(string name) => Header.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    public string? PayloadString(string name) => Payload.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    public long? PayloadNumber(string name) => Payload.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var n) ? n : null;
}

/// <summary>
/// The small amount of JOSE the OAuth extras need: reading a compact JWT, checking its signature against a JSON Web Key, and the RFC 7638 JWK
/// thumbprint. Only asymmetric algorithms ever verify (never "none", never HMAC, so a public key cannot be turned into a secret), RSA keys must be at
/// least 2048 bits, and a key only verifies the algorithm family it belongs to. EdDSA (Ed25519, <c>kty: OKP</c>) is verified with BouncyCastle, since .NET
/// has no built-in Ed25519.
/// </summary>
public static class Jose
{
    public const int MaxTokenLength = 16 * 1024;
    public static readonly string[] AssertionAlgorithms = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"];

    public static ParsedJwt? Parse(string? jwt)
    {
        if (string.IsNullOrEmpty(jwt) || jwt.Length > MaxTokenLength) return null;
        var parts = jwt.Split('.');
        if (parts.Length != 3 || parts[0].Length == 0 || parts[1].Length == 0 || parts[2].Length == 0) return null;
        try
        {
            using var header = JsonDocument.Parse(SigningKeyStore.FromBase64Url(parts[0]));
            using var payload = JsonDocument.Parse(SigningKeyStore.FromBase64Url(parts[1]));
            if (header.RootElement.ValueKind != JsonValueKind.Object || payload.RootElement.ValueKind != JsonValueKind.Object) return null;
            return new ParsedJwt(header.RootElement.Clone(), payload.RootElement.Clone(), $"{parts[0]}.{parts[1]}", SigningKeyStore.FromBase64Url(parts[2]));
        }
        catch (Exception e) when (e is JsonException or FormatException or ArgumentException) { return null; }
    }

    /// <summary>The algorithm names a key of this shape can verify (for choosing candidate keys).</summary>
    public static string[] AlgorithmsFor(JsonElement jwk) => Str(jwk, "kty") switch
    {
        "RSA" => ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"],
        "EC" => Str(jwk, "crv") switch { "P-256" => ["ES256"], "P-384" => ["ES384"], "P-521" => ["ES512"], _ => [] },
        "OKP" when Str(jwk, "crv") == "Ed25519" => ["EdDSA"],
        _ => [],
    };

    /// <summary>True when the signature on the token was made with this key under the token's own <c>alg</c>.</summary>
    public static bool Verify(ParsedJwt jwt, JsonElement jwk, IReadOnlyCollection<string> allowedAlgorithms)
    {
        var alg = jwt.HeaderString("alg");
        if (alg is null || !allowedAlgorithms.Contains(alg) || !AlgorithmsFor(jwk).Contains(alg)) return false;
        if (Str(jwk, "alg") is { } keyAlg && keyAlg != alg) return false;
        if (Str(jwk, "use") is { } use && use != "sig") return false;
        if (HasPrivateMembers(jwk)) return false;
        var data = Encoding.ASCII.GetBytes(jwt.SigningInput);
        try
        {
            if (alg == "EdDSA") return VerifyEd25519(jwk, data, jwt.Signature);
            if (alg.StartsWith("ES", StringComparison.Ordinal))
            {
                using var ec = ImportEc(jwk);
                return ec.VerifyData(data, jwt.Signature, HashFor(alg), DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
            using var rsa = ImportRsa(jwk);
            if (rsa.KeySize < 2048) return false;
            return rsa.VerifyData(data, jwt.Signature, HashFor(alg), alg.StartsWith("PS", StringComparison.Ordinal) ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1);
        }
        catch (Exception e) when (e is CryptographicException or FormatException or ArgumentException) { return false; }
    }

    public static bool HasPrivateMembers(JsonElement jwk) => new[] { "d", "p", "q", "dp", "dq", "qi", "oth", "k" }.Any(name => jwk.TryGetProperty(name, out _));

    /// <summary>The RFC 7638 thumbprint (SHA-256, base64url) of a public RSA or EC key; null for anything else.</summary>
    public static string? Thumbprint(JsonElement jwk)
    {
        string? canonical = Str(jwk, "kty") switch
        {
            "RSA" when Str(jwk, "e") is { } e && Str(jwk, "n") is { } n => $"{{\"e\":{JsonSerializer.Serialize(e)},\"kty\":\"RSA\",\"n\":{JsonSerializer.Serialize(n)}}}",
            "EC" when Str(jwk, "crv") is { } crv && Str(jwk, "x") is { } x && Str(jwk, "y") is { } y => $"{{\"crv\":{JsonSerializer.Serialize(crv)},\"kty\":\"EC\",\"x\":{JsonSerializer.Serialize(x)},\"y\":{JsonSerializer.Serialize(y)}}}",
            // RFC 8037 section 2: crv, kty, x.
            "OKP" when Str(jwk, "crv") is { } okpCrv && Str(jwk, "x") is { } okpX => $"{{\"crv\":{JsonSerializer.Serialize(okpCrv)},\"kty\":\"OKP\",\"x\":{JsonSerializer.Serialize(okpX)}}}",
            _ => null,
        };
        return canonical is null ? null : SigningKeyStore.Base64Url(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }

    /// <summary>Checks a public JWK is one we can verify with (shape, curve, no private parts, importable, RSA at least 2048 bits). Returns the reason when not.</summary>
    public static string? ValidatePublicKey(JsonElement jwk)
    {
        if (jwk.ValueKind != JsonValueKind.Object) return "jwks keys must be supported public JWKs with required key parameters";
        if (Str(jwk, "kty") == "oct" || HasPrivateMembers(jwk)) return "jwks must contain only public asymmetric keys";
        var kty = Str(jwk, "kty");
        var supported = kty switch
        {
            "RSA" => Str(jwk, "n") is { Length: > 0 } && Str(jwk, "e") is { Length: > 0 },
            "EC" => Str(jwk, "crv") is "P-256" or "P-384" or "P-521" && Str(jwk, "x") is { Length: > 0 } && Str(jwk, "y") is { Length: > 0 },
            "OKP" => Str(jwk, "crv") == "Ed25519" && Str(jwk, "x") is { Length: > 0 },
            _ => false,
        };
        if (!supported) return "jwks keys must be supported public JWKs with required key parameters";
        if (Str(jwk, "alg") is { } alg && (!AssertionAlgorithms.Contains(alg) || !AlgorithmsFor(jwk).Contains(alg)))
            return "jwks key alg must be supported for private_key_jwt and compatible with its key type and signing curve";
        try
        {
            if (kty == "EC") { using var _ = ImportEc(jwk); }
            else if (kty == "OKP") { if (SigningKeyStore.FromBase64Url(Str(jwk, "x")!).Length != 32) return "jwks keys must be supported public JWKs with required key parameters"; }
            else { using var rsa = ImportRsa(jwk); if (rsa.KeySize < 2048) return "jwks RSA keys must be at least 2048 bits"; }
        }
        catch (Exception e) when (e is CryptographicException or FormatException or ArgumentException) { return "jwks keys must be supported public JWKs with required key parameters"; }
        return null;
    }

    public static string? Str(JsonElement e, string name) => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static HashAlgorithmName HashFor(string alg) => alg[^3..] switch { "256" => HashAlgorithmName.SHA256, "384" => HashAlgorithmName.SHA384, _ => HashAlgorithmName.SHA512 };

    private static RSA ImportRsa(JsonElement jwk)
    {
        var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters { Modulus = SigningKeyStore.FromBase64Url(Str(jwk, "n")!), Exponent = SigningKeyStore.FromBase64Url(Str(jwk, "e")!) });
        return rsa;
    }

    /// <summary>Ed25519 (RFC 8032) over the signing input, with a 32-byte public key and a 64-byte signature.</summary>
    private static bool VerifyEd25519(JsonElement jwk, byte[] data, byte[] signature)
    {
        var x = SigningKeyStore.FromBase64Url(Str(jwk, "x")!);
        if (x.Length != 32 || signature.Length != 64) return false;
        var verifier = new Org.BouncyCastle.Crypto.Signers.Ed25519Signer();
        verifier.Init(false, new Org.BouncyCastle.Crypto.Parameters.Ed25519PublicKeyParameters(x, 0));
        verifier.BlockUpdate(data, 0, data.Length);
        return verifier.VerifySignature(signature);
    }

    private static ECDsa ImportEc(JsonElement jwk)
    {
        var curve = Str(jwk, "crv") switch { "P-256" => ECCurve.NamedCurves.nistP256, "P-384" => ECCurve.NamedCurves.nistP384, "P-521" => ECCurve.NamedCurves.nistP521, _ => throw new ArgumentException("curve") };
        return ECDsa.Create(new ECParameters { Curve = curve, Q = new ECPoint { X = SigningKeyStore.FromBase64Url(Str(jwk, "x")!), Y = SigningKeyStore.FromBase64Url(Str(jwk, "y")!) } });
    }
}
