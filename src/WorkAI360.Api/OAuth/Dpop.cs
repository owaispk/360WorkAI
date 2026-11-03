using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using WorkAI360.Api.Features.Replay;

namespace WorkAI360.Api.OAuth;

/// <summary>A DPoP proof (or a bound token's use) that is not acceptable. The code is always <c>invalid_dpop_proof</c> (or <c>invalid_token</c> at a resource).</summary>
public sealed class DpopException(string message, string code = "invalid_dpop_proof") : Exception(message)
{
    public string Code { get; } = code;
}

public sealed record DpopProof(string Jkt, string Jti, string Method, string Url, long IssuedAt);

/// <summary>
/// DPoP, RFC 9449, as the reference's OAuth provider does it: a token request may carry a <c>DPoP</c> proof; the access token (and refresh token) is then
/// bound to the proof's key (<c>cnf.jkt</c>, <c>token_type: "DPoP"</c>). Checks, in the reference's wording: <c>typ</c> is <c>dpop+jwt</c>; the algorithm is
/// asymmetric and on the allow-list; the header carries a public <c>jwk</c> (never private material); the signature verifies under that key;
/// <c>htm</c>, <c>htu</c>, <c>jti</c> (at most 512 characters) and <c>iat</c> are present; <c>htm</c> is the request method and <c>htu</c> the request URL (query and
/// case of the host ignored); <c>iat</c> is no more than 5 seconds ahead and at most 5 minutes old; at a resource <c>ath</c> is the SHA-256 of the access token
/// and the key must be the one the token is bound to. A proof works once: its (key, method, URL, jti) goes into the replay cache.
/// The allowed algorithms are ES256, ES512, PS256, RS256 and EdDSA (Ed25519, verified with BouncyCastle); <c>exp</c> and <c>nbf</c> in a proof are honoured.
/// </summary>
public sealed class DpopVerifier(ReplayGuard replay, DpopNonces nonces)
{
    public static readonly string[] SigningAlgorithms = ["ES256", "ES512", "PS256", "RS256", "EdDSA"];
    public const int MaxAgeSeconds = 300;
    public const int MaxFutureSeconds = 5;
    public const int MaxJtiLength = 512;
    public const string ReplayKind = "dpop-proof";

    /// <param name="acceptableUrls">The addresses this endpoint answers at; a proof's <c>htu</c> must match one (query and fragment ignored).</param>
    /// <param name="accessToken">At a resource: the token presented, so that <c>ath</c> can be checked (and is then required).</param>
    /// <param name="expectedJkt">The key the token or grant is bound to, when it is.</param>
    public async Task<DpopProof> VerifyAsync(string? proofJwt, string method, IEnumerable<string> acceptableUrls, string? accessToken, string? expectedJkt, CancellationToken ct = default)
    {
        var jwt = Jose.Parse(proofJwt) ?? throw new DpopException("DPoP proof must be a compact JWT");
        if (jwt.HeaderString("typ") != "dpop+jwt") throw new DpopException("DPoP proof typ must be \"dpop+jwt\"");
        var alg = jwt.HeaderString("alg");
        if (alg is null || alg == "none" || alg.StartsWith("HS", StringComparison.Ordinal)) throw new DpopException("DPoP proof must use an asymmetric JWS algorithm");
        if (!SigningAlgorithms.Contains(alg)) throw new DpopException("DPoP proof uses an unsupported JWS algorithm");
        if (!jwt.Header.TryGetProperty("jwk", out var jwk) || jwk.ValueKind != JsonValueKind.Object) throw new DpopException("DPoP proof header must include a public jwk");
        if (Jose.Str(jwk, "kty") == "oct") throw new DpopException("DPoP proof jwk must be asymmetric");
        if (Jose.HasPrivateMembers(jwk)) throw new DpopException("DPoP proof jwk must not contain private key material");
        if (!Jose.Verify(jwt, jwk, SigningAlgorithms)) throw new DpopException("DPoP proof signature is invalid");
        var jkt = Jose.Thumbprint(jwk) ?? throw new DpopException("DPoP proof jwk is not a supported public key");

        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (jwt.PayloadNumber("exp") is { } exp && exp <= now) throw new DpopException("DPoP proof has expired");
        if (jwt.PayloadNumber("nbf") is { } nbf && nbf > now + MaxFutureSeconds) throw new DpopException("DPoP proof is not yet valid");
        var htm = jwt.PayloadString("htm");
        var htu = jwt.PayloadString("htu");
        var jti = jwt.PayloadString("jti");
        var iat = jwt.PayloadNumber("iat");
        if (string.IsNullOrEmpty(htm) || string.IsNullOrEmpty(htu) || string.IsNullOrEmpty(jti) || iat is null) throw new DpopException("DPoP proof must include htm, htu, jti, and iat claims");
        if (jti.Length > MaxJtiLength) throw new DpopException("DPoP proof jti is too large");
        if (!htm.Equals(method, StringComparison.OrdinalIgnoreCase)) throw new DpopException("DPoP proof htm does not match the request method");
        var proofUrl = NormalizeUrl(htu) ?? throw new DpopException("DPoP proof htu is invalid");
        if (!acceptableUrls.Select(NormalizeUrl).Any(u => u is not null && u == proofUrl)) throw new DpopException("DPoP proof htu does not match the request URL");
        if (iat > now + MaxFutureSeconds || now - iat > MaxAgeSeconds) throw new DpopException("DPoP proof iat is outside the accepted window");

        var ath = jwt.PayloadString("ath");
        if (accessToken is not null)
        {
            if (ath is null) throw new DpopException("DPoP proof must include an ath claim");
            if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(ath), Encoding.ASCII.GetBytes(AccessTokenHash(accessToken))))
                throw new DpopException("DPoP proof ath does not match the access token");
        }
        if (expectedJkt is not null && !CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(jkt), Encoding.ASCII.GetBytes(expectedJkt)))
            throw new DpopException("DPoP proof key does not match the bound token");
        // Server nonces, when this deployment asks for them (checked before the jti is spent, so the retry with a fresh proof goes through).
        nonces.Check(jwt.PayloadString("nonce"), atResource: accessToken is not null);

        // A proof works once per (key, method, URL, jti) for as long as it could be accepted.
        var expires = DateTimeOffset.FromUnixTimeSeconds(iat.Value + MaxAgeSeconds).UtcDateTime;
        if (!await replay.ReserveAsync(ReplayKind, $"{jkt}\n{htm.ToUpperInvariant()}\n{proofUrl}\n{jti}", expires, ct)) throw new DpopException("DPoP proof jti has already been used");
        return new DpopProof(jkt, jti, htm.ToUpperInvariant(), proofUrl, iat.Value);
    }

    /// <summary><c>ath</c>: the base64url SHA-256 of the access token.</summary>
    public static string AccessTokenHash(string accessToken) => SigningKeyStore.Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken)));

    /// <summary>The reference's <c>normalizeDpopHtu</c>: origin and path, no query; a fragment is not allowed.</summary>
    public static string? NormalizeUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https") || uri.Fragment.Length > 0 || url.Contains('#')) return null;
        var authority = uri.IsDefaultPort ? uri.Host : $"{uri.Host}:{uri.Port}";
        return $"{uri.Scheme}://{authority}{uri.AbsolutePath}";
    }

    /// <summary>The key id an access token is bound to (<c>cnf.jkt</c>), or null for a plain bearer token.</summary>
    public static string? BoundKey(JsonElement tokenPayload) =>
        tokenPayload.TryGetProperty("cnf", out var cnf) && cnf.ValueKind == JsonValueKind.Object && cnf.TryGetProperty("jkt", out var jkt) && jkt.ValueKind == JsonValueKind.String && jkt.GetString() is { Length: > 0 } value ? value : null;

    /// <summary>A thumbprint as <c>dpop_jkt</c> carries it: 43 characters of base64url.</summary>
    public static bool IsThumbprint(string? value) => value is { Length: 43 } && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');
}
