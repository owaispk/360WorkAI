using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Oidc;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Features.Oidc;

/// <summary>
/// Signs OpenID Connect ID tokens (OIDC Core 3.1.3.7). The claims are the reference's: <c>iss</c>, <c>sub</c>, <c>aud</c> (the client id only),
/// <c>iat</c>, <c>exp</c> (ten hours), <c>auth_time</c>, <c>acr</c> "0", <c>at_hash</c> (left half of SHA-256 of the access token) and the client's
/// <c>nonce</c> when the authorization request carried one. The profile and email claims are NOT in the ID token, they come from the userinfo
/// endpoint. <c>sid</c> is added only for a client that may use RP-initiated logout. A refresh issues a new ID token for the same sign-in:
/// same <c>auth_time</c>, no nonce (the nonce belongs to one authorization response, OIDC Core 12.2).
/// </summary>
public sealed class IdTokenIssuer(DenDbContext db, SigningKeyStore keys, OAuthUrls urls)
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromHours(10);

    public async Task<string> IssueAsync(string clientId, string userId, string accessToken, string? codeHash, bool fromRefresh)
    {
        var grant = codeHash is null ? null : await db.Set<OidcGrant>().AsNoTracking().FirstOrDefaultAsync(g => g.Id == codeHash && g.ClientId == clientId && g.UserId == userId);
        var settings = await db.Set<OidcClientSettings>().AsNoTracking().FirstOrDefaultAsync(s => s.ClientId == clientId);
        var now = DateTimeOffset.UtcNow;
        var authTime = grant is null ? now : new DateTimeOffset(DateTime.SpecifyKind(grant.AuthTime, DateTimeKind.Utc));

        var claims = new Dictionary<string, object?>
        {
            ["auth_time"] = authTime.ToUnixTimeSeconds(),
            ["acr"] = "0",
            ["at_hash"] = AtHash(accessToken),
            ["iss"] = urls.Issuer,
            ["sub"] = userId,
            ["aud"] = clientId,
        };
        if (!fromRefresh && grant?.Nonce is { Length: > 0 } nonce) claims["nonce"] = nonce;
        claims["iat"] = now.ToUnixTimeSeconds();
        claims["exp"] = now.Add(Lifetime).ToUnixTimeSeconds();
        if (settings is { EnableEndSession: true } && grant?.SessionId is { } sid) claims["sid"] = sid;
        return Jwt.Create(await keys.ActiveAsync(), claims, type: null);
    }

    /// <summary>OIDC Core 3.1.3.6: base64url of the left half of the hash of the ASCII access token (SHA-256 for ES256).</summary>
    public static string AtHash(string accessToken)
    {
        var digest = SHA256.HashData(Encoding.ASCII.GetBytes(accessToken));
        return SigningKeyStore.Base64Url(digest[..(digest.Length / 2)]);
    }
}
