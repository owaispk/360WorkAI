using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;

namespace WorkAI360.Api.OAuth;

public sealed class TokenService(DenDbContext db, SigningKeyStore keys, OAuthUrls urls)
{
    /// <summary>Issues an access token (a signed JWT) and, when `offline_access` was granted, a refresh token.</summary>
    public async Task<Dictionary<string, object?>> IssueAsync(string clientId, string userId, string organizationId, string scope, string resource, string? codeHash, string? familyId = null)
    {
        var now = DateTimeOffset.UtcNow;
        var key = await keys.ActiveAsync();
        var jwt = Jwt.Create(key, new Dictionary<string, object?>
        {
            ["iss"] = urls.Issuer,
            ["sub"] = userId,
            ["aud"] = resource,
            ["azp"] = clientId,
            ["scope"] = scope,
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = now.Add(OAuthConstants.AccessTokenLifetime).ToUnixTimeSeconds(),
            ["jti"] = Ids.RandomAlnum(24),
            [OAuthConstants.ClaimOrg] = organizationId,
            [OAuthConstants.ClaimTokenUse] = "mcp",
        });

        var response = new Dictionary<string, object?>
        {
            ["access_token"] = jwt,
            ["token_type"] = "Bearer",
            ["expires_in"] = (int)OAuthConstants.AccessTokenLifetime.TotalSeconds,
            ["scope"] = scope,
        };

        if (OAuthConstants.SplitScope(scope).Contains(OAuthConstants.OfflineScope))
        {
            var refresh = OAuthConstants.RefreshTokenPrefix + Ids.RandomAlnum(48);
            db.RefreshTokens.Add(new RefreshToken
            {
                Id = Ids.Sha256Hex(refresh),
                FamilyId = familyId ?? Ids.New("fam"),
                CodeHash = codeHash,
                ClientId = clientId,
                UserId = userId,
                OrganizationId = organizationId,
                Scope = scope,
                Resource = resource,
                CreatedAt = now.UtcDateTime,
                ExpiresAt = now.Add(OAuthConstants.RefreshTokenLifetime).UtcDateTime,
            });
            await db.SaveChangesAsync();
            response["refresh_token"] = refresh;
        }
        return response;
    }

    public Task<int> RevokeFamilyAsync(string familyId) =>
        db.RefreshTokens.Where(t => t.FamilyId == familyId && t.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.RevokedAt, DateTime.UtcNow));

    public Task<int> RevokeByCodeAsync(string codeHash) =>
        db.RefreshTokens.Where(t => t.CodeHash == codeHash && t.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.RevokedAt, DateTime.UtcNow));
}
