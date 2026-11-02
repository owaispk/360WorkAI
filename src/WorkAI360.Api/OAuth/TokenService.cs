using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.OAuthExtras;
using WorkAI360.Api.Features.Oidc;

namespace WorkAI360.Api.OAuth;

public sealed class TokenService(DenDbContext db, SigningKeyStore keys, OAuthUrls urls, IdTokenIssuer idTokens)
{
    /// <summary>
    /// Issues an access token (a signed JWT) and, when `offline_access` was granted, a refresh token. With <paramref name="dpopJkt"/> (the thumbprint of a
    /// verified DPoP proof's key) the access token carries <c>cnf.jkt</c>, the response says <c>token_type: "DPoP"</c> and the refresh-token family is bound to the key.
    /// </summary>
    public async Task<Dictionary<string, object?>> IssueAsync(string clientId, string userId, string organizationId, string scope, string resource, string? codeHash, string? familyId = null, string? dpopJkt = null)
    {
        var now = DateTimeOffset.UtcNow;
        var key = await keys.ActiveAsync();
        var claims = new Dictionary<string, object?>
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
        };
        if (dpopJkt is not null) claims["cnf"] = new Dictionary<string, object?> { ["jkt"] = dpopJkt };
        var jwt = Jwt.Create(key, claims);

        var response = new Dictionary<string, object?>
        {
            ["access_token"] = jwt,
            ["token_type"] = dpopJkt is null ? "Bearer" : "DPoP",
            ["expires_in"] = (int)OAuthConstants.AccessTokenLifetime.TotalSeconds,
            ["scope"] = scope,
        };

        if (OAuthConstants.SplitScope(scope).Contains(OAuthConstants.OfflineScope))
        {
            var refresh = OAuthConstants.RefreshTokenPrefix + Ids.RandomAlnum(48);
            var family = familyId ?? Ids.New("fam");
            db.RefreshTokens.Add(new RefreshToken
            {
                Id = Ids.Sha256Hex(refresh),
                FamilyId = family,
                CodeHash = codeHash,
                ClientId = clientId,
                UserId = userId,
                OrganizationId = organizationId,
                Scope = scope,
                Resource = resource,
                CreatedAt = now.UtcDateTime,
                ExpiresAt = now.Add(OAuthConstants.RefreshTokenLifetime).UtcDateTime,
            });
            // A refresh-token family is bound to one key for its whole life; presenting a proof for an unbound family binds it.
            if (dpopJkt is not null && !await db.Set<OAuthDpopBinding>().AnyAsync(b => b.Id == family))
                db.Set<OAuthDpopBinding>().Add(new OAuthDpopBinding { Id = family, Jkt = dpopJkt, ExpiresAt = now.Add(OAuthConstants.RefreshTokenLifetime).UtcDateTime });
            try { await db.SaveChangesAsync(); }
            catch (DbUpdateException) when (dpopJkt is not null)
            {
                // A parallel refresh bound the family first: keep the refresh token, drop the duplicate binding.
                foreach (var entry in db.ChangeTracker.Entries<OAuthDpopBinding>().Where(e => e.State == EntityState.Added).ToList()) entry.State = EntityState.Detached;
                await db.SaveChangesAsync();
            }
            response["refresh_token"] = refresh;
        }
        // OpenID Connect: asking for "openid" also yields an ID token (signed for this client, bound to the request's nonce).
        if (OAuthConstants.SplitScope(scope).Contains(OAuthConstants.OpenIdScope))
            response["id_token"] = await idTokens.IssueAsync(clientId, userId, jwt, codeHash, fromRefresh: familyId is not null);
        return response;
    }

    /// <summary>
    /// A <c>client_credentials</c> access token: it speaks for the client itself (<c>sub</c> = the client id), so it has no workspace and no <c>token_use</c>, and
    /// the MCP endpoint (which needs a person in a workspace) does not accept it. No refresh token and no ID token, as in the reference.
    /// </summary>
    public async Task<Dictionary<string, object?>> IssueClientCredentialsAsync(string clientId, string scope, string resource, string? dpopJkt)
    {
        var now = DateTimeOffset.UtcNow;
        var expires = now.Add(OAuthConstants.AccessTokenLifetime);
        var claims = new Dictionary<string, object?>
        {
            ["iss"] = urls.Issuer, ["sub"] = clientId, ["aud"] = resource, ["client_id"] = clientId, ["azp"] = clientId, ["scope"] = scope,
            ["iat"] = now.ToUnixTimeSeconds(), ["exp"] = expires.ToUnixTimeSeconds(), ["jti"] = Ids.RandomAlnum(24),
        };
        if (dpopJkt is not null) claims["cnf"] = new Dictionary<string, object?> { ["jkt"] = dpopJkt };
        return new Dictionary<string, object?>
        {
            ["access_token"] = Jwt.Create(await keys.ActiveAsync(), claims),
            ["token_type"] = dpopJkt is null ? "Bearer" : "DPoP",
            ["expires_in"] = (int)OAuthConstants.AccessTokenLifetime.TotalSeconds,
            ["expires_at"] = expires.ToUnixTimeSeconds(),
            ["scope"] = scope,
        };
    }

    public Task<int> RevokeFamilyAsync(string familyId) =>
        db.RefreshTokens.Where(t => t.FamilyId == familyId && t.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.RevokedAt, DateTime.UtcNow));

    public Task<int> RevokeByCodeAsync(string codeHash) =>
        db.RefreshTokens.Where(t => t.CodeHash == codeHash && t.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.RevokedAt, DateTime.UtcNow));
}
