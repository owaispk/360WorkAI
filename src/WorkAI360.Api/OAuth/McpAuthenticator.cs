using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;

namespace WorkAI360.Api.OAuth;

public sealed record McpPrincipal(string UserId, string OrganizationId, string[] Scopes, string ClientId);

/// <summary>Authenticates a bearer token presented to an MCP endpoint: an OAuth access token (JWT) or a first-party opaque token.</summary>
public sealed class McpAuthenticator(DenDbContext db, SigningKeyStore keys, OAuthUrls urls)
{
    public async Task<McpPrincipal?> AuthenticateAsync(HttpRequest request)
    {
        var token = SessionService.ReadBearer(request);
        if (token is null) return null;

        McpPrincipal? principal = token.StartsWith(OAuthConstants.AccessTokenPrefix, StringComparison.Ordinal)
            ? await VerifyOpaqueAsync(token)
            : token.Contains('.') ? await VerifyJwtAsync(token) : null;
        if (principal is null) return null;

        // Tokens outlive memberships, so check the person still belongs to the workspace on every call.
        var stillMember = await db.Members.AnyAsync(m => m.OrganizationId == principal.OrganizationId && m.UserId == principal.UserId);
        return stillMember ? principal : null;
    }

    private async Task<McpPrincipal?> VerifyOpaqueAsync(string token)
    {
        var hash = Ids.Sha256Hex(token);
        var row = await db.McpAccessTokens.AsNoTracking().FirstOrDefaultAsync(t => t.Id == hash && t.ExpiresAt > DateTime.UtcNow);
        return row is null ? null : new McpPrincipal(row.UserId, row.OrganizationId, OAuthConstants.SplitScope(row.Scope), row.Kind);
    }

    private async Task<McpPrincipal?> VerifyJwtAsync(string token)
    {
        var payload = Jwt.Verify(token, await keys.KeysAsync());
        if (payload is not { } p) return null;
        string? Str(string name) => p.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

        if (Str("iss") != urls.Issuer || Str("aud") != urls.CanonicalResource || Str(OAuthConstants.ClaimTokenUse) != "mcp") return null;
        if (!p.TryGetProperty("exp", out var exp) || exp.ValueKind != JsonValueKind.Number || exp.GetInt64() <= DateTimeOffset.UtcNow.ToUnixTimeSeconds()) return null;
        var sub = Str("sub");
        var org = Str(OAuthConstants.ClaimOrg);
        return sub is null || org is null ? null : new McpPrincipal(sub, org, OAuthConstants.SplitScope(Str("scope")), Str("azp") ?? "");
    }
}
