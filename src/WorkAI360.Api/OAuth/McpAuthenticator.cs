using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;

namespace WorkAI360.Api.OAuth;

public sealed record McpPrincipal(string UserId, string OrganizationId, string[] Scopes, string ClientId);

/// <summary>
/// Authenticates a token presented to an MCP endpoint: an OAuth access token (JWT) or a first-party opaque token. A DPoP-bound access token (it carries
/// <c>cnf.jkt</c>, RFC 9449 section 7) is accepted only under the <c>DPoP</c> authorization scheme with a fresh proof made by the bound key and covering this very
/// token (<c>ath</c>), method and address; presented as a plain bearer it is refused, which is what makes the binding worth having.
/// </summary>
public sealed class McpAuthenticator(DenDbContext db, SigningKeyStore keys, OAuthUrls urls, DpopVerifier dpop)
{
    /// <summary>Why the last call refused a token on DPoP grounds (the endpoint answers with a <c>DPoP</c> challenge then), or null.</summary>
    public DpopException? DpopFailure { get; private set; }

    public async Task<McpPrincipal?> AuthenticateAsync(HttpRequest request)
    {
        DpopFailure = null;
        var (token, scheme) = ReadAuthorization(request);
        if (token is null) return null;

        McpPrincipal? principal;
        if (token.StartsWith(OAuthConstants.AccessTokenPrefix, StringComparison.Ordinal))
        {
            if (scheme == "DPoP") { DpopFailure = new DpopException("DPoP authorization requires a DPoP-bound access token", "invalid_token"); return null; }
            principal = await VerifyOpaqueAsync(token);
        }
        else principal = token.Contains('.') ? await VerifyJwtAsync(token, scheme, request) : null;
        if (principal is null) return null;

        // Tokens outlive memberships, so check the person still belongs to the workspace on every call.
        var stillMember = await db.Members.AnyAsync(m => m.OrganizationId == principal.OrganizationId && m.UserId == principal.UserId);
        return stillMember ? principal : null;
    }

    /// <summary>The credential in the <c>Authorization</c> header and the scheme it came under (<c>Bearer</c> or <c>DPoP</c>).</summary>
    public static (string? Token, string? Scheme) ReadAuthorization(HttpRequest request)
    {
        var header = request.Headers.Authorization.ToString().Trim();
        foreach (var scheme in new[] { "Bearer", "DPoP" })
        {
            if (!header.StartsWith(scheme + " ", StringComparison.OrdinalIgnoreCase)) continue;
            var token = header[(scheme.Length + 1)..].Trim();
            return token.Length == 0 ? (null, null) : (token, scheme);
        }
        return (null, null);
    }

    private async Task<McpPrincipal?> VerifyOpaqueAsync(string token)
    {
        var hash = Ids.Sha256Hex(token);
        var row = await db.McpAccessTokens.AsNoTracking().FirstOrDefaultAsync(t => t.Id == hash && t.ExpiresAt > DateTime.UtcNow);
        return row is null ? null : new McpPrincipal(row.UserId, row.OrganizationId, OAuthConstants.SplitScope(row.Scope), row.Kind);
    }

    private async Task<McpPrincipal?> VerifyJwtAsync(string token, string? scheme, HttpRequest request)
    {
        var payload = Jwt.Verify(token, await keys.KeysAsync());
        if (payload is not { } p) return null;
        string? Str(string name) => p.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

        if (Str("iss") != urls.Issuer || Str("aud") != urls.CanonicalResource || Str(OAuthConstants.ClaimTokenUse) != "mcp") return null;
        if (!p.TryGetProperty("exp", out var exp) || exp.ValueKind != JsonValueKind.Number || exp.GetInt64() <= DateTimeOffset.UtcNow.ToUnixTimeSeconds()) return null;
        var sub = Str("sub");
        var org = Str(OAuthConstants.ClaimOrg);
        if (sub is null || org is null) return null;

        // Sender-constrained tokens (RFC 9449 7.1).
        var bound = DpopVerifier.BoundKey(p);
        if (bound is null)
        {
            if (scheme == "DPoP") { DpopFailure = new DpopException("DPoP authorization requires a DPoP-bound access token", "invalid_token"); return null; }
        }
        else
        {
            if (scheme != "DPoP") { DpopFailure = new DpopException("DPoP-bound access token requires the DPoP authorization scheme", "invalid_token"); return null; }
            var proofs = request.Headers["DPoP"];
            if (proofs.Count == 0 || string.IsNullOrWhiteSpace(proofs[0])) { DpopFailure = new DpopException("DPoP proof header is required"); return null; }
            if (proofs.Count > 1) { DpopFailure = new DpopException("Multiple DPoP proofs are not allowed"); return null; }
            try
            {
                await dpop.VerifyAsync(proofs[0], request.Method, [$"{request.Scheme}://{request.Host}{request.Path}", urls.CanonicalResource], token, bound, request.HttpContext.RequestAborted);
            }
            catch (DpopException e) { DpopFailure = e; return null; }
        }
        return new McpPrincipal(sub, org, OAuthConstants.SplitScope(Str("scope")), Str("azp") ?? "");
    }
}
