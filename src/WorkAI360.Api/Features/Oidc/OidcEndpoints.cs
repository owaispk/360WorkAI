using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Features.Oidc;

/// <summary>
/// The OpenID Connect surface that sits next to the OAuth provider: <c>userinfo</c> (OIDC Core 5.3) and token introspection (RFC 7662).
/// Wire shapes, status codes and messages follow the reference (Better Auth's OAuth provider). Where this implementation is stricter, the
/// reason is in <c>docs/features/auth-completeness.md</c>.
/// </summary>
public static class OidcEndpoints
{
    private const string InvalidTokenChallenge = "Bearer error=\"invalid_token\", error_description=\"Invalid access token\"";

    public static void Map(WebApplication app)
    {
        foreach (var method in new[] { "GET", "POST" })
            app.MapMethods("/api/auth/oauth2/userinfo", [method], UserInfoAsync);
        app.MapPost("/api/auth/oauth2/introspect", IntrospectAsync);
    }

    private static IResult Error(int status, string error, string description) => Results.Json(new { error, error_description = description }, statusCode: status);

    // ============================== userinfo ==============================

    private static async Task<IResult> UserInfoAsync(HttpContext ctx, DenDbContext db, SigningKeyStore keys, OAuthUrls urls)
    {
        ctx.Response.Headers.CacheControl = "no-store";
        ctx.Response.Headers.Pragma = "no-cache";

        var header = SessionService.ReadBearer(ctx.Request);
        string? bodyToken = null;
        if (ctx.Request.Method == "POST" && ctx.Request.HasFormContentType) bodyToken = (await ctx.Request.ReadFormAsync()).TryGetValue("access_token", out var v) && v.Count == 1 ? v[0] : null;
        if (header is not null && !string.IsNullOrEmpty(bodyToken)) return Error(400, "invalid_request", "Multiple access token transport methods are not allowed");
        var token = header ?? (string.IsNullOrEmpty(bodyToken) ? null : bodyToken);
        if (token is null) return Error(401, "invalid_request", "access token not found");

        var principal = await VerifyAccessTokenAsync(token, keys, urls, db);
        if (principal is null)
        {
            ctx.Response.Headers.WWWAuthenticate = InvalidTokenChallenge;
            return Error(401, "invalid_token", "Invalid access token");
        }
        if (!OAuthConstants.SplitScope(principal.Scope).Contains(OAuthConstants.OpenIdScope)) return Error(400, "invalid_scope", "Missing required scope");

        var user = await db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == principal.UserId);
        if (user is null) return Error(400, "invalid_request", "user not found");

        // Claims depend on the scopes the person granted (OIDC Core 5.4): profile gives the name, email gives the address; sub is always there.
        var scopes = OAuthConstants.SplitScope(principal.Scope);
        var claims = new Dictionary<string, object?> { ["sub"] = user.Id };
        if (scopes.Contains(OAuthConstants.ProfileScope))
        {
            claims["name"] = user.Name;
            var parts = user.Name.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length > 1) { claims["given_name"] = string.Join(' ', parts[..^1]); claims["family_name"] = parts[^1]; }
            if (user.Image is { Length: > 0 }) claims["picture"] = user.Image;
        }
        if (scopes.Contains(OAuthConstants.EmailScope))
        {
            claims["email"] = user.Email;
            claims["email_verified"] = user.EmailVerified;
        }
        return Results.Json(claims);
    }

    private sealed record AccessPrincipal(string UserId, string OrganizationId, string ClientId, string Scope, JsonElement Payload);

    /// <summary>
    /// An access token this server issued and that is still good: signature (ES256, a known key), issuer, audience (the MCP resource, so an ID
    /// token, which is for a client, never passes), token use, expiry, the issuing client still exists, and the person still belongs to the workspace.
    /// </summary>
    private static async Task<AccessPrincipal?> VerifyAccessTokenAsync(string token, SigningKeyStore keys, OAuthUrls urls, DenDbContext db)
    {
        if (token.StartsWith(OAuthConstants.AccessTokenPrefix, StringComparison.Ordinal) || !token.Contains('.')) return null;
        if (Jwt.Verify(token, await keys.KeysAsync()) is not { } p) return null;
        string? Str(string name) => p.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        if (Str("iss") != urls.Issuer || Str("aud") != urls.CanonicalResource || Str(OAuthConstants.ClaimTokenUse) != "mcp") return null;
        if (!p.TryGetProperty("exp", out var exp) || exp.ValueKind != JsonValueKind.Number || exp.GetInt64() <= DateTimeOffset.UtcNow.ToUnixTimeSeconds()) return null;
        var sub = Str("sub"); var org = Str(OAuthConstants.ClaimOrg); var azp = Str("azp");
        if (sub is null || org is null || azp is null) return null;
        if (!await db.OAuthClients.AnyAsync(c => c.Id == azp)) return null;
        if (!await db.Members.AnyAsync(m => m.OrganizationId == org && m.UserId == sub)) return null;
        return new AccessPrincipal(sub, org, azp, Str("scope") ?? "", p);
    }

    // ============================== introspection ==============================

    private static async Task<IResult> IntrospectAsync(HttpContext ctx, DenDbContext db, ClientResolver clients, SigningKeyStore keys, OAuthUrls urls, TokenRateLimit rateLimit)
    {
        ctx.Response.Headers.CacheControl = "no-store";
        ctx.Response.Headers.Pragma = "no-cache";
        if (!ctx.Request.HasFormContentType)
            return Results.Json(new { message = "Content-Type \"application/json\" is not allowed. Allowed types: application/x-www-form-urlencoded", code = "UNSUPPORTED_MEDIA_TYPE", error = "request_failed", error_description = "Content-Type is not allowed. Allowed types: application/x-www-form-urlencoded" }, statusCode: 415);

        var form = await OAuthEndpoints.ReadParamsAsync(ctx.Request);
        // The same numbers as the token endpoint, in budgets of their own: a caller guessing client secrets or probing tokens is slowed down
        // and, once refused, learns nothing more (the answer to an unknown token is the same {"active": false} as to someone else's).
        var admission = rateLimit.Admit(ctx, form, OAuthEndpoints.BasicClientId(ctx.Request), "introspect");
        if (admission.Refused is { } refused) return refused;
        var result = await IntrospectCoreAsync(ctx, form, db, clients, keys, urls);
        rateLimit.RecordFailure(admission, result);
        return result;
    }

    private static async Task<IResult> IntrospectCoreAsync(HttpContext ctx, Dictionary<string, string> form, DenDbContext db, ClientResolver clients, SigningKeyStore keys, OAuthUrls urls)
    {
        // Only a client that can prove itself with a secret may ask (RFC 7662 section 2.1): public clients have none, so they never can.
        string? id = form.GetValueOrDefault("client_id"), secret = form.GetValueOrDefault("client_secret");
        var viaHeader = false;
        var header = ctx.Request.Headers.Authorization.ToString();
        if (header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(header[6..].Trim()));
                var colon = decoded.IndexOf(':');
                if (colon > 0) { id = Uri.UnescapeDataString(decoded[..colon]); secret = Uri.UnescapeDataString(decoded[(colon + 1)..]); viaHeader = true; }
            }
            catch (Exception e) when (e is FormatException or UriFormatException) { return Error(401, "invalid_client", "invalid client credentials"); }
        }
        if (string.IsNullOrEmpty(id) || string.IsNullOrEmpty(secret)) return Error(401, "invalid_client", "missing required credentials");

        var client = await clients.ResolveAsync(id);
        // One answer for an unknown client, a public client and a wrong secret, so the response does not say which client ids exist.
        if (client is null || client.AuthMethod == "none" || client.SecretHash is null
            || !CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Ids.Sha256Hex(secret)), Encoding.ASCII.GetBytes(client.SecretHash))
            || (client.AuthMethod == "client_secret_basic") != viaHeader)
            return Error(401, "invalid_client", "invalid client credentials");

        if (!form.TryGetValue("token", out var token) || string.IsNullOrEmpty(token)) return Error(400, "invalid_request", "token is required");
        var hint = form.GetValueOrDefault("token_type_hint");

        if (hint != "refresh_token" && await IntrospectAccessTokenAsync(token, client.Id, db, keys, urls) is { } access) return Results.Json(access);
        if (hint != "access_token" && await IntrospectRefreshTokenAsync(token, client.Id, db, urls) is { } refresh) return Results.Json(refresh);
        return Results.Json(new { active = false });
    }

    /// <summary>The access token's claims plus <c>active</c>, only when this very client was issued it. Anything else is null (inactive).</summary>
    private static async Task<Dictionary<string, object?>?> IntrospectAccessTokenAsync(string token, string clientId, DenDbContext db, SigningKeyStore keys, OAuthUrls urls)
    {
        var principal = await VerifyAccessTokenAsync(token, keys, urls, db);
        if (principal is null || principal.ClientId != clientId) return null;   // another client's token reads exactly like an unknown one
        var result = new Dictionary<string, object?>();
        foreach (var property in principal.Payload.EnumerateObject()) result[property.Name] = property.Value.Clone();
        result["client_id"] = principal.ClientId;
        result["active"] = true;
        result["token_type"] = "Bearer";
        return result;
    }

    private static async Task<Dictionary<string, object?>?> IntrospectRefreshTokenAsync(string token, string clientId, DenDbContext db, OAuthUrls urls)
    {
        var hash = Ids.Sha256Hex(token);
        var now = DateTime.UtcNow;
        var row = await db.RefreshTokens.AsNoTracking().FirstOrDefaultAsync(t => t.Id == hash);
        if (row is null || row.ClientId != clientId || row.RevokedAt is not null || row.RotatedAt is not null || row.ExpiresAt <= now) return null;
        if (!await db.Members.AnyAsync(m => m.OrganizationId == row.OrganizationId && m.UserId == row.UserId)) return null;
        return new Dictionary<string, object?>
        {
            ["active"] = true,
            ["client_id"] = row.ClientId,
            ["iss"] = urls.Issuer,
            ["sub"] = row.UserId,
            ["exp"] = new DateTimeOffset(DateTime.SpecifyKind(row.ExpiresAt, DateTimeKind.Utc)).ToUnixTimeSeconds(),
            ["iat"] = new DateTimeOffset(DateTime.SpecifyKind(row.CreatedAt, DateTimeKind.Utc)).ToUnixTimeSeconds(),
            ["scope"] = row.Scope,
            ["token_type"] = "Bearer",
        };
    }
}
