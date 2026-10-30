using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;

namespace WorkAI360.Api.Endpoints;

public sealed record HandoffCreateBody(string? DesktopScheme, string? ReturnUrl);
public sealed record GrantBody(string? Grant);

/// <summary>
/// Hands a signed-in web session to the desktop app. Unlike the reference (which returns the web session's own token),
/// the exchange mints a fresh session, so the stored grant never holds a usable credential.
/// </summary>
public static class HandoffEndpoints
{
    private static readonly TimeSpan GrantLifetime = TimeSpan.FromMinutes(5);

    public static void MapHandoffEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/v1/auth/desktop-handoff");

        group.MapPost("", async (HandoffCreateBody? body, HttpContext ctx, SessionService sessions, DenDbContext db, IOptions<AuthOptions> options) =>
        {
            var current = await sessions.ResolveAsync(ctx);
            if (current is null) return Responses.Unauthorized();

            // No Cloud web return URLs are approved yet; refuse rather than redirect somewhere unvetted.
            if (!string.IsNullOrWhiteSpace(body?.ReturnUrl))
                return Responses.Error(400, "invalid_return_url", "The Cloud web handoff return URL is not approved for this organization.");

            var scheme = string.IsNullOrWhiteSpace(body?.DesktopScheme) ? "openwork" : body!.DesktopScheme!.Trim();
            if (!System.Text.RegularExpressions.Regex.IsMatch(scheme, "^[a-z][a-z0-9+.-]{1,31}$"))
                return Responses.Error(400, "invalid_request", "Invalid desktop scheme.");

            var grant = Base64Url(RandomNumberGenerator.GetBytes(24));
            var expiresAt = DateTime.UtcNow + GrantLifetime;
            db.HandoffGrants.Add(new DesktopHandoffGrant { Id = grant, UserId = current.User.Id, OrganizationId = current.Session.ActiveOrganizationId, ExpiresAt = expiresAt });
            await db.SaveChangesAsync();

            var denBaseUrl = $"{PublicOrigin(ctx.Request, options.Value)}/api/den";
            return Results.Json(new
            {
                grant,
                expiresAt = Responses.IsoUtc(expiresAt),
                openworkUrl = $"{scheme}://den-auth?grant={Uri.EscapeDataString(grant)}&denBaseUrl={Uri.EscapeDataString(denBaseUrl)}",
            });
        });

        group.MapPost("/status", async (GrantBody? body, DenDbContext db) =>
        {
            if (!ValidGrant(body?.Grant)) return Responses.Error(400, "invalid_request", "grant: Too small: expected string to have >=12 characters");
            var grant = await db.HandoffGrants.FirstOrDefaultAsync(g => g.Id == body!.Grant);
            if (grant is null) return Results.Json(new { status = "unknown" });
            if (grant.ConsumedAt is not null) return Results.Json(new { status = "consumed" });
            return Results.Json(new { status = grant.ExpiresAt > DateTime.UtcNow ? "pending" : "unknown" });
        });

        group.MapPost("/exchange", async (GrantBody? body, HttpContext ctx, DenDbContext db, SessionService sessions) =>
        {
            if (!ValidGrant(body?.Grant)) return Responses.Error(400, "invalid_request", "grant: Too small: expected string to have >=12 characters");

            // Claim atomically: only one caller can flip ConsumedAt from null.
            var now = DateTime.UtcNow;
            var claimed = await db.HandoffGrants
                .Where(g => g.Id == body!.Grant && g.ConsumedAt == null && g.ExpiresAt > now)
                .ExecuteUpdateAsync(s => s.SetProperty(g => g.ConsumedAt, now));
            if (claimed == 0) return Responses.Error(404, "grant_not_found", "This desktop sign-in link is missing, expired, or already used.");

            var grant = await db.HandoffGrants.AsNoTracking().FirstAsync(g => g.Id == body!.Grant);
            var user = await db.Users.FirstAsync(u => u.Id == grant.UserId);
            var org = grant.OrganizationId is null ? null : await db.Organizations.FirstOrDefaultAsync(o => o.Id == grant.OrganizationId);
            var (token, _) = await sessions.CreateAsync(user, org?.Id, "desktop-handoff", ctx);

            return Results.Json(new
            {
                token,
                user = new { id = user.Id, email = user.Email, name = user.Name },
                organization = org is null ? null : new { id = org.Id, slug = org.Slug, name = org.Name },
                connectEnabled = org is null ? (bool?)null : true,
            });
        });
    }

    private static bool ValidGrant(string? grant) => grant is { Length: >= 12 and <= 128 };

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Origin the client used to reach this service, honouring the web host's forwarding headers.</summary>
    public static string PublicOrigin(HttpRequest request, AuthOptions options)
    {
        var host = request.Headers["X-Forwarded-Host"].ToString().Split(',')[0].Trim();
        var proto = request.Headers["X-Forwarded-Proto"].ToString().Split(',')[0].Trim();
        if (host.Length > 0 && (proto == "http" || proto == "https")) return $"{proto}://{host}";
        if (!string.IsNullOrWhiteSpace(options.PublicUrl)) return options.PublicUrl.TrimEnd('/');
        return $"{request.Scheme}://{request.Host}";
    }
}
