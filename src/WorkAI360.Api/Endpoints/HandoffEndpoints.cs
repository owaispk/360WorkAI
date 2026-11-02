using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Features.WebOrigins;

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

            // A web return URL is honored only when a workspace approved that exact origin (Org settings); anything else is refused rather than redirected.
            string? approvedReturnUrl = null;
            string? handoffOrganizationId = current.Session.ActiveOrganizationId;
            if (body?.ReturnUrl is not null)
            {
                var approval = await WebHandoffReturnUrls.ResolveAsync(db, body.ReturnUrl.Trim(), current.Session.ActiveOrganizationId, current.User.Id);
                if (approval is null)
                    return Responses.Error(400, "invalid_return_url", "The Cloud web handoff return URL is not approved for this organization.");
                approvedReturnUrl = approval.ReturnUrl;
                // The grant hands over this session, so it becomes active in the approving workspace before the web instance exchanges it.
                if (approval.OrganizationId != current.Session.ActiveOrganizationId)
                {
                    await db.Sessions.Where(x => x.Id == current.Session.Id).ExecuteUpdateAsync(x => x.SetProperty(y => y.ActiveOrganizationId, approval.OrganizationId));
                    handoffOrganizationId = approval.OrganizationId;
                }
            }

            var scheme = string.IsNullOrWhiteSpace(body?.DesktopScheme) ? "openwork" : body!.DesktopScheme!.Trim();
            if (!System.Text.RegularExpressions.Regex.IsMatch(scheme, "^[a-z][a-z0-9+.-]{1,31}$"))
                return Responses.Error(400, "invalid_request", "Invalid desktop scheme.");

            var grant = Base64Url(RandomNumberGenerator.GetBytes(24));
            var expiresAt = DateTime.UtcNow + GrantLifetime;
            db.HandoffGrants.Add(new DesktopHandoffGrant { Id = grant, UserId = current.User.Id, OrganizationId = handoffOrganizationId, ExpiresAt = expiresAt });
            await db.SaveChangesAsync();

            var denBaseUrl = $"{PublicOrigin(ctx.Request, options.Value)}/api/den";
            return Results.Json(new
            {
                grant,
                expiresAt = Responses.IsoUtc(expiresAt),
                openworkUrl = $"{scheme}://den-auth?grant={Uri.EscapeDataString(grant)}&denBaseUrl={Uri.EscapeDataString(denBaseUrl)}",
                returnUrl = approvedReturnUrl,
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

    /// <summary>
    /// The origin people reach this service at. An explicit PublicUrl wins; otherwise it is the request's own origin, which the
    /// forwarded-headers middleware has already adjusted, but only for the configured trusted proxies. Raw X-Forwarded-* headers
    /// are never read here, so a caller cannot choose the origin that ends up in deep links.
    /// </summary>
    public static string PublicOrigin(HttpRequest request, AuthOptions options)
    {
        if (!string.IsNullOrWhiteSpace(options.PublicUrl)) return options.PublicUrl.TrimEnd('/');
        return $"{request.Scheme}://{request.Host}";
    }
}
