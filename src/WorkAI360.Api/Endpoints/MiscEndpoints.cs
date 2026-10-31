using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Data;
using WorkAI360.Api.Features.Sso;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Endpoints;

public static class MiscEndpoints
{
    public static void MapMiscEndpoints(this WebApplication app)
    {
        app.MapGet("/health", () => Results.Json(new { ok = true, service = "den-api", version = "dev" }));

        // Tells the sign-in form which step comes next for an email address.
        app.MapGet("/v1/auth/login-options", async (string? email, string? invite, DenDbContext db, SsoRouting sso, OAuthUrls urls) =>
        {
            if (!AuthEndpoints.IsValidEmail(email)) return Results.Json(new { error = "invalid_request" }, statusCode: 400);
            var normalized = AuthEndpoints.NormalizeEmail(email!);
            // A workspace that enforces single sign-on for this email's domain sends the person there first.
            if (await sso.ForEmailDomainAsync(normalized) is { } required)
                return Results.Json(new { email = normalized, nextStep = "sso", allowPublicSignup = true, allowInvitationSignup = false, organizationSlug = required.OrganizationSlug, signInPath = required.SignInPath, signInUrl = urls.Web + required.SignInPath });
            var exists = await db.Users.AnyAsync(u => u.Email == normalized);
            var now = DateTime.UtcNow;
            var invited = !string.IsNullOrWhiteSpace(invite)
                && await db.Invitations.AnyAsync(i => (i.Id == invite || i.InviteToken == invite) && i.Email == normalized && i.Status == InvitationStatus.Pending && i.ExpiresAt > now);
            return Results.Json(new
            {
                email = normalized,
                nextStep = exists ? "password" : "new_account",
                allowPublicSignup = true,
                allowInvitationSignup = invited,
            });
        });

        // First-administrator setup for private deployments is not built yet: report it as unavailable.
        app.MapGet("/v1/auth/bootstrap/status", () => Results.Json(new { status = "unavailable" }));
        app.MapPost("/v1/auth/bootstrap/verify", () =>
            Results.Json(new { error = "bootstrap_unavailable", message = "Initial administrator setup is not enabled for this deployment." }, statusCode: 409));

        // Which sign-in method an address uses: its workspace's SSO when one claims the domain, else password (or sign-up when there is no account).
        app.MapGet("/v1/orgs/sso/resolve", async (string? email, DenDbContext db, SsoRouting sso, OAuthUrls urls) =>
        {
            if (!AuthEndpoints.IsValidEmail(email)) return Results.Json(new { error = "invalid_request" }, statusCode: 400);
            var normalized = AuthEndpoints.NormalizeEmail(email!);
            if (await sso.ForEmailDomainAsync(normalized) is { } required)
                return Results.Json(new { requireSso = true, method = "sso", organizationSlug = required.OrganizationSlug, signInPath = required.SignInPath, signInUrl = urls.Web + required.SignInPath });
            var exists = await db.Users.AnyAsync(u => u.Email == normalized);
            return Results.Json(new { requireSso = false, method = exists ? "password" : "signup" });
        });
    }
}
