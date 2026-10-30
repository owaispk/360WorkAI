using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Data;

namespace WorkAI360.Api.Endpoints;

public static class MiscEndpoints
{
    public static void MapMiscEndpoints(this WebApplication app)
    {
        app.MapGet("/health", () => Results.Json(new { ok = true, service = "den-api", version = "dev" }));

        // Tells the sign-in form which step comes next for an email address.
        app.MapGet("/v1/auth/login-options", async (string? email, string? invite, DenDbContext db) =>
        {
            if (!AuthEndpoints.IsValidEmail(email)) return Results.Json(new { error = "invalid_request" }, statusCode: 400);
            var normalized = AuthEndpoints.NormalizeEmail(email!);
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

        // Enterprise SSO is not built yet: every address resolves to a non-SSO method.
        app.MapGet("/v1/orgs/sso/resolve", (string? email) =>
            AuthEndpoints.IsValidEmail(email) ? Results.Json(new { method = "password" }) : Results.Json(new { error = "invalid_request" }, statusCode: 400));
    }
}
