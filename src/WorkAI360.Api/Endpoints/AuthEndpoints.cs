using System.Net.Mail;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;

namespace WorkAI360.Api.Endpoints;

public sealed record SignUpBody(string? Name, string? Email, string? Password, string? Invite);
public sealed record SignInBody(string? Email, string? Password);
public sealed record SetActiveBody(string? OrganizationId, string? OrganizationSlug);
public sealed record PasswordResetRequestBody(string? Email, string? RedirectTo);

public static class AuthEndpoints
{
    /// <summary>Better Auth mutations the reference API refuses in favour of its /v1 routes; the same refusals apply here.</summary>
    private static readonly Dictionary<string, string> Refused = new()
    {
        ["/organization/update"] = "Use the Den organization settings API to update workspace configuration.",
        ["/organization/delete"] = "Workspace deletion through Better Auth is disabled.",
        ["/organization/update-member-role"] = "Use the Den member role API to change organization roles.",
        ["/organization/remove-member"] = "Use the Den member API to remove organization members.",
        ["/organization/create-role"] = "Custom organization roles are not supported.",
        ["/organization/update-role"] = "Custom organization roles are not supported.",
        ["/organization/delete-role"] = "Custom organization roles are not supported.",
        ["/organization/create-team"] = "Use the Den teams API to manage teams.",
        ["/organization/update-team"] = "Use the Den teams API to manage teams.",
        ["/organization/remove-team"] = "Use the Den teams API to manage teams.",
        ["/organization/add-team-member"] = "Use the Den teams API to manage team membership.",
        ["/organization/remove-team-member"] = "Use the Den teams API to manage team membership.",
        ["/organization/add-member"] = "Use the Den invitation API to add members.",
        ["/organization/invite-member"] = "Use the Den invitation API to invite members.",
        ["/organization/cancel-invitation"] = "Use the Den invitation API to cancel invitations.",
        ["/organization/accept-invitation"] = "Use the Den invitation API to accept invitations.",
        ["/sso/register"] = "Use the Den SSO API to manage SSO providers.",
        ["/sso/update-provider"] = "Use the Den SSO API to manage SSO providers.",
        ["/sso/delete-provider"] = "Use the Den SSO API to manage SSO providers.",
        ["/sso/request-domain-verification"] = "Use the Den SSO API to verify SSO domains.",
        ["/sso/verify-domain"] = "Use the Den SSO API to verify SSO domains.",
        ["/api-key/create"] = "Use the Den API key API to manage organization API keys.",
        ["/api-key/update"] = "Use the Den API key API to manage organization API keys.",
        ["/api-key/delete"] = "Use the Den API key API to manage organization API keys.",
        ["/scim/generate-token"] = "Use the Den SCIM API to manage SCIM tokens.",
        ["/scim/delete-provider-connection"] = "Use the Den SCIM API to manage SCIM providers.",
        ["/device/approve"] = "Approve command-line sign-ins on the Den device page.",
        ["/device/deny"] = "Deny command-line sign-ins on the Den device page.",
    };

    public static string NormalizeEmail(string email) => email.Trim().ToLowerInvariant();

    public static bool IsValidEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email) || email.Length > 254) return false;
        return MailAddress.TryCreate(email.Trim(), out var parsed) && parsed.Address == email.Trim() && email.Contains('@') && email.Split('@')[1].Contains('.');
    }

    public static void MapAuthEndpoints(this WebApplication app)
    {
        var auth = app.MapGroup("/api/auth");

        auth.MapPost("/sign-up/email", async (SignUpBody? body, HttpContext ctx, DenDbContext db, SessionService sessions) =>
        {
            if (body is null || string.IsNullOrWhiteSpace(body.Name) || !IsValidEmail(body.Email) || body.Password is null)
                return Json(400, new { message = "Invalid name, email or password.", code = "VALIDATION_ERROR" });

            var problems = Passwords.Validate(body.Password);
            if (problems.Count > 0)
                return Json(400, new { error = "weak_password", message = string.Join(" ", problems), code = "PASSWORD_TOO_WEAK", problems });

            var email = NormalizeEmail(body.Email!);
            if (await db.Users.AnyAsync(u => u.Email == email))
                return Json(422, new { message = "User already exists. Use another email.", code = "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL" });

            var now = DateTime.UtcNow;
            var user = new User
            {
                Id = Ids.New("usr"),
                Email = email,
                Name = body.Name!.Trim(),
                PasswordHash = Passwords.Hash(body.Password),
                CreatedAt = now,
                UpdatedAt = now,
            };
            db.Users.Add(user);
            await db.SaveChangesAsync();

            var (token, session) = await sessions.CreateAsync(user, null, "email", ctx);
            sessions.WriteCookie(ctx, token, session);
            return Json(200, new { token, user = Responses.UserJson(user) });
        });

        auth.MapPost("/sign-in/email", async (SignInBody? body, HttpContext ctx, DenDbContext db, SessionService sessions, LoginThrottle throttle) =>
        {
            if (body is null || !IsValidEmail(body.Email) || string.IsNullOrEmpty(body.Password))
                return Json(400, new { message = "Invalid email or password.", code = "VALIDATION_ERROR" });

            var email = NormalizeEmail(body.Email!);
            if (throttle.LockedFor(email) is { } wait)
            {
                ctx.Response.Headers.RetryAfter = ((int)Math.Ceiling(wait.TotalSeconds)).ToString();
                return Json(429, new { error = "login_locked", message = "Too many failed sign-in attempts. Try again later." });
            }

            var user = await db.Users.FirstOrDefaultAsync(u => u.Email == email);
            // Verify against a dummy hash when the user is unknown so timing does not reveal which addresses exist.
            var ok = user is not null ? Passwords.Verify(body.Password, user.PasswordHash) : Passwords.Verify(body.Password, DummyHash);
            if (user is null || !ok)
            {
                throttle.RecordFailure(email);
                return Json(401, new { message = "Invalid email or password", code = "INVALID_EMAIL_OR_PASSWORD" });
            }

            throttle.Reset(email);
            var active = await db.Members.Where(m => m.UserId == user.Id).OrderBy(m => m.CreatedAt).Select(m => m.OrganizationId).FirstOrDefaultAsync();
            var (token, session) = await sessions.CreateAsync(user, active, "email", ctx);
            sessions.WriteCookie(ctx, token, session);
            return Json(200, new { redirect = false, token, user = Responses.UserJson(user) });
        });

        auth.MapGet("/get-session", async (HttpContext ctx, SessionService sessions) =>
        {
            var current = await sessions.ResolveAsync(ctx);
            return current is null
                ? Results.Text("null", "application/json")
                : Results.Json(new { session = Responses.SessionJson(current.Session, current.PresentedToken), user = Responses.UserJson(current.User) });
        });

        auth.MapPost("/sign-out", async (HttpContext ctx, SessionService sessions) =>
        {
            // Revoke whichever credentials were presented: the cookie session and/or the bearer session.
            if (sessions.ReadCookieToken(ctx.Request) is { } cookieToken) await sessions.RevokeAsync(cookieToken);
            if (SessionService.ReadBearer(ctx.Request) is { } bearer) await sessions.RevokeAsync(bearer);
            sessions.ClearCookie(ctx);
            return Results.Json(new { success = true });
        });

        auth.MapPost("/organization/set-active", async (SetActiveBody? body, HttpContext ctx, DenDbContext db, SessionService sessions) =>
        {
            var current = await sessions.ResolveAsync(ctx);
            if (current is null) return Json(401, new { message = "Unauthorized", code = "UNAUTHORIZED" });

            var org = await OrgEndpoints.ResolveMemberOrganizationAsync(db, current.User.Id, body?.OrganizationId, body?.OrganizationSlug);
            if (org is null) return Json(403, new { message = "You are not a member of this organization.", code = "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION" });

            await OrgEndpoints.SetActiveAsync(db, current.Session, org.Id);
            return Json(200, Responses.OrganizationJson(org));
        });

        // Sent whether or not the address exists, so the response never reveals which accounts exist.
        auth.MapPost("/request-password-reset", (PasswordResetRequestBody? body) =>
            IsValidEmail(body?.Email) ? Json(200, new { status = true }) : Json(400, new { message = "Invalid email.", code = "VALIDATION_ERROR" }));

        auth.MapPost("/reset-password", () => Json(400, new { message = "Invalid token", code = "INVALID_TOKEN" }));

        // Everything else under /api/auth: the refused mutations answer 403, the rest 404.
        auth.Map("/{**rest}", (string rest, HttpRequest request) =>
        {
            var path = "/" + rest.TrimEnd('/');
            if (request.Method == HttpMethods.Post && Refused.TryGetValue(path, out var message))
                return Json(403, new { error = "forbidden", message });
            return Json(404, new { message = "Not found" });
        });
    }

    private static readonly string DummyHash = Passwords.Hash("dummy-password-for-timing-only");

    private static IResult Json(int status, object body) => Results.Json(body, statusCode: status);
}
