using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Endpoints;
using WorkAI360.Api.Features.OrgAdmin;
using WorkAI360.Api.Features.Sso;

namespace WorkAI360.Api.Features.EmailCodes;

/// <summary>
/// The other uses of the emailed six-digit code (Better Auth's emailOTP): sign in with a code, check a code without using it, and reset a
/// password with a code. They share the verification code's rules: stored only as a keyed hash, ten minutes, five guesses (counted atomically),
/// a code issued for one purpose never works for another, and nothing says whether an address has an account. Status codes, error codes and
/// bodies are the reference's. Changing the email address by code is switched off in the reference and answers the same here.
/// </summary>
public sealed class EmailCodesFeature : IFeature
{
    public const string SsoManaged = "This account is managed by an organization. Use SSO to sign in.";

    public void AddServices(IServiceCollection services, IConfiguration configuration) { }

    public void MapEndpoints(WebApplication app)
    {
        var auth = app.MapGroup("/api/auth");

        // Sign in with a code: proves the inbox, so the account is verified; a new address gets an account (the reference does the same).
        auth.MapPost("/sign-in/email-otp", async (HttpContext ctx, DenDbContext db, EmailVerificationService verification, SessionService sessions, RateLimiter limiter, SsoRouting sso, IAuditLog audit) =>
        {
            var body = await EmailAuthEndpoints.ReadBodyAsync(ctx);
            if (EmailAuthEndpoints.Validate(body, ("email", "string"), ("otp", "string")) is { } invalid) return invalid;
            // The reference answers an invalid address here like any other wrong code.
            if (!AuthEndpoints.IsValidEmail(body!.Value.GetProperty("email").GetString())) return Responses.AuthError(400, "Invalid OTP", "INVALID_OTP");
            var email = AuthEndpoints.NormalizeEmail(body.Value.GetProperty("email").GetString()!);
            if (limiter.Hit(RateLimiter.VerifyOtp, email, AuthEndpoints.ClientIp(ctx)) is { } wait) return AuthEndpoints.TooManyRequests(ctx, wait);

            if (Refusal(await verification.VerifyAsync(email, body.Value.GetProperty("otp").GetString()!.Trim(), "sign-in")) is { } refused) return refused;

            // The inbox is proven. A workspace that requires SSO still closes this way in (checked after the code, so it is no oracle for who is in one).
            if (await sso.ForExistingUserAsync(email) is not null || await sso.ForEmailDomainAsync(email) is not null) return Results.Json(new { message = SsoManaged }, statusCode: 403);

            var now = DateTime.UtcNow;
            var user = await db.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user is null && await ctx.RequestServices.GetRequiredService<WorkAI360.Api.Features.PlatformAdmin.InitialAdminSetup>().BlocksOrdinarySignUpAsync())
                return Results.Json(new { error = "setup_required", message = WorkAI360.Api.Features.PlatformAdmin.InitialAdminSetup.SetupRequired }, statusCode: 403);
            if (user is null)
            {
                user = new User { Id = Ids.New("usr"), Email = email, Name = "", EmailVerified = true, PasswordHash = SsoProvisioning.UnusablePassword, CreatedAt = now, UpdatedAt = now };
                db.Users.Add(user);
            }
            else if (!user.EmailVerified) { user.EmailVerified = true; user.UpdatedAt = now; }
            try { await db.SaveChangesAsync(); }
            catch (DbUpdateException)
            {
                // Two sign-ins for a new address at once: the other one made the account.
                db.ChangeTracker.Clear();
                user = await db.Users.FirstAsync(u => u.Email == email);
            }

            var active = await db.Members.Where(m => m.UserId == user.Id).OrderBy(m => m.CreatedAt).Select(m => m.OrganizationId).FirstOrDefaultAsync();
            var (token, session) = await sessions.CreateAsync(user, active, "email-otp", ctx);
            sessions.WriteCookie(ctx, token, session);
            await audit.RecordForUserAsync(user.Id, new AuditEntry(AuditActions.SessionCreated, [new("session", session.Id)], "security", After: new() { ["method"] = "email-otp" }));
            return Results.Json(new { token, user = Responses.UserJson(user) });
        });

        // Check a code without using it. The guess still counts against the five, so this is no way to try more.
        auth.MapPost("/email-otp/check-verification-otp", async (HttpContext ctx, EmailVerificationService verification, RateLimiter limiter) =>
        {
            var body = await EmailAuthEndpoints.ReadBodyAsync(ctx);
            if (EmailAuthEndpoints.Validate(body, ("email", "string"), ("type", "string"), ("otp", "string")) is { } invalid) return invalid;
            if (!AuthEndpoints.IsValidEmail(body!.Value.GetProperty("email").GetString())) return Responses.AuthError(400, "Invalid email", "INVALID_EMAIL");
            var type = body.Value.GetProperty("type").GetString()!;
            if (!EmailAuthEndpoints.OtpTypes.Contains(type))
                return Responses.AuthError(400, $"[body.type] Invalid option: expected one of \"{string.Join("\"|\"", EmailAuthEndpoints.OtpTypes)}\"", "VALIDATION_ERROR");
            var email = AuthEndpoints.NormalizeEmail(body.Value.GetProperty("email").GetString()!);
            if (limiter.Hit(RateLimiter.VerifyOtp, email, AuthEndpoints.ClientIp(ctx)) is { } wait) return AuthEndpoints.TooManyRequests(ctx, wait);

            // No code of the unsupported type can exist, so asking about it is simply "invalid".
            var result = type == "change-email" ? OtpResult.Invalid : await verification.VerifyAsync(email, body.Value.GetProperty("otp").GetString()!.Trim(), type, consume: false);
            return Refusal(result) ?? Results.Json(new { success = true });
        });

        // Choose a new password with a code from forget-password. The password rules come first (a weak password does not use up the code).
        auth.MapPost("/email-otp/reset-password", async (HttpContext ctx, DenDbContext db, EmailVerificationService verification, RateLimiter limiter, LoginThrottle throttle, PasswordScreening screening) =>
        {
            var body = await EmailAuthEndpoints.ReadBodyAsync(ctx);
            if (EmailAuthEndpoints.Validate(body, ("email", "string"), ("otp", "string"), ("password", "string")) is { } invalid) return invalid;
            if (!AuthEndpoints.IsValidEmail(body!.Value.GetProperty("email").GetString())) return Responses.AuthError(400, "Invalid email", "INVALID_EMAIL");
            var email = AuthEndpoints.NormalizeEmail(body.Value.GetProperty("email").GetString()!);
            var password = body.Value.GetProperty("password").GetString()!;
            if (limiter.Hit(RateLimiter.VerifyOtp, email, AuthEndpoints.ClientIp(ctx)) is { } wait) return AuthEndpoints.TooManyRequests(ctx, wait);

            if (Passwords.Validate(password) is { } violation) return Results.Json(new { error = violation.Error, message = violation.Message }, statusCode: 400);
            if (await screening.CheckAsync(password, [email], strength: false) is { } rejected) return rejected;
            if (Refusal(await verification.VerifyAsync(email, body.Value.GetProperty("otp").GetString()!.Trim(), "forget-password")) is { } refused) return refused;

            var user = await db.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user is null) return Responses.AuthError(400, "Invalid OTP", "INVALID_OTP");
            var now = DateTime.UtcNow;
            await using var tx = await db.Database.BeginTransactionAsync();
            user.PasswordHash = Passwords.Hash(password);
            user.EmailVerified = true;   // the code proved the inbox
            user.UpdatedAt = now;
            await db.SaveChangesAsync();
            // The old password may be known to someone else: every signed-in device is signed out, and an old reset link stops working.
            await db.Sessions.Where(s => s.UserId == user.Id).ExecuteDeleteAsync();
            await db.PasswordResetTokens.Where(t => t.UserId == user.Id && t.ConsumedAt == null).ExecuteDeleteAsync();
            await tx.CommitAsync();
            throttle.Reset(user.Email);
            return Results.Json(new { success = true });
        });

        // Changing the address by code is off in the reference; nothing in the web app calls these.
        foreach (var path in new[] { "/email-otp/request-email-change", "/email-otp/change-email" })
            auth.MapPost(path, async (HttpContext ctx, SessionService sessions) =>
                await sessions.ResolveAsync(ctx) is null ? Responses.AuthError(401, "Unauthorized", "UNAUTHORIZED") : Results.Json(new { message = "Change email with OTP is disabled" }, statusCode: 400));
    }

    private static IResult? Refusal(OtpResult result) => result switch
    {
        OtpResult.Expired => Responses.AuthError(400, "OTP expired", "OTP_EXPIRED"),
        OtpResult.TooManyAttempts => Responses.AuthError(403, "Too many attempts", "TOO_MANY_ATTEMPTS"),
        OtpResult.Invalid => Responses.AuthError(400, "Invalid OTP", "INVALID_OTP"),
        _ => null,
    };
}
