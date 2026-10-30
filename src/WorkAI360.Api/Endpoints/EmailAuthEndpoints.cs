using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Email;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Endpoints;

/// <summary>
/// Email verification (six-digit codes) and password reset (single-use links). Status codes, error codes and response bodies
/// follow the reference's Better Auth endpoints, which the existing web app and CLI already depend on.
/// </summary>
public static class EmailAuthEndpoints
{
    public const string ResetMessage = "If this email exists in our system, check your email for the reset link";
    private static readonly TimeSpan ResetLifetime = TimeSpan.FromHours(1);
    private static readonly string[] OtpTypes = ["email-verification", "sign-in", "forget-password", "change-email"];

    public static void MapEmailAuthEndpoints(this WebApplication app)
    {
        var auth = app.MapGroup("/api/auth");

        // ---------- verification codes ----------

        auth.MapPost("/email-otp/send-verification-otp", async (HttpContext ctx, DenDbContext db, EmailVerificationService verification, RateLimiter limiter) =>
        {
            var body = await ReadBodyAsync(ctx);
            if (Validate(body, ("email", "string"), ("type", "string")) is { } invalid) return invalid;
            if (!AuthEndpoints.IsValidEmail(body!.Value.GetProperty("email").GetString())) return Responses.AuthError(400, "Invalid email", "INVALID_EMAIL");
            var type = body!.Value.GetProperty("type").GetString()!;
            if (!OtpTypes.Contains(type))
                return Responses.AuthError(400, $"[body.type] Invalid option: expected one of \"{string.Join("\"|\"", OtpTypes)}\"", "VALIDATION_ERROR");
            if (type != EmailVerificationService.TypeEmailVerification)
                return Responses.AuthError(400, "Only email-verification codes are supported.", "UNSUPPORTED_OTP_TYPE");

            var email = AuthEndpoints.NormalizeEmail(body.Value.GetProperty("email").GetString()!);
            if (limiter.Hit(RateLimiter.SendOtp, email, AuthEndpoints.ClientIp(ctx)) is { } wait) return AuthEndpoints.TooManyRequests(ctx, wait);

            // Same answer whether or not the account exists, so this cannot be used to find out who has one.
            var user = await db.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user is not null) await verification.SendCodeAsync(user, force: true);
            return Results.Json(new { success = true });
        });

        auth.MapPost("/email-otp/verify-email", async (HttpContext ctx, DenDbContext db, EmailVerificationService verification, RateLimiter limiter) =>
        {
            var body = await ReadBodyAsync(ctx);
            if (Validate(body, ("email", "string"), ("otp", "string")) is { } invalid) return invalid;
            if (!AuthEndpoints.IsValidEmail(body!.Value.GetProperty("email").GetString())) return Responses.AuthError(400, "Invalid email", "INVALID_EMAIL");
            var email = AuthEndpoints.NormalizeEmail(body!.Value.GetProperty("email").GetString()!);
            if (limiter.Hit(RateLimiter.VerifyOtp, email, AuthEndpoints.ClientIp(ctx)) is { } wait) return AuthEndpoints.TooManyRequests(ctx, wait);

            switch (await verification.VerifyAsync(email, body.Value.GetProperty("otp").GetString()!.Trim()))
            {
                case OtpResult.Expired: return Responses.AuthError(400, "OTP expired", "OTP_EXPIRED");
                case OtpResult.TooManyAttempts: return Responses.AuthError(403, "Too many attempts", "TOO_MANY_ATTEMPTS");
                case OtpResult.Invalid: return Responses.AuthError(400, "Invalid OTP", "INVALID_OTP");
            }

            var user = await db.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user is null) return Responses.AuthError(400, "User not found", "USER_NOT_FOUND");
            user.EmailVerified = true;
            user.UpdatedAt = DateTime.UtcNow;
            await db.SaveChangesAsync();
            // No session is created: the person signs in with their password next (the reference answers token: null too).
            return Results.Json(new { status = true, token = (string?)null, user = Responses.UserJson(user) });
        });

        // ---------- password reset ----------

        auth.MapPost("/request-password-reset", async (HttpContext ctx, DenDbContext db, IEmailSender sender, RateLimiter limiter, TrustedUrls trusted, OAuthUrls urls, ILoggerFactory logs) =>
        {
            var body = await ReadBodyAsync(ctx);
            if (Validate(body, ("email", "email")) is { } invalid) return invalid;
            var email = AuthEndpoints.NormalizeEmail(body!.Value.GetProperty("email").GetString()!);

            string? redirectTo = body.Value.TryGetProperty("redirectTo", out var r) && r.ValueKind == JsonValueKind.String && r.GetString() is { Length: > 0 } rt ? rt : null;
            if (redirectTo is not null && !trusted.IsTrusted(redirectTo)) return Responses.AuthError(403, "Invalid redirectURL", "INVALID_REDIRECT_URL");
            if (limiter.Hit(RateLimiter.ResetRequest, email, AuthEndpoints.ClientIp(ctx)) is { } wait) return AuthEndpoints.TooManyRequests(ctx, wait);

            var user = await db.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user is not null)
            {
                var token = Ids.RandomAlnum(32);
                var now = DateTime.UtcNow;
                await db.PasswordResetTokens.Where(t => t.UserId == user.Id && t.ConsumedAt == null).ExecuteDeleteAsync(); // only the newest link works
                db.PasswordResetTokens.Add(new PasswordResetToken { Id = Ids.Sha256Hex(token), UserId = user.Id, RedirectTo = redirectTo, CreatedAt = now, ExpiresAt = now + ResetLifetime });
                await db.SaveChangesAsync();

                var link = $"{urls.Web}/api/auth/reset-password/{token}?callbackURL={Uri.EscapeDataString(redirectTo ?? "")}";
                try { await sender.SendAsync(EmailTemplates.PasswordReset(user.Email, link)); }
                catch (Exception e) when (e is not OperationCanceledException) { logs.CreateLogger("PasswordReset").LogError(e, "Could not send a password reset email"); }
            }
            return Results.Json(new { status = true, message = ResetMessage });
        });

        // The link in the email. It checks the token and sends the browser on to the reset page; it never changes anything itself.
        auth.MapGet("/reset-password/{token}", async (string token, string? callbackURL, DenDbContext db, TrustedUrls trusted, OAuthUrls urls) =>
        {
            if (!string.IsNullOrEmpty(callbackURL) && !trusted.IsTrusted(callbackURL))
                return Responses.AuthError(403, "Invalid callbackURL", "INVALID_CALLBACK_URL");

            var target = string.IsNullOrEmpty(callbackURL) ? $"{urls.Web}/reset-password" : trusted.Absolute(callbackURL);
            var hash = Ids.Sha256Hex(token);
            var valid = await db.PasswordResetTokens.AsNoTracking().AnyAsync(t => t.Id == hash && t.ConsumedAt == null && t.ExpiresAt > DateTime.UtcNow);
            return Results.Redirect(valid
                ? QueryHelpers.AddQueryString(target, "token", token)
                : QueryHelpers.AddQueryString(target, "error", "INVALID_TOKEN"));
        });

        auth.MapPost("/reset-password", async (HttpContext ctx, DenDbContext db, LoginThrottle throttle) =>
        {
            var body = await ReadBodyAsync(ctx);
            if (body is not { ValueKind: JsonValueKind.Object } root) return Responses.AuthError(400, "Invalid token", "INVALID_TOKEN");
            var newPassword = root.TryGetProperty("newPassword", out var np) && np.ValueKind == JsonValueKind.String ? np.GetString() : null;
            var token = root.TryGetProperty("token", out var tk) && tk.ValueKind == JsonValueKind.String ? tk.GetString() : null;
            if (newPassword is null) return Responses.AuthError(400, "[body.newPassword] Invalid input: expected string, received undefined", "VALIDATION_ERROR");

            // The password rules come first, exactly as in the reference, so a weak password is reported whatever the token.
            if (Passwords.Validate(newPassword) is { } violation) return Results.Json(new { error = violation.Error, message = violation.Message }, statusCode: 400);
            if (string.IsNullOrEmpty(token)) return Responses.AuthError(400, "Invalid token", "INVALID_TOKEN");

            var hash = Ids.Sha256Hex(token);
            var now = DateTime.UtcNow;
            await using var tx = await db.Database.BeginTransactionAsync();
            // Single use: only one caller can flip ConsumedAt from null.
            var claimed = await db.PasswordResetTokens.Where(t => t.Id == hash && t.ConsumedAt == null && t.ExpiresAt > now).ExecuteUpdateAsync(s => s.SetProperty(t => t.ConsumedAt, now));
            if (claimed == 0) return Responses.AuthError(400, "Invalid token", "INVALID_TOKEN");

            var userId = await db.PasswordResetTokens.AsNoTracking().Where(t => t.Id == hash).Select(t => t.UserId).FirstAsync();
            var user = await db.Users.FirstAsync(u => u.Id == userId);
            user.PasswordHash = Passwords.Hash(newPassword);
            user.UpdatedAt = now;
            await db.SaveChangesAsync();
            // A reset means the old password may be known to someone else: every signed-in device is signed out.
            await db.Sessions.Where(s => s.UserId == userId).ExecuteDeleteAsync();
            await db.PasswordResetTokens.Where(t => t.UserId == userId && t.ConsumedAt == null).ExecuteDeleteAsync();
            await tx.CommitAsync();

            throttle.Reset(user.Email);
            return Results.Json(new { status = true });
        });
    }

    private static async Task<JsonElement?> ReadBodyAsync(HttpContext ctx)
    {
        try { return (await JsonDocument.ParseAsync(ctx.Request.Body)).RootElement.Clone(); }
        catch (JsonException) { return null; }
    }

    /// <summary>Checks required body fields and answers the way the reference's schema validation does.</summary>
    private static IResult? Validate(JsonElement? body, params (string Name, string Kind)[] fields)
    {
        if (body is not { ValueKind: JsonValueKind.Object } root)
            return Responses.AuthError(400, "Invalid request body", "VALIDATION_ERROR");
        foreach (var (name, kind) in fields)
        {
            if (!root.TryGetProperty(name, out var v))
                return Responses.AuthError(400, $"[body.{name}] Invalid input: expected string, received undefined", "VALIDATION_ERROR");
            if (v.ValueKind != JsonValueKind.String)
                return Responses.AuthError(400, $"[body.{name}] Invalid input: expected string, received {v.ValueKind.ToString().ToLowerInvariant()}", "VALIDATION_ERROR");
            if (kind == "email" && !AuthEndpoints.IsValidEmail(v.GetString()))
                return Responses.AuthError(400, $"[body.{name}] Invalid email address", "VALIDATION_ERROR");
        }
        return null;
    }
}

/// <summary>Where an emailed link may send the browser: this deployment's web origin, configured extras, or a path on this site.</summary>
public sealed class TrustedUrls(OAuthUrls urls, IOptions<AuthOptions> options)
{
    public bool IsTrusted(string url)
    {
        if (url.StartsWith('/')) return !url.StartsWith("//") && !url.Contains('\\');
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https")) return false;
        if (!string.IsNullOrEmpty(uri.UserInfo)) return false;
        var origin = $"{uri.Scheme}://{uri.Authority}";
        return string.Equals(origin, urls.Web, StringComparison.OrdinalIgnoreCase)
            || options.Value.TrustedOrigins.Any(o => string.Equals(o.TrimEnd('/'), origin, StringComparison.OrdinalIgnoreCase));
    }

    public string Absolute(string url) => url.StartsWith('/') ? urls.Web + url : url;
}
