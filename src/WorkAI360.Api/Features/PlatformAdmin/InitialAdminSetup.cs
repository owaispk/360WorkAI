using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.PlatformAdmin;
using WorkAI360.Api.Endpoints;

namespace WorkAI360.Api.Features.PlatformAdmin;

/// <summary>
/// First-administrator setup for a private deployment (the reference's <c>initial-admin-bootstrap.ts</c>). Before anyone has an account, the operator
/// configures one or more administrator addresses (<c>PlatformAdmin:BootstrapEmails</c>) and a one-time code (<c>PlatformAdmin:InitialAdminCode</c>).
/// On <c>/setup</c> a person proves both and receives a short-lived signed grant; signing up with it creates the first account with a verified
/// address, a workspace they own, and a place on the platform admin list. Once any account exists, setup is closed for good.
/// </summary>
public sealed class InitialAdminSetup(DenDbContext db, PlatformAdmins admins, IOptions<AuthOptions> auth, IOptions<PlatformAdminOptions> options)
{
    public const string GrantPrefix = "ow_bootstrap_";
    public const string AdminNote = "Initial administrator bootstrap";
    public const string SetupRequired = "This deployment is waiting for its first administrator. Sign-up opens once setup is complete.";
    public const string Rejection = "Setup could not be verified. Check the administrator email and one-time setup code.";
    public static readonly TimeSpan GrantLifetime = TimeSpan.FromMinutes(10);

    /// <summary><c>available</c>, <c>complete</c> (an account exists) or <c>unavailable</c> (no administrator address or no code configured).</summary>
    public async Task<string> StatusAsync()
    {
        if (await db.Users.AnyAsync()) return "complete";
        return Configured ? "available" : "unavailable";
    }

    private bool Configured => admins.Bootstrap().Any() && !string.IsNullOrEmpty(options.Value.InitialAdminCode);

    private bool IsConfiguredEmail(string normalizedEmail) => normalizedEmail.Length > 0 && admins.Bootstrap().Contains(normalizedEmail);

    public sealed record VerifyResult(int Status, string? Grant, DateTime ExpiresAt);

    /// <summary>Checks the address and code; 200 with a grant, 409 when setup is not open, 403 for anything else (one message, so nothing is revealed).</summary>
    public async Task<VerifyResult> VerifyAsync(string email, string code)
    {
        if (await StatusAsync() != "available") return new VerifyResult(409, null, default);
        var normalized = PlatformAdmins.Normalize(email);
        // Both checks always run, and the code is compared as fixed-length hashes, so neither the address nor the code's length shows in timing.
        var codeMatches = CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(code)), SHA256.HashData(Encoding.UTF8.GetBytes(options.Value.InitialAdminCode ?? "")));
        if (!IsConfiguredEmail(normalized) || !codeMatches) return new VerifyResult(403, null, default);
        var expiresAt = DateTime.UtcNow + GrantLifetime;
        return new VerifyResult(200, Encode(normalized, expiresAt), expiresAt);
    }

    /// <summary>The address a grant was issued for, when it is genuine, unexpired, for <paramref name="email"/>, and setup is still open; otherwise null.</summary>
    public async Task<string?> AuthorizeSignUpAsync(string? grant, string email)
    {
        if (string.IsNullOrWhiteSpace(grant) || Decode(grant.Trim()) is not { } decoded) return null;
        var normalized = PlatformAdmins.Normalize(email);
        if (decoded.Email != normalized || decoded.ExpiresAt <= DateTime.UtcNow || !IsConfiguredEmail(normalized)) return null;
        return await StatusAsync() == "available" ? normalized : null;
    }

    /// <summary>
    /// True while setup is open: ordinary sign-up waits until the first administrator exists (the reference closes public sign-up in a private
    /// deployment; here that holds only until setup is done, since this build has no single-workspace mode).
    /// </summary>
    public async Task<bool> BlocksOrdinarySignUpAsync() => Configured && !await db.Users.AnyAsync();

    /// <summary>After the account is created: a workspace the person owns, and their address on the admin list (added, or its note updated).</summary>
    public async Task<Organization> CompleteAsync(User user, PermissionService permissions)
    {
        var org = await OrgEndpoints.CreateWorkspaceAsync(db, permissions, user.Id, string.IsNullOrWhiteSpace(options.Value.InitialWorkspaceName) ? "OpenWork" : options.Value.InitialWorkspaceName.Trim());
        var now = DateTime.UtcNow;
        var entry = await db.Set<AdminAllowlistEntry>().FirstOrDefaultAsync(a => a.Email == user.Email);
        if (entry is null) db.Set<AdminAllowlistEntry>().Add(new AdminAllowlistEntry { Id = Ids.New("aal"), Email = user.Email, Note = AdminNote, CreatedAt = now, UpdatedAt = now });
        else { entry.Note = AdminNote; entry.UpdatedAt = now; }
        try { await db.SaveChangesAsync(); }
        catch (DbUpdateException)
        {
            // The seeding of configured admins listed the address at the same moment; it is listed either way.
            db.ChangeTracker.Clear();
        }
        return org;
    }

    private byte[] Key => HMACSHA256.HashData(Encoding.UTF8.GetBytes(auth.Value.Secret), "workai360:initial-admin-bootstrap"u8);

    private string Encode(string email, DateTime expiresAt)
    {
        var payload = Base64Url(JsonSerializer.SerializeToUtf8Bytes(new { email, expiresAt = new DateTimeOffset(expiresAt).ToUnixTimeMilliseconds() }));
        return $"{GrantPrefix}{payload}.{Base64Url(HMACSHA256.HashData(Key, Encoding.ASCII.GetBytes(payload)))}";
    }

    private (string Email, DateTime ExpiresAt)? Decode(string grant)
    {
        if (!grant.StartsWith(GrantPrefix, StringComparison.Ordinal)) return null;
        var parts = grant[GrantPrefix.Length..].Split('.');
        if (parts.Length != 2 || parts[0].Length == 0) return null;
        byte[] signature;
        try { signature = FromBase64Url(parts[1]); } catch (FormatException) { return null; }
        if (!CryptographicOperations.FixedTimeEquals(signature, HMACSHA256.HashData(Key, Encoding.ASCII.GetBytes(parts[0])))) return null;
        try
        {
            using var doc = JsonDocument.Parse(FromBase64Url(parts[0]));
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("email", out var email) || email.ValueKind != JsonValueKind.String
                || !root.TryGetProperty("expiresAt", out var expires) || !expires.TryGetInt64(out var ms)) return null;
            return (email.GetString()!, DateTimeOffset.FromUnixTimeMilliseconds(ms).UtcDateTime);
        }
        catch (Exception e) when (e is JsonException or FormatException or ArgumentOutOfRangeException) { return null; }
    }

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] FromBase64Url(string value)
    {
        var s = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(s + new string('=', (4 - s.Length % 4) % 4));
    }
}

public sealed record BootstrapVerifyBody(string? Email, string? Code);

public static class InitialAdminSetupEndpoints
{
    /// <summary>Verification attempts per address, as in the reference (5 per 5 minutes).</summary>
    private const int VerifyMax = 5;
    private static readonly TimeSpan VerifyWindow = TimeSpan.FromMinutes(5);

    public static void MapInitialAdminSetupEndpoints(this WebApplication app)
    {
        // Public: says whether setup is open without naming the configured addresses.
        app.MapGet("/v1/auth/bootstrap/status", async (InitialAdminSetup setup) => Results.Json(new { status = await setup.StatusAsync() }));

        app.MapPost("/v1/auth/bootstrap/verify", async (HttpContext ctx, InitialAdminSetup setup, RateLimiter limiter) =>
        {
            BootstrapVerifyBody? body;
            try { body = await ctx.Request.ReadFromJsonAsync<BootstrapVerifyBody>(); }
            catch (Exception e) when (e is JsonException or InvalidOperationException) { body = null; }
            var rejected = Results.Json(new { error = "bootstrap_verification_failed", message = InitialAdminSetup.Rejection }, statusCode: 403);
            if (body is null || !AuthEndpoints.IsValidEmail(body.Email?.Trim()) || string.IsNullOrEmpty(body.Code)) return rejected;

            var key = "bootstrap-verify:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(AuthEndpoints.NormalizeEmail(body.Email!.Trim()))));
            if (limiter.Window(key, VerifyMax, VerifyWindow, consume: true) is { } wait)
            {
                ctx.Response.Headers.RetryAfter = ((int)Math.Ceiling(wait.TotalSeconds)).ToString();
                return Results.Json(new { error = "rate_limited", message = "Too many setup attempts. Try again later." }, statusCode: 429);
            }

            var result = await setup.VerifyAsync(body.Email, body.Code);
            return result.Status switch
            {
                200 => Results.Json(new { grant = result.Grant, expiresAt = result.ExpiresAt.ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }),
                409 => Results.Json(new { error = "bootstrap_unavailable", message = "Initial administrator setup is not available." }, statusCode: 409),
                _ => rejected,
            };
        });
    }
}
