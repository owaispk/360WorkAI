using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.PlatformAdmin;

namespace WorkAI360.Api.Features.PlatformAdmin;

/// <summary>Settings for platform administration.</summary>
public sealed class PlatformAdminOptions
{
    public const string Section = "PlatformAdmin";

    /// <summary>
    /// Email addresses that are platform admins from the first start (the reference's DEN_BOOTSTRAP_ADMIN_EMAILS). They are added to the admin list once
    /// per process, so a seeded admin can be removed in the page but returns at the next start while it stays configured. Comma separated in an
    /// environment variable (<c>PlatformAdmin__BootstrapEmails=a@x.com,b@x.com</c>) or an array in a configuration file.
    /// </summary>
    public string[] BootstrapEmails { get; set; } = [];

    /// <summary>
    /// The one-time code that opens first-administrator setup on <c>/setup</c> (the reference's DEN_INITIAL_ADMIN_BOOTSTRAP_CODE). Setup is offered
    /// only while no account exists, and only to the <see cref="BootstrapEmails"/>. Hand it over through a secret store, never by email.
    /// </summary>
    public string? InitialAdminCode { get; set; }

    /// <summary>Name of the workspace the first administrator gets (default "OpenWork", as the reference's single-workspace default).</summary>
    public string? InitialWorkspaceName { get; set; }
}

/// <summary>Who is a platform admin: the admin list (a table), seeded from the configured bootstrap addresses.</summary>
public sealed class PlatformAdmins(DenDbContext db, IOptions<PlatformAdminOptions> options)
{
    public const string BootstrapNote = "Seeded bootstrap admin";
    private static readonly SemaphoreSlim SeedLock = new(1, 1);
    private static readonly HashSet<string> Seeded = [];

    public static string Normalize(string? email) => email?.Trim().ToLowerInvariant() ?? "";

    public IEnumerable<string> Bootstrap() =>
        options.Value.BootstrapEmails.SelectMany(e => e.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)).Select(Normalize).Where(e => e.Length > 0).Distinct();

    /// <summary>Adds the configured addresses that are not listed yet. Once per process and database, like the reference.</summary>
    public async Task EnsureSeededAsync()
    {
        var wanted = Bootstrap().ToList();
        if (wanted.Count == 0) return;
        var database = db.Database.GetConnectionString() ?? "";
        var fingerprint = database + "|" + string.Join(',', wanted);
        lock (Seeded) { if (Seeded.Contains(fingerprint)) return; }
        await SeedLock.WaitAsync();
        try
        {
            lock (Seeded) { if (Seeded.Contains(fingerprint)) return; }
            var existing = (await db.Set<AdminAllowlistEntry>().AsNoTracking().Select(a => a.Email).ToListAsync()).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var now = DateTime.UtcNow;
            foreach (var email in wanted.Where(e => !existing.Contains(e)))
                db.Set<AdminAllowlistEntry>().Add(new AdminAllowlistEntry { Id = Ids.New("aal"), Email = email, Note = BootstrapNote, CreatedAt = now, UpdatedAt = now });
            try { await db.SaveChangesAsync(); }
            catch (DbUpdateException) { db.ChangeTracker.Clear(); /* another process listed it first */ }
            lock (Seeded) Seeded.Add(fingerprint);
        }
        finally { SeedLock.Release(); }
    }

    public async Task<bool> IsAdminEmailAsync(string? email)
    {
        var normalized = Normalize(email);
        if (normalized.Length == 0) return false;
        await EnsureSeededAsync();
        return await db.Set<AdminAllowlistEntry>().AsNoTracking().AnyAsync(a => a.Email == normalized);
    }
}

/// <summary>The signed-in platform admin behind an /v1/admin request.</summary>
public sealed record AdminContext(User User, Session Session);

/// <summary>
/// The guard every /v1/admin route starts with (the reference's <c>adminRoute()</c>). Only a signed-in person (a web session or bearer session token;
/// an organization API key or an agent token is not one) whose email is on the admin list passes. Answers: 401 not signed in, 403 no email,
/// 403 admin_email_unverified where the deployment verifies emails, 403 forbidden for everyone else. A workspace role never matters.
/// </summary>
public sealed class PlatformAdminGuard(SessionService sessions, PlatformAdmins admins, IOptions<AuthOptions> auth)
{
    public async Task<(AdminContext? Admin, IResult? Failure)> RequireAsync(HttpContext ctx)
    {
        var resolved = await sessions.ResolveAsync(ctx);
        if (resolved is null) return (null, Responses.Unauthorized());
        var email = PlatformAdmins.Normalize(resolved.User.Email);
        if (email.Length == 0) return (null, Results.Json(new { error = "admin_email_required" }, statusCode: 403));
        // The list names emails, so where emails are verified only a proven address counts.
        if (auth.Value.RequireEmailVerification && !resolved.User.EmailVerified) return (null, Results.Json(new { error = "admin_email_unverified" }, statusCode: 403));
        if (!await admins.IsAdminEmailAsync(email)) return (null, Results.Json(new { error = "forbidden" }, statusCode: 403));
        return (new AdminContext(resolved.User, resolved.Session), null);
    }
}

/// <summary>Small helpers the admin routes share: id shapes and the reference's plain error bodies.</summary>
public static partial class AdminSupport
{
    [GeneratedRegex("^[0-7][0-9a-hjkmnp-tv-z]{25}$")]
    private static partial Regex Suffix();

    /// <summary>The TypeID shape (<c>prefix_</c> and 26 base32 characters), as the reference's isDenTypeId checks it.</summary>
    public static bool IsTypeId(string prefix, string value) => value.StartsWith(prefix + "_", StringComparison.Ordinal) && Suffix().IsMatch(value[(prefix.Length + 1)..]);

    public static IResult Invalid(string message) => Results.Json(new { error = "invalid_request", message }, statusCode: 400);
    public static IResult NotFound(string message) => Results.Json(new { error = "not_found", message }, statusCode: 404);

    public static string Iso(DateTime value) => Responses.IsoUtc(value);

    /// <summary>The lenient organization id check most admin routes use (a plain prefix test); a malformed id that passes it is a 404.</summary>
    public static bool LooksLikeOrganizationId(string value) => value.StartsWith("org_", StringComparison.Ordinal);

    /// <summary>Page request: limit 1 to 100 (default 50), offset 0 to 100000, search trimmed to 160 characters. Anything unparsable falls back.</summary>
    public static (int Limit, int Offset, string Search) Page(IQueryCollection query)
    {
        static int Number(string? value, int fallback) => int.TryParse(value, out var n) && n >= 0 ? n : fallback;
        var limit = Math.Max(1, Math.Min(100, Number(query["limit"], 50)));
        var offset = Math.Min(100000, Number(query["offset"], 0));
        var search = query["search"].ToString().Trim();
        return (limit, offset, search.Length > 160 ? search[..160] : search);
    }

    public static object PageInfo(int limit, int offset, string search, int total, int returned, long durationMs) =>
        new { limit, offset, search, total, returned, hasMore = offset < 100000 && offset + returned < total, durationMs };

    /// <summary>A LIKE pattern for a lower-case search with the escape character '|'.</summary>
    public static string LikePattern(string search) => "%" + search.ToLowerInvariant().Replace("|", "||").Replace("%", "|%").Replace("_", "|_") + "%";
}
