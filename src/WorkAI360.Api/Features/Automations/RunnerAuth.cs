using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Automations;

namespace WorkAI360.Api.Features.Automations;

/// <summary>
/// The credential a desktop runner uses: a 12-hour token signed with the server's secret that names the workspace, the person, the install and the server
/// URL it was minted for. It holds no server state, so every request also checks that the person is still an active member.
/// </summary>
public sealed class RunnerAuth(IOptions<AuthOptions> auth, DenDbContext db)
{
    private const long TokenTtlMs = 12 * 60 * 60_000;
    private byte[] Key => Encoding.UTF8.GetBytes(auth.Value.Secret);

    private string Sign(string payload) =>
        Base64Url(HMACSHA256.HashData(Key, Encoding.UTF8.GetBytes($"openwork-automation-runner-v1.{payload}")));

    private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] FromBase64Url(string value)
    {
        var s = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(s.PadRight(s.Length + (4 - s.Length % 4) % 4, '='));
    }

    public (string Token, long ExpiresAt) Issue(string organizationId, string memberId, string runnerId, IReadOnlyList<string> capabilities, string audience)
    {
        var expiresAt = AutomationService.Now() + TokenTtlMs;
        var payload = Base64Url(JsonSerializer.SerializeToUtf8Bytes(new { v = 2, o = organizationId, m = memberId, r = runnerId, c = capabilities, a = audience, e = expiresAt }));
        return ($"{payload}.{Sign(payload)}", expiresAt);
    }

    /// <summary>The identity in a bearer token, or null when it is missing, forged, expired or its person is no longer an active member.</summary>
    public async Task<RunnerIdentity?> AuthenticateAsync(HttpContext ctx)
    {
        var header = ctx.Request.Headers.Authorization.ToString().Trim();
        if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return null;
        var parts = header[7..].Trim().Split('.');
        if (parts.Length != 2 || parts[0].Length == 0 || parts[1].Length == 0) return null;
        if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(Sign(parts[0])), Encoding.UTF8.GetBytes(parts[1]))) return null;
        try
        {
            using var doc = JsonDocument.Parse(FromBase64Url(parts[0]));
            var root = doc.RootElement;
            var version = root.GetProperty("v").GetInt32();
            if (version is not (1 or 2)) return null;
            var expires = root.GetProperty("e").GetInt64();
            if (expires <= AutomationService.Now()) return null;
            var capabilities = root.TryGetProperty("c", out var c) ? c.EnumerateArray().Select(x => x.GetString()!).ToList() : [];
            var identity = new RunnerIdentity(root.GetProperty("o").GetString()!, root.GetProperty("m").GetString()!, root.GetProperty("r").GetString()!, capabilities,
                root.TryGetProperty("a", out var a) ? a.GetString() : null, expires);
            return await db.Members.AsNoTracking().AnyAsync(m => m.Id == identity.OwnerMemberId && m.OrganizationId == identity.OrganizationId) ? identity : null;
        }
        catch (Exception e) when (e is JsonException or KeyNotFoundException or InvalidOperationException or FormatException) { return null; }
    }

    /// <summary>One row per workspace, person and install, so one install in two workspaces is two runners.</summary>
    public static string RowId(string organizationId, string memberId, string installId) =>
        "rnr_" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes($"{organizationId}\n{memberId}\n{installId}")));
}

/// <summary>Remembers desktops: registering one (or seeing it ask for work) is what "a desktop is connected" means.</summary>
public sealed class RunnerRegistry(DenDbContext db)
{
    public async Task RegisterAsync(string organizationId, string memberId, RunnerRegistration registration, long now)
    {
        var id = RunnerAuth.RowId(organizationId, memberId, registration.RunnerId);
        var capabilities = JsonSerializer.Serialize(registration.Capabilities);
        for (var attempt = 0; ; attempt++)
        {
            var updated = await db.Set<AutomationRunner>().Where(r => r.Id == id && r.OrganizationId == organizationId && r.OwnerMemberId == memberId)
                .ExecuteUpdateAsync(s => s.SetProperty(r => r.ProtocolVersion, registration.ProtocolVersion).SetProperty(r => r.CapabilitiesJson, capabilities)
                    .SetProperty(r => r.AppVersion, registration.AppVersion).SetProperty(r => r.Platform, registration.Platform).SetProperty(r => r.Concurrency, registration.Concurrency)
                    .SetProperty(r => r.LastSeenAt, now).SetProperty(r => r.UpdatedAt, now));
            if (updated > 0) return;
            db.Set<AutomationRunner>().Add(new AutomationRunner
            {
                Id = id, OrganizationId = organizationId, OwnerMemberId = memberId, InstallId = registration.RunnerId, ProtocolVersion = registration.ProtocolVersion, CapabilitiesJson = capabilities,
                AppVersion = registration.AppVersion, Platform = registration.Platform, Concurrency = registration.Concurrency, LastSeenAt = now, CreatedAt = now, UpdatedAt = now,
            });
            try { await db.SaveChangesAsync(); return; }
            catch (DbUpdateException) when (attempt == 0) { db.ChangeTracker.Clear(); }   // another registration of this desktop got there first
        }
    }

    public Task TouchAsync(RunnerIdentity who, long now) =>
        db.Set<AutomationRunner>().Where(r => r.Id == RunnerAuth.RowId(who.OrganizationId, who.OwnerMemberId, who.RunnerId) && r.OrganizationId == who.OrganizationId && r.OwnerMemberId == who.OwnerMemberId)
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.LastSeenAt, now).SetProperty(r => r.UpdatedAt, now));

    public async Task<bool> SessionOnlyAsync(RunnerIdentity who)
    {
        if (who.Capabilities.Contains(RunnerCapability.SessionOnly)) return true;
        var stored = await db.Set<AutomationRunner>().AsNoTracking().Where(r => r.Id == RunnerAuth.RowId(who.OrganizationId, who.OwnerMemberId, who.RunnerId)).Select(r => r.CapabilitiesJson).FirstOrDefaultAsync();
        return stored is not null && stored.Contains(RunnerCapability.SessionOnly, StringComparison.Ordinal);
    }

    /// <summary>Forgets desktops that stopped checking in a month ago; signing in again registers them anew.</summary>
    public Task<int> PruneAsync(long now) =>
        db.Set<AutomationRunner>().Where(r => r.LastSeenAt < now - 30L * 24 * 60 * 60_000).ExecuteDeleteAsync();

    /// <summary>Wake-up hints are kept a week, as in the reference; a desktop away longer finds its work by polling.</summary>
    public Task<int> PruneNotificationsAsync(long now) =>
        db.Set<AutomationRunnerNotification>().Where(n => n.CreatedAt < now - 7L * 24 * 60 * 60_000).ExecuteDeleteAsync();

    /// <summary>The hints for this person's desktops after <paramref name="after"/>, oldest first (at most 100 at a time, as the reference).</summary>
    public Task<List<AutomationRunnerNotification>> NotificationsAsync(RunnerIdentity who, long after) =>
        db.Set<AutomationRunnerNotification>().AsNoTracking()
            .Where(n => n.OrganizationId == who.OrganizationId && n.OwnerMemberId == who.OwnerMemberId && n.Id > after)
            .OrderBy(n => n.Id).Take(100).ToListAsync();

    /// <summary>Whether this runner is still registered to this person (a stream ends when it is not).</summary>
    public Task<bool> RegisteredAsync(RunnerIdentity who) =>
        db.Set<AutomationRunner>().AsNoTracking().AnyAsync(r => r.Id == RunnerAuth.RowId(who.OrganizationId, who.OwnerMemberId, who.RunnerId) && r.OrganizationId == who.OrganizationId && r.OwnerMemberId == who.OwnerMemberId);

    /// <summary>Stores the runner's latest inventory; false when it has no registration (it must register again first).</summary>
    public async Task<bool> SaveInventoryAsync(RunnerIdentity who, string inventoryJson, long now) =>
        await db.Set<AutomationRunner>().Where(r => r.Id == RunnerAuth.RowId(who.OrganizationId, who.OwnerMemberId, who.RunnerId) && r.OrganizationId == who.OrganizationId && r.OwnerMemberId == who.OwnerMemberId)
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.InventoryJson, inventoryJson).SetProperty(r => r.InventoryUpdatedAt, (long?)now).SetProperty(r => r.LastSeenAt, now).SetProperty(r => r.UpdatedAt, now)) > 0;
}

public sealed record RunnerRegistration(string RunnerId, int ProtocolVersion, IReadOnlyList<string> Capabilities, string AppVersion, string Platform, int Concurrency);
