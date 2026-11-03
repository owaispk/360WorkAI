using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.PlatformAdmin;
using WorkAI360.Api.Features.OrgAdmin;

namespace WorkAI360.Api.Features.PlatformAdmin;

/// <summary>Writes feature state (for everyone, kill switch, per-workspace overrides) with its history, and reads the latest change per feature.</summary>
public sealed class FeatureChanges(DenDbContext db)
{
    private void Record(string key, string scope, string action, string? organizationId, string? userId, string? memberId = null) =>
        db.Set<PlatformFeatureChange>().Add(new PlatformFeatureChange { Id = Ids.New("fch"), FeatureKey = key, Scope = scope, Action = action, OrganizationId = organizationId, MemberId = memberId, ChangedByUserId = userId, CreatedAt = DateTime.UtcNow });

    /// <summary>On or off for everyone and/or the kill switch. Keys not given keep their value. Returns nothing; read the state again.</summary>
    public async Task SetRolloutAsync(FeatureInfo feature, bool? enabled, bool? killed, string userId)
    {
        for (var attempt = 0; ; attempt++)
        {
            try
            {
                await using var tx = await db.Database.BeginTransactionAsync();
                var row = await db.Set<PlatformFeatureRollout>().FirstOrDefaultAsync(r => r.FeatureKey == feature.Key);
                var wasEnabled = row?.Enabled ?? FeatureState.Default(feature.Key);
                var wasKilled = row?.Killed ?? false;
                var nowEnabled = enabled ?? wasEnabled;
                var nowKilled = killed ?? wasKilled;
                if (row is null) db.Set<PlatformFeatureRollout>().Add(row = new PlatformFeatureRollout { FeatureKey = feature.Key });
                row.Enabled = nowEnabled; row.Killed = nowKilled; row.UpdatedByUserId = userId; row.UpdatedAt = DateTime.UtcNow;
                if (nowKilled != wasKilled) Record(feature.Key, "everyone", nowKilled ? "killed" : "restored", null, userId);
                if (nowEnabled != wasEnabled) Record(feature.Key, "everyone", nowEnabled ? "on" : "off", null, userId);
                await db.SaveChangesAsync();
                await tx.CommitAsync();
                return;
            }
            catch (DbUpdateException) when (attempt == 0)
            {
                // Two first-time changes of the same feature raced on the new row: the loser reads theirs and applies its own change on top.
                db.ChangeTracker.Clear();
            }
        }
    }

    /// <summary>Sets (true or false) or clears (null) a workspace's overrides. Features missing from the list are left alone.</summary>
    public async Task SetOverridesAsync(string organizationId, IReadOnlyList<(FeatureInfo Feature, bool? Value)> requested, string userId)
    {
        if (requested.Count == 0) return;
        await using var tx = await db.Database.BeginTransactionAsync();
        await db.LockOrganizationAsync(organizationId);
        var keys = requested.Select(r => r.Feature.Key).ToList();
        var existing = await db.Set<PlatformOrganizationFeature>().Where(f => f.OrganizationId == organizationId && keys.Contains(f.FeatureKey)).ToDictionaryAsync(f => f.FeatureKey);
        var now = DateTime.UtcNow;
        foreach (var (feature, value) in requested)
        {
            existing.TryGetValue(feature.Key, out var row);
            if (value is null)
            {
                if (row is null) continue;
                db.Set<PlatformOrganizationFeature>().Remove(row);
                Record(feature.Key, "organization", "reset", organizationId, userId);
                continue;
            }
            var previous = row?.Enabled;
            if (row is null) db.Set<PlatformOrganizationFeature>().Add(new PlatformOrganizationFeature { OrganizationId = organizationId, FeatureKey = feature.Key, Enabled = value.Value, SetByUserId = userId, UpdatedAt = now });
            else { row.Enabled = value.Value; row.SetByUserId = userId; row.UpdatedAt = now; }
            if (previous != value) Record(feature.Key, "organization", value.Value ? "on" : "off", organizationId, userId);
        }
        await db.SaveChangesAsync();
        await tx.CommitAsync();
    }

    /// <summary>
    /// Sets (true or false) or clears (null) one member's overrides. The membership is re-read under the workspace lock, so a member removed meanwhile
    /// gets nothing; returns false then. Features missing from the list are left alone.
    /// </summary>
    public async Task<bool> SetMemberOverridesAsync(string organizationId, string memberId, IReadOnlyList<(FeatureInfo Feature, bool? Value)> requested, string userId)
    {
        await using var tx = await db.Database.BeginTransactionAsync();
        await db.LockOrganizationAsync(organizationId);
        if (!await ActiveMemberQuery(organizationId, memberId).AnyAsync()) return false;
        var keys = requested.Select(r => r.Feature.Key).ToList();
        var existing = await db.Set<PlatformMemberFeature>().Where(f => f.MemberId == memberId && keys.Contains(f.FeatureKey)).ToDictionaryAsync(f => f.FeatureKey);
        var now = DateTime.UtcNow;
        foreach (var (feature, value) in requested)
        {
            existing.TryGetValue(feature.Key, out var row);
            if (value is null)
            {
                if (row is null) continue;
                db.Set<PlatformMemberFeature>().Remove(row);
                Record(feature.Key, "member", "reset", organizationId, userId, memberId);
                continue;
            }
            var previous = row?.Enabled;
            if (row is null) db.Set<PlatformMemberFeature>().Add(new PlatformMemberFeature { MemberId = memberId, FeatureKey = feature.Key, Enabled = value.Value, SetByUserId = userId, CreatedAt = now, UpdatedAt = now });
            else { row.Enabled = value.Value; row.SetByUserId = userId; row.UpdatedAt = now; }
            if (previous != value) Record(feature.Key, "member", value.Value ? "on" : "off", organizationId, userId, memberId);
        }
        await db.SaveChangesAsync();
        await tx.CommitAsync();
        return true;
    }

    /// <summary>A joined person of the workspace (not the sign-in-less setup member an agent's provisional workspace has).</summary>
    public IQueryable<Member> ActiveMemberQuery(string organizationId, string memberId) =>
        from m in db.Members
        join u in db.Users on m.UserId equals u.Id
        where m.Id == memberId && m.OrganizationId == organizationId && !u.Email.EndsWith("@" + Onboarding.BootstrapService.AgentEmailDomain)
        select m;

    /// <summary>
    /// The latest change per feature that could have changed what a workspace gets (its own override or the deployment-wide state, and with a member,
    /// that member's override), or, with no workspace, the latest deployment-wide change. Shaped as the reference's lastChange.
    /// </summary>
    public async Task<Dictionary<string, object?>> LatestAsync(string? organizationId = null, string? memberId = null)
    {
        var rows = await (from c in db.Set<PlatformFeatureChange>().AsNoTracking()
                          where c.Scope == "everyone" || (organizationId != null && c.Scope == "organization" && c.OrganizationId == organizationId)
                             || (memberId != null && c.Scope == "member" && c.MemberId == memberId)
                          join u in db.Users.AsNoTracking() on c.ChangedByUserId equals u.Id into users
                          from u in users.DefaultIfEmpty()
                          orderby c.CreatedAt descending, c.Id descending
                          select new { c.FeatureKey, c.Scope, c.Action, c.CreatedAt, UserId = u == null ? null : u.Id, UserName = u == null ? null : u.Name, UserEmail = u == null ? null : u.Email }).ToListAsync();
        var latest = new Dictionary<string, object?>();
        foreach (var row in rows)
        {
            if (latest.ContainsKey(row.FeatureKey)) continue;
            latest[row.FeatureKey] = new
            {
                scope = row.Scope, action = row.Action, at = AdminSupport.Iso(row.CreatedAt),
                by = row.UserId is null ? null : new { id = row.UserId, name = row.UserName, email = row.UserEmail },
            };
        }
        return latest;
    }
}
