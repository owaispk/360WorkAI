using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;

namespace WorkAI360.Api.Auth;

/// <summary>Why a person holds a permission (the owner, a default set, or a team's role).</summary>
public sealed record PermissionSource(string Kind, string? SetId = null, string? SetName = null, string? Via = null, string? TeamId = null, string? TeamName = null)
{
    /// <summary>The label shown to people, e.g. "Admin permissions (via Ops team)".</summary>
    public string Label => Kind switch
    {
        "owner" => "Organization owner",
        "member_default" => SetName ?? "Member permissions",
        "admin_default" => Via == "role" ? $"{SetName} (admin role)" : $"{SetName} (via {TeamName ?? "an admin"} team)",
        _ => $"{SetName} (via {TeamName} team)",
    };
}

public sealed record PermissionGrant(PermissionSource Source, IReadOnlySet<string> Keys);

public sealed record TeamRef(string Id, string Name);

/// <summary>What one person may do in one workspace: the union of everything granted to them.</summary>
public sealed class MemberPermissions
{
    public required bool IsOwner { get; init; }
    /// <summary>A direct admin role, or membership of an Admin team. The owner is not counted here: the owner bypasses every check.</summary>
    public required bool IsAdmin { get; init; }
    public required bool IsDirectAdmin { get; init; }
    public required IReadOnlySet<string> Keys { get; init; }
    public required IReadOnlyList<PermissionGrant> Grants { get; init; }
    public required IReadOnlyList<TeamRef> AdminTeams { get; init; }

    public bool Has(string key) => IsOwner || Keys.Contains(key);

    /// <summary>Each permission held with every source that grants it, sorted by key.</summary>
    public IReadOnlyList<(string Key, IReadOnlyList<PermissionSource> Sources)> Explain() =>
        Keys.Order(StringComparer.Ordinal)
            .Select(key => (key, (IReadOnlyList<PermissionSource>)Grants.Where(g => g.Keys.Contains(key)).Select(g => g.Source).ToList()))
            .ToList();
}

public sealed record KeyState(string Status, PermissionSetPermission Row);

/// <summary>Teams' permission sets: seeding the built-in ones, reading what a set allows, and working out what a person holds.</summary>
public sealed class PermissionService(DenDbContext db)
{
    public const string Allow = "allow";
    public const string Deny = "deny";
    public const string MemberSetName = "Member permissions";
    public const string AdminSetName = "Admin permissions";

    private static readonly IReadOnlySet<string> AllKeys = PermissionCatalog.All.Select(p => p.Key).ToHashSet();

    /// <summary>The workspace's Member and Admin sets, created (with the reference's default keys) the first time they are needed.</summary>
    public async Task<(PermissionSet Member, PermissionSet Admin)> EnsureDefaultSetsAsync(string organizationId)
    {
        var existing = await db.PermissionSets.AsNoTracking().Where(s => s.OrganizationId == organizationId && s.DefaultKey != null).ToListAsync();
        var member = existing.FirstOrDefault(s => s.DefaultKey == "member");
        var admin = existing.FirstOrDefault(s => s.DefaultKey == "admin");
        if (member is not null && admin is not null) return (member, admin);

        var now = DateTime.UtcNow;
        var added = new List<object>();
        if (member is null) { member = NewSet(organizationId, "member", MemberSetName, now); Seed(member, PermissionCatalog.All.Where(p => p.MemberDefault).Select(p => p.Key), now, added); }
        if (admin is null) { admin = NewSet(organizationId, "admin", AdminSetName, now); Seed(admin, PermissionCatalog.All.Where(p => p.AdminDefault).Select(p => p.Key), now, added); }
        try
        {
            await db.SaveChangesAsync();
            return (member, admin);
        }
        catch (DbUpdateException)
        {
            // Another request created them first (the unique index says only one may exist): use theirs.
            foreach (var entity in added) db.Entry(entity).State = EntityState.Detached;
            var winners = await db.PermissionSets.AsNoTracking().Where(s => s.OrganizationId == organizationId && s.DefaultKey != null).ToListAsync();
            return (winners.First(s => s.DefaultKey == "member"), winners.First(s => s.DefaultKey == "admin"));
        }

        PermissionSet NewSet(string org, string key, string name, DateTime at) => new() { Id = Ids.New("pms"), OrganizationId = org, DefaultKey = key, Name = name, CreatedAt = at };
    }

    private void Seed(PermissionSet set, IEnumerable<string> keys, DateTime now, List<object> added)
    {
        db.PermissionSets.Add(set);
        added.Add(set);
        foreach (var key in keys)
        {
            var row = new PermissionSetPermission { Id = Ids.New("psp"), PermissionSetId = set.Id, PermissionKey = key, Status = Allow, Source = "seed", CreatedAt = now };
            db.PermissionSetPermissions.Add(row);
            added.Add(row);
        }
    }

    /// <summary>What each key is set to in each set: the newest recorded decision per key. A key with no row is denied.</summary>
    public async Task<Dictionary<string, Dictionary<string, KeyState>>> ReadStatesAsync(IReadOnlyCollection<string> setIds)
    {
        var result = setIds.ToDictionary(id => id, _ => new Dictionary<string, KeyState>());
        if (setIds.Count == 0) return result;
        var rows = await db.PermissionSetPermissions.AsNoTracking().Where(r => setIds.Contains(r.PermissionSetId)).ToListAsync();
        foreach (var row in rows)
        {
            var states = result[row.PermissionSetId];
            if (!states.TryGetValue(row.PermissionKey, out var current) || IsNewer(row, current.Row)) states[row.PermissionKey] = new KeyState(row.Status, row);
        }
        return result;
    }

    private static bool IsNewer(PermissionSetPermission row, PermissionSetPermission than) =>
        row.CreatedAt > than.CreatedAt || (row.CreatedAt == than.CreatedAt && string.CompareOrdinal(row.Id, than.Id) > 0);

    /// <summary>The catalog keys a set allows.</summary>
    public static HashSet<string> AllowedKeys(IReadOnlyDictionary<string, KeyState>? states) =>
        states is null ? [] : states.Where(s => s.Value.Status == Allow && AllKeys.Contains(s.Key)).Select(s => s.Key).ToHashSet();

    /// <summary>Records changes as new rows (never edits old ones), each strictly newer than anything already recorded for the set.</summary>
    public async Task AddRowsAsync(string setId, IEnumerable<PermissionChange> changes, string source, string? actorMemberId)
    {
        var latest = await db.PermissionSetPermissions.Where(r => r.PermissionSetId == setId).Select(r => (DateTime?)r.CreatedAt).MaxAsync();
        var at = DateTime.UtcNow;
        if (latest is { } l && at <= l) at = l.AddMilliseconds(1);
        foreach (var change in changes)
            db.PermissionSetPermissions.Add(new PermissionSetPermission { Id = Ids.New("psp"), PermissionSetId = setId, PermissionKey = change.Key, Status = change.Status, Source = source, ChangedByMemberId = actorMemberId, CreatedAt = at });
    }

    public async Task<MemberPermissions> ResolveAsync(string organizationId, Member member)
    {
        var teams = await (from tm in db.TeamMembers.AsNoTracking()
                           join t in db.Teams.AsNoTracking() on tm.TeamId equals t.Id
                           where tm.MemberId == member.Id && t.OrganizationId == organizationId
                           orderby t.Name
                           select t).ToListAsync();
        var adminTeams = teams.Where(t => t.GrantsOrganizationAdmin).Select(t => new TeamRef(t.Id, t.Name)).ToList();
        var directAdmin = member.Role == Roles.Admin;
        var isAdmin = directAdmin || adminTeams.Count > 0;

        if (member.Role == Roles.Owner)
            return new MemberPermissions { IsOwner = true, IsAdmin = isAdmin, IsDirectAdmin = false, Keys = AllKeys, AdminTeams = adminTeams, Grants = [new PermissionGrant(new PermissionSource("owner"), AllKeys)] };

        var (memberSet, adminSet) = await EnsureDefaultSetsAsync(organizationId);
        var teamIds = teams.Select(t => t.Id).ToList();
        var teamSets = await (from l in db.PermissionSetTeams.AsNoTracking()
                              join s in db.PermissionSets.AsNoTracking() on l.PermissionSetId equals s.Id
                              where l.RemovedAt == null && s.ArchivedAt == null && teamIds.Contains(l.TeamId)
                              orderby s.Name, l.TeamId
                              select new { l.TeamId, Set = s }).ToListAsync();

        var setIds = new List<string> { memberSet.Id };
        if (isAdmin) setIds.Add(adminSet.Id);
        setIds.AddRange(teamSets.Select(t => t.Set.Id));
        var states = await ReadStatesAsync(setIds.Distinct().ToList());

        // Order matters for explanations: the Member set, the Admin set (by role, then by Admin team), then team roles.
        var grants = new List<PermissionGrant> { new(new PermissionSource("member_default", memberSet.Id, memberSet.Name), AllowedKeys(states[memberSet.Id])) };
        if (isAdmin)
        {
            var adminKeys = AllowedKeys(states[adminSet.Id]);
            if (directAdmin) grants.Add(new PermissionGrant(new PermissionSource("admin_default", adminSet.Id, adminSet.Name, "role"), adminKeys));
            foreach (var team in adminTeams) grants.Add(new PermissionGrant(new PermissionSource("admin_default", adminSet.Id, adminSet.Name, "team", team.Id, team.Name), adminKeys));
        }
        foreach (var entry in teamSets)
        {
            var team = teams.First(t => t.Id == entry.TeamId);
            grants.Add(new PermissionGrant(new PermissionSource("team", entry.Set.Id, entry.Set.Name, null, team.Id, team.Name), AllowedKeys(states[entry.Set.Id])));
        }
        return new MemberPermissions { IsOwner = false, IsAdmin = isAdmin, IsDirectAdmin = directAdmin, Keys = grants.SelectMany(g => g.Keys).ToHashSet(), Grants = grants, AdminTeams = adminTeams };
    }

    /// <summary>The keys the Admin set allows: what making someone an admin (or a team an Admin team) hands out.</summary>
    public async Task<HashSet<string>> AdminDefaultKeysAsync(string organizationId)
    {
        var (_, admin) = await EnsureDefaultSetsAsync(organizationId);
        return AllowedKeys((await ReadStatesAsync([admin.Id]))[admin.Id]);
    }

    /// <summary>The keys the team's active role allows (not the Admin set).</summary>
    public async Task<HashSet<string>> TeamRoleKeysAsync(string teamId)
    {
        var setIds = await (from l in db.PermissionSetTeams.AsNoTracking()
                            join s in db.PermissionSets.AsNoTracking() on l.PermissionSetId equals s.Id
                            where l.TeamId == teamId && l.RemovedAt == null && s.ArchivedAt == null
                            select s.Id).ToListAsync();
        var states = await ReadStatesAsync(setIds);
        return setIds.SelectMany(id => AllowedKeys(states[id])).ToHashSet();
    }
}

public sealed record PermissionChange(string Key, string Status);

public sealed record EditProblem(string Error, IReadOnlyList<string> Keys)
{
    /// <summary>Missing permissions and non-admins are "forbidden" (403); invalid requests are 400.</summary>
    public int StatusCode => Error is "permission_not_held" or "admin_permissions_require_admin" ? 403 : 400;

    public string Message
    {
        get
        {
            var keys = string.Join(", ", Keys);
            return Error switch
            {
                "unknown_permission" => $"These permissions don't exist: {keys}.",
                "duplicate_permission" => $"Each permission can appear only once. Listed more than once: {keys}.",
                "admin_permissions_require_admin" => "Only the owner and admins can change Admin permissions.",
                "permission_locked" => $"These permissions are always on for admins, so admins can't be locked out of managing permissions: {keys}.",
                _ => $"You can only turn on permissions you have yourself. You don't have: {keys}.",
            };
        }
    }
}

public sealed record EditPlan(IReadOnlyList<PermissionChange> Changes, EditProblem? Problem)
{
    public bool Ok => Problem is null;
}

/// <summary>The rules for changing what a set allows (ported from the reference): who may turn on what, and what can never be turned off.</summary>
public static class PermissionEdits
{
    public static EditPlan PlanEdit(string? defaultKey, IReadOnlyDictionary<string, KeyState> current, IReadOnlyList<(string Key, string Status)> requested, MemberPermissions editor)
    {
        var validated = Validate(requested);
        if (validated.Problem is not null) return validated;

        if (defaultKey == "admin" && !editor.IsOwner && !editor.IsAdmin)
            return Fail("admin_permissions_require_admin", validated.Changes.Select(c => c.Key));

        // Denying a key that must stay on for admins would let admins lock themselves out.
        var locked = defaultKey == "admin"
            ? validated.Changes.Where(c => c.Status == PermissionService.Deny && IsLocked(c.Key)).Select(c => c.Key).ToList()
            : [];
        if (locked.Count > 0) return Fail("permission_locked", locked);

        var changes = validated.Changes.Where(c => StatusOf(current, c.Key) != c.Status).ToList();
        // Re-allowing a key the set shipped with restores a default and needs nothing; turning on anything else needs the editor to hold it.
        var turningOn = changes.Where(c => c.Status == PermissionService.Allow && !IsShippedDefault(c.Key, defaultKey)).Select(c => c.Key);
        var missing = NotHeld(editor, turningOn);
        if (missing.Count > 0) return Fail("permission_not_held", missing);
        return new EditPlan(changes, null);
    }

    public static EditPlan PlanCreate(IReadOnlyList<(string Key, string Status)> permissions, MemberPermissions editor)
    {
        var validated = Validate(permissions);
        if (validated.Problem is not null) return validated;
        var allowed = validated.Changes.Where(c => c.Status == PermissionService.Allow).ToList();
        var missing = NotHeld(editor, allowed.Select(c => c.Key));
        return missing.Count > 0 ? Fail("permission_not_held", missing) : new EditPlan(allowed, null);
    }

    private static EditPlan Validate(IReadOnlyList<(string Key, string Status)> requested)
    {
        var unknown = requested.Select(r => r.Key).Where(k => !PermissionCatalog.All.Any(p => p.Key == k)).ToList();
        if (unknown.Count > 0) return Fail("unknown_permission", unknown);
        var duplicates = requested.GroupBy(r => r.Key).Where(g => g.Count() > 1).Select(g => g.Key).ToList();
        if (duplicates.Count > 0) return Fail("duplicate_permission", duplicates);
        return new EditPlan(requested.Select(r => new PermissionChange(r.Key, r.Status)).ToList(), null);
    }

    private static EditPlan Fail(string error, IEnumerable<string> keys) =>
        new([], new EditProblem(error, keys.Distinct().Order(StringComparer.Ordinal).ToList()));

    private static List<string> NotHeld(MemberPermissions editor, IEnumerable<string> keys) =>
        editor.IsOwner ? [] : keys.Distinct().Where(k => !editor.Has(k)).Order(StringComparer.Ordinal).ToList();

    private static bool IsLocked(string key) => PermissionCatalog.All.First(p => p.Key == key).LockedOnAdmin;

    private static bool IsShippedDefault(string key, string? defaultKey) =>
        defaultKey is not null && PermissionCatalog.All.First(p => p.Key == key) is var d && (defaultKey == "admin" ? d.AdminDefault : d.MemberDefault);

    public static string StatusOf(IReadOnlyDictionary<string, KeyState> current, string key) =>
        current.TryGetValue(key, out var s) && s.Status == PermissionService.Allow ? PermissionService.Allow : PermissionService.Deny;

    /// <summary>The name of a team's own role, fixed from then on: "{team} Permissions".</summary>
    public static string TeamSetName(string teamName)
    {
        const string suffix = " Permissions";
        var name = teamName.Trim();
        return (name.Length > 255 - suffix.Length ? name[..(255 - suffix.Length)] : name) + suffix;
    }
}
