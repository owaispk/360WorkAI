using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Library;

namespace WorkAI360.Api.Features.Library;

public sealed record EffectiveAccess(Plugin Plugin, int ComponentCount, List<string> ComponentKinds, List<object> Edges, LibRole Role);

/// <summary>What each person can use through which door (my library, a team's plugins), and how much the library is used.</summary>
public sealed class LibraryUsage(DenDbContext db)
{
    public static readonly string[] Kinds = ["skills", "plugins", "connectors"];
    private static readonly string[] Dimensions = ["item", "member", "day"];
    private static readonly string[] DayChoices = ["7", "30", "90"];

    // ---------- who can use what ----------

    private static readonly Dictionary<string, int> EdgeOrder = new() { ["mine"] = 1, ["person"] = 2, ["team"] = 3, ["org_wide"] = 4, ["catalog"] = 5 };

    private static bool Applies(LibraryGrant g, Actor a) => g.OrgWide || g.MemberId == a.MemberId || (g.TeamId is not null && a.TeamIds.Contains(g.TeamId));

    private async Task<Dictionary<string, string>> NamesAsync(string orgId, IReadOnlyCollection<string> memberIds) =>
        memberIds.Count == 0 ? [] : (await (from m in db.Members.AsNoTracking()
                                            join u in db.Users.AsNoTracking() on m.UserId equals u.Id
                                            where m.OrganizationId == orgId && memberIds.Contains(m.Id)
                                            select new { m.Id, u.Name }).ToListAsync()).ToDictionary(x => x.Id, x => x.Name);

    /// <summary>Every active plugin the person can use, with each door it came through (made it, shared with them, their team, everyone, a marketplace).</summary>
    public async Task<List<EffectiveAccess>> EffectiveAccessAsync(Actor a)
    {
        var plugins = await db.Set<Plugin>().AsNoTracking().Where(p => p.OrganizationId == a.OrgId && p.Status == "active" && p.DeletedAt == null).ToListAsync();
        if (plugins.Count == 0) return [];
        var ids = plugins.Select(p => p.Id).ToList();
        var pluginGrants = (await db.Set<LibraryGrant>().AsNoTracking().Where(g => g.OrganizationId == a.OrgId && g.ResourceKind == GrantKinds.Plugin && ids.Contains(g.ResourceId) && g.RemovedAt == null).ToListAsync())
            .Where(g => Applies(g, a)).OrderBy(g => g.CreatedAt).ThenBy(g => g.Id, StringComparer.Ordinal).ToList();
        var memberships = await (from mp in db.Set<MarketplacePlugin>().AsNoTracking()
                                 join m in db.Set<Marketplace>().AsNoTracking() on mp.MarketplaceId equals m.Id
                                 where mp.OrganizationId == a.OrgId && ids.Contains(mp.PluginId) && mp.RemovedAt == null && m.OrganizationId == a.OrgId && m.Status == "active" && m.DeletedAt == null
                                 select new { mp.PluginId, MarketplaceId = m.Id, MarketplaceName = m.Name }).ToListAsync();
        var marketGrants = (await db.Set<LibraryGrant>().AsNoTracking().Where(g => g.OrganizationId == a.OrgId && g.ResourceKind == GrantKinds.Marketplace && g.RemovedAt == null).ToListAsync())
            .Where(g => Applies(g, a)).ToLookup(g => g.ResourceId);
        var components = (await (from m in db.Set<PluginConfigObject>().AsNoTracking()
                                 join o in db.Set<ConfigObject>().AsNoTracking() on m.ConfigObjectId equals o.Id
                                 where m.OrganizationId == a.OrgId && ids.Contains(m.PluginId) && m.RemovedAt == null
                                 select new { m.PluginId, o.ObjectType }).ToListAsync()).GroupBy(x => x.PluginId).ToDictionary(g => g.Key, g => (Count: g.Count(), Kinds: g.Select(x => x.ObjectType).Distinct().Order(StringComparer.Ordinal).ToList()));
        var creators = await NamesAsync(a.OrgId, pluginGrants.Where(g => g.MemberId == a.MemberId).Select(g => g.CreatedByMemberId).Distinct().ToList());
        var teams = await db.Teams.AsNoTracking().Where(t => t.OrganizationId == a.OrgId && a.TeamIds.Contains(t.Id)).ToDictionaryAsync(t => t.Id, t => t.Name);

        var candidates = new Dictionary<string, Dictionary<string, (string Kind, string Key, object Edge, LibRole Role)>>();
        void Add(string pluginId, string kind, string key, object edge, LibRole role)
        {
            if (!candidates.TryGetValue(pluginId, out var map)) candidates[pluginId] = map = [];
            if (!map.TryGetValue(key, out var current) || role > current.Role) map[key] = (kind, key, edge, role);
        }
        foreach (var p in plugins) if (p.CreatedByMemberId == a.MemberId) Add(p.Id, "mine", "mine", new { kind = "mine" }, LibRole.Manager);
        foreach (var g in pluginGrants)
        {
            var role = RoleNames.Parse(g.Role)!.Value;
            if (g.MemberId == a.MemberId)
                Add(g.ResourceId, "person", "person", new { kind = "person", sharedBy = creators.TryGetValue(g.CreatedByMemberId, out var n) ? new { orgMembershipId = g.CreatedByMemberId, name = n } : null, grantedAt = Responses.IsoUtc(g.CreatedAt) }, role);
            if (g.TeamId is not null && teams.TryGetValue(g.TeamId, out var teamName))
                Add(g.ResourceId, "team", "team:" + g.TeamId, new { kind = "team", team = new { id = g.TeamId, name = teamName } }, role);
            if (g.OrgWide) Add(g.ResourceId, "org_wide", "org_wide", new { kind = "org_wide" }, role);
        }
        foreach (var m in memberships)
            if (marketGrants[m.MarketplaceId].Any())
                Add(m.PluginId, "catalog", "catalog:" + m.MarketplaceId, new { kind = "catalog", marketplace = new { id = m.MarketplaceId, name = m.MarketplaceName } }, LibRole.Viewer);

        var result = new List<EffectiveAccess>();
        foreach (var p in plugins)
        {
            if (!candidates.TryGetValue(p.Id, out var map)) continue;
            var ordered = map.Values.OrderBy(c => EdgeOrder[c.Kind]).ThenBy(c => c.Key, StringComparer.Ordinal).ToList();
            var (count, kinds) = components.GetValueOrDefault(p.Id, (0, []));
            result.Add(new EffectiveAccess(p, count, kinds, ordered.Select(c => c.Edge).ToList(), ordered.Max(c => c.Role)));
        }
        return result.OrderBy(r => r.Plugin.Name, StringComparer.InvariantCultureIgnoreCase).ThenBy(r => r.Plugin.Id, StringComparer.Ordinal).ToList();
    }

    /// <summary>The plugins a team can use, and the door each came through. Only people in the team, and those who can view any team, may look.</summary>
    public async Task<List<object>> TeamAccessAsync(Actor a, string teamId)
    {
        if (!await db.Teams.AsNoTracking().AnyAsync(t => t.OrganizationId == a.OrgId && t.Id == teamId)) throw new LibraryFailure(404, "team_not_found", "Team not found.");
        if (!a.TeamIds.Contains(teamId) && !a.Has("teams.view")) throw new LibraryForbidden("Only organization admins and team members can view this team's plugin access.");

        var live = db.Set<Plugin>().AsNoTracking().Where(p => p.OrganizationId == a.OrgId && p.Status == "active" && p.DeletedAt == null);
        var direct = await (from g in db.Set<LibraryGrant>().AsNoTracking()
                            join p in live on g.ResourceId equals p.Id
                            where g.OrganizationId == a.OrgId && g.ResourceKind == GrantKinds.Plugin && g.TeamId == teamId && g.RemovedAt == null
                            select new { g.CreatedAt, g.CreatedByMemberId, GrantId = g.Id, PluginId = p.Id, PluginName = p.Name, g.Role }).ToListAsync();
        var catalog = await (from g in db.Set<LibraryGrant>().AsNoTracking()
                             join m in db.Set<Marketplace>().AsNoTracking() on g.ResourceId equals m.Id
                             join mp in db.Set<MarketplacePlugin>().AsNoTracking() on m.Id equals mp.MarketplaceId
                             join p in live on mp.PluginId equals p.Id
                             where g.OrganizationId == a.OrgId && g.ResourceKind == GrantKinds.Marketplace && g.TeamId == teamId && g.RemovedAt == null
                                   && m.OrganizationId == a.OrgId && m.Status == "active" && m.DeletedAt == null && mp.RemovedAt == null
                             select new { g.CreatedAt, g.CreatedByMemberId, MarketplaceId = m.Id, MarketplaceName = m.Name, PluginId = p.Id, PluginName = p.Name, g.Role }).ToListAsync();
        var orgWide = await (from g in db.Set<LibraryGrant>().AsNoTracking()
                             join p in live on g.ResourceId equals p.Id
                             where g.OrganizationId == a.OrgId && g.ResourceKind == GrantKinds.Plugin && g.OrgWide && g.RemovedAt == null
                             select new { g.CreatedAt, g.CreatedByMemberId, PluginId = p.Id, PluginName = p.Name, g.Role }).ToListAsync();

        var candidates = new List<(string Edge, string PluginId, string PluginName, LibRole Role, DateTime At, string By, string? GrantId, string? MarketId, string? MarketName)>();
        candidates.AddRange(direct.Select(r => ("direct_team", r.PluginId, r.PluginName, RoleNames.Parse(r.Role)!.Value, r.CreatedAt, r.CreatedByMemberId, (string?)r.GrantId, (string?)null, (string?)null)));
        candidates.AddRange(catalog.Select(r => ("via_catalog", r.PluginId, r.PluginName, RoleNames.Parse(r.Role)!.Value, r.CreatedAt, r.CreatedByMemberId, (string?)null, (string?)r.MarketplaceId, (string?)r.MarketplaceName)));
        candidates.AddRange(orgWide.Select(r => ("org_wide", r.PluginId, r.PluginName, RoleNames.Parse(r.Role)!.Value, r.CreatedAt, r.CreatedByMemberId, (string?)null, (string?)null, (string?)null)));
        var best = candidates.GroupBy(c => (c.PluginId, c.Edge)).Select(g => g.OrderByDescending(c => c.Role).First()).ToList();

        var pluginIds = best.Select(c => c.PluginId).Distinct().ToList();
        var counts = (await db.Set<PluginConfigObject>().AsNoTracking().Where(m => m.OrganizationId == a.OrgId && pluginIds.Contains(m.PluginId) && m.RemovedAt == null).GroupBy(m => m.PluginId).Select(g => new { g.Key, N = g.Count() }).ToListAsync()).ToDictionary(x => x.Key, x => x.N);
        var names = await NamesAsync(a.OrgId, best.Select(c => c.By).Distinct().ToList());
        var edgeOrder = new Dictionary<string, int> { ["direct_team"] = 1, ["via_catalog"] = 2, ["org_wide"] = 3 };
        return best.OrderBy(c => c.PluginName, StringComparer.InvariantCultureIgnoreCase).ThenBy(c => edgeOrder[c.Edge]).ThenBy(c => c.PluginId, StringComparer.Ordinal)
            .Select(c => (object)new
            {
                plugin = new { id = c.PluginId, name = c.PluginName, componentCount = counts.GetValueOrDefault(c.PluginId) },
                edge = c.Edge,
                marketplace = c.MarketId is null ? null : new { id = c.MarketId, name = c.MarketName },
                role = RoleNames.Name(c.Role),
                grantedBy = names.TryGetValue(c.By, out var n) ? new { orgMembershipId = c.By, name = n } : null,
                grantedAt = Responses.IsoUtc(c.At),
                grantId = c.GrantId,
            }).ToList();
    }

    // ---------- usage ----------

    public static int Days(HttpContext ctx)
    {
        if (!ctx.Request.Query.ContainsKey("days")) return 30;
        var raw = ctx.Request.Query["days"].ToString();
        if (!DayChoices.Contains(raw)) throw new Invalid("days", "Invalid option: expected one of \"7\"|\"30\"|\"90\"", "invalid_value");
        return int.Parse(raw);
    }

    private static DateTime WindowStart(int days)
    {
        var today = DateTime.UtcNow.Date;
        return DateTime.SpecifyKind(today.AddDays(-(days - 1)), DateTimeKind.Utc);
    }

    /// <summary>Records that a skill's text was served to a person's agent. Ids only.</summary>
    public async Task RecordSkillUseAsync(string orgId, string memberId, string pluginId, string configObjectId, string source = "agent")
    {
        db.Add(new LibraryUsageEvent { Id = Ids.New("cue"), OrganizationId = orgId, MemberId = memberId, PluginId = pluginId, ConfigObjectId = configObjectId, Source = source, CreatedAt = LibraryStore.Now() });
        await db.SaveChangesAsync();
    }

    private async Task<DateTime?> TrackingSinceAsync(string orgId) =>
        await db.Set<LibraryUsageEvent>().AsNoTracking().Where(e => e.OrganizationId == orgId).OrderBy(e => e.CreatedAt).Select(e => (DateTime?)e.CreatedAt).FirstOrDefaultAsync();

    private async Task<List<LibraryUsageEvent>> EventsAsync(string orgId, int days)
    {
        var from = WindowStart(days);
        return await db.Set<LibraryUsageEvent>().AsNoTracking().Where(e => e.OrganizationId == orgId && e.CreatedAt >= from).ToListAsync();
    }

    public async Task<object> ReportAsync(Actor a, string kind, int days)
    {
        var events = await EventsAsync(a.OrgId, days);
        var tracking = await TrackingSinceAsync(a.OrgId);
        var items = new List<(string Id, string Name, string? Detail, string? PluginId, bool Failures)>();
        if (kind == "skills")
        {
            var rows = await (from m in db.Set<PluginConfigObject>().AsNoTracking()
                              join p in db.Set<Plugin>().AsNoTracking() on m.PluginId equals p.Id
                              join o in db.Set<ConfigObject>().AsNoTracking() on m.ConfigObjectId equals o.Id
                              where m.OrganizationId == a.OrgId && m.RemovedAt == null && p.Status == "active" && p.DeletedAt == null && o.ObjectType == "skill" && o.Status == "active" && o.DeletedAt == null
                              select new { SkillId = o.Id, SkillName = o.Title, PluginId = p.Id, PluginName = p.Name }).ToListAsync();
            // A skill can sit in several plugins; list it once, under the first plugin by name.
            foreach (var r in rows.OrderBy(r => r.PluginName, StringComparer.InvariantCultureIgnoreCase))
                if (!items.Any(i => i.Id == r.SkillId)) items.Add((r.SkillId, r.SkillName, r.PluginName, r.PluginId, false));
        }
        else if (kind == "plugins")
        {
            var plugins = await db.Set<Plugin>().AsNoTracking().Where(p => p.OrganizationId == a.OrgId && p.Status == "active" && p.DeletedAt == null).ToListAsync();
            var skillCounts = (await (from m in db.Set<PluginConfigObject>().AsNoTracking()
                                      join o in db.Set<ConfigObject>().AsNoTracking() on m.ConfigObjectId equals o.Id
                                      where m.OrganizationId == a.OrgId && m.RemovedAt == null && o.ObjectType == "skill" && o.Status == "active" && o.DeletedAt == null
                                      select m.PluginId).ToListAsync()).GroupBy(x => x).ToDictionary(g => g.Key, g => g.Count());
            foreach (var p in plugins)
            {
                var n = skillCounts.GetValueOrDefault(p.Id);
                items.Add((p.Id, p.Name, n > 0 ? $"{n} {(n == 1 ? "skill" : "skills")}" : null, null, true));
            }
        }
        var key = kind == "skills" ? (Func<LibraryUsageEvent, string>)(e => e.ConfigObjectId) : e => e.PluginId;
        var totals = kind == "connectors" ? [] : events.GroupBy(key).ToDictionary(g => g.Key, g => (Uses: g.Count(), People: g.Select(e => e.MemberId).Distinct().Count(), Last: g.Max(e => e.CreatedAt)));
        var rowsOut = items.Select(i =>
        {
            var t = totals.GetValueOrDefault(i.Id);
            return new { id = i.Id, name = i.Name, detail = i.Detail, pluginId = i.PluginId, uses = t.Uses, people = t.People, failures = i.Failures ? (int?)0 : null, lastUsedAt = t.Uses > 0 ? Responses.IsoUtc(t.Last) : null };
        }).OrderByDescending(r => r.uses).ThenByDescending(r => r.people).ThenBy(r => r.name, StringComparer.InvariantCultureIgnoreCase).ToList();
        return new { kind, days, trackingSince = tracking is null ? null : Responses.IsoUtc(tracking.Value), items = rowsOut };
    }

    private static readonly string[] BreakdownKeys = ["kind", "days", "groupBy", "memberId", "teamId", "itemId"];

    public async Task<IResult> BreakdownAsync(Actor a, HttpContext ctx)
    {
        foreach (var key in ctx.Request.Query.Keys)
            if (!BreakdownKeys.Contains(key)) throw new Invalid(new[] { (Array.Empty<string>(), "unrecognized_keys", $"Unrecognized key: \"{key}\"") });
        if (!ctx.Request.Query.ContainsKey("kind")) throw new Invalid("kind", "Invalid input: expected string, received undefined");
        var kind = Zod.QueryEnum(ctx, "kind", Kinds)!;
        var days = Days(ctx);
        var groupBy = (ctx.Request.Query.ContainsKey("groupBy") ? ctx.Request.Query["groupBy"].ToString() : "item").Split(',').Select(s => s.Trim()).Where(s => s.Length > 0).Distinct().ToList();
        if (groupBy.Count < 1) throw new Invalid("groupBy", "Too small: expected array to have >=1 items", "too_small");
        foreach (var g in groupBy) if (!Dimensions.Contains(g)) throw new Invalid("groupBy.0", $"Invalid option: expected one of {string.Join("|", Dimensions.Select(d => $"\"{d}\""))}", "invalid_value");
        var memberId = ctx.Request.Query["memberId"].ToString();
        var teamId = ctx.Request.Query["teamId"].ToString();
        var itemId = ctx.Request.Query["itemId"].ToString();
        if (memberId.Length > 0) Zod.TypeId(memberId, "om", "memberId");
        if (teamId.Length > 0) Zod.TypeId(teamId, "tem", "teamId");
        if (memberId.Length > 0 && teamId.Length > 0) throw new Invalid("teamId", "Filter by memberId or teamId, not both.", "custom");

        HashSet<string>? members = memberId.Length > 0 ? [memberId] : null;
        if (teamId.Length > 0)
        {
            if (!await db.Teams.AsNoTracking().AnyAsync(t => t.OrganizationId == a.OrgId && t.Id == teamId)) return Results.Json(new { error = "not_found", message = "No such team in this organization." }, statusCode: 404);
            members = (await db.TeamMembers.AsNoTracking().Where(t => t.TeamId == teamId).Select(t => t.MemberId).ToListAsync()).ToHashSet();
        }
        var from = WindowStart(days);
        var events = kind == "connectors" ? [] : (await EventsAsync(a.OrgId, days)).Where(e => (members is null || members.Contains(e.MemberId)) && (itemId.Length == 0 || (kind == "skills" ? e.ConfigObjectId : e.PluginId) == itemId)).ToList();
        var byItem = groupBy.Contains("item"); var byMember = groupBy.Contains("member"); var byDay = groupBy.Contains("day");
        var rows = events.GroupBy(e => (Item: byItem ? (kind == "skills" ? e.ConfigObjectId : e.PluginId) : null, Member: byMember ? e.MemberId : null, Day: byDay ? e.CreatedAt.ToString("yyyy-MM-dd") : null))
            .Select(g => new
            {
                itemId = g.Key.Item,
                memberId = g.Key.Member,
                date = g.Key.Day,
                uses = g.Count(),
                people = g.Select(e => e.MemberId).Distinct().Count(),
                failures = kind == "skills" ? (int?)null : 0,
                lastUsedAt = (string?)Responses.IsoUtc(g.Max(e => e.CreatedAt)),
                sources = g.GroupBy(e => e.Source).ToDictionary(s => s.Key, s => s.Count()),
            })
            .OrderBy(r => byDay ? r.date : "", StringComparer.Ordinal).ThenByDescending(r => r.uses).ToList();
        var tracking = await TrackingSinceAsync(a.OrgId);
        return Results.Json(new
        {
            kind, days, from = from.ToString("yyyy-MM-dd"), to = DateTime.UtcNow.ToString("yyyy-MM-dd"), timezone = "UTC", groupBy,
            trackingSince = tracking is null ? null : Responses.IsoUtc(tracking.Value), rows,
        });
    }
}
