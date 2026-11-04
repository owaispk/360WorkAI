using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Connections;
using WorkAI360.Api.Domain.Gateway;
using WorkAI360.Api.Domain.Library;
using WorkAI360.Api.Domain.LlmProviders;
using WorkAI360.Api.Features.Gateway;
using WorkAI360.Api.Features.Library;

namespace WorkAI360.Api.Features.OrgAdmin;

/// <summary>One entry of the admin dashboard's Activity panel (the reference's <c>DashboardActivityEntry</c>).</summary>
public sealed record ActivityEntry(string Id, string Kind, string Title, string Detail, DateTime OccurredAt, Dictionary<string, object?> Target, Dictionary<string, object?>? Logo);

/// <summary>
/// The admin dashboard's Activity panel (the reference's <c>dashboard-activity.ts</c>): the workspace's five newest additions, newest first, ties by
/// entry id. A snapshot of what exists, not an audit log: only stored creation dates count, and removed or archived things contribute nothing. Each
/// source follows the permission of its own admin list.
/// </summary>
public sealed class DashboardActivity(DenDbContext db, LibraryAccess library, IOptions<GatewayOptions> gateway)
{
    public const int Limit = 5;

    public async Task<List<ActivityEntry>> ReadAsync(OrgContext c)
    {
        var orgId = c.Organization.Id;
        var entries = new List<ActivityEntry>();

        // Connections (View all connections). A connection a plugin set up for itself counts only while that plugin is active.
        if (c.Permissions.Has("connections.view"))
        {
            var connections = await db.Set<ExternalMcpConnection>().AsNoTracking()
                .Where(x => x.OrganizationId == orgId)
                .Where(x => !db.Set<Domain.PluginConnections.PluginMcpBinding>().Any(b => b.OrganizationId == orgId && b.ConnectionId == x.Id && b.ConnectionOwnedByPlugin)
                    || db.Set<Domain.PluginConnections.PluginMcpBinding>().Any(b => b.OrganizationId == orgId && b.ConnectionId == x.Id && b.ConnectionOwnedByPlugin
                        && db.Set<Plugin>().Any(p => p.Id == b.PluginId && p.Status == "active" && p.DeletedAt == null)))
                .OrderByDescending(x => x.CreatedAt).ThenBy(x => x.Id).Take(Limit)
                .Select(x => new { x.Id, x.Name, x.Url, x.CreatedAt }).ToListAsync();
            foreach (var x in connections)
                entries.Add(new($"connection:{x.Id}", "connection", $"{x.Name} was added", "Connection", x.CreatedAt,
                    new() { ["type"] = "connection", ["connectionId"] = x.Id }, new() { ["name"] = x.Name, ["url"] = x.Url }));
        }

        // Model providers: all of them with View all providers, otherwise the ones this person added.
        var allProviders = c.Permissions.Has("llm_providers.view");
        var memberId = c.Member.Id;
        var providers = await db.Set<LlmProvider>().AsNoTracking()
            .Where(p => p.OrganizationId == orgId && (allProviders || p.CreatedByMemberId == memberId))
            .OrderByDescending(p => p.CreatedAt).ThenBy(p => p.Id).Take(Limit)
            .Select(p => new { p.Id, p.Name, p.ProviderId, p.CreatedAt }).ToListAsync();
        foreach (var p in providers)
            entries.Add(new($"provider:legacy:{p.Id}", "provider", $"{p.Name} was added", "Model provider", p.CreatedAt,
                new() { ["type"] = "llm_provider", ["llmProviderId"] = p.Id }, new() { ["name"] = p.Name, ["providerId"] = p.ProviderId }));

        // AI Gateway providers (View Gateway providers, on a deployment with Gateway management on).
        if (gateway.Value.Enabled && c.Permissions.Has("gateway_providers.view"))
        {
            var gatewayProviders = await db.Set<GatewayProvider>().AsNoTracking().Where(g => g.OrganizationId == orgId)
                .OrderByDescending(g => g.CreatedAt).ThenBy(g => g.Id).Take(Limit)
                .Select(g => new { g.Id, g.Name, g.ProviderId, g.CreatedAt }).ToListAsync();
            foreach (var g in gatewayProviders)
                entries.Add(new($"provider:gateway:{g.Id}", "provider", $"{g.Name} was added", "Model provider", g.CreatedAt,
                    new() { ["type"] = "gateway_provider", ["inferenceProviderId"] = g.Id }, new() { ["name"] = g.Name, ["providerId"] = g.ProviderId }));
        }

        // Plugins and skills: everything with Manage everything shared, otherwise what is shared with this person.
        var actor = new Actor(c, (await db.TeamMembers.AsNoTracking().Where(t => t.MemberId == memberId).Select(t => t.TeamId).ToListAsync()).ToHashSet());
        var activePluginIds = await db.Set<Plugin>().AsNoTracking().Where(p => p.OrganizationId == orgId && p.Status == "active" && p.DeletedAt == null).Select(p => p.Id).ToListAsync();
        var activeMarketplaceIds = await db.Set<Marketplace>().AsNoTracking().Where(m => m.OrganizationId == orgId && m.Status == "active" && m.DeletedAt == null).Select(m => m.Id).ToListAsync();
        var visiblePlugins = actor.ManageAll ? activePluginIds.ToHashSet() : (await library.PluginRolesAsync(actor.Aud, activePluginIds)).Keys.ToHashSet();
        var visibleMarketplaces = actor.ManageAll ? activeMarketplaceIds.ToHashSet() : (await library.MarketplaceRolesAsync(actor.Aud, activeMarketplaceIds)).Keys.ToHashSet();

        if (visiblePlugins.Count > 0 && visibleMarketplaces.Count > 0)
        {
            // Plugins added to an active marketplace; the built-in catalog is provisioned by a read, not new work, so it is left out.
            var attachments = await (from mp in db.Set<MarketplacePlugin>().AsNoTracking()
                                     join p in db.Set<Plugin>().AsNoTracking() on mp.PluginId equals p.Id
                                     join m in db.Set<Marketplace>().AsNoTracking() on mp.MarketplaceId equals m.Id
                                     where mp.OrganizationId == orgId && mp.RemovedAt == null && mp.MembershipSource != "system"
                                           && visiblePlugins.Contains(p.Id) && visibleMarketplaces.Contains(m.Id)
                                     orderby mp.CreatedAt descending, mp.Id
                                     select new { mp.Id, mp.CreatedAt, mp.PluginId, PluginName = p.Name, MarketplaceId = m.Id, MarketplaceName = m.Name }).Take(Limit).ToListAsync();
            var counts = await SkillCountsAsync(orgId, attachments.Select(a => a.PluginId).Distinct().ToList());
            foreach (var a in attachments)
            {
                var n = counts.GetValueOrDefault(a.PluginId);
                entries.Add(new($"plugin:{a.Id}", "plugin", $"{a.PluginName} was added to the {a.MarketplaceName} marketplace", $"Plugin with {n} {(n == 1 ? "skill" : "skills")}", a.CreatedAt,
                    new() { ["type"] = "marketplace", ["marketplaceId"] = a.MarketplaceId }, null));
            }
        }

        if (visiblePlugins.Count > 0)
        {
            // Published versions of active skills that sit in a visible active plugin; each names one parent (the most recently updated one).
            var versions = await (from v in db.Set<ConfigObjectVersion>().AsNoTracking()
                                  join o in db.Set<ConfigObject>().AsNoTracking() on v.ConfigObjectId equals o.Id
                                  where !v.IsDeletedVersion && o.OrganizationId == orgId && o.ObjectType == "skill" && o.Status == "active" && o.DeletedAt == null
                                        && db.Set<PluginConfigObject>().Any(pc => pc.ConfigObjectId == o.Id && pc.RemovedAt == null && visiblePlugins.Contains(pc.PluginId))
                                  orderby v.CreatedAt descending, v.Id
                                  select new { v.Id, v.CreatedAt, SkillId = o.Id, o.Title }).Take(Limit).ToListAsync();
            var skillIds = versions.Select(v => v.SkillId).Distinct().ToList();
            var parents = (await (from pc in db.Set<PluginConfigObject>().AsNoTracking()
                                  join p in db.Set<Plugin>().AsNoTracking() on pc.PluginId equals p.Id
                                  where skillIds.Contains(pc.ConfigObjectId) && pc.RemovedAt == null && visiblePlugins.Contains(p.Id)
                                  orderby p.UpdatedAt descending, p.Id descending
                                  select new { pc.ConfigObjectId, p.Id, p.Name }).ToListAsync())
                .GroupBy(x => x.ConfigObjectId).ToDictionary(g => g.Key, g => g.First());
            foreach (var v in versions)
            {
                if (!parents.TryGetValue(v.SkillId, out var parent)) continue;
                entries.Add(new($"skill:{v.Id}", "skill", $"A new version of {v.Title} was published", $"Skill in {parent.Name}", v.CreatedAt,
                    new() { ["type"] = "skill", ["pluginId"] = parent.Id, ["skillId"] = v.SkillId }, null));
            }
        }

        return entries.GroupBy(e => e.Id).Select(g => g.Last())
            .OrderByDescending(e => e.OccurredAt).ThenBy(e => e.Id, StringComparer.Ordinal).Take(Limit).ToList();
    }

    private async Task<Dictionary<string, int>> SkillCountsAsync(string orgId, List<string> pluginIds) =>
        pluginIds.Count == 0 ? [] : await (from pc in db.Set<PluginConfigObject>().AsNoTracking()
                                           join o in db.Set<ConfigObject>().AsNoTracking() on pc.ConfigObjectId equals o.Id
                                           where pluginIds.Contains(pc.PluginId) && pc.RemovedAt == null && o.OrganizationId == orgId && o.ObjectType == "skill" && o.Status == "active" && o.DeletedAt == null
                                           group o.Id by pc.PluginId into g
                                           select new { g.Key, Count = g.Distinct().Count() }).ToDictionaryAsync(x => x.Key, x => x.Count);

    public static object Json(ActivityEntry e)
    {
        var d = new Dictionary<string, object?>
        {
            ["id"] = e.Id, ["kind"] = e.Kind, ["title"] = e.Title, ["detail"] = e.Detail,
            ["occurredAt"] = e.OccurredAt.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture), ["target"] = e.Target,
        };
        if (e.Logo is not null) d["logo"] = e.Logo.Where(kv => kv.Value is not null).ToDictionary(kv => kv.Key, kv => kv.Value);
        return d;
    }
}
