using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Library;
using WorkAI360.Api.Features.Library;

namespace WorkAI360.Api.Features.Onboarding;

/// <summary>What a desktop polls to learn whether its library changed: ids and update times only, for what this member may see.</summary>
public static class ResourceEndpoints
{
    public static void MapResourceEndpoints(this WebApplication app)
    {
        app.MapGet("/v1/resources", (HttpContext ctx, LibraryRunner run, LibraryAccess lib, DenDbContext db) => run.RunAsync(ctx, async a =>
        {
            var orgId = a.OrgId;
            var marketplaces = await db.Set<Marketplace>().AsNoTracking().Where(m => m.OrganizationId == orgId && m.Status == "active" && m.DeletedAt == null)
                .OrderByDescending(m => m.UpdatedAt).ThenByDescending(m => m.Id).ToListAsync();
            var roles = await lib.MarketplaceRolesAsync(a.Aud, marketplaces.Select(m => m.Id).ToList());
            var visible = marketplaces.Where(m => roles.ContainsKey(m.Id)).ToList();

            var result = new Dictionary<string, object>();
            if (visible.Count > 0)
            {
                var ids = visible.Select(m => m.Id).ToList();
                var memberships = await db.Set<MarketplacePlugin>().AsNoTracking().Where(m => m.OrganizationId == orgId && ids.Contains(m.MarketplaceId) && m.RemovedAt == null).ToListAsync();
                var pluginIds = memberships.Select(m => m.PluginId).Distinct().ToList();
                var plugins = await db.Set<Plugin>().AsNoTracking().Where(p => p.OrganizationId == orgId && pluginIds.Contains(p.Id) && p.Status == "active" && p.DeletedAt == null).ToDictionaryAsync(p => p.Id);
                var items = await (from pc in db.Set<PluginConfigObject>().AsNoTracking()
                                   join o in db.Set<ConfigObject>().AsNoTracking() on pc.ConfigObjectId equals o.Id
                                   where pc.OrganizationId == orgId && plugins.Keys.Contains(pc.PluginId) && pc.RemovedAt == null && o.Status == "active" && o.DeletedAt == null
                                   select new { pc.PluginId, ItemId = o.Id, o.UpdatedAt }).ToListAsync();
                var itemsByPlugin = items.GroupBy(i => i.PluginId).ToDictionary(g => g.Key, g => g.Select(i => new { configItemId = i.ItemId, lastUpdatedAt = Responses.IsoUtc(i.UpdatedAt) }).ToList());
                foreach (var m in visible)
                {
                    var inside = memberships.Where(x => x.MarketplaceId == m.Id && plugins.ContainsKey(x.PluginId)).Select(x => plugins[x.PluginId])
                        .Select(p => new { pluginId = p.Id, lastUpdatedAt = Responses.IsoUtc(p.UpdatedAt), configItems = itemsByPlugin.GetValueOrDefault(p.Id) ?? [] }).ToList();
                    result[m.Id] = new { lastUpdatedAt = Responses.IsoUtc(m.UpdatedAt), plugins = inside };
                }
            }
            var teamIds = a.TeamIds.Order(StringComparer.Ordinal).ToList();
            return Results.Json(new { organizationId = orgId, orgMemberId = a.MemberId, teamIds, resources = new { llmProviders = new Dictionary<string, string>(), marketplaces = result } });
        }));

        // Grant-scoped: what this member's agent may use, never widened by being an administrator.
        app.MapGet("/v1/resources/marketplace-capabilities", (HttpContext ctx, LibraryRunner run, LibraryAccess lib, DenDbContext db) => run.RunAsync(ctx, async a =>
        {
            var orgId = a.OrgId;
            var audience = new Audience(orgId, a.MemberId, a.TeamIds, ManageAll: false);
            var rows = await (from pc in db.Set<PluginConfigObject>().AsNoTracking()
                              join o in db.Set<ConfigObject>().AsNoTracking() on pc.ConfigObjectId equals o.Id
                              join p in db.Set<Plugin>().AsNoTracking() on pc.PluginId equals p.Id
                              where pc.OrganizationId == orgId && pc.RemovedAt == null && o.OrganizationId == orgId && o.Status == "active" && o.DeletedAt == null
                                    && p.OrganizationId == orgId && p.Status == "active" && p.DeletedAt == null
                              select new { PluginId = p.Id, ConfigObjectId = o.Id, o.ObjectType }).ToListAsync();
            if (rows.Count == 0) return Results.Json(new { items = Array.Empty<object>() });

            var objectRoles = await lib.ConfigObjectRolesAsync(audience, rows.Select(r => r.ConfigObjectId).Distinct().ToList());
            var pluginIds = rows.Select(r => r.PluginId).Distinct().ToList();
            var marketplaceLinks = await (from mp in db.Set<MarketplacePlugin>().AsNoTracking()
                                          join m in db.Set<Marketplace>().AsNoTracking() on mp.MarketplaceId equals m.Id
                                          where mp.OrganizationId == orgId && pluginIds.Contains(mp.PluginId) && mp.RemovedAt == null && m.Status == "active" && m.DeletedAt == null
                                          select new { mp.PluginId, mp.MarketplaceId }).ToListAsync();
            var marketRoles = await lib.MarketplaceRolesAsync(audience, marketplaceLinks.Select(l => l.MarketplaceId).Distinct().ToList());
            var viaMarketplace = marketplaceLinks.Where(l => marketRoles.ContainsKey(l.MarketplaceId)).ToLookup(l => l.PluginId, l => l.MarketplaceId);

            var references = new Dictionary<string, (string ConfigObjectId, string? MarketplaceId, string ObjectType, string PluginId)>();
            foreach (var r in rows)
            {
                if (!objectRoles.ContainsKey(r.ConfigObjectId)) continue;
                var type = r.ObjectType == "workflow" ? "script" : r.ObjectType;
                var markets = viaMarketplace[r.PluginId].Distinct().ToList();
                // Through each marketplace that shows it; with none, the grant on the skill itself is the only door.
                if (markets.Count == 0) references[$"grant-only:{r.PluginId}:{r.ConfigObjectId}"] = (r.ConfigObjectId, null, type, r.PluginId);
                foreach (var m in markets) references[$"{m}:{r.PluginId}:{r.ConfigObjectId}"] = (r.ConfigObjectId, m, type, r.PluginId);
            }
            var ordered = references.Values.OrderBy(v => v.MarketplaceId is null ? 1 : 0).ThenBy(v => v.MarketplaceId, StringComparer.Ordinal).ThenBy(v => v.PluginId, StringComparer.Ordinal).ThenBy(v => v.ConfigObjectId, StringComparer.Ordinal);
            return Results.Json(new { items = ordered.Select(v => new { configObjectId = v.ConfigObjectId, marketplaceId = v.MarketplaceId, objectType = v.ObjectType, pluginId = v.PluginId }) });
        }));
    }
}
