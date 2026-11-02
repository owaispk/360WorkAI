using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Library;
using WorkAI360.Api.Domain.PluginConnections;
using WorkAI360.Api.Features.Library;

namespace WorkAI360.Api.Features.PluginConnections;

/// <summary>A binding whose plugin, plugin membership and MCP object are all still active.</summary>
public sealed record ActiveBinding(string Id, string PluginId, string PluginName, string ConfigObjectId, string ServerName, string ConnectionId, string? RequiredAuthType, bool Owned);

/// <summary>What a connection says about the plugins that need it, for one reader.</summary>
public sealed record Provenance(List<(string PluginId, string Name)> RequiredBy, List<(string PluginId, string Name)> IdentityManagedBy, HashSet<string> RequiredAuthTypes);

/// <summary>
/// Reads plugin-to-connection bindings (database only, so the connection service can use it). Two rules live here:
/// <list type="bullet">
/// <item>A connection is usable through a binding by whoever the plugin is shared with: a grant on the MCP object, the plugin, or an active
/// marketplace that holds it, to the person, one of their teams, or everyone. Worked out when asked, so archiving or unsharing the plugin
/// withdraws it at once. Being an admin adds nothing.</item>
/// <item>The plugins a connection names (<c>requiredBy</c>) are only the ones the reader may see; a person never learns the name of a
/// plugin they cannot view.</item>
/// </list>
/// </summary>
public sealed class PluginBindingStore(DenDbContext db, LibraryAccess lib)
{
    private sealed class Row
    {
        public string Id { get; set; } = "";
        public string PluginId { get; set; } = "";
        public string PluginName { get; set; } = "";
        public string ConfigObjectId { get; set; } = "";
        public string ServerName { get; set; } = "";
        public string ConnectionId { get; set; } = "";
        public string? RequiredAuthType { get; set; }
        public bool Owned { get; set; }
        public ActiveBinding ToRecord() => new(Id, PluginId, PluginName, ConfigObjectId, ServerName, ConnectionId, RequiredAuthType, Owned);
    }

    private IQueryable<Row> Active(string orgId) =>
        from b in db.Set<PluginMcpBinding>().AsNoTracking()
        join p in db.Set<Plugin>().AsNoTracking() on b.PluginId equals p.Id
        join o in db.Set<ConfigObject>().AsNoTracking() on b.ConfigObjectId equals o.Id
        join m in db.Set<PluginConfigObject>().AsNoTracking() on new { b.PluginId, b.ConfigObjectId } equals new { m.PluginId, m.ConfigObjectId }
        where b.OrganizationId == orgId && p.OrganizationId == orgId && p.Status == "active" && p.DeletedAt == null
              && o.OrganizationId == orgId && o.ObjectType == "mcp" && o.Status == "active" && o.DeletedAt == null && m.RemovedAt == null
        select new Row { Id = b.Id, PluginId = p.Id, PluginName = p.Name, ConfigObjectId = o.Id, ServerName = b.ServerName, ConnectionId = b.ConnectionId, RequiredAuthType = b.RequiredAuthType, Owned = b.ConnectionOwnedByPlugin };

    public async Task<List<ActiveBinding>> ActiveAsync(string orgId, IReadOnlyCollection<string>? connectionIds = null)
    {
        var query = Active(orgId);
        if (connectionIds is not null) { var ids = connectionIds.ToList(); query = query.Where(b => ids.Contains(b.ConnectionId)); }
        return (await query.ToListAsync()).Select(r => r.ToRecord()).ToList();
    }

    public async Task<List<ActiveBinding>> ActiveForPluginAsync(string orgId, string pluginId) => (await Active(orgId).Where(b => b.PluginId == pluginId).ToListAsync()).Select(r => r.ToRecord()).ToList();

    /// <summary>Every binding of these plugins, active or not, with the connection it points at (used when a plugin is removed).</summary>
    public async Task<List<PluginMcpBinding>> AllForPluginAsync(string orgId, string pluginId) =>
        await db.Set<PluginMcpBinding>().Where(b => b.OrganizationId == orgId && b.PluginId == pluginId).ToListAsync();

    private async Task<Dictionary<string, List<string>>> MarketplacesOfAsync(string orgId, IReadOnlyCollection<string> pluginIds)
    {
        var rows = await (from mp in db.Set<MarketplacePlugin>().AsNoTracking()
                          join m in db.Set<Marketplace>().AsNoTracking() on mp.MarketplaceId equals m.Id
                          where mp.OrganizationId == orgId && mp.RemovedAt == null && pluginIds.Contains(mp.PluginId) && m.OrganizationId == orgId && m.Status == "active" && m.DeletedAt == null
                          select new { mp.PluginId, m.Id }).ToListAsync();
        return rows.GroupBy(r => r.PluginId).ToDictionary(g => g.Key, g => g.Select(r => r.Id).ToList());
    }

    private static bool Applies(LibraryGrant g, string memberId, IReadOnlyCollection<string> teamIds) =>
        (g.OrgWide || g.MemberId == memberId || (g.TeamId is not null && teamIds.Contains(g.TeamId)));

    /// <summary>The connections of this workspace the person may use because a plugin that needs them is shared with them.</summary>
    public async Task<HashSet<string>> UsableConnectionIdsAsync(string orgId, string memberId, IReadOnlyCollection<string> teamIds)
    {
        var bindings = await ActiveAsync(orgId);
        return await UsableAmongAsync(orgId, memberId, teamIds, bindings);
    }

    public async Task<bool> CanUseAsync(string orgId, string connectionId, string memberId, IReadOnlyCollection<string> teamIds)
    {
        var bindings = await ActiveAsync(orgId, [connectionId]);
        return (await UsableAmongAsync(orgId, memberId, teamIds, bindings)).Contains(connectionId);
    }

    private async Task<HashSet<string>> UsableAmongAsync(string orgId, string memberId, IReadOnlyCollection<string> teamIds, List<ActiveBinding> bindings)
    {
        var result = new HashSet<string>();
        if (bindings.Count == 0) return result;
        var pluginIds = bindings.Select(b => b.PluginId).Distinct().ToList();
        var objectIds = bindings.Select(b => b.ConfigObjectId).Distinct().ToList();
        var markets = await MarketplacesOfAsync(orgId, pluginIds);
        var marketIds = markets.Values.SelectMany(x => x).Distinct().ToList();
        var grants = await db.Set<LibraryGrant>().AsNoTracking()
            .Where(g => g.OrganizationId == orgId && g.RemovedAt == null && (g.OrgWide || g.MemberId == memberId || (g.TeamId != null && teamIds.Contains(g.TeamId)))
                && ((g.ResourceKind == GrantKinds.Plugin && pluginIds.Contains(g.ResourceId))
                    || (g.ResourceKind == GrantKinds.ConfigObject && objectIds.Contains(g.ResourceId))
                    || (g.ResourceKind == GrantKinds.Marketplace && marketIds.Contains(g.ResourceId))))
            .ToListAsync();
        var reach = grants.Where(g => Applies(g, memberId, teamIds)).Select(g => (g.ResourceKind, g.ResourceId)).ToHashSet();
        foreach (var b in bindings)
        {
            if (reach.Contains((GrantKinds.Plugin, b.PluginId)) || reach.Contains((GrantKinds.ConfigObject, b.ConfigObjectId))
                || markets.GetValueOrDefault(b.PluginId, []).Any(m => reach.Contains((GrantKinds.Marketplace, m))))
                result.Add(b.ConnectionId);
        }
        return result;
    }

    /// <summary>
    /// The plugins that need a connection, as this reader may know them. <paramref name="everything"/> is for a person who is already
    /// editing the connection (the reference names every plugin there).
    /// </summary>
    public async Task<Provenance> ProvenanceAsync(Audience reader, string connectionId, bool everything = false)
    {
        var bindings = await ActiveAsync(reader.OrgId, [connectionId]);
        if (bindings.Count == 0) return new Provenance([], [], []);
        var ids = bindings.Select(b => b.PluginId).Distinct().ToList();
        var visible = everything ? ids.ToHashSet() : (await lib.PluginRolesAsync(reader, ids)).Keys.ToHashSet();
        var shown = bindings.Where(b => visible.Contains(b.PluginId)).ToList();
        List<(string, string)> Names(IEnumerable<ActiveBinding> rows) =>
            rows.GroupBy(b => b.PluginId).Select(g => (g.Key, g.First().PluginName)).OrderBy(x => x.Item2, StringComparer.OrdinalIgnoreCase).ThenBy(x => x.Item2, StringComparer.Ordinal).ToList();
        return new Provenance(Names(shown), Names(shown.Where(b => b.Owned)), shown.Where(b => b.RequiredAuthType is not null).Select(b => b.RequiredAuthType!).ToHashSet());
    }

    /// <summary>Names of the plugins that own a connection's server and sign-in settings, limited to those the reader may see.</summary>
    public async Task<List<string>> OwnerNamesAsync(Audience reader, string connectionId)
    {
        var p = await ProvenanceAsync(reader, connectionId);
        return p.IdentityManagedBy.Select(x => x.Name).Distinct().ToList();
    }

    /// <summary>
    /// Connections a plugin made for itself follow that plugin: once every plugin bound to one is archived the connection is retired and
    /// left out of the lists (the binding and credentials stay, so restoring the plugin brings it back). A connection an admin made is never retired.
    /// </summary>
    public async Task<HashSet<string>> RetiredAsync(string orgId, IReadOnlyCollection<string> connectionIdSet)
    {
        if (connectionIdSet.Count == 0) return [];
        var connectionIds = connectionIdSet.ToList();
        var rows = await (from b in db.Set<PluginMcpBinding>().AsNoTracking()
                          join p in db.Set<Plugin>().AsNoTracking() on b.PluginId equals p.Id
                          where b.OrganizationId == orgId && connectionIds.Contains(b.ConnectionId)
                          select new { b.ConnectionId, b.ConnectionOwnedByPlugin, Active = p.Status == "active" && p.DeletedAt == null }).ToListAsync();
        var owned = rows.Where(r => r.ConnectionOwnedByPlugin).Select(r => r.ConnectionId).ToHashSet();
        var needed = rows.Where(r => r.Active).Select(r => r.ConnectionId).ToHashSet();
        owned.ExceptWith(needed);
        return owned;
    }

    public async Task<bool> IsManagedAsync(string orgId, string connectionId) => await Active(orgId).AnyAsync(b => b.ConnectionId == connectionId);

    public async Task RemoveForConnectionAsync(string orgId, string connectionId) =>
        await db.Set<PluginMcpBinding>().Where(b => b.OrganizationId == orgId && b.ConnectionId == connectionId).ExecuteDeleteAsync();
}
