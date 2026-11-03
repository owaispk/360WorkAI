using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Connections;
using WorkAI360.Api.Domain.Library;
using WorkAI360.Api.Domain.PluginConnections;
using WorkAI360.Api.Features.Connections;
using WorkAI360.Api.Features.Library;

namespace WorkAI360.Api.Features.PluginConnections;

public sealed record CloudReadiness(string State, bool HasInstructional, List<Dictionary<string, object?>> Connections)
{
    public object ToJson() => new { state = State, hasInstructional = HasInstructional, connections = Connections };
}

/// <summary>
/// "Is this plugin ready to use for me": whether each MCP server a plugin declares has a connection and whether that connection is signed in
/// for the person asking (the reference's <c>cloudReadiness</c> on marketplace plugins).
///
/// A connection is matched through the plugin's binding, else by address among the connections this person may use. A bound connection the
/// person may neither use nor list (no <c>connections.view</c>) is never named: the entry reads as not set up, so a plugin can never
/// reveal a connection to someone who cannot see it.
/// </summary>
public sealed class PluginReadiness(DenDbContext db, ConnectionService connections)
{
    private static readonly HashSet<string> Instructional = ["agent", "command", "context", "custom", "skill", "script", "workflow"];

    private sealed record Dependency(string ConfigObjectId, string PluginId, string Name, string ServerName, string Url, string? ConnectionId, bool Optional, string? RequiredAuthType);

    public async Task<Dictionary<string, CloudReadiness>> ForPluginsAsync(OrgContext context, Audience aud, IReadOnlyCollection<string> pluginIds)
    {
        var orgId = context.Organization.Id;
        var result = new Dictionary<string, CloudReadiness>();
        if (pluginIds.Count == 0) return result;
        var rows = await (from m in db.Set<PluginConfigObject>().AsNoTracking()
                          join o in db.Set<ConfigObject>().AsNoTracking() on m.ConfigObjectId equals o.Id
                          where m.OrganizationId == orgId && pluginIds.Contains(m.PluginId) && m.RemovedAt == null && o.OrganizationId == orgId && o.Status == "active" && o.DeletedAt == null
                          select new { o.Id, o.ObjectType, m.PluginId, o.Title }).ToListAsync();
        var byPlugin = rows.GroupBy(r => r.PluginId).ToDictionary(g => g.Key, g => g.ToList());
        var specs = await new PluginSpecs(db).LatestAsync(rows.Select(r => r.Id).Distinct().ToList());

        var pending = new List<(string PluginId, bool HasInstructional, List<Dependency> All, List<Dependency> Required)>();
        foreach (var pluginId in pluginIds)
        {
            var objects = byPlugin.GetValueOrDefault(pluginId) ?? [];
            if (objects.Count == 0) { result[pluginId] = new CloudReadiness("not_synced", false, []); continue; }
            var hasInstructional = objects.Any(o => specs.ContainsKey(o.Id) && Instructional.Contains(o.ObjectType));
            if (objects.Any(o => !specs.ContainsKey(o.Id))) { result[pluginId] = new CloudReadiness("not_synced", hasInstructional, []); continue; }
            var mcpObjects = objects.Where(o => o.ObjectType == "mcp").ToList();
            if (mcpObjects.Count == 0) { result[pluginId] = new CloudReadiness(hasInstructional ? "ready" : "desktop_only", hasInstructional, []); continue; }
            var all = mcpObjects.SelectMany(o => DependenciesOf(o.Id, pluginId, o.Title, specs[o.Id])).ToList();
            pending.Add((pluginId, hasInstructional, all, hasInstructional ? all.Where(d => !d.Optional).ToList() : all));
        }
        if (pending.Count == 0) return result;

        var allConnections = await connections.ListAllAsync(orgId);
        var usable = (await connections.UsableAsync(orgId, aud.MemberId, aud.TeamIds)).Select(c => c.Id).ToHashSet();
        var canList = context.Permissions.Has("connections.view");
        var objectIds = pending.SelectMany(p => p.All).Select(d => d.ConfigObjectId).Distinct().ToList();
        var boundRows = await db.Set<PluginMcpBinding>().AsNoTracking().Where(b => b.OrganizationId == orgId && objectIds.Contains(b.ConfigObjectId)).ToListAsync();
        var bound = boundRows.ToDictionary(b => $"{b.PluginId}\n{b.ConfigObjectId}\n{b.ServerName}", b => b.ConnectionId);
        var byId = allConnections.ToDictionary(c => c.Id);

        ExternalMcpConnection? Match(Dependency d)
        {
            var explicitId = bound.GetValueOrDefault($"{d.PluginId}\n{d.ConfigObjectId}\n{d.ServerName}") ?? d.ConnectionId;
            if (explicitId is not null)
            {
                var c = byId.GetValueOrDefault(explicitId);
                var same = c is not null && McpAuthPolicy.ComparableUrl(c.Url) == McpAuthPolicy.ComparableUrl(d.Url);
                return same && (usable.Contains(explicitId) || canList) ? c : null;
            }
            return d.Url.Length == 0 ? null : allConnections.FirstOrDefault(c => usable.Contains(c.Id) && McpAuthPolicy.ComparableUrl(c.Url) == McpAuthPolicy.ComparableUrl(d.Url));
        }

        var matched = pending.SelectMany(p => p.All).Select(Match).Where(c => c is not null).Select(c => c!).DistinctBy(c => c.Id).ToList();
        var perMember = matched.Where(c => c.CredentialMode != "shared").Select(c => c.Id).ToList();
        var signedIn = perMember.Count == 0 ? new HashSet<string>() : (await db.Set<ConnectedAccount>().AsNoTracking()
            .Where(a => a.MemberId == aud.MemberId && perMember.Contains(a.ConnectionId) && a.AccessTokenEnc != null).Select(a => a.ConnectionId).ToListAsync()).ToHashSet();
        var matchedIds = matched.Select(c => c.Id).ToList();
        var withClient = (await db.Set<ConnectionOAuthClient>().AsNoTracking().Where(o => matchedIds.Contains(o.ConnectionId)).Select(o => o.ConnectionId).ToListAsync()).ToHashSet();

        bool Ready(ExternalMcpConnection c) => c.CredentialMode == "shared"
            ? c.AccessTokenEnc != null || c.ApiKeyEnc != null || (c.AuthType == "none" && c.ConnectedAt != null)
            : signedIn.Contains(c.Id);

        Dictionary<string, object?> Entry(Dependency d)
        {
            var c = Match(d);
            if (c is null) return new() { ["configObjectId"] = d.ConfigObjectId, ["id"] = null, ["name"] = d.Name, ["serverName"] = d.ServerName, ["url"] = d.Url };
            var connected = Ready(c);
            var mismatch = !McpAuthPolicy.ExistingCompatible(c.AuthType, d.RequiredAuthType);
            var needsClient = d.RequiredAuthType == "oauth" || c.AuthType == "oauth";
            var entry = new Dictionary<string, object?>
            {
                ["authType"] = c.AuthType, ["authTypeMismatch"] = mismatch, ["configObjectId"] = d.ConfigObjectId, ["id"] = c.Id, ["name"] = c.Name, ["serverName"] = d.ServerName,
                ["url"] = c.Url, ["credentialMode"] = c.CredentialMode, ["connectedForMe"] = connected,
            };
            if (needsClient) entry["oauthClientConfigured"] = withClient.Contains(c.Id);
            if (d.RequiredAuthType is not null) entry["requiredAuthType"] = d.RequiredAuthType;
            if (needsClient) entry["oauthClientRequired"] = d.RequiredAuthType == "oauth" && McpAuthPolicy.RequiresPreRegisteredClient(c.Url);
            return entry;
        }

        foreach (var (pluginId, hasInstructional, all, required) in pending)
        {
            var entries = all.Select(Entry).ToList();
            var requiredEntries = required.Count == all.Count ? entries : required.Select(Entry).ToList();
            var needsAdmin = requiredEntries.Any(e => e["id"] is null || e.GetValueOrDefault("authTypeMismatch") is true
                || (e.GetValueOrDefault("oauthClientRequired") is true && e.GetValueOrDefault("oauthClientConfigured") is false)
                || ((string?)e.GetValueOrDefault("credentialMode") == "shared" && e.GetValueOrDefault("connectedForMe") is false));
            var needsSignIn = requiredEntries.Any(e => (string?)e.GetValueOrDefault("credentialMode") == "per_member" && e.GetValueOrDefault("connectedForMe") is false);
            result[pluginId] = new CloudReadiness(needsAdmin ? "needs_admin_setup" : needsSignIn ? "needs_signin" : "ready", hasInstructional, entries);
        }
        return result;
    }

    private static List<Dependency> DependenciesOf(string objectId, string pluginId, string title, JsonObject spec)
    {
        var entries = PluginConnectionService.Entries(spec, title);
        if (entries.Count == 0) return [new Dependency(objectId, pluginId, title, title, "", null, false, null)];
        return entries.Select(e =>
        {
            var url = PluginConnectionService.Text(e.Config["url"]) ?? "";
            return new Dependency(objectId, pluginId, e.Name, e.Name, url, PluginConnectionService.Text(e.Config["externalMcpConnectionId"]) ?? PluginConnectionService.Text(spec["externalMcpConnectionId"]),
                e.Config["optional"] is JsonValue o && o.TryGetValue<bool>(out var b) && b, McpAuthPolicy.Required(McpAuthPolicy.Declared(e.Config), url));
        }).ToList();
    }
}

/// <summary>Latest text of config objects, read as JSON (the spec of an MCP object).</summary>
public sealed class PluginSpecs(DenDbContext db)
{
    public async Task<Dictionary<string, JsonObject>> LatestAsync(IReadOnlyCollection<string> ids)
    {
        var result = new Dictionary<string, JsonObject>();
        if (ids.Count == 0) return result;
        var versions = await db.Set<ConfigObjectVersion>().AsNoTracking().Where(v => ids.Contains(v.ConfigObjectId)).ToListAsync();
        foreach (var g in versions.GroupBy(v => v.ConfigObjectId))
        {
            var latest = g.OrderByDescending(v => v.CreatedAt).ThenByDescending(v => v.Id, StringComparer.Ordinal).First();
            result[g.Key] = PluginConnectionService.ParseObject(latest.NormalizedPayloadJson) ?? PluginConnectionService.ParseObject(latest.RawSourceText) ?? new JsonObject();
        }
        return result;
    }
}
