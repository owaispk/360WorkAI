using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Library;
using WorkAI360.Api.Features.Library;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Features.Workspace;

/// <summary>
/// The Apps built in OpenWork that a person may use, for the dashboard (<c>GET /v1/mcp-apps</c>). An App is a config object of type <c>app</c> whose
/// newest revision is an authored MCP App; a person sees it only when its plugin is shared with them (the Workflow rule). Each element has the shape
/// a connection's MCP App has, so one dashboard tile code serves both. Apps are written by an app builder (React compilation), which this build does
/// not include, and each App's own MCP server is not served: only the catalog is.
/// </summary>
public sealed class McpAppCatalog(DenDbContext db, WorkflowService workflows, IOptions<WorkspaceOptions> options)
{
    public const string SchemaVersion = "openwork.mcp-app/1";
    public const string PayloadKind = "authored_mcp_app";
    public const string LaunchTool = "open_app";
    private const string HostPrefix = "openwork-app-host-connect-";

    public static string HostServerName(string appId) => HostPrefix + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(appId)))[..12];

    public static string ProjectedToolName(string serverName, string tool) =>
        $"{Regex.Replace(serverName, "[^a-zA-Z0-9_-]", "_")}_{Regex.Replace(tool, "[^a-zA-Z0-9_-]", "_")}";

    public static string ResourceUri(string appId, string revisionId) => $"ui://openwork/apps/{appId}/revisions/{revisionId}/index.html";

    /// <summary>Whether a version is a well-formed authored App revision (kind, schema version, a title and compiled page).</summary>
    public static bool IsAuthoredRevision(ConfigObjectVersion v)
    {
        if (v.IsDeletedVersion || v.SchemaVersion != SchemaVersion) return false;
        if (WorkflowArtifacts.Parse(v.NormalizedPayloadJson) is not JsonObject p) return false;
        return p["kind"]?.GetValue<string>() == PayloadKind && p["schemaVersion"] is JsonValue sv && WorkflowArtifacts.El(sv).GetDouble() == 1
            && p["title"] is JsonValue t && t.TryGetValue<string>(out var title) && title.Trim().Length is >= 1 and <= 120
            && p["html"] is JsonValue h && h.TryGetValue<string>(out var html) && html.Length > 0;
    }

    public async Task<JsonArray> ListAsync(Actor a)
    {
        if (!options.Value.AppMcpServersEnabled) return [];
        var shared = await workflows.SharedObjectsAsync(a.OrgId, a.MemberId, a.TeamIds, ["app"]);
        var apps = new Dictionary<string, (Plugin Plugin, ConfigObject Object)>();
        foreach (var (plugin, o) in shared) apps.TryAdd(o.Id, (plugin, o));
        if (apps.Count == 0) return [];
        var ids = apps.Keys.ToList();
        var versions = (await db.Set<ConfigObjectVersion>().AsNoTracking().Where(v => v.OrganizationId == a.OrgId && ids.Contains(v.ConfigObjectId)).ToListAsync())
            .GroupBy(v => v.ConfigObjectId).ToDictionary(g => g.Key, g => g.OrderByDescending(v => v.CreatedAt).ThenByDescending(v => v.Id, StringComparer.Ordinal).First());
        var entries = new List<(string AppId, string RevisionId, Plugin Plugin, string Title, string? Description)>();
        foreach (var (id, (plugin, o)) in apps)
            if (versions.TryGetValue(id, out var latest) && IsAuthoredRevision(latest)) entries.Add((id, latest.Id, plugin, o.Title, o.Description));
        var result = new JsonArray();
        foreach (var e in entries.OrderBy(x => x.Title, StringComparer.InvariantCulture).ThenBy(x => x.AppId, StringComparer.InvariantCulture))
        {
            var server = HostServerName(e.AppId);
            result.Add(new JsonObject
            {
                ["serverName"] = server, ["connectionId"] = e.AppId, ["toolName"] = LaunchTool, ["projectedToolName"] = ProjectedToolName(server, LaunchTool),
                ["resourceUri"] = ResourceUri(e.AppId, e.RevisionId), ["title"] = e.Title, ["description"] = e.Description, ["pluginId"] = e.Plugin.Id, ["pluginName"] = e.Plugin.Name,
                // open_app takes only optional launch input and runs no other tools.
                ["requiresInput"] = false, ["requiredInputKeys"] = new JsonArray(), ["requiresApproval"] = false,
            });
        }
        return result;
    }
}

/// <summary>
/// Saved Workflows as capabilities <c>plugin:&lt;pluginId&gt;:&lt;workflowId&gt;</c> (the reference's ids), so an agent finds them with
/// <c>search_capabilities</c> and runs them with <c>execute_capability</c>. A person is offered only the Workflows shared with them. Running one
/// runs its newest version as that person, under the same rules as the REST route.
/// </summary>
public sealed class WorkflowCapabilityProvider : ICapabilityProvider
{
    private static readonly JsonNode NoArguments = JsonNode.Parse("""{"type":"object","properties":{},"additionalProperties":false}""")!;

    private static async Task<WorkflowService.Who?> WhoAsync(McpPrincipal principal, DenDbContext db)
    {
        var member = await db.Members.AsNoTracking().FirstOrDefaultAsync(m => m.OrganizationId == principal.OrganizationId && m.UserId == principal.UserId);
        if (member is null) return null;
        var teams = await db.TeamMembers.AsNoTracking().Where(t => t.MemberId == member.Id).Select(t => t.TeamId).ToListAsync();
        return new WorkflowService.Who(principal.OrganizationId, principal.UserId, member.Id, teams.ToHashSet());
    }

    public static string IdOf(string pluginId, string configObjectId) => $"plugin:{pluginId}:{configObjectId}";

    public async Task<IReadOnlyList<CapabilityInfo>> ListAsync(McpPrincipal principal, IServiceProvider services)
    {
        var db = services.GetRequiredService<DenDbContext>();
        if (await WhoAsync(principal, db) is not { } who) return [];
        var svc = services.GetRequiredService<WorkflowService>();
        var result = new List<CapabilityInfo>();
        var seen = new HashSet<string>();
        foreach (var (plugin, o) in await svc.SharedWorkflowsAsync(who.OrgId, who.MemberId, who.TeamIds))
        {
            if (!seen.Add(o.Id)) continue;
            var latest = (await svc.VersionsAsync(who.OrgId, o.Id)).FirstOrDefault();
            if (latest is null) continue;
            var needsWrite = latest.Payload.Required.Any(r => r.CapabilityName.StartsWith(ConnectionCapabilityPrefix, StringComparison.Ordinal));
            result.Add(new CapabilityInfo(IdOf(plugin.Id, o.Id), $"[Workflow] {o.Title}{(string.IsNullOrWhiteSpace(o.Description) ? "" : ": " + o.Description)}",
                needsWrite ? OAuthConstants.WriteScope : OAuthConstants.ReadScope, latest.Payload.InputSchema?.DeepClone() ?? NoArguments.DeepClone()));
        }
        return result.OrderBy(c => c.Description, StringComparer.InvariantCulture).ToList();
    }

    private const string ConnectionCapabilityPrefix = "mcp:";

    public async Task<CapabilityOutcome> ExecuteAsync(string id, JsonObject arguments, McpPrincipal principal, IServiceProvider services)
    {
        var db = services.GetRequiredService<DenDbContext>();
        if (await WhoAsync(principal, db) is not { } who) return CapabilityOutcome.Fail("forbidden", "You are not a member of this organization.");
        var parts = id.Split(':');
        if (parts.Length != 3 || parts[0] != "plugin") return CapabilityOutcome.Fail("unknown_capability", "No such capability.");
        var svc = services.GetRequiredService<WorkflowService>();
        var (error, message, found) = await svc.FindRunnableAsync(who, parts[1], parts[2], null);
        if (found is null) return CapabilityOutcome.Fail(error == "content_not_synced" ? "content_not_synced" : error ?? "unknown_capability", message ?? "No such capability.");
        var execution = await svc.RunSavedAsync(who, found.Value, arguments.DeepClone(), live: false, timeZone: null, validateOutput: false, CancellationToken.None);
        switch (execution)
        {
            case WorkflowExecution.Succeeded ok:
                return CapabilityOutcome.Ok(new JsonObject { ["status"] = "executed", ["kind"] = "workflow", ["name"] = found.Value.Object.Title, ["value"] = ok.Value?.DeepClone(), ["receiptId"] = ok.ReceiptId });
            case WorkflowExecution.Invalid invalid: return CapabilityOutcome.Fail("invalid_capability_arguments", invalid.Message);
            case WorkflowExecution.CapabilityUnavailable unavailable: return CapabilityOutcome.Fail("capability_unavailable", unavailable.Message);
            case WorkflowExecution.ScriptFailed failed: return CapabilityOutcome.Fail("script_failed", failed.Message);
            default: return CapabilityOutcome.Fail("script_not_executable", (execution as WorkflowExecution.Unsupported)?.Message ?? "The Workflow could not run.");
        }
    }
}
