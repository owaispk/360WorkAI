using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Automations;
using WorkAI360.Api.Domain.Library;
using WorkAI360.Api.Domain.Workspace;
using WorkAI360.Api.Features.Connections;
using WorkAI360.Api.Features.Library;

namespace WorkAI360.Api.Features.Workspace;

public sealed class WorkspaceOptions
{
    public const string Section = "Workspace";
    /// <summary>Generated views ("apps" bound to a Workflow) and the <c>/v1/apps</c> routes. Off by default, as in the reference.</summary>
    public bool GeneratedArtifactViewsEnabled { get; set; }
    /// <summary>Apps built in OpenWork are their own MCP servers, and Workflow-bound views become read-only. On by default.</summary>
    public bool AppMcpServersEnabled { get; set; } = true;
    /// <summary>The secret GitHub signs connector webhooks with. Unset: the webhook answers 503.</summary>
    public string? GithubWebhookSecret { get; set; }
    /// <summary>The secret Stripe signs its webhooks with. Unset: the webhook answers 400 <c>stripe_webhook_secret_missing</c>.</summary>
    public string? StripeWebhookSecret { get; set; }
    public int DefaultTimeoutMs { get; set; } = 120_000;
    public int MaxTimeoutMs { get; set; } = 170_000;
}

public sealed record RunRecord(
    string OrganizationId, string? MemberId, string? PluginId, string? ConfigObjectId, string? ConfigObjectVersionId, string Source, string Code, string Status,
    string? ErrorKind, string? ErrorMessage, IReadOnlyList<string> ToolCalls, int DurationMs, DateTime StartedAt, DateTime FinishedAt,
    string? ScriptInputDigest, string? InputSchemaDigest, string? OutputSchemaDigest, JsonNode? ValidatedResult = null, string? ResultMarkdown = null, string? ResultDigest = null, string? RendererVersion = null);

/// <summary>What running a Workflow gave: a result, or one of the reference's named refusals and failures.</summary>
public abstract record WorkflowExecution
{
    public sealed record Succeeded(JsonNode? Value, string Canonical, string Markdown, string ResultDigest, string? InputSchemaDigest, string? OutputSchemaDigest, string? ReceiptId, List<string> Logs, List<string> ToolCalls, int DurationMs) : WorkflowExecution;
    public sealed record Unsupported(string Message) : WorkflowExecution;
    public sealed record Invalid(string Error, string Message, List<string> Issues, string? ReceiptId) : WorkflowExecution;
    public sealed record CapabilityUnavailable(string Message, List<RequiredCapability> Missing, string? ReceiptId) : WorkflowExecution;
    public sealed record ScriptFailed(string Message, string Kind, List<string> ToolCalls, string? ReceiptId) : WorkflowExecution;
}

/// <summary>
/// Workflows: saved Code Mode scripts that live as config objects (type <c>workflow</c>) inside a plugin. Reading, testing a draft, saving versions,
/// running an exact version, and the receipts every run leaves. Access follows the library: a person's role on the Workflow (viewer reads, editor
/// runs, manager changes it); a Workflow in another workspace reads as not found.
/// </summary>
public sealed class WorkflowService(DenDbContext db, LibraryAccess lib, LibraryUsage usage, WorkflowTools toolFactory, AuthoringSources authoring, SecretBox box, ConnectionService connections, IOptions<WorkspaceOptions> options, ILogger<WorkflowService> log)
{
    public const string SchemaVersion = "codemode-script-v1";
    public static readonly TimeSpan RecentWindow = TimeSpan.FromMinutes(15);
    private const string DefaultPluginName = "My Workflows";
    private static readonly string[] LegacyPluginNames = ["My Programs", "Saved scripts"];

    public static DateTime Now() => LibraryStore.Now();
    private static string Iso(DateTime d) => Responses.IsoUtc(d);

    public sealed record Resource(ConfigObject Object, Plugin Plugin);

    /// <summary>Who runs something: a person in a workspace, with their teams (an agent's token names the same things a session does).</summary>
    public sealed record Who(string OrgId, string UserId, string MemberId, HashSet<string> TeamIds)
    {
        public static Who Of(Actor a) => new(a.OrgId, a.Context.Member.UserId, a.MemberId, a.TeamIds);
    }

    // ---------------------------------------------------------------- access

    /// <summary>
    /// The Workflow and the plugin it runs under. The Workflow must be active, in an active plugin of this workspace; the caller needs the role
    /// on the Workflow. A Workflow in several plugins runs under the oldest one the caller can see.
    /// </summary>
    public async Task<Resource> ResourceAsync(Actor a, string value, LibRole need)
    {
        var id = TypeIds.ConfigObject(value);
        var rows = await (from o in db.Set<ConfigObject>().AsNoTracking()
                          join m in db.Set<PluginConfigObject>().AsNoTracking() on o.Id equals m.ConfigObjectId
                          join p in db.Set<Plugin>().AsNoTracking() on m.PluginId equals p.Id
                          where o.Id == id && o.OrganizationId == a.OrgId && o.ObjectType == "workflow" && o.Status == "active" && o.DeletedAt == null
                                && m.RemovedAt == null && p.Status == "active" && p.DeletedAt == null && p.OrganizationId == a.OrgId
                          orderby m.CreatedAt, m.Id
                          select new Resource(o, p)).ToListAsync();
        if (rows.Count == 0) throw new WorkflowException("workflow_not_found");
        if (await lib.ConfigObjectRoleAsync(a, id) is not { } role || role < need) throw new LibraryForbidden($"Missing {RoleNames.Name(need)} access for config object.");
        var pluginRoles = await lib.PluginRolesAsync(a.Aud, rows.Select(r => r.Plugin.Id).ToList());
        // A direct grant on the Workflow is independent of its plugin; then the oldest membership is its context.
        return rows.FirstOrDefault(r => pluginRoles.ContainsKey(r.Plugin.Id)) ?? rows[0];
    }

    public async Task<LibRole?> RoleAsync(Actor a, string configObjectId) => await lib.ConfigObjectRoleAsync(a, configObjectId);

    // ---------------------------------------------------------------- versions

    public sealed record VersionRow(ConfigObjectVersion Row, CodemodePayload Payload);

    /// <summary>Versions newest first; a version whose payload cannot be read is left out.</summary>
    public async Task<List<VersionRow>> VersionsAsync(string orgId, string configObjectId)
    {
        var rows = (await db.Set<ConfigObjectVersion>().AsNoTracking().Where(v => v.OrganizationId == orgId && v.ConfigObjectId == configObjectId && !v.IsDeletedVersion).ToListAsync())
            .OrderByDescending(v => v.CreatedAt).ThenByDescending(v => v.Id, StringComparer.Ordinal).ToList();
        var result = new List<VersionRow>();
        foreach (var r in rows)
            if (CodemodePayload.Parse(WorkflowArtifacts.Parse(r.NormalizedPayloadJson)) is { Payload: { } payload }) result.Add(new VersionRow(r, payload));
        return result;
    }

    private static JsonNode? Clone(JsonNode? n) => n?.DeepClone();

    private async Task<List<(string ConfigObjectId, JsonObject Reference)>> AutomationReferencesAsync(Actor a)
    {
        var rows = await (from au in db.Set<Automation>().AsNoTracking()
                          join r in db.Set<AutomationRevision>().AsNoTracking() on au.CurrentRevisionId equals r.Id
                          where au.OrganizationId == a.OrgId && au.OwnerMemberId == a.MemberId
                          select new { au.Id, au.Name, au.State, r.ActionJson }).ToListAsync();
        var result = new List<(string, JsonObject)>();
        foreach (var r in rows)
        {
            if (JsonNode.Parse(r.ActionJson) is not JsonObject action || action["kind"]?.GetValue<string>() != "saved_script" || action["script"] is not JsonObject script) continue;
            result.Add((script["configObjectId"]?.GetValue<string>() ?? "", new JsonObject
            {
                ["id"] = r.Id, ["name"] = r.Name, ["state"] = r.State, ["configObjectVersionId"] = script["configObjectVersionId"]?.GetValue<string>(), ["input"] = Clone(action["input"]),
            }));
        }
        return result;
    }

    private JsonObject VersionJson(VersionRow v, bool manager, List<JsonObject> automations)
    {
        var code = v.Row.RawSourceText ?? "";
        var graph = WorkflowGraph.Analyze(code);
        var refs = automations.Where(r => r["configObjectVersionId"]?.GetValue<string>() == v.Row.Id).ToList();
        return new JsonObject
        {
            ["id"] = v.Row.Id,
            ["code"] = manager ? code : null,
            ["graph"] = manager ? graph : WorkflowGraph.Redact(graph),
            ["inputSchema"] = Clone(v.Payload.InputSchema),
            ["outputSchema"] = Clone(v.Payload.OutputSchema),
            ["exampleInput"] = manager ? Clone(v.Payload.ExampleInput) : null,
            ["requiredCapabilities"] = RequiredJson(v.Payload.Required),
            ["codeDigest"] = WorkflowArtifacts.CodeDigest(code),
            ["inputSchemaDigest"] = WorkflowArtifacts.OptionalDigest(v.Payload.InputSchema),
            ["outputSchemaDigest"] = WorkflowArtifacts.OptionalDigest(v.Payload.OutputSchema),
            ["createdAt"] = Iso(v.Row.CreatedAt),
            ["automationReferences"] = new JsonArray(refs.Select(r => (JsonNode)(manager ? (JsonObject)r.DeepClone()
                : new JsonObject { ["id"] = r["id"]!.DeepClone(), ["name"] = r["name"]!.DeepClone(), ["state"] = r["state"]!.DeepClone(), ["configObjectVersionId"] = r["configObjectVersionId"]!.DeepClone() })).ToArray()),
        };
    }

    public static JsonArray RequiredJson(IEnumerable<RequiredCapability> required) =>
        new(required.Select(r => (JsonNode)new JsonObject { ["capabilityName"] = r.CapabilityName, ["scriptPath"] = r.ScriptPath }).ToArray());

    public async Task<JsonArray> ListVersionsAsync(Actor a, string configObjectId)
    {
        var resource = await ResourceAsync(a, configObjectId, LibRole.Viewer);
        var role = await RoleAsync(a, resource.Object.Id);
        var automations = (await AutomationReferencesAsync(a)).Where(r => r.ConfigObjectId == resource.Object.Id).Select(r => r.Reference).ToList();
        var versions = await VersionsAsync(a.OrgId, resource.Object.Id);
        return new JsonArray(versions.Select(v => (JsonNode)VersionJson(v, role == LibRole.Manager, automations)).ToArray());
    }

    // ---------------------------------------------------------------- snapshots

    private static JsonArray ToolCallsJson(string? json) =>
        json is null ? [] : JsonNode.Parse(json) is JsonArray a ? new JsonArray(a.Select(c => (JsonNode)new JsonObject { ["name"] = c?["name"]?.GetValue<string>() }).ToArray()) : [];

    private JsonObject? Snapshot(WorkflowRun r, string? automationTrigger)
    {
        if (r.PluginId is null || r.ConfigObjectId is null || r.ConfigObjectVersionId is null) return null;
        var deleted = r.ArtifactContentDeletedAt is not null;
        return new JsonObject
        {
            ["receiptId"] = r.Id, ["pluginId"] = r.PluginId, ["configObjectId"] = r.ConfigObjectId, ["configObjectVersionId"] = r.ConfigObjectVersionId, ["automationRunId"] = r.AutomationRunId,
            ["value"] = deleted ? null : WorkflowArtifacts.Parse(box.Decrypt(r.ValidatedResultCipher)),
            ["markdown"] = deleted ? null : box.Decrypt(r.ResultMarkdownCipher),
            ["codeDigest"] = r.CodeDigest, ["resultDigest"] = r.ResultDigest, ["inputSchemaDigest"] = r.InputSchemaDigest, ["outputSchemaDigest"] = r.OutputSchemaDigest,
            ["rendererVersion"] = r.RendererVersion == WorkflowArtifacts.RendererVersion ? WorkflowArtifacts.RendererVersion : null,
            ["toolCalls"] = ToolCallsJson(r.ToolCallsJson),
            ["status"] = r.Status, ["errorKind"] = r.ErrorKind, ["errorMessage"] = r.ErrorMessage,
            ["source"] = automationTrigger is not null and not "manual" ? "scheduled" : "manual",
            ["startedAt"] = Iso(r.StartedAt), ["finishedAt"] = Iso(r.FinishedAt), ["contentDeletedAt"] = r.ArtifactContentDeletedAt is { } d ? Iso(d) : null,
        };
    }

    /// <summary>Receipts of saved versions the person may read: their own, and anyone's under the Workflow's standing source (manual runs and Automations).</summary>
    private IQueryable<WorkflowRun> ReadableSnapshots(string orgId, string memberId, string configObjectId) =>
        db.Set<WorkflowRun>().AsNoTracking().Where(r => r.OrganizationId == orgId && r.ConfigObjectId == configObjectId && r.ConfigObjectVersionId != null
            && (r.MemberId == memberId || r.Source == "plugin:" + r.PluginId + ":" + r.ConfigObjectId));

    private async Task<Dictionary<string, string>> TriggersAsync(IEnumerable<string?> automationRunIds)
    {
        var ids = automationRunIds.Where(i => i is not null).Select(i => i!).Distinct().ToList();
        return ids.Count == 0 ? [] : await db.Set<AutomationRun>().AsNoTracking().Where(r => ids.Contains(r.Id)).ToDictionaryAsync(r => r.Id, r => r.Trigger);
    }

    public async Task<JsonObject> SnapshotPageAsync(Actor a, string configObjectId, int? limitInput, Keyset.Cursor? cursor)
    {
        var resource = await ResourceAsync(a, configObjectId, LibRole.Viewer);
        var limit = Math.Min(200, Math.Max(1, limitInput ?? 100));
        var query = ReadableSnapshots(a.OrgId, a.MemberId, resource.Object.Id);
        if (cursor is { } c) query = query.Where(r => r.FinishedAt < c.At || (r.FinishedAt == c.At && string.Compare(r.Id, c.Id) < 0));
        var rows = await query.OrderByDescending(r => r.FinishedAt).ThenByDescending(r => r.Id).Take(limit + 1).ToListAsync();
        var page = rows.Take(limit).ToList();
        var triggers = await TriggersAsync(page.Select(r => r.AutomationRunId));
        return new JsonObject
        {
            ["items"] = new JsonArray(page.Select(r => Snapshot(r, r.AutomationRunId is null ? null : triggers.GetValueOrDefault(r.AutomationRunId))).Where(s => s is not null).Select(s => (JsonNode)s!).ToArray()),
            ["nextCursor"] = rows.Count > limit && page.Count > 0 ? Keyset.Encode(page[^1].FinishedAt, page[^1].Id) : null,
        };
    }

    public async Task<JsonObject?> GetSnapshotAsync(Actor a, string configObjectId, string receiptId)
    {
        var resource = await ResourceAsync(a, configObjectId, LibRole.Viewer);
        var id = TypeIds.Receipt(receiptId);
        var row = await ReadableSnapshots(a.OrgId, a.MemberId, resource.Object.Id).FirstOrDefaultAsync(r => r.Id == id);
        return row is null ? null : Snapshot(row, await TriggerOfAsync(row));
    }

    private async Task<string?> TriggerOfAsync(WorkflowRun r) =>
        r.AutomationRunId is null ? null : await db.Set<AutomationRun>().AsNoTracking().Where(x => x.Id == r.AutomationRunId).Select(x => x.Trigger).FirstOrDefaultAsync();

    /// <summary>Erases a run's stored input, result and Markdown, keeping the receipt. Idempotent. Only the person who made the run may (and only if they manage the Workflow).</summary>
    public async Task<JsonObject?> DeleteSnapshotContentAsync(Actor a, string configObjectId, string receiptId)
    {
        var resource = await ResourceAsync(a, configObjectId, LibRole.Manager);
        var id = TypeIds.Receipt(receiptId);
        var row = await db.Set<WorkflowRun>().FirstOrDefaultAsync(r => r.Id == id && r.OrganizationId == a.OrgId && r.MemberId == a.MemberId && r.ConfigObjectId == resource.Object.Id && r.ConfigObjectVersionId != null);
        if (row is null) throw new WorkflowException("workflow_snapshot_not_found");
        if (row.ArtifactContentDeletedAt is null)
        {
            row.ValidatedResultCipher = null;
            row.ResultMarkdownCipher = null;
            row.ArtifactContentDeletedAt = Now();
            await db.SaveChangesAsync();
        }
        if (row.AutomationRunId is not null)
        {
            var automationId = await db.Set<AutomationRun>().Where(r => r.Id == row.AutomationRunId).Select(r => r.AutomationId).FirstOrDefaultAsync();
            if (automationId is not null)
            {
                var retained = await (from w in db.Set<WorkflowRun>().AsNoTracking()
                                      join r in db.Set<AutomationRun>().AsNoTracking() on w.AutomationRunId equals r.Id
                                      where r.AutomationId == automationId && w.ConfigObjectId == resource.Object.Id && w.Status == "succeeded" && w.ArtifactContentDeletedAt == null && w.ResultMarkdownCipher != null
                                      orderby w.FinishedAt descending, w.Id descending
                                      select new { RunId = r.Id, w.ValidatedResultCipher }).FirstOrDefaultAsync();
                var automation = await db.Set<Automation>().FirstOrDefaultAsync(x => x.Id == automationId);
                if (automation is not null)
                {
                    automation.LatestSuccessfulRunId = retained?.RunId;
                    automation.LatestSuccessfulResultJson = retained is null ? null : box.Decrypt(retained.ValidatedResultCipher);
                    await db.SaveChangesAsync();
                }
            }
        }
        return await GetSnapshotAsync(a, configObjectId, id);
    }

    // ---------------------------------------------------------------- detail

    private JsonObject SnapshotFreshness(List<JsonObject> snapshots, long maxAgeMs, out JsonObject? latest, out JsonObject? latestSuccessful)
    {
        latest = snapshots.FirstOrDefault(s => s["contentDeletedAt"] is null) ?? snapshots.FirstOrDefault();
        latestSuccessful = snapshots.FirstOrDefault(s => s["status"]!.GetValue<string>() == "succeeded" && s["markdown"] is not null);
        var l = latest;
        var ls = latestSuccessful;
        return WorkflowArtifacts.Freshness(
            l is not null && l["contentDeletedAt"] is null ? DateTime.Parse(l["finishedAt"]!.GetValue<string>(), null, System.Globalization.DateTimeStyles.RoundtripKind).ToUniversalTime() : null,
            l is not null && l["contentDeletedAt"] is null ? l["status"]!.GetValue<string>() : null,
            ls is null ? null : DateTime.Parse(ls["finishedAt"]!.GetValue<string>(), null, System.Globalization.DateTimeStyles.RoundtripKind).ToUniversalTime(),
            ls?["receiptId"]?.GetValue<string>(), Math.Min(30L * 24 * 60 * 60_000, Math.Max(60_000, maxAgeMs)), l?["errorMessage"]?.GetValue<string>());
    }

    public async Task<JsonObject> DetailAsync(Actor a, string configObjectId, long? maxAgeMs = null)
    {
        var resource = await ResourceAsync(a, configObjectId, LibRole.Viewer);
        var role = await RoleAsync(a, resource.Object.Id);
        var manager = role == LibRole.Manager;
        var automations = (await AutomationReferencesAsync(a)).Where(r => r.ConfigObjectId == resource.Object.Id).Select(r => r.Reference).ToList();
        var versions = (await VersionsAsync(a.OrgId, resource.Object.Id)).Select(v => VersionJson(v, manager, automations)).ToList();
        if (versions.Count == 0) throw new WorkflowException("workflow_version_not_found");
        var rows = await ReadableSnapshots(a.OrgId, a.MemberId, resource.Object.Id).OrderByDescending(r => r.FinishedAt).ThenByDescending(r => r.Id).Take(100).ToListAsync();
        var triggers = await TriggersAsync(rows.Select(r => r.AutomationRunId));
        var snapshots = rows.Select(r => Snapshot(r, r.AutomationRunId is null ? null : triggers.GetValueOrDefault(r.AutomationRunId))).Where(s => s is not null).Select(s => s!).ToList();
        var freshness = SnapshotFreshness(snapshots, maxAgeMs ?? 24L * 60 * 60_000, out var latest, out var latestSuccessful);
        return new JsonObject
        {
            ["pluginId"] = resource.Plugin.Id, ["configObjectId"] = resource.Object.Id, ["title"] = resource.Object.Title, ["description"] = resource.Object.Description,
            ["canRun"] = role is LibRole.Editor or LibRole.Manager, ["canManage"] = manager,
            ["currentVersion"] = versions[0].DeepClone(), ["versions"] = new JsonArray(versions.Select(v => (JsonNode)v).ToArray()),
            ["latestSnapshot"] = latest?.DeepClone(), ["latestSuccessfulSnapshot"] = latestSuccessful?.DeepClone(), ["freshness"] = freshness,
        };
    }

    /// <summary>What a library card needs for one Workflow, worked out the way the detail does.</summary>
    public sealed record Card(string Id, string Name, string? Description, Plugin? Plugin, LibRole Role, List<object> Edges, string State, string ResultState, string? LatestSuccessfulAt, int AutomationCount, List<RequiredCapability> Required, ConfigObject Object);

    public async Task<List<Card>> CardsAsync(Actor a, string? onlyId = null)
    {
        var rows = await (from o in db.Set<ConfigObject>().AsNoTracking()
                          join m in db.Set<PluginConfigObject>().AsNoTracking() on o.Id equals m.ConfigObjectId
                          join p in db.Set<Plugin>().AsNoTracking() on m.PluginId equals p.Id
                          where o.OrganizationId == a.OrgId && o.ObjectType == "workflow" && o.Status == "active" && o.DeletedAt == null && (onlyId == null || o.Id == onlyId)
                                && m.RemovedAt == null && p.OrganizationId == a.OrgId && p.Status == "active" && p.DeletedAt == null
                          orderby o.UpdatedAt descending, o.Id descending, m.CreatedAt, m.Id
                          select new { Object = o, Plugin = p }).ToListAsync();
        if (rows.Count == 0) return [];
        var effective = (await usage.EffectiveAccessAsync(a)).ToDictionary(e => e.Plugin.Id);
        var ids = rows.Select(r => r.Object.Id).Distinct().ToList();
        var roles = await lib.ConfigObjectRolesAsync(a.Aud, ids);
        var grants = (await db.Set<LibraryGrant>().AsNoTracking().Where(g => g.OrganizationId == a.OrgId && g.ResourceKind == GrantKinds.ConfigObject && ids.Contains(g.ResourceId) && g.RemovedAt == null).ToListAsync()).ToLookup(g => g.ResourceId);
        var teamNames = await db.Teams.AsNoTracking().Where(t => t.OrganizationId == a.OrgId && a.TeamIds.Contains(t.Id)).ToDictionaryAsync(t => t.Id, t => t.Name);
        var automations = await AutomationReferencesAsync(a);
        var connections = await UsableConnectionStatesAsync(a);
        var result = new List<Card>();
        foreach (var group in rows.GroupBy(r => r.Object.Id))
        {
            var o = group.First().Object;
            if (!roles.TryGetValue(o.Id, out var role)) continue;
            var versions = await VersionsAsync(a.OrgId, o.Id);
            if (versions.Count == 0) continue;
            var visible = group.FirstOrDefault(r => effective.ContainsKey(r.Plugin.Id));
            var edges = new Dictionary<string, object>();
            foreach (var e in group.SelectMany(r => effective.TryGetValue(r.Plugin.Id, out var ea) ? ea.Edges : []))
                edges[EdgeKey(e)] = e;
            if (o.CreatedByMemberId == a.MemberId) edges["mine"] = new { kind = "mine" };
            foreach (var g in grants[o.Id])
            {
                if (g.MemberId == a.MemberId) edges["person"] = new { kind = "person", sharedBy = (object?)null, grantedAt = Iso(g.CreatedAt) };
                if (g.OrgWide) edges["org_wide"] = new { kind = "org_wide" };
                if (g.TeamId is not null && teamNames.TryGetValue(g.TeamId, out var tn)) edges[$"team:{g.TeamId}"] = new { kind = "team", team = new { id = g.TeamId, name = tn } };
            }
            var snapshots = (await ReadableSnapshots(a.OrgId, a.MemberId, o.Id).OrderByDescending(r => r.FinishedAt).ThenByDescending(r => r.Id).Take(100).ToListAsync())
                .Where(r => r.PluginId is not null).ToList();
            var freshness = FreshnessOf(snapshots);
            var versionIds = versions.Select(v => v.Row.Id).ToHashSet();
            var count = automations.Where(x => x.ConfigObjectId == o.Id && versionIds.Contains(x.Reference["configObjectVersionId"]?.GetValue<string>() ?? "")).Select(x => x.Reference["id"]!.GetValue<string>()).Distinct().Count();
            result.Add(new Card(o.Id, o.Title, o.Description, visible?.Plugin, role, edges.Values.ToList(), Readiness(connections, versions[0].Payload.Required),
                freshness.State, freshness.LatestSuccessfulAt, count, versions[0].Payload.Required, o));
        }
        return result;
    }

    private static string EdgeKey(object edge)
    {
        var node = JsonSerializer.SerializeToNode(edge)!.AsObject();
        var kind = node["kind"]!.GetValue<string>();
        return kind switch { "team" => $"team:{node["team"]!["id"]!.GetValue<string>()}", "catalog" => $"catalog:{node["marketplace"]!["id"]!.GetValue<string>()}", _ => kind };
    }

    private sealed record FreshnessResult(string State, string? LatestSuccessfulAt);

    private FreshnessResult FreshnessOf(List<WorkflowRun> snapshots)
    {
        var latest = snapshots.FirstOrDefault(s => s.ArtifactContentDeletedAt is null) ?? snapshots.FirstOrDefault();
        var success = snapshots.FirstOrDefault(s => s.Status == "succeeded" && s.ResultMarkdownCipher is not null && s.ArtifactContentDeletedAt is null);
        var f = WorkflowArtifacts.Freshness(latest is not null && latest.ArtifactContentDeletedAt is null ? latest.FinishedAt : null, latest is not null && latest.ArtifactContentDeletedAt is null ? latest.Status : null,
            success?.FinishedAt, success?.Id, 24L * 60 * 60_000, latest?.ErrorMessage);
        return new FreshnessResult(f["state"]!.GetValue<string>(), success is null ? null : Iso(success.FinishedAt));
    }

    /// <summary>How ready each connection the person may use is: ready, needs their sign-in, or needs an administrator.</summary>
    private async Task<Dictionary<string, string>> UsableConnectionStatesAsync(Actor a)
    {
        var usable = await connections.UsableAsync(a.OrgId, a.MemberId, a.TeamIds);
        var result = new Dictionary<string, string>();
        foreach (var c in usable)
        {
            var cred = await connections.ResolveCredentialAsync(c, a.MemberId, CancellationToken.None);
            result[c.Id] = cred.Ok ? "ready" : c.CredentialMode == "per_member" ? "needs_signin" : "needs_admin_setup";
        }
        return result;
    }

    private static string Readiness(Dictionary<string, string> connections, List<RequiredCapability> required)
    {
        var state = "ready";
        foreach (var r in required)
        {
            var parsed = ConnectionCapabilityProvider.Parse(r.CapabilityName);
            if (parsed is null) continue;
            var s = connections.TryGetValue(parsed.Value.ConnectionId, out var known) ? known : "needs_admin_setup";
            if (s == "needs_admin_setup") return s;
            if (s == "needs_signin") state = s;
        }
        return state;
    }

    // ---------------------------------------------------------------- listing (what agents and people can run)

    /// <summary>The Workflows shared with a person through the Workflow itself, its plugin, or a marketplace holding the plugin: explicit sharing only.</summary>
    public Task<List<(Plugin Plugin, ConfigObject Object)>> SharedWorkflowsAsync(string orgId, string memberId, HashSet<string> teamIds, string? onlyPluginId = null, string? onlyObjectId = null) =>
        SharedObjectsAsync(orgId, memberId, teamIds, ["workflow", "script"], onlyPluginId, onlyObjectId);

    /// <summary>The same rule for any kind of config object (Workflows, Apps).</summary>
    public async Task<List<(Plugin Plugin, ConfigObject Object)>> SharedObjectsAsync(string orgId, string memberId, HashSet<string> teamIds, string[] types, string? onlyPluginId = null, string? onlyObjectId = null)
    {
        var rows = await (from m in db.Set<PluginConfigObject>().AsNoTracking()
                          join p in db.Set<Plugin>().AsNoTracking() on m.PluginId equals p.Id
                          join o in db.Set<ConfigObject>().AsNoTracking() on m.ConfigObjectId equals o.Id
                          where m.OrganizationId == orgId && m.RemovedAt == null && p.OrganizationId == orgId && p.Status == "active" && p.DeletedAt == null
                                && o.OrganizationId == orgId && types.Contains(o.ObjectType) && o.Status == "active" && o.DeletedAt == null
                                && (onlyPluginId == null || p.Id == onlyPluginId) && (onlyObjectId == null || o.Id == onlyObjectId)
                          orderby m.CreatedAt, m.Id
                          select new { Plugin = p, Object = o }).ToListAsync();
        if (rows.Count == 0) return [];
        var grants = (await db.Set<LibraryGrant>().AsNoTracking().Where(g => g.OrganizationId == orgId && g.RemovedAt == null).ToListAsync())
            .Where(g => g.OrgWide || g.MemberId == memberId || (g.TeamId is not null && teamIds.Contains(g.TeamId))).ToList();
        var objectGrants = grants.Where(g => g.ResourceKind == GrantKinds.ConfigObject).Select(g => g.ResourceId).ToHashSet();
        var pluginGrants = grants.Where(g => g.ResourceKind == GrantKinds.Plugin).Select(g => g.ResourceId).ToHashSet();
        var marketGrants = grants.Where(g => g.ResourceKind == GrantKinds.Marketplace).Select(g => g.ResourceId).ToHashSet();
        var pluginIds = rows.Select(r => r.Plugin.Id).Distinct().ToList();
        var viaMarketplace = (await (from mp in db.Set<MarketplacePlugin>().AsNoTracking()
                                     join mk in db.Set<Marketplace>().AsNoTracking() on mp.MarketplaceId equals mk.Id
                                     where mp.OrganizationId == orgId && pluginIds.Contains(mp.PluginId) && mp.RemovedAt == null && mk.OrganizationId == orgId && mk.Status == "active" && mk.DeletedAt == null
                                     select new { mp.PluginId, MarketplaceId = mk.Id }).ToListAsync()).Where(x => marketGrants.Contains(x.MarketplaceId)).Select(x => x.PluginId).ToHashSet();
        return rows.Where(r => objectGrants.Contains(r.Object.Id) || pluginGrants.Contains(r.Plugin.Id) || viaMarketplace.Contains(r.Plugin.Id)).Select(r => (r.Plugin, r.Object)).ToList();
    }

    public async Task<JsonArray> ListAccessibleAsync(Actor a)
    {
        var seen = new HashSet<string>();
        var items = new List<(string Title, JsonObject Item)>();
        foreach (var (plugin, o) in await SharedWorkflowsAsync(a.OrgId, a.MemberId, a.TeamIds))
        {
            if (!seen.Add(o.Id)) continue;
            var latest = (await VersionsAsync(a.OrgId, o.Id)).FirstOrDefault();
            if (latest is null) { seen.Remove(o.Id); continue; }
            items.Add((o.Title, new JsonObject
            {
                ["pluginId"] = plugin.Id, ["configObjectId"] = o.Id, ["configObjectVersionId"] = latest.Row.Id, ["title"] = o.Title, ["description"] = o.Description,
                ["inputSchema"] = Clone(latest.Payload.InputSchema), ["outputSchema"] = Clone(latest.Payload.OutputSchema), ["requiredCapabilities"] = RequiredJson(latest.Payload.Required),
            }));
        }
        return new JsonArray(items.OrderBy(i => i.Title, StringComparer.InvariantCulture).Select(i => (JsonNode)i.Item).ToArray());
    }

    // ---------------------------------------------------------------- running

    public async Task<string?> RecordAsync(RunRecord r)
    {
        var id = Ids.New("wfr");
        try
        {
            db.Add(new WorkflowRun
            {
                Id = id, OrganizationId = r.OrganizationId, MemberId = r.MemberId, PluginId = r.PluginId, ConfigObjectId = r.ConfigObjectId, ConfigObjectVersionId = r.ConfigObjectVersionId,
                Source = r.Source, CodeDigest = WorkflowArtifacts.CodeDigest(r.Code), Status = r.Status, ErrorKind = r.ErrorKind, ErrorMessage = r.ErrorMessage,
                ToolCallsJson = JsonSerializer.Serialize(r.ToolCalls.Select(n => new { name = n })), ToolCallCount = r.ToolCalls.Count, DurationMs = r.DurationMs,
                StartedAt = r.StartedAt, FinishedAt = r.FinishedAt, ScriptInputDigest = r.ScriptInputDigest, InputSchemaDigest = r.InputSchemaDigest,
                ValidatedResultCipher = r.ValidatedResult is null && r.ResultMarkdown is null ? null : box.Encrypt(r.ValidatedResult?.ToJsonString() ?? "null"),
                ResultMarkdownCipher = r.ResultMarkdown is null ? null : box.Encrypt(r.ResultMarkdown), ResultDigest = r.ResultDigest, OutputSchemaDigest = r.OutputSchemaDigest,
                RendererVersion = r.RendererVersion, CreatedAt = Now(),
            });
            await db.SaveChangesAsync();
            return id;
        }
        catch (DbUpdateException e)
        {
            // A receipt that cannot be written must not hide the result; the run just has no receipt.
            log.LogError(e, "workflow_run_receipt_failed {Source}", r.Source);
            db.ChangeTracker.Clear();
            return null;
        }
    }

    public sealed record RunRequest(string OrganizationId, string UserId, string MemberId, string PluginId, string ConfigObjectId, string? ConfigObjectVersionId, string PayloadJson, string Code,
        string? ReceiptSource, JsonNode? Input, bool ReadOnly, bool ValidateOutput, Func<Task<BuiltTools>> BuildTools);

    /// <summary>Runs a script under a Workflow's declared contract: input checked against its schema, only the capabilities it declared, output checked, a receipt kept.</summary>
    public async Task<WorkflowExecution> ExecuteAsync(RunRequest request, CancellationToken ct)
    {
        var (payload, message) = CodemodePayload.Parse(WorkflowArtifacts.Parse(request.PayloadJson));
        if (payload is null) return new WorkflowExecution.Unsupported(message!);
        var input = request.Input;
        var inputDigest = WorkflowArtifacts.Digest(input);
        var inputSchemaDigest = WorkflowArtifacts.OptionalDigest(payload.InputSchema);
        var outputSchemaDigest = WorkflowArtifacts.OptionalDigest(payload.OutputSchema);
        var source = request.ReadOnly ? $"live:plugin:{request.PluginId}:{request.ConfigObjectId}" : request.ReceiptSource ?? $"plugin:{request.PluginId}:{request.ConfigObjectId}";

        RunRecord Record(string status, string? kind, string? error, IReadOnlyList<string> calls, int duration, DateTime started, DateTime finished, JsonNode? result = null, string? markdown = null, string? resultDigest = null, string? renderer = null) =>
            new(request.OrganizationId, request.MemberId, request.PluginId, request.ConfigObjectId, request.ConfigObjectVersionId, source, request.Code, status, kind, error, calls, duration, started, finished,
                inputDigest, inputSchemaDigest, outputSchemaDigest, result, markdown, resultDigest, renderer);
        Task<string?> Preflight(string kind, string text) { var now = Now(); return RecordAsync(Record("failed", kind, text, [], 0, now, now)); }

        if (payload.InputSchema is not null)
        {
            var (problem, issues) = CodemodePayload.Check(payload.InputSchema, input);
            if (problem == "invalid_schema") return new WorkflowExecution.Unsupported(issues[0]);
            if (problem is not null)
            {
                const string text = "The arguments do not match the Workflow's inputSchema.";
                return new WorkflowExecution.Invalid("invalid_arguments", text, issues, await Preflight("InvalidArguments", text));
            }
        }

        BuiltTools built;
        try { built = await request.BuildTools(); } catch (Exception e) when (e is not OperationCanceledException) { built = BuiltTools.Empty; }
        var (tools, missing) = WorkflowTools.Restrict(built, payload.Required);
        if (missing.Count > 0)
        {
            var text = $"Required capability {missing[0].ScriptPath} ({missing[0].CapabilityName}) is unavailable or disabled for this organization.";
            return new WorkflowExecution.CapabilityUnavailable(text, missing, await Preflight("CapabilityUnavailable", text));
        }

        var o = options.Value;
        var limits = new CodeModeLimits(Math.Min(payload.TimeoutMs ?? o.DefaultTimeoutMs, o.MaxTimeoutMs), payload.MaxToolCalls ?? 1024, payload.MaxOutputBytes ?? 65_536);
        var started = Now();
        var run = await CodeModeRunner.RunAsync(request.Code, input, request.ReadOnly, tools, limits, ct);
        var finished = Now();
        if (!run.Ok)
        {
            var id = await RecordAsync(Record("failed", run.Error!.Kind, run.Error.Message, run.ToolCalls, run.DurationMs, started, finished));
            return new WorkflowExecution.ScriptFailed(run.Error.Message, run.Error.Kind, run.ToolCalls, id);
        }

        if (request.ValidateOutput && payload.OutputSchema is not null)
        {
            var (problem, issues) = CodemodePayload.Check(payload.OutputSchema, run.Value);
            if (problem == "invalid_schema") return new WorkflowExecution.Unsupported(issues[0]);
            if (problem is not null)
            {
                var id = await RecordAsync(Record("failed", "InvalidResult", "The Workflow result did not match its outputSchema.", run.ToolCalls, run.DurationMs, started, finished, resultDigest: WorkflowArtifacts.Digest(run.Value)));
                return new WorkflowExecution.Invalid("invalid_result", "The Workflow result does not match its outputSchema.", issues, id);
            }
        }
        var canonical = WorkflowArtifacts.Canonical(run.Value);
        var canonicalValue = JsonNode.Parse(canonical);
        var markdown = WorkflowArtifacts.RenderMarkdown(canonicalValue);
        var resultDigest = WorkflowArtifacts.Digest(canonicalValue);
        var receiptId = await RecordAsync(request.ValidateOutput
            ? Record("succeeded", null, null, run.ToolCalls, run.DurationMs, started, finished, canonicalValue, markdown, resultDigest, WorkflowArtifacts.RendererVersion)
            : Record("succeeded", null, null, run.ToolCalls, run.DurationMs, started, finished));
        return new WorkflowExecution.Succeeded(canonicalValue, canonical, markdown, resultDigest, inputSchemaDigest, outputSchemaDigest, receiptId, run.Logs.Select(l => l.Trim()).Where(l => l.Length > 0).ToList(), run.ToolCalls, run.DurationMs);
    }

    private async Task<Func<Task<BuiltTools>>> ToolsForAsync(Actor a, bool readOnly)
    {
        await Task.CompletedTask;
        return () => toolFactory.BuildAsync(a.Context.Member.UserId, a.OrgId, readOnly, CancellationToken.None);
    }

    // ---------------------------------------------------------------- draft test

    public sealed record Draft(string Name, string? Description, string Code, JsonNode? ExampleInput, bool HasExampleInput, JsonNode? InputSchema, JsonNode? OutputSchema, List<RequiredCapability> Required);

    private static (JsonObject Value, CodemodePayload Parsed) NormalizedPayload(Draft draft)
    {
        var value = new JsonObject { ["language"] = "codemode-js" };
        if (draft.InputSchema is not null) value["inputSchema"] = draft.InputSchema.DeepClone();
        if (draft.OutputSchema is not null) value["outputSchema"] = draft.OutputSchema.DeepClone();
        if (draft.HasExampleInput) value["exampleInput"] = draft.ExampleInput?.DeepClone();
        value["requiredCapabilities"] = RequiredJson(draft.Required);
        var (parsed, message) = CodemodePayload.Parse(value);
        if (parsed is null) throw new WorkflowException($"workflow_invalid_schema:{message}");
        return (value, parsed);
    }

    private static string DraftSource(string configObjectId, Draft d) =>
        $"workflow-test:{configObjectId}:{WorkflowArtifacts.Digest(new JsonObject { ["name"] = d.Name.Trim(), ["description"] = string.IsNullOrWhiteSpace(d.Description) ? null : d.Description.Trim(), ["requiredCapabilities"] = RequiredJson(d.Required) })}";

    public sealed record TestOutcome(WorkflowExecution Execution, string? FinishedAt, List<RequiredCapability>? Required);

    public async Task<TestOutcome> TestDraftAsync(Actor a, string configObjectId, Draft draft, CancellationToken ct)
    {
        var resource = await ResourceAsync(a, configObjectId, LibRole.Manager);
        var (value, parsed) = NormalizedPayload(draft);
        var execution = await ExecuteAsync(new RunRequest(a.OrgId, a.Context.Member.UserId, a.MemberId, resource.Plugin.Id, resource.Object.Id, null, value.ToJsonString(), draft.Code, DraftSource(resource.Object.Id, draft),
            draft.ExampleInput, false, true, await ToolsForAsync(a, false)), ct);
        if (execution is not WorkflowExecution.Succeeded ok) return new TestOutcome(execution, null, null);
        if (ok.ReceiptId is null) throw new WorkflowException("workflow_test_receipt_not_durable");
        return new TestOutcome(execution, Iso(Now()), parsed.Required);
    }

    // ---------------------------------------------------------------- new versions

    public async Task<JsonObject> CreateVersionAsync(Actor a, string configObjectId, string receiptId, Draft draft)
    {
        var resource = await ResourceAsync(a, configObjectId, LibRole.Manager);
        SourceSafety.AssertSafe(draft.Code);
        var (value, parsed) = NormalizedPayload(draft);
        if (parsed.InputSchema is not null && CodemodePayload.Check(parsed.InputSchema, draft.ExampleInput).Problem is not null) throw new WorkflowException("workflow_current_input_invalid");
        var receiptKey = TypeIds.Receipt(receiptId);
        var codeDigest = WorkflowArtifacts.CodeDigest(draft.Code);
        var scriptInputDigest = WorkflowArtifacts.Digest(draft.ExampleInput);
        var inputSchemaDigest = WorkflowArtifacts.OptionalDigest(parsed.InputSchema);
        var outputSchemaDigest = WorkflowArtifacts.OptionalDigest(parsed.OutputSchema);
        var source = DraftSource(resource.Object.Id, draft);
        var since = Now() - RecentWindow;

        var built = await toolFactory.BuildAsync(a.Context.Member.UserId, a.OrgId, false, CancellationToken.None);
        var manifest = built.Tools.ToDictionary(t => t.CallName, t => t, StringComparer.Ordinal);
        foreach (var required in parsed.Required)
            if (!manifest.TryGetValue(WorkflowTools.CallName(required.ScriptPath), out var current) || current.CapabilityName != required.CapabilityName)
                throw new WorkflowException($"workflow_capability_unavailable:{required.ScriptPath}");

        await using var tx = await db.Database.BeginTransactionAsync();
        // One receipt makes one version, even when two requests present it together.
        await db.LockOrganizationAsync(a.OrgId);
        var receipt = await db.Set<WorkflowRun>().AsNoTracking().FirstOrDefaultAsync(r => r.Id == receiptKey && r.OrganizationId == a.OrgId && r.MemberId == a.MemberId && r.PluginId == resource.Plugin.Id
            && r.ConfigObjectId == resource.Object.Id && r.ConfigObjectVersionId == null && r.Source == source && r.CodeDigest == codeDigest && r.ScriptInputDigest == scriptInputDigest
            && r.InputSchemaDigest == inputSchemaDigest && r.OutputSchemaDigest == outputSchemaDigest && r.Status == "succeeded" && r.ArtifactContentDeletedAt == null && r.FinishedAt > since);
        if (receipt is null || receipt.RendererVersion != WorkflowArtifacts.RendererVersion || receipt.ResultMarkdownCipher is null || receipt.ResultDigest is null)
            throw new WorkflowException("workflow_matching_test_receipt_required");
        if (await db.Set<ConfigObjectVersion>().AnyAsync(v => v.OrganizationId == a.OrgId && v.ConfigObjectId == resource.Object.Id && v.SourceRevisionRef == receipt.Id))
            throw new WorkflowException("workflow_test_receipt_already_used");
        foreach (var call in ParseCalls(receipt.ToolCallsJson))
            if (!parsed.Required.Any(r => WorkflowTools.CallName(r.ScriptPath) == WorkflowTools.CallName("tools." + call)))
                throw new WorkflowException($"workflow_test_capability_mismatch:{call}");

        var now = Now();
        db.Add(new ConfigObjectVersion
        {
            Id = Ids.New("cov"), OrganizationId = a.OrgId, ConfigObjectId = resource.Object.Id, NormalizedPayloadJson = value.ToJsonString(), RawSourceText = draft.Code, SchemaVersion = SchemaVersion,
            CreatedVia = "cloud", CreatedByMemberId = a.MemberId, SourceRevisionRef = receipt.Id, IsDeletedVersion = false, CreatedAt = now,
        });
        var tracked = await db.Set<ConfigObject>().FirstAsync(o => o.Id == resource.Object.Id);
        tracked.Title = draft.Name;
        tracked.Description = string.IsNullOrWhiteSpace(draft.Description) ? null : draft.Description.Trim();
        tracked.SearchText = $"{draft.Name} {draft.Description ?? ""}".Trim();
        tracked.UpdatedAt = now;
        await db.SaveChangesAsync();
        await tx.CommitAsync();
        return await DetailAsync(a, resource.Object.Id);
    }

    private static List<string> ParseCalls(string? json) =>
        json is null ? [] : (JsonNode.Parse(json) as JsonArray)?.Select(c => c?["name"]?.GetValue<string>() ?? "").Where(n => n.Length > 0).ToList() ?? [];

    // ---------------------------------------------------------------- saving a new Workflow from a run

    public sealed record SaveRequest(string? PluginId, string Name, string? Description, string? Code, string? ReceiptId, bool HasCurrentInput, JsonNode? CurrentInput, JsonNode? InputSchema, JsonNode? OutputSchema);

    public async Task<JsonObject> SaveAsync(Actor a, SaveRequest input)
    {
        string? requestedPlugin = null;
        if (input.PluginId is not null)
        {
            requestedPlugin = TypeIds.Plugin(input.PluginId);
            // A plugin the person cannot reach is the same answer whether or not it exists.
            if (await lib.PluginRoleAsync(a, requestedPlugin) is not { } pluginRole || pluginRole < LibRole.Editor) throw new LibraryForbidden("Missing editor access for plugin.");
        }
        AuthoringSource? retained = null;
        string? receiptId = null;
        if (input.ReceiptId is not null)
        {
            try { receiptId = TypeIds.Receipt(input.ReceiptId); } catch (WorkflowException) { throw new WorkflowException("workflow_authoring_receipt_required"); }
            retained = authoring.Get(a.OrgId, a.MemberId, receiptId);
            if (retained is null) throw new WorkflowException("workflow_authoring_receipt_required");
        }
        var code = retained?.Code ?? input.Code;
        if (string.IsNullOrEmpty(code)) throw new WorkflowException("workflow_code_or_receipt_required");
        if (retained is not null && input.Code is not null && input.Code != retained.Code) throw new WorkflowException("workflow_authoring_receipt_required");
        SourceSafety.AssertSafe(code);
        if (retained?.Mode == "live" && input.HasCurrentInput) throw new WorkflowException("workflow_live_current_input_forbidden");
        JsonNode? validationInput = retained?.Mode == "live" ? new JsonObject { ["runtime"] = retained.Runtime?.DeepClone() } : input.CurrentInput;
        if (retained is not null && (retained.InputDigest != WorkflowArtifacts.Digest(validationInput)
            || retained.InputSchemaDigest != WorkflowArtifacts.OptionalDigest(input.InputSchema) || retained.OutputSchemaDigest != WorkflowArtifacts.OptionalDigest(input.OutputSchema)))
            throw new WorkflowException("workflow_authoring_receipt_required");

        var codeDigest = WorkflowArtifacts.CodeDigest(code);
        var since = Now() - RecentWindow;
        var query = db.Set<WorkflowRun>().AsNoTracking().Where(r => r.OrganizationId == a.OrgId && r.MemberId == a.MemberId && r.CodeDigest == codeDigest && r.Status == "succeeded" && r.FinishedAt > since);
        if (receiptId is not null) query = query.Where(r => r.Id == receiptId);
        query = retained is null ? query.Where(r => r.Source != "authoring:live") : query.Where(r => r.Source == retained.Source);
        var receipt = await query.OrderByDescending(r => r.FinishedAt).FirstOrDefaultAsync();
        if (retained is null && receipt?.Source == "authoring:live") throw new WorkflowException("workflow_authoring_receipt_required");
        if (retained is not null)
        {
            var nowCheck = Now();
            if (receipt is null || receipt.Id != retained.ReceiptId || receipt.Source != retained.Source || receipt.CodeDigest != codeDigest || retained.CodeDigest != codeDigest
                || receipt.Status != "succeeded" || receipt.FinishedAt <= nowCheck - RecentWindow || receipt.FinishedAt > nowCheck
                || receipt.ScriptInputDigest != retained.InputDigest || receipt.InputSchemaDigest != retained.InputSchemaDigest || receipt.OutputSchemaDigest != retained.OutputSchemaDigest
                || receipt.ConfigObjectId is not null || receipt.ConfigObjectVersionId is not null || receipt.PluginId is not null || receipt.AutomationRunId is not null || receipt.ArtifactContentDeletedAt is not null)
                throw new WorkflowException("workflow_authoring_receipt_required");
        }
        if (receipt is null) throw new WorkflowException("workflow_recent_receipt_required");

        var built = await toolFactory.BuildAsync(a.Context.Member.UserId, a.OrgId, false, CancellationToken.None);
        var manifest = built.Tools.ToDictionary(t => t.CallName, t => t, StringComparer.Ordinal);
        var required = new List<RequiredCapability>();
        foreach (var call in ParseCalls(receipt.ToolCallsJson))
        {
            if (!manifest.TryGetValue(call, out var tool)) throw new WorkflowException($"workflow_capability_unavailable:{call}");
            if (!required.Any(r => r.ScriptPath == tool.ScriptPath)) required.Add(new RequiredCapability(tool.CapabilityName, tool.ScriptPath));
        }
        var payload = new JsonObject { ["language"] = "codemode-js" };
        if (input.InputSchema is not null) payload["inputSchema"] = input.InputSchema.DeepClone();
        if (input.OutputSchema is not null) payload["outputSchema"] = input.OutputSchema.DeepClone();
        if (retained?.Mode != "live" && input.HasCurrentInput) payload["exampleInput"] = input.CurrentInput?.DeepClone();
        payload["requiredCapabilities"] = RequiredJson(required);
        var (parsed, message) = CodemodePayload.Parse(payload);
        if (parsed is null) throw new WorkflowException($"workflow_invalid_schema:{message}");
        if (parsed.InputSchema is not null && CodemodePayload.Check(parsed.InputSchema, retained is not null ? validationInput : validationInput).Problem is not null) throw new WorkflowException("workflow_current_input_invalid");
        var graph = WorkflowGraph.Analyze(code);
        if (retained is not null && authoring.Get(a.OrgId, a.MemberId, retained.ReceiptId) is null) throw new WorkflowException("workflow_authoring_receipt_required");

        await using var tx = await db.Database.BeginTransactionAsync();
        // Finding or making the plugin and the Workflow is one decision per workspace.
        await db.LockOrganizationAsync(a.OrgId);
        var now = Now();
        Plugin? pluginRow;
        if (requestedPlugin is not null)
        {
            pluginRow = await db.Set<Plugin>().FirstOrDefaultAsync(p => p.Id == requestedPlugin && p.OrganizationId == a.OrgId && p.Status == "active" && p.DeletedAt == null)
                ?? throw new WorkflowException("saved_workflow_plugin_not_found");
        }
        else
        {
            pluginRow = await db.Set<Plugin>().FirstOrDefaultAsync(p => p.OrganizationId == a.OrgId && p.CreatedByMemberId == a.MemberId && p.Name == DefaultPluginName && p.Status == "active" && p.DeletedAt == null)
                ?? await db.Set<Plugin>().FirstOrDefaultAsync(p => p.OrganizationId == a.OrgId && p.CreatedByMemberId == a.MemberId && LegacyPluginNames.Contains(p.Name) && p.Status == "active" && p.DeletedAt == null);
        }
        if (pluginRow is null)
        {
            pluginRow = new Plugin { Id = Ids.New("plg"), OrganizationId = a.OrgId, Name = DefaultPluginName, Description = "Private reusable Workflows.", Status = "active", CreatedByMemberId = a.MemberId, CreatedAt = now, UpdatedAt = now };
            db.Add(pluginRow);
            db.Add(LibraryStore.NewGrant(a, GrantKinds.Plugin, pluginRow.Id, "m:" + a.MemberId, a.MemberId, null, false, "manager", "pag", now));
        }
        else if (requestedPlugin is null && LegacyPluginNames.Contains(pluginRow.Name))
        {
            pluginRow.Name = DefaultPluginName;
            pluginRow.Description = "Private reusable Workflows.";
            pluginRow.UpdatedAt = now;
        }
        var linked = await (from m in db.Set<PluginConfigObject>()
                            join o in db.Set<ConfigObject>() on m.ConfigObjectId equals o.Id
                            where m.PluginId == pluginRow.Id && m.RemovedAt == null && o.Title == input.Name && (o.ObjectType == "script" || o.ObjectType == "workflow") && o.Status == "active" && o.DeletedAt == null
                            select o).FirstOrDefaultAsync();
        string configObjectId;
        if (linked is not null)
        {
            configObjectId = linked.Id;
            // Plugin edit access can widen the audience, but never replaces another manager's executable code.
            if (await lib.ConfigObjectRoleAsync(a, configObjectId) is not { } role || role < LibRole.Manager) throw new LibraryForbidden("Missing manager access for config object.");
            linked.UpdatedAt = now;
        }
        else
        {
            configObjectId = Ids.New("cob");
            db.Add(new ConfigObject
            {
                Id = configObjectId, OrganizationId = a.OrgId, ObjectType = "workflow", SourceMode = "cloud", Title = input.Name, Description = string.IsNullOrWhiteSpace(input.Description) ? null : input.Description.Trim(),
                SearchText = $"{input.Name} {input.Description ?? ""}".Trim(), Status = "active", CreatedByMemberId = a.MemberId, CreatedAt = now, UpdatedAt = now,
            });
            db.Add(new PluginConfigObject { Id = Ids.New("pco"), OrganizationId = a.OrgId, PluginId = pluginRow.Id, ConfigObjectId = configObjectId, MembershipSource = "manual", CreatedByMemberId = a.MemberId, CreatedAt = now });
            db.Add(LibraryStore.NewGrant(a, GrantKinds.ConfigObject, configObjectId, "m:" + a.MemberId, a.MemberId, null, false, "manager", "coa", now));
        }
        var versionId = Ids.New("cov");
        db.Add(new ConfigObjectVersion
        {
            Id = versionId, OrganizationId = a.OrgId, ConfigObjectId = configObjectId, NormalizedPayloadJson = payload.ToJsonString(), RawSourceText = code, SchemaVersion = SchemaVersion,
            CreatedVia = "cloud", CreatedByMemberId = a.MemberId, SourceRevisionRef = receipt.CodeDigest, IsDeletedVersion = false, CreatedAt = now,
        });
        await db.SaveChangesAsync();
        await tx.CommitAsync();
        return new JsonObject { ["pluginId"] = pluginRow.Id, ["configObjectId"] = configObjectId, ["configObjectVersionId"] = versionId, ["graph"] = graph, ["mermaid"] = WorkflowGraph.ToMermaid(graph) };
    }

    // ---------------------------------------------------------------- running a saved version

    /// <summary>The Workflow's version and the plugin it runs under, if the person was shared it (a grant on it, its plugin, or a marketplace). The reference answers 400 with these names.</summary>
    public async Task<(string? Error, string? Message, (Plugin Plugin, ConfigObject Object, ConfigObjectVersion Version)? Found)> FindRunnableAsync(Actor a, string pluginId, string configObjectId, string? versionId) =>
        await FindRunnableAsync(Who.Of(a), pluginId, configObjectId, versionId);

    public async Task<(string? Error, string? Message, (Plugin Plugin, ConfigObject Object, ConfigObjectVersion Version)? Found)> FindRunnableAsync(Who a, string pluginId, string configObjectId, string? versionId)
    {
        string p, o;
        try { p = TypeIds.Plugin(pluginId); o = TypeIds.ConfigObject(configObjectId); }
        catch (WorkflowException) { return ("unknown_capability", "No such capability.", null); }
        var exists = await (from m in db.Set<PluginConfigObject>().AsNoTracking()
                            join pl in db.Set<Plugin>().AsNoTracking() on m.PluginId equals pl.Id
                            join co in db.Set<ConfigObject>().AsNoTracking() on m.ConfigObjectId equals co.Id
                            where m.OrganizationId == a.OrgId && m.PluginId == p && m.ConfigObjectId == o && m.RemovedAt == null && pl.OrganizationId == a.OrgId && pl.Status == "active" && pl.DeletedAt == null
                                  && co.OrganizationId == a.OrgId && co.Status == "active" && co.DeletedAt == null
                            select new { Plugin = pl, Object = co }).FirstOrDefaultAsync();
        if (exists is null) return ("unknown_capability", "No such capability.", null);
        var shared = await SharedWorkflowsAsync(a.OrgId, a.MemberId, a.TeamIds, p, o);
        if (shared.Count == 0) return ("forbidden", "You have not been granted access to this plugin capability.", null);
        ConfigObjectVersion? version;
        if (versionId is not null)
        {
            string vid;
            try { vid = TypeIds.ConfigObjectVersion(versionId); } catch (WorkflowException) { return ("content_not_synced", "content_not_synced", null); }
            version = await db.Set<ConfigObjectVersion>().AsNoTracking().FirstOrDefaultAsync(v => v.Id == vid && v.ConfigObjectId == o && v.OrganizationId == a.OrgId && !v.IsDeletedVersion);
        }
        else version = (await VersionsAsync(a.OrgId, o)).FirstOrDefault()?.Row;
        if (version is null) return ("content_not_synced", "This capability's content has not been synced yet.", null);
        return (null, null, (exists.Plugin, exists.Object, version));
    }

    public Task<WorkflowExecution?> RunSavedAsync(Actor a, (Plugin Plugin, ConfigObject Object, ConfigObjectVersion Version) found, JsonNode? input, bool live, string? timeZone, CancellationToken ct) =>
        RunSavedAsync(Who.Of(a), found, input, live, timeZone, live, ct);

    public async Task<WorkflowExecution?> RunSavedAsync(Who a, (Plugin Plugin, ConfigObject Object, ConfigObjectVersion Version) found, JsonNode? input, bool live, string? timeZone, bool validateOutput, CancellationToken ct)
    {
        JsonNode? scriptInput = input;
        if (live) scriptInput = new JsonObject { ["runtime"] = ArtifactRuntime.Build(timeZone) };
        return await ExecuteAsync(new RunRequest(a.OrgId, a.UserId, a.MemberId, found.Plugin.Id, found.Object.Id, found.Version.Id, found.Version.NormalizedPayloadJson ?? "null", found.Version.RawSourceText ?? "",
            null, scriptInput, live, validateOutput, () => toolFactory.BuildAsync(a.UserId, a.OrgId, live, CancellationToken.None)), ct);
    }

    /// <summary>The reference's words for a Workflow whose version content is missing.</summary>
    public async Task<string> NotSyncedHintAsync(Actor a, string pluginId, string configObjectId)
    {
        var plugin = await db.Set<Plugin>().AsNoTracking().Where(p => p.Id == pluginId && p.OrganizationId == a.OrgId).Select(p => p.Name).FirstOrDefaultAsync() ?? "";
        var title = await db.Set<ConfigObject>().AsNoTracking().Where(o => o.Id == configObjectId && o.OrganizationId == a.OrgId).Select(o => o.Title).FirstOrDefaultAsync() ?? "";
        return $"Marketplace plugin \"{plugin}\" has not synced content for \"{title}\" yet. Connect or sync the source, then try again.";
    }

    /// <summary>Runs the Workflow's newest version live (read-only) for an app, after checking its output schema is the one the app was built for.</summary>
    public async Task<(WorkflowExecution Execution, string? Error)> RunLiveForAppAsync(Actor a, string configObjectId, string expectedOutputSchemaDigest, string? timeZone, CancellationToken ct)
    {
        var resource = await ResourceAsync(a, configObjectId, LibRole.Viewer);
        var version = (await VersionsAsync(a.OrgId, resource.Object.Id)).FirstOrDefault() ?? throw new WorkflowException("workflow_version_not_found");
        if (version.Payload.OutputSchema is null || WorkflowArtifacts.OptionalDigest(version.Payload.OutputSchema) != expectedOutputSchemaDigest) throw new WorkflowException("artifact_view_schema_incompatible");
        var execution = await ExecuteAsync(new RunRequest(a.OrgId, a.Context.Member.UserId, a.MemberId, resource.Plugin.Id, resource.Object.Id, version.Row.Id, version.Row.NormalizedPayloadJson ?? "null", version.Row.RawSourceText ?? "",
            null, new JsonObject { ["runtime"] = ArtifactRuntime.Build(timeZone) }, true, true, await ToolsForAsync(a, true)), ct);
        return (execution, null);
    }

    // ---------------------------------------------------------------- run receipts list

    public async Task<JsonObject> RunsAsync(Actor a, int limit, Keyset.Cursor? cursor)
    {
        var query = db.Set<WorkflowRun>().AsNoTracking().Where(r => r.OrganizationId == a.OrgId && r.MemberId == a.MemberId);
        if (cursor is { } c) query = query.Where(r => r.CreatedAt < c.At || (r.CreatedAt == c.At && string.Compare(r.Id, c.Id) < 0));
        var rows = await query.OrderByDescending(r => r.CreatedAt).ThenByDescending(r => r.Id).Take(limit + 1).ToListAsync();
        var page = rows.Take(limit).ToList();
        var previews = await PreviewsAsync(a, page);
        return new JsonObject
        {
            ["runs"] = new JsonArray(page.Select(r => (JsonNode)new JsonObject
            {
                ["id"] = r.Id, ["source"] = r.Source, ["status"] = r.Status, ["errorKind"] = r.ErrorKind, ["errorMessage"] = r.ErrorMessage, ["toolCallCount"] = r.ToolCallCount,
                ["toolCalls"] = ToolCallsJson(r.ToolCallsJson), ["durationMs"] = r.DurationMs, ["startedAt"] = Iso(r.StartedAt), ["finishedAt"] = Iso(r.FinishedAt), ["createdAt"] = Iso(r.CreatedAt),
                ["orgMembershipId"] = r.MemberId, ["workflow"] = previews.GetValueOrDefault(r.Id)?.DeepClone(),
            }).ToArray()),
            ["nextCursor"] = rows.Count > limit && page.Count > 0 ? Keyset.Encode(page[^1].CreatedAt, page[^1].Id) : null,
        };
    }

    /// <summary>For each run of a Workflow the person may still read, the Workflow's title and the call graph of the version it ran (source-derived labels hidden unless they manage it).</summary>
    private async Task<Dictionary<string, JsonObject>> PreviewsAsync(Actor a, List<WorkflowRun> runs)
    {
        var result = new Dictionary<string, JsonObject>();
        var objectIds = runs.Where(r => r.ConfigObjectId is not null).Select(r => r.ConfigObjectId!).Distinct().ToList();
        if (objectIds.Count == 0) return result;
        var roles = await lib.ConfigObjectRolesAsync(a.Aud, objectIds);
        var objects = await db.Set<ConfigObject>().AsNoTracking().Where(o => o.OrganizationId == a.OrgId && objectIds.Contains(o.Id) && o.ObjectType == "workflow" && o.Status == "active" && o.DeletedAt == null).ToListAsync();
        var inPlugin = (await (from m in db.Set<PluginConfigObject>().AsNoTracking()
                               join p in db.Set<Plugin>().AsNoTracking() on m.PluginId equals p.Id
                               where m.OrganizationId == a.OrgId && objectIds.Contains(m.ConfigObjectId) && m.RemovedAt == null && p.Status == "active" && p.DeletedAt == null
                               select m.ConfigObjectId).ToListAsync()).ToHashSet();
        var visible = objects.Where(o => roles.ContainsKey(o.Id) && inPlugin.Contains(o.Id)).ToDictionary(o => o.Id);
        var versionIds = runs.Where(r => r.ConfigObjectVersionId is not null && r.ConfigObjectId is not null && visible.ContainsKey(r.ConfigObjectId)).Select(r => r.ConfigObjectVersionId!).Distinct().ToList();
        var versions = versionIds.Count == 0 ? [] : await db.Set<ConfigObjectVersion>().AsNoTracking().Where(v => v.OrganizationId == a.OrgId && versionIds.Contains(v.Id) && !v.IsDeletedVersion).ToDictionaryAsync(v => v.Id);
        foreach (var run in runs)
        {
            if (run.ConfigObjectId is null || !visible.TryGetValue(run.ConfigObjectId, out var o)) continue;
            JsonObject? graph = null;
            if (run.ConfigObjectVersionId is not null && versions.TryGetValue(run.ConfigObjectVersionId, out var v) && v.ConfigObjectId == run.ConfigObjectId && v.RawSourceText is not null)
            {
                graph = WorkflowGraph.Analyze(v.RawSourceText);
                if (roles[o.Id] != LibRole.Manager) graph = WorkflowGraph.Redact(graph);
            }
            result[run.Id] = new JsonObject { ["configObjectId"] = o.Id, ["title"] = o.Title, ["graph"] = graph };
        }
        return result;
    }
}

/// <summary>The runtime facts a live run gives a script as <c>input.runtime</c>: now, today, and the day's bounds in a time zone.</summary>
public static class ArtifactRuntime
{
    public static bool ValidZone(string zone)
    {
        try { _ = TimeZoneInfo.FindSystemTimeZoneById(zone); return true; }
        catch (Exception e) when (e is TimeZoneNotFoundException or InvalidTimeZoneException) { return false; }
    }

    public static JsonObject Build(string? timeZone = null, DateTime? at = null)
    {
        var zone = timeZone ?? "UTC";
        var tz = TimeZoneInfo.FindSystemTimeZoneById(zone);
        var now = (at ?? DateTime.UtcNow);
        now = new DateTime(now.Ticks - now.Ticks % TimeSpan.TicksPerMillisecond, DateTimeKind.Utc);
        var local = TimeZoneInfo.ConvertTimeFromUtc(now, tz);
        var today = local.Date;
        DateTime Boundary(DateTime date) => TimeZoneInfo.ConvertTimeToUtc(DateTime.SpecifyKind(date, DateTimeKind.Unspecified), tz);
        static string Z(DateTime d) => Responses.IsoUtc(d);
        return new JsonObject { ["now"] = Z(now), ["today"] = today.ToString("yyyy-MM-dd"), ["timeZone"] = zone, ["dayStart"] = Z(Boundary(today)), ["dayEnd"] = Z(Boundary(today.AddDays(1))) };
    }
}

/// <summary>Keyset pages: a cursor is the sort key of the last row, base64url of <c>{"at": ms, "id": …}</c>, opaque to clients.</summary>
public static class Keyset
{
    public sealed record Cursor(DateTime At, string Id);

    public static string Encode(DateTime at, string id)
    {
        var ms = new DateTimeOffset(DateTime.SpecifyKind(at, DateTimeKind.Utc)).ToUnixTimeMilliseconds();
        return Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(new { at = ms, id })).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public static Cursor? Decode(string value)
    {
        if (value.Length is < 1 or > 200 || !System.Text.RegularExpressions.Regex.IsMatch(value, "^[A-Za-z0-9_-]+$")) return null;
        try
        {
            var s = value.Replace('-', '+').Replace('_', '/');
            s = s.PadRight(s.Length + (4 - s.Length % 4) % 4, '=');
            using var doc = JsonDocument.Parse(Convert.FromBase64String(s));
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("at", out var at) || at.ValueKind != JsonValueKind.Number || !at.TryGetInt64(out var ms)
                || !root.TryGetProperty("id", out var id) || id.ValueKind != JsonValueKind.String || id.GetString() is not { Length: >= 1 and <= 160 } idText) return null;
            return new Cursor(DateTimeOffset.FromUnixTimeMilliseconds(ms).UtcDateTime, idText);
        }
        catch (Exception e) when (e is FormatException or JsonException or ArgumentOutOfRangeException) { return null; }
    }
}
