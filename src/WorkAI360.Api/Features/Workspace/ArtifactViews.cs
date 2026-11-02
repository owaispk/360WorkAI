using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Library;
using WorkAI360.Api.Domain.Workspace;
using WorkAI360.Api.Features.Library;

namespace WorkAI360.Api.Features.Workspace;

/// <summary>
/// Generated views ("apps") bound to a Workflow: the list a Workflow has, rolling a view back or forward to one of its revisions, retiring it, and a
/// person's saved apps and dashboard. A view is readable by whoever may read its Workflow and changed only by that Workflow's managers. A view or
/// revision of another workspace reads as not found. Revisions are written by an app builder (React compilation), which this build does not
/// include: only what already exists is served.
/// </summary>
public sealed class ArtifactViewService(DenDbContext db, WorkflowService workflows, LibraryStore store, IOptions<WorkspaceOptions> options)
{
    private const int ViewListLimit = 50;
    private const int RevisionListLimit = 50;

    public bool Enabled => options.Value.GeneratedArtifactViewsEnabled;

    /// <summary>When apps are their own MCP servers, Workflow-bound views keep opening and refreshing but cannot be activated or saved.</summary>
    private bool LegacyReadOnly => options.Value.AppMcpServersEnabled;

    public static string ResourceUri(string viewId, string revisionId) => $"ui://openwork/artifacts/{viewId}/views/{revisionId}/index.html";

    private static string Iso(DateTime d) => Responses.IsoUtc(d);

    private static JsonObject RevisionJson(ArtifactViewRevision r) => new()
    {
        ["id"] = r.Id, ["artifactViewId"] = r.ArtifactViewId, ["resourceUri"] = ResourceUri(r.ArtifactViewId, r.Id), ["buildStatus"] = r.BuildStatus, ["sourceDigest"] = r.SourceDigest,
        ["resourceDigest"] = r.ResourceDigest, ["outputSchemaDigest"] = r.OutputSchemaDigest, ["csp"] = JsonNode.Parse(r.CspJson), ["diagnostics"] = JsonNode.Parse(r.BuildDiagnosticsJson),
        ["compilerName"] = r.CompilerName, ["compilerVersion"] = r.CompilerVersion, ["reactVersion"] = r.ReactVersion, ["compiledHtmlBytes"] = r.CompiledHtmlBytes,
        ["retiredAt"] = r.RetiredAt is { } t ? Iso(t) : null, ["createdAt"] = Iso(r.CreatedAt),
    };

    private static JsonObject ViewJson(ArtifactView v, IEnumerable<ArtifactViewRevision> revisions) => new()
    {
        ["id"] = v.Id, ["configObjectId"] = v.ConfigObjectId, ["title"] = v.Title, ["description"] = v.Description, ["status"] = v.Status, ["activeRevisionId"] = v.ActiveRevisionId,
        ["useInWorkflow"] = v.UseInWorkflow, ["dataMode"] = v.DataMode, ["revisions"] = new JsonArray(revisions.Select(r => (JsonNode)RevisionJson(r)).ToArray()),
        ["createdAt"] = Iso(v.CreatedAt), ["updatedAt"] = Iso(v.UpdatedAt),
    };

    /// <summary>The revisions to show for a view: the newest 50, plus the active one when it is older, newest first (a rollback must stay renderable).</summary>
    private async Task<Dictionary<string, List<ArtifactViewRevision>>> RevisionsAsync(IReadOnlyCollection<ArtifactView> views)
    {
        var result = new Dictionary<string, List<ArtifactViewRevision>>();
        foreach (var v in views)
        {
            var rows = (await db.Set<ArtifactViewRevision>().AsNoTracking().Where(r => r.ArtifactViewId == v.Id).ToListAsync())
                .OrderByDescending(r => r.CreatedAt).ThenByDescending(r => r.Id, StringComparer.Ordinal).ToList();
            var shown = rows.Take(RevisionListLimit).ToList();
            if (v.ActiveRevisionId is not null && shown.All(r => r.Id != v.ActiveRevisionId) && rows.FirstOrDefault(r => r.Id == v.ActiveRevisionId) is { } active) shown.Add(active);
            result[v.Id] = shown;
        }
        return result;
    }

    // ---------------------------------------------------------------- access

    public sealed record WorkflowAccess(string ConfigObjectId, string Title, bool CanManage);

    /// <summary>Whether the person may read the Workflow (and it has a version that can be read), and whether they manage it.</summary>
    public async Task<WorkflowAccess> WorkflowAccessAsync(Actor a, string configObjectId)
    {
        var resource = await workflows.ResourceAsync(a, configObjectId, LibRole.Viewer);
        var role = await workflows.RoleAsync(a, resource.Object.Id);
        if ((await workflows.VersionsAsync(a.OrgId, resource.Object.Id)).Count == 0) throw new WorkflowException("workflow_version_not_found");
        return new WorkflowAccess(resource.Object.Id, resource.Object.Title, role == LibRole.Manager);
    }

    private async Task<ArtifactView> AccessibleAsync(Actor a, string viewId, bool manage)
    {
        var id = TypeIds.ArtifactView(viewId);
        var row = await db.Set<ArtifactView>().FirstOrDefaultAsync(v => v.Id == id && v.OrganizationId == a.OrgId) ?? throw new WorkflowException("artifact_view_not_found");
        var access = await WorkflowAccessAsync(a, row.ConfigObjectId);
        if (manage && !access.CanManage) throw new WorkflowException("artifact_view_not_found");
        return row;
    }

    // ---------------------------------------------------------------- views of a Workflow

    public async Task<JsonArray> ListForWorkflowAsync(Actor a, string configObjectId)
    {
        var access = await WorkflowAccessAsync(a, configObjectId);
        var views = (await db.Set<ArtifactView>().AsNoTracking().Where(v => v.OrganizationId == a.OrgId && v.ConfigObjectId == access.ConfigObjectId).ToListAsync())
            .OrderByDescending(v => v.UpdatedAt).ThenByDescending(v => v.Id, StringComparer.Ordinal).ToList();
        var revisions = await RevisionsAsync(views);
        return new JsonArray(views.Select(v => (JsonNode)ViewJson(v, revisions[v.Id])).ToArray());
    }

    /// <summary>Views of many Workflows the person can already read, keyed by Workflow.</summary>
    public async Task<Dictionary<string, List<JsonObject>>> ListForWorkflowsAsync(Actor a, IReadOnlyCollection<string> configObjectIds)
    {
        var result = new Dictionary<string, List<JsonObject>>();
        if (configObjectIds.Count == 0 || !Enabled) return result;
        var views = (await db.Set<ArtifactView>().AsNoTracking().Where(v => v.OrganizationId == a.OrgId && configObjectIds.Contains(v.ConfigObjectId)).ToListAsync())
            .OrderByDescending(v => v.UpdatedAt).ThenByDescending(v => v.Id, StringComparer.Ordinal).ToList();
        var revisions = await RevisionsAsync(views);
        foreach (var v in views)
        {
            if (!result.TryGetValue(v.ConfigObjectId, out var list)) result[v.ConfigObjectId] = list = [];
            list.Add(ViewJson(v, revisions[v.Id]));
        }
        return result;
    }

    public async Task<JsonObject> ActivateAsync(Actor a, string viewId, string revisionId, (string Title, bool UseInWorkflow, string? ExpectedActiveRevisionId)? save = null)
    {
        if (LegacyReadOnly) throw new WorkflowException("legacy_view_read_only");
        var view = await AccessibleAsync(a, viewId, manage: true);
        var rid = TypeIds.ArtifactViewRevision(revisionId);
        var revision = await db.Set<ArtifactViewRevision>().AsNoTracking().FirstOrDefaultAsync(r => r.Id == rid && r.ArtifactViewId == view.Id && r.BuildStatus == "ready" && r.RetiredAt == null);
        if (revision is null || revision.CompiledHtml is null || revision.ResourceDigest is null) throw new WorkflowException("artifact_view_revision_not_ready");
        var script = await workflows.DetailAsync(a, view.ConfigObjectId);
        if (script["currentVersion"]!["outputSchemaDigest"]?.GetValue<string>() != revision.OutputSchemaDigest) throw new WorkflowException("artifact_view_schema_incompatible");

        await using var tx = await db.Database.BeginTransactionAsync();
        // Two activations of one view at once take turns: the second sees what the first saved.
        await db.LockOrganizationAsync(a.OrgId);
        var current = await db.Set<ArtifactView>().FirstOrDefaultAsync(v => v.Id == view.Id) ?? throw new WorkflowException("artifact_view_not_found");
        if (save is { } s && current.ActiveRevisionId != s.ExpectedActiveRevisionId) throw new WorkflowException("app_changed_since_preview");
        current.Status = "active";
        current.ActiveRevisionId = revision.Id;
        current.UpdatedAt = WorkflowService.Now();
        if (save is { } saved)
        {
            current.Title = saved.Title;
            current.UseInWorkflow = saved.UseInWorkflow;
            // The Workflow and this exact revision become one dashboard entry; a failed activation leaves no card behind.
            if (!await db.Set<DashboardApp>().AnyAsync(d => d.OrganizationId == a.OrgId && d.MemberId == a.MemberId && d.ArtifactViewId == view.Id))
                db.Add(new DashboardApp { OrganizationId = a.OrgId, MemberId = a.MemberId, ArtifactViewId = view.Id, CreatedAt = WorkflowService.Now() });
        }
        await db.SaveChangesAsync();
        await tx.CommitAsync();
        return ViewJson(current, (await RevisionsAsync([current]))[current.Id]);
    }

    public async Task<JsonObject> RetireAsync(Actor a, string viewId)
    {
        var view = await AccessibleAsync(a, viewId, manage: true);
        await using var tx = await db.Database.BeginTransactionAsync();
        await db.LockOrganizationAsync(a.OrgId);
        var current = await db.Set<ArtifactView>().FirstAsync(v => v.Id == view.Id);
        current.Status = "retired";
        current.ActiveRevisionId = null;
        current.UseInWorkflow = false;
        current.UpdatedAt = WorkflowService.Now();
        db.RemoveRange(await db.Set<DashboardApp>().Where(d => d.OrganizationId == a.OrgId && d.ArtifactViewId == view.Id).ToListAsync());
        await db.SaveChangesAsync();
        await tx.CommitAsync();
        return ViewJson(current, (await RevisionsAsync([current]))[current.Id]);
    }

    // ---------------------------------------------------------------- saved apps

    private async Task<(JsonObject View, WorkflowAccess Workflow)> GetViewAsync(Actor a, string viewId)
    {
        var view = await AccessibleAsync(a, viewId, manage: false);
        var access = await WorkflowAccessAsync(a, view.ConfigObjectId);
        return (ViewJson(view, (await RevisionsAsync([view]))[view.Id]), access);
    }

    public async Task<JsonArray> ListSavedAsync(Actor a)
    {
        var rows = (await db.Set<ArtifactView>().AsNoTracking().Where(v => v.OrganizationId == a.OrgId && v.Status == "active" && v.ActiveRevisionId != null).ToListAsync())
            .OrderByDescending(v => v.UpdatedAt).ThenByDescending(v => v.Id, StringComparer.Ordinal).Take(ViewListLimit).ToList();
        var access = new Dictionary<string, WorkflowAccess>();
        foreach (var id in rows.Select(v => v.ConfigObjectId).Distinct())
        {
            try { access[id] = await WorkflowAccessAsync(a, id); }
            catch (Exception e) when (e is WorkflowException or LibraryForbidden or LibraryFailure) { /* unreadable Workflows leave their apps out */ }
        }
        var visible = rows.Where(v => access.ContainsKey(v.ConfigObjectId)).ToList();
        var revisions = await RevisionsAsync(visible);
        var onDashboard = (await db.Set<DashboardApp>().AsNoTracking().Where(d => d.OrganizationId == a.OrgId && d.MemberId == a.MemberId).Select(d => d.ArtifactViewId).ToListAsync()).ToHashSet();
        return new JsonArray(visible.Select(v => (JsonNode)new JsonObject
        {
            ["view"] = ViewJson(v, revisions[v.Id]), ["workflowTitle"] = access[v.ConfigObjectId].Title, ["canManage"] = access[v.ConfigObjectId].CanManage, ["onDashboard"] = onDashboard.Contains(v.Id),
        }).ToArray());
    }

    public async Task SetOnDashboardAsync(Actor a, string viewId, bool added)
    {
        var id = TypeIds.ArtifactView(viewId);
        if (!added)
        {
            // Removal still works after access to the app was revoked.
            db.RemoveRange(await db.Set<DashboardApp>().Where(d => d.OrganizationId == a.OrgId && d.MemberId == a.MemberId && d.ArtifactViewId == id).ToListAsync());
            await db.SaveChangesAsync();
            return;
        }
        var (view, _) = await GetViewAsync(a, id);
        if (view["status"]!.GetValue<string>() != "active" || view["activeRevisionId"] is null) throw new WorkflowException("artifact_view_not_found");
        await PlaceAsync(a.OrgId, a.MemberId, id);
    }

    private async Task PlaceAsync(string orgId, string memberId, string viewId)
    {
        if (await db.Set<DashboardApp>().AnyAsync(d => d.OrganizationId == orgId && d.MemberId == memberId && d.ArtifactViewId == viewId)) return;
        db.Add(new DashboardApp { OrganizationId = orgId, MemberId = memberId, ArtifactViewId = viewId, CreatedAt = WorkflowService.Now() });
        try { await db.SaveChangesAsync(); }
        catch (DbUpdateException) { db.ChangeTracker.Clear(); /* placed by a request at the same moment */ }
    }

    /// <summary>Shares through the Workflow's own access (viewer, never lowering an existing grant) and puts the app on the teammate's dashboard. Result data is never copied.</summary>
    public async Task ShareAsync(Actor a, string appId, string email)
    {
        var (view, workflow) = await GetViewAsync(a, appId);
        if (view["status"]!.GetValue<string>() != "active" || view["activeRevisionId"] is null) throw new WorkflowException("artifact_view_not_found");
        if (!workflow.CanManage) throw new LibraryForbidden("Missing manager access for config object.");
        var normalized = email.Trim().ToLowerInvariant();
        var member = await (from m in db.Members.AsNoTracking()
                            join u in db.Users.AsNoTracking() on m.UserId equals u.Id
                            where m.OrganizationId == a.OrgId && u.Email == normalized
                            select m.Id).FirstOrDefaultAsync();
        if (member is null) throw new WorkflowException("teammate_not_found");
        var has = await db.Set<LibraryGrant>().AnyAsync(g => g.OrganizationId == a.OrgId && g.ResourceKind == GrantKinds.ConfigObject && g.ResourceId == workflow.ConfigObjectId && g.MemberId == member && g.RemovedAt == null);
        if (!has) await store.GrantAsync(a, GrantKinds.ConfigObject, workflow.ConfigObjectId, member, null, false, "viewer");
        await PlaceAsync(a.OrgId, member, view["id"]!.GetValue<string>());
    }

    public async Task<JsonObject> GetSavedAsync(Actor a, string appId, string? revisionId, string? receiptId, string? timeZone, CancellationToken ct)
    {
        var id = TypeIds.ArtifactView(appId);
        ArtifactView row;
        ArtifactViewRevision? requested = null;
        if (revisionId is not null)
        {
            row = await AccessibleAsync(a, id, manage: false);
            var rid = TypeIds.ArtifactViewRevision(revisionId);
            requested = await db.Set<ArtifactViewRevision>().AsNoTracking().FirstOrDefaultAsync(r => r.Id == rid && r.ArtifactViewId == row.Id && r.OrganizationId == row.OrganizationId)
                ?? throw new WorkflowException("artifact_view_revision_not_found");
        }
        else row = await AccessibleAsync(a, id, manage: false);
        if (row.DataMode == "live" && row.Status != "active") throw new WorkflowException("artifact_view_not_found");
        var view = ViewJson(row, requested is not null ? [requested] : (await RevisionsAsync([row]))[row.Id]);
        var workflow = await workflows.DetailAsync(a, row.ConfigObjectId);
        var wanted = revisionId ?? row.ActiveRevisionId;
        var revision = view["revisions"]!.AsArray().Cast<JsonObject>().FirstOrDefault(r => r["id"]!.GetValue<string>() == wanted);
        var onDashboard = await db.Set<DashboardApp>().AnyAsync(d => d.OrganizationId == a.OrgId && d.MemberId == a.MemberId && d.ArtifactViewId == row.Id);
        JsonObject Detail(string? html, JsonNode? payload, string? notice, JsonObject? runError = null)
        {
            var o = new JsonObject
            {
                ["view"] = view.DeepClone(), ["workflowTitle"] = workflow["title"]!.DeepClone(), ["canManage"] = workflow["canManage"]!.DeepClone(), ["onDashboard"] = onDashboard,
                ["revision"] = revision?.DeepClone(), ["html"] = html, ["payload"] = payload, ["previewNotice"] = notice,
            };
            if (runError is not null) o["runError"] = runError;
            return o;
        }
        if (revision is null || revision["buildStatus"]!.GetValue<string>() != "ready" || revision["retiredAt"] is not null)
            return Detail(null, null, "This app is still being prepared. Ask OpenWork to finish its preview.");
        var stored = revisionId is not null ? requested! : await db.Set<ArtifactViewRevision>().AsNoTracking().FirstAsync(r => r.Id == revision["id"]!.GetValue<string>());
        var receipt = receiptId;
        if (row.DataMode == "live")
        {
            if (receipt is not null) throw new WorkflowException("artifact_view_live_receipt_override_denied");
            var (execution, _) = await workflows.RunLiveForAppAsync(a, row.ConfigObjectId, revision["outputSchemaDigest"]!.GetValue<string>(), timeZone, ct);
            if (execution is not WorkflowExecution.Succeeded ok)
            {
                var (message, error) = execution switch
                {
                    WorkflowExecution.Unsupported u => (u.Message, "unsupported"),
                    WorkflowExecution.Invalid i => (i.Message, i.Error),
                    WorkflowExecution.CapabilityUnavailable c => (c.Message, "capability_unavailable"),
                    WorkflowExecution.ScriptFailed f => (f.Message, "script_failed"),
                    _ => ("The workflow could not run.", "script_failed"),
                };
                return Detail(null, null, message, new JsonObject { ["ok"] = false, ["error"] = error, ["message"] = message });
            }
            receipt = ok.ReceiptId ?? throw new WorkflowException("workflow_receipt_unavailable");
        }
        JsonObject? snapshot = receipt is not null ? await workflows.GetSnapshotAsync(a, row.ConfigObjectId, receipt) : workflow["latestSuccessfulSnapshot"] as JsonObject;
        if (snapshot is null || snapshot["status"]!.GetValue<string>() != "succeeded" || snapshot["contentDeletedAt"] is not null || snapshot["resultDigest"] is null || snapshot["rendererVersion"] is null)
            return Detail(null, null, "Run the workflow to give this app a result to display.");
        if (snapshot["outputSchemaDigest"]?.GetValue<string>() != revision["outputSchemaDigest"]!.GetValue<string>())
            return Detail(null, null, "The workflow’s results have changed. Ask OpenWork to update this app to match.");
        var finished = DateTime.Parse(snapshot["finishedAt"]!.GetValue<string>(), null, System.Globalization.DateTimeStyles.RoundtripKind).ToUniversalTime();
        var payload = new JsonObject
        {
            ["schemaVersion"] = "1",
            ["artifact"] = new JsonObject
            {
                ["title"] = workflow["title"]!.DeepClone(), ["description"] = workflow["description"]?.DeepClone(), ["pluginId"] = snapshot["pluginId"]!.DeepClone(), ["configObjectId"] = snapshot["configObjectId"]!.DeepClone(),
                ["configObjectVersionId"] = snapshot["configObjectVersionId"]!.DeepClone(), ["receiptId"] = snapshot["receiptId"]!.DeepClone(), ["automationRunId"] = snapshot["automationRunId"]?.DeepClone(),
                ["source"] = snapshot["source"]!.DeepClone(), ["generatedAt"] = snapshot["finishedAt"]!.DeepClone(), ["resultDigest"] = snapshot["resultDigest"]!.DeepClone(),
                ["rendererVersion"] = snapshot["rendererVersion"]!.DeepClone(),
                ["freshness"] = WorkflowArtifacts.Freshness(finished, "succeeded", finished, snapshot["receiptId"]!.GetValue<string>(), 24L * 60 * 60_000, null),
            },
            ["data"] = snapshot["value"]?.DeepClone(),
        };
        return Detail(stored.CompiledHtml, payload, null);
    }
}
