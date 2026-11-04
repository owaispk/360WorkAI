using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Automations;
using WorkAI360.Api.Domain.Library;
using WorkAI360.Api.Features.Library;
using WorkAI360.Api.Features.Workspace;

namespace WorkAI360.Api.Features.Automations;

/// <summary>
/// Automations whose action is a saved Workflow version (<c>{kind: "saved_script", script: {pluginId, configObjectId, configObjectVersionId}, input}</c>), as the
/// reference's <c>validateWorkflowAutomationAction</c> and its in-Den Workflow executor. A Workflow never runs on a desktop: it runs here, on the cloud
/// target, through the same code-mode runner that runs it for agents, under the owner's own access, and its receipt names the Automation run.
/// </summary>
public sealed class WorkflowActions(DenDbContext db, PermissionService permissions, WorkflowService workflows, AutomationAudit runAudit,
    IOptions<AutomationOptions> automationOptions, IOptions<WorkspaceOptions> workspaceOptions, ILogger<WorkflowActions> log)
{
    public const string EngineKind = "openwork-cloud-codemode-v1";
    private static readonly string[] Editing = ["editor", "manager"];

    /// <summary>The reference's checks, in its order: the owner is a member; may run the Workflow; the version exists and parses; the stored input fits its schema.</summary>
    public async Task ValidateAsync(string organizationId, string ownerMemberId, ActionSpec action)
    {
        var member = await db.Members.AsNoTracking().FirstOrDefaultAsync(m => m.Id == ownerMemberId && m.OrganizationId == organizationId)
            ?? throw new AutomationFailure(409, "automation_owner_inactive", "The Automation owner is no longer an active organization member.");
        var script = JsonDocument.Parse(action.ScriptJson!).RootElement;
        var pluginId = script.GetProperty("pluginId").GetString()!;
        var objectId = script.GetProperty("configObjectId").GetString()!;
        var versionId = script.GetProperty("configObjectVersionId").GetString()!;

        // Scheduling a Workflow executes it, so the owner needs run access (editor or manager), as `canRun` reports; a viewer must not gain scheduled runs.
        var resolved = await permissions.ResolveAsync(organizationId, member);
        if (!resolved.Has("sharing.manage_all") && !await CanRunAsync(organizationId, ownerMemberId, pluginId, objectId))
            throw new AutomationFailure(403, "automation_saved_script_forbidden", "The Automation owner does not have access to this Workflow.");

        var version = await (from v in db.Set<ConfigObjectVersion>().AsNoTracking()
                             join o in db.Set<ConfigObject>().AsNoTracking() on v.ConfigObjectId equals o.Id
                             join m in db.Set<PluginConfigObject>().AsNoTracking() on o.Id equals m.ConfigObjectId
                             where v.Id == versionId && v.ConfigObjectId == objectId && v.OrganizationId == organizationId && !v.IsDeletedVersion
                                   && o.OrganizationId == organizationId && o.ObjectType == "workflow" && o.Status == "active" && o.DeletedAt == null
                                   && m.PluginId == pluginId && m.RemovedAt == null
                             select v).FirstOrDefaultAsync()
            ?? throw new AutomationFailure(400, "automation_saved_script_version_not_found", "The selected Workflow version is unavailable.");
        var (payload, _) = CodemodePayload.Parse(WorkflowArtifacts.Parse(version.NormalizedPayloadJson ?? "null"));
        if (payload is null) throw new AutomationFailure(400, "automation_saved_script_version_invalid", "The selected Workflow version is unavailable.");
        if (payload.InputSchema is not null && CodemodePayload.Check(payload.InputSchema, Input(action)).Problem is not null)
            throw new AutomationFailure(400, "automation_saved_script_input_invalid", "The existing Automation input does not match the selected Workflow version. Correct the input before creating the revision.");
    }

    /// <summary>A grant of editor or manager on the Workflow or its plugin (to the person, one of their teams, or everyone), or having made either one.</summary>
    private async Task<bool> CanRunAsync(string organizationId, string memberId, string pluginId, string objectId)
    {
        var made = await db.Set<ConfigObject>().AsNoTracking().AnyAsync(o => o.Id == objectId && o.OrganizationId == organizationId && o.CreatedByMemberId == memberId)
            || await db.Set<Plugin>().AsNoTracking().AnyAsync(p => p.Id == pluginId && p.OrganizationId == organizationId && p.CreatedByMemberId == memberId);
        if (made) return true;
        var teams = await db.TeamMembers.AsNoTracking().Where(t => t.MemberId == memberId).Select(t => t.TeamId).ToListAsync();
        return await db.Set<LibraryGrant>().AsNoTracking().AnyAsync(g => g.OrganizationId == organizationId && g.RemovedAt == null && Editing.Contains(g.Role)
            && ((g.ResourceKind == GrantKinds.ConfigObject && g.ResourceId == objectId) || (g.ResourceKind == GrantKinds.Plugin && g.ResourceId == pluginId))
            && (g.OrgWide || g.MemberId == memberId || (g.TeamId != null && teams.Contains(g.TeamId))));
    }

    private static JsonNode? Input(ActionSpec action) => action.InputJson is null ? null : JsonNode.Parse(action.InputJson);

    /// <summary>
    /// Runs the queued Workflow Automation runs (oldest first, at most <paramref name="limit"/>). Each run is taken with one conditional update, so two
    /// instances never run it twice; its lease covers the longest a Workflow may run, so a crash is recovered like any lost lease.
    /// </summary>
    public async Task<List<string>> RunQueuedAsync(long now, int limit, CancellationToken ct)
    {
        var queued = await (from r in db.Set<AutomationRun>().AsNoTracking()
                            join v in db.Set<AutomationRevision>().AsNoTracking() on r.RevisionId equals v.Id
                            where r.Status == "queued" && r.ExecutionTarget == "cloud" && v.ActionJson.Contains("\"saved_script\"")
                            orderby r.CreatedAt, r.Id
                            select r.Id).Take(limit).ToListAsync(ct);
        var finished = new List<string>();
        foreach (var runId in queued)
            if (await RunOneAsync(runId, ct)) finished.Add(runId);
        return finished;
    }

    private string LeaseOwner => $"den:{Environment.MachineName}:{Environment.ProcessId}";

    /// <summary>Runs one queued Workflow run, if this caller is the one that takes it. False when it was not queued (already taken, ended, or not a cloud run).</summary>
    public async Task<bool> RunOneAsync(string runId, CancellationToken ct)
    {
        var now = AutomationService.Now();
        var owner = LeaseOwner;
        var lease = now + Math.Max(automationOptions.Value.LeaseMs, workspaceOptions.Value.MaxTimeoutMs + 60_000);
        var taken = await db.Set<AutomationRun>().Where(r => r.Id == runId && r.Status == "queued" && r.ExecutionTarget == "cloud")
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.Status, "running").SetProperty(r => r.LeaseOwner, owner).SetProperty(r => r.LeaseExpiresAt, (long?)lease)
                .SetProperty(r => r.HeartbeatAt, (long?)now).SetProperty(r => r.AttemptCount, r => r.AttemptCount + 1).SetProperty(r => r.EngineKind, EngineKind)
                .SetProperty(r => r.StartedAt, r => r.StartedAt ?? now).SetProperty(r => r.UpdatedAt, now), ct);
        if (taken == 0) return false;
        var run = await db.Set<AutomationRun>().AsNoTracking().FirstAsync(r => r.Id == runId, ct);
        var automation = await db.Set<Automation>().AsNoTracking().FirstAsync(a => a.Id == run.AutomationId, ct);
        var revision = await db.Set<AutomationRevision>().AsNoTracking().FirstAsync(r => r.Id == run.RevisionId, ct);
        var action = AutomationService.ActionOf(revision);

        var (status, summary, error) = await ExecuteAsync(automation, action, runId, ct);
        var finishedAt = AutomationService.Now();
        var errorJson = error is null ? null : JsonSerializer.Serialize(new { code = error.Value.Code, message = error.Value.Message, retryable = error.Value.Retryable });
        await db.Set<AutomationRun>().Where(r => r.Id == runId && r.LeaseOwner == owner && r.Status == "running")
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.Status, status).SetProperty(r => r.ResultSummary, summary).SetProperty(r => r.ErrorJson, errorJson)
                .SetProperty(r => r.FinishedAt, (long?)finishedAt).SetProperty(r => r.LeaseExpiresAt, (long?)null).SetProperty(r => r.HeartbeatAt, (long?)finishedAt)
                .SetProperty(r => r.UpdatedAt, finishedAt), ct);
        await runAudit.CompletedAsync(runId);
        return true;
    }

    private async Task<(string Status, string? Summary, (string Code, string Message, bool Retryable)? Error)> ExecuteAsync(Automation automation, ActionSpec action, string runId, CancellationToken ct)
    {
        try
        {
            // The owner's access is checked again at run time: it may have changed since the Automation was saved.
            try { await ValidateAsync(automation.OrganizationId, automation.OwnerMemberId, action); }
            catch (AutomationFailure refused) { return ("failed", refused.Message, ("execution_failed", refused.Message, false)); }
            var member = await db.Members.AsNoTracking().FirstAsync(m => m.Id == automation.OwnerMemberId && m.OrganizationId == automation.OrganizationId, ct);
            var teams = (await db.TeamMembers.AsNoTracking().Where(t => t.MemberId == member.Id).Select(t => t.TeamId).ToListAsync(ct)).ToHashSet();
            var who = new WorkflowService.Who(automation.OrganizationId, member.UserId, member.Id, teams);
            var script = JsonDocument.Parse(action.ScriptJson!).RootElement;
            var (code, message, found) = await workflows.FindRunnableAsync(who, script.GetProperty("pluginId").GetString()!, script.GetProperty("configObjectId").GetString()!, script.GetProperty("configObjectVersionId").GetString());
            if (found is null) return ("failed", message, ("execution_failed", message ?? code ?? "The Workflow could not execute.", false));
            var execution = await workflows.RunSavedAsync(who, found.Value, Input(action), live: false, timeZone: null, validateOutput: true, ct, automationRunId: runId);
            return execution switch
            {
                WorkflowExecution.Succeeded ok when ok.ReceiptId is not null => ("succeeded", ok.Canonical, null),
                WorkflowExecution.Succeeded => ("failed", "The Workflow ran, but its durable artifact receipt could not be recorded.", ("execution_failed", "The Workflow ran, but its durable artifact receipt could not be recorded.", true)),
                WorkflowExecution.ScriptFailed failed => ("failed", failed.Message, ("execution_failed", failed.Message, false)),
                WorkflowExecution.Invalid invalid => ("failed", invalid.Message, ("execution_failed", invalid.Message, false)),
                WorkflowExecution.CapabilityUnavailable missing => ("failed", missing.Message, ("execution_failed", missing.Message, false)),
                WorkflowExecution.Unsupported unsupported => ("failed", unsupported.Message, ("execution_failed", unsupported.Message, false)),
                _ => ("failed", "The Workflow could not execute.", ("execution_failed", "The Workflow could not execute.", false)),
            };
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            log.LogError(e, "automation_workflow_run_failed {RunId}", runId);
            return ("failed", "Workflow execution failed.", ("execution_failed", "Workflow execution failed.", true));
        }
    }

    /// <summary>Queued Workflow runs need nothing but this server; the scheduler must not skip them as "no cloud runtime".</summary>
    public static bool IsWorkflowRun(AutomationRevision revision) => AutomationService.ActionOf(revision).Kind == "saved_script";
}
