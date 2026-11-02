using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Automations;
using WorkAI360.Api.Features.OrgAdmin;
using WorkAI360.Api.Features.Policy;

namespace WorkAI360.Api.Features.Automations;

public sealed class AutomationOptions
{
    public const string Section = "Automations";
    /// <summary>Run the scheduler loop that starts due occurrences, recovers expired leases and records missed runs.</summary>
    public bool SchedulerEnabled { get; set; } = true;
    public int PollIntervalMs { get; set; } = 15_000;
    public int BatchSize { get; set; } = 25;
    /// <summary>How long a runner holds a run without a heartbeat before it can be reclaimed.</summary>
    public int LeaseMs { get; set; } = 60_000;
    /// <summary>How long a scheduled desktop occurrence stays claimable. A laptop sleeps and reconnects, so this is a recovery window, not a liveness check.</summary>
    public int RunnerClaimDeadlineMs { get; set; } = 900_000;
}

/// <summary>Where cloud Automations run. Nothing here provides one, so the default says no; a deployment that does registers its own.</summary>
public interface ICloudAutomationRuntime
{
    Task<bool> AgentAvailableAsync(string organizationId, string ownerMemberId);
}

public sealed class NoCloudAutomationRuntime : ICloudAutomationRuntime
{
    public Task<bool> AgentAvailableAsync(string organizationId, string ownerMemberId) => Task.FromResult(false);
}

/// <summary>An answer the Automations routes give instead of a result: <c>{error, message?}</c> with a status.</summary>
public sealed class AutomationFailure(int status, string error, string? message = null) : Exception(message ?? error)
{
    public int Status { get; } = status;
    public string Error { get; } = error;
    public string? Detail { get; } = message;

    public IResult ToResult() => Detail is null ? Results.Json(new { error = Error }, statusCode: Status) : Results.Json(new { error = Error, message = Detail }, statusCode: Status);
}

/// <summary>Whose Automations a request is about, and what the caller can read and use.</summary>
public sealed record Scope(string OrganizationId, string MemberId, bool ModelAttention, IReadOnlySet<string>? ReadableKinds, bool IntervalSchedules, bool CalendarTriggers)
{
    public bool CanRead(AutomationSchedule schedule) => ReadableKinds is null || ReadableKinds.Contains(schedule.Kind);
}

public sealed record Failed(string Code, string Message);

/// <summary>
/// Creating, changing, activating and running Automations for their owner (ported from the reference's service): placement rules, schedule features,
/// model access, revisions, and the manual run. Members own their own Automations; nobody sees another person's.
/// </summary>
public sealed class AutomationService(DenDbContext db, PolicyStore policy, IOptions<PolicyOptions> policyOptions, IOptions<AutomationOptions> options, ICloudAutomationRuntime cloud, RunQueue queue)
{
    public const int DefaultMaximumRuntimeMs = 15 * 60_000;
    public static long Now() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

    // ---------------------------------------------------------------- availability and rules

    /// <summary>What the organization may run: its own switches (Policy settings), the deployment's, and for the cloud a headless runner.</summary>
    public async Task<(bool Desktop, bool Cloud)> AvailabilityAsync(string organizationId)
    {
        var settings = await policy.SettingsAsync(organizationId);
        var deployment = policyOptions.Value;
        return (deployment.AutomationsEnabled && settings.DesktopAutomations,
            deployment.AutomationsEnabled && deployment.HeadlessRunnerConfigured && settings.CloudAutomations);
    }

    public async Task<bool> TargetAllowedAsync(string organizationId, string target)
    {
        var (desktop, cloudOn) = await AvailabilityAsync(organizationId);
        return target == "cloud" ? cloudOn : desktop;
    }

    private async Task RequireTargetAllowedAsync(string organizationId, string target)
    {
        if (await TargetAllowedAsync(organizationId, target)) return;
        throw target == "cloud"
            ? new AutomationFailure(403, "automation_cloud_disabled", "Cloud Automations are not available for this organization. An admin can turn them on in Settings once OpenWork's headless runner is set up.")
            : new AutomationFailure(403, "automation_desktop_disabled", "Desktop Automations are turned off for this organization. An admin can turn them on in Settings.");
    }

    /// <summary>A new interval or calendar schedule needs its feature; keeping the one an Automation already has does not. Calendar triggers run only in the cloud.</summary>
    private static void RequireScheduleAllowed(Scope scope, AutomationSchedule? schedule, string target, AutomationSchedule? current = null)
    {
        if (schedule is null) return;
        if (schedule.Kind == "calendar" && target != "cloud")
            throw new AutomationFailure(400, "automation_calendar_trigger_cloud_only", "Automations that run around meetings run in OpenWork Cloud. Create it as a Cloud Automation, or choose a clock schedule to run it on a desktop.");
        if (current is not null && schedule.SameAs(current)) return;
        if (schedule.Kind == "interval" && !scope.IntervalSchedules)
            throw new AutomationFailure(400, "automation_interval_schedule_disabled", "Every-few-hours schedules are not turned on for this organization. Choose a once, daily or weekly schedule.");
        if (schedule.Kind == "calendar" && !scope.CalendarTriggers)
            throw new AutomationFailure(400, "automation_calendar_trigger_disabled", "Before- and after-meeting Automations are not turned on for this organization. Choose a clock schedule instead.");
    }

    private async Task RequireCloudAgentAsync(Scope scope)
    {
        if (!await cloud.AgentAvailableAsync(scope.OrganizationId, scope.MemberId))
            throw new AutomationFailure(409, "automation_cloud_worker_required", "Set up OpenWork Cloud before creating a Cloud Automation.");
    }

    public async Task<bool> CloudAgentAvailableAsync(string organizationId, string memberId) => await cloud.AgentAvailableAsync(organizationId, memberId);

    private static AutomationFailure WorkflowUnavailable() => new(400, "automation_saved_script_version_not_found", "The selected Workflow version is unavailable.");

    public async Task<bool> OwnerActiveAsync(string organizationId, string memberId) =>
        await db.Members.AsNoTracking().AnyAsync(m => m.Id == memberId && m.OrganizationId == organizationId);

    // ---------------------------------------------------------------- model access

    /// <summary>Whether the owner may use a model where a run executes. This build has no model catalog of its own, so only a desktop's own providers and the cloud default pass.</summary>
    public async Task<Failed?> ModelAccessAsync(string organizationId, string memberId, ModelChoice model, string target)
    {
        if (!await OwnerActiveAsync(organizationId, memberId))
            return new("owner_membership_lost", "The Automation owner is no longer an active organization member.");
        if (model.ProviderId == CloudDefault.ProviderId)
            return model.ModelId == CloudDefault.ModelId ? null : new("model_access_lost", "The selected cloud model is not available for Automations.");
        if (model.ProviderId == FreeModel.ProviderId)
            return new("model_access_lost", "The selected OpenCode Zen model is no longer available. Choose a supported model to resume this Automation.");
        if (model.ProviderId == "openwork")
            return new("model_access_lost", "The selected OpenWork-managed model is not available.");
        if (model.ProviderId.StartsWith("lpr_", StringComparison.OrdinalIgnoreCase))
            return new("provider_unavailable", "The selected model provider is no longer available.");
        // Anything else is a provider only the desktop that runs it has; that desktop checks before each run.
        return target == "desktop" ? null : new("provider_unavailable", "This model is only available on a desktop. Choose a model your organization provides to run this Automation in the cloud.");
    }

    /// <summary>Published desktops accepted the retired free model; only clients that say they handle model attention are told it is gone.</summary>
    public static bool ShouldApply(ModelChoice model, Failed failure, bool modelAttentionCapable) =>
        modelAttentionCapable || failure.Code != "model_access_lost" || model.ProviderId != FreeModel.ProviderId || model.ModelId != FreeModel.ModelId;

    private async Task RequireNewModelAsync(Scope scope, ModelChoice model, string target)
    {
        if (model.ProviderId == CloudDefault.ProviderId && target != "cloud")
            throw new AutomationFailure(409, "model_access_lost", "The cloud default model runs only cloud Automations on the headless runtime.");
        var failure = await ModelAccessAsync(scope.OrganizationId, scope.MemberId, model, target);
        if (failure is not null && ShouldApply(model, failure, scope.ModelAttention)) throw new AutomationFailure(409, failure.Code, failure.Message);
    }

    /// <summary>An active Automation whose model is gone is paused with the reason, so the person sees it rather than a run failing later.</summary>
    private async Task<Item> ReconcileAsync(Item item, Scope scope)
    {
        if (item.Automation.State != "active" || ActionOf(item.Revision).Kind == "saved_script") return item;
        var target = item.Revision.ExecutionTarget;
        var failure = await ModelAccessAsync(item.Automation.OrganizationId, item.Automation.OwnerMemberId, ModelOf(item.Revision), target);
        if (failure is null || !ShouldApply(ModelOf(item.Revision), failure, target == "cloud" || scope.ModelAttention)) return item;
        await MarkNeedsAttentionAsync(item.Automation.Id, item.Revision.Id, failure.Code, failure.Message, Now());
        return await GetAsync(scope, item.Automation.Id, reconcile: false) ?? item;
    }

    public static ModelChoice ModelOf(AutomationRevision r) => new(r.ProviderId, r.ModelId, r.ModelVariant, true);
    public static ActionSpec ActionOf(AutomationRevision r) => ParseAction(r.ActionJson);

    private static ActionSpec ParseAction(string json) => ActionSpec.Parse(JsonDocument.Parse(json).RootElement, []);

    public async Task<bool> MarkNeedsAttentionAsync(string automationId, string expectedRevisionId, string code, string message, long now)
    {
        var reason = JsonSerializer.Serialize(new { code, message, occurredAt = now });
        var changed = await db.Set<Automation>().Where(a => a.Id == automationId && a.CurrentRevisionId == expectedRevisionId && a.State == "active")
            .ExecuteUpdateAsync(s => s.SetProperty(a => a.State, "needs_attention").SetProperty(a => a.NextDueAt, (long?)null)
                .SetProperty(a => a.NeedsAttentionJson, reason).SetProperty(a => a.UpdatedAt, now));
        return changed > 0;
    }

    // ---------------------------------------------------------------- reading

    private async Task<List<Item>> ItemsAsync(List<Automation> automations)
    {
        if (automations.Count == 0) return [];
        var revisionIds = automations.Select(a => a.CurrentRevisionId).ToList();
        var revisions = await db.Set<AutomationRevision>().AsNoTracking().Where(r => revisionIds.Contains(r.Id)).ToDictionaryAsync(r => r.Id);
        var ids = automations.Select(a => a.Id).ToList();
        var stamps = automations.Where(a => a.LatestRunAt is not null).Select(a => a.LatestRunAt).Distinct().ToList();
        var candidates = stamps.Count == 0 ? [] : await db.Set<AutomationRun>().AsNoTracking().Where(r => ids.Contains(r.AutomationId) && stamps.Contains(r.CreatedAt)).ToListAsync();
        return automations.Select(a =>
        {
            var run = candidates.Where(r => r.AutomationId == a.Id && r.CreatedAt == a.LatestRunAt).OrderByDescending(r => r.Id, StringComparer.Ordinal).FirstOrDefault();
            return new Item(a, revisions[a.CurrentRevisionId], run);
        }).ToList();
    }

    public async Task<(List<Item> Items, string? NextCursor)> ListAsync(Scope scope, string? cursor, int limit)
    {
        limit = Math.Clamp(limit, 1, 100);
        var query = db.Set<Automation>().AsNoTracking().Where(a => a.OrganizationId == scope.OrganizationId && a.OwnerMemberId == scope.MemberId);
        if (cursor is not null) query = query.Where(a => string.Compare(a.Id, cursor) < 0);
        var rows = await query.OrderByDescending(a => a.Id).Take(limit + 1).ToListAsync();
        var page = rows.Take(limit).ToList();
        // Filter before reconciling: a caller must not touch Automations it is not shown.
        var items = (await ItemsAsync(page)).Where(i => scope.CanRead(AutomationSchedule.FromJson(i.Revision.ScheduleJson))).ToList();
        var result = new List<Item>();
        foreach (var item in items) result.Add(await ReconcileAsync(item, scope));
        return (result, rows.Count > limit ? page.LastOrDefault()?.Id : null);
    }

    public async Task<Item?> GetAsync(Scope scope, string id, bool reconcile = true)
    {
        var automation = await db.Set<Automation>().AsNoTracking().FirstOrDefaultAsync(a => a.Id == id && a.OrganizationId == scope.OrganizationId && a.OwnerMemberId == scope.MemberId);
        if (automation is null) return null;
        var item = (await ItemsAsync([automation]))[0];
        if (!scope.CanRead(AutomationSchedule.FromJson(item.Revision.ScheduleJson))) return null;
        return reconcile ? await ReconcileAsync(item, scope) : item;
    }

    // ---------------------------------------------------------------- creating and changing

    public async Task<Item> CreateAsync(Scope scope, CreateDefinition definition)
    {
        RequireScheduleAllowed(scope, definition.Schedule, definition.ExecutionTarget);
        await RequireTargetAllowedAsync(scope.OrganizationId, definition.ExecutionTarget);
        if (definition.FromActionShape)
        {
            // The action shape is the cloud's: it needs a runtime and, for an agent, a model the cloud may use.
            if (definition.Action.Kind == "agent")
            {
                await RequireNewModelAsync(scope with { ModelAttention = true }, definition.Action.Model!, "cloud");
                await RequireCloudAgentAsync(scope);
            }
            else
            {
                if (!await OwnerActiveAsync(scope.OrganizationId, scope.MemberId)) throw new AutomationFailure(409, "automation_owner_inactive", "The Automation owner is no longer an active organization member.");
                throw WorkflowUnavailable();
            }
        }
        else await RequireNewModelAsync(scope, definition.Action.Model!, "desktop");

        var now = Now();
        var model = definition.Action.Kind == "agent" ? definition.Action.Model! : new ModelChoice(FreeModel.ProviderId, FreeModel.ModelId, null, true);
        var instructions = definition.Action.Kind == "agent" ? definition.Action.Instructions! : "Execute the pinned Workflow.";
        var revision = NewRevision(Auto.NewId("atm"), 1, instructions, definition.Schedule, model, definition.Action, definition.ExecutionTarget, definition.WorkspaceId, DefaultMaximumRuntimeMs, now);
        var automation = new Automation
        {
            Id = revision.AutomationId, OrganizationId = scope.OrganizationId, OwnerMemberId = scope.MemberId, Name = definition.Name, State = "active",
            CurrentRevisionId = revision.Id, NextDueAt = ScheduleMath.Next(definition.Schedule, now), CreatedAt = now, UpdatedAt = now,
        };
        await using var tx = await db.Database.BeginTransactionAsync();
        db.Set<Automation>().Add(automation);
        await db.SaveChangesAsync();
        db.Set<AutomationRevision>().Add(revision);
        await db.SaveChangesAsync();
        await tx.CommitAsync();
        db.ChangeTracker.Clear();
        return await ReconcileAsync((await GetAsync(scope, automation.Id, reconcile: false))!, scope);
    }

    private static AutomationRevision NewRevision(string automationId, int version, string instructions, AutomationSchedule schedule, ModelChoice model, ActionSpec action, string target, string? workspaceId, int maximumRuntimeMs, long now) => new()
    {
        Id = Auto.NewId("atv"), AutomationId = automationId, Version = version, Instructions = instructions, ScheduleKind = schedule.Kind, ScheduleJson = schedule.ToJson(),
        ProviderId = model.ProviderId, ModelId = model.ModelId, ModelVariant = model.Variant, ActionJson = action.ToJson(), ExecutionTarget = target, WorkspaceId = workspaceId,
        MaximumRuntimeMs = maximumRuntimeMs, Digest = AutomationInput.Digest(instructions, schedule, model, action, target, maximumRuntimeMs, workspaceId), CreatedAt = now,
    };

    public async Task<Item?> UpdateAsync(Scope scope, string id, UpdateDefinition changes)
    {
        var current = await GetAsync(scope, id);
        if (current is null) return null;
        var currentTarget = current.Revision.ExecutionTarget;
        var nextTarget = changes.ExecutionTarget ?? currentTarget;
        var currentSchedule = AutomationSchedule.FromJson(current.Revision.ScheduleJson);
        RequireScheduleAllowed(scope, changes.Schedule ?? currentSchedule, nextTarget, currentSchedule);
        var moved = nextTarget != currentTarget;
        var currentAction = ActionOf(current.Revision);
        var nextAction = changes.Action ?? currentAction;
        if (nextTarget == "desktop" && nextAction.Kind == "saved_script") throw new AutomationFailure(400, "automation_action_target_mismatch", "This Automation runs only in OpenWork Cloud.");
        if (moved) await RequireTargetMoveAsync(scope, nextAction, nextTarget);
        if (nextAction.Kind == "saved_script") throw WorkflowUnavailable();
        var requested = changes.Action is { Kind: "agent" } ? changes.Action.Model! : changes.Model ?? currentAction.Model!;
        if (!moved && nextTarget == "cloud") await RequireCloudAgentAsync(scope);
        if (moved || !requested.Same(ModelOf(current.Revision)))
            await RequireNewModelAsync(nextTarget == "cloud" ? scope with { ModelAttention = true } : scope, requested, nextTarget);

        var now = Now();
        await using var tx = await db.Database.BeginTransactionAsync();
        // The Automation row is the lock: two edits of one Automation queue up, and an edit cannot interleave with a run being claimed.
        var locked = await LockAsync(id);
        var automation = locked ? await db.Set<Automation>().AsNoTracking().FirstAsync(a => a.Id == id) : null;
        if (automation is null || automation.State == "archived") { await tx.RollbackAsync(); return null; }
        var revision = await db.Set<AutomationRevision>().AsNoTracking().FirstAsync(r => r.Id == automation.CurrentRevisionId);
        var action = changes.Action ?? (currentAction.Kind == "agent"
            ? new ActionSpec("agent", changes.Instructions ?? currentAction.Instructions, changes.Model ?? currentAction.Model, null, null)
            : currentAction);
        var target = changes.ExecutionTarget ?? revision.ExecutionTarget;
        var instructions = action.Kind == "agent" ? action.Instructions! : "Execute the pinned Workflow.";
        var schedule = changes.Schedule ?? AutomationSchedule.FromJson(revision.ScheduleJson);
        var model = action.Kind == "agent" ? action.Model! : new ModelChoice(FreeModel.ProviderId, FreeModel.ModelId, null, true);
        // A pin names a folder on one computer, so moving drops it unless the same request pins a workspace on the new target.
        var workspace = changes.WorkspaceGiven ? changes.WorkspaceId : target == revision.ExecutionTarget ? revision.WorkspaceId : null;
        var digest = AutomationInput.Digest(instructions, schedule, model, action, target, revision.MaximumRuntimeMs, workspace);
        var name = changes.Name ?? automation.Name;
        if (digest == revision.Digest)
        {
            await db.Set<Automation>().Where(a => a.Id == id).ExecuteUpdateAsync(s => s.SetProperty(a => a.Name, name).SetProperty(a => a.UpdatedAt, now));
        }
        else
        {
            var created = NewRevision(id, revision.Version + 1, instructions, schedule, model, action, target, workspace, revision.MaximumRuntimeMs, now);
            db.Set<AutomationRevision>().Add(created);
            await db.SaveChangesAsync();
            var next = ScheduleMath.Next(schedule, now);
            await db.Set<Automation>().Where(a => a.Id == id).ExecuteUpdateAsync(s => s.SetProperty(a => a.Name, name).SetProperty(a => a.CurrentRevisionId, created.Id)
                .SetProperty(a => a.NextDueAt, next).SetProperty(a => a.State, "active").SetProperty(a => a.NeedsAttentionJson, (string?)null).SetProperty(a => a.UpdatedAt, now));
        }
        await tx.CommitAsync();
        db.ChangeTracker.Clear();
        var updated = await GetAsync(scope, id, reconcile: false);
        return updated is null ? null : await ReconcileAsync(updated, scope);
    }

    /// <summary>Takes the Automation's row lock for the rest of the transaction (a write that changes nothing). False when it does not exist.</summary>
    public async Task<bool> LockAsync(string automationId) =>
        await db.Set<Automation>().Where(a => a.Id == automationId).ExecuteUpdateAsync(s => s.SetProperty(a => a.UpdatedAt, a => a.UpdatedAt)) > 0;

    /// <summary>Moving an Automation, or one run of it, to the other target: the cloud needs what creating a cloud Automation needs, the desktop never runs Workflows.</summary>
    private async Task RequireTargetMoveAsync(Scope scope, ActionSpec? action, string target)
    {
        await RequireTargetAllowedAsync(scope.OrganizationId, target);
        if (target == "desktop")
        {
            if (action?.Kind == "saved_script") throw new AutomationFailure(400, "automation_action_target_mismatch", "This Automation runs only in OpenWork Cloud.");
            if (action?.Kind == "agent" && action.Model!.ProviderId == CloudDefault.ProviderId) throw new AutomationFailure(409, "model_access_lost", "Choose a model before running this Automation on a desktop.");
            return;
        }
        if (action?.Kind == "agent") await RequireCloudAgentAsync(scope);
    }

    public async Task<Item?> ActivateAsync(Scope scope, string id)
    {
        var current = await GetAsync(scope, id);
        if (current is null) return null;
        var target = current.Revision.ExecutionTarget;
        var action = ActionOf(current.Revision);
        if (action.Kind == "saved_script")
        {
            if (!await OwnerActiveAsync(scope.OrganizationId, scope.MemberId)) throw new AutomationFailure(409, "automation_owner_inactive", "The Automation owner is no longer an active organization member.");
        }
        else
        {
            if (target == "cloud") await RequireCloudAgentAsync(scope);
            await RequireNewModelAsync(target == "cloud" ? scope with { ModelAttention = true } : scope, ModelOf(current.Revision), target);
        }
        var activated = await SetStateAsync(scope, id, "active");
        return activated is null ? null : await ReconcileAsync(activated, scope);
    }

    public Task<Item?> DeactivateAsync(Scope scope, string id) => SetStateAsync(scope, id, "inactive");

    public Task<Item?> ArchiveAsync(Scope scope, string id) => SetStateAsync(scope, id, "archived");

    private async Task<Item?> SetStateAsync(Scope scope, string id, string state)
    {
        var current = await GetAsync(scope, id, reconcile: false);
        if (current is null) return null;
        if (current.Automation.State != state)
        {
            var now = Now();
            long? next = state == "active" ? ScheduleMath.Next(AutomationSchedule.FromJson(current.Revision.ScheduleJson), now) : null;
            long? archivedAt = state == "archived" ? now : null;
            await db.Set<Automation>().Where(a => a.Id == id).ExecuteUpdateAsync(s => s.SetProperty(a => a.State, state).SetProperty(a => a.NextDueAt, next)
                .SetProperty(a => a.ArchivedAt, archivedAt).SetProperty(a => a.NeedsAttentionJson, (string?)null).SetProperty(a => a.UpdatedAt, now));
        }
        return await GetAsync(scope, id, reconcile: false);
    }

    // ---------------------------------------------------------------- running

    public async Task<AutomationRun?> RunNowAsync(Scope scope, string id, string? requestedTarget)
    {
        var current = await GetAsync(scope, id);
        if (current is null || current.Automation.State == "archived") return null;
        var savedTarget = current.Revision.ExecutionTarget;
        var target = requestedTarget ?? savedTarget;
        var action = ActionOf(current.Revision);
        if (target != savedTarget) await RequireTargetMoveAsync(scope, action, target);
        else
        {
            await RequireTargetAllowedAsync(scope.OrganizationId, target);
            if (target == "cloud" && action.Kind == "agent") await RequireCloudAgentAsync(scope);
        }
        // This one occurrence runs on `target`; the Automation keeps its own.
        var revision = current.Revision;
        Failed? blocked = null;
        if (current.Automation.NeedsAttentionJson is { } attention)
        {
            var reason = JsonDocument.Parse(attention).RootElement;
            blocked = new(reason.GetProperty("code").GetString()!, reason.GetProperty("message").GetString()!);
        }
        else if (action.Kind == "saved_script")
        {
            if (!await OwnerActiveAsync(scope.OrganizationId, scope.MemberId)) throw new AutomationFailure(409, "automation_owner_inactive", "The Automation owner is no longer an active organization member.");
        }
        else
        {
            var access = await ModelAccessAsync(scope.OrganizationId, scope.MemberId, ModelOf(revision), target);
            if (access is not null && ShouldApply(ModelOf(revision), access, target == "cloud" || scope.ModelAttention)) blocked = access;
        }
        var now = Now();
        if (blocked is not null)
        {
            // A model only the desktop has blocks one cloud run, not the Automation's own schedule.
            if (revision.ExecutionTarget == target) await MarkNeedsAttentionAsync(id, revision.Id, blocked.Code, blocked.Message, now);
            return await queue.RecordSkippedManualAsync(current.Automation, revision, target, blocked, now);
        }
        var claim = await queue.ClaimAsync(new ClaimRequest(current.Automation, revision, target, "manual", null, Auto.NewId("nonce"), options.Value.LeaseMs, RunQueue.ManualClaimWindowMs, now));
        return claim.Run;
    }

    public async Task<(List<AutomationRun> Items, string? NextCursor)> ListRunsAsync(Scope scope, string id, string? cursor, int limit)
    {
        limit = Math.Clamp(limit, 1, 100);
        if (await GetAsync(scope, id, reconcile: false) is null) return ([], null);
        var query = db.Set<AutomationRun>().AsNoTracking().Where(r => r.AutomationId == id);
        if (cursor is not null) query = query.Where(r => string.Compare(r.Id, cursor) < 0);
        var rows = await query.OrderByDescending(r => r.Id).Take(limit + 1).ToListAsync();
        var page = rows.Take(limit).ToList();
        return (page, rows.Count > limit ? page.LastOrDefault()?.Id : null);
    }

    /// <summary>Runs of the caller's Automations placed in [from, to) by scheduled time, else start, else creation; for calendar views.</summary>
    public async Task<(List<AutomationRun> Items, string? NextCursor)> ListRunsInRangeAsync(Scope scope, long fromMs, long toMs, string? cursor, int limit)
    {
        const long pad = 24 * 60 * 60 * 1000;
        limit = Math.Clamp(limit, 1, 500);
        var query = from r in db.Set<AutomationRun>().AsNoTracking()
                    join a in db.Set<Automation>().AsNoTracking() on r.AutomationId equals a.Id
                    where a.OrganizationId == scope.OrganizationId && a.OwnerMemberId == scope.MemberId && r.CreatedAt >= fromMs - pad && r.CreatedAt < toMs + pad
                    select r;
        if (cursor is not null) query = query.Where(r => string.Compare(r.Id, cursor) > 0);
        var rows = await query.OrderBy(r => r.Id).Take(limit + 1).ToListAsync();
        var scanned = rows.Take(limit).ToList();
        var items = scanned.Where(r => { var at = r.ScheduledFor ?? r.StartedAt ?? r.CreatedAt; return at >= fromMs && at < toMs; }).ToList();
        return (items, rows.Count > limit ? scanned.LastOrDefault()?.Id : null);
    }

    public async Task<(AutomationRun Run, Automation Automation, AutomationRevision Revision, List<AutomationRunEvent> Events)?> GetRunAsync(Scope scope, string runId)
    {
        var run = await db.Set<AutomationRun>().AsNoTracking().FirstOrDefaultAsync(r => r.Id == runId);
        if (run is null) return null;
        var automation = await db.Set<Automation>().AsNoTracking().FirstOrDefaultAsync(a => a.Id == run.AutomationId && a.OrganizationId == scope.OrganizationId && a.OwnerMemberId == scope.MemberId);
        if (automation is null) return null;
        var revision = await db.Set<AutomationRevision>().AsNoTracking().FirstAsync(r => r.Id == run.RevisionId);
        var events = await db.Set<AutomationRunEvent>().AsNoTracking().Where(e => e.RunId == runId).OrderBy(e => e.Attempt).ThenBy(e => e.Sequence).ToListAsync();
        return (run, automation, revision, events);
    }

    public async Task<AutomationRun?> CancelRunAsync(Scope scope, string runId)
    {
        var owned = await db.Set<AutomationRun>().AsNoTracking().Where(r => r.Id == runId && db.Set<Automation>().Any(a => a.Id == r.AutomationId && a.OrganizationId == scope.OrganizationId && a.OwnerMemberId == scope.MemberId)).FirstOrDefaultAsync();
        return owned is null ? null : await queue.RequestCancellationAsync(runId, Now());
    }

    // ---------------------------------------------------------------- where Automations can run

    private static bool SessionOnly(string capabilitiesJson) => capabilitiesJson.Contains(RunnerCapability.SessionOnly, StringComparison.Ordinal);

    /// <summary>The latest moment any of the owner's desktops registered or asked for work.</summary>
    public async Task<long?> DesktopLastSeenAsync(string organizationId, string memberId)
    {
        var rows = await db.Set<AutomationRunner>().AsNoTracking().Where(r => r.OrganizationId == organizationId && r.OwnerMemberId == memberId).Select(r => new { r.LastSeenAt, r.CapabilitiesJson }).ToListAsync();
        var seen = rows.Where(r => !SessionOnly(r.CapabilitiesJson)).Select(r => (long?)r.LastSeenAt).DefaultIfEmpty(null).Max();
        return seen;
    }

    public static bool Connected(long? lastSeenAt, long now) => lastSeenAt is { } seen && now - seen <= RunQueue.PresenceWindowMs;

    public async Task<object> PresenceAsync(Scope scope)
    {
        var seen = await DesktopLastSeenAsync(scope.OrganizationId, scope.MemberId);
        return new { connected = Connected(seen, Now()), lastSeenAt = seen };
    }

    public async Task<object> ExecutionTargetsAsync(Scope scope)
    {
        var now = Now();
        var (desktopAllowed, cloudAllowed) = await AvailabilityAsync(scope.OrganizationId);
        var desktops = desktopAllowed
            ? (await db.Set<AutomationRunner>().AsNoTracking().Where(r => r.OrganizationId == scope.OrganizationId && r.OwnerMemberId == scope.MemberId).OrderByDescending(r => r.LastSeenAt).Take(100).ToListAsync())
                .Where(r => !SessionOnly(r.CapabilitiesJson))
                .Select(r => (object)new { kind = "desktop", id = r.Id, platform = r.Platform, appVersion = r.AppVersion, lastSeenAt = r.LastSeenAt, connected = Connected(r.LastSeenAt, now) })
            : [];
        var cloudOn = cloudAllowed && await cloud.AgentAvailableAsync(scope.OrganizationId, scope.MemberId);
        var cloudItem = cloudOn
            ? new { kind = "cloud", available = true, runtime = (string?)"headless", cloudComputer = false }
            : new { kind = "cloud", available = false, runtime = (string?)null, cloudComputer = false };
        return new { items = desktops.Append(cloudItem).ToList() };
    }
}

public static class CloudDefault
{
    public const string ProviderId = "openwork-cloud";
    public const string ModelId = "default";
}

public static class FreeModel
{
    public const string ProviderId = "opencode";
    public const string ModelId = "big-pickle";
}

public static class RunnerCapability
{
    public const string ModelAttention = "model_attention_v1";
    public const string SessionOnly = "remote_session_only_v1";
    public static readonly string[] All = ["model_attention_v1", "remote_session_v1", "remote_session_control_v1", "remote_session_only_v1", "remote_session_recovery_v1", "remote_session_answer_v1"];
}

public static class Auto
{
    public static string NewId(string prefix) => prefix == "nonce" ? Guid.NewGuid().ToString() : Ids.New(prefix);
}
