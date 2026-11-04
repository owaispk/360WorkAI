using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Automations;
using WorkAI360.Api.Features.OrgAdmin;

namespace WorkAI360.Api.Features.Automations;

/// <summary>
/// Automations (scheduled work for one person, run on their desktops through leases) and telemetry (usage events and the analytics computed from them).
/// See docs/features/automations.md.
/// </summary>
public sealed class AutomationFeature : IFeature
{
    public void AddServices(IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<AutomationOptions>(configuration.GetSection(AutomationOptions.Section));
        services.AddScoped<AutomationService>();
        services.AddScoped<RunQueue>();
        services.AddScoped<RunnerAuth>();
        services.AddScoped<RunnerRegistry>();
        services.AddScoped<RunnerService>();
        services.AddScoped<AutomationTicker>();
        services.AddScoped<WorkflowActions>();
        services.AddScoped<AutomationAudit>();
        services.AddScoped<TelemetryService>();
        services.AddSingleton<ICloudAutomationRuntime, NoCloudAutomationRuntime>();
        services.AddHostedService<AutomationSchedulerLoop>();
    }

    public void MapEndpoints(WebApplication app)
    {
        AutomationEndpoints.Map(app);
        RunnerEndpoints.Map(app);
        TelemetryEndpoints.Map(app);
    }
}

/// <summary>What the runner routes do beyond the queue: the access checks the reference makes at the last gate, and pausing an Automation whose model is gone.</summary>
public sealed class RunnerService(DenDbContext db, RunQueue queue, AutomationService service, AutomationAudit runAudit)
{
    public async Task<bool> DesktopAllowedAsync(RunnerIdentity who) => await service.TargetAllowedAsync(who.OrganizationId, "desktop");

    /// <summary>The assignment a runner receives, or null when the run is no longer claimable (or access to its model was revoked after it was queued).</summary>
    public async Task<object?> ClaimAsync(RunnerIdentity who, string runId)
    {
        var now = AutomationService.Now();
        var claimed = await queue.ClaimDesktopAsync(who, runId, now);
        if (claimed?.Run.LeaseExpiresAt is not { } lease) return null;
        // Last gate before the assignment leaves the server: access revoked after the run was queued must not reach the runner.
        var model = AutomationService.ModelOf(claimed.Revision);
        var access = await service.ModelAccessAsync(who.OrganizationId, who.OwnerMemberId, model, "desktop");
        if (access is not null && AutomationService.ShouldApply(model, access, who.Capabilities.Contains(RunnerCapability.ModelAttention)))
        {
            await queue.SkipAsync(claimed.Run.Id, access.Code, access.Message, now);
            await runAudit.CompletedAsync(claimed.Run.Id, AutomationAudit.Executor);
            await service.MarkNeedsAttentionAsync(claimed.Automation.Id, claimed.Revision.Id, access.Code, access.Message, now);
            return null;
        }
        return new
        {
            executionTarget = "desktop", runId = claimed.Run.Id, automationId = claimed.Automation.Id, automationName = claimed.Automation.Name,
            instructions = claimed.Revision.Instructions, model = new { providerId = model.ProviderId, modelId = model.ModelId, variant = model.Variant },
            timeoutMs = claimed.Revision.MaximumRuntimeMs, leaseExpiresAt = lease, attempt = claimed.Run.AttemptCount, workspaceId = claimed.Revision.WorkspaceId,
        };
    }

    public async Task<AutomationRun> CompleteAsync(RunnerIdentity who, string runId, RunnerResult result)
    {
        var now = AutomationService.Now();
        var receipt = new Dictionary<string, string>();
        if (result.SessionId is not null) receipt["nativeThreadId"] = result.SessionId;
        if (result.WorkspaceId is not null) receipt["workspaceId"] = result.WorkspaceId;
        var run = await queue.CompleteAsync(who, runId, result.Attempt, result.Status, result.Summary, result.UsageJson, result.ErrorJson,
            receipt.Count == 0 ? null : JsonSerializer.Serialize(receipt), now);
        // Only the report that ended the run is recorded: a repeated report finds an older end time and records nothing.
        if (run.FinishedAt == now) await runAudit.CompletedAsync(run.Id, await runAudit.OwnerActorAsync(who.OrganizationId, who.OwnerMemberId) ?? AutomationAudit.Executor);
        // A model the desktop lacks pauses the Automation's own schedule; a one-off run on the other target says nothing about it.
        if (result.ErrorCode is "model_access_lost" or "provider_unavailable")
        {
            var revision = await db.Set<AutomationRevision>().AsNoTracking().FirstOrDefaultAsync(r => r.Id == run.RevisionId);
            if (revision is not null && revision.ExecutionTarget != "cloud")
                await service.MarkNeedsAttentionAsync(run.AutomationId, run.RevisionId, result.ErrorCode, result.ErrorMessage ?? "", now);
        }
        return run;
    }
}

/// <summary>What the scheduler does each cycle: recover runs whose runner went silent, record the unclaimed as missed, start what is due.</summary>
public sealed class AutomationTicker(DenDbContext db, RunQueue queue, AutomationService service, RunnerRegistry registry, WorkflowActions workflows, AutomationAudit runAudit, IOptions<AutomationOptions> options, IConfiguration configuration)
{
    public async Task<List<string>> TickAsync(long? at = null, int? batch = null)
    {
        var now = at ?? AutomationService.Now();
        var size = batch ?? options.Value.BatchSize;
        foreach (var ended in await queue.RecoverExpiredLeasesAsync(now, size)) await runAudit.CompletedAsync(ended, AutomationAudit.Scheduler);
        foreach (var missed in await queue.ExpireUnclaimedDesktopAsync(now, size)) await runAudit.CompletedAsync(missed, AutomationAudit.Scheduler);
        await registry.PruneAsync(now);
        await registry.PruneNotificationsAsync(now);
        // Cloud runs have nowhere to execute unless a runtime is registered: say so instead of leaving them queued (a queued run makes every later occurrence overlap).
        var queuedCloud = await db.Set<AutomationRun>().AsNoTracking().Where(r => r.Status == "queued" && r.ExecutionTarget == "cloud").OrderBy(r => r.CreatedAt).Take(size).ToListAsync();
        foreach (var run in queuedCloud)
        {
            var owner = await db.Set<Automation>().AsNoTracking().Where(a => a.Id == run.AutomationId).Select(a => new { a.OrganizationId, a.OwnerMemberId }).FirstOrDefaultAsync();
            // A Workflow runs here, in Den, so it needs only cloud Automations to be on; an agent needs a cloud runtime too.
            var revision = await db.Set<AutomationRevision>().AsNoTracking().FirstAsync(r => r.Id == run.RevisionId);
            if (owner is null || await service.TargetAllowedAsync(owner.OrganizationId, "cloud") && (WorkflowActions.IsWorkflowRun(revision) || await HasCloudRuntimeAsync(owner.OrganizationId, owner.OwnerMemberId))) continue;
            await SkipAsync(run.Id, "execution_runtime_unavailable", "Cloud Automations are turned off for this organization, or no cloud runtime is available.", now);
        }
        var started = new List<string>();
        var due = await db.Set<Automation>().AsNoTracking().Where(a => a.State == "active" && a.NextDueAt <= now).OrderBy(a => a.NextDueAt).ThenBy(a => a.Id).Take(size).ToListAsync();
        foreach (var item in await ItemsAsync(due))
        {
            if (item.Automation.NextDueAt is not { } scheduledFor) continue;
            if (await DispatchAsync(item, scheduledFor, now) is { } runId) started.Add(runId);
        }
        // Workflow runs (scheduled or "run now") execute here; each is taken by one conditional update, so instances never run one twice.
        await workflows.RunQueuedAsync(now, size, CancellationToken.None);
        return started;
    }

    /// <summary>Ends a run that must not execute and records its end.</summary>
    private async Task SkipAsync(string runId, string code, string message, long now)
    {
        await queue.SkipAsync(runId, code, message, now);
        await runAudit.CompletedAsync(runId, AutomationAudit.Scheduler);
    }

    private Task<bool> HasCloudRuntimeAsync(string organizationId, string memberId) =>
        service.CloudAgentAvailableAsync(organizationId, memberId);

    private async Task<List<Item>> ItemsAsync(List<Automation> automations)
    {
        var ids = automations.Select(a => a.CurrentRevisionId).ToList();
        var revisions = await db.Set<AutomationRevision>().AsNoTracking().Where(r => ids.Contains(r.Id)).ToDictionaryAsync(r => r.Id);
        return automations.Select(a => new Item(a, revisions[a.CurrentRevisionId], null)).ToList();
    }

    /// <summary>
    /// Starts one due occurrence, or records why it was skipped. The occurrence is claimed even when a check fails, so the schedule advances durably and
    /// the person sees why. Returns the run's id when work was queued.
    /// </summary>
    private async Task<string?> DispatchAsync(Item item, long scheduledFor, long now)
    {
        var action = AutomationService.ActionOf(item.Revision);
        var model = AutomationService.ModelOf(item.Revision);
        var target = item.Revision.ExecutionTarget;
        Failed? access = action.Kind == "saved_script"
            ? (await service.OwnerActiveAsync(item.Automation.OrganizationId, item.Automation.OwnerMemberId) ? null : new Failed("owner_membership_lost", "The Automation owner is no longer active."))
            : await service.ModelAccessAsync(item.Automation.OrganizationId, item.Automation.OwnerMemberId, model, target);
        ClaimResult claim;
        try
        {
            claim = await queue.ClaimAsync(new ClaimRequest(item.Automation, item.Revision, target, "scheduled", scheduledFor, null, options.Value.LeaseMs, options.Value.RunnerClaimDeadlineMs, now));
        }
        catch (AutomationFailure failure) when (failure.Error == "automation_not_active") { return null; }
        if (claim.Kind == "overlap") await runAudit.CompletedAsync(claim.Run.Id, AutomationAudit.Scheduler);
        if (claim.Kind != "claimed") return null;
        await runAudit.StartedAsync(claim.Run.Id);
        var schedule = AutomationSchedule.FromJson(item.Revision.ScheduleJson);
        if (schedule.Kind == "interval" && !FeatureState.Resolve(configuration, "automationIntervalSchedules"))
        {
            // Turned off after the Automation was made: it stays, and each occurrence is recorded as skipped until it is back.
            await SkipAsync(claim.Run.Id, "execution_runtime_unavailable", "Every-few-hours schedules are turned off for this organization.", now);
            return null;
        }
        if (!await service.TargetAllowedAsync(item.Automation.OrganizationId, target))
        {
            await SkipAsync(claim.Run.Id, "execution_runtime_unavailable", $"{(target == "cloud" ? "Cloud" : "Desktop")} Automations are turned off for this organization.", now);
            return null;
        }
        if (access is not null && AutomationService.ShouldApply(model, access, target == "cloud"))
        {
            await SkipAsync(claim.Run.Id, access.Code, access.Message, now);
            await service.MarkNeedsAttentionAsync(item.Automation.Id, item.Revision.Id, access.Code, access.Message, now);
            return null;
        }
        return claim.Run.Id;
    }
}

/// <summary>Runs <see cref="AutomationTicker"/> on a timer, so due Automations start and abandoned runs are recovered without anyone calling.</summary>
public sealed class AutomationSchedulerLoop(IServiceScopeFactory scopes, IOptions<AutomationOptions> options, ILogger<AutomationSchedulerLoop> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Value.SchedulerEnabled) return;
        var delay = TimeSpan.FromMilliseconds(Math.Max(1000, options.Value.PollIntervalMs));
        // Let startup (migrations, first requests) finish before the first cycle.
        try { await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken); } catch (OperationCanceledException) { return; }
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await using var scope = scopes.CreateAsyncScope();
                await scope.ServiceProvider.GetRequiredService<AutomationTicker>().TickAsync();
            }
            catch (Exception e) when (e is not OperationCanceledException) { logger.LogError(e, "Automation scheduler cycle failed"); }
            try { await Task.Delay(delay, stoppingToken); } catch (OperationCanceledException) { return; }
        }
    }
}
