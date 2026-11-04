using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Automations;

namespace WorkAI360.Api.Features.Automations;

public sealed record ClaimRequest(Automation Automation, AutomationRevision Revision, string Target, string Trigger, long? ScheduledFor, string? Nonce, int LeaseMs, int ClaimWindowMs, long Now);

public sealed record ClaimResult(string Kind, AutomationRun Run);

/// <summary>A runner's identity: which person's desktop is talking, from its credential.</summary>
public sealed record RunnerIdentity(string OrganizationId, string OwnerMemberId, string RunnerId, IReadOnlyList<string> Capabilities, string? Audience, long ExpiresAt)
{
    public string LeaseOwner => $"desktop:{OwnerMemberId}:{RunnerId}";
}

public sealed record Assignment(AutomationRun Run, Automation Automation, AutomationRevision Revision);

/// <summary>
/// The run queue: starting occurrences, handing a run to exactly one desktop, keeping its lease alive, recording its events in order, ending it,
/// and recovering the ones whose runner went silent. Every state change is one conditional update (it names the state it expects), so two runners or two
/// server instances racing for the same run cannot both succeed: the database lets one statement change the row and the other finds nothing to change.
/// </summary>
public sealed class RunQueue(DenDbContext db, IOptions<AutomationOptions> options)
{
    public const int MaximumAttempts = 2;
    /// <summary>A manual run is claimable for this long: an idle desktop polls once a minute, plus discovery and claim.</summary>
    public const int ManualClaimWindowMs = 3 * 60_000;
    public const int MinClaimWindowMs = 60_000;
    /// <summary>A desktop counts as connected this long after it was last seen (idle streams do not write presence).</summary>
    public const long PresenceWindowMs = 10 * 60_000;
    public const string InterruptedMessage = "Run interrupted — the desktop execution lease expired.";
    public const string DesktopEngine = "openwork-desktop-runner-v1";

    private static readonly string[] Terminal = ["succeeded", "failed", "cancelled", "skipped"];
    private static readonly string[] Active = ["queued", "claimed", "running"];

    // ---------------------------------------------------------------- pure rules

    /// <summary>
    /// How long a desktop occurrence stays claimable: a recovery window, never past the next occurrence (a run still queued makes the next one overlap
    /// and skip), and never shorter than a minute.
    /// </summary>
    public static long ClaimDeadline(string trigger, long now, long windowMs, long? nextDueAt)
    {
        if (trigger == "manual") return now + windowMs;
        var requested = now + windowMs;
        var bounded = nextDueAt is { } next ? Math.Min(requested, next) : requested;
        var floor = now + Math.Min(windowMs, MinClaimWindowMs);
        return Math.Max(floor, bounded);
    }

    public static string IdempotencyKey(string automationId, long? scheduledFor, string? nonce)
    {
        if (scheduledFor is null && string.IsNullOrEmpty(nonce)) throw new ArgumentException("A manual occurrence needs a nonce");
        var occurrence = scheduledFor is null ? $"manual:{nonce}" : nonce is not null ? $"event:{nonce}" : scheduledFor.Value.ToString();
        return $"automation:{Uri.EscapeDataString(automationId)}:{Uri.EscapeDataString(occurrence)}";
    }

    public static string MissedMessage(bool busy, long? lastSeenAt, long now) =>
        busy ? "Missed — the desktop was busy with another Automation run."
        : AutomationService.Connected(lastSeenAt, now) ? "Missed — the connected desktop did not pick this up in time."
        : "Missed — no desktop was connected.";

    // ---------------------------------------------------------------- starting runs

    /// <summary>
    /// Records one occurrence as a queued run (or as skipped when another is still active, or as the run it already made). It runs under the Automation's
    /// row lock, so two replicas ticking at the same moment, or a manual run and a scheduled one, end with one run per occurrence.
    /// </summary>
    public async Task<ClaimResult> ClaimAsync(ClaimRequest request)
    {
        var automationId = request.Automation.Id;
        await using var tx = await db.Database.BeginTransactionAsync();
        var locked = await db.Set<Automation>().Where(a => a.Id == automationId).ExecuteUpdateAsync(s => s.SetProperty(a => a.UpdatedAt, a => a.UpdatedAt));
        var current = locked == 0 ? null : await db.Set<Automation>().AsNoTracking().FirstAsync(a => a.Id == automationId);
        var canRun = request.Trigger == "manual" ? current?.State is "active" or "inactive" : current?.State == "active";
        if (!canRun) { await tx.RollbackAsync(); throw new AutomationFailure(409, "automation_not_active"); }
        var key = IdempotencyKey(automationId, request.ScheduledFor, request.Nonce);
        var duplicate = await db.Set<AutomationRun>().AsNoTracking().FirstOrDefaultAsync(r => r.IdempotencyKey == key);
        if (duplicate is not null) { await tx.RollbackAsync(); return new ClaimResult("duplicate", duplicate); }
        var overlap = await db.Set<AutomationRun>().AnyAsync(r => r.AutomationId == automationId && (r.Status == "queued" || r.Status == "claimed" || r.Status == "running"));
        var schedule = AutomationSchedule.FromJson(request.Revision.ScheduleJson);
        var nextDueAt = request.Trigger == "manual" ? current!.NextDueAt : ScheduleMath.Next(schedule, request.ScheduledFor ?? request.Now);
        var run = new AutomationRun
        {
            Id = Auto.NewId("atr"), AutomationId = automationId, RevisionId = request.Revision.Id, Trigger = request.Trigger, ScheduledFor = request.ScheduledFor,
            IdempotencyKey = key, Status = overlap ? "skipped" : "queued", ExecutionTarget = request.Target,
            ClaimDeadlineAt = overlap ? null : ClaimDeadline(request.Trigger, request.Now, request.ClaimWindowMs, nextDueAt),
            ThreadId = Auto.NewId("ath"), ProviderId = request.Revision.ProviderId, ModelId = request.Revision.ModelId, ModelVariant = request.Revision.ModelVariant,
            FinishedAt = overlap ? request.Now : null, ResultSummary = overlap ? "Skipped because another occurrence is already active." : null,
            UsageJson = AutomationWire.EmptyUsage, CreatedAt = request.Now, UpdatedAt = request.Now,
        };
        db.Set<AutomationRun>().Add(run);
        // The owner's desktops hear about a queued desktop run at once (in the same transaction, so the hint never points at a run that does not exist).
        if (!overlap && request.Target == "desktop")
            db.Set<AutomationRunnerNotification>().Add(new AutomationRunnerNotification { OrganizationId = request.Automation.OrganizationId, OwnerMemberId = request.Automation.OwnerMemberId, EventType = "work_available", RunId = run.Id, CreatedAt = request.Now });
        await db.SaveChangesAsync();
        await db.Set<Automation>().Where(a => a.Id == automationId).ExecuteUpdateAsync(s => s.SetProperty(a => a.NextDueAt, nextDueAt).SetProperty(a => a.LatestRunAt, (long?)request.Now).SetProperty(a => a.UpdatedAt, request.Now));
        await tx.CommitAsync();
        db.ChangeTracker.Clear();
        return new ClaimResult(overlap ? "overlap" : "claimed", run);
    }

    /// <summary>Records a manual attempt that policy refused: a skipped run that says why, so the person sees it in the history.</summary>
    public async Task<AutomationRun> RecordSkippedManualAsync(Automation automation, AutomationRevision revision, string target, Failed reason, long now)
    {
        var run = new AutomationRun
        {
            Id = Auto.NewId("atr"), AutomationId = automation.Id, RevisionId = revision.Id, Trigger = "manual", IdempotencyKey = IdempotencyKey(automation.Id, null, Auto.NewId("nonce")),
            Status = "skipped", ExecutionTarget = target, ThreadId = Auto.NewId("ath"), ProviderId = revision.ProviderId, ModelId = revision.ModelId, ModelVariant = revision.ModelVariant,
            FinishedAt = now, ErrorJson = JsonSerializer.Serialize(new { code = reason.Code, message = reason.Message, retryable = false }), ResultSummary = reason.Message,
            UsageJson = AutomationWire.EmptyUsage, CreatedAt = now, UpdatedAt = now,
        };
        db.Set<AutomationRun>().Add(run);
        await db.SaveChangesAsync();
        await db.Set<Automation>().Where(a => a.Id == automation.Id).ExecuteUpdateAsync(s => s.SetProperty(a => a.LatestRunAt, (long?)now).SetProperty(a => a.UpdatedAt, now));
        db.ChangeTracker.Clear();
        return run;
    }

    // ---------------------------------------------------------------- the runner protocol

    /// <summary>Queued desktop runs of the owner that can still be claimed, oldest first. Every desktop sees the same list; a pinned one says which workspace it needs.</summary>
    public async Task<List<object>> DiscoverAsync(RunnerIdentity who, long now, int limit)
    {
        var rows = await (from r in db.Set<AutomationRun>().AsNoTracking()
                          join a in db.Set<Automation>().AsNoTracking() on r.AutomationId equals a.Id
                          join v in db.Set<AutomationRevision>().AsNoTracking() on r.RevisionId equals v.Id
                          where a.OrganizationId == who.OrganizationId && a.OwnerMemberId == who.OwnerMemberId && r.Status == "queued" && r.ExecutionTarget == "desktop" && r.ClaimDeadlineAt > now
                          orderby r.CreatedAt, r.Id
                          select new { r.Id, v.ExecutionTarget, v.WorkspaceId }).Take(limit).ToListAsync();
        // Unpinned items keep their original two-field shape for released runners.
        return rows.Select(x => x.ExecutionTarget == "desktop" && x.WorkspaceId is { } w
            ? (object)new { runId = x.Id, executionTarget = "desktop", workspaceId = w }
            : new { runId = x.Id, executionTarget = "desktop" }).ToList();
    }

    /// <summary>
    /// Hands a queued run to this runner. One statement changes the run from queued to running only if it is still queued and still inside its claim
    /// window, so of any number of runners asking at once exactly one gets it. The same runner asking again gets its own run back (a reconnect).
    /// </summary>
    public async Task<Assignment?> ClaimDesktopAsync(RunnerIdentity who, string runId, long now)
    {
        var owner = who.LeaseOwner;
        var lease = now + options.Value.LeaseMs;
        var changed = await db.Set<AutomationRun>().Where(r => r.Id == runId && r.Status == "queued" && r.ExecutionTarget == "desktop" && r.ClaimDeadlineAt > now
                && db.Set<Automation>().Any(a => a.Id == r.AutomationId && a.OrganizationId == who.OrganizationId && a.OwnerMemberId == who.OwnerMemberId))
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.Status, "running").SetProperty(r => r.LeaseOwner, owner).SetProperty(r => r.LeaseExpiresAt, (long?)lease)
                .SetProperty(r => r.HeartbeatAt, (long?)now).SetProperty(r => r.AttemptCount, r => r.AttemptCount + 1).SetProperty(r => r.EngineKind, DesktopEngine)
                .SetProperty(r => r.StartedAt, r => r.StartedAt ?? now).SetProperty(r => r.UpdatedAt, now));
        var run = await db.Set<AutomationRun>().AsNoTracking().FirstOrDefaultAsync(r => r.Id == runId && r.LeaseOwner == owner && (r.Status == "claimed" || r.Status == "running")
            && db.Set<Automation>().Any(a => a.Id == r.AutomationId && a.OrganizationId == who.OrganizationId && a.OwnerMemberId == who.OwnerMemberId));
        _ = changed;
        if (run is null) return null;
        var automation = await db.Set<Automation>().AsNoTracking().FirstAsync(a => a.Id == run.AutomationId);
        var revision = await db.Set<AutomationRevision>().AsNoTracking().FirstAsync(r => r.Id == run.RevisionId);
        return new Assignment(run, automation, revision);
    }

    /// <summary>Extends the lease of a run this runner holds. Null when the lease is gone (it expired, the run ended, or another attempt took over).</summary>
    public async Task<(int Attempt, long LeaseExpiresAt, bool CancelRequested)?> HeartbeatAsync(RunnerIdentity who, string runId, int attempt, long now)
    {
        var owner = who.LeaseOwner;
        var lease = now + options.Value.LeaseMs;
        var changed = await db.Set<AutomationRun>().Where(r => r.Id == runId && r.LeaseOwner == owner && r.AttemptCount == attempt && r.Status == "running" && r.LeaseExpiresAt > now)
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.HeartbeatAt, (long?)now).SetProperty(r => r.LeaseExpiresAt, (long?)lease).SetProperty(r => r.UpdatedAt, now));
        if (changed == 0) return null;
        var row = await db.Set<AutomationRun>().AsNoTracking().Where(r => r.Id == runId && r.LeaseOwner == owner && r.AttemptCount == attempt && r.Status == "running")
            .Select(r => new { r.LeaseExpiresAt, r.CancelRequestedAt }).FirstOrDefaultAsync();
        return row?.LeaseExpiresAt is { } expires ? (attempt, expires, row.CancelRequestedAt is not null) : null;
    }

    /// <summary>
    /// Records the runner's next step. The step must be the one after the last recorded, in this attempt, while the lease is valid; a repeat of a step already
    /// recorded (a retry after a dropped answer) returns that step instead of making a second. Two requests for the same step end with one event.
    /// </summary>
    public async Task<AutomationRunEvent> AppendEventAsync(RunnerIdentity who, string runId, int attempt, int sequence, string type, string payloadJson, long now)
    {
        var owner = who.LeaseOwner;
        var key = $"desktop:{runId}:{attempt}:{sequence}";
        await using var tx = await db.Database.BeginTransactionAsync();
        // Step one: move the run's sequence counter forward by exactly one, only if the lease is valid and the counter is where the runner expects.
        var advanced = await db.Set<AutomationRun>().Where(r => r.Id == runId && r.LeaseOwner == owner && r.AttemptCount == attempt && r.Status == "running" && r.LeaseExpiresAt > now && r.EngineSequence == sequence - 1)
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.EngineSequence, sequence).SetProperty(r => r.UpdatedAt, now));
        if (advanced == 0)
        {
            await tx.RollbackAsync();
            var duplicate = await db.Set<AutomationRunEvent>().AsNoTracking().FirstOrDefaultAsync(e => e.RunId == runId && e.Attempt == attempt && e.IdempotencyKey == key);
            var held = await db.Set<AutomationRun>().AsNoTracking().AnyAsync(r => r.Id == runId && r.LeaseOwner == owner && r.AttemptCount == attempt && r.Status == "running" && r.LeaseExpiresAt > now);
            if (!held) throw new AutomationFailure(409, "runner_lease_lost");
            if (duplicate is not null) return duplicate;
            throw new AutomationFailure(409, "automation_runner_event_sequence_gap");
        }
        var created = new AutomationRunEvent { Id = Auto.NewId("ate"), RunId = runId, Attempt = attempt, Sequence = sequence, EventType = type, PayloadJson = payloadJson, IdempotencyKey = key, CreatedAt = now };
        db.Set<AutomationRunEvent>().Add(created);
        await db.SaveChangesAsync();
        await tx.CommitAsync();
        db.ChangeTracker.Clear();
        return created;
    }

    /// <summary>
    /// Ends a run the runner holds. One statement moves it from running to the result, only while this runner holds a valid lease for this attempt. Telling
    /// us the same result again returns the stored run; a different result for a run that already ended is a conflict; a lost lease is a lost lease.
    /// </summary>
    public async Task<AutomationRun> CompleteAsync(RunnerIdentity who, string runId, int attempt, string status, string? resultSummary, string usageJson, string? errorJson, string? receiptJson, long now)
    {
        var owner = who.LeaseOwner;
        var changed = await db.Set<AutomationRun>().Where(r => r.Id == runId && r.LeaseOwner == owner && r.AttemptCount == attempt && r.Status == "running" && r.LeaseExpiresAt > now)
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.Status, status).SetProperty(r => r.ResultSummary, resultSummary).SetProperty(r => r.UsageJson, usageJson)
                .SetProperty(r => r.ErrorJson, errorJson).SetProperty(r => r.EngineReceiptJson, receiptJson).SetProperty(r => r.FinishedAt, (long?)now)
                .SetProperty(r => r.LeaseExpiresAt, (long?)null).SetProperty(r => r.HeartbeatAt, (long?)now).SetProperty(r => r.UpdatedAt, now));
        var current = await db.Set<AutomationRun>().AsNoTracking().FirstOrDefaultAsync(r => r.Id == runId && r.LeaseOwner == owner && r.AttemptCount == attempt);
        if (current is null) throw new AutomationFailure(409, "runner_lease_lost");
        if (changed > 0) return current;
        if (Terminal.Contains(current.Status))
        {
            if (current.Status != status) throw new AutomationFailure(409, "terminal_result_conflict");
            return current;
        }
        throw new AutomationFailure(409, "runner_lease_lost");
    }

    // ---------------------------------------------------------------- cancelling

    /// <summary>A queued run is cancelled on the spot; one a runner holds is only marked, and its next heartbeat tells the runner to stop.</summary>
    public async Task<AutomationRun?> RequestCancellationAsync(string runId, long now)
    {
        var immediate = await db.Set<AutomationRun>().Where(r => r.Id == runId && r.Status == "queued")
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.Status, "cancelled").SetProperty(r => r.CancelRequestedAt, (long?)now).SetProperty(r => r.FinishedAt, (long?)now).SetProperty(r => r.UpdatedAt, now));
        if (immediate == 0)
        {
            var marked = await db.Set<AutomationRun>().Where(r => r.Id == runId && r.CancelRequestedAt == null && !Terminal.Contains(r.Status))
                .ExecuteUpdateAsync(s => s.SetProperty(r => r.CancelRequestedAt, (long?)now).SetProperty(r => r.UpdatedAt, now));
            // A desktop holding the run is told on its stream, so it need not wait for its next heartbeat.
            if (marked > 0)
            {
                var held = await (from r in db.Set<AutomationRun>().AsNoTracking()
                                  join a in db.Set<Automation>().AsNoTracking() on r.AutomationId equals a.Id
                                  where r.Id == runId && r.ExecutionTarget == "desktop" && (r.Status == "claimed" || r.Status == "running")
                                  select new { a.OrganizationId, a.OwnerMemberId }).FirstOrDefaultAsync();
                if (held is not null)
                {
                    db.Set<AutomationRunnerNotification>().Add(new AutomationRunnerNotification { OrganizationId = held.OrganizationId, OwnerMemberId = held.OwnerMemberId, EventType = "cancellation", RunId = runId, CreatedAt = now });
                    await db.SaveChangesAsync();
                    db.ChangeTracker.Clear();
                }
            }
        }
        return await db.Set<AutomationRun>().AsNoTracking().FirstOrDefaultAsync(r => r.Id == runId);
    }

    // ---------------------------------------------------------------- recovery

    /// <summary>
    /// A run whose runner stopped sending heartbeats is queued again (the first time) or failed. The update names the lease it saw expire, so a runner that
    /// extended it in the meantime keeps its run, and two instances recovering the same run change it once. Returns the runs that ended.
    /// </summary>
    public async Task<List<string>> RecoverExpiredLeasesAsync(long now, int limit)
    {
        var rows = await db.Set<AutomationRun>().AsNoTracking().Where(r => (r.Status == "claimed" || r.Status == "running") && r.LeaseExpiresAt < now && r.LeaseOwner != null)
            .OrderBy(r => r.LeaseExpiresAt).Take(limit).ToListAsync();
        var ended = new List<string>();
        foreach (var run in rows)
        {
            var retry = run.AttemptCount < MaximumAttempts;
            var owner = run.LeaseOwner;
            var desktop = run.ExecutionTarget == "desktop";
            var message = desktop ? InterruptedMessage : "The execution lease expired.";
            var error = retry ? null : JsonSerializer.Serialize(new { code = "lease_lost", message, retryable = false });
            var summary = !retry && desktop ? InterruptedMessage : run.ResultSummary;
            var status = retry ? "queued" : "failed";
            var finished = retry ? (long?)null : now;
            var changed = await db.Set<AutomationRun>().Where(r => r.Id == run.Id && r.LeaseOwner == owner && r.LeaseExpiresAt < now && (r.Status == "claimed" || r.Status == "running"))
                .ExecuteUpdateAsync(s => s.SetProperty(r => r.Status, status).SetProperty(r => r.LeaseOwner, (string?)null).SetProperty(r => r.LeaseExpiresAt, (long?)null)
                    .SetProperty(r => r.EngineSequence, retry ? 0 : run.EngineSequence).SetProperty(r => r.ErrorJson, error).SetProperty(r => r.ResultSummary, summary)
                    .SetProperty(r => r.FinishedAt, finished).SetProperty(r => r.UpdatedAt, now));
            if (changed > 0 && !retry) ended.Add(run.Id);
        }
        return ended;
    }

    /// <summary>A desktop run nobody claimed in time is recorded as missed (or interrupted, if it had been tried), saying why in words a person can act on.</summary>
    public async Task<List<string>> ExpireUnclaimedDesktopAsync(long now, int limit)
    {
        var rows = await (from r in db.Set<AutomationRun>().AsNoTracking()
                          join a in db.Set<Automation>().AsNoTracking() on r.AutomationId equals a.Id
                          join v in db.Set<AutomationRevision>().AsNoTracking() on r.RevisionId equals v.Id
                          where r.Status == "queued" && r.ExecutionTarget == "desktop" && r.ClaimDeadlineAt <= now
                          orderby r.ClaimDeadlineAt
                          select new { Run = r, a.OrganizationId, a.OwnerMemberId, Pinned = v.ExecutionTarget == "desktop" && v.WorkspaceId != null }).Take(limit).ToListAsync();
        var expired = new List<string>();
        foreach (var row in rows)
        {
            var run = row.Run;
            var attempted = run.AttemptCount > 0 || run.StartedAt is not null;
            var code = attempted ? "lease_lost" : "runner_unavailable";
            var message = attempted ? InterruptedMessage : await MissedReasonAsync(row.OrganizationId, row.OwnerMemberId, row.Pinned, now);
            var status = attempted ? "failed" : "skipped";
            var error = JsonSerializer.Serialize(new { code, message, retryable = false });
            var changed = await db.Set<AutomationRun>().Where(r => r.Id == run.Id && r.Status == "queued" && r.AttemptCount == run.AttemptCount && r.ClaimDeadlineAt <= now)
                .ExecuteUpdateAsync(s => s.SetProperty(r => r.Status, status).SetProperty(r => r.ErrorJson, error).SetProperty(r => r.ResultSummary, message)
                    .SetProperty(r => r.FinishedAt, (long?)now).SetProperty(r => r.UpdatedAt, now));
            if (changed > 0) expired.Add(run.Id);
        }
        return expired;
    }

    private async Task<string> MissedReasonAsync(string organizationId, string memberId, bool pinned, long now)
    {
        var busy = await (from r in db.Set<AutomationRun>().AsNoTracking()
                          join a in db.Set<Automation>().AsNoTracking() on r.AutomationId equals a.Id
                          where a.OrganizationId == organizationId && a.OwnerMemberId == memberId && r.ExecutionTarget == "desktop" && r.Status == "running"
                          select r.Id).AnyAsync();
        var runners = await db.Set<AutomationRunner>().AsNoTracking().Where(r => r.OrganizationId == organizationId && r.OwnerMemberId == memberId).Select(r => new { r.LastSeenAt, r.CapabilitiesJson }).ToListAsync();
        long? lastSeen = runners.Where(r => !r.CapabilitiesJson.Contains(RunnerCapability.SessionOnly, StringComparison.Ordinal)).Select(r => (long?)r.LastSeenAt).DefaultIfEmpty(null).Max();
        // A desktop leaves a run pinned to a workspace it lacks for the desktop that has it, so a connected, idle one means none has it.
        if (!busy && pinned && AutomationService.Connected(lastSeen, now)) return "Missed — no connected desktop has this Automation's workspace.";
        return MissedMessage(busy, lastSeen, now);
    }

    /// <summary>Ends a run that must not execute (access lost, the kind turned off, no runtime).</summary>
    public async Task SkipAsync(string runId, string code, string message, long now)
    {
        var error = JsonSerializer.Serialize(new { code, message, retryable = false });
        await db.Set<AutomationRun>().Where(r => r.Id == runId && (r.Status == "queued" || r.Status == "running"))
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.Status, "skipped").SetProperty(r => r.ErrorJson, error).SetProperty(r => r.ResultSummary, message)
                .SetProperty(r => r.LeaseOwner, (string?)null).SetProperty(r => r.LeaseExpiresAt, (long?)null).SetProperty(r => r.FinishedAt, (long?)now).SetProperty(r => r.UpdatedAt, now));
    }
}
