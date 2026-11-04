using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace WorkAI360.Api.Domain.Automations;

// Every time in this file is epoch milliseconds (a long): that is what the wire carries, it compares the same way on SQLite and MySQL, and a lease
// deadline is therefore an exact number rather than a rounded timestamp.

/// <summary>
/// Work that runs on a schedule for one person (its owner). The owner sees and changes it; nobody else does. Behavior lives in immutable
/// <see cref="AutomationRevision"/>s: a change to what runs, when, or on what model makes a new one and applies to future runs at once.
/// </summary>
public sealed class Automation
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string OwnerMemberId { get; set; }
    public required string Name { get; set; }
    /// <summary>active, inactive, needs_attention or archived.</summary>
    public required string State { get; set; }
    public required string CurrentRevisionId { get; set; }
    /// <summary>When the scheduler next starts it; null while it is not active or has no clock time.</summary>
    public long? NextDueAt { get; set; }
    public long? LatestRunAt { get; set; }
    public string? LatestSuccessfulRunId { get; set; }
    public string? LatestSuccessfulResultJson { get; set; }
    /// <summary>JSON <c>{code, message, occurredAt}</c> while the state is needs_attention.</summary>
    public string? NeedsAttentionJson { get; set; }
    public long CreatedAt { get; set; }
    public long UpdatedAt { get; set; }
    public long? ArchivedAt { get; set; }
}

public sealed class AutomationRevision
{
    public required string Id { get; set; }
    public required string AutomationId { get; set; }
    public int Version { get; set; }
    public required string Instructions { get; set; }
    public required string ScheduleKind { get; set; }
    public required string ScheduleJson { get; set; }
    public required string ProviderId { get; set; }
    public required string ModelId { get; set; }
    public string? ModelVariant { get; set; }
    /// <summary>JSON: <c>{kind: "agent", instructions, model}</c> or <c>{kind: "saved_script", script, input}</c>.</summary>
    public required string ActionJson { get; set; }
    /// <summary>desktop or cloud.</summary>
    public required string ExecutionTarget { get; set; }
    /// <summary>The desktop workspace this is pinned to, or null for the desktop's active one.</summary>
    public string? WorkspaceId { get; set; }
    public int MaximumRuntimeMs { get; set; }
    public required string Digest { get; set; }
    public long CreatedAt { get; set; }
}

/// <summary>
/// One occurrence of an Automation. It is queued, claimed by exactly one runner under a lease that the runner keeps extending, and ends in a
/// terminal status (succeeded, failed, cancelled or skipped). Every change to it is a conditional update, so two runners racing never both win.
/// </summary>
public sealed class AutomationRun
{
    public required string Id { get; set; }
    public required string AutomationId { get; set; }
    public required string RevisionId { get; set; }
    /// <summary>scheduled, recovery or manual.</summary>
    public required string Trigger { get; set; }
    public long? ScheduledFor { get; set; }
    /// <summary>One occurrence is made once: the same key twice finds the first run.</summary>
    public required string IdempotencyKey { get; set; }
    public required string Status { get; set; }
    public required string ExecutionTarget { get; set; }
    /// <summary>Until when a queued desktop run may be claimed; after that it is recorded as missed.</summary>
    public long? ClaimDeadlineAt { get; set; }
    public string? LeaseOwner { get; set; }
    public long? LeaseExpiresAt { get; set; }
    public long? HeartbeatAt { get; set; }
    public int AttemptCount { get; set; }
    public long? CancelRequestedAt { get; set; }
    public string? EngineKind { get; set; }
    public string? EngineReceiptJson { get; set; }
    /// <summary>The last event sequence the runner recorded in this attempt; the next one must be this plus one.</summary>
    public int EngineSequence { get; set; }
    public required string ThreadId { get; set; }
    public required string ProviderId { get; set; }
    public required string ModelId { get; set; }
    public string? ModelVariant { get; set; }
    public long? StartedAt { get; set; }
    public long? FinishedAt { get; set; }
    public string? ErrorJson { get; set; }
    public string? ResultSummary { get; set; }
    public string? TriggerContextJson { get; set; }
    public required string UsageJson { get; set; }
    public long CreatedAt { get; set; }
    public long UpdatedAt { get; set; }
}

/// <summary>One step a runner reported for a run (what it was asked, what it answered, which capability it used), in order within an attempt.</summary>
public sealed class AutomationRunEvent
{
    public required string Id { get; set; }
    public required string RunId { get; set; }
    public int Attempt { get; set; }
    public int Sequence { get; set; }
    public required string EventType { get; set; }
    public required string PayloadJson { get; set; }
    /// <summary>Names the runner's own report (<c>desktop:run:attempt:sequence</c>), so a retried report finds the event it already made.</summary>
    public required string IdempotencyKey { get; set; }
    public long CreatedAt { get; set; }
}

/// <summary>A desktop a person signed in on, remembered so management screens can say whether one is connected and runs know where they can go.</summary>
public sealed class AutomationRunner
{
    /// <summary><c>rnr_</c> plus a hash of workspace, person and install, so one install in two workspaces is two runners.</summary>
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string OwnerMemberId { get; set; }
    /// <summary>The install's own id, as named in its credential and run leases.</summary>
    public required string InstallId { get; set; }
    public int ProtocolVersion { get; set; }
    public required string CapabilitiesJson { get; set; }
    public required string AppVersion { get; set; }
    public required string Platform { get; set; }
    public int Concurrency { get; set; }
    /// <summary>The desktop's latest computer, workspace and model report (<c>PUT /v1/automation-runner/inventory</c>), as sent.</summary>
    public string? InventoryJson { get; set; }
    public long? InventoryUpdatedAt { get; set; }
    public long LastSeenAt { get; set; }
    public long CreatedAt { get; set; }
    public long UpdatedAt { get; set; }
}

public sealed class AutomationConfiguration : IEntityTypeConfiguration<Automation>
{
    public void Configure(EntityTypeBuilder<Automation> b)
    {
        b.HasIndex(a => new { a.OwnerMemberId, a.Id });
        b.HasIndex(a => new { a.State, a.NextDueAt });
        b.HasIndex(a => a.OrganizationId);
        b.Property(a => a.Name).HasMaxLength(120);
        // A workspace's deletion removes its Automations (and, through them, their revisions, runs and events).
        b.HasOne<Organization>().WithMany().HasForeignKey(a => a.OrganizationId).OnDelete(DeleteBehavior.Cascade);
    }
}

public sealed class AutomationRevisionConfiguration : IEntityTypeConfiguration<AutomationRevision>
{
    public void Configure(EntityTypeBuilder<AutomationRevision> b)
    {
        b.HasIndex(r => new { r.AutomationId, r.Version }).IsUnique();
        b.Property(r => r.ProviderId).HasMaxLength(160);
        b.Property(r => r.ModelId).HasMaxLength(160);
        b.HasOne<Automation>().WithMany().HasForeignKey(r => r.AutomationId).OnDelete(DeleteBehavior.Cascade);
    }
}

public sealed class AutomationRunConfiguration : IEntityTypeConfiguration<AutomationRun>
{
    public void Configure(EntityTypeBuilder<AutomationRun> b)
    {
        b.HasIndex(r => r.IdempotencyKey).IsUnique();
        b.Property(r => r.IdempotencyKey).HasMaxLength(512);
        b.HasIndex(r => new { r.AutomationId, r.Status });
        b.HasIndex(r => new { r.AutomationId, r.Id });
        b.HasIndex(r => new { r.Status, r.ExecutionTarget });
        b.Property(r => r.LeaseOwner).HasMaxLength(255);
        b.HasOne<Automation>().WithMany().HasForeignKey(r => r.AutomationId).OnDelete(DeleteBehavior.Cascade);
    }
}

public sealed class AutomationRunEventConfiguration : IEntityTypeConfiguration<AutomationRunEvent>
{
    public void Configure(EntityTypeBuilder<AutomationRunEvent> b)
    {
        // Two runners (or one retrying) can never record the same step twice.
        b.HasIndex(e => new { e.RunId, e.Attempt, e.Sequence }).IsUnique();
        b.HasOne<AutomationRun>().WithMany().HasForeignKey(e => e.RunId).OnDelete(DeleteBehavior.Cascade);
        b.Property(e => e.IdempotencyKey).HasMaxLength(400);
    }
}

public sealed class AutomationRunnerConfiguration : IEntityTypeConfiguration<AutomationRunner>
{
    public void Configure(EntityTypeBuilder<AutomationRunner> b)
    {
        b.HasIndex(r => new { r.OrganizationId, r.OwnerMemberId, r.LastSeenAt });
        b.HasOne<Organization>().WithMany().HasForeignKey(r => r.OrganizationId).OnDelete(DeleteBehavior.Cascade);
    }
}
