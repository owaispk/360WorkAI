using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace WorkAI360.Api.Domain.Automations;

/// <summary>
/// A wake-up hint for a person's desktops (the reference's <c>automation_runner_notification</c>): a desktop run was queued for them, or one a desktop holds
/// was asked to stop. The growing id is the stream's cursor (<c>Last-Event-ID</c>), so every server instance reads the same sequence. Hints only: the
/// desktop's work poll and heartbeats find whatever a hint pointed at. Kept a week.
/// </summary>
public sealed class AutomationRunnerNotification
{
    public long Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string OwnerMemberId { get; set; }
    /// <summary>work_available | cancellation</summary>
    public required string EventType { get; set; }
    public required string RunId { get; set; }
    public long CreatedAt { get; set; }
}

public sealed class AutomationRunnerNotificationConfiguration : IEntityTypeConfiguration<AutomationRunnerNotification>
{
    public void Configure(EntityTypeBuilder<AutomationRunnerNotification> b)
    {
        b.HasKey(n => n.Id);
        b.Property(n => n.Id).ValueGeneratedOnAdd();
        b.Property(n => n.EventType).HasMaxLength(32);
        b.HasIndex(n => new { n.OrganizationId, n.OwnerMemberId, n.Id });
        b.HasIndex(n => n.CreatedAt);
    }
}
