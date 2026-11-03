using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace WorkAI360.Api.Domain.Automations;

/// <summary>
/// One usage event from the desktop or a worker, tied to a person in a workspace. Rows carry identifiers, timings and outcomes, never content.
/// Times are epoch milliseconds. They are not tied to a member by a foreign key: people who leave still count in the history.
/// </summary>
public sealed class TelemetryEvent
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string MemberId { get; set; }
    public required string EventType { get; set; }
    public long EventTimestamp { get; set; }
    /// <summary>app or worker; anything else is stored as none.</summary>
    public string? Source { get; set; }
    public string? SessionId { get; set; }
    public int? DurationMs { get; set; }
    public bool? Success { get; set; }
    public long CreatedAt { get; set; }
}

/// <summary>A label attached to a session (a project, a model), one row per workspace, source, session and dimension type.</summary>
public sealed class TelemetrySessionDimension
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string SessionId { get; set; }
    public required string Source { get; set; }
    public required string DimensionType { get; set; }
    public required string DimensionValue { get; set; }
    public required string DimensionLabel { get; set; }
    public string? MetadataJson { get; set; }
    public long CreatedAt { get; set; }
    public long UpdatedAt { get; set; }
    public long LastSeenAt { get; set; }
}

public sealed class TelemetryEventConfiguration : IEntityTypeConfiguration<TelemetryEvent>
{
    public void Configure(EntityTypeBuilder<TelemetryEvent> b)
    {
        b.HasIndex(e => new { e.OrganizationId, e.EventTimestamp });
        b.HasIndex(e => new { e.OrganizationId, e.SessionId, e.EventTimestamp });
        b.Property(e => e.EventType).HasMaxLength(64);
        b.Property(e => e.Source).HasMaxLength(32);
        b.Property(e => e.SessionId).HasMaxLength(128);
        b.HasOne<Organization>().WithMany().HasForeignKey(e => e.OrganizationId).OnDelete(DeleteBehavior.Cascade);
    }
}

public sealed class TelemetrySessionDimensionConfiguration : IEntityTypeConfiguration<TelemetrySessionDimension>
{
    public void Configure(EntityTypeBuilder<TelemetrySessionDimension> b)
    {
        b.Property(d => d.SessionId).HasMaxLength(128);
        b.Property(d => d.Source).HasMaxLength(32);
        b.Property(d => d.DimensionType).HasMaxLength(64);
        b.Property(d => d.DimensionValue).HasMaxLength(128);
        b.Property(d => d.DimensionLabel).HasMaxLength(255);
        b.HasIndex(d => new { d.OrganizationId, d.Source, d.SessionId, d.DimensionType }).IsUnique();
        b.HasIndex(d => new { d.OrganizationId, d.DimensionType, d.DimensionValue });
        b.HasOne<Organization>().WithMany().HasForeignKey(d => d.OrganizationId).OnDelete(DeleteBehavior.Cascade);
    }
}
