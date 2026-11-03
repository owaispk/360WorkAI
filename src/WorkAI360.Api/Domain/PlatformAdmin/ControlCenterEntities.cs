using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace WorkAI360.Api.Domain.PlatformAdmin;

/// <summary>
/// One precomputed Control Center section for one range (the reference's <c>admin_metric_snapshot</c>). The read endpoint only ever reads these rows;
/// a background job recomputes them. A failed refresh records its error and keeps the last good payload.
/// </summary>
public sealed class AdminMetricSnapshot
{
    public required string MetricKey { get; set; }
    /// <summary>7d | 30d | 90d | all</summary>
    public required string RangeKey { get; set; }
    public string? PayloadJson { get; set; }
    public DateTime? ComputedAt { get; set; }
    public int? DurationMs { get; set; }
    public string? Error { get; set; }
    public DateTime? AttemptedAt { get; set; }
}

public sealed class AdminMetricSnapshotConfiguration : IEntityTypeConfiguration<AdminMetricSnapshot>
{
    public void Configure(EntityTypeBuilder<AdminMetricSnapshot> b)
    {
        b.HasKey(s => new { s.MetricKey, s.RangeKey });
        b.Property(s => s.MetricKey).HasMaxLength(32);
        b.Property(s => s.RangeKey).HasMaxLength(8);
        b.Property(s => s.Error).HasMaxLength(500);
    }
}

/// <summary>
/// Who is refreshing a metric and until when (the reference's <c>admin_metric_refresh_lease</c>), so two instances never compute the same metric at
/// once. The row keyed <c>manual_refresh</c> holds the time of the last manual refresh request (one a minute across all admins).
/// </summary>
public sealed class AdminMetricRefreshLease
{
    public required string MetricKey { get; set; }
    public string? Owner { get; set; }
    public DateTime? LeaseUntil { get; set; }
    public DateTime? RequestedAt { get; set; }
}

public sealed class AdminMetricRefreshLeaseConfiguration : IEntityTypeConfiguration<AdminMetricRefreshLease>
{
    public void Configure(EntityTypeBuilder<AdminMetricRefreshLease> b)
    {
        b.HasKey(l => l.MetricKey);
        b.Property(l => l.MetricKey).HasMaxLength(32);
        b.Property(l => l.Owner).HasMaxLength(96);
    }
}

/// <summary>
/// A refused, rate-limited or failed request without a trusted workspace (sign-in, token, app registration, stale credentials), for
/// <c>/v1/admin/security/requests</c>. Holds no address, user, token, query string or path value: only the route's shape, the outcome and the status.
/// Kept for <c>PlatformAdmin:RequestLog:RetentionDays</c>.
/// </summary>
public sealed class PlatformRequestEvent
{
    public required string Id { get; set; }
    public DateTime OccurredAt { get; set; }
    /// <summary>The route as a dotted name, e.g. <c>auth.sign_in.email</c> (never a path value).</summary>
    public required string Action { get; set; }
    /// <summary>denied | failed</summary>
    public required string Outcome { get; set; }
    public int Status { get; set; }
}

public sealed class PlatformRequestEventConfiguration : IEntityTypeConfiguration<PlatformRequestEvent>
{
    public void Configure(EntityTypeBuilder<PlatformRequestEvent> b)
    {
        b.Property(e => e.Action).HasMaxLength(128);
        b.Property(e => e.Outcome).HasMaxLength(16);
        b.HasIndex(e => e.OccurredAt);
    }
}
