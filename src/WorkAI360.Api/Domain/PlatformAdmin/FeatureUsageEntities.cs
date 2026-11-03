using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace WorkAI360.Api.Domain.PlatformAdmin;

/// <summary>
/// That a member used a feature on a UTC day (the reference's <c>feature_usage</c>): member, feature and day only, never what they did. Written when a client
/// reports it (<c>POST /v1/org/feature-usage</c>); read by /admin to show who uses what.
/// </summary>
public sealed class FeatureUsageDay
{
    public required string MemberId { get; set; }
    public required string FeatureKey { get; set; }
    /// <summary>"yyyy-MM-dd" (UTC).</summary>
    public required string Day { get; set; }
    public required string OrganizationId { get; set; }
    public DateTime FirstUsedAt { get; set; }
    public DateTime LastUsedAt { get; set; }
}

public sealed class FeatureUsageDayConfiguration : IEntityTypeConfiguration<FeatureUsageDay>
{
    public void Configure(EntityTypeBuilder<FeatureUsageDay> b)
    {
        b.HasKey(u => new { u.MemberId, u.FeatureKey, u.Day });
        b.Property(u => u.MemberId).HasMaxLength(64);
        b.Property(u => u.FeatureKey).HasMaxLength(64);
        b.Property(u => u.Day).HasMaxLength(10);
        b.HasIndex(u => new { u.OrganizationId, u.FeatureKey });
        b.HasIndex(u => new { u.FeatureKey, u.Day });
    }
}
