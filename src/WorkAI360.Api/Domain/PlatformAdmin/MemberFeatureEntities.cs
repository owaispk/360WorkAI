using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace WorkAI360.Api.Domain.PlatformAdmin;

/// <summary>
/// A platform admin's feature override for one workspace member (the reference's <c>member_feature</c>). It belongs to the membership, never to the
/// person globally: the same person in another workspace is unaffected, and once the membership ends the row no longer applies.
/// </summary>
public sealed class PlatformMemberFeature
{
    public required string MemberId { get; set; }
    public required string FeatureKey { get; set; }
    public bool Enabled { get; set; }
    public string? SetByUserId { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

public sealed class PlatformMemberFeatureConfiguration : IEntityTypeConfiguration<PlatformMemberFeature>
{
    public void Configure(EntityTypeBuilder<PlatformMemberFeature> b)
    {
        b.HasKey(f => new { f.MemberId, f.FeatureKey });
        b.Property(f => f.FeatureKey).HasMaxLength(64);
    }
}
