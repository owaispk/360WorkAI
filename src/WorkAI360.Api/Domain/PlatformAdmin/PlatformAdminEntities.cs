using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace WorkAI360.Api.Domain.PlatformAdmin;

/// <summary>
/// An email address that operates this deployment (the reference's admin allowlist). Anyone who signs in with this address, verified where the
/// deployment verifies addresses, may use the /v1/admin routes. Being the owner of a workspace never makes someone a platform admin.
/// </summary>
public sealed class AdminAllowlistEntry
{
    public required string Id { get; set; }
    /// <summary>Lower-case.</summary>
    public required string Email { get; set; }
    public string? Note { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

public sealed class AdminAllowlistEntryConfiguration : IEntityTypeConfiguration<AdminAllowlistEntry>
{
    public void Configure(EntityTypeBuilder<AdminAllowlistEntry> b)
    {
        b.HasIndex(a => a.Email).IsUnique();
        b.Property(a => a.Email).HasMaxLength(255);
        b.Property(a => a.Note).HasMaxLength(255);
    }
}

/// <summary>On or off for everyone on this deployment, and the kill switch, for one feature. No row means the build's default.</summary>
public sealed class PlatformFeatureRollout
{
    public required string FeatureKey { get; set; }
    public bool Enabled { get; set; }
    public bool Killed { get; set; }
    public string? UpdatedByUserId { get; set; }
    public DateTime UpdatedAt { get; set; }
}

public sealed class PlatformFeatureRolloutConfiguration : IEntityTypeConfiguration<PlatformFeatureRollout>
{
    public void Configure(EntityTypeBuilder<PlatformFeatureRollout> b)
    {
        b.HasKey(r => r.FeatureKey);
        b.Property(r => r.FeatureKey).HasMaxLength(64);
    }
}

/// <summary>A per-workspace override of one feature (on or off). Cleared by deleting the row.</summary>
public sealed class PlatformOrganizationFeature
{
    public required string OrganizationId { get; set; }
    public required string FeatureKey { get; set; }
    public bool Enabled { get; set; }
    public string? SetByUserId { get; set; }
    public DateTime UpdatedAt { get; set; }
}

public sealed class PlatformOrganizationFeatureConfiguration : IEntityTypeConfiguration<PlatformOrganizationFeature>
{
    public void Configure(EntityTypeBuilder<PlatformOrganizationFeature> b)
    {
        b.HasKey(f => new { f.OrganizationId, f.FeatureKey });
        b.Property(f => f.FeatureKey).HasMaxLength(64);
    }
}

/// <summary>The history of feature changes, so /admin can say "On by someone, 26 Oct 2026".</summary>
public sealed class PlatformFeatureChange
{
    public required string Id { get; set; }
    public required string FeatureKey { get; set; }
    /// <summary>everyone | organization</summary>
    public required string Scope { get; set; }
    /// <summary>on | off | reset | killed | restored</summary>
    public required string Action { get; set; }
    public string? OrganizationId { get; set; }
    public string? ChangedByUserId { get; set; }
    public DateTime CreatedAt { get; set; }
}

public sealed class PlatformFeatureChangeConfiguration : IEntityTypeConfiguration<PlatformFeatureChange>
{
    public void Configure(EntityTypeBuilder<PlatformFeatureChange> b)
    {
        b.Property(c => c.FeatureKey).HasMaxLength(64);
        b.HasIndex(c => new { c.FeatureKey, c.CreatedAt });
        b.HasIndex(c => c.OrganizationId);
    }
}

/// <summary>
/// What a platform admin records about a workspace: its plan (stored, never billed), extra free seats, the data-processing-agreement decision
/// and complimentary web access. A workspace without a row has the defaults (free plan, source "default").
/// </summary>
public sealed class PlatformOrganization
{
    public required string OrganizationId { get; set; }
    /// <summary>free | team | enterprise; null until an admin sets one.</summary>
    public string? PlanTier { get; set; }
    /// <summary>Users allowed on a Team or Enterprise plan; null on Free.</summary>
    public int? PlanSeats { get; set; }
    /// <summary>The plan's display-only end date, YYYY-MM-DD.</summary>
    public string? PlanEndsAt { get; set; }
    /// <summary>How many users the workspace may have while Free (at least 5).</summary>
    public int SeatLimit { get; set; } = 5;
    /// <summary>Free seats beyond the 5 every workspace has.</summary>
    public int SeatsFreeAdditional { get; set; }
    public bool? DpaSigned { get; set; }
    public bool ComplimentaryWebAccess { get; set; }
    public DateTime UpdatedAt { get; set; }
}

public sealed class PlatformOrganizationConfiguration : IEntityTypeConfiguration<PlatformOrganization>
{
    public void Configure(EntityTypeBuilder<PlatformOrganization> b)
    {
        b.HasKey(o => o.OrganizationId);
        b.Property(o => o.PlanTier).HasMaxLength(16);
        b.Property(o => o.PlanEndsAt).HasMaxLength(10);
    }
}
