using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace WorkAI360.Api.Domain.Sso;

/// <summary>A workspace's SCIM connection (one per workspace). The bearer token is only stored as a hash.</summary>
public sealed class ScimProvider
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string ProviderId { get; set; }
    public required string TokenHash { get; set; }
    public string? CreatedByUserId { get; set; }
    /// <summary>metadata_only | create_teams</summary>
    public required string GroupMappingMode { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

public sealed class ScimGroup
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string ProviderId { get; set; }
    public string? ExternalId { get; set; }
    public required string DisplayName { get; set; }
    /// <summary>The team this group projects to when the connection maps groups to teams.</summary>
    public string? TeamId { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

public sealed class ScimGroupMember
{
    public required string Id { get; set; }
    public required string GroupId { get; set; }
    public required string OrganizationId { get; set; }
    public required string ProviderId { get; set; }
    /// <summary>The user id the identity provider sent (may name someone who is not in the workspace yet).</summary>
    public required string RemoteUserId { get; set; }
    public string? MemberId { get; set; }
    public string? TeamMemberId { get; set; }
}

/// <summary>Remembers who SCIM deprovisioned, so single sign-on cannot quietly bring them back.</summary>
public sealed class ScimUserTombstone
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string ProviderId { get; set; }
    public required string DeprovisionedUserId { get; set; }
    public string? ExternalId { get; set; }
    public string? Email { get; set; }
    public DateTime DeprovisionedAt { get; set; }
}

public sealed class ScimSyncEvent
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string ProviderId { get; set; }
    public string? UserId { get; set; }
    public required string Action { get; set; }
    public required string Status { get; set; }
    public int Attempts { get; set; }
    public string? LastError { get; set; }
    public string? PayloadJson { get; set; }
    public DateTime? NextRetryAt { get; set; }
    public DateTime? ResolvedAt { get; set; }
    public DateTime CreatedAt { get; set; }
}

public sealed class ScimConfiguration :
    IEntityTypeConfiguration<ScimProvider>, IEntityTypeConfiguration<ScimGroup>, IEntityTypeConfiguration<ScimGroupMember>,
    IEntityTypeConfiguration<ScimUserTombstone>, IEntityTypeConfiguration<ScimSyncEvent>
{
    public void Configure(EntityTypeBuilder<ScimProvider> b)
    {
        b.HasIndex(p => p.OrganizationId).IsUnique();
        b.HasIndex(p => p.ProviderId).IsUnique();
        b.HasIndex(p => p.TokenHash).IsUnique();
    }

    public void Configure(EntityTypeBuilder<ScimGroup> b)
    {
        b.HasIndex(g => new { g.ProviderId, g.ExternalId });
        b.HasIndex(g => g.OrganizationId);
    }

    public void Configure(EntityTypeBuilder<ScimGroupMember> b)
    {
        b.HasIndex(m => new { m.GroupId, m.RemoteUserId }).IsUnique();
        b.HasIndex(m => m.RemoteUserId);
    }

    public void Configure(EntityTypeBuilder<ScimUserTombstone> b)
    {
        b.HasIndex(t => new { t.OrganizationId, t.DeprovisionedUserId }).IsUnique();
        b.HasIndex(t => new { t.OrganizationId, t.Email });
    }

    public void Configure(EntityTypeBuilder<ScimSyncEvent> b)
    {
        b.HasIndex(e => e.OrganizationId);
    }
}
