using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace WorkAI360.Api.Domain.OAuthProviders;

/// <summary>
/// The OAuth app (client) a workspace brings for a provider such as Google Workspace, instead of one owned by the platform. The secret is
/// encrypted at rest (AES-GCM, the same box connections use) and never returned: it can be replaced but not read.
/// </summary>
public sealed class OrgOAuthClient
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    /// <summary>google-workspace or microsoft-365.</summary>
    public required string ProviderId { get; set; }
    public required string ClientId { get; set; }
    public string? ClientSecretEnc { get; set; }
    /// <summary>JSON array of the optional permissions chosen; null means "the provider's defaults".</summary>
    public string? FeaturesJson { get; set; }
    /// <summary>Microsoft Entra tenant (a GUID or verified domain), for providers that are tenant-scoped.</summary>
    public string? TenantId { get; set; }
    public required string CreatedByMemberId { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

public sealed class OrgOAuthClientConfiguration : IEntityTypeConfiguration<OrgOAuthClient>
{
    public void Configure(EntityTypeBuilder<OrgOAuthClient> b)
    {
        b.HasIndex(c => new { c.OrganizationId, c.ProviderId }).IsUnique();
        b.Property(c => c.ClientId).HasMaxLength(512);
        b.Property(c => c.ProviderId).HasMaxLength(64);
    }
}
