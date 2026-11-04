using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace WorkAI360.Api.Domain.Gateway;

/// <summary>
/// An AI Gateway provider: a LiteLLM proxy this workspace serves models through (the reference's <c>gateway_providers</c> row with
/// <c>provider_id = "litellm"</c>). Either the deployment's own proxy (configured by the operator, <see cref="UsesDeploymentProxy"/>) or the
/// workspace's own proxy with an admin key. Den keeps the model catalog, groups and grants; LiteLLM serves the requests with keys Den issues.
/// </summary>
public sealed class GatewayProvider
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string CreatedByMemberId { get; set; }
    /// <summary>Always "litellm" in this build.</summary>
    public required string ProviderId { get; set; }
    public required string Name { get; set; }
    /// <summary>active | disabled</summary>
    public required string Status { get; set; }
    public bool UsesDeploymentProxy { get; set; }
    /// <summary>Proxy root for management calls (no /v1). Null for the deployment proxy (configuration decides).</summary>
    public string? AdminBaseUrl { get; set; }
    /// <summary>The workspace's LiteLLM admin key, encrypted. Null for the deployment proxy (its master key is configuration).</summary>
    public string? AdminKeyEnc { get; set; }
    /// <summary>The LiteLLM team every key of this provider belongs to, so spend can be read per provider.</summary>
    public string? LiteLlmTeamId { get; set; }
    public DateTime? LastSyncedAt { get; set; }
    public string? LastSyncError { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

public sealed class GatewayProviderConfiguration : IEntityTypeConfiguration<GatewayProvider>
{
    public void Configure(EntityTypeBuilder<GatewayProvider> b)
    {
        b.HasIndex(p => p.OrganizationId);
        b.Property(p => p.AdminBaseUrl).HasMaxLength(2048);
        b.Property(p => p.LastSyncError).HasMaxLength(1024);
    }
}

/// <summary>A model the proxy serves, as last synced (<c>gateway_provider_models</c>).</summary>
public sealed class GatewayProviderModel
{
    public required string Id { get; set; }
    public required string GatewayProviderId { get; set; }
    public required string ModelId { get; set; }
    public required string Name { get; set; }
    public required string ConfigJson { get; set; }
    public DateTime CreatedAt { get; set; }
}

public sealed class GatewayProviderModelConfiguration : IEntityTypeConfiguration<GatewayProviderModel>
{
    public void Configure(EntityTypeBuilder<GatewayProviderModel> b)
    {
        b.HasIndex(m => new { m.GatewayProviderId, m.ModelId }).IsUnique();
    }
}

/// <summary>A named set of a provider's models that can be granted (<c>gateway_model_groups</c>).</summary>
public sealed class GatewayModelGroup
{
    public required string Id { get; set; }
    public required string GatewayProviderId { get; set; }
    public required string Name { get; set; }
    public string? Description { get; set; }
    /// <summary>active | disabled</summary>
    public required string Status { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

public sealed class GatewayModelGroupConfiguration : IEntityTypeConfiguration<GatewayModelGroup>
{
    public void Configure(EntityTypeBuilder<GatewayModelGroup> b)
    {
        b.HasIndex(g => g.GatewayProviderId);
    }
}

public sealed class GatewayModelGroupModel
{
    public required string ModelGroupId { get; set; }
    public required string GatewayProviderModelId { get; set; }
}

public sealed class GatewayModelGroupModelConfiguration : IEntityTypeConfiguration<GatewayModelGroupModel>
{
    public void Configure(EntityTypeBuilder<GatewayModelGroupModel> b)
    {
        b.HasKey(l => new { l.ModelGroupId, l.GatewayProviderModelId });
        b.HasIndex(l => l.GatewayProviderModelId);
    }
}

/// <summary>Who may use a model group: the whole workspace, a team or a member (<c>gateway_provider_access</c>).</summary>
public sealed class GatewayAccessGrant
{
    public required string Id { get; set; }
    public required string GatewayProviderId { get; set; }
    public required string ModelGroupId { get; set; }
    /// <summary>organization | team:&lt;id&gt; | member:&lt;id&gt;</summary>
    public required string AudienceKey { get; set; }
    public string? MemberId { get; set; }
    public string? TeamId { get; set; }
    public DateTime CreatedAt { get; set; }
}

public sealed class GatewayAccessGrantConfiguration : IEntityTypeConfiguration<GatewayAccessGrant>
{
    public void Configure(EntityTypeBuilder<GatewayAccessGrant> b)
    {
        b.HasIndex(a => new { a.GatewayProviderId, a.AudienceKey, a.ModelGroupId }).IsUnique();
        b.HasIndex(a => a.MemberId);
        b.HasIndex(a => a.TeamId);
        b.HasIndex(a => a.ModelGroupId);
        b.Property(a => a.AudienceKey).HasMaxLength(80);
    }
}

/// <summary>
/// The LiteLLM virtual key Den issued for one member on one provider (the reference's issued keys). The value is encrypted and only ever given to
/// that member through <c>/connect</c>; <see cref="TokenHash"/> is LiteLLM's id for it, used to update, delete and attribute usage.
/// </summary>
public sealed class GatewayIssuedKey
{
    public required string GatewayProviderId { get; set; }
    public required string MemberId { get; set; }
    public required string OrganizationId { get; set; }
    /// <summary>The member's user, so access can be revoked after the membership row is gone.</summary>
    public required string UserId { get; set; }
    public required string KeyEnc { get; set; }
    public required string TokenHash { get; set; }
    public required string KeyPrefix { get; set; }
    /// <summary>The sorted model ids the key was issued for, as JSON.</summary>
    public required string ModelsJson { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

public sealed class GatewayIssuedKeyConfiguration : IEntityTypeConfiguration<GatewayIssuedKey>
{
    public void Configure(EntityTypeBuilder<GatewayIssuedKey> b)
    {
        b.HasKey(k => new { k.GatewayProviderId, k.MemberId });
        b.HasIndex(k => k.TokenHash).IsUnique();
        b.HasIndex(k => new { k.OrganizationId, k.UserId });
        b.Property(k => k.KeyPrefix).HasMaxLength(32);
    }
}
