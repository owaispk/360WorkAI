using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace WorkAI360.Api.Domain.LlmProviders;

/// <summary>
/// A model provider a workspace configured (the reference's <c>llm_provider</c>): a models.dev catalog provider or a pasted custom one, with the
/// credential people's desktops use to call it. The credential is encrypted (<c>SecretBox</c>); a provider with one env key stores the bare value,
/// one with several stores a JSON map of env name to value (the reference's self-describing encoding).
/// </summary>
public sealed class LlmProvider
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    /// <summary>Stable key from declarative provisioning (<c>/v1/llm-providers/by-key/{key}</c>), unique per workspace.</summary>
    public string? ExternalKey { get; set; }
    public required string CreatedByMemberId { get; set; }
    /// <summary>models_dev | custom | openwork</summary>
    public required string Source { get; set; }
    public required string ProviderId { get; set; }
    public required string Name { get; set; }
    public required string ProviderConfigJson { get; set; }
    /// <summary>shared (one workspace credential) | per_member (each person's own).</summary>
    public required string CredentialMode { get; set; }
    /// <summary>Encrypted credential, or null when none is set.</summary>
    public string? ApiKeyEnc { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

public sealed class LlmProviderModel
{
    public required string Id { get; set; }
    public required string LlmProviderId { get; set; }
    public required string ModelId { get; set; }
    public required string Name { get; set; }
    public required string ModelConfigJson { get; set; }
    public DateTime CreatedAt { get; set; }
}

/// <summary>Who may use a provider: one member, one team, or (both empty) everyone in the workspace.</summary>
public sealed class LlmProviderAccess
{
    public required string Id { get; set; }
    public required string LlmProviderId { get; set; }
    public string? MemberId { get; set; }
    public string? TeamId { get; set; }
    public DateTime CreatedAt { get; set; }
}

/// <summary>One member's own credential for a per-member provider. Versioned; a blocked one is the administrator's and the member cannot change it.</summary>
public sealed class LlmProviderMemberCredential
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string LlmProviderId { get; set; }
    public required string MemberId { get; set; }
    public required string SecretEnc { get; set; }
    public string? ExternalPrincipalId { get; set; }
    public string? ExternalCredentialId { get; set; }
    /// <summary>active | blocked | stale | error</summary>
    public required string State { get; set; }
    public int Version { get; set; } = 1;
    /// <summary>member | admin | provisioner</summary>
    public required string CreatedBy { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

public sealed class LlmProviderConfiguration : IEntityTypeConfiguration<LlmProvider>
{
    public void Configure(EntityTypeBuilder<LlmProvider> b)
    {
        b.HasIndex(p => new { p.OrganizationId, p.ExternalKey }).IsUnique();
        b.HasIndex(p => p.CreatedByMemberId);
        b.Property(p => p.ExternalKey).HasMaxLength(128);
        b.Property(p => p.Source).HasMaxLength(16);
        b.Property(p => p.CredentialMode).HasMaxLength(16);
        b.Property(p => p.ProviderId).HasMaxLength(255);
        b.Property(p => p.Name).HasMaxLength(255);
    }
}

public sealed class LlmProviderModelConfiguration : IEntityTypeConfiguration<LlmProviderModel>
{
    public void Configure(EntityTypeBuilder<LlmProviderModel> b)
    {
        b.HasIndex(m => new { m.LlmProviderId, m.ModelId }).IsUnique();
        b.Property(m => m.ModelId).HasMaxLength(255);
        b.Property(m => m.Name).HasMaxLength(255);
    }
}

public sealed class LlmProviderAccessConfiguration : IEntityTypeConfiguration<LlmProviderAccess>
{
    public void Configure(EntityTypeBuilder<LlmProviderAccess> b)
    {
        // Nulls never collide in a unique index on either database, so the workspace-wide row (both null) is allowed beside the others.
        b.HasIndex(a => new { a.LlmProviderId, a.MemberId }).IsUnique();
        b.HasIndex(a => new { a.LlmProviderId, a.TeamId }).IsUnique();
        b.HasIndex(a => a.MemberId);
        b.HasIndex(a => a.TeamId);
    }
}

public sealed class LlmProviderMemberCredentialConfiguration : IEntityTypeConfiguration<LlmProviderMemberCredential>
{
    public void Configure(EntityTypeBuilder<LlmProviderMemberCredential> b)
    {
        b.HasIndex(c => new { c.MemberId, c.LlmProviderId }).IsUnique();
        b.HasIndex(c => c.OrganizationId);
        b.Property(c => c.State).HasMaxLength(16);
        b.Property(c => c.CreatedBy).HasMaxLength(16);
        b.Property(c => c.ExternalPrincipalId).HasMaxLength(255);
        b.Property(c => c.ExternalCredentialId).HasMaxLength(255);
    }
}
