using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace WorkAI360.Api.Domain.OrgAdmin;

/// <summary>An organization API key. Only the SHA-256 of the secret is stored; the secret is shown once, at creation.</summary>
public sealed class ApiKey
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    /// <summary>The member the key acts as: it can do what that member can, and stops working when the member loses access.</summary>
    public required string MemberId { get; set; }
    public required string UserId { get; set; }
    public required string Name { get; set; }
    public required string Prefix { get; set; }
    /// <summary>The first few characters of the secret, so people can tell keys apart in a list.</summary>
    public required string Start { get; set; }
    public required string KeyHash { get; set; }
    public bool Enabled { get; set; } = true;
    public bool RateLimitEnabled { get; set; } = true;
    public int RateLimitMax { get; set; }
    public int RateLimitTimeWindow { get; set; }
    public DateTime? LastRequestAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

public sealed class ApiKeyConfiguration : IEntityTypeConfiguration<ApiKey>
{
    public void Configure(EntityTypeBuilder<ApiKey> b)
    {
        b.HasIndex(k => k.KeyHash).IsUnique();
        b.HasIndex(k => new { k.OrganizationId, k.MemberId });
    }
}

/// <summary>Per-organization settings the base organization row has no column for (new table: the dev schema only adds tables).</summary>
public sealed class OrganizationSettings
{
    public required string OrganizationId { get; set; }
    /// <summary>JSON array of lower-case domains, or null for "anyone".</summary>
    public string? AllowedEmailDomainsJson { get; set; }
    /// <summary>JSON object of the organization's metadata (limits, brand fields, SSO requirement...), kept like the reference's metadata column.</summary>
    public string? MetadataJson { get; set; }
    public DateTime UpdatedAt { get; set; }
}

public sealed class OrganizationSettingsConfiguration : IEntityTypeConfiguration<OrganizationSettings>
{
    public void Configure(EntityTypeBuilder<OrganizationSettings> b) => b.HasKey(s => s.OrganizationId);
}

/// <summary>An approved web origin (an exact https origin allowed to embed or call the workspace).</summary>
public sealed class OrganizationWebOrigin
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string Origin { get; set; }
    public string? CreatedByMemberId { get; set; }
    public string? CreatedByName { get; set; }
    public DateTime CreatedAt { get; set; }
}

public sealed class OrganizationWebOriginConfiguration : IEntityTypeConfiguration<OrganizationWebOrigin>
{
    public void Configure(EntityTypeBuilder<OrganizationWebOrigin> b) => b.HasIndex(o => new { o.OrganizationId, o.Origin }).IsUnique();
}

/// <summary>A brand image (wordmark or app icon), stored in the database. Versions are content hashes, so a URL never changes meaning.</summary>
public sealed class BrandAsset
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string Kind { get; set; }
    public required string Version { get; set; }
    public required string Extension { get; set; }
    public required byte[] Bytes { get; set; }
    public DateTime CreatedAt { get; set; }
}

public sealed class BrandAssetConfiguration : IEntityTypeConfiguration<BrandAsset>
{
    public void Configure(EntityTypeBuilder<BrandAsset> b) => b.HasIndex(a => new { a.OrganizationId, a.Kind, a.Version, a.Extension }).IsUnique();
}

/// <summary>The audit capture policy of one organization (one row; <see cref="Revision"/> guards concurrent changes).</summary>
public sealed class AuditPolicy
{
    public required string OrganizationId { get; set; }
    public int Revision { get; set; }
    public required string Source { get; set; }
    public bool Enabled { get; set; }
    public required string CategoriesJson { get; set; }
    public long Allowance { get; set; }
    public required string ExcessMode { get; set; }
    public DateTime EffectiveAt { get; set; }
    public DateTime? CaptureStartedAt { get; set; }
    public int AttachmentWindowSeconds { get; set; }
}

public sealed class AuditPolicyConfiguration : IEntityTypeConfiguration<AuditPolicy>
{
    public void Configure(EntityTypeBuilder<AuditPolicy> b) => b.HasKey(p => p.OrganizationId);
}

/// <summary>A group of related audit events (one request, usually one event; reading audit history records two).</summary>
public sealed class AuditOperation
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string Kind { get; set; }
    public required string Scope { get; set; }
    public required string Origin { get; set; }
    public required string OriginTrust { get; set; }
    public required string InitiatingActorJson { get; set; }
    public string? InitiatingActorType { get; set; }
    public string? InitiatingActorId { get; set; }
    public DateTime FirstRecordedAt { get; set; }
    public required string Outcome { get; set; }
    public int EventCount { get; set; }
    public long LogicalBytes { get; set; }
}

public sealed class AuditOperationConfiguration : IEntityTypeConfiguration<AuditOperation>
{
    public void Configure(EntityTypeBuilder<AuditOperation> b) => b.HasIndex(o => new { o.OrganizationId, o.FirstRecordedAt, o.Id });
}

/// <summary>One recorded event. The full versioned envelope is kept as JSON; the columns are for filtering. Never updated after it is written.</summary>
public sealed class AuditEvent
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string OperationId { get; set; }
    public required string Action { get; set; }
    public string? RequestId { get; set; }
    public DateTime RecordedAt { get; set; }
    public required string EnvelopeJson { get; set; }
}

public sealed class AuditEventConfiguration : IEntityTypeConfiguration<AuditEvent>
{
    public void Configure(EntityTypeBuilder<AuditEvent> b)
    {
        b.HasIndex(e => new { e.OrganizationId, e.OperationId, e.RecordedAt, e.Id });
        b.HasIndex(e => new { e.OrganizationId, e.Action });
    }
}

/// <summary>A resource an event touched (for the "search by ID" filter and the operation summary).</summary>
public sealed class AuditEventResource
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string OperationId { get; set; }
    public required string EventId { get; set; }
    public required string ResourceType { get; set; }
    public required string ResourceId { get; set; }
    public required string Relationship { get; set; }
    public string? Label { get; set; }
    /// <summary>Position in the event's list, so references read back in the order they were written.</summary>
    public int Position { get; set; }
}

public sealed class AuditEventResourceConfiguration : IEntityTypeConfiguration<AuditEventResource>
{
    public void Configure(EntityTypeBuilder<AuditEventResource> b)
    {
        b.HasIndex(r => new { r.OrganizationId, r.ResourceId });
        b.HasIndex(r => r.EventId);
    }
}
