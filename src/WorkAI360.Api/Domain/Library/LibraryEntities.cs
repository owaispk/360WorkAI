using WorkAI360.Api.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace WorkAI360.Api.Domain.Library;

/// <summary>A bundle of skills and other pieces an agent can use. Shared with people through grants.</summary>
public sealed class Plugin : IDerivedKeys
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string Name { get; set; }
    public string? Description { get; set; }
    public string? SourceRepositoryUrl { get; set; }
    public string? SourceFormat { get; set; }
    public string? SourceSchemaVersion { get; set; }
    /// <summary>active, archived (inactive and deleted exist in the reference but nothing sets them).</summary>
    public required string Status { get; set; }
    public required string CreatedByMemberId { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public DateTime? DeletedAt { get; set; }

    /// <summary>
    /// Set while the plugin is active, to a hash of its workspace, creator and lowercased name; empty otherwise. A plain unique index on it is
    /// "one active plugin per creator and name, ignoring case" on every database (filtered indexes are not available on all of them).
    /// </summary>
    public string? ActiveKey { get; set; }

    public void RefreshKeys() =>
        ActiveKey = Status == "active" ? Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes($"{OrganizationId}|{CreatedByMemberId}|{Name.ToLowerInvariant()}"))) : null;
}

/// <summary>One skill, command, agent or other thing a plugin holds. Its text lives in versions.</summary>
public sealed class ConfigObject
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string ObjectType { get; set; }
    public required string SourceMode { get; set; }
    public required string Title { get; set; }
    public string? Description { get; set; }
    public string? SearchText { get; set; }
    /// <summary>Where an imported object lived in its repository (used to match it again on re-import).</summary>
    public string? CurrentRelativePath { get; set; }
    public required string Status { get; set; }
    public required string CreatedByMemberId { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public DateTime? DeletedAt { get; set; }
}

/// <summary>An immutable revision of a config object's text. The newest one is the current text.</summary>
public sealed class ConfigObjectVersion
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string ConfigObjectId { get; set; }
    public string? NormalizedPayloadJson { get; set; }
    public string? RawSourceText { get; set; }
    public string? SchemaVersion { get; set; }
    public required string CreatedVia { get; set; }
    public string? CreatedByMemberId { get; set; }
    public string? SourceRevisionRef { get; set; }
    public bool IsDeletedVersion { get; set; }
    public DateTime CreatedAt { get; set; }
}

/// <summary>A named shelf of plugins that people are given access to together.</summary>
public sealed class Marketplace
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public string? ExternalKey { get; set; }
    public required string Name { get; set; }
    public string? Description { get; set; }
    public string? LogoUrl { get; set; }
    public required string Status { get; set; }
    public required string CreatedByMemberId { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public DateTime? DeletedAt { get; set; }
}

public sealed class MarketplacePlugin
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string MarketplaceId { get; set; }
    public required string PluginId { get; set; }
    public required string MembershipSource { get; set; }
    public string? CreatedByMemberId { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? RemovedAt { get; set; }
}

public sealed class PluginConfigObject
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string PluginId { get; set; }
    public required string ConfigObjectId { get; set; }
    public required string MembershipSource { get; set; }
    public string? CreatedByMemberId { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? RemovedAt { get; set; }
}

public static class GrantKinds
{
    public const string Plugin = "plugin";
    public const string Marketplace = "marketplace";
    public const string ConfigObject = "config_object";
}

/// <summary>
/// "This person, this team, or everyone may use this plugin, marketplace or skill, as viewer, editor or manager." One table serves
/// all three kinds. <see cref="SubjectKey"/> (m:id, t:id or org) is unique per resource, so two requests sharing the same thing with the
/// same person at once end up with one row. A removed grant keeps its row (RemovedAt) and is reactivated by sharing again.
/// </summary>
public sealed class LibraryGrant
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string ResourceKind { get; set; }
    public required string ResourceId { get; set; }
    public required string SubjectKey { get; set; }
    public string? MemberId { get; set; }
    public string? TeamId { get; set; }
    public bool OrgWide { get; set; }
    public required string Role { get; set; }
    public required string CreatedByMemberId { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? RemovedAt { get; set; }
}

/// <summary>One time a person's agent read a skill. Ids only: no text, no arguments.</summary>
public sealed class LibraryUsageEvent
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string MemberId { get; set; }
    public required string PluginId { get; set; }
    public required string ConfigObjectId { get; set; }
    public required string Source { get; set; }
    public DateTime CreatedAt { get; set; }
}

public sealed class PluginConfiguration : IEntityTypeConfiguration<Plugin>
{
    public void Configure(EntityTypeBuilder<Plugin> b)
    {
        b.HasIndex(p => new { p.OrganizationId, p.UpdatedAt, p.Id });
        // One active plugin per creator and name, ignoring case, even when two requests race (the reference compares in a case-insensitive collation).
        b.HasIndex(p => p.ActiveKey).IsUnique();
    }
}

public sealed class ConfigObjectConfiguration : IEntityTypeConfiguration<ConfigObject>
{
    public void Configure(EntityTypeBuilder<ConfigObject> b) => b.HasIndex(o => new { o.OrganizationId, o.UpdatedAt, o.Id });
}

public sealed class ConfigObjectVersionConfiguration : IEntityTypeConfiguration<ConfigObjectVersion>
{
    public void Configure(EntityTypeBuilder<ConfigObjectVersion> b) => b.HasIndex(v => new { v.ConfigObjectId, v.CreatedAt, v.Id });
}

public sealed class MarketplaceConfiguration : IEntityTypeConfiguration<Marketplace>
{
    public void Configure(EntityTypeBuilder<Marketplace> b)
    {
        b.HasIndex(m => m.OrganizationId);
        b.HasIndex(m => new { m.OrganizationId, m.ExternalKey }).IsUnique();   // marketplaces without a key have none, and empty values are distinct
    }
}

public sealed class MarketplacePluginConfiguration : IEntityTypeConfiguration<MarketplacePlugin>
{
    public void Configure(EntityTypeBuilder<MarketplacePlugin> b)
    {
        b.HasIndex(m => new { m.MarketplaceId, m.PluginId }).IsUnique();
        b.HasIndex(m => m.PluginId);
    }
}

public sealed class PluginConfigObjectConfiguration : IEntityTypeConfiguration<PluginConfigObject>
{
    public void Configure(EntityTypeBuilder<PluginConfigObject> b)
    {
        b.HasIndex(m => new { m.PluginId, m.ConfigObjectId }).IsUnique();
        b.HasIndex(m => m.ConfigObjectId);
    }
}

public sealed class LibraryGrantConfiguration : IEntityTypeConfiguration<LibraryGrant>
{
    public void Configure(EntityTypeBuilder<LibraryGrant> b)
    {
        b.HasIndex(g => new { g.ResourceKind, g.ResourceId, g.SubjectKey }).IsUnique();
        b.HasIndex(g => new { g.OrganizationId, g.MemberId });
        b.HasIndex(g => new { g.OrganizationId, g.TeamId });
    }
}

public sealed class LibraryUsageEventConfiguration : IEntityTypeConfiguration<LibraryUsageEvent>
{
    public void Configure(EntityTypeBuilder<LibraryUsageEvent> b) => b.HasIndex(e => new { e.OrganizationId, e.CreatedAt });
}
