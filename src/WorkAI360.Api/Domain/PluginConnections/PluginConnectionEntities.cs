using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace WorkAI360.Api.Domain.PluginConnections;

/// <summary>
/// "This server a plugin declares is served by this connection." One row per plugin, per MCP config object, per declared server name.
/// Who may use the connection through it is not stored: it is worked out from who may use the plugin (see <c>PluginBindingStore</c>), so
/// sharing or archiving the plugin changes it at once and nothing can go stale.
/// </summary>
public sealed class PluginMcpBinding
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string PluginId { get; set; }
    public required string ConfigObjectId { get; set; }
    public required string ServerName { get; set; }
    public required string ConnectionId { get; set; }
    /// <summary>oauth, apikey or none: what the requirement needs (what the plugin declares, else what was configured).</summary>
    public string? RequiredAuthType { get; set; }
    /// <summary>True when configuring the plugin made the connection, so it is the plugin's to manage and to remove again.</summary>
    public bool ConnectionOwnedByPlugin { get; set; }
    public required string CreatedByMemberId { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

public sealed class PluginMcpBindingConfiguration : IEntityTypeConfiguration<PluginMcpBinding>
{
    public void Configure(EntityTypeBuilder<PluginMcpBinding> b)
    {
        b.HasIndex(x => new { x.PluginId, x.ConfigObjectId, x.ServerName }).IsUnique();
        b.HasIndex(x => x.ConnectionId);
        b.HasIndex(x => x.ConfigObjectId);
        b.Property(x => x.ServerName).HasMaxLength(255);
    }
}
