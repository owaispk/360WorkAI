using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace WorkAI360.Api.Domain.Connections;

/// <summary>
/// An external MCP server a workspace connects ("Add any MCP"). Secrets (API key, request header values, OAuth tokens) are stored
/// encrypted (<c>*Enc</c> columns hold AES-GCM text) and never returned. A shared connection has one credential held here; a per-member one
/// keeps each person's credential in <see cref="ConnectedAccount"/>.
/// </summary>
public sealed class ExternalMcpConnection
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string Name { get; set; }
    public string? ExternalKey { get; set; }
    public required string Url { get; set; }
    /// <summary>oauth, apikey or none.</summary>
    public required string AuthType { get; set; }
    /// <summary>shared or per_member.</summary>
    public required string CredentialMode { get; set; }
    public bool ExposeDirectly { get; set; }
    /// <summary>bearer or token.</summary>
    public string ApiKeyAuthScheme { get; set; } = "bearer";
    public string? ApiKeyEnc { get; set; }
    /// <summary>JSON <c>[{name,value}]</c>, encrypted.</summary>
    public string? RequestHeadersEnc { get; set; }
    public string? AccessTokenEnc { get; set; }
    public string? RefreshTokenEnc { get; set; }
    public string? TokenType { get; set; }
    public string? Scope { get; set; }
    public DateTime? ExpiresAt { get; set; }
    /// <summary>JSON: authorizationServerIssuer, requestedScopes, manualOAuthEndpoints.</summary>
    public string? OAuthConfigJson { get; set; }
    /// <summary>JSON: allDisabled, disabledTools, updatedByName, updatedAt.</summary>
    public string? ToolPolicyJson { get; set; }
    public string? ReadinessJson { get; set; }
    public string? CredentialHealthJson { get; set; }
    public DateTime? ConnectedAt { get; set; }
    public required string CreatedByMemberId { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

/// <summary>Who may use a connection: everyone in the workspace, one person, or one team (exactly one of the three per row).</summary>
public sealed class ConnectionAccessGrant
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string ConnectionId { get; set; }
    public string? MemberId { get; set; }
    public string? TeamId { get; set; }
    public bool OrgWide { get; set; }
    public required string CreatedByMemberId { get; set; }
    public DateTime CreatedAt { get; set; }
}

/// <summary>One person's own credential for a per-member connection (an OAuth grant or a personal API key). Never shared.</summary>
public sealed class ConnectedAccount
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string MemberId { get; set; }
    public required string ConnectionId { get; set; }
    public string? AccessTokenEnc { get; set; }
    public string? RefreshTokenEnc { get; set; }
    /// <summary>Bearer for OAuth tokens, api_key for a personal key.</summary>
    public string? TokenType { get; set; }
    public string? Scopes { get; set; }
    public DateTime? ExpiresAt { get; set; }
    public string? ReadinessJson { get; set; }
    public string? CredentialHealthJson { get; set; }
    public DateTime ConnectedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

/// <summary>The OAuth app (client) this workspace uses with a connection's authorization server, registered dynamically or entered by an admin.</summary>
public sealed class ConnectionOAuthClient
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string ConnectionId { get; set; }
    public required string ClientId { get; set; }
    public string? ClientSecretEnc { get; set; }
    /// <summary>dynamic, client-metadata or pre-registered.</summary>
    public required string RegistrationSource { get; set; }
    public string? TokenEndpointAuthMethod { get; set; }
    /// <summary>The authorization server the client belongs to; a different issuer needs a new client.</summary>
    public string? Issuer { get; set; }
    public required string CreatedByMemberId { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

/// <summary>A sign-in in progress: the random <c>state</c> value sent to the provider finds this row when the provider comes back. Single use.</summary>
public sealed class ConnectionOAuthTransaction
{
    /// <summary>SHA-256 of the state value (the value itself only travels to the provider and back).</summary>
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string ConnectionId { get; set; }
    public required string MemberId { get; set; }
    public required string CodeVerifierEnc { get; set; }
    public required string RedirectUri { get; set; }
    public required string TokenEndpoint { get; set; }
    public required string Issuer { get; set; }
    public required string Resource { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
}

public sealed class ExternalMcpConnectionConfiguration : IEntityTypeConfiguration<ExternalMcpConnection>
{
    public void Configure(EntityTypeBuilder<ExternalMcpConnection> b)
    {
        b.HasIndex(c => c.OrganizationId);
        b.HasIndex(c => new { c.OrganizationId, c.ExternalKey }).IsUnique();
        b.Property(c => c.Url).HasMaxLength(2048);
        b.Property(c => c.Name).HasMaxLength(255);
        // An edit applies only to the version the person opened; two edits at once cannot both win.
        b.Property(c => c.UpdatedAt).IsConcurrencyToken();
    }
}

public sealed class ConnectionAccessGrantConfiguration : IEntityTypeConfiguration<ConnectionAccessGrant>
{
    public void Configure(EntityTypeBuilder<ConnectionAccessGrant> b)
    {
        b.HasIndex(g => g.ConnectionId);
        b.HasIndex(g => g.MemberId);
        b.HasIndex(g => g.TeamId);
        b.HasIndex(g => new { g.ConnectionId, g.MemberId }).IsUnique();
        b.HasIndex(g => new { g.ConnectionId, g.TeamId }).IsUnique();
    }
}

public sealed class ConnectedAccountConfiguration : IEntityTypeConfiguration<ConnectedAccount>
{
    public void Configure(EntityTypeBuilder<ConnectedAccount> b)
    {
        b.HasIndex(a => new { a.MemberId, a.ConnectionId }).IsUnique();
        b.HasIndex(a => a.ConnectionId);
    }
}

public sealed class ConnectionOAuthClientConfiguration : IEntityTypeConfiguration<ConnectionOAuthClient>
{
    public void Configure(EntityTypeBuilder<ConnectionOAuthClient> b) => b.HasIndex(c => new { c.OrganizationId, c.ConnectionId }).IsUnique();
}

public sealed class ConnectionOAuthTransactionConfiguration : IEntityTypeConfiguration<ConnectionOAuthTransaction>
{
    public void Configure(EntityTypeBuilder<ConnectionOAuthTransaction> b) => b.HasIndex(t => t.ExpiresAt);
}
