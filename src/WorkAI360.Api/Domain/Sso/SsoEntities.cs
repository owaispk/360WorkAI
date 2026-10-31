using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace WorkAI360.Api.Domain.Sso;

/// <summary>
/// A workspace's single sign-on setup (one per workspace). The reference keeps this in two tables (connection and provider); one table is
/// enough here. The client secret is only ever stored encrypted.
/// </summary>
public sealed class SsoConnection
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    /// <summary>"openwork-sso-{organizationId}": names the connection in URLs and on linked sign-ins.</summary>
    public required string ProviderId { get; set; }
    /// <summary>"oidc" or "saml".</summary>
    public required string Kind { get; set; }
    public required string Issuer { get; set; }
    /// <summary>One or more comma-separated email domains the workspace claims.</summary>
    public required string Domain { get; set; }
    public required string Status { get; set; }              // disabled | enabled
    public required string SignInPath { get; set; }
    public required string ConfigRevision { get; set; }
    public required string TestStatus { get; set; }          // untested | testing | succeeded | failed
    public DateTime? LastTestedAt { get; set; }
    public string? LastTestedRevision { get; set; }
    public string? LastError { get; set; }

    public bool DomainVerified { get; set; }
    public string? DomainVerificationToken { get; set; }
    public DateTime? DomainVerificationExpiresAt { get; set; }

    /// <summary>Public OIDC settings (client id, scopes, endpoints) as JSON. Never holds the secret.</summary>
    public string? OidcConfigJson { get; set; }
    /// <summary>The client secret, AES-GCM encrypted with a key derived from Auth:Secret.</summary>
    public string? ClientSecretProtected { get; set; }
    public string? SamlConfigJson { get; set; }

    public string? ActiveTestIntentId { get; set; }
    public string? ActiveTestUserId { get; set; }
    public string? ActiveTestProviderId { get; set; }
    public string? ActiveTestConfigRevision { get; set; }
    public DateTime? ActiveTestExpiresAt { get; set; }
    public DateTime? ActiveTestStartedAt { get; set; }

    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

public sealed class SsoConnectionConfiguration : IEntityTypeConfiguration<SsoConnection>
{
    public void Configure(EntityTypeBuilder<SsoConnection> b)
    {
        b.HasIndex(c => c.OrganizationId).IsUnique();
        b.HasIndex(c => c.ProviderId).IsUnique();
        b.HasIndex(c => c.ActiveTestIntentId);
    }
}

/// <summary>
/// One sign-in attempt in flight (the OIDC "state"). The state value is only stored hashed, the PKCE verifier encrypted, and the nonce
/// hashed; a state works once, only for the connection it was made for, and only in the browser that started it (cookie binding).
/// </summary>
public sealed class SsoAuthState
{
    public required string Id { get; set; }                  // SHA-256 of the state value
    public required string ProviderId { get; set; }
    public required string ConfigRevision { get; set; }
    public required string BrowserBindingHash { get; set; }  // SHA-256 of the value in the binding cookie
    public required string NonceHash { get; set; }
    public required string CodeVerifierProtected { get; set; }
    public required string CallbackUrl { get; set; }
    public string? ErrorCallbackUrl { get; set; }
    public string? NewUserCallbackUrl { get; set; }
    public string? TestIntentId { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime? ConsumedAt { get; set; }
}

/// <summary>
/// Links an identity at an outside provider to a person: for single sign-on the provider's stable subject, for SCIM the account id the
/// identity provider uses. Later sign-ins follow the link, never the email, so a changed email at the provider cannot take over an account.
/// </summary>
public sealed class ExternalAccount
{
    public required string Id { get; set; }
    public required string UserId { get; set; }
    public required string ProviderId { get; set; }
    public required string AccountId { get; set; }
    public DateTime CreatedAt { get; set; }
}

public sealed class ExternalAccountConfiguration : IEntityTypeConfiguration<ExternalAccount>
{
    public void Configure(EntityTypeBuilder<ExternalAccount> b)
    {
        b.HasIndex(a => new { a.ProviderId, a.AccountId }).IsUnique();
        b.HasIndex(a => a.UserId);
    }
}

/// <summary>What the workspace knows about a person who comes from single sign-on and/or SCIM.</summary>
public sealed class ExternalIdentity
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string UserId { get; set; }
    /// <summary>sso | scim | scim+sso</summary>
    public required string Source { get; set; }
    public string? SsoProviderId { get; set; }
    public string? ScimProviderId { get; set; }
    public string? RemoteId { get; set; }
    public string? ExternalId { get; set; }
    public string? UserName { get; set; }
    public string? Email { get; set; }
    public string? DisplayName { get; set; }
    public bool Active { get; set; } = true;
    public DateTime? LastSsoLoginAt { get; set; }
    public DateTime? LastScimSyncAt { get; set; }
}

public sealed class ExternalIdentityConfiguration : IEntityTypeConfiguration<ExternalIdentity>
{
    public void Configure(EntityTypeBuilder<ExternalIdentity> b)
    {
        b.HasIndex(i => new { i.OrganizationId, i.UserId }).IsUnique();
    }
}
