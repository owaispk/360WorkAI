using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace WorkAI360.Api.Domain.Saml;

/// <summary>
/// The service provider's own key pair for one SAML connection: it signs AuthnRequests and logout messages, and identity providers encrypt assertions
/// to it. Made on first use (an RSA 2048 key with a self-signed certificate); the certificate is public and published in the SP metadata, the private
/// key is stored encrypted (AES-GCM, key derived from Auth:Secret).
/// </summary>
public sealed class SamlSpKey
{
    public required string ProviderId { get; set; }
    /// <summary>Base64 DER of the self-signed certificate.</summary>
    public required string CertificateDer { get; set; }
    /// <summary>The PKCS#8 private key, encrypted.</summary>
    public required string ProtectedPrivateKey { get; set; }
    public DateTime CreatedAt { get; set; }
}

/// <summary>
/// Which SAML sign-in a session came from (its NameID and SessionIndex), so Single Logout can end exactly those sessions: a LogoutRequest from the
/// identity provider names a NameID and optionally session indexes; a person's own sign-out sends the identity provider a LogoutRequest naming them.
/// </summary>
public sealed class SamlSessionLink
{
    public required string SessionId { get; set; }
    public required string ProviderId { get; set; }
    public required string NameId { get; set; }
    public string? NameIdFormat { get; set; }
    public string? SessionIndex { get; set; }
    public DateTime CreatedAt { get; set; }
}

/// <summary>A LogoutRequest this service sent (id hashed), so that only an answer to it is accepted as a LogoutResponse.</summary>
public sealed class SamlLogoutRequest
{
    public required string Id { get; set; }
    public required string ProviderId { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime? AnsweredAt { get; set; }
}

public sealed class SamlSpKeyConfiguration : IEntityTypeConfiguration<SamlSpKey>
{
    public void Configure(EntityTypeBuilder<SamlSpKey> b) => b.HasKey(k => k.ProviderId);
}

public sealed class SamlSessionLinkConfiguration : IEntityTypeConfiguration<SamlSessionLink>
{
    public void Configure(EntityTypeBuilder<SamlSessionLink> b)
    {
        b.HasKey(l => l.SessionId);
        b.Property(l => l.NameId).HasMaxLength(512);
        b.Property(l => l.SessionIndex).HasMaxLength(512);
        b.HasIndex(l => new { l.ProviderId, l.NameId });
    }
}

public sealed class SamlLogoutRequestConfiguration : IEntityTypeConfiguration<SamlLogoutRequest>
{
    public void Configure(EntityTypeBuilder<SamlLogoutRequest> b)
    {
        b.HasKey(r => r.Id);
        b.HasIndex(r => r.ExpiresAt);
    }
}
