using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace WorkAI360.Api.Domain.Saml;

/// <summary>
/// One SP-initiated SAML sign-in in flight. The AuthnRequest id (what the response's <c>InResponseTo</c> must name) and the RelayState value are
/// stored only as SHA-256 hex. The row passes through three states: started (the person was sent to the identity provider), answered (the
/// assertion at the ACS endpoint was fully validated and its identity stored here) and consumed (the browser that started the sign-in came
/// back and was signed in). The last step happens on a same-site navigation so the binding cookie, which a cross-site POST would not carry,
/// proves it is the same browser.
/// </summary>
public sealed class SamlAuthRequest
{
    public required string Id { get; set; }                  // SHA-256 hex of the AuthnRequest id
    public required string RelayStateHash { get; set; }      // SHA-256 hex of the RelayState value
    public required string ProviderId { get; set; }
    public required string ConfigRevision { get; set; }
    public required string BrowserBindingHash { get; set; }  // SHA-256 hex of the value in the binding cookie
    public required string CallbackUrl { get; set; }
    public string? ErrorCallbackUrl { get; set; }
    public string? NewUserCallbackUrl { get; set; }
    public string? TestIntentId { get; set; }
    /// <summary>The AuthnRequest XML, kept only for the POST binding (the page that submits it to the identity provider).</summary>
    public string? RequestXml { get; set; }
    /// <summary>The validated identity (subject, email, name), set when the response was accepted.</summary>
    public string? IdentityJson { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime? AnsweredAt { get; set; }
    public DateTime? ConsumedAt { get; set; }
}

public sealed class SamlAuthRequestConfiguration : IEntityTypeConfiguration<SamlAuthRequest>
{
    public void Configure(EntityTypeBuilder<SamlAuthRequest> b)
    {
        b.HasKey(r => r.Id);
        b.Property(r => r.Id).HasMaxLength(64);
        b.Property(r => r.RelayStateHash).HasMaxLength(64);
        b.HasIndex(r => r.RelayStateHash).IsUnique();
        b.HasIndex(r => r.ProviderId);
        b.HasIndex(r => r.ExpiresAt);
    }
}
