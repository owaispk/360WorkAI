using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace WorkAI360.Api.Domain.Social;

/// <summary>
/// One social sign-in attempt (Google or GitHub), from the moment the person is sent to the provider until they come back. The state value
/// itself is never stored, only its SHA-256, so the table cannot be used to forge a return. An attempt works once, for one provider, in the
/// browser that started it. The PKCE verifier is stored encrypted.
/// </summary>
public sealed class SocialAuthState
{
    public required string Id { get; set; }                  // SHA-256 of the state value
    public required string Provider { get; set; }            // google | github
    public required string BrowserBindingHash { get; set; }  // SHA-256 of the value in the binding cookie
    public string? NonceHash { get; set; }                   // Google only (ID token nonce)
    public required string CodeVerifierProtected { get; set; }
    public required string CallbackUrl { get; set; }
    public string? ErrorCallbackUrl { get; set; }
    public string? NewUserCallbackUrl { get; set; }
    public bool RequestSignUp { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime? ConsumedAt { get; set; }
}

public sealed class SocialAuthStateConfiguration : IEntityTypeConfiguration<SocialAuthState>
{
    public void Configure(EntityTypeBuilder<SocialAuthState> b)
    {
        b.HasKey(s => s.Id);
        b.HasIndex(s => s.ExpiresAt);
    }
}
