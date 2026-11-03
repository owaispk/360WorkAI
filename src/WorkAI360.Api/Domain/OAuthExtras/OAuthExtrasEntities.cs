using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace WorkAI360.Api.Domain.OAuthExtras;

/// <summary>
/// What a client registered beyond the original two grants and three authentication methods: its grant types, the keys it signs client assertions
/// with (<c>private_key_jwt</c>), whether its access tokens must be DPoP-bound, and the scopes it may ask for with <c>client_credentials</c>.
/// A client without a row here has the original defaults (authorization code and refresh token; no keys; not DPoP-bound).
/// </summary>
public sealed class OAuthClientExtras
{
    public required string ClientId { get; set; }
    /// <summary>JSON array of grant types; null means the defaults (authorization_code, refresh_token).</summary>
    public string? GrantTypesJson { get; set; }
    /// <summary>The client's public keys as a JWK Set (inline <c>jwks</c>); the other source is <see cref="JwksUri"/>.</summary>
    public string? JwksJson { get; set; }
    public string? JwksUri { get; set; }
    public bool DpopBoundAccessTokens { get; set; }
    /// <summary>The scopes (space separated) a <c>client_credentials</c> token may carry; set only by a platform administrator.</summary>
    public string? ClientCredentialsScope { get; set; }
}

public sealed class OAuthClientExtrasConfiguration : IEntityTypeConfiguration<OAuthClientExtras>
{
    public void Configure(EntityTypeBuilder<OAuthClientExtras> b)
    {
        b.HasKey(e => e.ClientId);
        b.Property(e => e.ClientId).HasMaxLength(255);
        b.Property(e => e.JwksUri).HasMaxLength(2048);
    }
}

/// <summary>
/// The key (RFC 7638 thumbprint) an authorization code or a refresh-token family is bound to: a code that was requested with <c>dpop_jkt</c>, or a
/// refresh token that was issued against a DPoP proof. The primary key is the code's hash or the family id.
/// </summary>
public sealed class OAuthDpopBinding
{
    public required string Id { get; set; }
    public required string Jkt { get; set; }
    public DateTime ExpiresAt { get; set; }
}

public sealed class OAuthDpopBindingConfiguration : IEntityTypeConfiguration<OAuthDpopBinding>
{
    public void Configure(EntityTypeBuilder<OAuthDpopBinding> b)
    {
        b.HasKey(e => e.Id);
        b.Property(e => e.Id).HasMaxLength(64);
        b.Property(e => e.Jkt).HasMaxLength(64);
        b.HasIndex(e => e.ExpiresAt);
    }
}
