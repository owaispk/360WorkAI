using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace WorkAI360.Api.Domain.Oidc;

/// <summary>
/// What an ID token needs to know about the sign-in that produced an authorization code: the client's nonce, when the person signed in, and
/// which browser session it was. Keyed by the authorization code's hash (the same key the refresh tokens carry as CodeHash), so a refresh can
/// re-issue an ID token for the same sign-in. Only written for requests that ask for the "openid" scope.
/// </summary>
public sealed class OidcGrant
{
    public required string Id { get; set; }          // SHA-256 of the authorization code
    public required string ClientId { get; set; }
    public required string UserId { get; set; }
    public string? Nonce { get; set; }
    public DateTime AuthTime { get; set; }
    public string? SessionId { get; set; }
    public DateTime CreatedAt { get; set; }
}

/// <summary>OpenID Connect settings of a client that the base client table does not carry (one row per client that sets any).</summary>
public sealed class OidcClientSettings
{
    public required string ClientId { get; set; }
    /// <summary>The client may use RP-initiated logout. Only a registration made while signed in can set it.</summary>
    public bool EnableEndSession { get; set; }
    public string? PostLogoutRedirectUrisJson { get; set; }
}

public sealed class OidcGrantConfiguration : IEntityTypeConfiguration<OidcGrant>
{
    public void Configure(EntityTypeBuilder<OidcGrant> b)
    {
        b.HasKey(g => g.Id);
        b.Property(g => g.Nonce).HasMaxLength(512);
    }
}

public sealed class OidcClientSettingsConfiguration : IEntityTypeConfiguration<OidcClientSettings>
{
    public void Configure(EntityTypeBuilder<OidcClientSettings> b) => b.HasKey(s => s.ClientId);
}
