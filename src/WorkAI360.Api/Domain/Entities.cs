namespace WorkAI360.Api.Domain;

public sealed class User
{
    public required string Id { get; set; }
    public required string Email { get; set; }
    public required string Name { get; set; }
    public bool EmailVerified { get; set; }
    public string? Image { get; set; }
    public required string PasswordHash { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

/// <summary>A signed-in browser, desktop app or CLI. The bearer token and the cookie both carry the same secret; only its SHA-256 is stored.</summary>
public sealed class Session
{
    public required string Id { get; set; }
    public required string TokenHash { get; set; }
    public required string UserId { get; set; }
    public string? ActiveOrganizationId { get; set; }
    public required string Method { get; set; }
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
}

public sealed class Organization
{
    public required string Id { get; set; }
    public required string Name { get; set; }
    public required string Slug { get; set; }
    public DateTime CreatedAt { get; set; }
}

public sealed class Member
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string UserId { get; set; }
    public required string Role { get; set; }
    public DateTime CreatedAt { get; set; }
}

/// <summary>One-time grant that hands a signed-in web session to the desktop app.</summary>
public sealed class DesktopHandoffGrant
{
    public required string Id { get; set; }
    public required string UserId { get; set; }
    public string? OrganizationId { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime? ConsumedAt { get; set; }
}

public static class DeviceStatus
{
    public const string Pending = "pending";
    public const string Approved = "approved";
    public const string Denied = "denied";
    public const string Consumed = "consumed";
}

/// <summary>RFC 8628 device authorization (CLI and OpenCode plugin sign-in).</summary>
public sealed class DeviceCode
{
    public required string Id { get; set; }
    public required string DeviceCodeHash { get; set; }
    public required string UserCode { get; set; }
    public required string ClientId { get; set; }
    public required string Status { get; set; }
    public string? UserId { get; set; }
    public string? OrganizationId { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime? LastPolledAt { get; set; }
}

// ---- OAuth provider (MCP clients) ----

/// <summary>An OAuth client: registered dynamically (RFC 7591) by an MCP client such as Claude Code or Cursor.</summary>
public sealed class OAuthClient
{
    public required string Id { get; set; }            // the client_id
    public required string Name { get; set; }
    public required string RedirectUrisJson { get; set; }
    public required string Scope { get; set; }
    public required string AuthMethod { get; set; }    // none | client_secret_basic | client_secret_post
    public string? SecretHash { get; set; }
    public string? LogoUri { get; set; }
    public DateTime CreatedAt { get; set; }
}

/// <summary>A one-time authorization code; the primary key is the SHA-256 of the code.</summary>
public sealed class AuthorizationCode
{
    public required string Id { get; set; }
    public required string ClientId { get; set; }
    public required string UserId { get; set; }
    public required string OrganizationId { get; set; }
    public required string RedirectUri { get; set; }
    public required string Scope { get; set; }
    public required string Resource { get; set; }
    public required string CodeChallenge { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime? ConsumedAt { get; set; }
}

/// <summary>What a person already allowed a client to do in one workspace, so repeat sign-ins skip the consent screen.</summary>
public sealed class OAuthConsent
{
    public required string Id { get; set; }
    public required string ClientId { get; set; }
    public required string UserId { get; set; }
    public required string OrganizationId { get; set; }
    public required string Scope { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

/// <summary>Opaque refresh token (SHA-256 stored). Tokens from one grant share a family so reuse can revoke them all.</summary>
public sealed class RefreshToken
{
    public required string Id { get; set; }
    public required string FamilyId { get; set; }
    public string? CodeHash { get; set; }
    public required string ClientId { get; set; }
    public required string UserId { get; set; }
    public required string OrganizationId { get; set; }
    public required string Scope { get; set; }
    public required string Resource { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime? RotatedAt { get; set; }
    public DateTime? RevokedAt { get; set; }
}

/// <summary>First-party opaque MCP token (`ow_mcp_at_…`) minted for a signed-in person by the desktop app.</summary>
public sealed class McpAccessToken
{
    public required string Id { get; set; }
    public required string Kind { get; set; }          // first-party | app-host
    public required string UserId { get; set; }
    public required string OrganizationId { get; set; }
    public required string Scope { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
}

/// <summary>An ES256 key that signs access tokens. The private half is encrypted with a key derived from Auth:Secret.</summary>
public sealed class SigningKey
{
    public required string Id { get; set; }            // kid
    public required string X { get; set; }
    public required string Y { get; set; }
    public required string ProtectedPrivate { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? RetiredAt { get; set; }
}
