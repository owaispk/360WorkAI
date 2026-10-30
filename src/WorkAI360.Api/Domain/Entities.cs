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
    public DateTime? JoinedAt { get; set; }
    /// <summary>The invitation this person joined through, if any.</summary>
    public string? InviteId { get; set; }
}

public static class InvitationStatus
{
    public const string Pending = "pending";
    public const string Accepted = "accepted";
    public const string Canceled = "canceled";
    /// <summary>Not stored: a pending invitation past its expiry is reported as expired.</summary>
    public const string Expired = "expired";
}

/// <summary>An invitation to join a workspace. The token in the emailed link proves the person received it.</summary>
public sealed class Invitation
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string Email { get; set; }
    public required string Role { get; set; }
    public required string Status { get; set; }
    public required string InviteToken { get; set; }
    public required string InvitedByUserId { get; set; }
    /// <summary>The id the members list shows for this pending person (the reference lists invitations as placeholder members).</summary>
    public required string PlaceholderMemberId { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime? AcceptedAt { get; set; }
    public string? AcceptedByUserId { get; set; }

    public string EffectiveStatus(DateTime now) => Status == InvitationStatus.Pending && ExpiresAt <= now ? InvitationStatus.Expired : Status;
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

// ---- Email verification and password reset ----

/// <summary>A six-digit code emailed to prove inbox control. Only a keyed hash of the code is stored.</summary>
public sealed class EmailOtp
{
    public required string Id { get; set; }
    public required string Email { get; set; }
    public required string Type { get; set; }          // email-verification
    public required string CodeHash { get; set; }
    public int Attempts { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
}

/// <summary>A single-use password reset link; the primary key is the SHA-256 of the token in the link.</summary>
public sealed class PasswordResetToken
{
    public required string Id { get; set; }
    public required string UserId { get; set; }
    public string? RedirectTo { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime? ConsumedAt { get; set; }
}

/// <summary>A named group of members. An "Admin team" makes everyone in it an effective admin.</summary>
public sealed class Team
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    public required string Name { get; set; }
    public bool GrantsOrganizationAdmin { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

public sealed class TeamMember
{
    public required string Id { get; set; }
    public required string TeamId { get; set; }
    public required string MemberId { get; set; }
    public DateTime CreatedAt { get; set; }
}

/// <summary>
/// A set of permissions. Every workspace has a Member set (applies to everyone) and an Admin set (applies to admins);
/// any other set is a team's role, applying to the people in the teams it is linked to.
/// </summary>
public sealed class PermissionSet
{
    public required string Id { get; set; }
    public required string OrganizationId { get; set; }
    /// <summary>"member" or "admin" for the two built-in sets, null for a team role.</summary>
    public string? DefaultKey { get; set; }
    public required string Name { get; set; }
    public string? CreatedByMemberId { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? ArchivedAt { get; set; }
}

/// <summary>
/// One recorded decision about one key in one set. Rows are only ever added, so the history is kept; the newest row for a key is what
/// applies, and a key with no row is denied.
/// </summary>
public sealed class PermissionSetPermission
{
    public required string Id { get; set; }
    public required string PermissionSetId { get; set; }
    public required string PermissionKey { get; set; }
    /// <summary>"allow" or "deny".</summary>
    public required string Status { get; set; }
    /// <summary>"user" or "seed".</summary>
    public required string Source { get; set; }
    public string? ChangedByMemberId { get; set; }
    public DateTime CreatedAt { get; set; }
}

/// <summary>Links a role to a team. A team has at most one active role; unlinking keeps the row so history shows where it applied.</summary>
public sealed class PermissionSetTeam
{
    public required string Id { get; set; }
    public required string PermissionSetId { get; set; }
    public required string TeamId { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? RemovedAt { get; set; }
}
