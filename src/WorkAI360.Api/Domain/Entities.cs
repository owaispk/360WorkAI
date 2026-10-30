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
