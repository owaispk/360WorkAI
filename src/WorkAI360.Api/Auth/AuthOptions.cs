namespace WorkAI360.Api.Auth;

public sealed class AuthOptions
{
    public const string Section = "Auth";

    /// <summary>Signs the session cookie. At least 32 characters; set via configuration in every real deployment.</summary>
    public string Secret { get; set; } = "";

    /// <summary>Same name the reference API and den-web's cookie filter use.</summary>
    public string CookieName { get; set; } = "openwork-den.session_token";

    public int SessionDays { get; set; } = 7;

    /// <summary>Public web origin used in deep links when no forwarding headers are present.</summary>
    public string? PublicUrl { get; set; }

    /// <summary>
    /// The web origin, which is the OAuth issuer's host (issuer = WebUrl + "/api/auth"). Set it in every real deployment:
    /// changing it changes the issuer, and MCP clients must then sign in again. Falls back to the request's origin.
    /// </summary>
    public string? WebUrl { get; set; }

    /// <summary>The public API origin that serves /mcp/agent. Falls back to the request's origin.</summary>
    public string? ApiPublicUrl { get; set; }

    /// <summary>Client ids accepted by the device authorization flow.</summary>
    public string[] DeviceClientIds { get; set; } = ["openwork-cli", "openwork-opencode-plugin"];
}
