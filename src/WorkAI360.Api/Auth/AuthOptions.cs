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

    /// <summary>
    /// When true, a new account must prove its email with an emailed code before it can sign in: sign-up returns no session,
    /// and sign-in answers 403 EMAIL_NOT_VERIFIED until then. Off by default (private deployments, local development).
    /// </summary>
    public bool RequireEmailVerification { get; set; }

    /// <summary>A new OAuth signing key is created when the newest one is this many days old (default 90).</summary>
    public int SigningKeyRotationDays { get; set; } = 90;

    /// <summary>A replaced key keeps being published for this many hours after its successor appeared, so tokens it signed still verify (default 48; access tokens last 45 minutes).</summary>
    public int SigningKeyGraceHours { get; set; } = 48;

    /// <summary>
    /// Refuse passwords found in public breaches (Have I Been Pwned range lookups: only the first five characters of the password's SHA-1 leave
    /// the server). Default: on everywhere except Development, so a local run works offline. When the lookup service is unreachable, sign-up and
    /// reset are refused with 503 rather than waved through.
    /// </summary>
    public bool? PasswordBreachScreening { get; set; }

    /// <summary>The range API's address (changed only to point tests at a local fake).</summary>
    public string PwnedPasswordsUrl { get; set; } = "https://api.pwnedpasswords.com";

    /// <summary>How recent a sign-in must be for sensitive workspace actions (changing roles, removing people, inviting). Default 120.</summary>
    public int PrivilegedSessionMinutes { get; set; } = 120;

    /// <summary>Extra origins a reset link may return to, besides the web origin.</summary>
    public string[] TrustedOrigins { get; set; } = [];

    /// <summary>
    /// Addresses of the proxies whose X-Forwarded-* headers are believed (the web host in front of the API). Everyone else's are
    /// ignored, so a caller cannot choose the origin in deep links or the address a rate limit sees. When empty, loopback is
    /// trusted (web host and API on one machine). Set it in any deployment where the web host is elsewhere: until it is, the API
    /// sees every visitor as the web host and the per-address rate limits share one bucket.
    /// (The default lives in code, not here: the configuration binder appends to an array's default instead of replacing it.)
    /// </summary>
    public string[] TrustedProxies { get; set; } = [];

    public const string LoopbackV4 = "127.0.0.1";
    public const string LoopbackV6 = "::1";

    /// <summary>Rate limits on the email endpoints. Off in Development unless set explicitly.</summary>
    public bool? RateLimitsEnabled { get; set; }

    /// <summary>The public API origin that serves /mcp/agent. Falls back to the request's origin.</summary>
    public string? ApiPublicUrl { get; set; }

    /// <summary>Client ids accepted by the device authorization flow.</summary>
    public string[] DeviceClientIds { get; set; } = ["openwork-cli", "openwork-opencode-plugin"];
}
