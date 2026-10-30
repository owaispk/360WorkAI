namespace WorkAI360.Api.OAuth;

public static class OAuthConstants
{
    public const string ReadScope = "mcp:read";
    public const string WriteScope = "mcp:write";
    public const string OfflineScope = "offline_access";

    /// <summary>Scopes public OAuth may grant. The first-party desktop scope is never in this list.</summary>
    public static readonly string[] Scopes = [ReadScope, WriteScope, OfflineScope];
    public const string DefaultScope = "mcp:read mcp:write offline_access";

    public static readonly TimeSpan AccessTokenLifetime = TimeSpan.FromMinutes(45);
    public static readonly TimeSpan RefreshTokenLifetime = TimeSpan.FromDays(30);
    public static readonly TimeSpan CodeLifetime = TimeSpan.FromMinutes(10);
    public static readonly TimeSpan AuthorizationRequestLifetime = TimeSpan.FromMinutes(30);
    /// <summary>A rotated refresh token may be presented again this soon (a client that lost the response).</summary>
    public static readonly TimeSpan RefreshReuseInterval = TimeSpan.FromSeconds(30);

    public const string AccessTokenPrefix = "ow_mcp_at_";
    public const string RefreshTokenPrefix = "ow_mcp_rt_";
    public const string ClientSecretPrefix = "ow_mcp_cs_";
    public const string ClaimOrg = "org_id";
    public const string ClaimTokenUse = "token_use";

    public static string[] SplitScope(string? scope) =>
        (scope ?? "").Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries).Distinct().ToArray();

    public static string JoinScope(IEnumerable<string> scopes) => string.Join(' ', scopes.Distinct());
}
