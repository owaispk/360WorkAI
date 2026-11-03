using WorkAI360.Api.Auth;
using WorkAI360.Api.Features.Onboarding;

namespace WorkAI360.Api.OAuth;

/// <summary>
/// The RFC 7523 JWT-bearer grant for pre-claim assertions (the reference's <c>exchangePreclaimAssertion</c>). <c>POST /v1/bootstrap/workspace</c> gives an
/// agent a signed assertion naming one provisional workspace and its sign-in-less setup member; at the token endpoint the agent trades it for a short MCP
/// access token for that member in that workspace. No refresh token: the agent exchanges the assertion again. Claiming the workspace revokes the assertion
/// and removes the setup member, so tokens already minted stop working at once (the MCP endpoint checks membership on every call).
/// </summary>
public sealed class PreclaimGrant(BootstrapService bootstrap, SigningKeyStore keys, OAuthUrls urls)
{
    public const string GrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    public const string ClientId = "openwork-preclaim";
    public const string Scope = "mcp:read mcp:write";
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(15);

    private static IResult Refuse(string error, string description) =>
        Results.Json(new { error, error_description = description }, statusCode: 400);

    public async Task<IResult> ExchangeAsync(string? assertion)
    {
        assertion = assertion?.Trim();
        if (string.IsNullOrEmpty(assertion)) return Refuse("invalid_request", "The assertion parameter is required.");
        var (workspace, revoked) = await bootstrap.VerifyAssertionAsync(assertion);
        if (workspace is null) return Refuse("invalid_grant", "The assertion is invalid or expired.");
        if (revoked || string.IsNullOrEmpty(workspace.AgentUserId))
            return Refuse("invalid_grant", "This workspace was claimed or expired; its pre-claim credentials are revoked.");

        var now = DateTimeOffset.UtcNow;
        // Never outlives the provisional workspace itself.
        var workspaceEnds = new DateTimeOffset(DateTime.SpecifyKind(workspace.ExpiresAt, DateTimeKind.Utc));
        var expires = now + Lifetime < workspaceEnds ? now + Lifetime : workspaceEnds;
        var token = Jwt.Create(await keys.ActiveAsync(), new Dictionary<string, object?>
        {
            ["iss"] = urls.Issuer,
            ["sub"] = workspace.AgentUserId,
            ["aud"] = urls.CanonicalResource,
            ["azp"] = ClientId,
            ["client_id"] = ClientId,
            ["scope"] = Scope,
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = expires.ToUnixTimeSeconds(),
            ["jti"] = Ids.RandomAlnum(24),
            [OAuthConstants.ClaimOrg] = workspace.OrganizationId,
            [OAuthConstants.ClaimTokenUse] = "mcp",
        });
        return Results.Json(new
        {
            access_token = token,
            token_type = "Bearer",
            expires_in = Math.Max(1, (int)(expires - now).TotalSeconds),
            scope = Scope,
        });
    }
}
