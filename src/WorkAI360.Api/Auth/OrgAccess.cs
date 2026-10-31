using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Endpoints;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Auth;

public sealed record OrgContext(AuthContext Auth, Organization Organization, Member Member, MemberPermissions Permissions, string? ApiKeyId = null)
{
    public bool IsOwner => Permissions.IsOwner;
    /// <summary>An admin by role or through an Admin team.</summary>
    public bool IsAdmin => Permissions.IsAdmin;
}

/// <summary>
/// Resolves "who is asking, in which workspace" for /v1 routes and decides what they may do, answering with the
/// reference's exact error shapes (so the web app's messages and re-authentication prompt keep working).
/// </summary>
public sealed class OrgAccess(DenDbContext db, SessionService sessions, PermissionService permissions, OAuthUrls urls, IOptions<AuthOptions> options, ApiKeyAuthenticator apiKeys)
{
    private const string RequiresAdmin = "requires_admin";

    /// <summary>
    /// The workspace is the one named by x-openwork-org-id, else the session's active one. Not signed in is 401; not a member is 404.
    /// An organization API key (x-api-key) is tried first, as in the reference: it names its own workspace (the header is ignored) and acts as the
    /// member that created it, who must still belong to it. API keys are accepted here and nowhere else, so session-only routes refuse them.
    /// </summary>
    public async Task<(OrgContext? Context, IResult? Failure)> ResolveAsync(HttpContext ctx)
    {
        var (principal, retryAfter) = await apiKeys.ResolveAsync(ctx);
        if (retryAfter is { } wait)
        {
            ctx.Response.Headers.RetryAfter = ((int)Math.Ceiling(wait.TotalSeconds)).ToString();
            return (null, Results.Json(new { error = "rate_limited", message = "This API key sent too many requests. Try again shortly." }, statusCode: 429));
        }

        var auth = principal is null ? await sessions.ResolveAsync(ctx) : AsAuth(principal);
        if (auth is null) return (null, Responses.Unauthorized());

        var requested = ctx.Request.Headers[OrgEndpoints.OrgHeader].ToString();
        var orgId = principal is not null ? principal.Key.OrganizationId : string.IsNullOrWhiteSpace(requested) ? auth.Session.ActiveOrganizationId : requested.Trim();
        if (orgId is null) return (null, NotFound());

        var member = await db.Members.AsNoTracking().FirstOrDefaultAsync(m => m.OrganizationId == orgId && m.UserId == auth.User.Id);
        if (member is null) return (null, NotFound());
        if (principal is not null && principal.Key.MemberId != member.Id)
            return (null, Results.Json(new { error = "forbidden", message = "This API key is no longer valid for the current organization member." }, statusCode: 403));
        var org = await db.Organizations.AsNoTracking().FirstAsync(o => o.Id == orgId);
        return (new OrgContext(auth, org, member, await permissions.ResolveAsync(orgId, member), principal?.Key.Id), null);
    }

    /// <summary>A key has no web session: this stand-in is never stored, and counts as freshly signed in (keys skip the recent-sign-in rule, as in the reference).</summary>
    private static AuthContext AsAuth(ApiKeyPrincipal principal)
    {
        var now = DateTime.UtcNow;
        var session = new Session
        {
            Id = "apikey_" + principal.Key.Id, TokenHash = "", UserId = principal.User.Id, ActiveOrganizationId = principal.Key.OrganizationId,
            Method = "api_key", CreatedAt = now, UpdatedAt = now, ExpiresAt = principal.Key.ExpiresAt,
        };
        return new AuthContext(principal.User, session, "");
    }

    /// <summary>For routes about the person rather than a workspace (/v1/me): a signed-in session, or an API key (then <c>Session</c> is null, as in the reference).</summary>
    public async Task<(User User, Session? Session, string Token)?> ResolveUserAsync(HttpContext ctx)
    {
        var (principal, _) = await apiKeys.ResolveAsync(ctx);
        if (principal is not null) return (principal.User, null, "");
        var auth = await sessions.ResolveAsync(ctx);
        return auth is null ? null : (auth.User, auth.Session, auth.PresentedToken);
    }

    private static IResult NotFound() => Results.Json(new { error = "organization_not_found" }, statusCode: 404);

    /// <summary>Null when allowed. A sensitive permission also needs a sign-in within the privileged window.</summary>
    public IResult? Require(OrgContext context, string permission)
    {
        var definition = Permissions.Definition(permission);
        if (!context.Permissions.Has(permission)) return Denied(definition);
        if (definition.Sensitive && !IsFresh(context.Auth.Session)) return ReauthRequired();
        return null;
    }

    public IResult? RequireOwner(OrgContext context)
    {
        if (!context.IsOwner) return Results.Json(DeniedBody("Only the workspace owner can do this.", null), statusCode: 403);
        return IsFresh(context.Auth.Session) ? null : ReauthRequired();
    }

    public bool IsFresh(Session session) =>
        DateTime.UtcNow - session.CreatedAt <= TimeSpan.FromMinutes(options.Value.PrivilegedSessionMinutes);

    public IResult Denied(PermissionDefinition definition)
    {
        var action = char.ToLowerInvariant(definition.Label[0]) + definition.Label[1..];
        // Keys no default set grants are the owner's to hand out; the rest an admin can.
        var ask = definition.AdminDefault || definition.MemberDefault ? "an admin to change your permissions" : "the organization owner";
        return Results.Json(DeniedBody($"You don't have permission to {action}. Ask {ask}.", definition.Key), statusCode: 403);
    }

    /// <summary>A 403 in the usual shape with a specific message (and, when one permission is the reason, its key).</summary>
    public IResult Forbidden(string message, string? permission = null) => Results.Json(DeniedBody(message, permission), statusCode: 403);

    private object DeniedBody(string message, string? permission) => permission is null
        ? new { error = "forbidden", code = RequiresAdmin, message, retryable = false, action_url = $"{urls.Web}/dashboard/members" }
        : new { error = "forbidden", code = RequiresAdmin, message, retryable = false, action_url = $"{urls.Web}/dashboard/members", requiredPermission = permission };

    public static IResult ReauthRequired() =>
        Results.Json(new { error = "reauth", reason = "fresh_auth_required", message = "For security, confirm it's you before changing workspace settings." }, statusCode: 403);
}
