using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Sso;
using WorkAI360.Api.Endpoints;

namespace WorkAI360.Api.Features.Sso;

/// <summary>The routes a browser (and the sign-in pages) use to sign in through SSO: <c>POST /api/auth/sign-in/sso</c> and the provider's return, <c>GET /api/auth/sso/callback/{providerId}</c>.</summary>
public static class SsoSignInEndpoints
{
    public static readonly AuthLimitPolicy StartLimit = new("sso-start", TimeSpan.FromMinutes(5), 20, 100);
    private const string NotEnabled = "SSO is not enabled for this organization. An administrator must test and enable the saved configuration first.";

    private static IResult Message(int status, string message, string? code = null) =>
        code is null ? Results.Json(new { message }, statusCode: status) : Results.Json(new { message, code }, statusCode: status);

    public static void Map(WebApplication app)
    {
        app.MapPost("/api/auth/sign-in/sso", async (HttpContext ctx, DenDbContext db, OidcFlow flow, TrustedUrls trusted, RateLimiter limiter) =>
        {
            if (limiter.Hit(StartLimit, null, AuthEndpoints.ClientIp(ctx)) is { } wait) return AuthEndpoints.TooManyRequests(ctx, wait);
            var body = await BodyReader.ReadAsync(ctx.Request);
            string? Opt(string name) => body.String(name, false) is { Length: > 0 } s ? s.Trim() : null;
            var email = Opt("email"); var slug = Opt("organizationSlug"); var providerId = Opt("providerId"); var domain = Opt("domain");
            var callback = Opt("callbackURL"); var errorCallback = Opt("errorCallbackURL"); var newUserCallback = Opt("newUserCallbackURL"); var loginHint = Opt("loginHint");
            if (body.Details.Count > 0) return Message(400, "Invalid request body.", "VALIDATION_ERROR");

            // Which connection? (providerId, then the workspace slug, then the email's domain), as the reference resolves it.
            SsoConnection? connection = null;
            if (providerId is not null) connection = await db.Set<SsoConnection>().FirstOrDefaultAsync(c => c.ProviderId == providerId, ctx.RequestAborted);
            else if (slug is not null)
            {
                connection = await (from c in db.Set<SsoConnection>() join o in db.Organizations on c.OrganizationId equals o.Id where o.Slug == slug select c).FirstOrDefaultAsync(ctx.RequestAborted);
                if (connection is null) return Message(400, "providerId, orgId or domain is required");
            }
            else
            {
                var d = domain?.ToLowerInvariant() ?? SsoService.EmailDomain(email);
                if (d is null) return Message(400, "email, organizationSlug, domain or providerId is required");
                var all = await db.Set<SsoConnection>().OrderByDescending(c => c.Status == "enabled").ThenBy(c => c.CreatedAt).ToListAsync(ctx.RequestAborted);
                connection = all.FirstOrDefault(c => SsoService.EmailDomainMatches(d, c.Domain));
            }
            if (connection is null) return Message(404, "No provider found for the issuer");
            // A disabled connection only signs in for an administrator's test, which starts from the dashboard (never from here).
            if (!SsoService.Ready(connection)) return Message(403, NotEnabled);
            if (connection.Kind != "oidc") return Message(400, "Invalid SSO provider");

            if (callback is null) return Message(400, "[body.callbackURL] Invalid input: expected string, received undefined", "VALIDATION_ERROR");
            // Open-redirect guard: only this site's own pages may be returned to.
            if (!trusted.IsTrusted(callback)) return Message(403, "Invalid callbackURL", "INVALID_CALLBACK_URL");
            if (errorCallback is not null && !trusted.IsTrusted(errorCallback)) return Message(403, "Invalid errorCallbackURL", "INVALID_ERROR_CALLBACK_URL");
            if (newUserCallback is not null && !trusted.IsTrusted(newUserCallback)) return Message(403, "Invalid newUserCallbackURL", "INVALID_NEW_USER_CALLBACK_URL");

            var url = await flow.StartAsync(ctx, connection, new OidcFlow.Start(callback, errorCallback, newUserCallback, loginHint ?? email, null), ctx.RequestAborted);
            return Results.Json(new { url, redirect = true });
        });

        app.MapGet("/api/auth/sso/callback/{providerId}", (string providerId, HttpContext ctx, OidcFlow flow) => flow.CallbackAsync(ctx, providerId, ctx.RequestAborted));
    }
}
