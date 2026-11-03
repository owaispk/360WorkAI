using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Sso;
using WorkAI360.Api.Endpoints;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Features.Sso;

/// <summary>
/// The SAML routes under <c>/api/auth/sso/saml2/sp/*</c> (the reference's paths): <c>acs/{providerId}</c> (the identity provider's POST), <c>metadata</c>
/// (what the identity provider administrator imports), plus <c>login/{providerId}</c> (the POST-binding page) and <c>continue/{providerId}</c> (the same-site
/// last step), which only this implementation has.
/// </summary>
public static class SamlEndpoints
{
    public static void Map(WebApplication app)
    {
        app.MapPost("/api/auth/sso/saml2/sp/acs/{providerId}", async (string providerId, HttpContext ctx, SamlFlow flow, RateLimiter limiter) =>
        {
            if (limiter.Hit(SamlFlow.AcsLimit, null, AuthEndpoints.ClientIp(ctx)) is { } wait) return AuthEndpoints.TooManyRequests(ctx, wait);
            string? response = null, relay = null;
            if (ctx.Request.HasFormContentType)
            {
                var form = await ctx.Request.ReadFormAsync(ctx.RequestAborted);
                response = form["SAMLResponse"].FirstOrDefault();
                relay = form["RelayState"].FirstOrDefault();
            }
            else if (ctx.Request.ContentType?.Contains("application/json", StringComparison.OrdinalIgnoreCase) == true)
            {
                var body = await BodyReader.ReadAsync(ctx.Request);
                response = body.String("SAMLResponse", false);
                relay = body.String("RelayState", false);
            }
            return await flow.AcsAsync(ctx, providerId, response, relay, ctx.RequestAborted);
        });

        // A browser that lands here without a response (a bookmark, a back button) is simply sent on.
        app.MapGet("/api/auth/sso/saml2/sp/acs/{providerId}", async (HttpContext ctx, SessionService sessions, OAuthUrls urls) =>
            await sessions.ResolveAsync(ctx) is null
                ? Results.Redirect($"{urls.Web}/connect/error?error=invalid_request")
                : Results.Redirect(urls.Web));

        app.MapGet("/api/auth/sso/saml2/sp/continue/{providerId}", (string providerId, string? id, HttpContext ctx, SamlFlow flow) => flow.ContinueAsync(ctx, providerId, id, ctx.RequestAborted));

        app.MapGet("/api/auth/sso/saml2/sp/login/{providerId}", (string providerId, string? relay, HttpContext ctx, SamlFlow flow) => flow.LoginFormAsync(ctx, providerId, relay, ctx.RequestAborted));

        app.MapGet("/api/auth/sso/saml2/sp/metadata", async (string? providerId, HttpContext ctx, DenDbContext db, SsoService sso, SamlServiceProvider sp) =>
        {
            if (string.IsNullOrEmpty(providerId)) return Results.Json(new { message = "[query.providerId] Invalid input: expected string, received undefined" }, statusCode: 400);
            var connection = await db.Set<SsoConnection>().FirstOrDefaultAsync(c => c.ProviderId == providerId);
            if (connection is null) return Results.Json(new { message = "No provider found for the given providerId" }, statusCode: 404);
            return await SamlMetadataResultAsync(sso, sp, connection, ctx.RequestAborted) ?? Results.Json(new { message = "Invalid SAML configuration" }, statusCode: 400);
        });

        // Single Logout: logout messages from the identity provider (redirect or POST binding), and a person's own SAML logout.
        app.MapGet("/api/auth/sso/saml2/sp/slo/{providerId}", (string providerId, HttpContext ctx, SamlLogoutFlow flow) => flow.ReceiveAsync(ctx, providerId, ctx.RequestAborted));
        app.MapPost("/api/auth/sso/saml2/sp/slo/{providerId}", (string providerId, HttpContext ctx, SamlLogoutFlow flow) => flow.ReceiveAsync(ctx, providerId, ctx.RequestAborted));
        app.MapGet("/api/auth/sso/saml2/sp/logout/{providerId}", (string providerId, HttpContext ctx, SamlLogoutFlow flow) => flow.StartAsync(ctx, providerId, ctx.RequestAborted));
    }

    /// <summary>
    /// The service provider metadata as XML, or null when the connection is not a SAML one. It carries this connection's service provider certificate
    /// (made on first request) for checking signed requests and for encrypting assertions, and its Single Logout endpoints.
    /// </summary>
    public static async Task<IResult?> SamlMetadataResultAsync(SsoService sso, SamlServiceProvider sp, SsoConnection connection, CancellationToken ct)
    {
        var settings = SsoService.SamlSettingsOf(connection);
        if (settings is null) return null;
        var certificate = await sp.CertificateAsync(connection.ProviderId, ct);
        var xml = SamlProtocol.Metadata(sso.SpEntityId(settings), sso.AcsUrl(connection.ProviderId), sso.SloUrl(connection.ProviderId), certificate, settings.SignAuthnRequests);
        return Results.Content(xml, "application/xml", Encoding.UTF8);
    }
}
