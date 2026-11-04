using WorkAI360.Api.Features.OrgAdmin;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Sso;
using WorkAI360.Api.Features.Sso;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Features.Scim;

/// <summary>The SCIM settings API (<c>/v1/scim*</c>) the dashboard's SCIM page uses.</summary>
public static class ScimAdminEndpoints
{
    public static string BaseUrl(OAuthUrls urls) => $"{urls.Web}/api/auth/scim/v2";

    private static object Connection(ScimProvider c) => new
    {
        id = c.Id, providerId = c.ProviderId, organizationId = c.OrganizationId,
        groupMappingMode = ScimService.TeamModeOf(c), createdAt = Responses.IsoUtc(c.CreatedAt), updatedAt = Responses.IsoUtc(c.UpdatedAt),
    };

    private static async Task<bool> SsoReadyAsync(DenDbContext db, string organizationId) =>
        await db.Set<SsoConnection>().AnyAsync(c => c.OrganizationId == organizationId && c.Status == "enabled" && c.DomainVerified);

    private static async Task<object> StateAsync(DenDbContext db, ScimService scim, OAuthUrls urls, string organizationId, ScimProvider? connection) => new
    {
        baseUrl = BaseUrl(urls), ssoReady = await SsoReadyAsync(db, organizationId), connection = connection is null ? null : Connection(connection), health = await scim.HealthAsync(organizationId),
    };

    public static void Map(WebApplication app)
    {
        app.MapGet("/v1/scim", async (HttpContext ctx, OrgAccess access, DenDbContext db, ScimService scim, OAuthUrls urls) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "scim.view") is { } denied) return denied;
            var org = context!.Organization.Id;
            return Results.Json(await StateAsync(db, scim, urls, org, await db.Set<ScimProvider>().AsNoTracking().FirstOrDefaultAsync(p => p.OrganizationId == org)));
        });

        // Creates the connection when there is none and always hands out a fresh token; the token is shown here once and kept only as a hash.
        app.MapPost("/v1/scim/token", async (HttpContext ctx, OrgAccess access, DenDbContext db, ScimService scim, OAuthUrls urls, IAuditLog audit) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "scim.manage") is { } denied) return denied;
            var org = context!.Organization.Id;
            if (!await SsoReadyAsync(db, org))
                return Results.Json(new { error = "sso_required", message = "Configure an enabled SSO connection before creating or rotating a SCIM token." }, statusCode: 409);
            var existing = await db.Set<ScimProvider>().AsNoTracking().FirstOrDefaultAsync(p => p.OrganizationId == org);
            var before = existing is null ? null : DomainAuditEvents.Scim(existing);
            var (provider, token) = await scim.RotateTokenAsync(org, context.Auth.User.Id);
            await audit.RecordAsync(context, DomainAuditEvents.ScimTokenRotatedEntry(org, before, provider));
            return Results.Json(new { baseUrl = BaseUrl(urls), ssoReady = true, connection = Connection(provider), scimToken = token, health = await scim.HealthAsync(org) }, statusCode: 201);
        });

        app.MapPatch("/v1/scim", async (HttpContext ctx, OrgAccess access, DenDbContext db, ScimService scim, OAuthUrls urls, IAuditLog audit) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "scim.manage") is { } denied) return denied;
            var body = await BodyReader.ReadAsync(ctx.Request);
            var mode = body.Enum("groupMappingMode", ScimService.MetadataOnly, ScimService.CreateTeams);
            if (mode is null && body.Details.Count == 0) body.String("groupMappingMode", true);
            if (body.Failure is { } invalid) return invalid;
            var org = context!.Organization.Id;
            var connection = await db.Set<ScimProvider>().AsNoTracking().FirstOrDefaultAsync(p => p.OrganizationId == org);
            if (connection is null) return Results.Json(new { error = "not_found", message = "Create the SCIM connector before enabling group mapping." }, statusCode: 404);
            var mappingEntry = DomainAuditEvents.ScimGroupMappingEntry(org, connection, mode!);
            await scim.SetMappingModeAsync(connection, mode!);
            if (mappingEntry is not null) await audit.RecordAsync(context, mappingEntry);
            return Results.Json(await StateAsync(db, scim, urls, org, await db.Set<ScimProvider>().AsNoTracking().FirstAsync(p => p.OrganizationId == org)));
        });

        app.MapPost("/v1/scim/reconcile", async (HttpContext ctx, OrgAccess access, ScimService scim, DenDbContext db, IAuditLog audit) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "scim.manage") is { } denied) return denied;
            var (checkedCount, repaired, failures) = await scim.ReconcileAsync(context!.Organization.Id);
            var connectionId = await db.Set<ScimProvider>().AsNoTracking().Where(p => p.OrganizationId == context.Organization.Id).Select(p => p.Id).FirstOrDefaultAsync();
            await audit.RecordAsync(context, DomainAuditEvents.ScimReconciledEntry(context.Organization.Id, connectionId, checkedCount, repaired, failures));
            return Results.Json(new { @checked = checkedCount, repaired, failures });
        });

        app.MapDelete("/v1/scim", async (HttpContext ctx, OrgAccess access, DenDbContext db, ScimService scim, IAuditLog audit) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "scim.manage") is { } denied) return denied;
            var connection = await db.Set<ScimProvider>().AsNoTracking().FirstOrDefaultAsync(p => p.OrganizationId == context!.Organization.Id);
            if (connection is not null)
            {
                await scim.DeleteConnectionAsync(connection);
                await audit.RecordAsync(context!, DomainAuditEvents.ScimDeletedEntry(context!.Organization.Id, connection));
            }
            return Results.NoContent();
        });
    }
}
