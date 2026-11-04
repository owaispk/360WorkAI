using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Endpoints;

namespace WorkAI360.Api.Features.OrgAdmin;

/// <summary>
/// One catalog permission and its status in every active set (the reference's <c>GET /v1/permissions/keys/:permissionKey</c>): the Member and
/// Admin defaults first, then each team set by name. Requires permissions.view; an unknown key is 404 <c>permission_not_found</c>.
/// </summary>
public sealed class PermissionKeyFeature : IFeature
{
    private const int MaxKeyLength = 128;

    public void AddServices(IServiceCollection services, IConfiguration configuration) { }

    public void MapEndpoints(WebApplication app)
    {
        app.MapGet("/v1/permissions/keys/{permissionKey}", async (string permissionKey, HttpContext ctx, OrgAccess access, DenDbContext db, PermissionService permissions) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            // As in the reference, the permission check comes before the path is validated.
            if (access.Require(context!, "permissions.view") is { } denied) return denied;
            var key = permissionKey.Trim();
            if (key.Length < 1) return MemberEndpoints.InvalidRequest("permissionKey", "Too small: expected string to have >=1 characters", "too_small");
            if (key.Length > MaxKeyLength) return MemberEndpoints.InvalidRequest("permissionKey", $"Too big: expected string to have <={MaxKeyLength} characters", "too_big");
            var definition = PermissionCatalog.All.FirstOrDefault(p => p.Key == key);
            if (definition is null) return Results.Json(new { error = "permission_not_found", message = "This permission doesn't exist." }, statusCode: 404);

            var org = context!.Organization.Id;
            var (memberSet, adminSet) = await permissions.EnsureDefaultSetsAsync(org);
            var teamSets = await db.PermissionSets.AsNoTracking().Where(s => s.OrganizationId == org && s.ArchivedAt == null && s.DefaultKey == null).OrderBy(s => s.Name).ThenBy(s => s.Id).ToListAsync();
            var sets = new List<PermissionSet> { memberSet, adminSet };
            sets.AddRange(teamSets);
            var ids = sets.Select(s => s.Id).ToList();
            var states = await permissions.ReadStatesAsync(ids);
            var links = await SetBody.LinksAsync(db, ids);

            return Results.Json(new
            {
                permission = new
                {
                    key = definition.Key,
                    area = definition.Area,
                    label = definition.Label,
                    description = definition.Description,
                    sensitive = definition.Sensitive,
                    lockedOn = definition.LockedOnAdmin ? new[] { "admin" } : [],
                    defaultOn = new[] { definition.MemberDefault ? "member" : null, definition.AdminDefault ? "admin" : null }.OfType<string>().ToArray(),
                },
                sets = sets.Select(set =>
                {
                    var active = (links.GetValueOrDefault(set.Id) ?? []).Where(l => !l.Removed).ToList();
                    var first = active.FirstOrDefault();
                    return new
                    {
                        id = set.Id,
                        name = set.Name,
                        kind = set.DefaultKey switch { "member" => "member_default", "admin" => "admin_default", _ => "team" },
                        team = first is null ? null : new { id = first.TeamId, name = first.TeamName },
                        teams = set.DefaultKey is null ? active.Select(l => new { id = l.TeamId, name = l.TeamName }).ToList() : [],
                        status = PermissionService.AllowedKeys(states.GetValueOrDefault(set.Id)).Contains(key) ? PermissionService.Allow : PermissionService.Deny,
                        locked = set.DefaultKey == "admin" && definition.LockedOnAdmin,
                    };
                }).ToList(),
            });
        });
    }
}
