using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;

namespace WorkAI360.Api.Endpoints;

public sealed record CreateOrgBody(string? Name);

public static class OrgEndpoints
{
    public const string OrgHeader = "x-openwork-org-id";

    public static async Task<Organization?> ResolveMemberOrganizationAsync(DenDbContext db, string userId, string? organizationId, string? organizationSlug)
    {
        if (string.IsNullOrWhiteSpace(organizationId) && string.IsNullOrWhiteSpace(organizationSlug)) return null;
        var query = from m in db.Members
                    join o in db.Organizations on m.OrganizationId equals o.Id
                    where m.UserId == userId
                    select o;
        if (!string.IsNullOrWhiteSpace(organizationId)) query = query.Where(o => o.Id == organizationId);
        else query = query.Where(o => o.Slug == organizationSlug);
        return await query.FirstOrDefaultAsync();
    }

    public static async Task SetActiveAsync(DenDbContext db, Session session, string organizationId)
    {
        session.ActiveOrganizationId = organizationId;
        session.UpdatedAt = DateTime.UtcNow;
        db.Sessions.Update(session);
        await db.SaveChangesAsync();
    }

    public static void MapOrgEndpoints(this WebApplication app)
    {
        var v1 = app.MapGroup("/v1");

        v1.MapGet("/me", async (HttpContext ctx, SessionService sessions) =>
        {
            var current = await sessions.ResolveAsync(ctx);
            if (current is null) return Responses.Unauthorized();
            var user = (IDictionary<string, object?>)ToDictionary(Responses.UserJson(current.User));
            user["authProviders"] = new[] { "email" };
            return Results.Json(new { user, session = Responses.SessionJson(current.Session, current.PresentedToken) });
        });

        v1.MapGet("/me/orgs", async (HttpContext ctx, SessionService sessions, DenDbContext db) =>
        {
            var current = await sessions.ResolveAsync(ctx);
            if (current is null) return Responses.Unauthorized();

            var rows = await (from m in db.Members
                              join o in db.Organizations on m.OrganizationId equals o.Id
                              where m.UserId == current.User.Id
                              orderby m.CreatedAt
                              select new { Org = o, m.Role }).ToListAsync();
            var activeId = current.Session.ActiveOrganizationId;
            var active = rows.FirstOrDefault(r => r.Org.Id == activeId)?.Org;
            return Results.Json(new
            {
                orgs = rows.Select(r => new
                {
                    id = r.Org.Id,
                    name = r.Org.Name,
                    slug = r.Org.Slug,
                    logo = (string?)null,
                    role = r.Role,
                    directRole = r.Role,
                    isActive = r.Org.Id == activeId,
                }),
                activeOrgId = active?.Id,
                activeOrgSlug = active?.Slug,
            });
        });

        v1.MapPost("/me/active-organization", async (SetActiveBody? body, HttpContext ctx, SessionService sessions, DenDbContext db) =>
        {
            var current = await sessions.ResolveAsync(ctx);
            if (current is null) return Responses.Unauthorized();
            var org = await ResolveMemberOrganizationAsync(db, current.User.Id, body?.OrganizationId, body?.OrganizationSlug);
            if (org is null) return Responses.Error(403, "forbidden", "You are not a member of this organization.");
            await SetActiveAsync(db, current.Session, org.Id);
            return Results.Json(new { ok = true, organizationId = org.Id, organizationSlug = org.Slug });
        });

        v1.MapPost("/org", async (CreateOrgBody? body, HttpContext ctx, SessionService sessions, DenDbContext db) =>
        {
            var current = await sessions.ResolveAsync(ctx);
            if (current is null) return Responses.Unauthorized();
            var name = body?.Name?.Trim() ?? "";
            if (name.Length < 2 || name.Length > 80) return Responses.Error(400, "invalid_request", "Workspace name must be 2 to 80 characters.");

            var now = DateTime.UtcNow;
            var id = Ids.New("org");
            var org = new Organization { Id = id, Name = name, Slug = id, CreatedAt = now };
            db.Organizations.Add(org);
            db.Members.Add(new Member { Id = Ids.New("mem"), OrganizationId = id, UserId = current.User.Id, Role = "owner", CreatedAt = now });
            await db.SaveChangesAsync();
            await SetActiveAsync(db, current.Session, id);
            return Results.Json(new { organization = Responses.OrganizationJson(org) }, statusCode: StatusCodes.Status201Created);
        });

        v1.MapGet("/org", async (HttpContext ctx, SessionService sessions, DenDbContext db) =>
        {
            var current = await sessions.ResolveAsync(ctx);
            if (current is null) return Responses.Unauthorized();

            var requested = ctx.Request.Headers[OrgHeader].ToString();
            var orgId = string.IsNullOrWhiteSpace(requested) ? current.Session.ActiveOrganizationId : requested.Trim();
            if (orgId is null) return Responses.Error(404, "not_found", "No active organization.");

            var member = await db.Members.FirstOrDefaultAsync(m => m.OrganizationId == orgId && m.UserId == current.User.Id);
            if (member is null) return Responses.Error(403, "forbidden", "You are not a member of this organization.");
            var org = await db.Organizations.FirstAsync(o => o.Id == orgId);

            var members = await (from m in db.Members
                                 join u in db.Users on m.UserId equals u.Id
                                 where m.OrganizationId == orgId
                                 orderby m.CreatedAt
                                 select new { id = m.Id, userId = u.Id, role = m.Role, name = u.Name, email = u.Email }).ToListAsync();
            return Results.Json(new
            {
                organization = Responses.OrganizationJson(org),
                currentMember = new { id = member.Id, userId = member.UserId, role = member.Role },
                members,
                invitations = Array.Empty<object>(),
                teams = Array.Empty<object>(),
                plan = "free",
            });
        });
    }

    private static Dictionary<string, object?> ToDictionary(object value) =>
        System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, System.Text.Json.JsonElement>>(System.Text.Json.JsonSerializer.Serialize(value))!
            .ToDictionary(kv => kv.Key, kv => (object?)kv.Value);
}
