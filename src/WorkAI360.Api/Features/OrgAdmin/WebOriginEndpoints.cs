using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.OrgAdmin;
using WorkAI360.Api.Endpoints;

namespace WorkAI360.Api.Features.OrgAdmin;

/// <summary>Approved web origins: exact https origins a workspace allows to embed or call it (at most 20).</summary>
public static class WebOriginEndpoints
{
    public const int Limit = 20;
    private const string InvalidMessage = "Enter an exact HTTPS origin like https://workspace.example.com, with an optional port and no path.";

    /// <summary>
    /// The canonical origin when the text is an exact https origin (a concrete host, an optional port, nothing else; one trailing slash and
    /// the default port are tolerated), otherwise null. Same rules as the reference's <c>normalizeExactHttpsOrigin</c>.
    /// </summary>
    public static string? Normalize(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.Length == 0 || trimmed.Length > 255) return null;
        if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var url)) return null;
        if (url.Scheme != "https" || string.IsNullOrEmpty(url.Host) || url.Host.Contains('*') || !string.IsNullOrEmpty(url.UserInfo)
            || !string.IsNullOrEmpty(url.Query) || !string.IsNullOrEmpty(url.Fragment) || url.AbsolutePath != "/") return null;
        var written = (trimmed.EndsWith('/') ? trimmed[..^1] : trimmed).ToLowerInvariant();
        var origin = url.GetLeftPart(UriPartial.Authority).ToLowerInvariant();
        // "https://host?" and "https://host#" parse to the same origin but were not written as one.
        var forms = new List<string> { origin };
        if (url.IsDefaultPort) forms.Add($"{origin}:443");
        if (!forms.Contains(written)) return null;
        return origin;
    }

    public static void MapWebOriginEndpoints(this WebApplication app)
    {
        app.MapGet("/v1/org/web-origins", async (HttpContext ctx, OrgAccess access, DenDbContext db) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "web_origins.view") is { } denied) return denied;
            var rows = await db.Set<OrganizationWebOrigin>().AsNoTracking().Where(o => o.OrganizationId == context!.Organization.Id).OrderBy(o => o.CreatedAt).ThenBy(o => o.Id).ToListAsync();
            return Results.Json(new { origins = rows.Select(Wire), limit = Limit });
        });

        app.MapPost("/v1/org/web-origins", async (HttpContext ctx, OrgAccess access, DenDbContext db, IAuditLog audit, WebOrigins.WebOriginApprovals approvals) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "web_origins.manage") is { } denied) return denied;
            var (root, invalid) = await Zod.ReadObjectAsync(ctx, "origin");
            if (invalid is not null) return invalid;
            var issues = new List<ZodIssue>();
            if (Zod.String(root, "origin", 1, 255, true, out var text) is { } issue) issues.Add(issue);
            if (Zod.Unrecognized(root, "origin") is { } extra) issues.Add(extra);
            if (issues.Count > 0) return Zod.Respond(issues);
            var origin = Normalize(text!);
            if (origin is null) return Results.Json(new { error = "invalid_web_origin", message = InvalidMessage }, statusCode: 400);

            var organizationId = context!.Organization.Id;
            var creator = await db.Users.AsNoTracking().Where(u => u.Id == context.Auth.User.Id).Select(u => u.Name).FirstAsync();
            var row = new OrganizationWebOrigin { Id = Ids.New("owo"), OrganizationId = organizationId, Origin = origin, CreatedByMemberId = context.Member.Id, CreatedByName = creator, CreatedAt = DateTime.UtcNow };
            // The limit and the duplicate check run inside one transaction, and a unique index backs the duplicate rule, so concurrent requests cannot exceed either.
            await using (var tx = await db.Database.BeginTransactionAsync())
            {
                await db.LockOrganizationAsync(organizationId);
                if (await db.Set<OrganizationWebOrigin>().AnyAsync(o => o.OrganizationId == organizationId && o.Origin == origin)) return AlreadyApproved();
                if (await db.Set<OrganizationWebOrigin>().CountAsync(o => o.OrganizationId == organizationId) >= Limit) return LimitReached();
                db.Set<OrganizationWebOrigin>().Add(row);
                try { await db.SaveChangesAsync(); }
                catch (DbUpdateException) { return AlreadyApproved(); }
                await tx.CommitAsync();
            }
            approvals.Invalidate(origin);
            await audit.RecordAsync(context, new AuditEntry(AuditActions.WebOriginApproved, [new("web_origin", row.Id, "target", origin), new("organization", organizationId, "parent")],
                After: new() { ["id"] = row.Id, ["origin"] = origin }));
            return Results.Json(Wire(row), statusCode: 201);
        });

        app.MapDelete("/v1/org/web-origins/{webOriginId}", async (string webOriginId, HttpContext ctx, OrgAccess access, DenDbContext db, IAuditLog audit, WebOrigins.WebOriginApprovals approvals) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "web_origins.manage") is { } denied) return denied;
            if (MemberEndpoints.ValidateTypeId(webOriginId, "owo", "webOriginId") is { } malformed) return malformed;
            var row = await db.Set<OrganizationWebOrigin>().FirstOrDefaultAsync(o => o.Id == webOriginId && o.OrganizationId == context!.Organization.Id);
            if (row is null || await db.Set<OrganizationWebOrigin>().Where(o => o.Id == row.Id).ExecuteDeleteAsync() == 0)
                return Results.Json(new { error = "web_origin_not_found", message = "This approved origin no longer exists." }, statusCode: 404);
            approvals.Invalidate(row.Origin);
            await audit.RecordAsync(context!, new AuditEntry(AuditActions.WebOriginRemoved, [new("web_origin", row.Id, "target", row.Origin), new("organization", context!.Organization.Id, "parent")],
                Before: new() { ["id"] = row.Id, ["origin"] = row.Origin }));
            return Results.NoContent();
        });
    }

    private static object Wire(OrganizationWebOrigin o) => new { id = o.Id, origin = o.Origin, createdAt = Responses.IsoUtc(o.CreatedAt), createdByName = o.CreatedByName };

    private static IResult AlreadyApproved() => Results.Json(new { error = "web_origin_already_approved", message = "This origin is already approved." }, statusCode: 409);

    private static IResult LimitReached() => Results.Json(new { error = "web_origin_limit_reached", message = $"This organization already has {Limit} approved web origins. Remove one before adding another." }, statusCode: 409);
}
