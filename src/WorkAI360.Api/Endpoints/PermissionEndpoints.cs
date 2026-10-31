using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;

namespace WorkAI360.Api.Endpoints;

/// <summary>
/// Permission sets (the Member and Admin defaults, and a role per team), what each person ends up holding, and the history of every change.
/// Reading needs permissions.view and changing needs permissions.manage, which only the owner holds by default.
/// </summary>
public static class PermissionEndpoints
{
    private const int MaxChanges = 500;
    private const int DefaultHistory = 50;
    private const int MaxHistory = 200;

    private sealed record Change(string Key, string Status);

    public static void MapPermissionEndpoints(this WebApplication app)
    {
        app.MapGet("/v1/permissions/catalog", async (HttpContext ctx, OrgAccess access) =>
        {
            var (_, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            return Results.Json(new
            {
                areas = PermissionCatalog.Areas.Select(a => new { key = a.Key, label = a.Label }),
                permissions = PermissionCatalog.All.Select(p => new
                {
                    key = p.Key,
                    area = p.Area,
                    label = p.Label,
                    description = p.Description,
                    sensitive = p.Sensitive,
                    lockedOn = p.LockedOnAdmin ? new[] { "admin" } : [],
                    defaultOn = new[] { p.MemberDefault ? "member" : null, p.AdminDefault ? "admin" : null }.OfType<string>().ToArray(),
                }),
            });
        });

        app.MapGet("/v1/permissions/sets", async (HttpContext ctx, OrgAccess access, DenDbContext db, PermissionService permissions) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "permissions.view") is { } denied) return denied;
            var org = context!.Organization.Id;
            var (memberSet, adminSet) = await permissions.EnsureDefaultSetsAsync(org);
            var sets = await db.PermissionSets.AsNoTracking().Where(s => s.OrganizationId == org && s.ArchivedAt == null && s.DefaultKey == null).OrderBy(s => s.Name).ThenBy(s => s.Id).ToListAsync();
            var ordered = new List<PermissionSet> { memberSet, adminSet };
            ordered.AddRange(sets);
            var ids = ordered.Select(s => s.Id).ToList();
            var states = await permissions.ReadStatesAsync(ids);
            var links = await SetBody.LinksAsync(db, ids);
            var people = await SetBody.PeopleAsync(db, org);
            return Results.Json(new { sets = ordered.Select(s => SetBody.Summary(s, states[s.Id], links.GetValueOrDefault(s.Id) ?? [], people)).ToList() });
        });

        app.MapGet("/v1/permissions/sets/{permissionSetId}", async (string permissionSetId, HttpContext ctx, OrgAccess access, DenDbContext db, PermissionService permissions) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "permissions.view") is { } denied) return denied;
            if (MemberEndpoints.ValidateTypeId(permissionSetId, "pms", "permissionSetId") is { } malformed) return malformed;
            await permissions.EnsureDefaultSetsAsync(context!.Organization.Id);
            var set = await db.PermissionSets.AsNoTracking().FirstOrDefaultAsync(s => s.Id == permissionSetId && s.OrganizationId == context.Organization.Id);
            if (set is null) return SetNotFound();
            return Results.Json(new { set = await SetBody.DetailAsync(db, permissions, context, set) });
        });

        app.MapPost("/v1/permissions/sets", async (HttpContext ctx, OrgAccess access, DenDbContext db, PermissionService permissions) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "permissions.manage") is { } denied) return denied;
            JsonElement body;
            try { using var doc = await JsonDocument.ParseAsync(ctx.Request.Body); body = doc.RootElement.Clone(); }
            catch (JsonException) { return MemberEndpoints.InvalidRequest("permissions", "Invalid input: expected array, received undefined"); }
            if (body.ValueKind != JsonValueKind.Object) return MemberEndpoints.InvalidRequest("permissions", "Invalid input: expected array, received undefined");

            var (permissionsRequested, bad) = ReadChanges(body, "permissions", min: 0);
            if (bad is not null) return bad;
            string? teamId = null, name = null;
            List<string>? teamIds = null;
            if (body.TryGetProperty("teamId", out var t) && t.ValueKind != JsonValueKind.Null)
            {
                if (t.ValueKind != JsonValueKind.String) return MemberEndpoints.InvalidRequest("teamId", "Invalid input: expected string");
                if (MemberEndpoints.ValidateTypeId(teamId = t.GetString()!, "tem", "teamId") is { } m1) return m1;
            }
            if (body.TryGetProperty("name", out var n) && n.ValueKind != JsonValueKind.Null)
            {
                if (n.ValueKind != JsonValueKind.String) return MemberEndpoints.InvalidRequest("name", "Invalid input: expected string");
                name = n.GetString()!.Trim();
                if (name.Length is < 1 or > 120) return MemberEndpoints.InvalidRequest("name", "Invalid string: must contain between 1 and 120 character(s)", "too_small");
            }
            if (body.TryGetProperty("teamIds", out var ti) && ti.ValueKind != JsonValueKind.Null)
            {
                if (ti.ValueKind != JsonValueKind.Array || ti.GetArrayLength() > 100) return MemberEndpoints.InvalidRequest("teamIds", "Invalid input: expected an array of at most 100 team ids");
                teamIds = [];
                foreach (var item in ti.EnumerateArray())
                {
                    if (item.ValueKind != JsonValueKind.String) return MemberEndpoints.InvalidRequest("teamIds", "Invalid input: expected string");
                    if (MemberEndpoints.ValidateTypeId(item.GetString()!, "tem", "teamIds") is { } m2) return m2;
                    teamIds.Add(item.GetString()!);
                }
                teamIds = teamIds.Distinct().ToList();
            }

            var plan = PermissionEdits.PlanCreate(permissionsRequested!, context!.Permissions);
            if (!plan.Ok) return Problem(plan.Problem!);

            var org = context.Organization.Id;
            await permissions.EnsureDefaultSetsAsync(org);
            await using var tx = await db.Database.BeginTransactionAsync();
            var now = DateTime.UtcNow;
            PermissionSet set;
            if (teamId is not null)
            {
                if (name is not null || teamIds is not null) return MemberEndpoints.InvalidRequest("teamId", "Send either teamId, or a name and teamIds.", "custom");
                var team = await db.Teams.FirstOrDefaultAsync(x => x.Id == teamId && x.OrganizationId == org);
                if (team is null) return Results.Json(new { error = "team_not_found", message = "This team doesn't exist in your organization." }, statusCode: 404);
                var existing = await (from l in db.PermissionSetTeams join s in db.PermissionSets on l.PermissionSetId equals s.Id
                                      where l.TeamId == team.Id && l.RemovedAt == null && s.ArchivedAt == null select s.Id).FirstOrDefaultAsync();
                if (existing is not null) return Results.Json(new { error = "team_permission_set_exists", message = "This team already has permissions. Edit them instead.", permissionSetId = existing }, statusCode: 409);
                set = NewSet(org, PermissionEdits.TeamSetName(team.Name), context.Member.Id, now);
                db.PermissionSets.Add(set);
                db.PermissionSetTeams.Add(new PermissionSetTeam { Id = Ids.New("pst"), PermissionSetId = set.Id, TeamId = team.Id, CreatedAt = now });
            }
            else
            {
                // A named role, given to zero or more teams now.
                if (name is null) return Results.Json(new { error = "invalid_request", message = "Name the role.", details = Array.Empty<object>() }, statusCode: 400);
                var ids = teamIds ?? [];
                if (ids.Count > 0 && await db.Teams.CountAsync(x => x.OrganizationId == org && ids.Contains(x.Id)) != ids.Count)
                    return Results.Json(new { error = "team_not_found", message = "One of these teams doesn't exist in your organization." }, statusCode: 404);
                set = NewSet(org, name, context.Member.Id, now);
                db.PermissionSets.Add(set);
                await AssignTeamsAsync(db, set.Id, ids, now);
            }
            try { await db.SaveChangesAsync(); }
            catch (DbUpdateException) when (teamId is not null)
            {
                // Someone else gave this team its role first.
                db.ChangeTracker.Clear();
                var winner = await (from l in db.PermissionSetTeams.AsNoTracking() join s in db.PermissionSets.AsNoTracking() on l.PermissionSetId equals s.Id
                                    where l.TeamId == teamId && l.RemovedAt == null && s.ArchivedAt == null select s.Id).FirstOrDefaultAsync();
                return Results.Json(new { error = "team_permission_set_exists", message = "This team already has permissions. Edit them instead.", permissionSetId = winner }, statusCode: 409);
            }
            await permissions.AddRowsAsync(set.Id, plan.Changes, "user", context.Member.Id);
            await db.SaveChangesAsync();
            await tx.CommitAsync();
            return Results.Json(new { set = await SetBody.DetailAsync(db, permissions, context, set) }, statusCode: 201);
        });

        app.MapPut("/v1/permissions/sets/{permissionSetId}/permissions", async (string permissionSetId, HttpContext ctx, OrgAccess access, DenDbContext db, PermissionService permissions) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "permissions.manage") is { } denied) return denied;
            if (MemberEndpoints.ValidateTypeId(permissionSetId, "pms", "permissionSetId") is { } malformed) return malformed;
            JsonElement body;
            try { using var doc = await JsonDocument.ParseAsync(ctx.Request.Body); body = doc.RootElement.Clone(); }
            catch (JsonException) { return MemberEndpoints.InvalidRequest("changes", "Invalid input: expected array, received undefined"); }
            if (body.ValueKind != JsonValueKind.Object) return MemberEndpoints.InvalidRequest("changes", "Invalid input: expected array, received undefined");
            var (requested, bad) = ReadChanges(body, "changes", min: 1);
            if (bad is not null) return bad;

            var org = context!.Organization.Id;
            await permissions.EnsureDefaultSetsAsync(org);
            await using var tx = await db.Database.BeginTransactionAsync();
            var set = await db.PermissionSets.FirstOrDefaultAsync(s => s.Id == permissionSetId && s.OrganizationId == org);
            if (set is null) return SetNotFound();
            if (set.ArchivedAt is not null) return Results.Json(new { error = "permission_set_archived", message = "This permission set was deleted and can't be changed." }, statusCode: 409);

            var current = (await permissions.ReadStatesAsync([set.Id]))[set.Id];
            var plan = PermissionEdits.PlanEdit(set.DefaultKey, current, requested!, context.Permissions);
            if (!plan.Ok) return Problem(plan.Problem!);
            if (plan.Changes.Count > 0)
            {
                await permissions.AddRowsAsync(set.Id, plan.Changes, "user", context.Member.Id);
                await db.SaveChangesAsync();
            }
            await tx.CommitAsync();
            return Results.Json(new { set = await SetBody.DetailAsync(db, permissions, context, set) });
        });

        app.MapPatch("/v1/permissions/sets/{permissionSetId}", async (string permissionSetId, HttpContext ctx, OrgAccess access, DenDbContext db, PermissionService permissions) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "permissions.manage") is { } denied) return denied;
            if (MemberEndpoints.ValidateTypeId(permissionSetId, "pms", "permissionSetId") is { } malformed) return malformed;
            string? name = null;
            try
            {
                using var doc = await JsonDocument.ParseAsync(ctx.Request.Body);
                if (doc.RootElement.ValueKind == JsonValueKind.Object && doc.RootElement.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String) name = n.GetString()!.Trim();
            }
            catch (JsonException) { }
            if (name is null) return MemberEndpoints.InvalidRequest("name", "Invalid input: expected string, received undefined");
            if (name.Length is < 1 or > 120) return MemberEndpoints.InvalidRequest("name", "Invalid string: must contain between 1 and 120 character(s)", "too_small");

            await permissions.EnsureDefaultSetsAsync(context!.Organization.Id);
            var set = await db.PermissionSets.FirstOrDefaultAsync(s => s.Id == permissionSetId && s.OrganizationId == context.Organization.Id);
            if (set is null) return SetNotFound();
            if (set.DefaultKey is not null) return Results.Json(new { error = "default_permission_set", message = "Member and Admin keep their names." }, statusCode: 400);
            if (set.ArchivedAt is not null) return Results.Json(new { error = "permission_set_archived", message = "This role was deleted and can't be changed." }, statusCode: 409);
            if (set.Name != name) { set.Name = name; await db.SaveChangesAsync(); }
            return Results.Json(new { set = await SetBody.DetailAsync(db, permissions, context, set) });
        });

        app.MapDelete("/v1/permissions/sets/{permissionSetId}", async (string permissionSetId, HttpContext ctx, OrgAccess access, DenDbContext db, PermissionService permissions) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "permissions.manage") is { } denied) return denied;
            if (MemberEndpoints.ValidateTypeId(permissionSetId, "pms", "permissionSetId") is { } malformed) return malformed;
            await permissions.EnsureDefaultSetsAsync(context!.Organization.Id);
            var set = await db.PermissionSets.FirstOrDefaultAsync(s => s.Id == permissionSetId && s.OrganizationId == context.Organization.Id);
            if (set is null) return SetNotFound();
            if (set.DefaultKey is not null) return Results.Json(new { error = "default_permission_set", message = "Member and Admin permissions can't be deleted. Turn permissions off instead." }, statusCode: 400);
            if (set.ArchivedAt is not null) return Results.Json(new { error = "permission_set_archived", message = "This permission set was already deleted." }, statusCode: 409);

            // The set and its history are kept; it just stops applying to anyone.
            var now = DateTime.UtcNow;
            foreach (var link in await db.PermissionSetTeams.Where(l => l.PermissionSetId == set.Id && l.RemovedAt == null).ToListAsync()) link.RemovedAt = now;
            set.ArchivedAt = now;
            await db.SaveChangesAsync();
            return Results.NoContent();
        });

        app.MapPut("/v1/teams/{teamId}/permission-set", async (string teamId, HttpContext ctx, OrgAccess access, DenDbContext db, PermissionService permissions) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "permissions.manage") is { } denied) return denied;
            if (MemberEndpoints.ValidateTypeId(teamId, "tem", "teamId") is { } malformed) return malformed;
            string? setId = null;
            try
            {
                using var doc = await JsonDocument.ParseAsync(ctx.Request.Body);
                if (doc.RootElement.ValueKind != JsonValueKind.Object || !doc.RootElement.TryGetProperty("permissionSetId", out var p)) return MemberEndpoints.InvalidRequest("permissionSetId", "Invalid input: expected string, received undefined");
                if (p.ValueKind == JsonValueKind.String) setId = p.GetString();
                else if (p.ValueKind != JsonValueKind.Null) return MemberEndpoints.InvalidRequest("permissionSetId", "Invalid input: expected string");
            }
            catch (JsonException) { return MemberEndpoints.InvalidRequest("permissionSetId", "Invalid input: expected string, received undefined"); }
            if (setId is not null && MemberEndpoints.ValidateTypeId(setId, "pms", "permissionSetId") is { } badSet) return badSet;

            var org = context!.Organization.Id;
            // Two people giving the same team different roles at once race on the one-active-role rule; the loser (or a database deadlock) simply
            // tries again against what the winner left, so the last request wins and nobody sees an error.
            for (var attempt = 1; ; attempt++)
            {
                try { return await ChangeTeamRoleAsync(); }
                catch (DbUpdateException) when (attempt < 6)
                {
                    db.ChangeTracker.Clear();
                    await Task.Delay(15 * attempt);
                }
            }

            async Task<IResult> ChangeTeamRoleAsync()
            {
                await using var tx = await db.Database.BeginTransactionAsync();
                var team = await db.Teams.FirstOrDefaultAsync(t => t.Id == teamId && t.OrganizationId == org);
                if (team is null) return Results.Json(new { error = "team_not_found", message = "This team doesn't exist in your organization." }, statusCode: 404);
                PermissionSet? set = null;
                if (setId is not null)
                {
                    await permissions.EnsureDefaultSetsAsync(org);
                    set = await db.PermissionSets.FirstOrDefaultAsync(s => s.Id == setId && s.OrganizationId == org);
                    if (set is null) return SetNotFound();
                    if (set.DefaultKey is not null) return Results.Json(new { error = "default_permission_set", message = "Member and Admin aren't custom roles. Make the team an Admin team instead." }, statusCode: 400);
                    if (set.ArchivedAt is not null) return Results.Json(new { error = "permission_set_archived", message = "This role was deleted." }, statusCode: 409);
                    // Giving a role grants its permissions to everyone in the team, so the editor must hold them all.
                    var missing = (PermissionService.AllowedKeys((await permissions.ReadStatesAsync([set.Id]))[set.Id])).Where(k => !context.Permissions.Has(k)).Order(StringComparer.Ordinal).ToList();
                    if (missing.Count > 0) return Problem(new EditProblem("permission_not_held", missing));
                }
                await AssignTeamsAsync(db, set?.Id, [team.Id], DateTime.UtcNow);
                await db.SaveChangesAsync();
                await tx.CommitAsync();
                return Results.Json(new { set = set is null ? null : await SetBody.DetailAsync(db, permissions, context, set) });
            }
        });

        app.MapGet("/v1/permissions/sets/{permissionSetId}/history", async (string permissionSetId, HttpContext ctx, OrgAccess access, DenDbContext db) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "permissions.view") is { } denied) return denied;
            if (MemberEndpoints.ValidateTypeId(permissionSetId, "pms", "permissionSetId") is { } malformed) return malformed;
            if (!await db.PermissionSets.AnyAsync(s => s.Id == permissionSetId && s.OrganizationId == context!.Organization.Id)) return SetNotFound();

            var limit = DefaultHistory;
            if (ctx.Request.Query.TryGetValue("limit", out var l))
            {
                if (!int.TryParse(l.ToString(), out limit) || limit is < 1 or > MaxHistory) return MemberEndpoints.InvalidRequest("limit", $"Invalid input: expected an integer between 1 and {MaxHistory}", "too_big");
            }
            var rows = await db.PermissionSetPermissions.AsNoTracking().Where(r => r.PermissionSetId == permissionSetId).ToListAsync();
            var ordered = rows.OrderByDescending(r => r.CreatedAt).ThenByDescending(r => r.Id, StringComparer.Ordinal).AsEnumerable();
            if (ctx.Request.Query.TryGetValue("cursor", out var c) && c.ToString().Length > 0)
            {
                var cursor = ReadCursor(c.ToString());
                if (cursor is null) return MemberEndpoints.InvalidRequest("cursor", "Invalid cursor", "custom");
                ordered = ordered.Where(r => r.CreatedAt < cursor.Value.At || (r.CreatedAt == cursor.Value.At && string.CompareOrdinal(r.Id, cursor.Value.Id) < 0));
            }
            var page = ordered.Take(limit + 1).ToList();
            var items = page.Take(limit).ToList();
            var includeEmail = context!.Permissions.Has("teams.view");
            var who = await SetBody.PeopleByMemberAsync(db, items.Select(i => i.ChangedByMemberId).OfType<string>().Distinct().ToList());
            return Results.Json(new
            {
                items = items.Select(r => new
                {
                    id = r.Id,
                    key = r.PermissionKey,
                    label = PermissionCatalog.All.FirstOrDefault(p => p.Key == r.PermissionKey)?.Label,
                    status = r.Status,
                    source = r.Source,
                    changedBy = SetBody.ChangedBy(r.ChangedByMemberId, who, includeEmail),
                    createdAt = Responses.IsoUtc(r.CreatedAt),
                }),
                nextCursor = page.Count > limit ? WriteCursor(items[^1]) : null,
            });
        });

        app.MapGet("/v1/members/{memberId}/permissions", async (string memberId, HttpContext ctx, OrgAccess access, DenDbContext db, PermissionService permissions) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (MemberEndpoints.ValidateTypeId(memberId, "om", "memberId") is { } malformed) return malformed;
            // Anyone may see their own; seeing someone else's needs permissions.view.
            if (memberId != context!.Member.Id && !context.Permissions.Has("permissions.view")) return access.Denied(Permissions.Definition("permissions.view"));
            var member = await db.Members.AsNoTracking().FirstOrDefaultAsync(m => m.Id == memberId && m.OrganizationId == context.Organization.Id);
            if (member is null) return Results.Json(new { error = "member_not_found" }, statusCode: 404);
            var held = memberId == context.Member.Id ? context.Permissions : await permissions.ResolveAsync(context.Organization.Id, member);
            return Results.Json(new
            {
                memberId,
                featureEnabled = true,
                isOwner = held.IsOwner,
                isAdmin = held.IsAdmin,
                permissions = held.Explain().Select(e => new
                {
                    key = e.Key,
                    label = Permissions.Definition(e.Key).Label,
                    sources = e.Sources.Select(SourceBody).ToList(),
                }).ToList(),
            });
        });
    }

    private static Dictionary<string, object?> SourceBody(PermissionSource s)
    {
        var body = new Dictionary<string, object?> { ["kind"] = s.Kind };
        if (s.SetId is not null) { body["setId"] = s.SetId; body["setName"] = s.SetName; }
        if (s.Via is not null) body["via"] = s.Via;
        if (s.TeamId is not null) { body["teamId"] = s.TeamId; body["teamName"] = s.TeamName; }
        body["label"] = s.Label;
        return body;
    }

    private static PermissionSet NewSet(string organizationId, string name, string createdBy, DateTime now) =>
        new() { Id = Ids.New("pms"), OrganizationId = organizationId, Name = name, CreatedByMemberId = createdBy, CreatedAt = now };

    private static IResult SetNotFound() => Results.Json(new { error = "permission_set_not_found" }, statusCode: 404);

    private static IResult Problem(EditProblem problem) =>
        Results.Json(new { error = problem.Error, message = problem.Message, keys = problem.Keys }, statusCode: problem.StatusCode);

    /// <summary>Gives each team this role (or none), replacing the one it had. A team has at most one active role.</summary>
    private static async Task AssignTeamsAsync(DenDbContext db, string? setId, IReadOnlyCollection<string> teamIds, DateTime now)
    {
        var order = 0;
        foreach (var teamId in teamIds)
        {
            // Strictly increasing stamps keep "the first team" the first one named, even when several are linked in the same instant.
            var stamp = now.AddTicks(order++);
            var links = await db.PermissionSetTeams.Where(l => l.TeamId == teamId).ToListAsync();
            var replaced = links.Where(l => l.RemovedAt == null && l.PermissionSetId != setId).ToList();
            foreach (var active in replaced) active.RemovedAt = now;
            // The old link is closed before the new one opens, so the one-active-role-per-team rule is never broken in between.
            if (replaced.Count > 0) await db.SaveChangesAsync();
            if (setId is null || links.Any(l => l.RemovedAt == null && l.PermissionSetId == setId)) continue;
            var earlier = links.FirstOrDefault(l => l.PermissionSetId == setId);
            if (earlier is not null) earlier.RemovedAt = null;
            else db.PermissionSetTeams.Add(new PermissionSetTeam { Id = Ids.New("pst"), PermissionSetId = setId, TeamId = teamId, CreatedAt = stamp });
        }
    }

    private static (List<(string Key, string Status)>? Changes, IResult? Invalid) ReadChanges(JsonElement body, string field, int min)
    {
        if (!body.TryGetProperty(field, out var array) || array.ValueKind != JsonValueKind.Array)
            return (null, MemberEndpoints.InvalidRequest(field, $"Invalid input: expected array, received {(body.TryGetProperty(field, out var x) ? x.ValueKind.ToString().ToLowerInvariant() : "undefined")}"));
        var list = new List<(string, string)>();
        foreach (var item in array.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object || !item.TryGetProperty("key", out var key) || key.ValueKind != JsonValueKind.String)
                return (null, MemberEndpoints.InvalidRequest(field, "Invalid input: expected string, received undefined"));
            var k = key.GetString()!.Trim();
            if (k.Length is < 1 or > 128) return (null, MemberEndpoints.InvalidRequest(field, "Invalid string: must contain between 1 and 128 character(s)", "too_small"));
            if (!item.TryGetProperty("status", out var status) || status.ValueKind != JsonValueKind.String || status.GetString() is not (PermissionService.Allow or PermissionService.Deny))
                return (null, MemberEndpoints.InvalidRequest(field, "Invalid option: expected one of \"allow\"|\"deny\"", "invalid_value"));
            list.Add((k, status.GetString()!));
        }
        if (list.Count < min) return (null, MemberEndpoints.InvalidRequest(field, "Too small: expected array to have >=1 items", "too_small"));
        if (list.Count > MaxChanges) return (null, MemberEndpoints.InvalidRequest(field, $"Too big: expected array to have <={MaxChanges} items", "too_big"));
        return (list, null);
    }

    private static string WriteCursor(PermissionSetPermission r) => Convert.ToBase64String(Encoding.UTF8.GetBytes($"{r.CreatedAt.Ticks}|{r.Id}")).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static (DateTime At, string Id)? ReadCursor(string value)
    {
        try
        {
            var padded = value.Replace('-', '+').Replace('_', '/');
            padded = padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '=');
            var parts = Encoding.UTF8.GetString(Convert.FromBase64String(padded)).Split('|');
            return parts.Length == 2 && long.TryParse(parts[0], out var ticks) ? (new DateTime(ticks, DateTimeKind.Utc), parts[1]) : null;
        }
        catch (FormatException) { return null; }
    }
}

/// <summary>How a permission set is shown: a short form for lists and a full one with every key and who it applies to.</summary>
public static class SetBody
{
    public sealed record Link(string TeamId, string? TeamName, DateTime CreatedAt, bool Removed);
    public sealed record Person(string MemberId, string Name, string Email, string Role);

    public static async Task<Dictionary<string, List<Link>>> LinksAsync(DenDbContext db, IReadOnlyCollection<string> setIds)
    {
        var rows = await (from l in db.PermissionSetTeams.AsNoTracking()
                          join t in db.Teams.AsNoTracking() on l.TeamId equals t.Id into teams
                          from t in teams.DefaultIfEmpty()
                          where setIds.Contains(l.PermissionSetId)
                          orderby l.CreatedAt, l.Id
                          select new { l.PermissionSetId, l.TeamId, TeamName = t == null ? null : t.Name, l.CreatedAt, Removed = l.RemovedAt != null }).ToListAsync();
        return rows.GroupBy(r => r.PermissionSetId).ToDictionary(g => g.Key, g => g.Select(r => new Link(r.TeamId, r.TeamName, r.CreatedAt, r.Removed)).ToList());
    }

    /// <summary>Everyone who has joined the workspace (pending invitations are not people yet), with their team memberships.</summary>
    public sealed class People(List<Person> everyone, List<TeamMember> memberships, List<Team> teams)
    {
        public List<Person> Everyone => everyone;
        public List<Team> Teams => teams;
        public int InTeams(IEnumerable<string> teamIds) => PeopleInTeams(teamIds).Count;
        public List<Person> PeopleInTeams(IEnumerable<string> teamIds)
        {
            var wanted = teamIds.ToHashSet();
            var ids = memberships.Where(m => wanted.Contains(m.TeamId)).Select(m => m.MemberId).ToHashSet();
            return everyone.Where(p => ids.Contains(p.MemberId)).OrderBy(p => p.Name, StringComparer.Ordinal).ThenBy(p => p.MemberId, StringComparer.Ordinal).ToList();
        }
        public int TeamSize(string teamId) => memberships.Count(m => m.TeamId == teamId);
    }

    public static async Task<People> PeopleAsync(DenDbContext db, string organizationId)
    {
        var everyone = await (from m in db.Members.AsNoTracking() join u in db.Users.AsNoTracking() on m.UserId equals u.Id
                              where m.OrganizationId == organizationId select new Person(m.Id, u.Name, u.Email, m.Role)).ToListAsync();
        var teams = await db.Teams.AsNoTracking().Where(t => t.OrganizationId == organizationId).ToListAsync();
        var ids = teams.Select(t => t.Id).ToList();
        var memberships = await db.TeamMembers.AsNoTracking().Where(tm => ids.Contains(tm.TeamId)).ToListAsync();
        return new People(everyone, memberships, teams);
    }

    public static async Task<Dictionary<string, (string Name, string Email)>> PeopleByMemberAsync(DenDbContext db, List<string> memberIds)
    {
        var rows = await (from m in db.Members.AsNoTracking() join u in db.Users.AsNoTracking() on m.UserId equals u.Id where memberIds.Contains(m.Id) select new { m.Id, u.Name, u.Email }).ToListAsync();
        return rows.ToDictionary(r => r.Id, r => (r.Name, r.Email));
    }

    public static object? ChangedBy(string? memberId, Dictionary<string, (string Name, string Email)> who, bool includeEmail)
    {
        if (memberId is null) return null;
        who.TryGetValue(memberId, out var person);
        return new { memberId, name = person.Name, email = includeEmail ? person.Email : null };
    }

    private static List<Link> ActiveLinks(IReadOnlyList<Link> links) => links.Where(l => !l.Removed).ToList();

    /// <summary>The first team the set applies to; for a deleted role, the team it last applied to.</summary>
    private static object? FirstTeam(PermissionSet set, IReadOnlyList<Link> links)
    {
        var chosen = set.ArchivedAt is null ? ActiveLinks(links).FirstOrDefault() : links.LastOrDefault();
        return chosen is null ? null : new { id = chosen.TeamId, name = chosen.TeamName };
    }

    private static string Kind(PermissionSet s) => s.DefaultKey switch { "member" => "member_default", "admin" => "admin_default", _ => "team" };

    public static object Summary(PermissionSet set, IReadOnlyDictionary<string, KeyState> states, IReadOnlyList<Link> links, People people)
    {
        var teams = set.ArchivedAt is null ? ActiveLinks(links) : [];
        return new
        {
            id = set.Id,
            name = set.Name,
            kind = Kind(set),
            team = FirstTeam(set, links),
            teams = teams.Select(l => new { id = l.TeamId, name = l.TeamName }).ToList(),
            allowedCount = PermissionService.AllowedKeys(states).Count,
            createdAt = Responses.IsoUtc(set.CreatedAt),
            appliesTo = set.DefaultKey switch
            {
                "member" => (object)new { kind = "everyone", memberCount = people.Everyone.Count },
                "admin" => new { kind = "admins", directAdminCount = people.Everyone.Count(p => p.Role == Roles.Admin), adminTeams = AdminTeams(people) },
                _ => new { kind = "team", team = FirstTeam(set, links), teams = teams.Select(l => new { id = l.TeamId, name = l.TeamName }).ToList(), memberCount = people.InTeams(teams.Select(l => l.TeamId)) },
            },
        };
    }

    private static List<object> AdminTeams(People people) =>
        people.Teams.Where(t => t.GrantsOrganizationAdmin).OrderBy(t => t.Name, StringComparer.Ordinal).Select(t => (object)new { id = t.Id, name = t.Name, memberCount = people.TeamSize(t.Id) }).ToList();

    public static async Task<object> DetailAsync(DenDbContext db, PermissionService service, OrgContext context, PermissionSet set)
    {
        var states = (await service.ReadStatesAsync([set.Id]))[set.Id];
        var links = (await LinksAsync(db, [set.Id])).GetValueOrDefault(set.Id) ?? [];
        var people = await PeopleAsync(db, context.Organization.Id);
        var includeIdentities = context.Permissions.Has("teams.view");
        var who = await PeopleByMemberAsync(db, states.Values.Select(s => s.Row.ChangedByMemberId).OfType<string>().Distinct().ToList());
        var activeTeamIds = set.ArchivedAt is null ? ActiveLinks(links).Select(l => l.TeamId).ToList() : [];

        object appliesTo = set.DefaultKey switch
        {
            "member" => new { kind = "everyone", memberCount = people.Everyone.Count },
            "admin" => new
            {
                kind = "admins",
                directAdminCount = people.Everyone.Count(p => p.Role == Roles.Admin),
                directAdmins = includeIdentities ? people.Everyone.Where(p => p.Role == Roles.Admin).OrderBy(p => p.Name, StringComparer.Ordinal).Select(p => new { memberId = p.MemberId, name = p.Name, email = p.Email }).ToList() : null,
                adminTeams = AdminTeams(people),
            },
            _ => new
            {
                kind = "team",
                team = FirstTeam(set, links),
                teams = activeTeamIds.Select(id => new { id, name = links.First(l => l.TeamId == id).TeamName }).ToList(),
                memberCount = people.InTeams(activeTeamIds),
                members = includeIdentities ? people.PeopleInTeams(activeTeamIds).Select(p => new { memberId = p.MemberId, name = p.Name, email = p.Email }).ToList() : null,
            },
        };

        var permissions = PermissionCatalog.All.Select(p =>
        {
            states.TryGetValue(p.Key, out var state);
            return new
            {
                key = p.Key,
                status = state?.Status == PermissionService.Allow ? PermissionService.Allow : PermissionService.Deny,
                locked = set.DefaultKey == "admin" && p.LockedOnAdmin,
                lastChangedAt = state is null ? null : Responses.IsoUtc(state.Row.CreatedAt),
                lastChangedBy = state is null ? null : ChangedBy(state.Row.ChangedByMemberId, who, includeIdentities),
                lastChangeSource = state?.Row.Source,
            };
        }).ToList();

        return new
        {
            id = set.Id,
            name = set.Name,
            kind = Kind(set),
            team = FirstTeam(set, links),
            teams = activeTeamIds.Select(id => new { id, name = links.First(l => l.TeamId == id).TeamName }).ToList(),
            allowedCount = permissions.Count(p => p.status == PermissionService.Allow),
            createdAt = Responses.IsoUtc(set.CreatedAt),
            archivedAt = set.ArchivedAt is { } a ? Responses.IsoUtc(a) : null,
            permissions,
            appliesTo,
        };
    }
}
