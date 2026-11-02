using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Features.OrgAdmin;
using WorkAI360.Api.Features.Scim;

namespace WorkAI360.Api.Endpoints;

/// <summary>The shapes teams take on the wire.</summary>
public static class TeamBody
{
    /// <summary>The short form listed in GET /v1/org.</summary>
    public static object Summary(Team team, IReadOnlyList<string> memberIds) => new
    {
        id = team.Id,
        name = team.Name,
        createdAt = Responses.IsoUtc(team.CreatedAt),
        updatedAt = Responses.IsoUtc(team.UpdatedAt),
        grantsOrganizationAdmin = team.GrantsOrganizationAdmin,
        memberIds,
        managedByScim = false,
    };

    /// <summary>Reading or changing one team. The reference also sends a stored member count that is never updated (always 0); kept for compatibility.</summary>
    public static object Detail(Team team, IReadOnlyList<string> memberIds) => new
    {
        id = team.Id,
        externalKey = (string?)null,
        organizationId = team.OrganizationId,
        name = team.Name,
        memberCount = 0,
        grantsOrganizationAdmin = team.GrantsOrganizationAdmin,
        createdAt = Responses.IsoUtc(team.CreatedAt),
        updatedAt = Responses.IsoUtc(team.UpdatedAt),
        memberIds,
        managedByScim = false,
    };

    public static object Created(Team team, IReadOnlyList<string> memberIds) => new
    {
        id = team.Id,
        externalKey = (string?)null,
        organizationId = team.OrganizationId,
        name = team.Name,
        createdAt = Responses.IsoUtc(team.CreatedAt),
        updatedAt = Responses.IsoUtc(team.UpdatedAt),
        memberIds,
        managedByScim = false,
        grantsOrganizationAdmin = team.GrantsOrganizationAdmin,
    };
}

/// <summary>Creating, reading, renaming and deleting teams, and who is in them.</summary>
public static class TeamEndpoints
{
    private const string TeamExists = "That team already exists in this organization.";

    private sealed record TeamInput(string? Name, List<string>? MemberIds, bool? GrantsAdmin);

    public static void MapTeamEndpoints(this WebApplication app)
    {
        app.MapGet("/v1/teams/{teamId}", async (string teamId, HttpContext ctx, OrgAccess access, DenDbContext db) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "teams.view") is { } denied) return denied;
            if (MemberEndpoints.ValidateTypeId(teamId, "tem", "teamId") is { } malformed) return malformed;
            var team = await db.Teams.AsNoTracking().FirstOrDefaultAsync(t => t.Id == teamId && t.OrganizationId == context!.Organization.Id);
            if (team is null) return Results.Json(new { error = "team_not_found" }, statusCode: 404);
            return Results.Json(new { team = TeamBody.Detail(team, await MemberIdsAsync(db, team.Id)) });
        });

        app.MapPost("/v1/teams", async (HttpContext ctx, OrgAccess access, DenDbContext db, TeamRules rules, IAuditLog audit) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "teams.manage") is { } denied) return denied;
            var (input, invalid) = await ReadAsync(ctx, creating: true);
            if (invalid is not null) return invalid;

            // Even naming the field needs the right to make Admin teams, so a plain team manager cannot probe or flip it.
            if (input!.GrantsAdmin is not null && access.Require(context!, "teams.manage_admin") is { } adminDenied) return adminDenied;
            if (input.GrantsAdmin == true)
            {
                var change = input.MemberIds!.Count > 0 ? TeamRules.AdminTeamChange.AddsMembers : TeamRules.AdminTeamChange.Makes;
                if (rules.AdminTeamDenial(context!, TeamRules.AdminTeamChange.Makes) is { } nope) return nope;
                if (change == TeamRules.AdminTeamChange.AddsMembers && rules.AdminTeamDenial(context!, change) is { } nope2) return nope2;
                // A new team has no role yet, so it grants only the Admin set.
                if (await rules.GrantDenialAsync(context!, null, true, false, TeamRules.AdminTeamGrantsForbidden) is { } cannotGrant) return cannotGrant;
            }

            var memberIds = input.MemberIds!.Distinct().ToList();
            if (!await AllBelongAsync(db, context!.Organization.Id, memberIds)) return Results.Json(new { error = "member_not_found" }, statusCode: 404);

            var name = input.Name!;
            if (await db.Teams.AnyAsync(t => t.OrganizationId == context.Organization.Id && t.Name == name)) return Results.Json(new { error = "team_exists", message = TeamExists }, statusCode: 409);

            var now = DateTime.UtcNow;
            var team = new Team { Id = Ids.New("tem"), OrganizationId = context.Organization.Id, Name = name, GrantsOrganizationAdmin = input.GrantsAdmin ?? false, CreatedAt = now, UpdatedAt = now };
            db.Teams.Add(team);
            foreach (var memberId in memberIds) db.TeamMembers.Add(new TeamMember { Id = Ids.New("tmm"), TeamId = team.Id, MemberId = memberId, CreatedAt = now });
            try { await db.SaveChangesAsync(); }
            catch (DbUpdateException) { return Results.Json(new { error = "team_exists", message = TeamExists }, statusCode: 409); }
            await audit.RecordAsync(context, new AuditEntry(AuditActions.TeamCreated, [new("team", team.Id, "target", team.Name), new("organization", context.Organization.Id, "parent")],
                After: TeamSnapshot(team, memberIds)));
            return Results.Json(new { team = TeamBody.Created(team, memberIds) }, statusCode: 201);
        });

        app.MapPatch("/v1/teams/{teamId}", async (string teamId, HttpContext ctx, OrgAccess access, DenDbContext db, TeamRules rules, IAuditLog audit) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "teams.manage") is { } denied) return denied;
            if (MemberEndpoints.ValidateTypeId(teamId, "tem", "teamId") is { } malformed) return malformed;
            var (input, invalid) = await ReadAsync(ctx, creating: false);
            if (invalid is not null) return invalid;

            var team = await db.Teams.FirstOrDefaultAsync(t => t.Id == teamId && t.OrganizationId == context!.Organization.Id);
            if (team is null) return Results.Json(new { error = "team_not_found" }, statusCode: 404);
            // A team the identity provider projects (SCIM group mapping) is changed there, not here.
            if ((input!.Name is not null || input.MemberIds is not null) && await ScimTeams.IsManagedAsync(db, context!.Organization.Id, team.Id))
                return Results.Json(new { error = "scim_managed_team", message = "Manage this team through the SCIM identity provider." }, statusCode: 409);

            // Anything that changes who is admin through an Admin team needs the right to manage Admin teams.
            var touchesAdminTeam = input!.GrantsAdmin is not null || (team.GrantsOrganizationAdmin && input.MemberIds is not null);
            if (touchesAdminTeam && access.Require(context!, "teams.manage_admin") is { } adminDenied) return adminDenied;

            var nextGrantsAdmin = input.GrantsAdmin ?? team.GrantsOrganizationAdmin;
            if (team.GrantsOrganizationAdmin && !nextGrantsAdmin && rules.AdminTeamDenial(context!, TeamRules.AdminTeamChange.Unmakes) is { } unmake) return unmake;
            if (nextGrantsAdmin && !team.GrantsOrganizationAdmin)
            {
                if (rules.AdminTeamDenial(context!, TeamRules.AdminTeamChange.Makes) is { } makes) return makes;
                if (await rules.GrantDenialAsync(context!, team.Id, true, true, TeamRules.AdminTeamGrantsForbidden) is { } cannotGrant) return cannotGrant;
            }

            List<string>? memberIds = null;
            if (input.MemberIds is not null)
            {
                memberIds = input.MemberIds.Distinct().ToList();
                if (!await AllBelongAsync(db, context!.Organization.Id, memberIds)) return Results.Json(new { error = "member_not_found" }, statusCode: 404);
                var current = await MemberIdsAsync(db, team.Id);
                if (team.GrantsOrganizationAdmin && current.Any(id => !memberIds.Contains(id)) && rules.AdminTeamDenial(context, TeamRules.AdminTeamChange.RemovesMembers) is { } removes) return removes;
                if (memberIds.Any(id => !current.Contains(id)))
                {
                    if (nextGrantsAdmin && rules.AdminTeamDenial(context, TeamRules.AdminTeamChange.AddsMembers) is { } adds) return adds;
                    if (await rules.GrantDenialAsync(context, team.Id, nextGrantsAdmin, false, TeamRules.TeamGrantsForbidden) is { } cannotGrant) return cannotGrant;
                }
            }

            var nextName = input.Name ?? team.Name;
            if (await db.Teams.AnyAsync(t => t.OrganizationId == context!.Organization.Id && t.Name == nextName && t.Id != team.Id)) return Results.Json(new { error = "team_exists", message = TeamExists }, statusCode: 409);

            var now = DateTime.UtcNow;
            var beforeMembers = await MemberIdsAsync(db, team.Id);
            var before = TeamSnapshot(team, beforeMembers);
            team.Name = nextName;
            team.GrantsOrganizationAdmin = nextGrantsAdmin;
            team.UpdatedAt = now;
            if (memberIds is not null)
            {
                db.TeamMembers.RemoveRange(await db.TeamMembers.Where(tm => tm.TeamId == team.Id).ToListAsync());
                foreach (var memberId in memberIds) db.TeamMembers.Add(new TeamMember { Id = Ids.New("tmm"), TeamId = team.Id, MemberId = memberId, CreatedAt = now });
            }
            try { await db.SaveChangesAsync(); }
            catch (DbUpdateException) { return Results.Json(new { error = "team_exists", message = TeamExists }, statusCode: 409); }
            var afterMembers = memberIds ?? beforeMembers;
            await audit.RecordAsync(context!, new AuditEntry(AuditActions.TeamUpdated, [new("team", team.Id, "target", team.Name), new("organization", context!.Organization.Id, "parent")],
                Before: before, After: TeamSnapshot(team, afterMembers)));
            return Results.Json(new { team = TeamBody.Detail(team, afterMembers) });
        });

        app.MapDelete("/v1/teams/{teamId}", async (string teamId, HttpContext ctx, OrgAccess access, DenDbContext db, TeamRules rules, IAuditLog audit) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "teams.manage") is { } denied) return denied;
            if (MemberEndpoints.ValidateTypeId(teamId, "tem", "teamId") is { } malformed) return malformed;
            var team = await db.Teams.FirstOrDefaultAsync(t => t.Id == teamId && t.OrganizationId == context!.Organization.Id);
            if (team is null) return Results.Json(new { error = "team_not_found" }, statusCode: 404);
            if (await ScimTeams.IsManagedAsync(db, context!.Organization.Id, team.Id))
                return Results.Json(new { error = "scim_managed_team", message = "Disable SCIM team mapping before deleting this team." }, statusCode: 409);
            if (team.GrantsOrganizationAdmin)
            {
                if (access.Require(context!, "teams.manage_admin") is { } adminDenied) return adminDenied;
                if (rules.AdminTeamDenial(context!, TeamRules.AdminTeamChange.Deletes) is { } nope) return nope;
            }

            // A team's role outlives it (it can be given to another team); it just stops applying here.
            var now = DateTime.UtcNow;
            foreach (var link in await db.PermissionSetTeams.Where(l => l.TeamId == team.Id && l.RemovedAt == null).ToListAsync()) link.RemovedAt = now;
            var deletedMembers = await MemberIdsAsync(db, team.Id);
            db.TeamMembers.RemoveRange(await db.TeamMembers.Where(tm => tm.TeamId == team.Id).ToListAsync());
            // Pending invitations that named this team keep going without one.
            await db.Invitations.Where(i => i.TeamId == team.Id).ExecuteUpdateAsync(s => s.SetProperty(i => i.TeamId, (string?)null));
            db.Teams.Remove(team);
            await db.SaveChangesAsync();
            await audit.RecordAsync(context!, new AuditEntry(AuditActions.TeamDeleted, [new("team", team.Id, "target", team.Name), new("organization", context!.Organization.Id, "parent")],
                Before: TeamSnapshot(team, deletedMembers)));
            return Results.NoContent();
        });
    }

    private static System.Text.Json.Nodes.JsonObject TeamSnapshot(Team team, IReadOnlyList<string> memberIds) => new()
    {
        ["name"] = team.Name,
        ["grantsOrganizationAdmin"] = team.GrantsOrganizationAdmin,
        ["memberIds"] = new System.Text.Json.Nodes.JsonArray(memberIds.Select(id => (System.Text.Json.Nodes.JsonNode)System.Text.Json.Nodes.JsonValue.Create(id)!).ToArray()),
    };

    private static async Task<List<string>> MemberIdsAsync(DenDbContext db, string teamId) =>
        await db.TeamMembers.AsNoTracking().Where(tm => tm.TeamId == teamId).OrderBy(tm => tm.CreatedAt).ThenBy(tm => tm.Id).Select(tm => tm.MemberId).ToListAsync();

    /// <summary>Every id is a person of this workspace (a person with a pending invitation counts: they already show in the team).</summary>
    private static async Task<bool> AllBelongAsync(DenDbContext db, string organizationId, List<string> memberIds) =>
        memberIds.Count == 0 || await db.Members.CountAsync(m => m.OrganizationId == organizationId && memberIds.Contains(m.Id))
            + await db.Invitations.CountAsync(i => i.OrganizationId == organizationId && i.Status == InvitationStatus.Pending && memberIds.Contains(i.PlaceholderMemberId)) == memberIds.Count;

    /// <summary>Reads {name, memberIds, grantsOrganizationAdmin}, answering like the reference's validator does when something is wrong.</summary>
    private static async Task<(TeamInput? Input, IResult? Invalid)> ReadAsync(HttpContext ctx, bool creating)
    {
        JsonElement root;
        try
        {
            using var doc = await JsonDocument.ParseAsync(ctx.Request.Body);
            root = doc.RootElement.Clone();
        }
        catch (JsonException) { return (null, MemberEndpoints.InvalidRequest("name", "Invalid input: expected object, received undefined")); }
        if (root.ValueKind != JsonValueKind.Object) return (null, MemberEndpoints.InvalidRequest("name", "Invalid input: expected object"));

        string? name = null;
        if (root.TryGetProperty("name", out var n))
        {
            if (n.ValueKind != JsonValueKind.String) return (null, MemberEndpoints.InvalidRequest("name", $"Invalid input: expected string, received {Kind(n)}"));
            name = n.GetString()!.Trim();
            if (name.Length < 1) return (null, MemberEndpoints.InvalidRequest("name", "Too small: expected string to have >=1 characters", "too_small"));
            if (name.Length > 255) return (null, MemberEndpoints.InvalidRequest("name", "Too big: expected string to have <=255 characters", "too_big"));
        }
        else if (creating) return (null, MemberEndpoints.InvalidRequest("name", "Invalid input: expected string, received undefined"));

        List<string>? memberIds = creating ? [] : null;
        if (root.TryGetProperty("memberIds", out var m))
        {
            if (m.ValueKind != JsonValueKind.Array) return (null, MemberEndpoints.InvalidRequest("memberIds", $"Invalid input: expected array, received {Kind(m)}"));
            memberIds = [];
            foreach (var item in m.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.String) return (null, MemberEndpoints.InvalidRequest("memberIds", $"Invalid input: expected string, received {Kind(item)}"));
                var id = item.GetString()!;
                if (MemberEndpoints.ValidateTypeId(id, "om", "memberIds") is { } bad) return (null, bad);
                memberIds.Add(id);
            }
        }

        bool? grants = null;
        if (root.TryGetProperty("grantsOrganizationAdmin", out var g))
        {
            if (g.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) return (null, MemberEndpoints.InvalidRequest("grantsOrganizationAdmin", $"Invalid input: expected boolean, received {Kind(g)}"));
            grants = g.GetBoolean();
        }
        if (!creating && name is null && memberIds is null && grants is null) return (null, MemberEndpoints.InvalidRequest("name", "Provide at least one field to update.", "custom"));
        return (new TeamInput(name, memberIds, grants), null);
    }

    private static string Kind(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.Null => "null",
        JsonValueKind.Number => "number",
        JsonValueKind.String => "string",
        JsonValueKind.Array => "array",
        JsonValueKind.Object => "object",
        _ => "boolean",
    };
}
