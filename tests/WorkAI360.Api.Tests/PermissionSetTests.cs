using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

public sealed class PermissionSetTests : IClassFixture<ApiFactory>
{
    private readonly ApiFactory _factory;
    public PermissionSetTests(ApiFactory factory) => _factory = factory;

    private static object Allow(params string[] keys) => keys.Select(k => new { key = k, status = "allow" }).ToArray();

    private async Task<JsonElement> SetsAsync(Workspace w, Person? by = null) =>
        (await w.CallAsync(by ?? w.Owner, HttpMethod.Get, "/v1/permissions/sets")).Body.GetProperty("sets");

    [Fact]
    public async Task A_new_workspace_has_a_Member_set_with_nothing_on_and_an_Admin_set_with_the_reference_defaults()
    {
        var w = await Workspace.CreateAsync(_factory);
        await w.AddAsync();
        var sets = (await SetsAsync(w)).EnumerateArray().ToList();
        Assert.Equal(["member_default", "admin_default"], sets.Select(s => s.GetProperty("kind").GetString()));
        Assert.Equal(0, sets[0].GetProperty("allowedCount").GetInt32());
        Assert.Equal(43, sets[1].GetProperty("allowedCount").GetInt32());
        Assert.Equal(2, sets[0].GetProperty("appliesTo").GetProperty("memberCount").GetInt32());
        Assert.Equal(0, sets[1].GetProperty("appliesTo").GetProperty("directAdminCount").GetInt32());
        Assert.Equal(1, _factory.WithDb(db => db.PermissionSets.Count(s => s.OrganizationId == w.OrgId && s.DefaultKey == "member")));
        // The catalog is the same for everyone signed in, and not for anonymous callers.
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/permissions/catalog")).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Http.GetAsync("/v1/permissions/catalog")).StatusCode);
    }

    [Fact]
    public async Task Listing_and_reading_sets_needs_permissions_view()
    {
        var w = await Workspace.CreateAsync(_factory);
        var member = await w.AddAsync();
        var admin = await w.AddAsync("admin");
        var denied = await w.CallAsync(member, HttpMethod.Get, "/v1/permissions/sets");
        Assert.Equal(HttpStatusCode.Forbidden, denied.Status);
        Assert.Equal("permissions.view", denied.Required());
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(admin, HttpMethod.Get, "/v1/permissions/sets")).Status);
        // Names and emails of who a set applies to are shown only to those who may see teams.
        var teamId = await w.TeamAsync("Readers", member);
        var role = await w.RoleAsync(teamId, "prompts.view");
        var asOwner = (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/permissions/sets/{role}")).Body.GetProperty("set").GetProperty("appliesTo");
        Assert.Equal(1, asOwner.GetProperty("members").GetArrayLength());
        // Give a member only permissions.view: they see the count, not the people.
        var viewer = await w.AddAsync();
        await w.RoleAsync(await w.TeamAsync("Viewers", viewer), "permissions.view");
        var asViewer = (await w.CallAsync(viewer, HttpMethod.Get, $"/v1/permissions/sets/{role}")).Body.GetProperty("set").GetProperty("appliesTo");
        Assert.Equal(1, asViewer.GetProperty("memberCount").GetInt32());
        Assert.Equal(JsonValueKind.Null, asViewer.GetProperty("members").ValueKind);
    }

    [Fact]
    public async Task Permissions_are_the_union_of_everything_granted_and_each_is_explained_by_its_sources()
    {
        var w = await Workspace.CreateAsync(_factory);
        var admin = await w.AddAsync("admin");
        var support = await w.TeamAsync("Support", admin);
        var billing = await w.TeamAsync("Billing", admin);
        await w.RoleAsync(support, "teams.view", "organization.update");     // teams.view is also in the Admin set; organization.update is not
        await w.RoleAsync(billing, "organization.update");

        var r = await w.CallAsync(admin, HttpMethod.Get, $"/v1/members/{admin.MemberId}/permissions");
        var perms = r.Body.GetProperty("permissions").EnumerateArray().ToDictionary(p => p.GetProperty("key").GetString()!, p => p.GetProperty("sources").EnumerateArray().Select(s => s.GetProperty("label").GetString()!).ToArray());
        Assert.True(r.Body.GetProperty("isAdmin").GetBoolean());
        Assert.Equal(["Admin permissions (admin role)", "Support Permissions (via Support team)"], perms["teams.view"]);   // admin role first, then the team's role
        Assert.Equal(["Billing Permissions (via Billing team)", "Support Permissions (via Support team)"], perms["organization.update"]);   // two roles grant it, listed by role name
        Assert.Equal(["Admin permissions (admin role)"], perms["invitations.manage"]);
        Assert.Equal(43 + 1, perms.Count);                                // the 43 admin keys plus organization.update
        Assert.Equal(perms.Keys.Order(StringComparer.Ordinal), perms.Keys);   // sorted by key, as the reference returns them
    }

    [Fact]
    public async Task A_role_applies_immediately_and_stops_applying_when_turned_off_deleted_or_replaced()
    {
        var w = await Workspace.CreateAsync(_factory);
        var member = await w.AddAsync();
        var team = await w.TeamAsync("Support", member);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(member, HttpMethod.Get, $"/v1/teams/{team}")).Status);

        var role = await w.RoleAsync(team, "teams.view");
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(member, HttpMethod.Get, $"/v1/teams/{team}")).Status);
        Assert.Contains("teams.view", (await w.OrgAsync(member.Token)).GetProperty("currentMember").GetProperty("permissions").EnumerateArray().Select(p => p.GetString()));

        // Turned off.
        await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/permissions/sets/{role}/permissions", new { changes = new[] { new { key = "teams.view", status = "deny" } } });
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(member, HttpMethod.Get, $"/v1/teams/{team}")).Status);
        await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/permissions/sets/{role}/permissions", new { changes = new[] { new { key = "teams.view", status = "allow" } } });
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(member, HttpMethod.Get, $"/v1/teams/{team}")).Status);

        // Replaced by another role: the first one stops applying.
        var other = (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/permissions/sets", new { name = "Nothing much", permissions = Allow("prompts.view") })).Body.GetProperty("set").GetProperty("id").GetString()!;
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/teams/{team}/permission-set", new { permissionSetId = other })).Status);
        Assert.Equal(["prompts.view"], await w.HeldAsync(member));
        Assert.Equal(1, _factory.WithDb(db => db.PermissionSetTeams.Count(l => l.TeamId == team && l.RemovedAt == null)));

        // None at all.
        var cleared = await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/teams/{team}/permission-set", new { permissionSetId = (string?)null });
        Assert.Equal(JsonValueKind.Null, cleared.Body.GetProperty("set").ValueKind);
        Assert.Empty(await w.HeldAsync(member));

        // Deleted: the role is archived, applies to no one and cannot be given again or changed.
        await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/teams/{team}/permission-set", new { permissionSetId = role });
        Assert.Contains("teams.view", await w.HeldAsync(member));
        Assert.Equal(HttpStatusCode.NoContent, (await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/permissions/sets/{role}")).Status);
        Assert.Empty(await w.HeldAsync(member));
        Assert.Equal("permission_set_archived", (await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/permissions/sets/{role}")).Error());
        Assert.Equal("permission_set_archived", (await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/teams/{team}/permission-set", new { permissionSetId = role })).Error());
        Assert.Equal("permission_set_archived", (await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/permissions/sets/{role}/permissions", new { changes = Allow("billing.view") })).Error());
        Assert.Equal("permission_set_archived", (await w.CallAsync(w.Owner, HttpMethod.Patch, $"/v1/permissions/sets/{role}", new { name = "Again" })).Error());
        // The team can get a new role of its own now that the old one is gone.
        Assert.Equal(HttpStatusCode.Created, (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/permissions/sets", new { teamId = team, permissions = Allow("teams.view") })).Status);
        // The archived role (and its history) is still readable.
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/permissions/sets/{role}/history")).Status);
    }

    [Fact]
    public async Task Two_roles_created_for_one_team_at_once_make_exactly_one()
    {
        var w = await Workspace.CreateAsync(_factory);
        var team = await w.TeamAsync("Racers");
        var results = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => w.CallAsync(w.Owner, HttpMethod.Post, "/v1/permissions/sets", new { teamId = team, permissions = Allow("teams.view") })));
        Assert.Equal(1, results.Count(r => r.Status == HttpStatusCode.Created));
        Assert.Equal(5, results.Count(r => r.Status == HttpStatusCode.Conflict && r.Error() == "team_permission_set_exists"));
        Assert.Equal(1, _factory.WithDb(db => db.PermissionSetTeams.Count(l => l.TeamId == team && l.RemovedAt == null)));
        // The losers left no orphan roles behind.
        Assert.Equal(3, (await SetsAsync(w)).GetArrayLength());   // Member, Admin, and the one team role
    }

    [Fact]
    public async Task Giving_a_team_a_role_in_parallel_never_leaves_it_with_two_active_roles()
    {
        var w = await Workspace.CreateAsync(_factory);
        var team = await w.TeamAsync("Switching");
        var roles = new List<string>();
        for (var i = 0; i < 4; i++) roles.Add((await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/permissions/sets", new { name = $"Role {i}", permissions = Allow("prompts.view") })).Body.GetProperty("set").GetProperty("id").GetString()!);
        await Task.WhenAll(roles.Select(r => w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/teams/{team}/permission-set", new { permissionSetId = r })));
        Assert.Equal(1, _factory.WithDb(db => db.PermissionSetTeams.Count(l => l.TeamId == team && l.RemovedAt == null)));
    }

    [Fact]
    public async Task Setting_permissions_is_checked_for_unknown_repeated_and_unheld_keys()
    {
        var w = await Workspace.CreateAsync(_factory);
        var manager = await w.AddAsync();
        var team = await w.TeamAsync("Managers", manager);
        var role = await w.RoleAsync(team, "permissions.manage", "permissions.view", "prompts.view");
        var scratch = (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/permissions/sets", new { name = "Scratch", permissions = Array.Empty<object>() })).Body.GetProperty("set").GetProperty("id").GetString()!;

        async Task<(HttpStatusCode Status, JsonElement Body)> Put(Person p, string setId, params (string Key, string Status)[] changes) =>
            await w.CallAsync(p, HttpMethod.Put, $"/v1/permissions/sets/{setId}/permissions", new { changes = changes.Select(c => new { key = c.Key, status = c.Status }).ToArray() });

        var unknown = await Put(w.Owner, scratch, ("nope.x", "allow"), ("also.nope", "deny"));
        Assert.Equal((HttpStatusCode.BadRequest, "unknown_permission"), (unknown.Status, unknown.Error()));
        Assert.Equal(["also.nope", "nope.x"], unknown.Body.GetProperty("keys").EnumerateArray().Select(k => k.GetString()));   // sorted
        Assert.Equal("duplicate_permission", (await Put(w.Owner, scratch, ("teams.view", "allow"), ("teams.view", "deny"))).Error());
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/permissions/sets/{scratch}/permissions", new { changes = Array.Empty<object>() })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/permissions/sets/{scratch}/permissions", new { changes = new[] { new { key = "teams.view", status = "maybe" } } })).Status);

        // The manager may turn on what they hold, not what they don't, and turning things off is always allowed.
        Assert.Equal(HttpStatusCode.OK, (await Put(manager, scratch, ("prompts.view", "allow"))).Status);
        var notHeld = await Put(manager, scratch, ("organization.update", "allow"), ("billing.manage", "allow"));
        Assert.Equal((HttpStatusCode.Forbidden, "permission_not_held"), (notHeld.Status, notHeld.Error()));
        Assert.Equal(["billing.manage", "organization.update"], notHeld.Body.GetProperty("keys").EnumerateArray().Select(k => k.GetString()));
        Assert.Equal(HttpStatusCode.OK, (await Put(manager, scratch, ("prompts.view", "deny"))).Status);
        // A failed request changed nothing, even the keys in it the manager could have turned on.
        var mixed = await Put(manager, scratch, ("prompts.view", "allow"), ("organization.update", "allow"));
        Assert.Equal(HttpStatusCode.Forbidden, mixed.Status);
        var current = (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/permissions/sets/{scratch}")).Body.GetProperty("set");
        Assert.Equal(0, current.GetProperty("allowedCount").GetInt32());
        // New roles are held to the same rule.
        Assert.Equal("permission_not_held", (await w.CallAsync(manager, HttpMethod.Post, "/v1/permissions/sets", new { name = "Escalate", permissions = Allow("organization.update") })).Error());
        // Giving a team a role grants everything in it, so the giver must hold it all.
        var powerful = (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/permissions/sets", new { name = "Powerful", permissions = Allow("organization.update") })).Body.GetProperty("set").GetProperty("id").GetString()!;
        Assert.Equal("permission_not_held", (await w.CallAsync(manager, HttpMethod.Put, $"/v1/teams/{team}/permission-set", new { permissionSetId = powerful })).Error());
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/teams/{team}/permission-set", new { permissionSetId = role })).Status);
    }

    [Fact]
    public async Task Admin_permissions_can_only_be_changed_by_the_owner_or_an_admin()
    {
        var w = await Workspace.CreateAsync(_factory);
        var manager = await w.AddAsync();
        await w.RoleAsync(await w.TeamAsync("Managers", manager), "permissions.manage");
        var adminSet = (await SetsAsync(w)).EnumerateArray().First(s => s.GetProperty("kind").GetString() == "admin_default").GetProperty("id").GetString()!;
        var r = await w.CallAsync(manager, HttpMethod.Put, $"/v1/permissions/sets/{adminSet}/permissions", new { changes = new[] { new { key = "teams.view", status = "deny" } } });
        Assert.Equal((HttpStatusCode.Forbidden, "admin_permissions_require_admin"), (r.Status, r.Error()));
        Assert.Equal("Only the owner and admins can change Admin permissions.", r.Body.GetProperty("message").GetString());
        Assert.Equal(43, (await SetsAsync(w)).EnumerateArray().First(s => s.GetProperty("id").GetString() == adminSet).GetProperty("allowedCount").GetInt32());
    }

    [Fact]
    public async Task The_built_in_sets_cannot_be_renamed_or_deleted_and_roles_can_be_renamed()
    {
        var w = await Workspace.CreateAsync(_factory);
        var team = await w.TeamAsync("Named");
        var role = await w.RoleAsync(team, "prompts.view");
        var memberSet = (await SetsAsync(w))[0].GetProperty("id").GetString()!;
        Assert.Equal("default_permission_set", (await w.CallAsync(w.Owner, HttpMethod.Patch, $"/v1/permissions/sets/{memberSet}", new { name = "x" })).Error());
        Assert.Equal("default_permission_set", (await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/permissions/sets/{memberSet}")).Error());
        Assert.Equal("default_permission_set", (await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/teams/{team}/permission-set", new { permissionSetId = memberSet })).Error());
        var renamed = await w.CallAsync(w.Owner, HttpMethod.Patch, $"/v1/permissions/sets/{role}", new { name = "  Reviewers  " });
        Assert.Equal("Reviewers", renamed.Body.GetProperty("set").GetProperty("name").GetString());
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Patch, $"/v1/permissions/sets/{role}", new { name = " " })).Status);
        Assert.Equal("permission_set_not_found", (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/permissions/sets/pms_01h2xcejqtf2nbrexx3vqjhp41")).Error());
        // Another workspace's set is not found either.
        var w2 = await Workspace.CreateAsync(_factory);
        Assert.Equal("permission_set_not_found", (await w2.CallAsync(w2.Owner, HttpMethod.Get, $"/v1/permissions/sets/{role}")).Error());
        Assert.Equal("permission_set_not_found", (await w2.CallAsync(w2.Owner, HttpMethod.Put, $"/v1/permissions/sets/{role}/permissions", new { changes = Allow("billing.view") })).Error());
    }

    [Fact]
    public async Task History_keeps_every_real_change_newest_first_and_pages_without_repeats()
    {
        var w = await Workspace.CreateAsync(_factory);
        var role = await w.RoleAsync(await w.TeamAsync("Audited"), "teams.view", "prompts.view");        // two rows
        for (var i = 0; i < 3; i++)
        {
            await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/permissions/sets/{role}/permissions", new { changes = new[] { new { key = "billing.view", status = i % 2 == 0 ? "allow" : "deny" } } });
            // Saying the same thing again records nothing.
            await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/permissions/sets/{role}/permissions", new { changes = new[] { new { key = "billing.view", status = i % 2 == 0 ? "allow" : "deny" } } });
        }
        var all = (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/permissions/sets/{role}/history")).Body;
        Assert.Equal(5, all.GetProperty("items").GetArrayLength());
        Assert.Equal(["allow", "deny", "allow"], all.GetProperty("items").EnumerateArray().Take(3).Select(i => i.GetProperty("status").GetString()));
        Assert.Equal(JsonValueKind.Null, all.GetProperty("nextCursor").ValueKind);

        var seen = new List<string>(); string? cursor = null;
        do
        {
            var page = (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/permissions/sets/{role}/history?limit=2" + (cursor is null ? "" : $"&cursor={Uri.EscapeDataString(cursor)}"))).Body;
            seen.AddRange(page.GetProperty("items").EnumerateArray().Select(i => i.GetProperty("id").GetString()!));
            cursor = page.GetProperty("nextCursor").ValueKind == JsonValueKind.String ? page.GetProperty("nextCursor").GetString() : null;
        } while (cursor is not null);
        Assert.Equal(5, seen.Count);
        Assert.Equal(5, seen.Distinct().Count());
        Assert.Equal(all.GetProperty("items").EnumerateArray().Select(i => i.GetProperty("id").GetString()), seen);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/permissions/sets/{role}/history?limit=0")).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/permissions/sets/{role}/history?cursor=garbage")).Status);
        // Rows are only ever added: the stored count matches what was reported.
        Assert.Equal(5, _factory.WithDb(db => db.PermissionSetPermissions.Count(p => p.PermissionSetId == role)));
    }

    [Fact]
    public async Task Permissions_given_by_a_role_still_need_a_recent_sign_in_when_the_action_is_sensitive()
    {
        var w = await Workspace.CreateAsync(_factory);
        var inviter = await w.AddAsync();
        await w.RoleAsync(await w.TeamAsync("Inviters", inviter), "invitations.manage");
        Assert.Equal(HttpStatusCode.Created, (await w.CallAsync(inviter, HttpMethod.Post, "/v1/invitations", new { email = NewEmail(), role = "member" })).Status);

        _factory.WithDb(db => db.Database.ExecuteSqlRaw("UPDATE Sessions SET CreatedAt = {0} WHERE UserId = {1}", DateTime.UtcNow.AddHours(-3), inviter.UserId));
        var stale = await w.CallAsync(inviter, HttpMethod.Post, "/v1/invitations", new { email = NewEmail(), role = "member" });
        Assert.Equal((HttpStatusCode.Forbidden, "reauth"), (stale.Status, stale.Error()));
        // Holding the permission is checked before freshness: someone without it is told so, not asked to sign in again.
        var plain = await w.AddAsync();
        _factory.WithDb(db => db.Database.ExecuteSqlRaw("UPDATE Sessions SET CreatedAt = {0} WHERE UserId = {1}", DateTime.UtcNow.AddHours(-3), plain.UserId));
        Assert.Equal("forbidden", (await w.CallAsync(plain, HttpMethod.Post, "/v1/invitations", new { email = NewEmail(), role = "member" })).Error());
        // Reading one's own permissions is not sensitive.
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(inviter, HttpMethod.Get, $"/v1/members/{inviter.MemberId}/permissions")).Status);
    }

    [Fact]
    public async Task Naming_two_teams_in_a_role_puts_the_first_one_first_and_replaces_each_teams_old_role()
    {
        var w = await Workspace.CreateAsync(_factory);
        var a = await w.TeamAsync("Alpha"); var b = await w.TeamAsync("Beta");
        var old = await w.RoleAsync(a, "prompts.view");
        var created = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/permissions/sets", new { name = "Shared", teamIds = new[] { a, b, a }, permissions = Allow("billing.view") });
        Assert.Equal(HttpStatusCode.Created, created.Status);
        var set = created.Body.GetProperty("set");
        Assert.Equal([a, b], set.GetProperty("teams").EnumerateArray().Select(t => t.GetProperty("id").GetString()));
        Assert.Equal(a, set.GetProperty("team").GetProperty("id").GetString());
        Assert.Equal(0, (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/permissions/sets/{old}")).Body.GetProperty("set").GetProperty("teams").GetArrayLength());
        Assert.Equal("team_not_found", (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/permissions/sets", new { name = "Lost", teamIds = new[] { "tem_01h2xcejqtf2nbrexx3vqjhp41" }, permissions = Array.Empty<object>() })).Error());
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/permissions/sets", new { teamId = a, name = "Both", permissions = Array.Empty<object>() })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/permissions/sets", new { permissions = Array.Empty<object>() })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/permissions/sets", new { name = "No list" })).Status);
    }
}

/// <summary>The rules for editing a set, with no server in the way.</summary>
public sealed class PermissionEditRuleTests
{
    private static MemberPermissions Editor(bool owner = false, bool admin = false, params string[] keys) => new()
    {
        IsOwner = owner, IsAdmin = admin, IsDirectAdmin = admin, Keys = keys.ToHashSet(), Grants = [], AdminTeams = [],
    };

    private static Dictionary<string, KeyState> State(params (string Key, string Status)[] rows) =>
        rows.ToDictionary(r => r.Key, r => new KeyState(r.Status, new() { Id = "psp", PermissionSetId = "pms", PermissionKey = r.Key, Status = r.Status, Source = "user" }));

    [Fact]
    public void A_change_to_what_a_key_already_is_is_dropped()
    {
        var plan = PermissionEdits.PlanEdit(null, State(("teams.view", "allow")), [("teams.view", "allow"), ("prompts.view", "deny"), ("billing.view", "allow")], Editor(owner: true));
        Assert.True(plan.Ok);
        Assert.Equal(["billing.view"], plan.Changes.Select(c => c.Key));    // allowing what is allowed and denying what has no row are both no-ops
    }

    [Fact]
    public void Turning_on_a_key_the_editor_lacks_is_refused_with_all_missing_keys_sorted()
    {
        var plan = PermissionEdits.PlanEdit(null, State(), [("teams.view", "allow"), ("billing.view", "allow"), ("prompts.view", "allow")], Editor(false, false, "prompts.view"));
        Assert.False(plan.Ok);
        Assert.Equal("permission_not_held", plan.Problem!.Error);
        Assert.Equal(["billing.view", "teams.view"], plan.Problem.Keys);
        Assert.Equal(403, plan.Problem.StatusCode);
    }

    [Fact]
    public void Resending_a_sets_current_state_never_fails_even_for_keys_the_editor_lacks()
    {
        var plan = PermissionEdits.PlanEdit(null, State(("billing.view", "allow")), [("billing.view", "allow")], Editor());
        Assert.True(plan.Ok);
        Assert.Empty(plan.Changes);
    }

    [Fact]
    public void Turning_a_key_off_needs_nothing_but_the_right_to_edit()
    {
        var plan = PermissionEdits.PlanEdit(null, State(("billing.view", "allow")), [("billing.view", "deny")], Editor());
        Assert.True(plan.Ok);
        Assert.Equal("deny", plan.Changes.Single().Status);
    }

    [Fact]
    public void An_editor_may_restore_a_key_the_Admin_set_shipped_with_without_holding_it()
    {
        // invitations.manage is on in the Admin set by default; once removed, restoring it is not "granting something new".
        var restore = PermissionEdits.PlanEdit("admin", State(("invitations.manage", "deny")), [("invitations.manage", "allow")], Editor(false, true));
        Assert.True(restore.Ok);
        // A key that was never an Admin default is different.
        var extra = PermissionEdits.PlanEdit("admin", State(), [("organization.update", "allow")], Editor(false, true));
        Assert.Equal("permission_not_held", extra.Problem!.Error);
    }

    [Fact]
    public void Only_the_owner_and_admins_edit_the_Admin_set()
    {
        var plan = PermissionEdits.PlanEdit("admin", State(), [("teams.view", "deny"), ("billing.view", "deny")], Editor(false, false, "teams.view"));
        Assert.Equal("admin_permissions_require_admin", plan.Problem!.Error);
        Assert.Equal(403, plan.Problem.StatusCode);
        Assert.Equal(["billing.view", "teams.view"], plan.Problem.Keys);
        Assert.True(PermissionEdits.PlanEdit("admin", State(), [("teams.view", "deny")], Editor(owner: true)).Ok);
        Assert.True(PermissionEdits.PlanEdit("admin", State(), [("teams.view", "deny")], Editor(false, true)).Ok);
    }

    [Fact]
    public void Unknown_keys_win_over_everything_else_and_repeats_are_named()
    {
        var unknown = PermissionEdits.PlanEdit("admin", State(), [("zzz", "allow"), ("teams.view", "allow"), ("teams.view", "deny")], Editor());
        Assert.Equal("unknown_permission", unknown.Problem!.Error);
        Assert.Equal(400, unknown.Problem.StatusCode);
        var repeat = PermissionEdits.PlanEdit(null, State(), [("teams.view", "allow"), ("teams.view", "deny"), ("billing.view", "allow")], Editor(owner: true));
        Assert.Equal("duplicate_permission", repeat.Problem!.Error);
        Assert.Equal(["teams.view"], repeat.Problem.Keys);
    }

    [Fact]
    public void A_new_role_records_only_allowed_keys_and_the_editor_must_hold_them_all()
    {
        var ok = PermissionEdits.PlanCreate([("teams.view", "allow"), ("billing.view", "deny")], Editor(false, false, "teams.view"));
        Assert.True(ok.Ok);
        Assert.Equal(["teams.view"], ok.Changes.Select(c => c.Key));          // a deny needs no row: no row means denied
        var bad = PermissionEdits.PlanCreate([("teams.view", "allow"), ("billing.view", "allow")], Editor(false, false, "teams.view"));
        Assert.Equal(["billing.view"], bad.Problem!.Keys);
    }

    [Fact]
    public void A_role_for_a_team_is_named_after_the_team_and_stays_within_the_column()
    {
        Assert.Equal("Support Permissions", PermissionEdits.TeamSetName("  Support "));
        Assert.Equal(255, PermissionEdits.TeamSetName(new string('x', 400)).Length);
        Assert.EndsWith(" Permissions", PermissionEdits.TeamSetName(new string('x', 400)));
    }

    [Fact]
    public void Problem_messages_match_the_reference()
    {
        Assert.Equal("These permissions don't exist: a, b.", new EditProblem("unknown_permission", ["a", "b"]).Message);
        Assert.Equal("Each permission can appear only once. Listed more than once: a.", new EditProblem("duplicate_permission", ["a"]).Message);
        Assert.Equal("You can only turn on permissions you have yourself. You don't have: a.", new EditProblem("permission_not_held", ["a"]).Message);
        Assert.Equal("Only the owner and admins can change Admin permissions.", new EditProblem("admin_permissions_require_admin", ["a"]).Message);
    }
}
