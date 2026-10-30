using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>Shared helpers for tests that build teams and roles through the public API.</summary>
public static class TeamHelpers
{
    public static async Task<string> TeamAsync(this Workspace w, string name, params Person[] members) =>
        await TeamAsync(w, w.Owner, name, members);

    public static async Task<string> TeamAsync(this Workspace w, Person by, string name, params Person[] members)
    {
        var r = await w.CallAsync(by, HttpMethod.Post, "/v1/teams", new { name, memberIds = members.Select(m => m.MemberId).ToArray() });
        Assert.True(r.Status == HttpStatusCode.Created, $"create team {name}: {r.Status} {r.Body}");
        return r.Body.GetProperty("team").GetProperty("id").GetString()!;
    }

    /// <summary>Gives a team its own role (set) allowing the keys.</summary>
    public static async Task<string> RoleAsync(this Workspace w, string teamId, params string[] keys)
    {
        var r = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/permissions/sets", new { teamId, permissions = keys.Select(k => new { key = k, status = "allow" }).ToArray() });
        Assert.True(r.Status == HttpStatusCode.Created, $"create role: {r.Status} {r.Body}");
        return r.Body.GetProperty("set").GetProperty("id").GetString()!;
    }

    public static async Task<string[]> HeldAsync(this Workspace w, Person p)
    {
        var r = await w.CallAsync(p, HttpMethod.Get, $"/v1/members/{p.MemberId}/permissions");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        return r.Body.GetProperty("permissions").EnumerateArray().Select(e => e.GetProperty("key").GetString()!).ToArray();
    }

    public static string Error(this (HttpStatusCode Status, JsonElement Body) r) => r.Body.ValueKind == JsonValueKind.Object && r.Body.TryGetProperty("error", out var e) ? e.GetString() ?? "" : "";

    public static string Required(this (HttpStatusCode Status, JsonElement Body) r) => r.Body.TryGetProperty("requiredPermission", out var p) ? p.GetString() ?? "" : "";
}

public sealed class TeamTests : IClassFixture<ApiFactory>
{
    private readonly ApiFactory _factory;
    public TeamTests(ApiFactory factory) => _factory = factory;

    [Fact]
    public async Task Creating_teams_validates_input_and_refuses_duplicates_in_any_case()
    {
        var w = await Workspace.CreateAsync(_factory);
        var mia = await w.AddAsync();
        var created = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/teams", new { name = "  Support  ", memberIds = new[] { mia.MemberId, mia.MemberId } });
        Assert.Equal(HttpStatusCode.Created, created.Status);
        var team = created.Body.GetProperty("team");
        Assert.Equal("Support", team.GetProperty("name").GetString());
        Assert.Single(team.GetProperty("memberIds").EnumerateArray());   // repeated ids collapse

        Assert.Equal("team_exists", (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/teams", new { name = "support" })).Error());
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/teams", new { name = " " })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/teams", new { })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/teams", new { name = new string('x', 256) })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/teams", new { name = "X", memberIds = new[] { "nope" } })).Status);
        Assert.Equal("member_not_found", (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/teams", new { name = "Ghosts", memberIds = new[] { "om_01h2xcejqtf2nbrexx3vqjhp41" } })).Error());
        Assert.Equal(1, (await w.OrgAsync()).GetProperty("teams").GetArrayLength());   // nothing half-created
    }

    [Fact]
    public async Task Two_teams_created_with_the_same_name_at_once_make_exactly_one()
    {
        var w = await Workspace.CreateAsync(_factory);
        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => w.CallAsync(w.Owner, HttpMethod.Post, "/v1/teams", new { name = "Racers" })));
        Assert.Equal(1, results.Count(r => r.Status == HttpStatusCode.Created));
        Assert.Equal(7, results.Count(r => r.Status == HttpStatusCode.Conflict));
        Assert.Equal(1, (await w.OrgAsync()).GetProperty("teams").GetArrayLength());
    }

    [Fact]
    public async Task Managing_teams_needs_the_permission_and_everyone_can_still_see_the_list()
    {
        var w = await Workspace.CreateAsync(_factory);
        var member = await w.AddAsync();
        var admin = await w.AddAsync("admin");
        var denied = await w.CallAsync(member, HttpMethod.Post, "/v1/teams", new { name = "Nope" });
        Assert.Equal(HttpStatusCode.Forbidden, denied.Status);
        Assert.Equal("teams.manage", denied.Required());
        Assert.Equal(HttpStatusCode.Created, (await w.CallAsync(admin, HttpMethod.Post, "/v1/teams", new { name = "Made by admin" })).Status);
        // The list rides along with GET /v1/org for any member; reading one team needs teams.view.
        Assert.Equal(1, (await w.OrgAsync(member.Token)).GetProperty("teams").GetArrayLength());
        var id = (await w.OrgAsync()).GetProperty("teams")[0].GetProperty("id").GetString();
        Assert.Equal("teams.view", (await w.CallAsync(member, HttpMethod.Get, $"/v1/teams/{id}")).Required());
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(admin, HttpMethod.Get, $"/v1/teams/{id}")).Status);
    }

    [Fact]
    public async Task Renaming_and_replacing_members_keeps_the_team_and_refuses_a_taken_name()
    {
        var w = await Workspace.CreateAsync(_factory);
        var a = await w.AddAsync(); var b = await w.AddAsync();
        var one = await w.TeamAsync("One", a);
        await w.TeamAsync("Two");
        var patched = await w.CallAsync(w.Owner, HttpMethod.Patch, $"/v1/teams/{one}", new { name = "Uno", memberIds = new[] { b.MemberId } });
        Assert.Equal(HttpStatusCode.OK, patched.Status);
        Assert.Equal(one, patched.Body.GetProperty("team").GetProperty("id").GetString());
        Assert.Equal(b.MemberId, patched.Body.GetProperty("team").GetProperty("memberIds")[0].GetString());
        Assert.Equal("team_exists", (await w.CallAsync(w.Owner, HttpMethod.Patch, $"/v1/teams/{one}", new { name = "TWO" })).Error());
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Patch, $"/v1/teams/{one}", new { })).Status);
        Assert.Equal("team_not_found", (await w.CallAsync(w.Owner, HttpMethod.Patch, "/v1/teams/tem_01h2xcejqtf2nbrexx3vqjhp41", new { name = "x" })).Error());
        // The failed rename changed nothing.
        Assert.Equal("Uno", (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/teams/{one}")).Body.GetProperty("team").GetProperty("name").GetString());
    }

    [Fact]
    public async Task Teams_of_another_workspace_are_invisible()
    {
        var w1 = await Workspace.CreateAsync(_factory);
        var w2 = await Workspace.CreateAsync(_factory);
        var team = await w1.TeamAsync("Private");
        Assert.Equal(HttpStatusCode.NotFound, (await w2.CallAsync(w2.Owner, HttpMethod.Get, $"/v1/teams/{team}")).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await w2.CallAsync(w2.Owner, HttpMethod.Patch, $"/v1/teams/{team}", new { name = "Mine now" })).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await w2.CallAsync(w2.Owner, HttpMethod.Delete, $"/v1/teams/{team}")).Status);
        // And a member of another workspace cannot be put in this one's team.
        var outsider = w2.Owner;
        Assert.Equal("member_not_found", (await w1.CallAsync(w1.Owner, HttpMethod.Post, "/v1/teams", new { name = "Sneaky", memberIds = new[] { outsider.MemberId } })).Error());
        Assert.Equal("Private", (await w1.CallAsync(w1.Owner, HttpMethod.Get, $"/v1/teams/{team}")).Body.GetProperty("team").GetProperty("name").GetString());
    }

    [Fact]
    public async Task Deleting_a_team_or_removing_a_person_cleans_up_membership_and_the_role_stops_applying()
    {
        var w = await Workspace.CreateAsync(_factory);
        var a = await w.AddAsync(); var b = await w.AddAsync();
        var team = await w.TeamAsync("Cleanup", a, b);
        var role = await w.RoleAsync(team, "prompts.view");
        Assert.Contains("prompts.view", await w.HeldAsync(a));

        Assert.Equal(HttpStatusCode.NoContent, (await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/members/{b.MemberId}")).Status);
        Assert.Single((await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/teams/{team}")).Body.GetProperty("team").GetProperty("memberIds").EnumerateArray());

        Assert.Equal(HttpStatusCode.NoContent, (await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/teams/{team}")).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/teams/{team}")).Status);
        Assert.DoesNotContain("prompts.view", await w.HeldAsync(a));
        // The role is kept (it can be given to another team); it just applies to no one.
        var set = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/permissions/sets/{role}");
        Assert.Equal(HttpStatusCode.OK, set.Status);
        Assert.Equal(0, set.Body.GetProperty("set").GetProperty("teams").GetArrayLength());
        Assert.Equal(JsonValueKind.Null, set.Body.GetProperty("set").GetProperty("archivedAt").ValueKind);
        // Nothing is left behind in the table.
        Assert.Equal(0, _factory.WithDb(db => db.TeamMembers.Count(tm => tm.TeamId == team || tm.MemberId == b.MemberId)));
    }

    [Fact]
    public async Task Adding_people_to_a_team_needs_every_permission_the_team_grants()
    {
        var w = await Workspace.CreateAsync(_factory);
        var admin = await w.AddAsync("admin");
        var target = await w.AddAsync();
        var lab = await w.TeamAsync("Lab");
        await w.RoleAsync(lab, "organization.update");     // the owner may hand this out; an admin does not hold it

        var denied = await w.CallAsync(admin, HttpMethod.Patch, $"/v1/teams/{lab}", new { memberIds = new[] { target.MemberId } });
        Assert.Equal(HttpStatusCode.Forbidden, denied.Status);
        Assert.Equal("organization.update", denied.Required());
        Assert.Equal("You can't add people to this team because it grants permissions you don't have.", denied.Body.GetProperty("message").GetString());
        Assert.DoesNotContain("organization.update", await w.HeldAsync(target));

        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Patch, $"/v1/teams/{lab}", new { memberIds = new[] { target.MemberId } })).Status);
        Assert.Contains("organization.update", await w.HeldAsync(target));
    }

    [Fact]
    public async Task An_Admin_team_makes_its_members_effective_admins_and_only_admins_may_change_that()
    {
        var w = await Workspace.CreateAsync(_factory);
        var admin = await w.AddAsync("admin");
        var bob = await w.AddAsync();
        var manager = await w.AddAsync();

        // Naming the field at all needs teams.manage_admin, which only the owner holds by default.
        var byAdmin = await w.CallAsync(admin, HttpMethod.Post, "/v1/teams", new { name = "Ops", grantsOrganizationAdmin = true });
        Assert.Equal("teams.manage_admin", byAdmin.Required());
        Assert.Equal("teams.manage_admin", (await w.CallAsync(admin, HttpMethod.Post, "/v1/teams", new { name = "Ops", grantsOrganizationAdmin = false })).Required());

        var ops = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/teams", new { name = "Ops", grantsOrganizationAdmin = true, memberIds = new[] { bob.MemberId } });
        Assert.Equal(HttpStatusCode.Created, ops.Status);
        var opsId = ops.Body.GetProperty("team").GetProperty("id").GetString()!;

        var org = await w.OrgAsync(bob.Token);
        var current = org.GetProperty("currentMember");
        Assert.Equal("member,admin", current.GetProperty("role").GetString());
        Assert.Equal("member", current.GetProperty("directRole").GetString());
        Assert.Equal(opsId, current.GetProperty("adminTeams")[0].GetProperty("id").GetString());
        Assert.Equal(43, current.GetProperty("permissions").GetArrayLength());
        Assert.Equal(43, (await w.HeldAsync(bob)).Length);
        // Admin powers are real: the member can invite, and cannot be removed by a mere members.delete holder (below).
        Assert.Equal(HttpStatusCode.Created, (await w.CallAsync(bob, HttpMethod.Post, "/v1/invitations", new { email = NewEmail(), role = "member" })).Status);

        // Someone holding teams.manage and teams.manage_admin through a role, but not an admin, still may not change who is admin.
        var delegates = await w.TeamAsync("Delegates", manager);
        await w.RoleAsync(delegates, "teams.manage", "teams.manage_admin");
        var make = await w.CallAsync(manager, HttpMethod.Post, "/v1/teams", new { name = "Sneaky admins", grantsOrganizationAdmin = true });
        Assert.Equal(HttpStatusCode.Forbidden, make.Status);
        Assert.Equal("Only the owner or an admin can make a team an Admin team or add people to one.", make.Body.GetProperty("message").GetString());
        Assert.Equal("", make.Required());
        Assert.Equal("Only the owner or an admin can delete an Admin team, turn it off, or remove people from it.", (await w.CallAsync(manager, HttpMethod.Delete, $"/v1/teams/{opsId}")).Body.GetProperty("message").GetString());
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(manager, HttpMethod.Patch, $"/v1/teams/{opsId}", new { memberIds = Array.Empty<string>() })).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(manager, HttpMethod.Patch, $"/v1/teams/{opsId}", new { grantsOrganizationAdmin = false })).Status);
        // Making an existing team an Admin team, or adding to one, is refused the same way.
        var plain = await w.TeamAsync("Plain");
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(manager, HttpMethod.Patch, $"/v1/teams/{plain}", new { grantsOrganizationAdmin = true })).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(manager, HttpMethod.Patch, $"/v1/teams/{opsId}", new { memberIds = new[] { bob.MemberId, manager.MemberId } })).Status);
        Assert.Equal(43, (await w.HeldAsync(bob)).Length);   // none of it took effect

        // Switching the team off takes the admin power away.
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Patch, $"/v1/teams/{opsId}", new { grantsOrganizationAdmin = false })).Status);
        Assert.Empty(await w.HeldAsync(bob));
    }

    [Fact]
    public async Task An_admin_who_may_manage_Admin_teams_hands_out_exactly_what_the_Admin_set_allows_right_now()
    {
        var w = await Workspace.CreateAsync(_factory);
        var admin = await w.AddAsync("admin");
        var target = await w.AddAsync();
        var delegates = await w.TeamAsync("Delegates", admin);
        await w.RoleAsync(delegates, "teams.manage_admin");
        var adminSet = (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/permissions/sets")).Body.GetProperty("sets").EnumerateArray().First(s => s.GetProperty("kind").GetString() == "admin_default").GetProperty("id").GetString();
        // The owner narrows the Admin set: one permission off.
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/permissions/sets/{adminSet}/permissions", new { changes = new[] { new { key = "web_origins.view", status = "deny" } } })).Status);
        Assert.DoesNotContain("web_origins.view", await w.HeldAsync(admin));
        // An admin holds the whole Admin set by definition, so may hand it out; what is handed out is the narrowed set.
        var made = await w.CallAsync(admin, HttpMethod.Post, "/v1/teams", new { name = "More admins", grantsOrganizationAdmin = true, memberIds = new[] { target.MemberId } });
        Assert.Equal(HttpStatusCode.Created, made.Status);
        var held = await w.HeldAsync(target);
        Assert.Equal(42, held.Length);
        Assert.DoesNotContain("web_origins.view", held);
        // Turning the permission back on reaches everyone the set applies to, at once.
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/permissions/sets/{adminSet}/permissions", new { changes = new[] { new { key = "web_origins.view", status = "allow" } } })).Status);
        Assert.Contains("web_origins.view", await w.HeldAsync(target));
        Assert.Contains("web_origins.view", await w.HeldAsync(admin));
    }

    [Fact]
    public async Task Someone_with_members_delete_cannot_remove_an_admin_even_through_an_Admin_team()
    {
        var w = await Workspace.CreateAsync(_factory);
        var remover = await w.AddAsync();
        var viaTeam = await w.AddAsync();
        var direct = await w.AddAsync("admin");
        var removers = await w.TeamAsync("Removers", remover);
        await w.RoleAsync(removers, "members.delete");
        await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/teams", new { name = "Admins by team", grantsOrganizationAdmin = true, memberIds = new[] { viaTeam.MemberId } });

        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(remover, HttpMethod.Delete, $"/v1/members/{direct.MemberId}")).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(remover, HttpMethod.Delete, $"/v1/members/{viaTeam.MemberId}")).Status);
        Assert.Equal(HttpStatusCode.NoContent, (await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/members/{viaTeam.MemberId}")).Status);
        var plain = await w.AddAsync();
        Assert.Equal(HttpStatusCode.NoContent, (await w.CallAsync(remover, HttpMethod.Delete, $"/v1/members/{plain.MemberId}")).Status);
    }

    [Fact]
    public async Task Role_changes_need_an_admin_holding_the_whole_Admin_set_and_nobody_changes_their_own()
    {
        var w = await Workspace.CreateAsync(_factory);
        var changer = await w.AddAsync();
        var other = await w.AddAsync();
        var admin = await w.AddAsync("admin");
        await w.RoleAsync(await w.TeamAsync("Hr", changer), "members.update");

        var own = await w.CallAsync(changer, HttpMethod.Post, $"/v1/members/{changer.MemberId}/role", new { role = "member" });
        Assert.Equal("You can't change your own role. Ask the owner or another admin.", own.Body.GetProperty("message").GetString());
        var promote = await w.CallAsync(changer, HttpMethod.Post, $"/v1/members/{other.MemberId}/role", new { role = "admin" });
        Assert.Equal("Only the owner or an admin can make someone an admin.", promote.Body.GetProperty("message").GetString());
        var demote = await w.CallAsync(changer, HttpMethod.Post, $"/v1/members/{admin.MemberId}/role", new { role = "member" });
        Assert.Equal("Only the owner or an admin can change an admin's role.", demote.Body.GetProperty("message").GetString());
        // Inviting someone as an admin is the same grant.
        var invite = await w.CallAsync(changer, HttpMethod.Post, "/v1/invitations", new { email = NewEmail(), role = "admin" });
        Assert.Equal(HttpStatusCode.Forbidden, invite.Status);
        // Nothing changed.
        Assert.Equal("admin", (await w.OrgAsync()).GetProperty("members").EnumerateArray().First(m => m.GetProperty("id").GetString() == admin.MemberId).GetProperty("role").GetString());
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/members/{other.MemberId}/role", new { role = "admin" })).Status);
    }
}
