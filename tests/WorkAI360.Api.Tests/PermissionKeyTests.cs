using System.Net;
using System.Text.Json;

namespace WorkAI360.Api.Tests;

/// <summary>GET /v1/permissions/keys/{permissionKey}: one permission and its status in every active set of the workspace.</summary>
public sealed class PermissionKeyTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    [Fact]
    public async Task One_permission_is_shown_in_the_Member_and_Admin_sets_then_each_team_set_by_name()
    {
        var w = await Workspace.CreateAsync(factory);
        var bob = await w.AddAsync();
        var zeta = await w.TeamAsync("Zeta", bob);
        var alpha = await w.TeamAsync("Alpha");
        var zetaRole = await w.RoleAsync(zeta, "prompts.view");
        var alphaRole = await w.RoleAsync(alpha, "teams.view");

        var r = await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/permissions/keys/prompts.view");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        var permission = r.Body.GetProperty("permission");
        Assert.Equal(["key", "area", "label", "description", "sensitive", "lockedOn", "defaultOn"], permission.EnumerateObject().Select(p => p.Name).ToArray());
        Assert.Equal("prompts.view", permission.GetProperty("key").GetString());
        Assert.Equal("desktop", permission.GetProperty("area").GetString());
        Assert.Equal(["admin"], permission.GetProperty("defaultOn").EnumerateArray().Select(e => e.GetString()!).ToArray());

        var sets = r.Body.GetProperty("sets").EnumerateArray().ToList();
        Assert.Equal(["member_default", "admin_default", "team", "team"], sets.Select(s => s.GetProperty("kind").GetString()!).ToArray());
        Assert.Equal(alphaRole, sets[2].GetProperty("id").GetString());     // team sets by name: "Alpha Permissions" before "Zeta Permissions"
        Assert.Equal(zetaRole, sets[3].GetProperty("id").GetString());
        Assert.All(sets, s => Assert.Equal(["id", "name", "kind", "team", "teams", "status", "locked"], s.EnumerateObject().Select(p => p.Name).ToArray()));
        Assert.Equal(["deny", "allow", "deny", "allow"], sets.Select(s => s.GetProperty("status").GetString()!).ToArray());
        Assert.All(sets, s => Assert.False(s.GetProperty("locked").GetBoolean()));
        // Default sets apply to no team; a team set names its team.
        Assert.Equal(JsonValueKind.Null, sets[0].GetProperty("team").ValueKind);
        Assert.Equal(0, sets[1].GetProperty("teams").GetArrayLength());
        Assert.Equal(zeta, sets[3].GetProperty("team").GetProperty("id").GetString());
        Assert.Equal("Zeta", sets[3].GetProperty("teams")[0].GetProperty("name").GetString());

        // The key is trimmed, as the reference's schema does.
        var trimmed = await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/permissions/keys/%20teams.view%20");
        Assert.Equal(HttpStatusCode.OK, trimmed.Status);
        Assert.Equal("allow", trimmed.Body.GetProperty("sets")[2].GetProperty("status").GetString());
    }

    [Fact]
    public async Task Reading_needs_permissions_view()
    {
        var w = await Workspace.CreateAsync(factory);
        var member = await w.AddAsync();
        var admin = await w.AddAsync("admin");
        var denied = await w.CallAsync(member, HttpMethod.Get, "/v1/permissions/keys/teams.view");
        Assert.Equal(HttpStatusCode.Forbidden, denied.Status);
        Assert.Equal("permissions.view", denied.Required());
        // The permission is checked before the key, so a member cannot probe which keys exist.
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(member, HttpMethod.Get, "/v1/permissions/keys/no.such.key")).Status);
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(admin, HttpMethod.Get, "/v1/permissions/keys/teams.view")).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Http.GetAsync("/v1/permissions/keys/teams.view")).StatusCode);
    }

    [Fact]
    public async Task An_unknown_key_is_404_and_a_malformed_one_is_400()
    {
        var w = await Workspace.CreateAsync(factory);
        var unknown = await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/permissions/keys/no.such.key");
        Assert.Equal(HttpStatusCode.NotFound, unknown.Status);
        Assert.Equal("permission_not_found", Workspace.Error(unknown.Body));
        Assert.Equal("This permission doesn't exist.", unknown.Body.GetProperty("message").GetString());

        var tooLong = await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/permissions/keys/" + new string('a', 129));
        Assert.Equal(HttpStatusCode.BadRequest, tooLong.Status);
        Assert.Equal("permissionKey: Too big: expected string to have <=128 characters", tooLong.Body.GetProperty("message").GetString());
        var blank = await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/permissions/keys/%20%20");
        Assert.Equal(HttpStatusCode.BadRequest, blank.Status);
        Assert.Equal("too_small", blank.Body.GetProperty("details")[0].GetProperty("code").GetString());
    }

    [Fact]
    public async Task Another_workspaces_sets_are_never_listed()
    {
        var w = await Workspace.CreateAsync(factory);
        var other = await Workspace.CreateAsync(factory, "Other Space");
        var otherRole = await other.RoleAsync(await other.TeamAsync("Elsewhere"), "teams.view");
        var r = await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/permissions/keys/teams.view");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        var ids = r.Body.GetProperty("sets").EnumerateArray().Select(s => s.GetProperty("id").GetString()!).ToList();
        Assert.Equal(2, ids.Count);
        Assert.DoesNotContain(otherRole, ids);
        // Asking with the other workspace's header but no membership there reads as not found.
        var request = w.As(w.Owner, HttpMethod.Get, "/v1/permissions/keys/teams.view");
        request.Headers.Remove("x-openwork-org-id");
        request.Headers.Add("x-openwork-org-id", other.OrgId);
        Assert.Equal(HttpStatusCode.NotFound, (await w.SendAsync(request)).StatusCode);
    }
}
