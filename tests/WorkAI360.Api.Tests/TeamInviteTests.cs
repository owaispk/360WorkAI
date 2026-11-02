using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Domain;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

public sealed class TeamInviteTests : IClassFixture<ApiFactory>
{
    private readonly ApiFactory _factory;
    public TeamInviteTests(ApiFactory factory) => _factory = factory;

    private async Task<(HttpStatusCode Status, JsonElement Body)> InviteAsync(Workspace w, Person by, string email, object? teamId = null, bool omitTeam = false)
    {
        var body = omitTeam ? (object)new { email, role = "member" } : new { email, role = "member", teamId };
        return await w.CallAsync(by, HttpMethod.Post, "/v1/invitations", body);
    }

    private static string[] TeamMembers(JsonElement org, string teamId) =>
        org.GetProperty("teams").EnumerateArray().First(t => t.GetProperty("id").GetString() == teamId).GetProperty("memberIds").EnumerateArray().Select(m => m.GetString()!).ToArray();

    private async Task<(string Email, string Token, string UserId)> SignUpAsync(Workspace w) => await _factory.SignUpAsync(w.Http, "Invitee Person");

    private static async Task<HttpStatusCode> AcceptAsync(Workspace w, string token, string id) =>
        (await w.Http.SendAsync(Bearer(HttpMethod.Post, "/v1/orgs/invitations/accept", token, new { id }))).StatusCode;

    [Fact]
    public async Task An_invited_person_shows_in_the_team_at_once_and_stays_in_it_as_the_same_member_after_accepting()
    {
        var w = await Workspace.CreateAsync(_factory, "Team invites");
        var team = await w.TeamAsync("Alpha");
        var person = await SignUpAsync(w);
        var invited = await InviteAsync(w, w.Owner, person.Email, team);
        Assert.Equal(HttpStatusCode.Created, invited.Status);

        var pending = (await w.OrgAsync()).GetProperty("members").EnumerateArray().Single(m => m.GetProperty("userId").ValueKind == JsonValueKind.Null).GetProperty("id").GetString()!;
        Assert.Contains(pending, TeamMembers(await w.OrgAsync(), team));

        Assert.Equal(HttpStatusCode.OK, await AcceptAsync(w, person.Token, invited.Body.GetProperty("invitationId").GetString()!));
        var after = await w.OrgAsync();
        var me = after.GetProperty("members").EnumerateArray().Single(m => m.GetProperty("userId").GetString() == person.UserId);
        Assert.Equal(pending, me.GetProperty("id").GetString());
        Assert.Contains(pending, TeamMembers(after, team));
        // Accepting again changes nothing: still one membership of the team.
        Assert.Equal(HttpStatusCode.OK, await AcceptAsync(w, person.Token, invited.Body.GetProperty("invitationId").GetString()!));
        Assert.Single(TeamMembers(await w.OrgAsync(), team), pending);
    }

    [Fact]
    public async Task A_team_that_grants_permissions_applies_to_the_person_only_once_they_have_accepted()
    {
        var w = await Workspace.CreateAsync(_factory, "Team invite grants");
        var team = await w.TeamAsync("Deleters");
        await w.RoleAsync(team, "members.delete");
        var person = await SignUpAsync(w);
        var invited = await InviteAsync(w, w.Owner, person.Email, team);
        Assert.Equal(HttpStatusCode.Created, invited.Status);
        // Not a member yet: the invitation gives no access to the workspace.
        var before = await w.Http.SendAsync(w.As(person.Token, HttpMethod.Get, "/v1/org"));
        Assert.NotEqual(HttpStatusCode.OK, before.StatusCode);
        Assert.Equal(HttpStatusCode.OK, await AcceptAsync(w, person.Token, invited.Body.GetProperty("invitationId").GetString()!));
        var held = new Person(person.Email, person.Token, person.UserId, (await w.OrgAsync()).GetProperty("members").EnumerateArray().Single(m => m.GetProperty("userId").GetString() == person.UserId).GetProperty("id").GetString()!);
        Assert.Contains("members.delete", await w.HeldAsync(held));
    }

    [Fact]
    public async Task Choosing_a_team_follows_resend_rules_and_other_workspaces_teams_are_refused()
    {
        var w = await Workspace.CreateAsync(_factory, "Resend rules");
        var other = await Workspace.CreateAsync(_factory, "Resend rules other");
        var a = await w.TeamAsync("A"); var b = await w.TeamAsync("B");
        var theirs = await other.TeamAsync("Theirs");
        var email = ApiFactory.NewEmail("invitee");

        Assert.Equal(HttpStatusCode.Created, (await InviteAsync(w, w.Owner, email, a)).Status);
        var placeholder = TeamMembers(await w.OrgAsync(), a).Single();
        // Omitted keeps, a different team moves, null clears.
        Assert.Equal(HttpStatusCode.OK, (await InviteAsync(w, w.Owner, email, omitTeam: true)).Status);
        Assert.Equal([placeholder], TeamMembers(await w.OrgAsync(), a));
        Assert.Equal(HttpStatusCode.OK, (await InviteAsync(w, w.Owner, email, b)).Status);
        Assert.Empty(TeamMembers(await w.OrgAsync(), a));
        Assert.Equal([placeholder], TeamMembers(await w.OrgAsync(), b));
        Assert.Equal(HttpStatusCode.OK, (await InviteAsync(w, w.Owner, email, null)).Status);
        Assert.Empty(TeamMembers(await w.OrgAsync(), b));

        // Another workspace's team, an unknown team and a malformed id are refused, and nothing reaches the other workspace.
        var foreign = await InviteAsync(w, w.Owner, "f." + email, theirs);
        Assert.Equal(HttpStatusCode.BadRequest, foreign.Status);
        Assert.StartsWith("Choose a team in this organization", foreign.Body.GetProperty("message").GetString());
        Assert.Equal(HttpStatusCode.BadRequest, (await InviteAsync(w, w.Owner, "g." + email, "tem_01m6797hhce34acegcde4y57bd")).Status);
        var malformed = await InviteAsync(w, w.Owner, "h." + email, "nope");
        Assert.StartsWith("teamId:", malformed.Body.GetProperty("message").GetString());
        Assert.Empty(TeamMembers(await other.OrgAsync(), theirs));
        Assert.Empty(_factory.WithDb(db => db.Invitations.Where(i => i.TeamId == theirs).ToList()));
        // Nothing was created for the refused ones.
        Assert.DoesNotContain((await w.OrgAsync()).GetProperty("invitations").EnumerateArray(), i => i.GetProperty("email").GetString()!.StartsWith("f."));
    }

    [Fact]
    public async Task Choosing_a_team_needs_manage_teams_and_every_permission_the_team_grants()
    {
        var w = await Workspace.CreateAsync(_factory, "Team invite rights");
        var inviter = await w.AddAsync();
        var inviters = await w.TeamAsync("Inviters", inviter);
        await w.RoleAsync(inviters, "invitations.manage");
        var plain = await w.TeamAsync("Plain");
        var email = ApiFactory.NewEmail("invitee");

        var noTeamsManage = await InviteAsync(w, inviter, email, plain);
        Assert.Equal(HttpStatusCode.Forbidden, noTeamsManage.Status);
        Assert.Equal("teams.manage", noTeamsManage.Body.GetProperty("requiredPermission").GetString());
        // Without a team (or clearing none) they still may invite.
        Assert.Equal(HttpStatusCode.Created, (await InviteAsync(w, inviter, "ok." + email, omitTeam: true)).Status);

        // Teams manage is held, but the team grants more than the inviter has.
        var manager = await w.AddAsync();
        var managers = await w.TeamAsync("Team managers", manager);
        await w.RoleAsync(managers, "invitations.manage", "teams.manage");
        var strong = await w.TeamAsync("Strong");
        await w.RoleAsync(strong, "members.delete");
        var refused = await InviteAsync(w, manager, "s." + email, strong);
        Assert.Equal(HttpStatusCode.Forbidden, refused.Status);
        Assert.Contains("grants permissions you don't have", refused.Body.GetProperty("message").GetString());
        Assert.Equal(HttpStatusCode.Created, (await InviteAsync(w, manager, "p." + email, plain)).Status);

        // An admin team needs the permission to manage admin teams.
        var adminTeam = (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/teams", new { name = "Admins", memberIds = Array.Empty<string>(), grantsOrganizationAdmin = true })).Body.GetProperty("team").GetProperty("id").GetString()!;
        var viaAdmin = await InviteAsync(w, manager, "a." + email, adminTeam);
        Assert.Equal(HttpStatusCode.Forbidden, viaAdmin.Status);
        Assert.Empty(TeamMembers(await w.OrgAsync(), adminTeam));
    }

    [Fact]
    public async Task Canceling_or_deleting_the_team_takes_the_pending_person_out_and_the_invitation_still_works()
    {
        var w = await Workspace.CreateAsync(_factory, "Team invite cleanup");
        var keep = await w.TeamAsync("Keep"); var doomed = await w.TeamAsync("Doomed");
        var canceled = ApiFactory.NewEmail("canceled");
        var inv = (await InviteAsync(w, w.Owner, canceled, keep)).Body.GetProperty("invitationId").GetString()!;
        Assert.Single(TeamMembers(await w.OrgAsync(), keep));
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/invitations/{inv}/cancel", new { })).Status);
        Assert.Empty(TeamMembers(await w.OrgAsync(), keep));

        var person = await SignUpAsync(w);
        var invited = (await InviteAsync(w, w.Owner, person.Email, doomed)).Body.GetProperty("invitationId").GetString()!;
        Assert.Equal(HttpStatusCode.NoContent, (await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/teams/{doomed}")).Status);
        Assert.Null(_factory.WithDb(db => db.Invitations.AsNoTracking().Single(i => i.Id == invited).TeamId));
        Assert.Equal(HttpStatusCode.OK, await AcceptAsync(w, person.Token, invited));
        var org = await w.OrgAsync();
        Assert.All(org.GetProperty("teams").EnumerateArray(), t => Assert.Empty(t.GetProperty("memberIds").EnumerateArray()));
    }

    [Fact]
    public async Task Editing_a_team_keeps_a_pending_person_in_it_and_unknown_people_are_still_refused()
    {
        var w = await Workspace.CreateAsync(_factory, "Team edit pending");
        var team = await w.TeamAsync("Edited");
        var member = await w.AddAsync();
        var email = ApiFactory.NewEmail("pending");
        await InviteAsync(w, w.Owner, email, team);
        var pending = TeamMembers(await w.OrgAsync(), team).Single();
        var patched = await w.CallAsync(w.Owner, HttpMethod.Patch, $"/v1/teams/{team}", new { memberIds = new[] { pending, member.MemberId } });
        Assert.Equal(HttpStatusCode.OK, patched.Status);
        Assert.Equal(2, TeamMembers(await w.OrgAsync(), team).Length);
        // An id that is neither a person nor a pending invitation of this workspace is refused.
        var other = await Workspace.CreateAsync(_factory, "Team edit pending other");
        var foreign = await w.CallAsync(w.Owner, HttpMethod.Patch, $"/v1/teams/{team}", new { memberIds = new[] { other.Owner.MemberId } });
        Assert.Equal(HttpStatusCode.NotFound, foreign.Status);
    }

    [Fact]
    public async Task Two_acceptances_at_once_make_one_member_in_one_team_membership()
    {
        var w = await Workspace.CreateAsync(_factory, "Team accept race");
        var team = await w.TeamAsync("Race");
        var person = await SignUpAsync(w);
        var id = (await InviteAsync(w, w.Owner, person.Email, team)).Body.GetProperty("invitationId").GetString()!;
        var results = await Task.WhenAll(Enumerable.Range(0, 5).Select(_ => AcceptAsync(w, person.Token, id)));
        Assert.All(results, r => Assert.Equal(HttpStatusCode.OK, r));
        var org = await w.OrgAsync();
        Assert.Single(org.GetProperty("members").EnumerateArray(), m => m.GetProperty("userId").GetString() == person.UserId);
        Assert.Single(TeamMembers(org, team));
    }
}
