using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using WorkAI360.Api.Domain.OrgAdmin;
using WorkAI360.Api.Domain.PlatformAdmin;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>Per-member feature overrides set by a platform admin (GET/PUT /v1/admin/organizations/{org}/members/{member}/capabilities).</summary>
public sealed class MemberFeatureTests(PlatformAdminFactory factory) : IClassFixture<PlatformAdminFactory>
{
    private static string Path(string org, string member) => $"/v1/admin/organizations/{org}/members/{member}/capabilities";

    private async Task<Person> AdminAsync()
    {
        var http = factory.Plain();
        var signIn = await http.PostAsJsonAsync("/api/auth/sign-in/email", new { email = PlatformAdminFactory.BootstrapEmail, password = Password });
        if (!signIn.IsSuccessStatusCode)
            signIn = await http.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "Boot Admin", email = PlatformAdminFactory.BootstrapEmail, password = Password });
        var body = await ReadJsonAsync(signIn);
        return new Person(PlatformAdminFactory.BootstrapEmail, body.GetProperty("token").GetString()!, body.GetProperty("user").GetProperty("id").GetString()!, "");
    }

    private async Task<(HttpStatusCode Status, JsonElement Body)> CallAsync(Person p, HttpMethod method, string url, object? body = null)
    {
        var r = await factory.Plain().SendAsync(Bearer(method, url, p.Token, body));
        var text = await r.Content.ReadAsStringAsync();
        return (r.StatusCode, string.IsNullOrEmpty(text) ? default : JsonDocument.Parse(text).RootElement.Clone());
    }

    private static async Task<bool> OrgFeatureAsync(Workspace w, Person p, string key) => (await w.OrgAsync(p.Token)).GetProperty("features").GetProperty(key).GetBoolean();

    [Fact]
    public async Task A_member_override_applies_to_that_member_only_wins_over_the_workspace_and_clears_back()
    {
        var admin = await AdminAsync();
        var w = await Workspace.CreateAsync(factory);
        var alice = await w.AddAsync();
        var bob = await w.AddAsync();
        var other = await Workspace.CreateAsync(factory, "Other Space");
        var (_, aliceElsewhereToken, _) = (alice.Email, alice.Token, alice.UserId);
        // Alice is also in another workspace: her override there must not follow her.
        var invitation = await other.InviteAsync(alice.Email);
        await other.Http.SendAsync(Bearer(HttpMethod.Post, "/v1/orgs/invitations/accept", alice.Token, new { id = invitation.GetProperty("invitationId").GetString() }));

        Assert.False(await OrgFeatureAsync(w, alice, "browserUse"));
        var put = await CallAsync(admin, HttpMethod.Put, Path(w.OrgId, alice.MemberId), new { capabilities = new { browserUse = true } });
        Assert.Equal(HttpStatusCode.OK, put.Status);
        var state = put.Body.GetProperty("featureStates").GetProperty("browserUse");
        Assert.True(state.GetProperty("enabled").GetBoolean());
        Assert.Equal("member", state.GetProperty("source").GetString());
        Assert.True(state.GetProperty("override").GetBoolean());
        Assert.False(state.GetProperty("everyone").GetBoolean());
        Assert.Equal("member", state.GetProperty("lastChange").GetProperty("scope").GetString());
        Assert.Equal("on", state.GetProperty("lastChange").GetProperty("action").GetString());

        Assert.True(await OrgFeatureAsync(w, alice, "browserUse"));
        Assert.False(await OrgFeatureAsync(w, bob, "browserUse"));
        Assert.False(await OrgFeatureAsync(w, w.Owner, "browserUse"));
        var elsewhere = await other.Http.SendAsync(Bearer(HttpMethod.Get, "/v1/org", aliceElsewhereToken).WithOrg(other.OrgId));
        Assert.False((await ReadJsonAsync(elsewhere)).GetProperty("features").GetProperty("browserUse").GetBoolean());

        // The member's override beats the workspace's own: the workspace turns it on, Alice's says off.
        await CallAsync(admin, HttpMethod.Put, $"/v1/admin/organizations/{w.OrgId}/capabilities", new { capabilities = new { browserUse = true } });
        await CallAsync(admin, HttpMethod.Put, Path(w.OrgId, alice.MemberId), new { capabilities = new { browserUse = false } });
        Assert.False(await OrgFeatureAsync(w, alice, "browserUse"));
        Assert.True(await OrgFeatureAsync(w, bob, "browserUse"));
        var read = await CallAsync(admin, HttpMethod.Get, Path(w.OrgId, alice.MemberId));
        Assert.True(read.Body.GetProperty("featureStates").GetProperty("browserUse").GetProperty("everyone").GetBoolean());

        // null clears: back to the workspace's value; a change recorded in the workspace's audit history, done by the platform admin.
        var cleared = await CallAsync(admin, HttpMethod.Put, Path(w.OrgId, alice.MemberId), new { capabilities = new { browserUse = (bool?)null } });
        Assert.Equal("override", cleared.Body.GetProperty("featureStates").GetProperty("browserUse").GetProperty("source").GetString());
        Assert.Equal(JsonValueKind.Null, cleared.Body.GetProperty("featureStates").GetProperty("browserUse").GetProperty("override").ValueKind);
        Assert.True(await OrgFeatureAsync(w, alice, "browserUse"));
        Assert.Equal(0, factory.WithDb(db => db.Set<PlatformMemberFeature>().Count(f => f.MemberId == alice.MemberId)));
        Assert.Equal(3, factory.WithDb(db => db.Set<AuditEvent>().Count(e => e.OrganizationId == w.OrgId && e.Action == "member.capabilities.updated")));
    }

    [Fact]
    public async Task Kill_switch_and_operator_lock_still_win_over_a_member_override()
    {
        var admin = await AdminAsync();
        var w = await Workspace.CreateAsync(factory);
        var alice = await w.AddAsync();
        // mermaidZoom is locked off by the deployment's configuration.
        var locked = await CallAsync(admin, HttpMethod.Put, Path(w.OrgId, alice.MemberId), new { capabilities = new { mermaidZoom = true } });
        var state = locked.Body.GetProperty("featureStates").GetProperty("mermaidZoom");
        Assert.False(state.GetProperty("enabled").GetBoolean());
        Assert.Equal("lock", state.GetProperty("source").GetString());
        Assert.False(state.GetProperty("overrideApplies").GetBoolean());
        Assert.False(await OrgFeatureAsync(w, alice, "mermaidZoom"));
    }

    [Fact]
    public async Task Only_platform_admins_ids_must_be_real_and_the_body_is_strict()
    {
        var admin = await AdminAsync();
        var w = await Workspace.CreateAsync(factory);
        var alice = await w.AddAsync();
        var other = await Workspace.CreateAsync(factory, "Elsewhere");

        // Owners of the workspace are not platform admins.
        Assert.Equal(HttpStatusCode.Forbidden, (await CallAsync(w.Owner, HttpMethod.Get, Path(w.OrgId, alice.MemberId))).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await CallAsync(w.Owner, HttpMethod.Put, Path(w.OrgId, alice.MemberId), new { capabilities = new { browserUse = true } })).Status);
        Assert.Equal(0, factory.WithDb(db => db.Set<PlatformMemberFeature>().Count(f => f.MemberId == alice.MemberId)));

        Assert.Equal(HttpStatusCode.BadRequest, (await CallAsync(admin, HttpMethod.Get, Path("nope", alice.MemberId))).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await CallAsync(admin, HttpMethod.Get, Path(w.OrgId, "nope"))).Status);
        // A member of another workspace, addressed through this one, is not found (and nothing is written).
        Assert.Equal(HttpStatusCode.NotFound, (await CallAsync(admin, HttpMethod.Get, Path(w.OrgId, other.Owner.MemberId))).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await CallAsync(admin, HttpMethod.Put, Path(w.OrgId, other.Owner.MemberId), new { capabilities = new { browserUse = true } })).Status);
        Assert.Equal(0, factory.WithDb(db => db.Set<PlatformMemberFeature>().Count(f => f.MemberId == other.Owner.MemberId)));

        static string Msg(JsonElement e) => e.GetProperty("message").GetString()!;
        Assert.Equal("Unrecognized key: \"zzz\"", Msg((await CallAsync(admin, HttpMethod.Put, Path(w.OrgId, alice.MemberId), new { capabilities = new { zzz = true } })).Body));
        Assert.Equal("Unrecognized key: \"extra\"", Msg((await CallAsync(admin, HttpMethod.Put, Path(w.OrgId, alice.MemberId), new { capabilities = new { }, extra = 1 })).Body));
        Assert.Equal("Invalid input: expected boolean, received string", Msg((await CallAsync(admin, HttpMethod.Put, Path(w.OrgId, alice.MemberId), new { capabilities = new { browserUse = "yes" } })).Body));
        Assert.Equal("autoRouter is not part of this deployment.", Msg((await CallAsync(admin, HttpMethod.Put, Path(w.OrgId, alice.MemberId), new { capabilities = new { autoRouter = true } })).Body));
    }

    [Fact]
    public async Task An_override_stops_applying_when_the_membership_ends_and_does_not_return_with_a_new_one()
    {
        var admin = await AdminAsync();
        var w = await Workspace.CreateAsync(factory);
        var alice = await w.AddAsync();
        await CallAsync(admin, HttpMethod.Put, Path(w.OrgId, alice.MemberId), new { capabilities = new { browserUse = true } });
        Assert.True(await OrgFeatureAsync(w, alice, "browserUse"));

        Assert.Equal(HttpStatusCode.NoContent, (await w.SendAsync(w.As(w.Owner, HttpMethod.Delete, $"/v1/members/{alice.MemberId}"))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await CallAsync(admin, HttpMethod.Get, Path(w.OrgId, alice.MemberId))).Status);

        // Removal signed Alice out. Invited back: a new membership, starting from the workspace's value.
        var signIn = await ReadJsonAsync(await w.Http.PostAsJsonAsync("/api/auth/sign-in/email", new { email = alice.Email, password = Password }));
        alice = alice with { Token = signIn.GetProperty("token").GetString()! };
        var again = await w.InviteAsync(alice.Email);
        Assert.Equal(HttpStatusCode.OK, (await w.Http.SendAsync(Bearer(HttpMethod.Post, "/v1/orgs/invitations/accept", alice.Token, new { id = again.GetProperty("invitationId").GetString() }))).StatusCode);
        Assert.False(await OrgFeatureAsync(w, alice, "browserUse"));
    }
}

file static class RequestExtensions
{
    public static HttpRequestMessage WithOrg(this HttpRequestMessage request, string orgId) { request.Headers.Add("x-openwork-org-id", orgId); return request; }
}
