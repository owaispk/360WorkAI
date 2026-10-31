using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using WorkAI360.Api.Domain.Policy;
using WorkAI360.Api.Features.Policy;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>A factory whose default-model catalog knows two models, so choosing and delivering a default model can be tested end to end.</summary>
public sealed class PolicyFactory : ApiFactory
{
    public const string Provider = "ipr_01h2xcejqtf2nbrexx3vqjhp41";

    protected override void ConfigureWebHost(Microsoft.AspNetCore.Hosting.IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureServices(s => s.AddScoped<IDefaultModelCatalog, FakeCatalog>());
    }

    private sealed class FakeCatalog : IDefaultModelCatalog
    {
        public Task<DefaultModelOptions> OptionsAsync(string organizationId) => Task.FromResult(new DefaultModelOptions(
            [new(Provider, "model-a", "Gateway", "Model A", "anthropic", "gateway"), new(Provider, "model-b", "Gateway", "Model B", "anthropic", "gateway")], []));

        // Members can reach every model except "model-b" for teams not named "Allowed" (the alias is the member's own in the real catalog).
        public Task<(string ProviderId, string ModelId)?> ReferenceForMemberAsync(string organizationId, string memberId, IReadOnlyList<string> teamIds, ModelChoice choice) =>
            Task.FromResult(choice.ModelId == "model-unreachable" ? null : ((string, string)?)(choice.ProviderId, "alias-" + choice.ModelId));
    }
}

public sealed class PolicyTests : IClassFixture<PolicyFactory>
{
    private readonly PolicyFactory _factory;
    public PolicyTests(PolicyFactory factory) => _factory = factory;

    private const string MissingTeam = "tem_01h2xcejqtf2nbrexx3vqjhp41";
    private static readonly string[] Keys = DesktopPolicyRules.Keys.ToArray();

    private static async Task<JsonElement> OkAsync(Workspace w, Person p, HttpMethod m, string url, object? body = null)
    {
        var r = await w.CallAsync(p, m, url, body);
        Assert.True((int)r.Status is >= 200 and < 300, $"{m} {url}: {r.Status} {r.Body}");
        return r.Body;
    }

    private static async Task<JsonElement> ConfigAsync(Workspace w, Person p) => await OkAsync(w, p, HttpMethod.Get, "/v1/me/desktop-config");

    private static string[] Off(JsonElement config) => Keys.Where(k => !config.GetProperty(k).GetBoolean()).ToArray();

    private static async Task<string> PolicyAsync(Workspace w, object body)
    {
        var r = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/desktop-policies", body);
        Assert.True(r.Status == HttpStatusCode.Created, $"{r.Status} {r.Body}");
        return r.Body.GetProperty("desktopPolicy").GetProperty("id").GetString()!;
    }

    // ---------------------------------------------------------------- validation

    [Fact]
    public async Task Desktop_policy_requests_are_validated_and_name_only_what_exists()
    {
        var w = await Workspace.CreateAsync(_factory);
        var team = await w.TeamAsync("Design");
        async Task<HttpStatusCode> Post(object body) => (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/desktop-policies", body)).Status;
        Assert.Equal(HttpStatusCode.BadRequest, await Post(new { policyName = " ", policy = new { } }));
        Assert.Equal(HttpStatusCode.BadRequest, await Post(new { policy = new { } }));
        Assert.Equal(HttpStatusCode.BadRequest, await Post(new { policyName = "x" }));
        Assert.Equal(HttpStatusCode.BadRequest, await Post(new { policyName = "x", policy = new { allowZenModel = "no" } }));
        Assert.Equal(HttpStatusCode.BadRequest, await Post(new { policyName = "x", policy = new { }, priority = -1 }));
        Assert.Equal(HttpStatusCode.BadRequest, await Post(new { policyName = "x", policy = new { }, priority = 1.5 }));
        Assert.Equal(HttpStatusCode.BadRequest, await Post(new { policyName = "x", policy = new { }, roles = new[] { "boss" } }));
        Assert.Equal(HttpStatusCode.BadRequest, await Post(new { policyName = "x", policy = new { }, teamIds = new[] { "nope" } }));
        Assert.Equal(HttpStatusCode.BadRequest, await Post(new { policyName = "x", policy = new { onboardingPrompts = new[] { "one" } } }));
        Assert.Equal(HttpStatusCode.BadRequest, await Post(new { policyName = "x", policy = new { onboardingPrompts = new[] { "a", " " } } }));
        Assert.Equal(HttpStatusCode.BadRequest, await Post(new { policyName = "x", policy = new { execution = new { commands = "maybe" } } }));
        Assert.Equal(HttpStatusCode.BadRequest, await Post(new { policyName = "x", policy = new { execution = new { browserOrigins = new[] { "https://user:pw@a.com" } } } }));
        Assert.Equal(HttpStatusCode.BadRequest, await Post(new { policyName = "x", policy = new { execution = new { browserOrigins = new[] { "javascript:alert(1)" } } } }));
        var missingTeam = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/desktop-policies", new { policyName = "x", policy = new { }, teamIds = new[] { MissingTeam } });
        Assert.Equal("team_not_found", missingTeam.Error());
        Assert.Equal("member_not_found", (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/desktop-policies", new { policyName = "x", policy = new { }, memberIds = new[] { "om_01h2xcejqtf2nbrexx3vqjhp41" } })).Error());
        // Nothing was half-created: only the default policy exists.
        Assert.Single((await OkAsync(w, w.Owner, HttpMethod.Get, "/v1/desktop-policies")).GetProperty("desktopPolicies").EnumerateArray());
        var ok = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/desktop-policies", new { policyName = "Fine", policy = new { execution = new { browserOrigins = new[] { "HTTPS://A.com:443/" } } }, teamIds = new[] { team, team } });
        Assert.Equal(HttpStatusCode.Created, ok.Status);
        Assert.Equal("https://a.com", ok.Body.GetProperty("desktopPolicy").GetProperty("policy").GetProperty("execution").GetProperty("browserOrigins")[0].GetString());
        Assert.Single(ok.Body.GetProperty("desktopPolicy").GetProperty("assignments").EnumerateArray());   // a repeated team collapses
    }

    [Fact]
    public async Task Agent_permission_prompt_and_model_writes_are_validated()
    {
        var w = await Workspace.CreateAsync(_factory);
        async Task<(HttpStatusCode Status, JsonElement Body)> Agent(object settings) => await w.CallAsync(w.Owner, HttpMethod.Put, "/v1/agent-permissions/everyone", new { settings });
        Assert.Equal(HttpStatusCode.BadRequest, (await Agent(new { webSearch = new { decision = "ask" } })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await Agent(new { fileEdits = new { block = new[] { "x" } } })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await Agent(new { websites = new { allow = new[] { "not a site" } } })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await Agent(new { websites = new { allow = new[] { "a.com/*/b" } } })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await Agent(new { commands = new { allow = Enumerable.Range(0, 101).Select(i => "c" + i).ToArray() } })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await Agent(new { unknown = new { } })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Put, "/v1/agent-permissions/everyone", new { settings = new { }, extra = 1 })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Put, "/v1/agent-permissions/teams/not-an-id", new { settings = new { } })).Status);
        Assert.Equal("team_not_found", (await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/agent-permissions/teams/{MissingTeam}", new { settings = new { } })).Error());

        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Put, "/v1/org/prompts/everyone", new { content = "  " })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Put, "/v1/org/prompts/everyone", new { content = new string('x', 20_001) })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Put, "/v1/org/prompts/everyone", new { content = 5 })).Status);
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Put, "/v1/org/prompts/everyone", new { content = new string('x', 20_000) })).Status);

        Assert.Equal("unknown_model", (await w.CallAsync(w.Owner, HttpMethod.Put, "/v1/org/default-model/everyone", new { model = new { providerId = "p", modelId = "nope" } })).Error());
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Put, "/v1/org/default-model/everyone", new { model = new { providerId = " ", modelId = "x" } })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Put, "/v1/org/default-model/everyone", new { })).Status);
    }

    // ---------------------------------------------------------------- permissions

    [Fact]
    public async Task Every_policy_route_needs_its_permission_and_says_which()
    {
        var w = await Workspace.CreateAsync(_factory);
        var member = await w.AddAsync();
        var team = await w.TeamAsync("Design");
        async Task Denied(HttpMethod method, string url, string permission, object? body = null)
        {
            var r = await w.CallAsync(member, method, url, body);
            Assert.True(r.Status == HttpStatusCode.Forbidden, $"{method} {url}: {r.Status}");
            Assert.Equal(permission, r.Required());
        }
        await Denied(HttpMethod.Get, "/v1/desktop-policies", "desktop_policies.view");
        await Denied(HttpMethod.Post, "/v1/desktop-policies", "desktop_policies.manage", new { policyName = "x", policy = new { } });
        await Denied(HttpMethod.Put, "/v1/desktop-policies/by-key/k", "desktop_policies.manage", new { policyName = "x", policy = new { } });
        await Denied(HttpMethod.Delete, "/v1/desktop-policies/by-key/k", "desktop_policies.manage");
        await Denied(HttpMethod.Get, "/v1/agent-permissions", "agent_permissions.view");
        await Denied(HttpMethod.Put, "/v1/agent-permissions/everyone", "agent_permissions.manage", new { settings = new { } });
        await Denied(HttpMethod.Delete, $"/v1/agent-permissions/teams/{team}", "agent_permissions.manage");
        await Denied(HttpMethod.Get, "/v1/org/prompts", "prompts.view");
        await Denied(HttpMethod.Put, $"/v1/org/prompts/teams/{team}", "prompts.manage", new { content = "x" });
        await Denied(HttpMethod.Delete, "/v1/org/prompts/everyone", "prompts.manage");
        await Denied(HttpMethod.Get, "/v1/org/default-model", "inference.view");
        await Denied(HttpMethod.Get, "/v1/org/default-model/options", "inference.view");
        await Denied(HttpMethod.Put, "/v1/org/default-model/everyone", "inference.manage", new { model = (object?)null });
        await Denied(HttpMethod.Put, "/v1/org/automation-settings", "organization.update", new { desktop = true });
        await Denied(HttpMethod.Put, "/v1/org/workbot-settings", "inference.manage", new { model = (object?)null });
        await Denied(HttpMethod.Get, "/v1/org/workbot-settings", "inference.view");
        // What a person's own desktop receives needs no permission, only membership.
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(member, HttpMethod.Get, "/v1/me/desktop-config")).Status);
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(member, HttpMethod.Get, "/v1/me/prompts")).Status);
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(member, HttpMethod.Get, "/v1/org/workbot-readiness")).Status);
        // Not signed in: 401. Signed in but not a member of this workspace: 404.
        var anonymous = await w.Http.GetAsync("/v1/me/desktop-config");
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        var stranger = await Workspace.CreateAsync(_factory);
        var request = Bearer(HttpMethod.Get, "/v1/me/desktop-config", stranger.Owner.Token);
        request.Headers.Add("x-openwork-org-id", w.OrgId);
        Assert.Equal(HttpStatusCode.NotFound, (await w.Http.SendAsync(request)).StatusCode);
    }

    [Fact]
    public async Task A_team_role_can_hand_out_policy_permissions_and_the_owner_stays_the_only_default_manager_of_agent_permissions()
    {
        var w = await Workspace.CreateAsync(_factory);
        var admin = await w.AddAsync("admin");
        var carol = await w.AddAsync();
        // An admin may view agent permissions but not change them by default.
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(admin, HttpMethod.Get, "/v1/agent-permissions")).Status);
        Assert.Equal("agent_permissions.manage", (await w.CallAsync(admin, HttpMethod.Put, "/v1/agent-permissions/everyone", new { settings = new { } })).Required());
        var ops = await w.TeamAsync("Ops", carol);
        await w.RoleAsync(ops, "agent_permissions.view", "agent_permissions.manage", "prompts.manage");
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(carol, HttpMethod.Put, "/v1/agent-permissions/everyone", new { settings = new { webSearch = new { decision = "deny" } } })).Status);
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(carol, HttpMethod.Put, "/v1/org/prompts/everyone", new { content = "hi" })).Status);
        // canEdit follows the permission.
        Assert.True((await w.CallAsync(carol, HttpMethod.Get, "/v1/agent-permissions")).Body.GetProperty("canEdit").GetBoolean());
        Assert.False((await w.CallAsync(admin, HttpMethod.Get, "/v1/agent-permissions")).Body.GetProperty("canEdit").GetBoolean());
    }

    [Fact]
    public async Task Changing_policy_needs_a_recent_sign_in()
    {
        var w = await Workspace.CreateAsync(_factory);
        var team = await w.TeamAsync("Design");
        _factory.WithDb(db => db.Database.ExecuteSqlRaw("UPDATE Sessions SET CreatedAt = {0} WHERE UserId = {1}", DateTime.UtcNow.AddHours(-3), w.Owner.UserId));
        async Task Reauth(HttpMethod method, string url, object? body = null)
        {
            var r = await w.CallAsync(w.Owner, method, url, body);
            Assert.Equal(HttpStatusCode.Forbidden, r.Status);
            Assert.Equal("reauth", r.Body.GetProperty("error").GetString());
        }
        await Reauth(HttpMethod.Put, "/v1/org/prompts/everyone", new { content = "x" });
        await Reauth(HttpMethod.Delete, $"/v1/org/prompts/teams/{team}");
        await Reauth(HttpMethod.Put, "/v1/org/default-model/everyone", new { model = (object?)null });
        await Reauth(HttpMethod.Put, "/v1/org/workbot-settings", new { model = (object?)null });
        // Reading is not sensitive.
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/org/prompts")).Status);
    }

    // ---------------------------------------------------------------- isolation

    [Fact]
    public async Task Policy_of_another_workspace_is_invisible_and_cannot_be_reached_by_id()
    {
        var w1 = await Workspace.CreateAsync(_factory);
        var w2 = await Workspace.CreateAsync(_factory);
        var policy = await PolicyAsync(w1, new { policyName = "Private", policy = new { allowZenModel = false } });
        var theirTeam = await w1.TeamAsync("Private team");
        await w1.CallAsync(w1.Owner, HttpMethod.Put, $"/v1/org/prompts/teams/{theirTeam}", new { content = "secret" });
        await w1.CallAsync(w1.Owner, HttpMethod.Put, $"/v1/agent-permissions/teams/{theirTeam}", new { settings = new { webSearch = new { decision = "deny" } } });

        Assert.Equal(HttpStatusCode.NotFound, (await w2.CallAsync(w2.Owner, HttpMethod.Get, $"/v1/desktop-policies/{policy}")).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await w2.CallAsync(w2.Owner, HttpMethod.Patch, $"/v1/desktop-policies/{policy}", new { policyName = "Mine", policy = new { } })).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await w2.CallAsync(w2.Owner, HttpMethod.Delete, $"/v1/desktop-policies/{policy}")).Status);
        Assert.Equal("team_not_found", (await w2.CallAsync(w2.Owner, HttpMethod.Put, $"/v1/agent-permissions/teams/{theirTeam}", new { settings = new { } })).Error());
        Assert.Equal("team_not_found", (await w2.CallAsync(w2.Owner, HttpMethod.Put, $"/v1/org/prompts/teams/{theirTeam}", new { content = "x" })).Error());
        Assert.Equal("team_not_found", (await w2.CallAsync(w2.Owner, HttpMethod.Delete, $"/v1/org/prompts/teams/{theirTeam}")).Error());
        Assert.Equal("team_not_found", (await w2.CallAsync(w2.Owner, HttpMethod.Put, $"/v1/org/default-model/teams/{theirTeam}", new { model = (object?)null })).Error());
        Assert.Equal("team_not_found", (await w2.CallAsync(w2.Owner, HttpMethod.Post, "/v1/desktop-policies", new { policyName = "x", policy = new { }, teamIds = new[] { theirTeam } })).Error());
        Assert.Equal("member_not_found", (await w2.CallAsync(w2.Owner, HttpMethod.Post, "/v1/desktop-policies", new { policyName = "x", policy = new { }, memberIds = new[] { w1.Owner.MemberId } })).Error());
        // Nothing of the first workspace shows in the second's lists or its owner's desktop config.
        var list = await OkAsync(w2, w2.Owner, HttpMethod.Get, "/v1/desktop-policies");
        Assert.Single(list.GetProperty("desktopPolicies").EnumerateArray());
        Assert.Empty((await OkAsync(w2, w2.Owner, HttpMethod.Get, "/v1/org/prompts")).GetProperty("teams").EnumerateArray());
        Assert.Empty((await ConfigAsync(w2, w2.Owner)).GetProperty("agentPermissions").GetProperty("rules").EnumerateArray());
        Assert.Empty((await OkAsync(w2, w2.Owner, HttpMethod.Get, "/v1/me/prompts")).GetProperty("prompts").EnumerateArray());
        // The first workspace's policy is unharmed, and a key is only unique within a workspace.
        Assert.Equal(HttpStatusCode.OK, (await w1.CallAsync(w1.Owner, HttpMethod.Get, $"/v1/desktop-policies/{policy}")).Status);
        Assert.Equal(HttpStatusCode.Created, (await w1.CallAsync(w1.Owner, HttpMethod.Put, "/v1/desktop-policies/by-key/shared-key", new { policyName = "A", policy = new { } })).Status);
        Assert.Equal(HttpStatusCode.Created, (await w2.CallAsync(w2.Owner, HttpMethod.Put, "/v1/desktop-policies/by-key/shared-key", new { policyName = "B", policy = new { } })).Status);
    }

    [Fact]
    public async Task Settings_and_the_default_policy_belong_to_their_workspace()
    {
        var w1 = await Workspace.CreateAsync(_factory);
        var w2 = await Workspace.CreateAsync(_factory);
        await OkAsync(w1, w1.Owner, HttpMethod.Put, "/v1/org/automation-settings", new { desktop = false });
        Assert.False((await OkAsync(w1, w1.Owner, HttpMethod.Get, "/v1/org/automation-settings")).GetProperty("settings").GetProperty("desktop").GetBoolean());
        Assert.True((await OkAsync(w2, w2.Owner, HttpMethod.Get, "/v1/org/automation-settings")).GetProperty("settings").GetProperty("desktop").GetBoolean());
        var d1 = (await OkAsync(w1, w1.Owner, HttpMethod.Get, "/v1/desktop-policies")).GetProperty("desktopPolicies")[0].GetProperty("id").GetString();
        var d2 = (await OkAsync(w2, w2.Owner, HttpMethod.Get, "/v1/desktop-policies")).GetProperty("desktopPolicies")[0].GetProperty("id").GetString();
        Assert.NotEqual(d1, d2);
    }

    // ---------------------------------------------------------------- cleanup when teams and people go

    [Fact]
    public async Task Deleting_a_team_removes_everything_set_for_it_and_removing_a_person_removes_what_was_assigned_to_them()
    {
        var w = await Workspace.CreateAsync(_factory);
        var mia = await w.AddAsync();
        var team = await w.TeamAsync("Gone soon", mia);
        var policy = await PolicyAsync(w, new { policyName = "T", policy = new { access = new { mode = "custom", capabilities = new { allowZenModel = false } } }, teamIds = new[] { team }, memberIds = new[] { mia.MemberId } });
        await OkAsync(w, w.Owner, HttpMethod.Put, $"/v1/agent-permissions/teams/{team}", new { settings = new { webSearch = new { decision = "deny" } } });
        await OkAsync(w, w.Owner, HttpMethod.Put, $"/v1/org/prompts/teams/{team}", new { content = "team prompt" });
        await OkAsync(w, w.Owner, HttpMethod.Put, $"/v1/org/default-model/teams/{team}", new { model = new { providerId = PolicyFactory.Provider, modelId = "model-a" } });
        Assert.Contains("allowZenModel", Off(await ConfigAsync(w, mia)));
        Assert.Single((await OkAsync(w, mia, HttpMethod.Get, "/v1/me/prompts")).GetProperty("prompts").EnumerateArray());

        Assert.Equal(HttpStatusCode.NoContent, (await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/teams/{team}")).Status);
        Assert.Equal(0, _factory.WithDb(db => db.Set<DesktopPolicyAssignment>().Count(p => p.TeamId == team)));
        Assert.Contains("allowZenModel", Off(await ConfigAsync(w, mia)));                // still applies, through her own assignment
        Assert.Equal(0, _factory.WithDb(db => db.Set<AgentPermissionPolicy>().Count(p => p.OrganizationId == w.OrgId)));
        Assert.Equal(0, _factory.WithDb(db => db.Set<OrgPrompt>().Count(p => p.OrganizationId == w.OrgId)));
        Assert.Equal(0, _factory.WithDb(db => db.Set<OrgDefaultModel>().Count(p => p.OrganizationId == w.OrgId)));
        Assert.Equal(1, _factory.WithDb(db => db.Set<DesktopPolicyAssignment>().Count(p => p.PolicyId == policy)));   // the person's own assignment stays
        Assert.Empty((await OkAsync(w, mia, HttpMethod.Get, "/v1/me/prompts")).GetProperty("prompts").EnumerateArray());
        Assert.Empty((await OkAsync(w, w.Owner, HttpMethod.Get, "/v1/org/prompts")).GetProperty("teams").EnumerateArray());

        // Removing the person removes her assignment as well; the policy itself stays.
        Assert.Equal(HttpStatusCode.NoContent, (await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/members/{mia.MemberId}")).Status);
        Assert.Equal(0, _factory.WithDb(db => db.Set<DesktopPolicyAssignment>().Count(p => p.PolicyId == policy)));
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/desktop-policies/{policy}")).Status);
    }

    [Fact]
    public async Task What_a_person_receives_follows_their_membership_at_once()
    {
        var w = await Workspace.CreateAsync(_factory);
        var mia = await w.AddAsync();
        var team = await w.TeamAsync("Locked down");
        await PolicyAsync(w, new { policyName = "Locked", policy = new { access = new { mode = "locked", capabilities = new { } } }, teamIds = new[] { team } });
        await OkAsync(w, w.Owner, HttpMethod.Put, $"/v1/org/prompts/teams/{team}", new { content = "Careful." });
        await OkAsync(w, w.Owner, HttpMethod.Put, $"/v1/agent-permissions/teams/{team}", new { settings = new { webSearch = new { decision = "deny" } } });
        Assert.Empty(Off(await ConfigAsync(w, mia)));
        await OkAsync(w, w.Owner, HttpMethod.Patch, $"/v1/teams/{team}", new { memberIds = new[] { mia.MemberId } });
        Assert.Equal(7, Off(await ConfigAsync(w, mia)).Length);
        Assert.Single((await ConfigAsync(w, mia)).GetProperty("agentPermissions").GetProperty("rules").EnumerateArray());
        Assert.Equal("Careful.", (await OkAsync(w, mia, HttpMethod.Get, "/v1/me/prompts")).GetProperty("prompts")[0].GetProperty("content").GetString());
        await OkAsync(w, w.Owner, HttpMethod.Patch, $"/v1/teams/{team}", new { memberIds = Array.Empty<string>() });
        Assert.Empty(Off(await ConfigAsync(w, mia)));
        Assert.Empty((await ConfigAsync(w, mia)).GetProperty("agentPermissions").GetProperty("rules").EnumerateArray());
    }

    [Fact]
    public async Task A_policy_for_a_role_follows_a_role_change_and_an_Admin_team()
    {
        var w = await Workspace.CreateAsync(_factory);
        var mia = await w.AddAsync();
        await PolicyAsync(w, new { policyName = "Admins only", policy = new { access = new { mode = "custom", capabilities = new { allowControlSettings = false } } }, roles = new[] { "admin" } });
        Assert.Empty(Off(await ConfigAsync(w, mia)));
        Assert.Contains("allowControlSettings", Off(await ConfigAsync(w, w.Owner)));   // an owner matches the admin role too
        var ops = await OkAsync(w, w.Owner, HttpMethod.Post, "/v1/teams", new { name = "Ops", grantsOrganizationAdmin = true, memberIds = new[] { mia.MemberId } });
        Assert.Contains("allowControlSettings", Off(await ConfigAsync(w, mia)));
        await OkAsync(w, w.Owner, HttpMethod.Delete, $"/v1/teams/{ops.GetProperty("team").GetProperty("id").GetString()}");
        Assert.Empty(Off(await ConfigAsync(w, mia)));
    }

    // ---------------------------------------------------------------- default policy and soft delete

    [Fact]
    public async Task The_default_policy_is_made_once_even_when_many_requests_ask_at_the_same_moment()
    {
        var w = await Workspace.CreateAsync(_factory);
        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => w.CallAsync(w.Owner, HttpMethod.Get, "/v1/desktop-policies")));
        Assert.All(results, r => Assert.Equal(HttpStatusCode.OK, r.Status));
        Assert.Equal(1, _factory.WithDb(db => db.Set<DesktopPolicy>().Count(p => p.OrganizationId == w.OrgId && p.IsDefault)));
        Assert.Single((await OkAsync(w, w.Owner, HttpMethod.Get, "/v1/desktop-policies")).GetProperty("desktopPolicies").EnumerateArray());
    }

    [Fact]
    public async Task Deleting_a_policy_hides_it_frees_its_key_and_stops_it_applying()
    {
        var w = await Workspace.CreateAsync(_factory);
        var mia = await w.AddAsync();
        var put = await w.CallAsync(w.Owner, HttpMethod.Put, "/v1/desktop-policies/by-key/limits", new { policyName = "Limits", policy = new { access = new { mode = "locked", capabilities = new { } } }, roles = new[] { "member" } });
        Assert.Equal(HttpStatusCode.Created, put.Status);
        Assert.Equal(7, Off(await ConfigAsync(w, mia)).Length);
        var id = put.Body.GetProperty("desktopPolicy").GetProperty("id").GetString();
        Assert.Equal(HttpStatusCode.NoContent, (await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/desktop-policies/{id}")).Status);
        Assert.Empty(Off(await ConfigAsync(w, mia)));
        Assert.Equal(HttpStatusCode.NotFound, (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/desktop-policies/by-key/limits")).Status);
        var again = await w.CallAsync(w.Owner, HttpMethod.Put, "/v1/desktop-policies/by-key/limits", new { policyName = "Limits again", policy = new { } });
        Assert.Equal(HttpStatusCode.Created, again.Status);
        Assert.NotEqual(id, again.Body.GetProperty("desktopPolicy").GetProperty("id").GetString());
        // The default policy can never go: not by id, not disabled.
        var def = (await OkAsync(w, w.Owner, HttpMethod.Get, "/v1/desktop-policies")).GetProperty("desktopPolicies")[0].GetProperty("id").GetString();
        Assert.Equal("default_policy_required", (await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/desktop-policies/{def}")).Error());
        Assert.Equal("default_policy_required", (await w.CallAsync(w.Owner, HttpMethod.Patch, $"/v1/desktop-policies/{def}", new { policyName = "x", policy = new { }, isEnabled = false })).Error());
    }

    // ---------------------------------------------------------------- concurrency

    [Fact]
    public async Task Applying_the_same_key_at_once_makes_one_policy()
    {
        var w = await Workspace.CreateAsync(_factory);
        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(i => w.CallAsync(w.Owner, HttpMethod.Put, "/v1/desktop-policies/by-key/racers", new { policyName = "Racer " + i, policy = new { } })));
        Assert.All(results, r => Assert.True(r.Status is HttpStatusCode.Created or HttpStatusCode.OK or HttpStatusCode.Conflict, r.Status.ToString()));
        Assert.True(results.Count(r => r.Status == HttpStatusCode.Created) == 1, string.Join(",", results.Select(r => (int)r.Status)));
        Assert.Equal(1, _factory.WithDb(db => db.Set<DesktopPolicy>().Count(p => p.OrganizationId == w.OrgId && p.ExternalKey == "racers" && p.DeletedAt == null)));
    }

    [Fact]
    public async Task Replacing_assignments_at_once_never_leaves_duplicates()
    {
        var w = await Workspace.CreateAsync(_factory);
        var mia = await w.AddAsync();
        var team = await w.TeamAsync("Racing", mia);
        var id = await PolicyAsync(w, new { policyName = "Race", policy = new { } });
        var body = new { policyName = "Race", policy = new { }, teamIds = new[] { team }, memberIds = new[] { mia.MemberId }, roles = new[] { "member" } };
        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => w.CallAsync(w.Owner, HttpMethod.Patch, $"/v1/desktop-policies/{id}", body)));
        Assert.All(results, r => Assert.True(r.Status is HttpStatusCode.OK or HttpStatusCode.Conflict, $"{r.Status} {r.Body}"));
        Assert.Contains(results, r => r.Status == HttpStatusCode.OK);
        Assert.Equal(3, _factory.WithDb(db => db.Set<DesktopPolicyAssignment>().Count(a => a.PolicyId == id)));
        Assert.Equal(3, (await OkAsync(w, w.Owner, HttpMethod.Get, $"/v1/desktop-policies/{id}")).GetProperty("desktopPolicy").GetProperty("assignments").GetArrayLength());
    }

    [Fact]
    public async Task First_saves_of_one_scope_at_once_make_one_row_and_never_fail()
    {
        var w = await Workspace.CreateAsync(_factory);
        var team = await w.TeamAsync("Racing");
        var agent = await Task.WhenAll(Enumerable.Range(0, 8).Select(i => w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/agent-permissions/teams/{team}", new { settings = new { commands = new { decision = i % 2 == 0 ? "ask" : "deny" } } })));
        Assert.All(agent, r => Assert.Equal(HttpStatusCode.OK, r.Status));
        var prompts = await Task.WhenAll(Enumerable.Range(0, 8).Select(i => w.CallAsync(w.Owner, HttpMethod.Put, "/v1/org/prompts/everyone", new { content = "v" + i })));
        Assert.All(prompts, r => Assert.Equal(HttpStatusCode.OK, r.Status));
        var models = await Task.WhenAll(Enumerable.Range(0, 8).Select(i => w.CallAsync(w.Owner, HttpMethod.Put, "/v1/org/default-model/everyone", new { model = new { providerId = PolicyFactory.Provider, modelId = i % 2 == 0 ? "model-a" : "model-b" } })));
        Assert.All(models, r => Assert.Equal(HttpStatusCode.OK, r.Status));
        Assert.Equal(1, _factory.WithDb(db => db.Set<AgentPermissionPolicy>().Count(p => p.OrganizationId == w.OrgId)));
        Assert.Equal(1, _factory.WithDb(db => db.Set<OrgPrompt>().Count(p => p.OrganizationId == w.OrgId)));
        Assert.Equal(1, _factory.WithDb(db => db.Set<OrgDefaultModel>().Count(p => p.OrganizationId == w.OrgId)));
    }

    [Fact]
    public async Task Automation_settings_changed_at_once_keep_both_choices_in_one_row()
    {
        var w = await Workspace.CreateAsync(_factory);
        var results = await Task.WhenAll(Enumerable.Range(0, 6).Select(i => w.CallAsync(w.Owner, HttpMethod.Put, "/v1/org/automation-settings", i % 2 == 0 ? new { desktop = false } : new { cloud = false })));
        Assert.All(results, r => Assert.Equal(HttpStatusCode.OK, r.Status));
        Assert.Equal(1, _factory.WithDb(db => db.Set<OrgPolicySettings>().Count(s => s.Id == w.OrgId)));
        var settings = (await OkAsync(w, w.Owner, HttpMethod.Get, "/v1/org/automation-settings")).GetProperty("settings");
        Assert.False(settings.GetProperty("desktop").GetBoolean());
        Assert.False(settings.GetProperty("cloud").GetBoolean());
    }

    // ---------------------------------------------------------------- agent permissions through the API

    [Fact]
    public async Task Agent_permissions_resolve_for_each_person_from_everyone_and_their_teams()
    {
        var w = await Workspace.CreateAsync(_factory);
        var mia = await w.AddAsync();
        var ann = await w.AddAsync();
        var design = await w.TeamAsync("Design", mia);
        var audit = await w.TeamAsync("Audit", mia);
        await OkAsync(w, w.Owner, HttpMethod.Put, "/v1/agent-permissions/everyone", new { settings = new { commands = new { decision = "ask", allow = new[] { "git status" }, block = new[] { "rm *" } } } });
        await OkAsync(w, w.Owner, HttpMethod.Put, $"/v1/agent-permissions/teams/{design}", new { settings = new { commands = new { decision = "deny" } } });
        await OkAsync(w, w.Owner, HttpMethod.Put, $"/v1/agent-permissions/teams/{audit}", new { settings = new { commands = new { decision = "ask" } } });
        string Rules(JsonElement config) => string.Join(" | ", config.GetProperty("agentPermissions").GetProperty("rules").EnumerateArray().Select(r => $"{r.GetProperty("action").GetString()} {r.GetProperty("resource").GetString()} {r.GetProperty("effect").GetString()} {r.GetProperty("source").GetString()}"));
        // Mia: deny (Design) beats ask (Audit); everyone's allowed "git status" is in both teams' lists, so it stays an exception.
        Assert.Equal("shell * deny Design | shell git status allow Everyone | shell rm * deny Everyone", Rules(await ConfigAsync(w, mia)));
        Assert.Equal("shell * ask Everyone | shell git status allow Everyone | shell rm * deny Everyone", Rules(await ConfigAsync(w, ann)));
        // The listing shows the stored form and real team sizes.
        var list = await OkAsync(w, w.Owner, HttpMethod.Get, "/v1/agent-permissions");
        Assert.Equal(new[] { "Audit", "Design" }, list.GetProperty("teams").EnumerateArray().Select(t => t.GetProperty("name").GetString()!).ToArray());
        Assert.All(list.GetProperty("teams").EnumerateArray(), t => Assert.Equal(1, t.GetProperty("memberCount").GetInt32()));
    }

    // ---------------------------------------------------------------- default model through the API

    [Fact]
    public async Task The_default_model_is_chosen_from_the_catalog_and_delivered_as_the_persons_own_reference()
    {
        var w = await Workspace.CreateAsync(_factory);
        var mia = await w.AddAsync();
        var ann = await w.AddAsync();
        var teamA = await w.TeamAsync("Alpha", mia);
        var teamB = await w.TeamAsync("Beta", mia, ann);
        var options = await OkAsync(w, w.Owner, HttpMethod.Get, "/v1/org/default-model/options");
        Assert.Equal(2, options.GetProperty("options").GetArrayLength());
        Assert.Equal("Model A", options.GetProperty("options")[0].GetProperty("modelName").GetString());
        Assert.Equal("unknown_model", (await w.CallAsync(w.Owner, HttpMethod.Put, "/v1/org/default-model/everyone", new { model = new { providerId = PolicyFactory.Provider, modelId = "model-zzz" } })).Error());

        Assert.False((await ConfigAsync(w, mia)).TryGetProperty("defaultModel", out _));                       // nothing chosen
        await OkAsync(w, w.Owner, HttpMethod.Put, "/v1/org/default-model/everyone", new { model = new { providerId = PolicyFactory.Provider, modelId = "model-a" } });
        var d = (await ConfigAsync(w, mia)).GetProperty("defaultModel");
        Assert.Equal(("alias-model-a", "organization"), (d.GetProperty("modelID").GetString(), d.GetProperty("source").GetString()));
        Assert.Equal(PolicyFactory.Provider, d.GetProperty("providerID").GetString());

        // One team overrides: its members get that model, the others the organization's.
        await OkAsync(w, w.Owner, HttpMethod.Put, $"/v1/org/default-model/teams/{teamA}", new { model = new { providerId = PolicyFactory.Provider, modelId = "model-b" } });
        var viaTeam = (await ConfigAsync(w, mia)).GetProperty("defaultModel");
        Assert.Equal(("alias-model-b", "team", "Alpha"), (viaTeam.GetProperty("modelID").GetString(), viaTeam.GetProperty("source").GetString(), viaTeam.GetProperty("teamName").GetString()));
        Assert.Equal("alias-model-a", (await ConfigAsync(w, ann)).GetProperty("defaultModel").GetProperty("modelID").GetString());

        // Two teams disagree: Mia starts on the organization default, and the listing counts her on both teams.
        await OkAsync(w, w.Owner, HttpMethod.Put, $"/v1/org/default-model/teams/{teamB}", new { model = new { providerId = PolicyFactory.Provider, modelId = "model-a" } });
        Assert.Equal("organization", (await ConfigAsync(w, mia)).GetProperty("defaultModel").GetProperty("source").GetString());
        var view = await OkAsync(w, w.Owner, HttpMethod.Get, "/v1/org/default-model");
        Assert.Equal(new[] { 1, 1 }, view.GetProperty("teams").EnumerateArray().Select(t => t.GetProperty("conflictingMemberCount").GetInt32()).ToArray());
        Assert.Equal("model-a", view.GetProperty("everyone").GetProperty("modelId").GetString());

        // Clearing the organization default leaves a conflicted person with nothing; clearing a team's override resolves the conflict.
        await OkAsync(w, w.Owner, HttpMethod.Put, "/v1/org/default-model/everyone", new { model = (object?)null });
        Assert.False((await ConfigAsync(w, mia)).TryGetProperty("defaultModel", out _));
        await OkAsync(w, w.Owner, HttpMethod.Put, $"/v1/org/default-model/teams/{teamA}", new { model = (object?)null });
        Assert.Equal("alias-model-a", (await ConfigAsync(w, mia)).GetProperty("defaultModel").GetProperty("modelID").GetString());

        // A model the person cannot reach is not sent.
        _factory.WithDb(db =>
        {
            var row = db.Set<OrgDefaultModel>().Single(r => r.OrganizationId == w.OrgId && r.TeamId == teamB);
            row.ModelId = "model-unreachable";
            db.SaveChanges();
            return 0;
        });
        Assert.False((await ConfigAsync(w, mia)).TryGetProperty("defaultModel", out _));
    }

    // ---------------------------------------------------------------- settings

    [Fact]
    public async Task Automation_settings_reach_the_desktop_and_cloud_needs_a_runner()
    {
        var w = await Workspace.CreateAsync(_factory);
        var mia = await w.AddAsync();
        var before = await ConfigAsync(w, mia);
        Assert.True(before.GetProperty("automationsEnabled").GetBoolean());
        Assert.True(before.GetProperty("desktopAutomationsEnabled").GetBoolean());
        Assert.False(before.GetProperty("cloudAutomationsEnabled").GetBoolean());
        var cloud = await w.CallAsync(w.Owner, HttpMethod.Put, "/v1/org/automation-settings", new { cloud = true });
        Assert.Equal("headless_runner_required", cloud.Error());
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Put, "/v1/org/automation-settings", new { })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Put, "/v1/org/automation-settings", new { desktop = true, other = 1 })).Status);
        await OkAsync(w, w.Owner, HttpMethod.Put, "/v1/org/automation-settings", new { desktop = false });
        var after = await ConfigAsync(w, mia);
        Assert.False(after.GetProperty("desktopAutomationsEnabled").GetBoolean());
        Assert.False(after.GetProperty("automationsEnabled").GetBoolean());
    }

    [Fact]
    public async Task Workbot_settings_accept_only_the_default_without_a_runner_and_the_auto_router_is_off()
    {
        var w = await Workspace.CreateAsync(_factory);
        var model = await w.CallAsync(w.Owner, HttpMethod.Put, "/v1/org/workbot-settings", new { model = "openai/gpt-5" });
        Assert.Equal(HttpStatusCode.ServiceUnavailable, model.Status);
        Assert.Equal("workbot_runner_unavailable", model.Error());
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Put, "/v1/org/workbot-settings", new { model = (object?)null })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Put, "/v1/org/workbot-settings", new { })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Put, "/v1/org/workbot-settings", new { model = "x", extra = 1 })).Status);
        var ready = await OkAsync(w, w.Owner, HttpMethod.Get, "/v1/org/workbot-readiness");
        Assert.True(ready.GetProperty("gatewayRequired").GetBoolean());
        Assert.False(ready.GetProperty("hasGatewayProvider").GetBoolean());
        var router = await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/org/auto-router");
        Assert.Equal(HttpStatusCode.NotFound, router.Status);
        Assert.Equal("feature_disabled", router.Error());
    }
}
