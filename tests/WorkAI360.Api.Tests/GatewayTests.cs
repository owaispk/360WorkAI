using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using WorkAI360.Api.Domain.Gateway;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>Gateway on, with the deployment's LiteLLM proxy pointing at an in-process fake.</summary>
public class GatewayFactory : ApiFactory
{
    public const string AdminEmail = "gw.platform.admin@example.com";
    public FakeLiteLlm Fake { get; } = FakeLiteLlm.StartAsync().GetAwaiter().GetResult();
    protected override IEnumerable<KeyValuePair<string, string>> Settings =>
    [
        new("Gateway:Enabled", "true"), new("Gateway:LiteLlm:BaseUrl", Fake.Origin), new("Gateway:LiteLlm:MasterKey", FakeLiteLlm.MasterKey),
        new("Gateway:LiteLlm:PublicUrl", "https://ai.example.com"), new("PlatformAdmin:BootstrapEmails", AdminEmail), .. More,
    ];
    protected virtual IEnumerable<KeyValuePair<string, string>> More => [];
    public override async ValueTask DisposeAsync() { await Fake.DisposeAsync(); await base.DisposeAsync(); }
}

/// <summary>Gateway management off (the default).</summary>
public sealed class GatewayOffFactory : ApiFactory;

file static class Gw
{
    public static async Task<(HttpStatusCode Status, JsonElement Body)> CreateAsync(Workspace w, Person by, object body) =>
        await w.CallAsync(by, HttpMethod.Post, "/v1/inference-providers/litellm", body);

    public static async Task<string> ProviderAsync(Workspace w, object? body = null)
    {
        var r = await CreateAsync(w, w.Owner, body ?? new { useDeploymentProxy = true, allMembers = true });
        Assert.True(r.Status == HttpStatusCode.Created, r.Body.ToString());
        return r.Body.GetProperty("inferenceProvider").GetProperty("id").GetString()!;
    }

    public static async Task<JsonElement> DetailsAsync(Workspace w, string id) =>
        (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/inference-providers/{id}")).Body.GetProperty("inferenceProvider");

    public static string[] Strings(JsonElement e) => e.EnumerateArray().Select(x => x.GetString()!).ToArray();
}

public sealed class GatewayTests(GatewayFactory factory) : IClassFixture<GatewayFactory>
{
    private FakeLiteLlm Fake => factory.Fake;

    [Fact]
    public async Task Creating_on_the_deployment_proxy_syncs_chat_models_makes_a_team_a_group_and_grants_and_returns_no_secret()
    {
        var w = await Workspace.CreateAsync(factory, "Gateway Space");
        var r = await Gw.CreateAsync(w, w.Owner, new { useDeploymentProxy = true, allMembers = true });
        Assert.Equal(HttpStatusCode.Created, r.Status);
        var text = r.Body.ToString();
        Assert.DoesNotContain(FakeLiteLlm.MasterKey, text);
        var p = r.Body.GetProperty("inferenceProvider");
        Assert.Equal("litellm", p.GetProperty("providerId").GetString());
        // The embedding model is left out; wildcard routes too.
        Assert.Equal(["fake-large", "fake-small"], p.GetProperty("models").EnumerateArray().Select(m => m.GetProperty("id").GetString()!).ToArray());
        var large = p.GetProperty("models").EnumerateArray().First(m => m.GetProperty("id").GetString() == "fake-large").GetProperty("config");
        Assert.Equal(3, large.GetProperty("cost").GetProperty("input").GetDouble());
        Assert.Equal(200000, large.GetProperty("limit").GetProperty("context").GetInt32());
        var group = Assert.Single(p.GetProperty("modelGroups").EnumerateArray());
        Assert.Equal("All LiteLLM models", group.GetProperty("name").GetString());
        Assert.Equal("organization", Assert.Single(p.GetProperty("accessGrants").EnumerateArray()).GetProperty("audience").GetProperty("type").GetString());
        Assert.Equal("https://ai.example.com/v1", p.GetProperty("litellm").GetProperty("baseUrl").GetString());
        Assert.Equal(2, r.Body.GetProperty("sync").GetProperty("modelCount").GetInt32());
        var team = Assert.Single(factory.WithDb(db => db.Set<GatewayProvider>().Where(x => x.OrganizationId == w.OrgId).Select(x => x.LiteLlmTeamId).ToList()));
        Assert.Equal(["fake-large", "fake-small"], Fake.Teams[team!].Order().ToArray());
    }

    [Fact]
    public async Task Connect_issues_the_person_one_model_only_LiteLLM_key_in_the_provider_team_and_gives_the_same_key_again()
    {
        var w = await Workspace.CreateAsync(factory);
        var member = await w.AddAsync();
        var id = await Gw.ProviderAsync(w);
        var r = await w.CallAsync(member, HttpMethod.Get, $"/v1/inference-providers/{id}/connect");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        var p = r.Body.GetProperty("inferenceProvider");
        var key = p.GetProperty("apiKey").GetString()!;
        Assert.Equal(key, p.GetProperty("apiKeys").GetProperty("LITELLM_API_KEY").GetString());
        Assert.Equal("https://ai.example.com/v1", p.GetProperty("baseUrl").GetString());
        var issued = Fake.Keys[FakeLiteLlm.HashOf(key)];
        Assert.Equal(member.MemberId, issued.UserId);
        Assert.Equal(["llm_api_routes"], issued.AllowedRoutes);
        Assert.Equal(["fake-large", "fake-small"], issued.Models.Order().ToArray());
        var team = factory.WithDb(db => db.Set<GatewayProvider>().Single(x => x.Id == id).LiteLlmTeamId);
        Assert.Equal(team, issued.TeamId);
        // Stored encrypted, never in clear.
        Assert.DoesNotContain(key, factory.WithDb(db => db.Set<GatewayIssuedKey>().Single(k => k.GatewayProviderId == id).KeyEnc));
        var generated = Fake.Calls.Count(c => c == "POST /key/generate");
        var again = await w.CallAsync(member, HttpMethod.Get, $"/v1/inference-providers/{id}/connect");
        Assert.Equal(key, again.Body.GetProperty("inferenceProvider").GetProperty("apiKey").GetString());
        Assert.Equal(generated, Fake.Calls.Count(c => c == "POST /key/generate"));
        // The key really works against the proxy.
        using var http = new HttpClient();
        using var call = new HttpRequestMessage(HttpMethod.Post, $"{Fake.Origin}/v1/chat/completions") { Content = JsonContent.Create(new { model = "fake-small", messages = new[] { new { role = "user", content = "x" } } }) };
        call.Headers.Authorization = new("Bearer", key);
        Assert.Equal(HttpStatusCode.OK, (await http.SendAsync(call)).StatusCode);
    }

    [Fact]
    public async Task Only_granted_people_see_and_connect_and_grants_reach_through_teams_and_members()
    {
        var w = await Workspace.CreateAsync(factory);
        var inTeam = await w.AddAsync();
        var named = await w.AddAsync();
        var outsider = await w.AddAsync();
        var id = await Gw.ProviderAsync(w, new { useDeploymentProxy = true });
        foreach (var p in new[] { inTeam, named, outsider })
        {
            Assert.Empty((await w.CallAsync(p, HttpMethod.Get, "/v1/inference-providers")).Body.GetProperty("inferenceProviders").EnumerateArray());
            Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(p, HttpMethod.Get, $"/v1/inference-providers/{id}/connect")).Status);
        }
        var group = (await Gw.DetailsAsync(w, id)).GetProperty("modelGroups")[0].GetProperty("id").GetString()!;
        var teamId = await w.TeamAsync("Writers", inTeam);
        Assert.Equal(HttpStatusCode.Created, (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/inference-providers/{id}/access-grants", new { modelGroupId = group, audience = new { type = "team", teamId } })).Status);
        Assert.Equal(HttpStatusCode.Created, (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/inference-providers/{id}/access-grants", new { modelGroupId = group, audience = new { type = "member", memberId = named.MemberId } })).Status);
        Assert.Equal(HttpStatusCode.Conflict, (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/inference-providers/{id}/access-grants", new { modelGroupId = group, audience = new { type = "member", memberId = named.MemberId } })).Status);
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(inTeam, HttpMethod.Get, $"/v1/inference-providers/{id}/connect")).Status);
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(named, HttpMethod.Get, $"/v1/inference-providers/{id}/connect")).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(outsider, HttpMethod.Get, $"/v1/inference-providers/{id}/connect")).Status);
        Assert.Single((await w.CallAsync(named, HttpMethod.Get, "/v1/inference-providers")).Body.GetProperty("inferenceProviders").EnumerateArray());
        // Another workspace's people and teams are not found here.
        var other = await Workspace.CreateAsync(factory, "Other");
        Assert.Equal(HttpStatusCode.NotFound, (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/inference-providers/{id}/access-grants", new { modelGroupId = group, audience = new { type = "member", memberId = other.Owner.MemberId } })).Status);
        // ...and this provider is not found from there.
        Assert.Equal(HttpStatusCode.NotFound, (await other.CallAsync(other.Owner, HttpMethod.Get, $"/v1/inference-providers/{id}")).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await other.CallAsync(other.Owner, HttpMethod.Get, $"/v1/inference-providers/{id}/connect")).Status);
    }

    [Fact]
    public async Task Narrowing_a_group_updates_the_same_key_and_removing_access_deletes_it_in_LiteLLM_at_once()
    {
        var w = await Workspace.CreateAsync(factory);
        var member = await w.AddAsync();
        var id = await Gw.ProviderAsync(w);
        var key = (await w.CallAsync(member, HttpMethod.Get, $"/v1/inference-providers/{id}/connect")).Body.GetProperty("inferenceProvider").GetProperty("apiKey").GetString()!;
        var details = await Gw.DetailsAsync(w, id);
        var group = details.GetProperty("modelGroups")[0].GetProperty("id").GetString()!;
        var grant = details.GetProperty("accessGrants")[0].GetProperty("id").GetString()!;

        var patched = await w.CallAsync(w.Owner, HttpMethod.Patch, $"/v1/inference-providers/{id}/model-groups/{group}", new { modelIds = new[] { "fake-small" } });
        Assert.Equal(HttpStatusCode.OK, patched.Status);
        Assert.Equal(["fake-small"], Fake.Keys[FakeLiteLlm.HashOf(key)].Models.ToArray());
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Patch, $"/v1/inference-providers/{id}/model-groups/{group}", new { modelIds = new[] { "not-served" } })).Status);

        Assert.Equal(HttpStatusCode.NoContent, (await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/inference-providers/{id}/access-grants/{grant}")).Status);
        Assert.False(Fake.Keys.ContainsKey(FakeLiteLlm.HashOf(key)));
        Assert.Equal(0, factory.WithDb(db => db.Set<GatewayIssuedKey>().Count(k => k.GatewayProviderId == id)));
    }

    [Fact]
    public async Task Leaving_the_workspace_or_disabling_the_provider_deletes_the_keys()
    {
        var w = await Workspace.CreateAsync(factory);
        var leaver = await w.AddAsync();
        var stayer = await w.AddAsync();
        var id = await Gw.ProviderAsync(w);
        string KeyOf(Person p) => factory.WithDb(db => db.Set<GatewayIssuedKey>().Single(k => k.GatewayProviderId == id && k.MemberId == p.MemberId).TokenHash);
        await w.CallAsync(leaver, HttpMethod.Get, $"/v1/inference-providers/{id}/connect");
        await w.CallAsync(stayer, HttpMethod.Get, $"/v1/inference-providers/{id}/connect");
        var leaverHash = KeyOf(leaver);
        var stayerHash = KeyOf(stayer);

        Assert.Equal(HttpStatusCode.NoContent, (await w.SendAsync(w.As(w.Owner, HttpMethod.Delete, $"/v1/members/{leaver.MemberId}"))).StatusCode);
        Assert.False(Fake.Keys.ContainsKey(leaverHash));
        Assert.True(Fake.Keys.ContainsKey(stayerHash));

        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Patch, $"/v1/inference-providers/{id}", new { status = "disabled" })).Status);
        Assert.False(Fake.Keys.ContainsKey(stayerHash));
        Assert.Equal(HttpStatusCode.NotFound, (await w.CallAsync(stayer, HttpMethod.Get, $"/v1/inference-providers/{id}/connect")).Status);
        Assert.Empty((await w.CallAsync(stayer, HttpMethod.Get, "/v1/inference-providers")).Body.GetProperty("inferenceProviders").EnumerateArray());
    }

    [Fact]
    public async Task Deleting_removes_keys_and_team_in_LiteLLM_and_refuses_when_LiteLLM_cannot_confirm()
    {
        var w = await Workspace.CreateAsync(factory);
        var member = await w.AddAsync();
        var id = await Gw.ProviderAsync(w);
        var key = (await w.CallAsync(member, HttpMethod.Get, $"/v1/inference-providers/{id}/connect")).Body.GetProperty("inferenceProvider").GetProperty("apiKey").GetString()!;
        var team = factory.WithDb(db => db.Set<GatewayProvider>().Single(x => x.Id == id).LiteLlmTeamId)!;

        Fake.FailKeyDelete = true;
        try
        {
            var refused = await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/inference-providers/{id}");
            Assert.Equal(HttpStatusCode.Conflict, refused.Status);
            Assert.Equal("litellm_bad_response", refused.Body.GetProperty("error").GetString());
            Assert.Equal(1, factory.WithDb(db => db.Set<GatewayProvider>().Count(x => x.Id == id)));
        }
        finally { Fake.FailKeyDelete = false; }

        Assert.Equal(HttpStatusCode.NoContent, (await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/inference-providers/{id}")).Status);
        Assert.False(Fake.Keys.ContainsKey(FakeLiteLlm.HashOf(key)));
        Assert.False(Fake.Teams.ContainsKey(team));
        Assert.Equal(0, factory.WithDb(db => db.Set<GatewayProviderModel>().Count(m => m.GatewayProviderId == id) + db.Set<GatewayIssuedKey>().Count(k => k.GatewayProviderId == id)));
    }

    [Fact]
    public async Task Sync_follows_the_proxy_models_into_the_all_models_group_and_the_keys()
    {
        var w = await Workspace.CreateAsync(factory);
        var member = await w.AddAsync();
        var id = await Gw.ProviderAsync(w);
        var key = (await w.CallAsync(member, HttpMethod.Get, $"/v1/inference-providers/{id}/connect")).Body.GetProperty("inferenceProvider").GetProperty("apiKey").GetString()!;
        lock (Fake.Models) { Fake.Models.Remove("fake-large"); Fake.Models.Add("fake-new"); }
        try
        {
            var r = await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/inference-providers/{id}/litellm/sync");
            Assert.Equal(HttpStatusCode.OK, r.Status);
            Assert.Equal(["fake-new", "fake-small"], Gw.Strings(r.Body.GetProperty("inferenceProvider").GetProperty("modelGroups")[0].GetProperty("modelIds")));
            Assert.Equal(["fake-new", "fake-small"], Fake.Keys[FakeLiteLlm.HashOf(key)].Models.Order().ToArray());
        }
        finally { lock (Fake.Models) { Fake.Models.Remove("fake-new"); Fake.Models.Insert(0, "fake-large"); } }
    }

    [Fact]
    public async Task Management_needs_the_permissions_and_keys_never_arrive_through_an_API_key()
    {
        var w = await Workspace.CreateAsync(factory);
        var member = await w.AddAsync();
        var id = await Gw.ProviderAsync(w);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(member, HttpMethod.Get, "/v1/inference-providers?scope=manageable")).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(member, HttpMethod.Get, $"/v1/inference-providers/{id}")).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await Gw.CreateAsync(w, member, new { useDeploymentProxy = true })).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(member, HttpMethod.Delete, $"/v1/inference-providers/{id}")).Status);

        var bad = await Gw.CreateAsync(w, w.Owner, new { useDeploymentProxy = true, mode = "org" });
        Assert.Equal("litellm_mode_unsupported", bad.Body.GetProperty("error").GetString());
        Assert.Equal("Unrecognized key: \"surprise\"", (await Gw.CreateAsync(w, w.Owner, new { useDeploymentProxy = true, surprise = 1 })).Body.GetProperty("message").GetString());

        // A workspace's own proxy on a private address is refused unless the deployment allows private addresses.
        var priv = await Gw.CreateAsync(w, w.Owner, new { baseUrl = Fake.Origin, apiKey = FakeLiteLlm.MasterKey });
        Assert.Equal(HttpStatusCode.BadRequest, priv.Status);
        Assert.Equal("litellm_invalid_base_url", priv.Body.GetProperty("error").GetString());
        Assert.Equal("litellm_invalid_base_url", (await Gw.CreateAsync(w, w.Owner, new { baseUrl = "https://user:pw@litellm.example.com", apiKey = "x" })).Body.GetProperty("error").GetString());

        // Organization API keys may manage, but may not carry a LiteLLM key.
        var created = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/api-keys", new { name = "automation", scopes = Array.Empty<string>() });
        if (created.Status is HttpStatusCode.OK or HttpStatusCode.Created && created.Body.TryGetProperty("key", out var apiKey))
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, "/v1/inference-providers/litellm") { Content = JsonContent.Create(new { baseUrl = "https://litellm.example.com", apiKey = "sk-anything" }) };
            request.Headers.Add("x-api-key", apiKey.GetString());
            var r = await factory.Plain().SendAsync(request);
            Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
            Assert.Equal("secure_entry_required", (await ReadJsonAsync(r)).GetProperty("error").GetString());
        }
    }

    [Fact]
    public async Task Usage_counts_only_this_provider_attributes_people_and_marks_unpriced_requests()
    {
        var w = await Workspace.CreateAsync(factory, "Usage Space");
        var alice = await w.AddAsync();
        var bob = await w.AddAsync();
        var id = await Gw.ProviderAsync(w);
        string Hash(Person p) => factory.WithDb(db => db.Set<GatewayIssuedKey>().Single(k => k.GatewayProviderId == id && k.MemberId == p.MemberId).TokenHash);
        await w.CallAsync(alice, HttpMethod.Get, $"/v1/inference-providers/{id}/connect");
        await w.CallAsync(bob, HttpMethod.Get, $"/v1/inference-providers/{id}/connect");
        var team = factory.WithDb(db => db.Set<GatewayProvider>().Single(x => x.Id == id).LiteLlmTeamId);
        Fake.Log(Hash(alice), team, "fake-large", 1000, 0.012);
        Fake.Log(Hash(alice), team, "fake-small", 50, 0);
        Fake.Log(Hash(bob), team, "fake-small", 10, 0, status: "failure");
        Fake.Log("someone-elses-key", "", "fake-small", 99999, 5);
        Fake.Log("someone-elses-key", "another-team", "fake-small", 99999, 5);

        // Den attributes a row only to its own team or keys, even when the proxy ignores the team filter.
        Fake.IgnoreTeamFilter = true;
        (HttpStatusCode Status, JsonElement Body) r;
        try { r = await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/inference-providers/usage?groupBy=person&days=7"); }
        finally { Fake.IgnoreTeamFilter = false; }
        Assert.Equal(HttpStatusCode.OK, r.Status);
        var u = r.Body.GetProperty("usage");
        Assert.Equal(2, u.GetProperty("requestCount").GetInt32());
        Assert.Equal(1050, u.GetProperty("totalTokens").GetInt64());
        Assert.Equal(12000, u.GetProperty("totalCostMicroUsd").GetInt64());
        Assert.Equal(1, u.GetProperty("unpricedRequests").GetInt32());
        Assert.Equal(1, u.GetProperty("uncountableRequests").GetProperty("rejected").GetInt32());
        Assert.Equal([alice.MemberId], u.GetProperty("series").EnumerateArray().Select(s => s.GetProperty("id").GetString()!).ToArray());
        Assert.Equal(7, u.GetProperty("daily").GetArrayLength());

        // A member reads their own usage; anyone else's needs View Gateway usage.
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(alice, HttpMethod.Get, $"/v1/inference-providers/usage?groupBy=person&memberId={alice.MemberId}")).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(alice, HttpMethod.Get, $"/v1/inference-providers/usage?groupBy=person&memberId={bob.MemberId}")).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(alice, HttpMethod.Get, "/v1/inference-providers/usage")).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/inference-providers/usage?days=0")).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/inference-providers/usage?groupBy=person&filterIds=ipr_x")).Status);

        // The checklist's Gateway step is done, with the provider's name for people who may see it.
        var steps = (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/me/activation")).Body.GetProperty("steps").EnumerateArray().Single(s => s.GetProperty("id").GetString() == "gateway_provider");
        Assert.True(steps.GetProperty("done").GetBoolean());
        Assert.Equal("LiteLLM on AI Gateway", steps.GetProperty("detail").GetString());
        var mine = (await w.CallAsync(alice, HttpMethod.Get, "/v1/me/activation")).Body.GetProperty("steps").EnumerateArray().Single(s => s.GetProperty("id").GetString() == "gateway_provider");
        Assert.True(mine.GetProperty("done").GetBoolean());
        Assert.False(mine.TryGetProperty("detail", out _));
    }
}

public sealed class GatewayDashboardTests(GatewayFactory factory) : IClassFixture<GatewayFactory>
{
    [Fact]
    public async Task The_platform_dashboard_reads_each_workspace_usage_from_LiteLLM()
    {
        var w = await Workspace.CreateAsync(factory, "Busy Space");
        var member = await w.AddAsync();
        var id = await Gw.ProviderAsync(w);
        await w.CallAsync(member, HttpMethod.Get, $"/v1/inference-providers/{id}/connect");
        var hash = factory.WithDb(db => db.Set<GatewayIssuedKey>().Single(k => k.GatewayProviderId == id).TokenHash);
        var team = factory.WithDb(db => db.Set<GatewayProvider>().Single(x => x.Id == id).LiteLlmTeamId);
        factory.Fake.Log(hash, team, "fake-large", 2000, 0.03);
        factory.Fake.Log(hash, team, "fake-small", 100, 0);
        factory.Fake.Log(hash, team, "fake-small", 100, 0, at: DateTime.UtcNow.AddDays(-40));

        var http = factory.Plain();
        var signUp = await http.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "Platform Admin", email = GatewayFactory.AdminEmail, password = Password });
        var token = (await ReadJsonAsync(signUp)).GetProperty("token").GetString()!;
        var r = await http.SendAsync(Bearer(HttpMethod.Get, "/v1/admin/dashboard", token));
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        var body = await ReadJsonAsync(r);
        Assert.Equal(30, body.GetProperty("daily").GetArrayLength());
        var org = body.GetProperty("organizations").EnumerateArray().Single(o => o.GetProperty("id").GetString() == w.OrgId);
        Assert.Equal("Busy Space", org.GetProperty("name").GetString());
        Assert.Equal(2, org.GetProperty("requests").GetInt32());
        Assert.Equal(2100, org.GetProperty("tokens").GetInt64());
        Assert.Equal(30000, org.GetProperty("costMicroUsd").GetInt64());
        Assert.Equal(1, org.GetProperty("unpricedRequests").GetInt32());
        // A workspace owner is not a platform admin.
        Assert.Equal(HttpStatusCode.Forbidden, (await http.SendAsync(Bearer(HttpMethod.Get, "/v1/admin/dashboard", w.Owner.Token))).StatusCode);
    }
}

public sealed class GatewayOffTests(GatewayOffFactory factory) : IClassFixture<GatewayOffFactory>
{
    [Fact]
    public async Task With_gateway_management_off_management_answers_gateway_not_enabled_and_the_usable_list_is_empty()
    {
        var w = await Workspace.CreateAsync(factory);
        foreach (var (method, path) in new[] { (HttpMethod.Get, "/v1/inference-providers?scope=manageable"), (HttpMethod.Post, "/v1/inference-providers/litellm"), (HttpMethod.Get, "/v1/inference-providers/usage") })
        {
            var r = await w.CallAsync(w.Owner, method, path, method == HttpMethod.Post ? new { useDeploymentProxy = true } : null);
            Assert.Equal(HttpStatusCode.Forbidden, r.Status);
            Assert.Equal("gateway_not_enabled", r.Body.GetProperty("error").GetString());
        }
        Assert.Empty((await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/inference-providers")).Body.GetProperty("inferenceProviders").EnumerateArray());
        Assert.False((await w.OrgAsync()).GetProperty("capabilities").GetProperty("gatewayDashboard").GetBoolean());
    }
}
