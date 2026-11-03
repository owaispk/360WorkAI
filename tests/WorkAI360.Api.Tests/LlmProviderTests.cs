using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using WorkAI360.Api.Domain.LlmProviders;
using WorkAI360.Api.Features.LlmProviders;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>Model providers may probe a local fake endpoint.</summary>
public sealed class LlmProviderFactory : ApiFactory
{
    protected override IEnumerable<KeyValuePair<string, string>> Settings => [new("Connections:AllowPrivateUrls", "true")];
}

/// <summary>An OpenAI-compatible endpoint: GET /v1/models (needs the right key), POST /v1/chat/completions (gpt-5 wants max_completion_tokens).</summary>
public sealed class FakeOpenAiServer : IAsyncDisposable
{
    public const string Key = "sk-fake-provider-key";
    private readonly WebApplication _app;
    public string Origin { get; private set; } = "";
    private FakeOpenAiServer(WebApplication app) => _app = app;

    public static async Task<FakeOpenAiServer> StartAsync()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        var app = builder.Build();
        var fake = new FakeOpenAiServer(app);
        app.Run(async ctx =>
        {
            var authorized = ctx.Request.Headers.Authorization.ToString() == $"Bearer {Key}";
            ctx.Response.ContentType = "application/json";
            if (!authorized) { ctx.Response.StatusCode = 401; await ctx.Response.WriteAsync("""{"error":{"message":"bad key"}}"""); return; }
            if (ctx.Request.Path == "/v1/models") { await ctx.Response.WriteAsync("""{"data":[{"id":"zeta-model"},{"id":"gpt-5"},{"id":"alpha-model"}]}"""); return; }
            if (ctx.Request.Path == "/v1/chat/completions")
            {
                var body = JsonNode.Parse(await new StreamReader(ctx.Request.Body).ReadToEndAsync())!.AsObject();
                if (body["model"]!.GetValue<string>() == "gpt-5" && body.ContainsKey("max_tokens"))
                {
                    ctx.Response.StatusCode = 400;
                    await ctx.Response.WriteAsync("""{"error":{"message":"Unsupported parameter: 'max_tokens'. Use 'max_completion_tokens' instead.","param":"max_tokens"}}""");
                    return;
                }
                await ctx.Response.WriteAsync("""{"choices":[{"message":{"content":"ok"}}]}""");
                return;
            }
            ctx.Response.StatusCode = 404;
        });
        await app.StartAsync();
        fake.Origin = app.Urls.First().Replace("localhost", "127.0.0.1");
        return fake;
    }

    public async ValueTask DisposeAsync() => await _app.DisposeAsync();
}

public sealed class LlmProviderTests(LlmProviderFactory factory) : IClassFixture<LlmProviderFactory>
{
    private static object OpenAi(string name = "Team OpenAI", string apiKey = "sk-shared-secret-123", bool allMembers = true, string mode = "shared") =>
        new { name, source = "models_dev", providerId = "openai", modelIds = new[] { "gpt-4o", "gpt-4.1" }, apiKey, allMembers, credentialMode = mode };

    private static string Custom(string api) => $$"""
        // An OpenCode provider block, as people paste it
        { "provider": { "acme": { "id": "acme", "name": "Acme", "npm": "@ai-sdk/openai-compatible", "env": ["ACME_API_KEY"],
          "options": { "baseURL": "{{api}}" }, "models": { "acme-large": { "name": "Acme Large", "limit": { "context": 128000, "output": 8000 } } }, } } }
        """;

    private static async Task<(HttpStatusCode Status, JsonElement Body, string Text)> Call(Workspace w, Person p, HttpMethod method, string url, object? body = null)
    {
        var r = await w.SendAsync(w.As(p, method, url, body));
        var text = await r.Content.ReadAsStringAsync();
        return (r.StatusCode, string.IsNullOrEmpty(text) ? default : JsonDocument.Parse(text).RootElement.Clone(), text);
    }

    private static string Error(JsonElement e) => e.GetProperty("error").GetString()!;
    private static string Message(JsonElement e) => e.GetProperty("message").GetString()!;

    private async Task<string> CreateAsync(Workspace w, Person p, object body)
    {
        var r = await Call(w, p, HttpMethod.Post, "/v1/llm-providers", body);
        Assert.True(r.Status == HttpStatusCode.Created, r.Text);
        return r.Body.GetProperty("llmProvider").GetProperty("id").GetString()!;
    }

    private void MakeStale(string userId) => factory.WithDb(db =>
    {
        foreach (var s in db.Sessions.Where(s => s.UserId == userId)) s.CreatedAt = DateTime.UtcNow.AddDays(-2);
        return db.SaveChanges();
    });

    [Fact]
    public async Task The_catalog_lists_providers_and_one_entry_has_its_models()
    {
        var w = await Workspace.CreateAsync(factory);
        var list = await Call(w, w.Owner, HttpMethod.Get, "/v1/llm-provider-catalog");
        Assert.Equal(HttpStatusCode.OK, list.Status);
        var openai = list.Body.GetProperty("providers").EnumerateArray().Single(p => p.GetProperty("id").GetString() == "openai");
        Assert.Equal("@ai-sdk/openai", openai.GetProperty("npm").GetString());
        Assert.True(openai.GetProperty("modelCount").GetInt32() > 10);
        var one = await Call(w, w.Owner, HttpMethod.Get, "/v1/llm-provider-catalog/anthropic");
        Assert.Equal("ANTHROPIC_API_KEY", one.Body.GetProperty("provider").GetProperty("env")[0].GetString());
        Assert.NotEmpty(one.Body.GetProperty("provider").GetProperty("models").EnumerateArray());
        Assert.Equal("provider_not_found", Error((await Call(w, w.Owner, HttpMethod.Get, "/v1/llm-provider-catalog/nope")).Body));
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Http.GetAsync("/v1/llm-provider-catalog")).StatusCode);
    }

    [Fact]
    public async Task A_shared_provider_reaches_granted_people_with_its_key_and_never_leaks_it_elsewhere()
    {
        var w = await Workspace.CreateAsync(factory);
        var member = await w.AddAsync();
        var created = await Call(w, w.Owner, HttpMethod.Post, "/v1/llm-providers", OpenAi());
        Assert.Equal(HttpStatusCode.Created, created.Status);
        Assert.DoesNotContain("sk-shared-secret-123", created.Text);
        var provider = created.Body.GetProperty("llmProvider");
        var id = provider.GetProperty("id").GetString()!;
        Assert.StartsWith("lpr_", id);
        Assert.True(provider.GetProperty("hasApiKey").GetBoolean());
        Assert.Equal(["OPENAI_API_KEY"], provider.GetProperty("configuredEnvKeys").EnumerateArray().Select(e => e.GetString()));
        var runtimeName = provider.GetProperty("runtimeEnvKeys")[0].GetString()!;
        Assert.Matches("^LPR_[0-9A-Z]{5}_OPENAI_API_KEY$", runtimeName);

        // The member sees it as usable (granted: full configuration, no identities of other people).
        var usable = await Call(w, member, HttpMethod.Get, "/v1/llm-providers");
        Assert.DoesNotContain("sk-shared-secret-123", usable.Text);
        var item = Assert.Single(usable.Body.GetProperty("llmProviders").EnumerateArray());
        Assert.False(item.GetProperty("configRedacted").GetBoolean());
        Assert.False(item.GetProperty("canManage").GetBoolean());
        Assert.True(item.GetProperty("access").GetProperty("membersHidden").GetBoolean());
        Assert.All(item.GetProperty("access").GetProperty("members").EnumerateArray(), m => Assert.False(m.TryGetProperty("user", out _)));
        Assert.DoesNotContain(w.Owner.Email, usable.Text);
        Assert.True(item.GetProperty("access").GetProperty("allMembers").GetBoolean());
        Assert.Equal(["gpt-4.1", "gpt-4o"], item.GetProperty("models").EnumerateArray().Select(m => m.GetProperty("id").GetString()).Order());

        // Connect gives the key and the runtime env names.
        var connect = await Call(w, member, HttpMethod.Get, $"/v1/llm-providers/{id}/connect");
        Assert.Equal(HttpStatusCode.OK, connect.Status);
        var payload = connect.Body.GetProperty("llmProvider");
        Assert.Equal("sk-shared-secret-123", payload.GetProperty("apiKey").GetString());
        Assert.Equal(runtimeName, payload.GetProperty("providerConfig").GetProperty("env")[0].GetString());
        Assert.Equal(JsonValueKind.Null, payload.GetProperty("apiKeys").ValueKind);

        // The single read (admins and the owner hold View all providers) never carries the key either.
        var single = await Call(w, w.Owner, HttpMethod.Get, $"/v1/llm-providers/{id}");
        Assert.Equal(HttpStatusCode.OK, single.Status);
        Assert.DoesNotContain("sk-shared-secret-123", single.Text);
        Assert.False(single.Body.GetProperty("llmProvider").GetProperty("access").GetProperty("membersHidden").GetBoolean());
        // A plain member has no View all providers.
        Assert.Equal(HttpStatusCode.Forbidden, (await Call(w, member, HttpMethod.Get, $"/v1/llm-providers/{id}")).Status);
        // The stored value is encrypted.
        Assert.DoesNotContain("sk-shared-secret-123", factory.WithDb(db => db.Set<LlmProvider>().Single(p => p.Id == id).ApiKeyEnc!));
    }

    [Fact]
    public async Task People_not_granted_cannot_connect_and_other_workspaces_see_nothing()
    {
        var w = await Workspace.CreateAsync(factory);
        var member = await w.AddAsync();
        var id = await CreateAsync(w, w.Owner, OpenAi(allMembers: false));
        var denied = await Call(w, member, HttpMethod.Get, $"/v1/llm-providers/{id}/connect");
        Assert.Equal(HttpStatusCode.Forbidden, denied.Status);
        Assert.Equal("You do not have access to this provider.", Message(denied.Body));
        Assert.Empty((await Call(w, member, HttpMethod.Get, "/v1/llm-providers")).Body.GetProperty("llmProviders").EnumerateArray());

        var other = await Workspace.CreateAsync(factory, "Elsewhere");
        foreach (var (method, url) in new[] { (HttpMethod.Get, $"/v1/llm-providers/{id}"), (HttpMethod.Get, $"/v1/llm-providers/{id}/connect"), (HttpMethod.Delete, $"/v1/llm-providers/{id}") })
            Assert.Equal("llm_provider_not_found", Error((await Call(other, other.Owner, method, url)).Body));
        Assert.Equal(HttpStatusCode.BadRequest, (await Call(w, w.Owner, HttpMethod.Get, "/v1/llm-providers/not-an-id")).Status);
    }

    [Fact]
    public async Task Granting_through_a_team_works_and_the_view_only_read_is_redacted()
    {
        var w = await Workspace.CreateAsync(factory);
        var member = await w.AddAsync();
        var outsider = await w.AddAsync();
        var team = await Call(w, w.Owner, HttpMethod.Post, "/v1/teams", new { name = "Writers", memberIds = new[] { member.MemberId } });
        var teamId = team.Body.GetProperty("team").GetProperty("id").GetString()!;
        var id = await CreateAsync(w, w.Owner, new { name = "Acme", source = "custom", customConfigText = Custom("https://acme.example.com/v1"), apiKey = "acme-secret", teamIds = new[] { teamId } });
        Assert.Equal(HttpStatusCode.OK, (await Call(w, member, HttpMethod.Get, $"/v1/llm-providers/{id}/connect")).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await Call(w, outsider, HttpMethod.Get, $"/v1/llm-providers/{id}/connect")).Status);

        // Someone who may view every provider but neither edits nor is granted this one gets the minimal configuration.
        using var scope = factory.Services.CreateScope();
        var service = scope.ServiceProvider.GetRequiredService<LlmProviderService>();
        var view = Assert.Single(await service.LoadAsync(w.OrgId, outsider.MemberId, [], viewAll: true, updateAll: false, "manageable"));
        Assert.True((bool)view["configRedacted"]!);
        Assert.False((bool)view["hasApiKey"]!);
        var config = JsonSerializer.SerializeToElement(view["providerConfig"]);
        Assert.Equal(["id", "name", "npm"], config.EnumerateObject().Select(p => p.Name).Order());
        var model = JsonSerializer.SerializeToElement(view["models"]).EnumerateArray().Single();
        Assert.Equal(["id", "limit", "name"], model.GetProperty("config").EnumerateObject().Select(p => p.Name).Order());
        Assert.DoesNotContain("acme.example.com", JsonSerializer.Serialize(view));
        Assert.Empty((List<string>)view["runtimeEnvKeys"]!);
    }

    [Fact]
    public async Task The_creator_may_edit_others_need_the_permission_and_admins_a_recent_sign_in()
    {
        var w = await Workspace.CreateAsync(factory);
        var creator = await w.AddAsync();
        var stranger = await w.AddAsync();
        var admin = await w.AddAsync("admin");
        var id = await CreateAsync(w, creator, OpenAi("Mine", allMembers: false));

        var mine = await Call(w, creator, HttpMethod.Patch, $"/v1/llm-providers/{id}", OpenAi("Mine renamed", apiKey: "sk-rotated-456", allMembers: false));
        Assert.Equal(HttpStatusCode.OK, mine.Status);
        Assert.Equal("Mine renamed", mine.Body.GetProperty("llmProvider").GetProperty("name").GetString());

        var refused = await Call(w, stranger, HttpMethod.Patch, $"/v1/llm-providers/{id}", OpenAi("Theirs", allMembers: false));
        Assert.Equal(HttpStatusCode.Forbidden, refused.Status);
        Assert.Equal("Only the provider creator or a workspace admin can update providers.", Message(refused.Body));
        Assert.Equal("Only the provider creator or a workspace admin can delete providers.", Message((await Call(w, stranger, HttpMethod.Delete, $"/v1/llm-providers/{id}")).Body));

        Assert.Equal(HttpStatusCode.OK, (await Call(w, admin, HttpMethod.Patch, $"/v1/llm-providers/{id}", OpenAi("By admin", allMembers: false))).Status);
        MakeStale(admin.UserId);
        var stale = await Call(w, admin, HttpMethod.Patch, $"/v1/llm-providers/{id}", OpenAi("Stale admin", allMembers: false));
        Assert.Equal("reauth", Error(stale.Body));
        // An admin's own provider still needs the recent sign-in; an ordinary creator's never does.
        MakeStale(creator.UserId);
        Assert.Equal(HttpStatusCode.OK, (await Call(w, creator, HttpMethod.Patch, $"/v1/llm-providers/{id}", OpenAi("Still mine", allMembers: false))).Status);
        Assert.Equal(HttpStatusCode.NoContent, (await Call(w, creator, HttpMethod.Delete, $"/v1/llm-providers/{id}")).Status);
        Assert.Equal(0, factory.WithDb(db => db.Set<LlmProviderModel>().Count(m => m.LlmProviderId == id) + db.Set<LlmProviderAccess>().Count(a => a.LlmProviderId == id)));
    }

    [Fact]
    public async Task An_admin_without_the_edit_permission_still_needs_a_recent_sign_in_for_their_own_provider()
    {
        var w = await Workspace.CreateAsync(factory);
        var admin = await w.AddAsync("admin");
        var sets = (await Call(w, w.Owner, HttpMethod.Get, "/v1/permissions/sets")).Body.GetProperty("sets");
        var adminSet = sets.EnumerateArray().First(s => s.GetProperty("kind").GetString() == "admin_default").GetProperty("id").GetString()!;
        Assert.Equal(HttpStatusCode.OK, (await Call(w, w.Owner, HttpMethod.Put, $"/v1/permissions/sets/{adminSet}/permissions",
            new { changes = new[] { new { key = "llm_providers.update", status = "deny" } } })).Status);
        var id = await CreateAsync(w, admin, OpenAi("Admin's own", allMembers: false));
        Assert.Equal(HttpStatusCode.OK, (await Call(w, admin, HttpMethod.Patch, $"/v1/llm-providers/{id}", OpenAi("Fresh edit", allMembers: false))).Status);
        MakeStale(admin.UserId);
        Assert.Equal("reauth", Error((await Call(w, admin, HttpMethod.Patch, $"/v1/llm-providers/{id}", OpenAi("Stale edit", allMembers: false))).Body));
    }

    [Fact]
    public async Task Keys_can_never_arrive_through_an_api_key()
    {
        var w = await Workspace.CreateAsync(factory);
        var secret = (await Call(w, w.Owner, HttpMethod.Post, "/v1/api-keys", new { name = "Automation" })).Body;
        var token = secret.TryGetProperty("key", out var k) ? k.GetString()! : secret.GetProperty("apiKey").GetProperty("key").GetString()!;
        async Task<JsonElement> Send(HttpMethod method, string url, object body)
        {
            var request = new HttpRequestMessage(method, url) { Content = JsonContent.Create(body) };
            request.Headers.Add("x-api-key", token);
            request.Headers.Add("x-openwork-org-id", w.OrgId);
            var r = await w.Http.SendAsync(request);
            Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
            return await ReadJsonAsync(r);
        }
        Assert.Equal("secure_entry_required", Error(await Send(HttpMethod.Post, "/v1/llm-providers", OpenAi())));
        Assert.Equal("secure_entry_required", Error(await Send(HttpMethod.Post, "/v1/llm-providers/test-connection", new { api = "https://example.com/v1", apiKey = "sk" })));
        var id = await CreateAsync(w, w.Owner, OpenAi("Per person", apiKey: "", mode: "per_member"));
        Assert.Equal("secure_entry_required", Error(await Send(HttpMethod.Put, $"/v1/llm-providers/{id}/my-credential", new { apiKey = "sk" })));
        Assert.Equal("secure_entry_required", Error(await Send(HttpMethod.Patch, $"/v1/llm-providers/{id}", OpenAi(apiKey: "sk"))));
    }

    [Fact]
    public async Task The_creators_access_is_protected_and_other_grants_can_be_removed()
    {
        var w = await Workspace.CreateAsync(factory);
        var member = await w.AddAsync();
        var id = await CreateAsync(w, w.Owner, new { name = "Shared", source = "models_dev", providerId = "openai", modelIds = new[] { "gpt-4o" }, apiKey = "k", memberIds = new[] { member.MemberId } });
        var access = factory.WithDb(db => db.Set<LlmProviderAccess>().Where(a => a.LlmProviderId == id).ToList());
        var creatorRow = access.Single(a => a.MemberId == w.Owner.MemberId);
        var memberRow = access.Single(a => a.MemberId == member.MemberId);
        var protectedRow = await Call(w, w.Owner, HttpMethod.Delete, $"/v1/llm-providers/{id}/access/{creatorRow.Id}");
        Assert.Equal(HttpStatusCode.Conflict, protectedRow.Status);
        Assert.Equal("protected_access", Error(protectedRow.Body));
        Assert.Equal(HttpStatusCode.NoContent, (await Call(w, w.Owner, HttpMethod.Delete, $"/v1/llm-providers/{id}/access/{memberRow.Id}")).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await Call(w, member, HttpMethod.Get, $"/v1/llm-providers/{id}/connect")).Status);
        Assert.Equal("llm_provider_access_not_found", Error((await Call(w, w.Owner, HttpMethod.Delete, $"/v1/llm-providers/{id}/access/{memberRow.Id}")).Body));
    }

    [Fact]
    public async Task Per_member_keys_are_versioned_blockable_and_only_the_owner_of_the_key_receives_it()
    {
        var w = await Workspace.CreateAsync(factory);
        var member = await w.AddAsync();
        var other = await w.AddAsync();
        var id = await CreateAsync(w, w.Owner, OpenAi("Per person", apiKey: "", mode: "per_member"));
        var url = $"/v1/llm-providers/{id}/my-credential";

        var missing = (await Call(w, member, HttpMethod.Get, $"/v1/llm-providers/{id}/connect")).Body.GetProperty("llmProvider");
        Assert.Equal("missing", missing.GetProperty("memberCredential").GetProperty("state").GetString());
        Assert.Equal(JsonValueKind.Null, missing.GetProperty("apiKey").ValueKind);

        var set = await Call(w, member, HttpMethod.Put, url, new { apiKey = "sk-member-own-1" });
        Assert.Equal(HttpStatusCode.OK, set.Status);
        Assert.Equal(1, set.Body.GetProperty("version").GetInt32());
        Assert.Equal(2, (await Call(w, member, HttpMethod.Put, url, new { apiKey = "sk-member-own-2" })).Body.GetProperty("version").GetInt32());
        var connected = (await Call(w, member, HttpMethod.Get, $"/v1/llm-providers/{id}/connect")).Body.GetProperty("llmProvider");
        Assert.Equal("sk-member-own-2", connected.GetProperty("apiKey").GetString());
        Assert.True((await Call(w, member, HttpMethod.Get, "/v1/llm-providers")).Body.GetProperty("llmProviders")[0].GetProperty("hasMyCredential").GetBoolean());
        // Another person's connect never returns it.
        var others = await Call(w, other, HttpMethod.Get, $"/v1/llm-providers/{id}/connect");
        Assert.DoesNotContain("sk-member-own", others.Text);

        // Administrators see states, never secrets.
        var list = await Call(w, w.Owner, HttpMethod.Get, $"/v1/llm-providers/{id}/member-credentials");
        Assert.DoesNotContain("sk-member-own", list.Text);
        Assert.Equal("active", list.Body.GetProperty("memberCredentials").EnumerateArray().Single(m => m.GetProperty("orgMembershipId").GetString() == member.MemberId).GetProperty("state").GetString());
        Assert.Equal(HttpStatusCode.Forbidden, (await Call(w, member, HttpMethod.Get, $"/v1/llm-providers/{id}/member-credentials")).Status);

        // Blocked: no longer delivered, and the member can neither replace nor remove it.
        var blocked = await Call(w, w.Owner, HttpMethod.Post, $"/v1/llm-providers/{id}/member-credentials/{member.MemberId}/block");
        Assert.Equal("blocked", blocked.Body.GetProperty("state").GetString());
        Assert.Equal(3, blocked.Body.GetProperty("version").GetInt32());
        Assert.Equal(JsonValueKind.Null, (await Call(w, member, HttpMethod.Get, $"/v1/llm-providers/{id}/connect")).Body.GetProperty("llmProvider").GetProperty("apiKey").ValueKind);
        Assert.Equal("credential_blocked", Error((await Call(w, member, HttpMethod.Put, url, new { apiKey = "sk-sneaky" })).Body));
        Assert.Equal("credential_blocked", Error((await Call(w, member, HttpMethod.Delete, url)).Body));

        // The administrator's write unblocks; a stale expected version is refused.
        var admin = $"/v1/llm-providers/{id}/member-credentials/{member.MemberId}";
        Assert.Equal("version_conflict", Error((await Call(w, w.Owner, HttpMethod.Put, admin, new { apiKey = "sk-admin-set", expectedVersion = 1 })).Body));
        var unblocked = await Call(w, w.Owner, HttpMethod.Put, admin, new { apiKey = "sk-admin-set", expectedVersion = 3, externalPrincipalId = "p-1" });
        Assert.Equal("active", unblocked.Body.GetProperty("state").GetString());
        Assert.Equal(4, unblocked.Body.GetProperty("version").GetInt32());
        Assert.Equal("member_credential_not_found", Error((await Call(w, w.Owner, HttpMethod.Post, $"/v1/llm-providers/{id}/member-credentials/{other.MemberId}/block")).Body));
        Assert.Equal(HttpStatusCode.OK, (await Call(w, member, HttpMethod.Delete, url)).Status);

        // Switching the provider to a shared key drops everyone's own keys.
        await Call(w, member, HttpMethod.Put, url, new { apiKey = "sk-again" });
        Assert.Equal(HttpStatusCode.OK, (await Call(w, w.Owner, HttpMethod.Patch, $"/v1/llm-providers/{id}", OpenAi("Per person", apiKey: "sk-shared", mode: "shared"))).Status);
        Assert.Equal(0, factory.WithDb(db => db.Set<LlmProviderMemberCredential>().Count(c => c.LlmProviderId == id)));
        Assert.Equal("not_per_member", Error((await Call(w, member, HttpMethod.Put, url, new { apiKey = "x" })).Body));
    }

    [Fact]
    public async Task Writes_are_validated_like_the_reference()
    {
        var w = await Workspace.CreateAsync(factory);
        async Task<JsonElement> Bad(object body, HttpStatusCode status = HttpStatusCode.BadRequest)
        {
            var r = await Call(w, w.Owner, HttpMethod.Post, "/v1/llm-providers", body);
            Assert.True(r.Status == status, r.Text);
            return r.Body;
        }
        Assert.Equal("providerId: Select a provider.", Message(await Bad(new { name = "x", source = "models_dev", modelIds = new[] { "gpt-4o" } })));
        Assert.Equal("modelIds: Select at least one model.", Message(await Bad(new { name = "x", source = "models_dev", providerId = "openai" })));
        Assert.Equal("customConfigText: Paste a custom provider config.", Message(await Bad(new { name = "x", source = "custom" })));
        Assert.StartsWith("source: Invalid option", Message(await Bad(new { name = "x", source = "openwork" })));
        Assert.Equal("model_not_found", Error(await Bad(new { name = "x", source = "models_dev", providerId = "openai", modelIds = new[] { "nope" } }, HttpStatusCode.NotFound)));
        Assert.Equal("provider_not_found", Error(await Bad(new { name = "x", source = "models_dev", providerId = "nope", modelIds = new[] { "a" } }, HttpStatusCode.NotFound)));
        Assert.Equal("member_not_found", Error(await Bad(new { name = "x", source = "models_dev", providerId = "openai", modelIds = new[] { "gpt-4o" }, memberIds = new[] { "om_01m6h6ap60ew49eha3he2jw133" } }, HttpStatusCode.NotFound)));
        var invalid = await Bad(new { name = "x", source = "custom", customConfigText = "{ not json" });
        Assert.Equal("invalid_custom_provider_config", Error(invalid));
        Assert.Equal("Custom provider config must be valid JSON or JSONC.", Message(invalid));
        Assert.Equal("env: Invalid input: expected array, received undefined",
            Message(await Bad(new { name = "x", source = "custom", customConfig = new { id = "a", name = "A", npm = "p", models = new[] { "m" } } })));
        Assert.Equal("Custom provider config contains multiple providers. Paste one provider block or remove the others.",
            Message(await Bad(new { name = "x", source = "custom", customConfig = new { provider = new { a = new { }, b = new { } } } })));
        // Azure deployments can be named anything.
        Assert.Equal(HttpStatusCode.Created, (await Call(w, w.Owner, HttpMethod.Post, "/v1/llm-providers",
            new { name = "Azure", source = "models_dev", providerId = "azure", modelIds = new[] { "my-own-deployment" }, apiKeys = new Dictionary<string, string> { ["AZURE_API_KEY"] = "k", ["AZURE_RESOURCE_NAME"] = "res" } })).Status);
        // Unknown env names and a Bedrock key without a region are refused.
        Assert.Equal("ANTHROPIC_API_KEY is not one of this provider's env keys (OPENAI_API_KEY).",
            Message(await Bad(new { name = "x", source = "models_dev", providerId = "openai", modelIds = new[] { "gpt-4o" }, apiKeys = new Dictionary<string, string> { ["ANTHROPIC_API_KEY"] = "k" } })));
        Assert.Equal("Amazon Bedrock requires AWS_REGION set to an AWS region code such as us-east-1.",
            Message(await Bad(new { name = "x", source = "models_dev", providerId = "amazon-bedrock", modelIds = new[] { "amazon.nova-lite-v1:0" }, apiKeys = new Dictionary<string, string> { ["AWS_BEARER_TOKEN_BEDROCK"] = "t" } })));
    }

    [Fact]
    public async Task Several_env_keys_merge_and_reach_the_desktop_under_runtime_names()
    {
        var w = await Workspace.CreateAsync(factory);
        var body = new Dictionary<string, object>
        {
            ["name"] = "Bedrock", ["source"] = "models_dev", ["providerId"] = "amazon-bedrock", ["modelIds"] = new[] { "amazon.nova-lite-v1:0" }, ["allMembers"] = true,
            ["apiKeys"] = new Dictionary<string, string> { ["AWS_BEARER_TOKEN_BEDROCK"] = "tok-1", ["AWS_REGION"] = "us-east-1" },
        };
        var id = await CreateAsync(w, w.Owner, body);
        // An edit that leaves apiKeys out keeps them; a blank value clears one.
        body["apiKeys"] = new Dictionary<string, string> { ["AWS_BEARER_TOKEN_BEDROCK"] = "tok-2" };
        var edited = await Call(w, w.Owner, HttpMethod.Patch, $"/v1/llm-providers/{id}", body);
        Assert.Equal(["AWS_REGION", "AWS_BEARER_TOKEN_BEDROCK"], edited.Body.GetProperty("llmProvider").GetProperty("configuredEnvKeys").EnumerateArray().Select(e => e.GetString()));
        var connect = (await Call(w, w.Owner, HttpMethod.Get, $"/v1/llm-providers/{id}/connect")).Body.GetProperty("llmProvider");
        Assert.Equal(JsonValueKind.Null, connect.GetProperty("apiKey").ValueKind);
        var keys = connect.GetProperty("apiKeys").EnumerateObject().ToDictionary(p => p.Name[(p.Name.IndexOf("_AWS", StringComparison.Ordinal) + 1)..], p => p.Value.GetString());
        Assert.Equal("tok-2", keys["AWS_BEARER_TOKEN_BEDROCK"]);
        Assert.Equal("us-east-1", keys["AWS_REGION"]);
        // The SDK reads the region option, bound to the runtime name rather than the value.
        Assert.StartsWith("{env:LPR_", connect.GetProperty("providerConfig").GetProperty("options").GetProperty("region").GetString());
    }

    [Fact]
    public async Task Test_connection_lists_the_models_an_endpoint_serves_and_explains_failures()
    {
        await using var fake = await FakeOpenAiServer.StartAsync();
        var w = await Workspace.CreateAsync(factory);
        var ok = await Call(w, w.Owner, HttpMethod.Post, "/v1/llm-providers/test-connection", new { api = $"{fake.Origin}/v1/chat/completions", apiKey = FakeOpenAiServer.Key, modelIds = new[] { "gpt-5", "alpha-model" } });
        Assert.Equal(HttpStatusCode.OK, ok.Status);
        var result = ok.Body.GetProperty("result");
        Assert.True(result.GetProperty("ok").GetBoolean());
        Assert.Equal($"{fake.Origin}/v1", result.GetProperty("normalizedApi").GetString());
        Assert.Equal(["alpha-model", "gpt-5", "zeta-model"], result.GetProperty("models").EnumerateArray().Select(m => m.GetProperty("id").GetString()));
        var verifications = ok.Body.GetProperty("verifications").EnumerateArray().ToDictionary(v => v.GetProperty("id").GetString()!);
        Assert.Equal("adjusted", verifications["gpt-5"].GetProperty("status").GetString());
        Assert.Equal("@ai-sdk/openai", verifications["gpt-5"].GetProperty("npm").GetString());
        Assert.Equal("ok", verifications["alpha-model"].GetProperty("status").GetString());

        var badKey = (await Call(w, w.Owner, HttpMethod.Post, "/v1/llm-providers/test-connection", new { api = $"{fake.Origin}/v1", apiKey = "wrong" })).Body.GetProperty("result");
        Assert.False(badKey.GetProperty("ok").GetBoolean());
        Assert.Equal(401, badKey.GetProperty("status").GetInt32());
        Assert.Equal("The endpoint rejected the key. Double-check the credential for this endpoint.", badKey.GetProperty("hint").GetString());
        Assert.Equal("Enter a valid http(s) base URL.", (await Call(w, w.Owner, HttpMethod.Post, "/v1/llm-providers/test-connection", new { api = "ftp://x" })).Body.GetProperty("result").GetProperty("hint").GetString());
    }

    [Fact]
    public async Task Declarative_by_key_writes_create_then_replace_and_delete_idempotently()
    {
        var w = await Workspace.CreateAsync(factory);
        var url = "/v1/llm-providers/by-key/team-openai";
        var created = await Call(w, w.Owner, HttpMethod.Put, url, OpenAi("Keyed"));
        Assert.Equal(HttpStatusCode.Created, created.Status);
        var id = created.Body.GetProperty("llmProvider").GetProperty("id").GetString();
        var replaced = await Call(w, w.Owner, HttpMethod.Put, url, new { name = "Keyed 2", source = "models_dev", providerId = "openai", modelIds = new[] { "gpt-4o" }, allMembers = true });
        Assert.Equal(HttpStatusCode.OK, replaced.Status);
        Assert.Equal(id, replaced.Body.GetProperty("llmProvider").GetProperty("id").GetString());
        Assert.True(replaced.Body.GetProperty("llmProvider").GetProperty("hasApiKey").GetBoolean()); // omitted key kept
        Assert.Equal("Keyed 2", (await Call(w, w.Owner, HttpMethod.Get, url)).Body.GetProperty("llmProvider").GetProperty("name").GetString());
        Assert.Equal("invalid_api_keys", Error((await Call(w, w.Owner, HttpMethod.Put, url, OpenAi("Blank", apiKey: ""))).Body));
        Assert.Equal(HttpStatusCode.BadRequest, (await Call(w, w.Owner, HttpMethod.Put, "/v1/llm-providers/by-key/Bad Key", OpenAi())).Status);
        Assert.True((await Call(w, w.Owner, HttpMethod.Delete, url)).Body.GetProperty("deleted").GetBoolean());
        Assert.False((await Call(w, w.Owner, HttpMethod.Delete, url)).Body.GetProperty("deleted").GetBoolean());
        var member = await w.AddAsync();
        Assert.Equal(HttpStatusCode.Forbidden, (await Call(w, member, HttpMethod.Put, url, OpenAi())).Status);
    }
}
