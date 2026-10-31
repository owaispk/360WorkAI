using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Domain.Connections;
using WorkAI360.Api.Features.Connections;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>A factory that may reach loopback servers (the fake MCP server listens there).</summary>
public class ConnectionFactory : ApiFactory
{
    protected override IEnumerable<KeyValuePair<string, string>> Settings => [new("Connections:AllowPrivateUrls", "true"), .. More];
    protected virtual IEnumerable<KeyValuePair<string, string>> More => [];
}

/// <summary>A factory with short limits, to prove timeouts and size limits bite.</summary>
public sealed class ConnectionLimitsFactory : ConnectionFactory
{
    protected override IEnumerable<KeyValuePair<string, string>> More => [new("Connections:ToolTimeoutSeconds", "1")];
}

public static class ConnectionHelpers
{
    public static Task<(HttpStatusCode Status, JsonElement Body)> Post(this Workspace w, Person by, object body) => w.CallAsync(by, HttpMethod.Post, "/v1/mcp-connections", body);

    public static async Task<string> NoneAsync(this Workspace w, FakeMcpServer fake, string name = "Fake none", object? access = null)
    {
        var r = await w.Post(w.Owner, new { name, url = fake.Url("none"), authType = "none", access = access ?? new { orgWide = true, memberIds = Array.Empty<string>(), teamIds = Array.Empty<string>() } });
        Assert.True(r.Status == HttpStatusCode.OK, $"create: {r.Status} {r.Body}");
        return r.Body.GetProperty("id").GetString()!;
    }

    public static object Only(params string[] members) => new { orgWide = false, memberIds = members, teamIds = Array.Empty<string>() };

    public static async Task<string> MintAsync(this Workspace w, Person p, params string[] scopes)
    {
        var r = await w.CallAsync(p, HttpMethod.Post, "/v1/mcp/token", new { scopes });
        Assert.Equal(HttpStatusCode.OK, r.Status);
        return r.Body.GetProperty("token").GetString()!;
    }

    /// <summary>One MCP tool call to /mcp/agent as an agent with this token; the JSON-RPC result.</summary>
    public static async Task<JsonElement> AgentAsync(this Workspace w, string token, string tool, object arguments)
    {
        var r = await w.Http.SendAsync(Bearer(HttpMethod.Post, "/mcp/agent", token, new { jsonrpc = "2.0", id = 1, method = "tools/call", @params = new { name = tool, arguments } }));
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        return (await ReadJsonAsync(r)).GetProperty("result");
    }

    public static Task<JsonElement> ExecuteAsync(this Workspace w, string token, string capability, object? body = null) => w.AgentAsync(token, "execute_capability", new { name = capability, body = body ?? new { } });

    public static async Task<string[]> SearchAsync(this Workspace w, string token, string query) =>
        (await w.AgentAsync(token, "search_capabilities", new { query })).GetProperty("structuredContent").GetProperty("capabilities").EnumerateArray().Select(c => c.GetProperty("id").GetString()!).ToArray();

    public static string ErrorOf(this JsonElement result) =>
        result.TryGetProperty("isError", out var e) && e.GetBoolean() ? JsonDocument.Parse(result.GetProperty("content")[0].GetProperty("text").GetString()!).RootElement.GetProperty("error").GetString()! : "";

    public static string Msg(this (HttpStatusCode Status, JsonElement Body) r) => r.Body.TryGetProperty("message", out var m) ? m.GetString() ?? "" : "";
}

public sealed class ConnectionTests : IClassFixture<ConnectionFactory>, IAsyncLifetime
{
    private readonly ConnectionFactory _factory;
    private FakeMcpServer _fake = null!;
    public ConnectionTests(ConnectionFactory factory) => _factory = factory;
    public async Task InitializeAsync() => _fake = await FakeMcpServer.StartAsync();
    public async Task DisposeAsync() => await _fake.DisposeAsync();

    // ---------- validation ----------

    [Theory]
    [InlineData("{}")]
    [InlineData("""{"name":"X","url":"ftp://x","authType":"none"}""")]
    [InlineData("""{"name":"X","url":"https://u:p@x.example/mcp","authType":"none"}""")]
    [InlineData("""{"name":"X","url":"https://x.example/mcp#frag","authType":"none"}""")]
    [InlineData("""{"name":"X","url":"https://x.example/mcp?api_key=1","authType":"none"}""")]
    [InlineData("""{"name":"X","url":"not a url","authType":"none"}""")]
    [InlineData("""{"name":" ","url":"https://x.example/mcp","authType":"none"}""")]
    [InlineData("""{"name":"X","url":"https://x.example/mcp","authType":"basic"}""")]
    [InlineData("""{"name":"X","url":"https://x.example/mcp","authType":"none","externalKey":"Bad Key"}""")]
    [InlineData("""{"name":"X","url":"https://x.example/mcp","authType":"none","requestHeaders":[{"name":"A","value":"1"},{"name":"B","value":"1"},{"name":"C","value":"1"},{"name":"D","value":"1"},{"name":"E","value":"1"}]}""")]
    [InlineData("""{"name":"X","url":"https://x.example/mcp","authType":"none","access":{"orgWide":"yes"}}""")]
    [InlineData("""{"name":"X","url":"https://x.example/mcp","authType":"none","access":{"memberIds":["nope"]}}""")]
    public async Task Invalid_create_requests_are_a_400_and_save_nothing(string json)
    {
        var w = await Workspace.CreateAsync(_factory);
        var request = w.As(w.Owner, HttpMethod.Post, "/v1/mcp-connections");
        request.Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json");
        var response = await w.Http.SendAsync(request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_request", (await ReadJsonAsync(response)).GetProperty("error").GetString());
        Assert.Empty((await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/mcp-connections?scope=manageable")).Body.GetProperty("connections").EnumerateArray());
    }

    [Fact]
    public async Task Header_and_option_rules_give_the_reference_messages()
    {
        var w = await Workspace.CreateAsync(_factory);
        string Url() => _fake.Url("none");
        async Task<string> Msg(object body) { var r = await w.Post(w.Owner, body); Assert.Equal(HttpStatusCode.BadRequest, r.Status); return r.Msg(); }
        Assert.Equal("The request header \"Host\" is set by OpenWork and can't be added.", await Msg(new { name = "X", url = Url(), authType = "none", requestHeaders = new[] { new { name = "Host", value = "x" } } }));
        Assert.Equal("The request header \"authorization\" is set by OpenWork for this sign-in method and can't be added.", await Msg(new { name = "X", url = _fake.Url("key"), authType = "apikey", apiKey = FakeMcpServer.Key, requestHeaders = new[] { new { name = "authorization", value = "x" } } }));
        Assert.Equal("The request header \"a\" is listed more than once.", await Msg(new { name = "X", url = Url(), authType = "none", requestHeaders = new[] { new { name = "A", value = "1" }, new { name = "a", value = "2" } } }));
        Assert.Equal("oauthClient is only allowed when authType is oauth.", await Msg(new { name = "X", url = Url(), authType = "none", oauthClient = new { clientId = "c" } }));
        Assert.Equal("apiKeyAuthScheme is only allowed for API-key connections.", await Msg(new { name = "X", url = Url(), authType = "none", apiKeyAuthScheme = "token" }));
        Assert.Equal("OAuth issuer and scopes are only allowed when authType is oauth.", await Msg(new { name = "X", url = Url(), authType = "none", requestedScopes = new[] { "a" } }));
        Assert.Equal("Individual accounts require OAuth or a personal API key enrolled by each member. Do not supply a shared key.", await Msg(new { name = "X", url = Url(), authType = "none", credentialMode = "per_member" }));
        Assert.Equal("Manual sign-in addresses require OAuth and a pre-registered client ID.", await Msg(new { name = "X", url = Url(), authType = "none", manualOAuthEndpoints = new { authorizationEndpoint = "https://a.example/a", tokenEndpoint = "https://a.example/t" } }));
    }

    [Fact]
    public async Task A_connection_to_a_server_that_is_not_MCP_or_is_down_is_refused_with_a_diagnostic_and_nothing_is_kept()
    {
        var w = await Workspace.CreateAsync(_factory);
        var notMcp = await w.Post(w.Owner, new { name = "Not MCP", url = $"{_fake.Origin}/missing/mcp", authType = "none" });
        Assert.Equal(HttpStatusCode.BadGateway, notMcp.Status);
        Assert.Equal("connection_validation_failed", FakeError(notMcp));
        Assert.StartsWith("req_", notMcp.Body.GetProperty("diagnostic").GetProperty("referenceId").GetString());
        var down = await w.Post(w.Owner, new { name = "Down", url = "http://127.0.0.1:1/mcp", authType = "none" });
        Assert.Equal(HttpStatusCode.BadGateway, down.Status);
        Assert.Empty((await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/mcp-connections?scope=manageable")).Body.GetProperty("connections").EnumerateArray());
    }

    private static string FakeError((HttpStatusCode Status, JsonElement Body) r) => r.Body.GetProperty("error").GetString()!;

    // ---------- permission denials ----------

    [Fact]
    public async Task What_a_plain_member_may_and_may_not_do()
    {
        var w = await Workspace.CreateAsync(_factory);
        var bob = await w.AddAsync();
        var id = await w.NoneAsync(_fake, access: ConnectionHelpers.Only(bob.MemberId));
        string Denied((HttpStatusCode Status, JsonElement Body) r) { Assert.Equal(HttpStatusCode.Forbidden, r.Status); return r.Body.TryGetProperty("requiredPermission", out var p) ? p.GetString()! : "message:" + r.Msg(); }

        Assert.Equal("message:Only workspace owners and admins can list all MCP connections.", Denied(await w.CallAsync(bob, HttpMethod.Get, "/v1/mcp-connections?scope=manageable")));
        Assert.Equal("connections.view", Denied(await w.CallAsync(bob, HttpMethod.Get, $"/v1/mcp-connections/{id}")));
        Assert.Equal("connections.view", Denied(await w.CallAsync(bob, HttpMethod.Get, $"/v1/mcp-connections/{id}/tool-policy")));
        Assert.Equal("connections.manage", Denied(await w.CallAsync(bob, HttpMethod.Put, $"/v1/mcp-connections/{id}/tool-policy", new { allDisabled = true, disabledTools = Array.Empty<string>() })));
        Assert.Equal("connections.manage", Denied(await w.CallAsync(bob, HttpMethod.Post, $"/v1/mcp-connections/{id}/tools/call", new { toolName = "echo", arguments = new { } })));
        Assert.Equal("connections.manage", Denied(await w.CallAsync(bob, HttpMethod.Post, $"/v1/mcp-connections/{id}/check")));
        Assert.Equal("connections.manage", Denied(await w.CallAsync(bob, HttpMethod.Post, "/v1/mcp-connections/resolve", new { query = "x" })));
        Assert.Equal("connections.disconnect", Denied(await w.CallAsync(bob, HttpMethod.Post, $"/v1/mcp-connections/{id}/disconnect")));
        Assert.StartsWith("message:", Denied(await w.CallAsync(bob, HttpMethod.Delete, $"/v1/mcp-connections/{id}")));
        Assert.StartsWith("message:", Denied(await w.CallAsync(bob, HttpMethod.Put, $"/v1/mcp-connections/{id}/access", new { access = new { orgWide = false, memberIds = new[] { bob.MemberId }, teamIds = Array.Empty<string>() } })));
        // What they may do: see and list tools of what they were given.
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(bob, HttpMethod.Get, $"/v1/mcp-connections/{id}/tools")).Status);
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(bob, HttpMethod.Get, "/v1/mcp-connections")).Status);
    }

    [Fact]
    public async Task Sensitive_changes_need_a_recent_sign_in()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await w.NoneAsync(_fake);
        // Age the owner's session beyond the privileged window.
        _factory.WithDb(db => { db.Sessions.Where(s => s.UserId == w.Owner.UserId).ExecuteUpdate(s => s.SetProperty(x => x.CreatedAt, DateTime.UtcNow.AddHours(-5))); return 0; });
        var delete = await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/mcp-connections/{id}");
        Assert.Equal(HttpStatusCode.Forbidden, delete.Status);
        Assert.Equal("reauth", delete.Body.GetProperty("error").GetString());
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/mcp-connections/{id}")).Status);   // still there
    }

    // ---------- who can use a connection ----------

    [Fact]
    public async Task Access_grants_decide_who_sees_and_uses_a_connection_and_admins_get_nothing_by_being_admins()
    {
        var w = await Workspace.CreateAsync(_factory);
        var bob = await w.AddAsync(); var carol = await w.AddAsync(); var dave = await w.AddAsync(); var admin = await w.AddAsync("admin");
        var id = await w.NoneAsync(_fake, "Private", ConnectionHelpers.Only());
        async Task<bool> Sees(Person p) => (await w.CallAsync(p, HttpMethod.Get, "/v1/mcp-connections")).Body.GetProperty("connections").EnumerateArray().Any(c => c.GetProperty("id").GetString() == id);

        Assert.False(await Sees(bob)); Assert.False(await Sees(w.Owner)); Assert.False(await Sees(admin));
        // A person.
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/mcp-connections/{id}/access", new { access = ConnectionHelpers.Only(bob.MemberId) })).Status);
        Assert.True(await Sees(bob)); Assert.False(await Sees(carol));
        // A team.
        var team = (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/teams", new { name = "Readers", memberIds = new[] { carol.MemberId } })).Body.GetProperty("team").GetProperty("id").GetString()!;
        await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/mcp-connections/{id}/access", new { access = new { orgWide = false, memberIds = new[] { bob.MemberId }, teamIds = new[] { team } } });
        Assert.True(await Sees(carol)); Assert.False(await Sees(dave));
        // Everyone.
        await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/mcp-connections/{id}/access", new { access = new { orgWide = true, memberIds = Array.Empty<string>(), teamIds = Array.Empty<string>() } });
        Assert.True(await Sees(dave));
        // Back to nobody: gone again for all, including from the API surface agents use.
        await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/mcp-connections/{id}/access", new { access = ConnectionHelpers.Only() });
        Assert.False(await Sees(dave)); Assert.False(await Sees(bob));
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(bob, HttpMethod.Get, $"/v1/mcp-connections/{id}/tools")).Status);
        Assert.DoesNotContain($"mcp:{id}:echo", await w.SearchAsync(await w.MintAsync(bob, "mcp:read", "mcp:write"), "echo"));
        // The admin may inspect it (connections.view) but not use it.
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(admin, HttpMethod.Get, $"/v1/mcp-connections/{id}/tools")).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(admin, HttpMethod.Post, $"/v1/mcp-connections/{id}/tools/call", new { toolName = "echo", arguments = new { message = "x" } })).Status);
    }

    [Fact]
    public async Task A_member_who_adds_a_connection_keeps_it_for_themselves_and_cannot_share_it_with_everyone()
    {
        var w = await Workspace.CreateAsync(_factory);
        var bob = await w.AddAsync(); var carol = await w.AddAsync();
        var own = await w.Post(bob, new { name = "Bobs", url = _fake.Url("none"), authType = "none", access = new { orgWide = false, memberIds = new[] { carol.MemberId }, teamIds = Array.Empty<string>() } });
        Assert.Equal(HttpStatusCode.OK, own.Status);
        var members = own.Body.GetProperty("access").GetProperty("memberIds").EnumerateArray().Select(e => e.GetString()).ToList();
        Assert.Contains(bob.MemberId, members); Assert.Contains(carol.MemberId, members);
        Assert.False(own.Body.GetProperty("access").GetProperty("orgWide").GetBoolean());
        var id = own.Body.GetProperty("id").GetString()!;
        // Left to its default (everyone), a member's connection is refused; nor can they add keys or shared OAuth.
        Assert.Equal(HttpStatusCode.Forbidden, (await w.Post(bob, new { name = "All", url = _fake.Url("none"), authType = "none" })).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.Post(bob, new { name = "Key", url = _fake.Url("key"), authType = "apikey", apiKey = FakeMcpServer.Key })).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.Post(bob, new { name = "Shared", url = _fake.Url("oauth"), authType = "oauth" })).Status);
        // Bob may reshape who can use it, but not make it org-wide, and can drop others but never himself.
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(bob, HttpMethod.Put, $"/v1/mcp-connections/{id}/access", new { access = new { orgWide = true } })).Status);
        var narrowed = await w.CallAsync(bob, HttpMethod.Put, $"/v1/mcp-connections/{id}/access", new { access = ConnectionHelpers.Only() });
        Assert.Equal(HttpStatusCode.OK, narrowed.Status);
        Assert.Equal(new[] { bob.MemberId }, narrowed.Body.GetProperty("access").GetProperty("memberIds").EnumerateArray().Select(e => e.GetString()).ToArray());
        // Carol did not add it: she cannot change its access.
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(carol, HttpMethod.Put, $"/v1/mcp-connections/{id}/access", new { access = ConnectionHelpers.Only(carol.MemberId) })).Status);
        // Bob can edit and remove what he added.
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(bob, HttpMethod.Delete, $"/v1/mcp-connections/{id}")).Status);
    }

    // ---------- isolation between workspaces ----------

    [Fact]
    public async Task Another_workspaces_connections_people_and_teams_are_not_reachable()
    {
        var a = await Workspace.CreateAsync(_factory, "A place");
        var b = await Workspace.CreateAsync(_factory, "B place");
        var mine = await a.NoneAsync(_fake, "Mine");
        var theirs = await b.NoneAsync(_fake, "Theirs");
        // Every route reads the other workspace's id as not found (never 403).
        foreach (var (method, path, body) in new (HttpMethod, string, object?)[]
        {
            (HttpMethod.Get, $"/v1/mcp-connections/{theirs}", null), (HttpMethod.Get, $"/v1/mcp-connections/{theirs}/tools", null), (HttpMethod.Get, $"/v1/mcp-connections/{theirs}/tool-policy", null),
            (HttpMethod.Put, $"/v1/mcp-connections/{theirs}/tool-policy", new { allDisabled = true, disabledTools = Array.Empty<string>() }), (HttpMethod.Put, $"/v1/mcp-connections/{theirs}/access", new { access = new { orgWide = true } }),
            (HttpMethod.Post, $"/v1/mcp-connections/{theirs}/tools/call", new { toolName = "echo", arguments = new { } }), (HttpMethod.Post, $"/v1/mcp-connections/{theirs}/check", null),
            (HttpMethod.Post, $"/v1/mcp-connections/{theirs}/disconnect", null), (HttpMethod.Post, $"/v1/mcp-connections/{theirs}/disconnect-my-account", null), (HttpMethod.Get, $"/v1/mcp-connections/{theirs}/connect/start", null),
            (HttpMethod.Post, $"/v1/mcp-connections/{theirs}/removal-request", new { expectedName = "Theirs" }), (HttpMethod.Delete, $"/v1/mcp-connections/{theirs}", null),
        })
        {
            var r = await a.CallAsync(a.Owner, method, path, body);
            Assert.True(r.Status == HttpStatusCode.NotFound, $"{method} {path}: {r.Status} {r.Body}");
        }
        // Their connection is untouched; a person or team of theirs cannot be granted ours.
        Assert.True((await b.CallAsync(b.Owner, HttpMethod.Get, $"/v1/mcp-connections/{theirs}")).Status == HttpStatusCode.OK);
        var stranger = await b.AddAsync();
        var team = (await b.CallAsync(b.Owner, HttpMethod.Post, "/v1/teams", new { name = "Theirs team" })).Body.GetProperty("team").GetProperty("id").GetString()!;
        Assert.Equal("member_not_found", Workspace.Error((await a.CallAsync(a.Owner, HttpMethod.Put, $"/v1/mcp-connections/{mine}/access", new { access = ConnectionHelpers.Only(stranger.MemberId) })).Body));
        Assert.Equal("team_not_found", Workspace.Error((await a.CallAsync(a.Owner, HttpMethod.Put, $"/v1/mcp-connections/{mine}/access", new { access = new { orgWide = false, memberIds = Array.Empty<string>(), teamIds = new[] { team } } })).Body));
        Assert.Equal("member_not_found", Workspace.Error((await a.Post(a.Owner, new { name = "X", url = _fake.Url("none"), authType = "none", access = ConnectionHelpers.Only(stranger.MemberId) })).Body));
        // The same through agents: one workspace's agent cannot run another's connection by id.
        var token = await a.MintAsync(a.Owner, "mcp:read", "mcp:write");
        var result = await a.ExecuteAsync(token, $"mcp:{theirs}:echo", new { message = "x" });
        Assert.Equal("unknown_capability", result.ErrorOf());
        Assert.DoesNotContain(_fake.McpCalls("none", "tools/call"), c => c.Tool == "echo");
        // Removing a person from a workspace is the Members area's job; here a person of workspace B holding a token for B cannot use A's id either.
        var bToken = await b.MintAsync(b.Owner, "mcp:read", "mcp:write");
        Assert.Equal("unknown_capability", (await b.ExecuteAsync(bToken, $"mcp:{mine}:echo", new { message = "x" })).ErrorOf());
    }

    // ---------- secrets ----------

    [Fact]
    public async Task Secrets_are_stored_encrypted_and_never_returned()
    {
        var w = await Workspace.CreateAsync(_factory);
        var bob = await w.AddAsync();
        var created = await w.Post(w.Owner, new { name = "Keyed", url = _fake.Url("key"), authType = "apikey", apiKey = FakeMcpServer.Key, requestHeaders = new[] { new { name = "X-Test-One", value = "header-secret-value" } } });
        Assert.Equal(HttpStatusCode.OK, created.Status);
        var id = created.Body.GetProperty("id").GetString()!;
        // A personal key for another connection.
        var personal = (await w.Post(w.Owner, new { name = "Personal", url = _fake.Url("key"), authType = "apikey", credentialMode = "per_member" })).Body.GetProperty("id").GetString()!;
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(bob, HttpMethod.Put, $"/v1/mcp-connections/{personal}/my-credential", new { apiKey = FakeMcpServer.Key })).Status);

        var all = new[] { created.Body.GetRawText(), (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/mcp-connections/{id}")).Body.GetRawText(), (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/mcp-connections?scope=manageable")).Body.GetRawText(),
            (await w.CallAsync(bob, HttpMethod.Get, "/v1/mcp-connections")).Body.GetRawText(), (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/mcp-connections/{id}/tools")).Body.GetRawText() };
        foreach (var text in all) { Assert.DoesNotContain(FakeMcpServer.Key, text); Assert.DoesNotContain("header-secret-value", text); }

        // At rest: nothing readable in any column, and the encrypted ones are ours (not just base64 of the secret).
        var rows = _factory.WithDb(db => (db.Set<ExternalMcpConnection>().AsNoTracking().Where(c => c.Id == id).ToList(), db.Set<ConnectedAccount>().AsNoTracking().Where(a => a.ConnectionId == personal).ToList()));
        var dump = JsonSerializer.Serialize(rows);
        Assert.DoesNotContain(FakeMcpServer.Key, dump); Assert.DoesNotContain("header-secret-value", dump);
        Assert.DoesNotContain(Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(FakeMcpServer.Key)), dump);
        Assert.StartsWith("v1.", rows.Item1.Single().ApiKeyEnc); Assert.StartsWith("v1.", rows.Item1.Single().RequestHeadersEnc); Assert.StartsWith("v1.", rows.Item2.Single().AccessTokenEnc);
        var box = _factory.Services.GetRequiredService<SecretBox>();
        Assert.Equal(FakeMcpServer.Key, box.Decrypt(rows.Item1.Single().ApiKeyEnc));
        Assert.Equal(FakeMcpServer.Key, box.Decrypt(rows.Item2.Single().AccessTokenEnc));
        // Encrypting twice differs (fresh nonce) and a tampered value reads as nothing instead of throwing.
        Assert.NotEqual(box.Encrypt("same"), box.Encrypt("same"));
        var enc = box.Encrypt("secret"); var tampered = enc[..^2] + (enc[^2] == 'A' ? "B=" : "A=");
        Assert.Null(box.Decrypt(tampered)); Assert.Null(box.Decrypt("plain text")); Assert.Null(box.Decrypt(null));
        // The server received the right credential and header.
        Assert.Contains(_fake.McpCalls("key"), c => c.Auth == $"Bearer {FakeMcpServer.Key}" && c.Headers.GetValueOrDefault("x-test-one") == "header-secret-value");
    }

    [Fact]
    public async Task A_key_that_is_not_one_token_is_refused_without_repeating_it()
    {
        var w = await Workspace.CreateAsync(_factory);
        var waiting = (await w.Post(w.Owner, new { name = "Waiting", url = _fake.Url("key"), authType = "apikey" }));
        Assert.False(waiting.Body.GetProperty("connected").GetBoolean());
        Assert.Equal("credential_prompt", waiting.Body.GetProperty("credentialPrompt").GetProperty("kind").GetString());
        var id = waiting.Body.GetProperty("id").GetString()!;
        var bad = await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/mcp-connections/{id}/shared-credential", new { apiKey = "has space", extra = 1 });
        Assert.Equal(HttpStatusCode.BadRequest, bad.Status);
        Assert.DoesNotContain("has space", bad.Body.GetRawText());
        var rejected = await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/mcp-connections/{id}/shared-credential", new { apiKey = "wrongkey" });
        Assert.Equal("credential_rejected", Workspace.Error(rejected.Body));
        Assert.False(_factory.WithDb(db => db.Set<ExternalMcpConnection>().AsNoTracking().Single(c => c.Id == id).ApiKeyEnc is not null));   // a rejected key is not kept
    }

    // ---------- tool policy and tools through agents ----------

    [Fact]
    public async Task The_tool_policy_hides_tools_from_agents_and_is_enforced_again_when_a_tool_runs()
    {
        var w = await Workspace.CreateAsync(_factory);
        var bob = await w.AddAsync();
        var id = await w.NoneAsync(_fake, "Policy", ConnectionHelpers.Only(bob.MemberId));
        var token = await w.MintAsync(bob, "mcp:read", "mcp:write");

        Assert.Contains($"mcp:{id}:delete_everything", await w.SearchAsync(token, "dangerous"));
        // Between searching and running the admin switches the tool off: running it is refused and the server never sees the call.
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/mcp-connections/{id}/tool-policy", new { allDisabled = false, disabledTools = new[] { "delete_everything" } })).Status);
        _fake.Reset();
        var blocked = await w.ExecuteAsync(token, $"mcp:{id}:delete_everything");
        Assert.Equal("policy_blocked", blocked.ErrorOf());
        Assert.Contains("disabled for your organization", blocked.GetProperty("content")[0].GetProperty("text").GetString());
        Assert.Empty(_fake.McpCalls(method: "tools/call"));
        Assert.DoesNotContain($"mcp:{id}:delete_everything", await w.SearchAsync(token, "dangerous"));
        Assert.Contains($"mcp:{id}:echo", await w.SearchAsync(token, "echo"));

        // Everything off.
        await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/mcp-connections/{id}/tool-policy", new { allDisabled = true, disabledTools = Array.Empty<string>() });
        Assert.Equal("policy_blocked", (await w.ExecuteAsync(token, $"mcp:{id}:echo", new { message = "x" })).ErrorOf());
        Assert.Empty(await w.SearchAsync(token, "echo"));
        // And back on: running works and the result is the server's own.
        await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/mcp-connections/{id}/tool-policy", new { allDisabled = false, disabledTools = Array.Empty<string>() });
        var ok = await w.ExecuteAsync(token, $"mcp:{id}:echo", new { message = "hello" });
        Assert.Equal("echo: hello", ok.GetProperty("content")[0].GetProperty("text").GetString());
        Assert.Equal("hello", ok.GetProperty("structuredContent").GetProperty("echoed").GetString());
        Assert.Contains(_fake.McpCalls("none", "tools/call"), c => c.Tool == "echo");
    }

    [Fact]
    public async Task Agents_need_the_write_scope_to_run_and_a_grant_to_see_and_unknown_ids_are_refused()
    {
        var w = await Workspace.CreateAsync(_factory);
        var bob = await w.AddAsync(); var carol = await w.AddAsync();
        var id = await w.NoneAsync(_fake, "Scoped", ConnectionHelpers.Only(bob.MemberId));
        var readOnly = await w.MintAsync(bob, "mcp:read");
        var full = await w.MintAsync(bob, "mcp:read", "mcp:write");
        var carolToken = await w.MintAsync(carol, "mcp:read", "mcp:write");
        var ownerToken = await w.MintAsync(w.Owner, "mcp:read", "mcp:write");

        Assert.Equal("insufficient_scope", (await w.ExecuteAsync(readOnly, $"mcp:{id}:echo", new { message = "x" })).ErrorOf());
        Assert.DoesNotContain(_fake.McpCalls(method: "tools/call"), c => c.Tool == "echo");
        Assert.Equal("forbidden", (await w.ExecuteAsync(carolToken, $"mcp:{id}:echo", new { message = "x" })).ErrorOf());
        Assert.Equal("forbidden", (await w.ExecuteAsync(ownerToken, $"mcp:{id}:echo", new { message = "x" })).ErrorOf());   // owner is not granted
        Assert.DoesNotContain(id, string.Join(' ', await w.SearchAsync(carolToken, "echo")));
        Assert.Equal("unknown_capability", (await w.ExecuteAsync(full, $"mcp:{id}:nope")).ErrorOf());
        Assert.Equal("unknown_capability", (await w.ExecuteAsync(full, "mcp:emc_01m6798bqbeaeagm9dmr8grtrt:echo")).ErrorOf());
        Assert.Equal("unknown_capability", (await w.ExecuteAsync(full, "mcp:garbage")).ErrorOf());
        var ids = await w.SearchAsync(full, "echo");
        Assert.Contains($"mcp:{id}:echo", ids);
        // Removing the connection removes it from agents at once.
        await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/mcp-connections/{id}");
        Assert.Equal("unknown_capability", (await w.ExecuteAsync(full, $"mcp:{id}:echo", new { message = "x" })).ErrorOf());
        Assert.Empty(await w.SearchAsync(full, "echo"));
    }

    [Fact]
    public async Task Tool_arguments_over_one_megabyte_are_refused_and_never_forwarded()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await w.NoneAsync(_fake, access: ConnectionHelpers.Only(w.Owner.MemberId));
        var r = await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/mcp-connections/{id}/tools/call", new { toolName = "echo", arguments = new { message = new string('x', 1100 * 1024) } });
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, r.Status);
        Assert.Equal("payload_too_large", Workspace.Error(r.Body));
        Assert.Empty(_fake.McpCalls(method: "tools/call"));
    }

    // ---------- the MCP client ----------

    [Fact]
    public async Task The_MCP_client_reads_json_and_event_stream_replies_and_every_page_of_tools()
    {
        var w = await Workspace.CreateAsync(_factory);
        async Task<JsonElement> ToolsOf(string kind)
        {
            var created = await w.Post(w.Owner, new { name = kind, url = _fake.Url(kind), authType = "none" });
            Assert.True(created.Status == HttpStatusCode.OK, $"{kind}: {created.Status} {created.Body}");
            return (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/mcp-connections/{created.Body.GetProperty("id").GetString()}/tools")).Body.GetProperty("tools");
        }
        Assert.Equal(3, (await ToolsOf("sse")).GetArrayLength());
        Assert.Equal(new[] { "echo", "add", "delete_everything" }, (await ToolsOf("paged")).EnumerateArray().Select(t => t.GetProperty("name").GetString()).ToArray());
    }

    [Fact]
    public async Task Redirects_from_a_server_are_never_followed()
    {
        var w = await Workspace.CreateAsync(_factory);
        var r = await w.Post(w.Owner, new { name = "Redirector", url = _fake.Url("redirect"), authType = "none" });
        Assert.Equal(HttpStatusCode.BadGateway, r.Status);
        Assert.Contains("redirect-hit", _fake.Other);
        Assert.DoesNotContain("secret", _fake.Other);
    }

    // ---------- OAuth ----------

    private async Task<string> ConnectOAuthAsync(Workspace w, Person p, string id, Action<UriBuilderHook>? tweak = null)
    {
        var start = await w.CallAsync(p, HttpMethod.Get, $"/v1/mcp-connections/{id}/connect/start");
        Assert.True(start.Status == HttpStatusCode.OK, $"{start.Status} {start.Body}");
        var url = start.Body.GetProperty("authorizeUrl").GetString()!;
        if (tweak is not null) { var hook = new UriBuilderHook(url); tweak(hook); url = hook.Url; }
        using var browser = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        var redirect = await browser.GetAsync(url);
        return redirect.Headers.Location!.ToString();
    }

    public sealed class UriBuilderHook(string url) { public string Url { get; private set; } = url; public void Add(string kv) => Url += (Url.Contains('?') ? "&" : "?") + kv; }

    private async Task<(HttpStatusCode Status, string Html)> CallbackAsync(Workspace w, string location)
    {
        var r = await w.Http.GetAsync(new Uri(location).PathAndQuery);
        return (r.StatusCode, await r.Content.ReadAsStringAsync());
    }

    private async Task<string> OAuthConnectionAsync(Workspace w, string mode = "per_member")
    {
        var r = await w.Post(w.Owner, new { name = "OAuth server", url = _fake.Url("oauth"), authType = "oauth", credentialMode = mode });
        Assert.Equal(HttpStatusCode.OK, r.Status);
        return r.Body.GetProperty("id").GetString()!;
    }

    [Fact]
    public async Task OAuth_sign_in_uses_PKCE_registers_the_app_stores_tokens_encrypted_and_works_for_the_person_only()
    {
        var w = await Workspace.CreateAsync(_factory);
        var bob = await w.AddAsync();
        var id = await OAuthConnectionAsync(w);
        var location = await ConnectOAuthAsync(w, w.Owner, id);
        var authorize = _fake.OAuthCalls.Single(c => c.Kind == "authorize");
        Assert.Equal($"{_fake.Url("oauth")}", authorize.Resource);
        Assert.False(string.IsNullOrEmpty(authorize.Challenge));
        Assert.Contains(_fake.OAuthCalls, c => c.Kind == "register" && c.RedirectUri!.EndsWith("/v1/mcp-connections/oauth/callback"));
        Assert.Equal("mcp", authorize.Scope);

        var (status, html) = await CallbackAsync(w, location);
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Contains("connected", html, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(_fake.OAuthCalls, c => c.Kind == "token" && c.Grant == "authorization_code" && c.HasVerifier && c.Resource == _fake.Url("oauth"));

        var mine = (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/mcp-connections/{id}")).Body;
        Assert.True(mine.GetProperty("connectedForMe").GetBoolean());
        Assert.Equal("ready", mine.GetProperty("credentialHealth").GetString());
        Assert.Equal("dynamic", mine.GetProperty("oauthRegistrationSource").GetString());
        Assert.Equal("ready", mine.GetProperty("readiness").GetProperty("status").GetString());
        Assert.Equal(new[] { "mcp" }, mine.GetProperty("grantedScopes").EnumerateArray().Select(e => e.GetString()).ToArray());
        // Bob has not signed in himself, so he has no tools; the owner's tools use the owner's token.
        Assert.Equal(HttpStatusCode.Conflict, (await w.CallAsync(bob, HttpMethod.Get, $"/v1/mcp-connections/{id}/tools")).Status);
        _fake.Reset();
        Assert.Equal(3, (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/mcp-connections/{id}/tools")).Body.GetProperty("tools").GetArrayLength());
        Assert.All(_fake.McpCalls("oauth", "tools/list"), c => Assert.StartsWith("Bearer at_", c.Auth));

        // At rest the tokens are encrypted and the PKCE secret and state are gone.
        var (account, transactions, client) = _factory.WithDb(db => (db.Set<ConnectedAccount>().AsNoTracking().Single(a => a.ConnectionId == id), db.Set<ConnectionOAuthTransaction>().Count(t => t.ConnectionId == id), db.Set<ConnectionOAuthClient>().AsNoTracking().Single(c => c.ConnectionId == id)));
        Assert.StartsWith("v1.", account.AccessTokenEnc); Assert.StartsWith("v1.", account.RefreshTokenEnc);
        Assert.DoesNotContain("at_", JsonSerializer.Serialize(account)); Assert.DoesNotContain("rt_", JsonSerializer.Serialize(account));
        Assert.Equal(0, transactions);
        Assert.Equal("dynamic", client.RegistrationSource);
    }

    [Fact]
    public async Task A_callback_can_be_used_once_and_only_with_its_own_state()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await OAuthConnectionAsync(w);
        var location = await ConnectOAuthAsync(w, w.Owner, id);
        Assert.Equal(HttpStatusCode.OK, (await CallbackAsync(w, location)).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await CallbackAsync(w, location)).Status);                      // replay
        Assert.Equal(HttpStatusCode.BadRequest, (await w.Http.GetAsync("/v1/mcp-connections/oauth/callback")).StatusCode);  // no state
        Assert.Equal(HttpStatusCode.BadRequest, (await w.Http.GetAsync("/v1/mcp-connections/oauth/callback?state=forged&code=x")).StatusCode);
        // A state minted for one connection does not complete through another connection's scoped callback.
        await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/mcp-connections/{id}/disconnect-my-account");
        var second = await ConnectOAuthAsync(w, w.Owner, id);
        var other = await OAuthConnectionAsync(w);
        var query = new Uri(second).Query;
        Assert.Equal(HttpStatusCode.BadRequest, (await w.Http.GetAsync($"/v1/mcp-connections/{other}/connect/callback{query}")).StatusCode);
        // Concurrent completion of the same state: exactly one wins.
        await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/mcp-connections/{id}/disconnect-my-account");
        var raced = await ConnectOAuthAsync(w, w.Owner, id);
        var results = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => CallbackAsync(w, raced)));
        Assert.Equal(1, results.Count(r => r.Status == HttpStatusCode.OK));
    }

    [Fact]
    public async Task An_expired_sign_in_a_denied_sign_in_and_a_response_from_another_issuer_connect_nothing()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await OAuthConnectionAsync(w);
        // Expired.
        var location = await ConnectOAuthAsync(w, w.Owner, id);
        _factory.WithDb(db => { db.Set<ConnectionOAuthTransaction>().ExecuteUpdate(t => t.SetProperty(x => x.ExpiresAt, DateTime.UtcNow.AddMinutes(-1))); return 0; });
        Assert.Equal(HttpStatusCode.BadRequest, (await CallbackAsync(w, location)).Status);
        // Denied by the person at the provider.
        var denied = await ConnectOAuthAsync(w, w.Owner, id, h => h.Add("deny=1"));
        var (status, html) = await CallbackAsync(w, denied);
        Assert.Equal(HttpStatusCode.BadRequest, status);
        Assert.Contains("Connection failed", html);
        // A response claiming to come from another authorization server (RFC 9207).
        var wrongIssuer = await ConnectOAuthAsync(w, w.Owner, id, h => h.Add("wrong_iss=1"));
        Assert.Equal(HttpStatusCode.BadRequest, (await CallbackAsync(w, wrongIssuer)).Status);
        var mine = (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/mcp-connections/{id}")).Body;
        Assert.False(mine.GetProperty("connectedForMe").GetBoolean());
        Assert.Equal(0, _factory.WithDb(db => db.Set<ConnectedAccount>().Count(a => a.ConnectionId == id && a.AccessTokenEnc != null)));
    }

    [Fact]
    public async Task An_authorization_endpoint_that_is_not_http_or_names_another_issuer_is_refused()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await OAuthConnectionAsync(w);
        _fake.AuthorizationEndpointOverride = "javascript:alert(1)";
        try
        {
            var r = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/mcp-connections/{id}/connect/start");
            Assert.Equal((HttpStatusCode)424, r.Status);
            Assert.Equal("oauth_handshake_failed", Workspace.Error(r.Body));
        }
        finally { _fake.AuthorizationEndpointOverride = null; }
        _fake.IssuerOverride = "https://evil.example";
        try { Assert.Equal(HttpStatusCode.Conflict, (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/mcp-connections/{id}/connect/start")).Status); }
        finally { _fake.IssuerOverride = null; }
    }

    [Fact]
    public async Task Expired_tokens_are_refreshed_once_even_when_many_calls_arrive_together_and_a_rejected_refresh_signs_the_person_out()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await OAuthConnectionAsync(w);
        Assert.Equal(HttpStatusCode.OK, (await CallbackAsync(w, await ConnectOAuthAsync(w, w.Owner, id))).Status);
        var token = await w.MintAsync(w.Owner, "mcp:read", "mcp:write");
        await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/mcp-connections/{id}/access", new { access = ConnectionHelpers.Only(w.Owner.MemberId) });
        // Expire the stored token by time (our side) so each call wants to refresh.
        _fake.SlowMs = 1;
        _factory.WithDb(db => { db.Set<ConnectedAccount>().ExecuteUpdate(a => a.SetProperty(x => x.ExpiresAt, DateTime.UtcNow.AddMinutes(-5))); return 0; });
        _fake.Reset();
        var calls = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/mcp-connections/{id}/tools")));
        Assert.All(calls, c => Assert.Equal(HttpStatusCode.OK, c.Status));
        Assert.Equal(1, _fake.OAuthCalls.Count(c => c.Kind == "token" && c.Grant == "refresh_token"));
        _fake.SlowMs = 0;

        // The provider revokes the grant: the next refresh is rejected, the sign-in is cleared and agents see "needs connection".
        _fake.RejectRefresh = true;
        _factory.WithDb(db => { db.Set<ConnectedAccount>().ExecuteUpdate(a => a.SetProperty(x => x.ExpiresAt, DateTime.UtcNow.AddMinutes(-5))); return 0; });
        var failed = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/mcp-connections/{id}/tools");
        Assert.NotEqual(HttpStatusCode.OK, failed.Status);
        var mine = (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/mcp-connections/{id}")).Body;
        Assert.False(mine.GetProperty("connectedForMe").GetBoolean());
        Assert.True(mine.GetProperty("needsReconnect").GetBoolean());
        Assert.Equal("reconnect_required", mine.GetProperty("credentialHealth").GetString());
        Assert.Null(_factory.WithDb(db => db.Set<ConnectedAccount>().AsNoTracking().Single(a => a.ConnectionId == id).AccessTokenEnc));
        var ids = await w.SearchAsync(token, "oauth");
        Assert.Contains($"mcp:{id}:*", ids);
        Assert.DoesNotContain($"mcp:{id}:echo", ids);
        _fake.RejectRefresh = false;
    }

    [Fact]
    public async Task A_shared_OAuth_connection_is_connected_by_a_manager_and_used_by_everyone_granted()
    {
        var w = await Workspace.CreateAsync(_factory);
        var bob = await w.AddAsync();
        var id = await OAuthConnectionAsync(w, "shared");
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(bob, HttpMethod.Get, $"/v1/mcp-connections/{id}/connect/start")).Status);
        Assert.Equal(HttpStatusCode.OK, (await CallbackAsync(w, await ConnectOAuthAsync(w, w.Owner, id))).Status);
        var shared = (await w.CallAsync(bob, HttpMethod.Get, "/v1/mcp-connections")).Body.GetProperty("connections").EnumerateArray().Single(c => c.GetProperty("id").GetString() == id);
        Assert.True(shared.GetProperty("connectedForMe").GetBoolean());
        _fake.Reset();
        var result = await w.ExecuteAsync(await w.MintAsync(bob, "mcp:read", "mcp:write"), $"mcp:{id}:echo", new { message = "shared" });
        Assert.Equal("echo: shared", result.GetProperty("content")[0].GetProperty("text").GetString());
        Assert.Contains(_fake.McpCalls("oauth", "tools/call"), c => c.Auth.StartsWith("Bearer at_"));
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/mcp-connections/{id}/disconnect")).Status);
        Assert.Equal("needs_connection", (await w.ExecuteAsync(await w.MintAsync(bob, "mcp:read", "mcp:write"), $"mcp:{id}:echo", new { message = "x" })).ErrorOf());
    }

    // ---------- removing and concurrency ----------

    [Fact]
    public async Task Removing_a_connection_removes_its_grants_accounts_and_client()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await OAuthConnectionAsync(w);
        await CallbackAsync(w, await ConnectOAuthAsync(w, w.Owner, id));
        Assert.True(_factory.WithDb(db => db.Set<ConnectedAccount>().Any(a => a.ConnectionId == id) && db.Set<ConnectionOAuthClient>().Any(c => c.ConnectionId == id) && db.Set<ConnectionAccessGrant>().Any(g => g.ConnectionId == id)));
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/mcp-connections/{id}")).Status);
        Assert.False(_factory.WithDb(db => db.Set<ConnectedAccount>().Any(a => a.ConnectionId == id) || db.Set<ConnectionOAuthClient>().Any(c => c.ConnectionId == id) || db.Set<ConnectionAccessGrant>().Any(g => g.ConnectionId == id) || db.Set<ExternalMcpConnection>().Any(c => c.Id == id)));
        Assert.Equal(HttpStatusCode.NotFound, (await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/mcp-connections/{id}")).Status);
    }

    [Fact]
    public async Task Edits_made_at_the_same_moment_from_the_same_version_let_exactly_one_win()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await w.NoneAsync(_fake);
        var version = (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/mcp-connections/{id}")).Body.GetProperty("updatedAt").GetString();
        var results = await Task.WhenAll(Enumerable.Range(0, 6).Select(i => w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/mcp-connections/{id}",
            new { expectedUpdatedAt = version, name = $"Edit {i}", url = _fake.Url("none"), authType = "none", credentialMode = "shared", access = new { orgWide = true } })));
        Assert.Equal(1, results.Count(r => r.Status == HttpStatusCode.OK));
        Assert.Equal(5, results.Count(r => r.Status == HttpStatusCode.Conflict));
    }

    [Fact]
    public async Task Changing_where_a_connection_points_ends_the_old_sign_ins_but_renaming_keeps_them()
    {
        var w = await Workspace.CreateAsync(_factory);
        var bob = await w.AddAsync();
        var id = (await w.Post(w.Owner, new { name = "Personal", url = _fake.Url("key"), authType = "apikey", credentialMode = "per_member" })).Body.GetProperty("id").GetString()!;
        await w.CallAsync(bob, HttpMethod.Put, $"/v1/mcp-connections/{id}/my-credential", new { apiKey = FakeMcpServer.Key });
        async Task<(HttpStatusCode Status, JsonElement Body)> Edit(string name, string url)
        {
            var version = (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/mcp-connections/{id}")).Body.GetProperty("updatedAt").GetString();
            return await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/mcp-connections/{id}", new { expectedUpdatedAt = version, name, url, authType = "apikey", credentialMode = "per_member", access = new { orgWide = true } });
        }
        var renamed = await Edit("Renamed", _fake.Url("key"));
        Assert.False(renamed.Body.GetProperty("identityChanged").GetBoolean());
        Assert.Equal(1, _factory.WithDb(db => db.Set<ConnectedAccount>().Count(a => a.ConnectionId == id)));
        var moved = await Edit("Renamed", _fake.Url("none"));
        Assert.True(moved.Body.GetProperty("identityChanged").GetBoolean());
        Assert.True(moved.Body.GetProperty("reconnectionRequired").GetBoolean());
        Assert.Equal(0, _factory.WithDb(db => db.Set<ConnectedAccount>().Count(a => a.ConnectionId == id)));   // the key for the old server is gone
    }

    [Fact]
    public async Task Many_people_changing_access_at_once_never_leave_duplicate_or_missing_grants()
    {
        var w = await Workspace.CreateAsync(_factory);
        var bob = await w.AddAsync(); var carol = await w.AddAsync();
        var id = await w.NoneAsync(_fake, access: ConnectionHelpers.Only());
        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(i => w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/mcp-connections/{id}/access",
            new { access = ConnectionHelpers.Only(i % 2 == 0 ? bob.MemberId : carol.MemberId, bob.MemberId) })));
        Assert.All(results, r => Assert.True(r.Status is HttpStatusCode.OK or HttpStatusCode.Conflict, $"{r.Status} {r.Body}"));
        var grants = _factory.WithDb(db => db.Set<ConnectionAccessGrant>().Where(g => g.ConnectionId == id).Select(g => g.MemberId).ToList());
        Assert.Equal(grants.Distinct().Count(), grants.Count);
        Assert.Contains(bob.MemberId, grants);
    }

    // ---------- catalog and discovery ----------

    [Fact]
    public async Task The_catalog_lists_presets_with_what_each_needs()
    {
        var w = await Workspace.CreateAsync(_factory);
        var bob = await w.AddAsync();
        var r = await w.CallAsync(bob, HttpMethod.Get, "/v1/mcp-connections/presets");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        var presets = r.Body.GetProperty("presets").EnumerateArray().ToList();
        Assert.Equal(new[] { "github", "notion", "linear", "stripe", "sentry", "granola", "polar", "slack", "exa", "render", "context7" }, presets.Select(p => p.GetProperty("presetId").GetString()).ToArray());
        var github = presets[0]; Assert.True(github.GetProperty("requiresOAuthClient").GetBoolean()); Assert.EndsWith("/v1/mcp-connections/oauth/callback", github.GetProperty("oauthCallbackUrl").GetString());
        Assert.Equal("https://mcp.notion.com/mcp", presets[1].GetProperty("url").GetString());
        Assert.Equal("apikey", presets.Single(p => p.GetProperty("presetId").GetString() == "exa").GetProperty("authType").GetString());
        Assert.Equal(11, presets.Select(p => p.GetProperty("presetId").GetString()).Distinct().Count());
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Http.GetAsync("/v1/mcp-connections/presets")).StatusCode);
    }

    [Fact]
    public async Task Discovery_reports_what_a_server_needs_without_saving_or_registering_anything()
    {
        var w = await Workspace.CreateAsync(_factory);
        var bob = await w.AddAsync();
        var oauth = (await w.CallAsync(bob, HttpMethod.Post, "/v1/mcp-connections/discover", new { url = _fake.Url("oauth") })).Body;
        Assert.Equal("oauth", oauth.GetProperty("authentication").GetProperty("kind").GetString());
        Assert.Equal("dynamic", oauth.GetProperty("authentication").GetProperty("recommendedRegistrationMethod").GetString());
        Assert.Equal("authentication_required", oauth.GetProperty("server").GetProperty("initialize").GetString());
        var none = (await w.CallAsync(bob, HttpMethod.Post, "/v1/mcp-connections/discover", new { url = _fake.Url("none") })).Body;
        Assert.Equal(3, none.GetProperty("tools").GetProperty("count").GetInt32());
        var key = (await w.CallAsync(bob, HttpMethod.Post, "/v1/mcp-connections/discover", new { url = _fake.Url("key") })).Body;
        Assert.Equal("manual_bearer", key.GetProperty("authentication").GetProperty("kind").GetString());
        Assert.DoesNotContain(_fake.OAuthCalls, c => c.Kind is "register" or "authorize");
        Assert.Empty((await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/mcp-connections?scope=manageable")).Body.GetProperty("connections").EnumerateArray());
        var resolved = (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/mcp-connections/resolve", new { query = _fake.Url("none") })).Body;
        Assert.Equal("discovered", resolved.GetProperty("resolution").GetString());
        var preset = (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/mcp-connections/resolve", new { query = "Notion" })).Body;
        Assert.Equal("preset", preset.GetProperty("resolution").GetString());
        Assert.Equal("not_found", (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/mcp-connections/resolve", new { query = "two words" })).Body.GetProperty("resolution").GetString());
    }
}

/// <summary>Outbound calls to addresses people typed in: private, loopback and link-local addresses are refused by default.</summary>
public sealed class ConnectionSsrfTests : IClassFixture<ApiFactory>
{
    private readonly ApiFactory _factory;
    public ConnectionSsrfTests(ApiFactory factory) => _factory = factory;

    [Theory]
    [InlineData("8.8.8.8", true)] [InlineData("1.1.1.1", true)] [InlineData("2606:4700:4700::1111", true)]
    [InlineData("127.0.0.1", false)] [InlineData("127.1.2.3", false)] [InlineData("10.0.0.1", false)] [InlineData("172.16.5.5", false)] [InlineData("172.31.255.255", false)] [InlineData("192.168.1.1", false)]
    [InlineData("169.254.169.254", false)] [InlineData("100.64.0.1", false)] [InlineData("0.0.0.0", false)] [InlineData("224.0.0.1", false)] [InlineData("255.255.255.255", false)]
    [InlineData("::1", false)] [InlineData("::", false)] [InlineData("fe80::1", false)] [InlineData("fc00::1", false)] [InlineData("fd12:3456::1", false)] [InlineData("::ffff:127.0.0.1", false)] [InlineData("::ffff:10.1.1.1", false)] [InlineData("::ffff:169.254.169.254", false)]
    [InlineData("64:ff9b::7f00:1", false)] [InlineData("2002:7f00:1::", false)]
    public void Only_public_addresses_pass(string address, bool expected) => Assert.Equal(expected, GuardedHttp.IsPublic(System.Net.IPAddress.Parse(address)));

    [Theory]
    [InlineData("https://127.0.0.1/mcp")] [InlineData("https://localhost/mcp")] [InlineData("https://[::1]/mcp")] [InlineData("https://169.254.169.254/latest/meta-data")] [InlineData("https://10.0.0.5/mcp")]
    [InlineData("https://192.168.0.1/mcp")] [InlineData("https://[::ffff:127.0.0.1]/mcp")] [InlineData("https://0.0.0.0/mcp")] [InlineData("https://2130706433/mcp")] [InlineData("https://0x7f.0.0.1/mcp")] [InlineData("https://127.1/mcp")]
    public async Task Creating_a_connection_to_an_internal_address_is_refused_by_default(string url)
    {
        var w = await Workspace.CreateAsync(_factory);
        var r = await w.Post(w.Owner, new { name = "Internal", url, authType = "none" });
        Assert.Equal(HttpStatusCode.BadRequest, r.Status);
        Assert.Equal("invalid_request", Workspace.Error(r.Body));
        Assert.Empty((await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/mcp-connections?scope=manageable")).Body.GetProperty("connections").EnumerateArray());
    }

    [Fact]
    public async Task Plain_http_is_refused_and_so_is_discovery_resolve_and_manual_sign_in_addresses_on_internal_hosts()
    {
        var w = await Workspace.CreateAsync(_factory);
        var http = await w.Post(w.Owner, new { name = "X", url = "http://example.com/mcp", authType = "none" });
        Assert.Equal(HttpStatusCode.BadRequest, http.Status);
        Assert.Equal("url: Hosted MCP connections must use HTTPS.", http.Msg());
        Assert.Equal(HttpStatusCode.BadGateway, (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/mcp-connections/discover", new { url = "https://127.0.0.1/mcp" })).Status);
        var stream = await w.Http.SendAsync(w.As(w.Owner, HttpMethod.Post, "/v1/mcp-connections/discover/stream", new { url = "https://169.254.169.254/" }));
        Assert.Contains("event: error", await stream.Content.ReadAsStringAsync());
        Assert.Equal("not_found", (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/mcp-connections/resolve", new { query = "https://10.0.0.1/mcp" })).Body.GetProperty("resolution").GetString());
        var manual = await w.Post(w.Owner, new { name = "X", url = "https://example.com/mcp", authType = "oauth", oauthClient = new { clientId = "c" }, manualOAuthEndpoints = new { authorizationEndpoint = "https://127.0.0.1/a", tokenEndpoint = "https://10.0.0.1/t" } });
        Assert.Equal(HttpStatusCode.BadRequest, manual.Status);
    }

    [Fact]
    public async Task The_guard_refuses_a_host_name_that_resolves_to_an_internal_address()
    {
        var guard = new GuardedHttp(Microsoft.Extensions.Options.Options.Create(new ConnectionsOptions()));
        await Assert.ThrowsAsync<UrlRefusedException>(() => guard.SendAsync(new HttpRequestMessage(HttpMethod.Get, "https://localhost:9/"), TimeSpan.FromSeconds(5)));
        await Assert.ThrowsAsync<UrlRefusedException>(() => guard.SendAsync(new HttpRequestMessage(HttpMethod.Get, "http://example.com/"), TimeSpan.FromSeconds(5)));
        await Assert.ThrowsAsync<UrlRefusedException>(() => guard.SendAsync(new HttpRequestMessage(HttpMethod.Get, "https://user:pw@example.com/"), TimeSpan.FromSeconds(5)));
    }
}

/// <summary>Timeouts and response size limits on what remote servers send back.</summary>
public sealed class ConnectionLimitTests : IClassFixture<ConnectionLimitsFactory>, IAsyncLifetime
{
    private readonly ConnectionLimitsFactory _factory;
    private FakeMcpServer _fake = null!;
    public ConnectionLimitTests(ConnectionLimitsFactory factory) => _factory = factory;
    public async Task InitializeAsync() => _fake = await FakeMcpServer.StartAsync();
    public async Task DisposeAsync() => await _fake.DisposeAsync();

    [Fact]
    public async Task A_slow_server_times_out_and_an_oversized_answer_is_refused()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await w.NoneAsync(_fake, access: ConnectionHelpers.Only(w.Owner.MemberId));
        _fake.SlowMs = 4000;
        var slow = await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/mcp-connections/{id}/tools/call", new { toolName = "echo", arguments = new { message = "x" } });
        Assert.Equal(HttpStatusCode.BadGateway, slow.Status);
        Assert.Equal("MCP_REQUEST_TIMEOUT", slow.Body.GetProperty("diagnostic").GetProperty("code").GetString());
        _fake.SlowMs = 0;
        _fake.BigBody = true;
        var big = await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/mcp-connections/{id}/tools/call", new { toolName = "echo", arguments = new { message = "x" } });
        Assert.Equal(HttpStatusCode.BadGateway, big.Status);
        Assert.Equal("MCP_RESPONSE_TOO_LARGE", big.Body.GetProperty("diagnostic").GetProperty("code").GetString());
        // The same through an agent: an error the agent can read, not a hang or a crash.
        var token = await w.MintAsync(w.Owner, "mcp:read", "mcp:write");
        Assert.Equal("connection_failed", (await w.ExecuteAsync(token, $"mcp:{id}:echo", new { message = "x" })).ErrorOf());
    }
}
