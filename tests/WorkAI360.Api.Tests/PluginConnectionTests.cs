using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Domain.Connections;
using WorkAI360.Api.Domain.PluginConnections;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

internal static class PluginConnectionHelpers
{
    private static int _n;

    /// <summary>A plugin with one MCP component that declares a server at its own address (servers at one address share a connection).</summary>
    public static async Task<(string PluginId, string ObjectId)> McpPluginAsync(this Workspace w, FakeMcpServer fake, string name, Person? by = null, string kind = "none", string? address = null, object? extra = null)
    {
        var url = address ?? $"{fake.Url(kind)}?t={Interlocked.Increment(ref _n)}";
        var server = new Dictionary<string, object?> { ["type"] = "remote", ["url"] = url };
        if (extra is not null) foreach (var p in extra.GetType().GetProperties()) server[p.Name] = p.GetValue(extra);
        var payload = new { mcpServers = new Dictionary<string, object?> { ["docs"] = server } };
        var r = await w.CallAsync(by ?? w.Owner, HttpMethod.Post, "/v1/plugins", new { name, components = new[] { new { type = "mcp", input = new { rawSourceText = JsonSerializer.Serialize(payload), normalizedPayloadJson = payload, metadata = new { name = "Docs MCP" } } } } });
        Assert.True(r.Status == HttpStatusCode.Created, $"plugin {name}: {r.Status} {r.Body}");
        var id = r.Body.GetProperty("item").GetProperty("id").GetString()!;
        var objects = await w.CallAsync(by ?? w.Owner, HttpMethod.Get, $"/v1/plugins/{id}/config-objects");
        return (id, objects.Body.GetProperty("items")[0].GetProperty("configObjectId").GetString()!);
    }

    public static Task<(HttpStatusCode Status, JsonElement Body)> ConfigureAsync(this Workspace w, Person by, string pluginId, string objectId, object? body = null) =>
        w.CallAsync(by, HttpMethod.Post, $"/v1/plugins/{pluginId}/mcp-connections", body ?? new { configObjectId = objectId, serverName = "docs", authType = "none" });

    public static async Task<string> BindAsync(this Workspace w, string pluginId, string objectId)
    {
        var r = await w.ConfigureAsync(w.Owner, pluginId, objectId);
        Assert.True(r.Status == HttpStatusCode.OK, $"configure: {r.Status} {r.Body}");
        return r.Body.GetProperty("item").GetProperty("connection").GetProperty("id").GetString()!;
    }

    public static async Task<JsonElement[]> UsableAsync(this Workspace w, Person who)
    {
        var r = await w.CallAsync(who, HttpMethod.Get, "/v1/mcp-connections?scope=usable");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        return r.Body.GetProperty("connections").EnumerateArray().ToArray();
    }

    public static async Task<JsonElement[]> ManageableAsync(this Workspace w, Person who)
    {
        var r = await w.CallAsync(who, HttpMethod.Get, "/v1/mcp-connections?scope=manageable");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        return r.Body.GetProperty("connections").EnumerateArray().ToArray();
    }

    public static bool Has(this IEnumerable<JsonElement> connections, string id) => connections.Any(c => c.GetProperty("id").GetString() == id);

    public static string[] RequiredByNames(this JsonElement connection) => connection.GetProperty("requiredBy").EnumerateArray().Select(x => x.GetProperty("name").GetString()!).ToArray();

    public static Task Share(this Workspace w, string pluginId, object subject) => w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/plugins/{pluginId}/access", subject);
}

public sealed class PluginConnectionTests : IClassFixture<ConnectionFactory>, IAsyncLifetime
{
    private readonly ConnectionFactory _factory;
    private FakeMcpServer _fake = null!;
    public PluginConnectionTests(ConnectionFactory factory) => _factory = factory;
    public async Task InitializeAsync() => _fake = await FakeMcpServer.StartAsync();
    public async Task DisposeAsync() => await _fake.DisposeAsync();

    // ---------- who may use a connection through a plugin ----------

    [Fact]
    public async Task A_connection_is_usable_through_a_plugin_only_by_those_the_plugin_is_shared_with()
    {
        var w = await Workspace.CreateAsync(_factory, "Bound access");
        var bob = await w.AddAsync(); var carol = await w.AddAsync(); var dave = await w.AddAsync();
        var (plugin, cob) = await w.McpPluginAsync(_fake, "Bound plugin");
        var connection = await w.BindAsync(plugin, cob);

        // Nobody was given anything: only the maker (a manager of the plugin) may use it. Being an admin or owner adds nothing by itself.
        Assert.False((await w.UsableAsync(bob)).Has(connection));
        Assert.False((await w.UsableAsync(carol)).Has(connection));

        await w.Share(plugin, new { orgMembershipId = bob.MemberId, role = "viewer" });
        Assert.True((await w.UsableAsync(bob)).Has(connection));
        Assert.False((await w.UsableAsync(carol)).Has(connection));
        Assert.False((await w.UsableAsync(dave)).Has(connection));

        // The connection's own access list did not change: the use comes from the plugin.
        var owner = (await w.ManageableAsync(w.Owner)).Single(c => c.GetProperty("id").GetString() == connection);
        Assert.Empty(owner.GetProperty("access").GetProperty("memberIds").EnumerateArray());

        // Tools of a usable connection can be listed by the person, and an unrelated person is refused.
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(bob, HttpMethod.Get, $"/v1/mcp-connections/{connection}/tools")).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(carol, HttpMethod.Get, $"/v1/mcp-connections/{connection}/tools")).Status);

        // Removing the grant withdraws the use at once.
        var grants = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/plugins/{plugin}/access");
        var grantId = grants.Body.GetProperty("items").EnumerateArray().First(g => g.TryGetProperty("orgMembershipId", out var m) && m.GetString() == bob.MemberId).GetProperty("id").GetString();
        Assert.Equal(HttpStatusCode.NoContent, (await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/plugins/{plugin}/access/{grantId}")).Status);
        Assert.False((await w.UsableAsync(bob)).Has(connection));
    }

    [Fact]
    public async Task A_team_grant_a_marketplace_grant_and_a_grant_on_the_object_each_open_the_connection_and_archiving_closes_it()
    {
        var w = await Workspace.CreateAsync(_factory, "Bound routes");
        var team = await w.AddAsync(); var shelf = await w.AddAsync(); var outsider = await w.AddAsync();
        var teamId = await w.TeamAsync("Readers", team);
        var (plugin, cob) = await w.McpPluginAsync(_fake, "Team plugin");
        var connection = await w.BindAsync(plugin, cob);

        await w.Share(plugin, new { teamId, role = "viewer" });
        Assert.True((await w.UsableAsync(team)).Has(connection));
        Assert.False((await w.UsableAsync(outsider)).Has(connection));

        var market = (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/marketplaces", new { name = "Shelf" })).Body.GetProperty("item").GetProperty("id").GetString()!;
        await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/marketplaces/{market}/plugins", new { pluginId = plugin });
        await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/marketplaces/{market}/access", new { orgMembershipId = shelf.MemberId, role = "viewer" });
        Assert.True((await w.UsableAsync(shelf)).Has(connection));
        // An archived shelf stops opening what is on it.
        await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/marketplaces/{market}/archive", new { });
        Assert.False((await w.UsableAsync(shelf)).Has(connection));
        await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/marketplaces/{market}/restore", new { });
        Assert.True((await w.UsableAsync(shelf)).Has(connection));

        // Archiving the plugin withdraws every route at once; restoring brings them back.
        await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/plugins/{plugin}/archive", new { });
        Assert.False((await w.UsableAsync(team)).Has(connection));
        Assert.False((await w.UsableAsync(shelf)).Has(connection));
        await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/plugins/{plugin}/restore", new { });
        Assert.True((await w.UsableAsync(team)).Has(connection));

        // A plugin taken off the shelf no longer opens the connection through the shelf.
        Assert.Equal(HttpStatusCode.NoContent, (await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/marketplaces/{market}/plugins/{plugin}")).Status);
        Assert.False((await w.UsableAsync(shelf)).Has(connection));

        // A grant on the MCP object itself opens it too.
        await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/config-objects/{cob}/access", new { orgMembershipId = outsider.MemberId, role = "viewer" });
        Assert.True((await w.UsableAsync(outsider)).Has(connection));
        // ...unless the object is taken out of the plugin.
        await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/plugins/{plugin}/config-objects/{cob}");
        Assert.False((await w.UsableAsync(outsider)).Has(connection));
        Assert.False((await w.UsableAsync(team)).Has(connection));
    }

    [Fact]
    public async Task Another_workspaces_grants_never_open_a_connection()
    {
        var w = await Workspace.CreateAsync(_factory, "Bound isolation");
        var other = await Workspace.CreateAsync(_factory, "Bound isolation other");
        var (plugin, cob) = await w.McpPluginAsync(_fake, "Mine");
        var connection = await w.BindAsync(plugin, cob);
        // The other workspace's owner shares nothing of mine, and cannot name my plugin, object or connection.
        Assert.Equal(HttpStatusCode.NotFound, (await other.ConfigureAsync(other.Owner, plugin, cob)).Status);
        Assert.False((await other.UsableAsync(other.Owner)).Has(connection));
        var (theirPlugin, theirCob) = await other.McpPluginAsync(_fake, "Theirs");
        Assert.Equal("mcp_requirement_not_found", Workspace.Error((await w.ConfigureAsync(w.Owner, theirPlugin, theirCob)).Body));
        Assert.Equal("mcp_requirement_not_found", Workspace.Error((await w.ConfigureAsync(w.Owner, plugin, theirCob)).Body));
        var theirConnection = await other.BindAsync(theirPlugin, theirCob);
        var steal = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/plugins", new { name = "Steals 2", components = new[] { new { type = "mcp", connectionId = theirConnection } } });
        Assert.Equal(HttpStatusCode.NotFound, steal.Status);
        Assert.Equal("mcp_connection_not_found", Workspace.Error(steal.Body));
    }

    // ---------- what a person may learn ----------

    [Fact]
    public async Task requiredBy_names_only_plugins_the_reader_may_see()
    {
        var w = await Workspace.CreateAsync(_factory, "Provenance");
        var bob = await w.AddAsync(); var carol = await w.AddAsync();
        // One connection, given to everyone directly, needed by two plugins.
        var address = $"{_fake.Url("none")}?t=provenance";
        var (open, openCob) = await w.McpPluginAsync(_fake, "Open plugin", address: address);
        var (secret, secretCob) = await w.McpPluginAsync(_fake, "Confidential plugin", address: address);
        var connection = await w.BindAsync(open, openCob);
        Assert.Equal(connection, await w.BindAsync(secret, secretCob));
        await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/mcp-connections/{connection}/access", new { access = new { orgWide = true, memberIds = Array.Empty<string>(), teamIds = Array.Empty<string>() } });
        await w.Share(open, new { orgMembershipId = bob.MemberId, role = "viewer" });

        var asBob = (await w.UsableAsync(bob)).Single(c => c.GetProperty("id").GetString() == connection);
        Assert.Equal(["Open plugin"], asBob.RequiredByNames());
        Assert.DoesNotContain("Confidential", asBob.ToString());
        var asCarol = (await w.UsableAsync(carol)).Single(c => c.GetProperty("id").GetString() == connection);
        Assert.Empty(asCarol.GetProperty("requiredBy").EnumerateArray());
        Assert.Empty(asCarol.GetProperty("identityManagedBy").EnumerateArray());
        var asOwner = (await w.ManageableAsync(w.Owner)).Single(c => c.GetProperty("id").GetString() == connection);
        Assert.Equal(["Confidential plugin", "Open plugin"], asOwner.RequiredByNames());
        // The person asking to remove the connection learns only what they may see either.
        var removal = await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/mcp-connections/{connection}/removal-request", new { expectedName = asOwner.GetProperty("name").GetString() });
        Assert.Equal(2, removal.Body.GetProperty("requiredBy").GetArrayLength());
    }

    [Fact]
    public async Task A_marketplace_viewer_who_cannot_use_the_bound_connection_is_not_told_about_it()
    {
        var w = await Workspace.CreateAsync(_factory, "Readiness privacy");
        // A role that manages everything shared (so the person sees every plugin) but may not list connections.
        var manager = await w.AddAsync();
        var teamId = await w.TeamAsync("Curators", manager);
        await w.RoleAsync(teamId, "sharing.manage_all");
        var market = (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/marketplaces", new { name = "Readiness shelf" })).Body.GetProperty("item").GetProperty("id").GetString()!;
        var (plugin, cob) = await w.McpPluginAsync(_fake, "Privacy plugin");
        var connection = await w.BindAsync(plugin, cob);
        await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/marketplaces/{market}/plugins", new { pluginId = plugin });

        Assert.False((await w.UsableAsync(manager)).Has(connection));
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(manager, HttpMethod.Get, "/v1/mcp-connections?scope=manageable")).Status);

        var readiness = (await w.CallAsync(manager, HttpMethod.Get, $"/v1/marketplaces/{market}/resolved")).Body.GetProperty("item").GetProperty("plugins")[0].GetProperty("cloudReadiness");
        Assert.Equal("needs_admin_setup", readiness.GetProperty("state").GetString());
        var entry = readiness.GetProperty("connections")[0];
        Assert.Equal(JsonValueKind.Null, entry.GetProperty("id").ValueKind);
        Assert.Equal("docs", entry.GetProperty("name").GetString());
        Assert.DoesNotContain(connection, readiness.ToString());
        Assert.DoesNotContain("Privacy plugin / docs", readiness.ToString());

        // The owner (who may use it) sees it ready.
        var owner = (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/marketplaces/{market}/resolved")).Body.GetProperty("item").GetProperty("plugins")[0].GetProperty("cloudReadiness");
        Assert.Equal("ready", owner.GetProperty("state").GetString());
        Assert.Equal(connection, owner.GetProperty("connections")[0].GetProperty("id").GetString());
    }

    [Fact]
    public async Task Configuring_a_plugin_needs_both_the_permission_and_the_right_to_see_the_plugin()
    {
        var w = await Workspace.CreateAsync(_factory, "Configure rights");
        var bob = await w.AddAsync(); var clerk = await w.AddAsync();
        var teamId = await w.TeamAsync("Connection clerks", clerk);
        await w.RoleAsync(teamId, "connections.manage");
        var (plugin, cob) = await w.McpPluginAsync(_fake, "Not for clerks");

        var member = await w.ConfigureAsync(bob, plugin, cob);
        Assert.Equal(HttpStatusCode.Forbidden, member.Status);
        Assert.Equal("connections.manage", member.Body.GetProperty("requiredPermission").GetString());
        // The clerk holds the permission but cannot see the plugin: refused, and nothing is created.
        var before = (await w.ManageableAsync(w.Owner)).Length;
        var clerkTry = await w.ConfigureAsync(clerk, plugin, cob);
        Assert.Equal(HttpStatusCode.Forbidden, clerkTry.Status);
        Assert.DoesNotContain("Not for clerks", clerkTry.Body.ToString());
        Assert.Equal(before, (await w.ManageableAsync(w.Owner)).Length);
        // Once the plugin is shared with them, they may.
        await w.Share(plugin, new { orgMembershipId = clerk.MemberId, role = "viewer" });
        Assert.Equal(HttpStatusCode.OK, (await w.ConfigureAsync(clerk, plugin, cob)).Status);
    }

    // ---------- the connection stays the plugin's to manage ----------

    [Fact]
    public async Task A_connection_a_plugin_needs_cannot_have_its_address_or_sign_in_changed_but_can_be_renamed()
    {
        var w = await Workspace.CreateAsync(_factory, "Managed edits");
        var (plugin, cob) = await w.McpPluginAsync(_fake, "Managing plugin");
        var connection = await w.BindAsync(plugin, cob);
        var current = (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/mcp-connections/{connection}")).Body;
        object Edit(string name, string url, JsonElement c) => new { name, url, authType = "none", credentialMode = "shared", expectedUpdatedAt = c.GetProperty("updatedAt").GetString(), access = new { orgWide = false, memberIds = Array.Empty<string>(), teamIds = Array.Empty<string>() } };

        var moved = await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/mcp-connections/{connection}", Edit("Moved", current.GetProperty("url").GetString() + "&x=1", current));
        Assert.Equal(HttpStatusCode.Conflict, moved.Status);
        Assert.Equal("marketplace_managed", moved.Body.GetProperty("error").GetString());
        Assert.Contains("Managing plugin", moved.Msg());
        var renamed = await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/mcp-connections/{connection}", Edit("A nicer name", current.GetProperty("url").GetString()!, current));
        Assert.Equal(HttpStatusCode.OK, renamed.Status);

        // A person who cannot see the plugin is not told its name in the refusal.
        var admin = await w.AddAsync();
        var teamId = await w.TeamAsync("Editors", admin);
        await w.RoleAsync(teamId, "connections.update", "connections.view");
        var now = (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/mcp-connections/{connection}")).Body;
        var refusal = await w.CallAsync(admin, HttpMethod.Put, $"/v1/mcp-connections/{connection}", Edit("A nicer name", now.GetProperty("url").GetString() + "&y=1", now));
        Assert.Equal(HttpStatusCode.Conflict, refusal.Status);
        Assert.DoesNotContain("Managing plugin", refusal.Msg());
        Assert.StartsWith("A marketplace plugin owns", refusal.Msg());
    }

    [Fact]
    public async Task A_key_entered_for_a_plugin_is_encrypted_never_returned_and_a_wrong_key_leaves_nothing()
    {
        var w = await Workspace.CreateAsync(_factory, "Plugin keys");
        var (plugin, cob) = await w.McpPluginAsync(_fake, "Keyed", kind: "key");
        var bad = await w.ConfigureAsync(w.Owner, plugin, cob, new { configObjectId = cob, serverName = "docs", authType = "apikey", apiKey = "wrong-wrong-wrong" });
        Assert.Equal(HttpStatusCode.BadRequest, bad.Status);
        Assert.Equal("credential_rejected", Workspace.Error(bad.Body));
        Assert.DoesNotContain("wrong-wrong-wrong", bad.Body.ToString());
        Assert.Empty(await w.ManageableAsync(w.Owner));

        var good = await w.ConfigureAsync(w.Owner, plugin, cob, new { configObjectId = cob, serverName = "docs", authType = "apikey", apiKey = FakeMcpServer.Key });
        Assert.Equal(HttpStatusCode.OK, good.Status);
        Assert.DoesNotContain(FakeMcpServer.Key, good.Body.ToString());
        Assert.DoesNotContain(FakeMcpServer.Key, (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/mcp-connections?scope=manageable")).Body.ToString());
        var stored = _factory.WithDb(db => db.Set<ExternalMcpConnection>().AsNoTracking().Single(c => c.OrganizationId == w.OrgId).ApiKeyEnc);
        Assert.NotNull(stored);
        Assert.DoesNotContain(FakeMcpServer.Key, stored);

        // The key is refused when it arrives through an API key (a machine), as the reference refuses it.
        var (_, secret) = await w.MakeKeyAsync();
        var viaKey = await w.WithKeyAsync(secret, HttpMethod.Post, $"/v1/plugins/{plugin}/mcp-connections", new { configObjectId = cob, serverName = "docs", authType = "apikey", apiKey = FakeMcpServer.Key });
        Assert.Equal(HttpStatusCode.BadRequest, viaKey.Status);
        Assert.Equal("secure_entry_required", Workspace.Error(viaKey.Body));
    }

    [Fact]
    public async Task A_connection_made_for_a_plugin_retires_with_it_and_deleting_the_connection_removes_the_binding()
    {
        var w = await Workspace.CreateAsync(_factory, "Retiring");
        var (plugin, cob) = await w.McpPluginAsync(_fake, "Retiring plugin");
        var connection = await w.BindAsync(plugin, cob);
        Assert.True((await w.ManageableAsync(w.Owner)).Has(connection));
        await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/plugins/{plugin}/archive", new { });
        Assert.False((await w.ManageableAsync(w.Owner)).Has(connection));
        await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/plugins/{plugin}/restore", new { });
        Assert.True((await w.ManageableAsync(w.Owner)).Has(connection));

        // A connection an admin made first is never retired.
        var bob = await w.AddAsync();
        var made = await w.Post(w.Owner, new { name = "Admin made", url = _fake.Url("none") + "?t=admin", authType = "none", access = new { orgWide = false, memberIds = Array.Empty<string>(), teamIds = Array.Empty<string>() } });
        var adminConnection = made.Body.GetProperty("id").GetString()!;
        var (p2, c2) = await w.McpPluginAsync(_fake, "Uses admin one", address: _fake.Url("none") + "?t=admin");
        Assert.Equal(adminConnection, await w.BindAsync(p2, c2));
        Assert.False((await w.UsableAsync(bob)).Has(adminConnection));
        await w.Share(p2, new { orgMembershipId = bob.MemberId, role = "viewer" });
        Assert.True((await w.UsableAsync(bob)).Has(adminConnection));
        await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/plugins/{p2}/archive", new { });
        Assert.True((await w.ManageableAsync(w.Owner)).Has(adminConnection));
        // The plugin is archived, so it no longer opens the connection (the connection itself stays, as an admin made it).
        Assert.False((await w.UsableAsync(bob)).Has(adminConnection));

        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/mcp-connections/{connection}")).Status);
        Assert.Equal(0, _factory.WithDb(db => db.Set<PluginMcpBinding>().Count(b => b.ConnectionId == connection)));
    }

    [Fact]
    public async Task Two_people_configuring_the_same_server_at_once_end_up_with_one_connection()
    {
        var w = await Workspace.CreateAsync(_factory, "Racing");
        var other = await w.AddAsync("admin");
        var address = $"{_fake.Url("none")}?t=race";
        var (p1, c1) = await w.McpPluginAsync(_fake, "Race one", address: address);
        var (p2, c2) = await w.McpPluginAsync(_fake, "Race two", address: address);
        var results = await Task.WhenAll(Enumerable.Range(0, 6).Select(i => i % 2 == 0 ? w.ConfigureAsync(w.Owner, p1, c1) : w.ConfigureAsync(w.Owner, p2, c2)));
        Assert.All(results, r => Assert.Equal(HttpStatusCode.OK, r.Status));
        Assert.Single(results.Select(r => r.Body.GetProperty("item").GetProperty("connection").GetProperty("id").GetString()).Distinct());
        Assert.Equal(1, _factory.WithDb(db => db.Set<ExternalMcpConnection>().Count(c => c.OrganizationId == w.OrgId)));
        _ = other;
    }

    // ---------- creating a plugin with connections ----------

    [Fact]
    public async Task Creating_a_plugin_with_a_connection_configures_it_and_a_failure_archives_the_plugin_and_removes_what_it_made()
    {
        var w = await Workspace.CreateAsync(_factory, "Inline");
        var payload = new { mcpServers = new { docs = new { type = "remote", url = _fake.Url("key") + "?t=inline" } } };
        object Body(string name, string key) => new { name, components = new[] { new { type = "mcp", connection = new { authType = "apikey", apiKey = key }, input = new { normalizedPayloadJson = payload, metadata = new { name = "Docs" } } } } };

        var bad = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/plugins", Body("Inline plugin", "not-the-key"));
        Assert.Equal(HttpStatusCode.BadRequest, bad.Status);
        Assert.Equal("credential_rejected", Workspace.Error(bad.Body));
        Assert.Empty(await w.ManageableAsync(w.Owner));
        var plugins = await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/plugins?status=active");
        Assert.DoesNotContain(plugins.Body.GetProperty("items").EnumerateArray(), p => p.GetProperty("name").GetString() == "Inline plugin");

        // The name is free again, and the right key works.
        var good = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/plugins", Body("Inline plugin", FakeMcpServer.Key));
        Assert.Equal(HttpStatusCode.Created, good.Status);
        var connection = (await w.ManageableAsync(w.Owner)).Single();
        Assert.Equal(["Inline plugin"], connection.RequiredByNames());
        Assert.Equal("Inline plugin / docs", connection.GetProperty("name").GetString());
    }

    [Fact]
    public async Task A_member_may_bind_only_a_connection_they_made_and_may_not_configure_one()
    {
        var w = await Workspace.CreateAsync(_factory, "Member binding");
        var bob = await w.AddAsync();
        var admin = await w.Post(w.Owner, new { name = "Org owned", url = _fake.Url("none") + "?t=org", authType = "none" });
        var orgConnection = admin.Body.GetProperty("id").GetString()!;
        var refused = await w.CallAsync(bob, HttpMethod.Post, "/v1/plugins", new { name = "Bob binds", components = new[] { new { type = "mcp", connectionId = orgConnection } } });
        Assert.Equal(HttpStatusCode.Forbidden, refused.Status);

        // Bob's own connection (per-person sign-in, which members may add).
        var mine = await w.Post(bob, new { name = "Bob's", url = _fake.Url("none") + "?t=bob", authType = "none", access = new { orgWide = false, memberIds = Array.Empty<string>(), teamIds = Array.Empty<string>() } });
        Assert.True(mine.Status == HttpStatusCode.OK, $"{mine.Status} {mine.Body}");
        var ok = await w.CallAsync(bob, HttpMethod.Post, "/v1/plugins", new { name = "Bob binds mine", components = new[] { new { type = "mcp", connectionId = mine.Body.GetProperty("id").GetString() } } });
        Assert.Equal(HttpStatusCode.Created, ok.Status);
        var inline = await w.CallAsync(bob, HttpMethod.Post, "/v1/plugins", new { name = "Bob inline", components = new[] { new { type = "mcp", connection = new { authType = "none" }, input = new { normalizedPayloadJson = new { mcpServers = new { docs = new { type = "remote", url = _fake.Url("none") } } } } } } });
        Assert.Equal(HttpStatusCode.Forbidden, inline.Status);
    }
}
