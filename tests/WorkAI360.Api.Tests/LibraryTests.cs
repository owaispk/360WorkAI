using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>A stand-in for GitHub (API and raw files) on a local port, so import is tested for real over HTTP without the internet.</summary>
public sealed class FakeGithub : IAsyncDisposable
{
    private readonly WebApplication _app;
    public string BaseUrl { get; }
    public Dictionary<string, string> Files { get; } = new();
    public int Requests;

    public FakeGithub()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Configuration["urls"] = "http://127.0.0.1:0";
        _app = builder.Build();
        _app.Use(async (ctx, next) => { Interlocked.Increment(ref Requests); await next(); });
        _app.MapGet("/repos/o/r", () => Results.Json(new { default_branch = "main", @private = false }));
        _app.MapGet("/repos/o/secret", () => Results.Json(new { default_branch = "main", @private = true }));
        _app.MapGet("/repos/o/limited", () => Results.Json(new { message = "API rate limit exceeded" }, statusCode: 403));
        _app.MapGet("/repos/o/missing", () => Results.Json(new { message = "Not Found" }, statusCode: 404));
        _app.MapGet("/repos/o/r/commits/{branch}", (string branch) => branch == "main" || branch == "dev" ? Results.Json(new { sha = "abc123", commit = new { tree = new { sha = "tree1" } } }) : Results.Json(new { message = "No commit found" }, statusCode: 404));
        _app.MapGet("/repos/o/r/git/trees/tree1", () => Results.Json(new { truncated = false, tree = Files.Keys.Select(path => new { path, type = "blob", sha = "s" + path.GetHashCode() }).ToArray() }));
        _app.MapGet("/o/r/abc123/{**path}", (string path) => Files.TryGetValue(path, out var text) ? Results.Text(text) : Results.NotFound());
        _app.Start();
        BaseUrl = _app.Urls.First();
    }

    public async ValueTask DisposeAsync() => await _app.DisposeAsync();
}

public sealed class LibraryFactory : ApiFactory
{
    public FakeGithub Github { get; } = new();
    protected override IEnumerable<KeyValuePair<string, string>> Settings =>
    [
        new("Library:GithubApiBase", Github.BaseUrl),
        new("Library:GithubRawBase", Github.BaseUrl),
    ];

    public override async ValueTask DisposeAsync()
    {
        await Github.DisposeAsync();
        await base.DisposeAsync();
    }
}

public static class LibraryHelpers
{
    public static string Skill(string name, string description = "Does a thing", string body = "Do the thing.") => $"---\nname: {name}\ndescription: {description}\n---\n\n{body}\n";

    public static async Task<string> PluginAsync(this Workspace w, Person by, string name, params string[] skills)
    {
        var r = await w.CallAsync(by, HttpMethod.Post, "/v1/plugins", new { name, components = skills.Select(s => new { type = "skill", input = new { rawSourceText = s } }).ToArray() });
        Assert.True(r.Status == HttpStatusCode.Created, $"create plugin {name}: {r.Status} {r.Body}");
        return r.Body.GetProperty("item").GetProperty("id").GetString()!;
    }

    public static async Task<string> SkillIdAsync(this Workspace w, Person by, string pluginId, int index = 0)
    {
        var r = await w.CallAsync(by, HttpMethod.Get, $"/v1/plugins/{pluginId}/resolved");
        return r.Body.GetProperty("items")[index].GetProperty("configObjectId").GetString()!;
    }

    public static async Task<JsonElement> ShareAsync(this Workspace w, Person by, string kind, string id, object target, string role = "viewer")
    {
        var body = JsonSerializer.SerializeToElement(target);
        var merged = new Dictionary<string, object?> { ["role"] = role };
        foreach (var p in body.EnumerateObject()) merged[p.Name] = p.Value.Clone();
        var r = await w.CallAsync(by, HttpMethod.Post, $"/v1/{kind}/{id}/access", merged);
        Assert.True(r.Status == HttpStatusCode.Created, $"share {kind} {id}: {r.Status} {r.Body}");
        return r.Body.GetProperty("item");
    }

    public static async Task<HttpStatusCode> StatusAsync(this Workspace w, Person p, string url) => (await w.CallAsync(p, HttpMethod.Get, url)).Status;

    public static async Task<string[]> IdsAsync(this Workspace w, Person p, string url)
    {
        var r = await w.CallAsync(p, HttpMethod.Get, url);
        Assert.Equal(HttpStatusCode.OK, r.Status);
        return r.Body.GetProperty("items").EnumerateArray().Select(i => i.GetProperty("id").GetString()!).ToArray();
    }

    public static string Message(this (HttpStatusCode Status, JsonElement Body) r) => r.Body.ValueKind == JsonValueKind.Object && r.Body.TryGetProperty("message", out var m) ? m.GetString() ?? "" : "";
}

public sealed class LibraryTests : IClassFixture<LibraryFactory>
{
    private readonly LibraryFactory _factory;
    public LibraryTests(LibraryFactory factory) => _factory = factory;

    private const string Missing = "plg_01m6797hhce34acegcde4y57bd";

    // ---------- validation ----------

    [Fact]
    public async Task Plugin_and_skill_input_is_checked_and_nothing_is_left_behind_when_it_fails()
    {
        var w = await Workspace.CreateAsync(_factory);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/plugins", new { name = " " })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/plugins", new { })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/plugins", new { name = new string('x', 256) })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/plugins", new { name = "x", orgWide = "yes" })).Status);
        var bad = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/plugins", new { name = "Half", components = new object[] { new { type = "skill", input = new { rawSourceText = LibraryHelpers.Skill("fine") } }, new { type = "skill", input = new { rawSourceText = "no frontmatter" } } } });
        Assert.Equal(HttpStatusCode.BadRequest, bad.Status);
        Assert.Equal("invalid_skill_frontmatter", Workspace.Error(bad.Body));
        Assert.Empty(await w.IdsAsync(w.Owner, "/v1/plugins"));       // not even the first, valid component survived
        Assert.Empty(await w.IdsAsync(w.Owner, "/v1/config-objects"));

        async Task<string> Code(string text) => Workspace.Error((await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/config-objects", new { type = "skill", sourceMode = "cloud", input = new { rawSourceText = text } })).Body);
        Assert.Equal("invalid_skill_name", await Code(LibraryHelpers.Skill("Bad Name")));
        Assert.Equal("invalid_skill_name", await Code(LibraryHelpers.Skill("double--dash")));
        Assert.Equal("invalid_skill_name", await Code(LibraryHelpers.Skill(new string('a', 65))));
        Assert.Equal("invalid_skill_description", await Code("---\nname: abc\n---\n\nbody"));
        Assert.Equal("invalid_skill_description", await Code(LibraryHelpers.Skill("abc", new string('d', 1025))));
        Assert.Equal("invalid_skill_body", await Code("---\nname: abc\ndescription: d\n---\n\n  \n"));
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/config-objects", new { type = "skill", sourceMode = "connector", input = new { rawSourceText = LibraryHelpers.Skill("abc") } })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/config-objects", new { type = "skill", sourceMode = "cloud", input = new { } })).Status);
        var big = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/config-objects", new { type = "command", sourceMode = "cloud", input = new { rawSourceText = new string('x', 1_048_577) } });
        Assert.Equal(HttpStatusCode.BadRequest, big.Status);
        Assert.Contains("1 MiB", big.Message());
    }

    [Fact]
    public async Task Block_style_frontmatter_and_quoted_values_are_read_like_the_reference_reads_them()
    {
        var w = await Workspace.CreateAsync(_factory);
        var text = "---\nname: \"quoted-name\"\ndescription: >\n  A long description\n  over two lines.\n---\n\nBody.\n";
        var r = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/config-objects", new { type = "skill", sourceMode = "cloud", input = new { rawSourceText = text } });
        Assert.Equal(HttpStatusCode.Created, r.Status);
        Assert.Equal("quoted-name", r.Body.GetProperty("item").GetProperty("title").GetString());
        Assert.Equal("A long description over two lines.", r.Body.GetProperty("item").GetProperty("description").GetString());
    }

    [Fact]
    public async Task Ids_in_paths_and_bodies_are_validated_and_unknown_ids_are_404()
    {
        var w = await Workspace.CreateAsync(_factory);
        var bad = await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/plugins/nope");
        Assert.Equal(HttpStatusCode.BadRequest, bad.Status);
        Assert.StartsWith("pluginId: TypeID must be 30 characters (plg_<26 char suffix>)", bad.Message());
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/plugins/mkt_01m6797hhce34acegcde4y57bd")).Status);
        Assert.Equal("plugin_not_found", Workspace.Error((await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/plugins/{Missing}")).Body));
        Assert.Equal("config_object_not_found", Workspace.Error((await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/config-objects/cob_01m6797hhce34acegcde4y57bd")).Body));
        Assert.Equal("marketplace_not_found", Workspace.Error((await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/marketplaces/mkt_01m6797hhce34acegcde4y57bd")).Body));
        var p = await w.PluginAsync(w.Owner, "P");
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/plugins/{p}/config-objects", new { configObjectId = "x" })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/resolved-plugins")).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/resolved-plugins?pluginIds=nope")).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.Plain().GetAsync("/v1/plugins")).StatusCode);
    }

    // ---------- who may see what ----------

    [Fact]
    public async Task A_person_never_sees_or_fetches_a_plugin_or_skill_that_was_not_shared_with_them()
    {
        var w = await Workspace.CreateAsync(_factory);
        var bob = await w.AddAsync();
        var admin = await w.AddAsync("admin");
        var plugin = await w.PluginAsync(w.Owner, "Secret plan", LibraryHelpers.Skill("hidden-skill", "Secret skill", "Secret body text."));
        var skill = await w.SkillIdAsync(w.Owner, plugin);

        foreach (var url in new[] { $"/v1/plugins/{plugin}", $"/v1/plugins/{plugin}/resolved", $"/v1/plugins/{plugin}/config-objects", $"/v1/plugins/{plugin}/access",
                     $"/v1/config-objects/{skill}", $"/v1/config-objects/{skill}/versions", $"/v1/config-objects/{skill}/versions/latest", $"/v1/config-objects/{skill}/plugins", $"/v1/config-objects/{skill}/access" })
        {
            var r = await w.CallAsync(bob, HttpMethod.Get, url);
            Assert.True(r.Status == HttpStatusCode.Forbidden, $"{url}: {r.Status}");
            Assert.DoesNotContain("Secret body text", r.Body.ToString());
        }
        Assert.DoesNotContain(plugin, await w.IdsAsync(bob, "/v1/plugins"));
        Assert.DoesNotContain(skill, await w.IdsAsync(bob, "/v1/config-objects"));
        Assert.DoesNotContain(plugin, (await w.CallAsync(bob, HttpMethod.Get, "/v1/me/library")).Body.ToString());
        Assert.DoesNotContain(plugin, (await w.CallAsync(bob, HttpMethod.Get, "/v1/me/plugin-access")).Body.ToString());
        Assert.DoesNotContain("Secret", (await w.CallAsync(bob, HttpMethod.Get, $"/v1/resolved-plugins?pluginIds={plugin}")).Body.ToString().Replace("Missing viewer access", ""));
        var resolved = await w.CallAsync(bob, HttpMethod.Get, $"/v1/resolved-plugins?pluginIds={plugin}");
        Assert.Equal(403, resolved.Body.GetProperty("failures").GetProperty(plugin).GetProperty("status").GetInt32());
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(bob, HttpMethod.Post, $"/v1/plugins/{plugin}/access", new { orgWide = true, role = "viewer" })).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(bob, HttpMethod.Patch, $"/v1/plugins/{plugin}", new { name = "Mine" })).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(bob, HttpMethod.Post, $"/v1/plugins/{plugin}/archive")).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(bob, HttpMethod.Post, $"/v1/config-objects/{skill}/versions", new { input = new { rawSourceText = LibraryHelpers.Skill("hidden-skill", "Secret skill", "Rewritten") } })).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(bob, HttpMethod.Post, $"/v1/config-objects/{skill}/delete")).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(bob, HttpMethod.Post, $"/v1/plugins/{plugin}/config-objects", new { configObjectId = skill })).Status);
        // An admin holds "Manage everything shared" by default: that is the one other way in.
        Assert.Equal(HttpStatusCode.OK, await w.StatusAsync(admin, $"/v1/plugins/{plugin}"));
        // ...and the owner's plugin is untouched after all of that.
        var after = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/plugins/{plugin}");
        Assert.Equal("Secret plan", after.Body.GetProperty("item").GetProperty("name").GetString());
        Assert.Equal("active", after.Body.GetProperty("item").GetProperty("status").GetString());
    }

    [Fact]
    public async Task Without_manage_everything_even_an_admin_sees_only_what_was_shared_with_them()
    {
        var w = await Workspace.CreateAsync(_factory);
        var admin = await w.AddAsync("admin");
        var plugin = await w.PluginAsync(w.Owner, "Owner only");
        // Turn "Manage everything shared" off for admins (their role set), then they are like anyone else.
        var sets = await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/permissions/sets");
        var adminSet = sets.Body.GetProperty("sets").EnumerateArray().First(s => s.GetProperty("kind").GetString() == "admin_default").GetProperty("id").GetString();
        var off = await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/permissions/sets/{adminSet}/permissions", new { changes = new[] { new { key = "sharing.manage_all", status = "deny" } } });
        Assert.Equal(HttpStatusCode.OK, off.Status);
        Assert.Equal(HttpStatusCode.Forbidden, await w.StatusAsync(admin, $"/v1/plugins/{plugin}"));
        Assert.DoesNotContain(plugin, await w.IdsAsync(admin, "/v1/plugins"));
        await w.ShareAsync(w.Owner, "plugins", plugin, new { orgMembershipId = admin.MemberId });
        Assert.Equal(HttpStatusCode.OK, await w.StatusAsync(admin, $"/v1/plugins/{plugin}"));
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(admin, HttpMethod.Patch, $"/v1/plugins/{plugin}", new { name = "Edited" })).Status);   // shared as viewer
    }

    [Fact]
    public async Task Sharing_with_a_person_a_team_and_everyone_each_opens_the_door_and_revoking_closes_it()
    {
        var w = await Workspace.CreateAsync(_factory);
        var ann = await w.AddAsync(); var ben = await w.AddAsync(); var cy = await w.AddAsync(); var dee = await w.AddAsync();
        var plugin = await w.PluginAsync(w.Owner, "Shared plugin", LibraryHelpers.Skill("shared-skill"));
        var skill = await w.SkillIdAsync(w.Owner, plugin);
        var team = await w.TeamAsync("Readers", ben);

        var toAnn = await w.ShareAsync(w.Owner, "plugins", plugin, new { orgMembershipId = ann.MemberId });
        var toTeam = await w.ShareAsync(w.Owner, "plugins", plugin, new { teamId = team });
        Assert.Equal(HttpStatusCode.OK, await w.StatusAsync(ann, $"/v1/plugins/{plugin}"));
        Assert.Equal(HttpStatusCode.OK, await w.StatusAsync(ben, $"/v1/plugins/{plugin}"));
        Assert.Equal(HttpStatusCode.Forbidden, await w.StatusAsync(cy, $"/v1/plugins/{plugin}"));
        Assert.Contains(plugin, await w.IdsAsync(ben, "/v1/plugins"));
        // A plugin's viewers can read the skills in it.
        Assert.Equal(HttpStatusCode.OK, await w.StatusAsync(ben, $"/v1/config-objects/{skill}"));
        Assert.Equal(HttpStatusCode.Forbidden, await w.StatusAsync(cy, $"/v1/config-objects/{skill}"));

        // Leaving the team closes the team's door.
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Patch, $"/v1/teams/{team}", new { memberIds = Array.Empty<string>() })).Status);
        Assert.Equal(HttpStatusCode.Forbidden, await w.StatusAsync(ben, $"/v1/plugins/{plugin}"));
        Assert.DoesNotContain(plugin, await w.IdsAsync(ben, "/v1/plugins"));
        await w.CallAsync(w.Owner, HttpMethod.Patch, $"/v1/teams/{team}", new { memberIds = new[] { ben.MemberId } });
        Assert.Equal(HttpStatusCode.OK, await w.StatusAsync(ben, $"/v1/plugins/{plugin}"));

        var everyone = await w.ShareAsync(w.Owner, "plugins", plugin, new { orgWide = true });
        Assert.Equal(HttpStatusCode.OK, await w.StatusAsync(cy, $"/v1/plugins/{plugin}"));
        Assert.Equal(HttpStatusCode.OK, await w.StatusAsync(dee, $"/v1/plugins/{plugin}"));

        // Each revoke closes exactly its door.
        Assert.Equal(HttpStatusCode.NoContent, (await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/plugins/{plugin}/access/{everyone.GetProperty("id").GetString()}")).Status);
        Assert.Equal(HttpStatusCode.Forbidden, await w.StatusAsync(cy, $"/v1/plugins/{plugin}"));
        Assert.Equal(HttpStatusCode.OK, await w.StatusAsync(ann, $"/v1/plugins/{plugin}"));
        Assert.Equal(HttpStatusCode.NoContent, (await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/plugins/{plugin}/access/{toAnn.GetProperty("id").GetString()}")).Status);
        Assert.Equal(HttpStatusCode.Forbidden, await w.StatusAsync(ann, $"/v1/plugins/{plugin}"));
        Assert.Equal(HttpStatusCode.NoContent, (await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/plugins/{plugin}/access/{toTeam.GetProperty("id").GetString()}")).Status);
        Assert.Equal(HttpStatusCode.Forbidden, await w.StatusAsync(ben, $"/v1/plugins/{plugin}"));
        // Sharing again with the same person brings the same grant back.
        var again = await w.ShareAsync(w.Owner, "plugins", plugin, new { orgMembershipId = ann.MemberId }, "editor");
        Assert.Equal(toAnn.GetProperty("id").GetString(), again.GetProperty("id").GetString());
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(ann, HttpMethod.Patch, $"/v1/plugins/{plugin}", new { description = "Edited by Ann" })).Status);
    }

    [Fact]
    public async Task Roles_are_viewer_editor_manager_and_each_action_needs_its_role()
    {
        var w = await Workspace.CreateAsync(_factory);
        var viewer = await w.AddAsync(); var editor = await w.AddAsync(); var manager = await w.AddAsync();
        var plugin = await w.PluginAsync(w.Owner, "Roles plugin", LibraryHelpers.Skill("roles-skill"));
        var skill = await w.SkillIdAsync(w.Owner, plugin);
        await w.ShareAsync(w.Owner, "plugins", plugin, new { orgMembershipId = viewer.MemberId }, "viewer");
        await w.ShareAsync(w.Owner, "plugins", plugin, new { orgMembershipId = editor.MemberId }, "editor");
        await w.ShareAsync(w.Owner, "plugins", plugin, new { orgMembershipId = manager.MemberId }, "manager");

        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(viewer, HttpMethod.Patch, $"/v1/plugins/{plugin}", new { name = "V" })).Status);
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(editor, HttpMethod.Patch, $"/v1/plugins/{plugin}", new { name = "E" })).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(editor, HttpMethod.Post, $"/v1/plugins/{plugin}/archive")).Status);
        Assert.Equal(HttpStatusCode.Forbidden, await w.StatusAsync(editor, $"/v1/plugins/{plugin}/access"));
        // An editor of the plugin may add a skill to it and cannot manage the skill itself.
        var added = await w.CallAsync(editor, HttpMethod.Post, "/v1/config-objects", new { type = "skill", sourceMode = "cloud", pluginIds = new[] { plugin }, input = new { rawSourceText = LibraryHelpers.Skill("by-editor") } });
        Assert.Equal(HttpStatusCode.Created, added.Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(viewer, HttpMethod.Post, "/v1/config-objects", new { type = "skill", sourceMode = "cloud", pluginIds = new[] { plugin }, input = new { rawSourceText = LibraryHelpers.Skill("by-viewer") } })).Status);
        // Editing the plugin's skills as editor of the *skill* needs a grant on the skill: a plugin editor alone only views it.
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(editor, HttpMethod.Post, $"/v1/config-objects/{skill}/versions", new { input = new { rawSourceText = LibraryHelpers.Skill("roles-skill", "x") } })).Status);
        await w.ShareAsync(w.Owner, "config-objects", skill, new { orgMembershipId = editor.MemberId }, "editor");
        Assert.Equal(HttpStatusCode.Created, (await w.CallAsync(editor, HttpMethod.Post, $"/v1/config-objects/{skill}/versions", new { input = new { rawSourceText = LibraryHelpers.Skill("roles-skill", "edited") } })).Status);
        // The manager shares and archives, but may not share with everyone.
        await w.ShareAsync(w.Owner, "plugins", plugin, new { orgMembershipId = viewer.MemberId }, "viewer");
        var wide = await w.CallAsync(manager, HttpMethod.Post, $"/v1/plugins/{plugin}/access", new { orgWide = true, role = "viewer" });
        Assert.Equal(HttpStatusCode.Forbidden, wide.Status);
        Assert.Equal("Only organization owners and admins can grant org-wide access.", wide.Message());
        Assert.Equal(HttpStatusCode.Created, (await w.CallAsync(manager, HttpMethod.Post, $"/v1/plugins/{plugin}/access", new { orgMembershipId = (await w.AddAsync()).MemberId, role = "viewer" })).Status);
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(manager, HttpMethod.Post, $"/v1/plugins/{plugin}/archive")).Status);
    }

    [Fact]
    public async Task A_marketplace_share_shows_its_plugins_read_only_and_never_the_skills_inside()
    {
        var w = await Workspace.CreateAsync(_factory);
        var reader = await w.AddAsync();
        var plugin = await w.PluginAsync(w.Owner, "On the shelf", LibraryHelpers.Skill("shelf-skill"));
        var skill = await w.SkillIdAsync(w.Owner, plugin);
        var market = (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/marketplaces", new { name = "Shelf" })).Body.GetProperty("item").GetProperty("id").GetString()!;
        Assert.Equal(HttpStatusCode.Created, (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/marketplaces/{market}/plugins", new { pluginId = plugin })).Status);
        Assert.Equal(HttpStatusCode.Forbidden, await w.StatusAsync(reader, $"/v1/plugins/{plugin}"));
        var grant = await w.ShareAsync(w.Owner, "marketplaces", market, new { orgMembershipId = reader.MemberId });

        Assert.Equal(HttpStatusCode.OK, await w.StatusAsync(reader, $"/v1/marketplaces/{market}"));
        Assert.Equal(HttpStatusCode.OK, await w.StatusAsync(reader, $"/v1/marketplaces/{market}/resolved"));
        Assert.Equal(HttpStatusCode.OK, await w.StatusAsync(reader, $"/v1/plugins/{plugin}"));
        Assert.Contains(plugin, await w.IdsAsync(reader, "/v1/plugins"));
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(reader, HttpMethod.Patch, $"/v1/plugins/{plugin}", new { name = "x" })).Status);
        Assert.Equal(HttpStatusCode.Forbidden, await w.StatusAsync(reader, $"/v1/config-objects/{skill}"));   // catalog access is not skill access
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(reader, HttpMethod.Post, $"/v1/marketplaces/{market}/plugins", new { pluginId = plugin })).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(reader, HttpMethod.Patch, $"/v1/marketplaces/{market}", new { name = "Mine" })).Status);
        var me = await w.CallAsync(reader, HttpMethod.Get, "/v1/me/plugin-access");
        Assert.Equal("catalog", me.Body.GetProperty("items")[0].GetProperty("edges")[0].GetProperty("kind").GetString());

        await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/marketplaces/{market}/access/{grant.GetProperty("id").GetString()}");
        Assert.Equal(HttpStatusCode.Forbidden, await w.StatusAsync(reader, $"/v1/plugins/{plugin}"));
        Assert.Equal(HttpStatusCode.Forbidden, await w.StatusAsync(reader, $"/v1/marketplaces/{market}"));
        // Taking the plugin out of the marketplace closes it too, even for someone still shared the marketplace.
        await w.ShareAsync(w.Owner, "marketplaces", market, new { orgMembershipId = reader.MemberId });
        Assert.Equal(HttpStatusCode.OK, await w.StatusAsync(reader, $"/v1/plugins/{plugin}"));
        await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/marketplaces/{market}/plugins/{plugin}");
        Assert.Equal(HttpStatusCode.Forbidden, await w.StatusAsync(reader, $"/v1/plugins/{plugin}"));
        // Deleting the marketplace removes the door and the shares with it.
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/marketplaces/{market}/delete")).Status);
        Assert.Equal(HttpStatusCode.NotFound, await w.StatusAsync(w.Owner, $"/v1/marketplaces/{market}"));
    }

    [Fact]
    public async Task Creating_marketplaces_and_sharing_with_everyone_need_their_permissions()
    {
        var w = await Workspace.CreateAsync(_factory);
        var member = await w.AddAsync(); var admin = await w.AddAsync("admin");
        var denied = await w.CallAsync(member, HttpMethod.Post, "/v1/marketplaces", new { name = "Nope" });
        Assert.Equal(HttpStatusCode.Forbidden, denied.Status);
        Assert.Equal("Missing organization capability: marketplace.create", denied.Message());
        Assert.Equal(HttpStatusCode.Created, (await w.CallAsync(admin, HttpMethod.Post, "/v1/marketplaces", new { name = "Admin shelf" })).Status);
        var byKey = await w.CallAsync(member, HttpMethod.Put, "/v1/marketplaces/by-key/mine", new { name = "x" });
        Assert.Equal("marketplaces.manage", byKey.Body.GetProperty("requiredPermission").GetString());
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(member, HttpMethod.Delete, "/v1/marketplaces/by-key/mine")).Status);

        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(member, HttpMethod.Post, "/v1/plugins", new { name = "Wide", orgWide = true })).Status);
        Assert.Equal(HttpStatusCode.Created, (await w.CallAsync(admin, HttpMethod.Post, "/v1/plugins", new { name = "Wide", orgWide = true })).Status);
        var own = await w.PluginAsync(member, "Members plugin");
        var wide = await w.CallAsync(member, HttpMethod.Post, $"/v1/plugins/{own}/access", new { orgWide = true, role = "viewer" });
        Assert.Equal(HttpStatusCode.Forbidden, wide.Status);
        Assert.Equal("Only organization owners and admins can grant org-wide access.", wide.Message());
    }

    [Fact]
    public async Task Grants_name_exactly_one_target_in_this_workspace_and_a_real_role()
    {
        var w = await Workspace.CreateAsync(_factory);
        var other = await Workspace.CreateAsync(_factory);
        var plugin = await w.PluginAsync(w.Owner, "Grant checks");
        var url = $"/v1/plugins/{plugin}/access";
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Post, url, new { role = "viewer" })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Post, url, new { orgWide = true, teamId = "tem_01m6797hhce34acegcde4y57bd", role = "viewer" })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Post, url, new { orgWide = true, role = "boss" })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Post, url, new { orgMembershipId = "nope", role = "viewer" })).Status);
        Assert.Equal("member_not_found", Workspace.Error((await w.CallAsync(w.Owner, HttpMethod.Post, url, new { orgMembershipId = other.Owner.MemberId, role = "viewer" })).Body));   // another workspace's person
        var foreignTeam = await other.TeamAsync("Foreign");
        Assert.Equal("team_not_found", Workspace.Error((await w.CallAsync(w.Owner, HttpMethod.Post, url, new { teamId = foreignTeam, role = "viewer" })).Body));
        Assert.Equal("access_grant_not_found", Workspace.Error((await w.CallAsync(w.Owner, HttpMethod.Delete, $"{url}/pag_01m6797hhce34acegcde4y57bd")).Body));
        Assert.Single((await w.CallAsync(w.Owner, HttpMethod.Get, url)).Body.GetProperty("items").EnumerateArray());   // only the maker's manager grant: nothing was added
    }

    // ---------- other workspaces ----------

    [Fact]
    public async Task Another_workspace_cannot_see_touch_or_share_anything_here()
    {
        var w = await Workspace.CreateAsync(_factory);
        var other = await Workspace.CreateAsync(_factory);
        var plugin = await w.PluginAsync(w.Owner, "Ours", LibraryHelpers.Skill("our-skill"));
        var skill = await w.SkillIdAsync(w.Owner, plugin);
        var market = (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/marketplaces", new { name = "Our shelf" })).Body.GetProperty("item").GetProperty("id").GetString()!;
        await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/plugins/{plugin}/access", new { orgWide = true, role = "viewer" });

        foreach (var (method, url, body) in new (HttpMethod, string, object?)[]
                 {
                     (HttpMethod.Get, $"/v1/plugins/{plugin}", null), (HttpMethod.Patch, $"/v1/plugins/{plugin}", new { name = "Taken" }), (HttpMethod.Post, $"/v1/plugins/{plugin}/archive", null),
                     (HttpMethod.Get, $"/v1/plugins/{plugin}/resolved", null), (HttpMethod.Get, $"/v1/plugins/{plugin}/access", null), (HttpMethod.Post, $"/v1/plugins/{plugin}/access", new { orgWide = true, role = "viewer" }),
                     (HttpMethod.Get, $"/v1/config-objects/{skill}", null), (HttpMethod.Get, $"/v1/config-objects/{skill}/versions", null), (HttpMethod.Post, $"/v1/config-objects/{skill}/delete", null),
                     (HttpMethod.Post, $"/v1/config-objects/{skill}/access", new { orgWide = true, role = "viewer" }),
                     (HttpMethod.Get, $"/v1/marketplaces/{market}", null), (HttpMethod.Post, $"/v1/marketplaces/{market}/delete", null), (HttpMethod.Post, $"/v1/marketplaces/{market}/access", new { orgWide = true, role = "viewer" }),
                 })
        {
            var r = await other.CallAsync(other.Owner, method, url, body);
            Assert.True(r.Status == HttpStatusCode.NotFound, $"{method} {url}: {r.Status} {r.Body}");
        }
        Assert.Empty(await other.IdsAsync(other.Owner, "/v1/plugins"));
        Assert.Empty(await other.IdsAsync(other.Owner, "/v1/config-objects"));
        Assert.Empty(await other.IdsAsync(other.Owner, "/v1/marketplaces"));
        Assert.DoesNotContain(plugin, (await other.CallAsync(other.Owner, HttpMethod.Get, "/v1/me/library")).Body.ToString());
        // Putting our skill into their plugin, or their plugin's id in our marketplace, is also refused.
        var theirs = await other.PluginAsync(other.Owner, "Theirs");
        Assert.Equal(HttpStatusCode.NotFound, (await other.CallAsync(other.Owner, HttpMethod.Post, $"/v1/plugins/{theirs}/config-objects", new { configObjectId = skill })).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/marketplaces/{market}/plugins", new { pluginId = theirs })).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/config-objects", new { type = "skill", sourceMode = "cloud", pluginIds = new[] { theirs }, input = new { rawSourceText = LibraryHelpers.Skill("sneak") } })).Status);
        // Someone who belongs only to the other workspace cannot use our workspace id in the header.
        var stranger = await _factory.Plain().SendAsync(w.As(other.Owner.Token, HttpMethod.Get, "/v1/plugins"));
        Assert.Equal(HttpStatusCode.NotFound, stranger.StatusCode);
        // Names may repeat across workspaces.
        Assert.Equal(HttpStatusCode.Created, (await other.CallAsync(other.Owner, HttpMethod.Post, "/v1/plugins", new { name = "Ours" })).Status);
    }

    // ---------- lists, versions, lifecycle ----------

    [Fact]
    public async Task Versions_are_kept_newest_first_and_the_skill_follows_the_latest_one()
    {
        var w = await Workspace.CreateAsync(_factory);
        var plugin = await w.PluginAsync(w.Owner, "Versions", LibraryHelpers.Skill("versioned", "one"));
        var skill = await w.SkillIdAsync(w.Owner, plugin);
        var first = (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/config-objects/{skill}/versions/latest")).Body.GetProperty("item").GetProperty("id").GetString()!;
        var v2 = await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/config-objects/{skill}/versions", new { input = new { rawSourceText = LibraryHelpers.Skill("versioned", "two") }, reason = "tweak" });
        Assert.Equal("two", v2.Body.GetProperty("item").GetProperty("description").GetString());
        var list = (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/config-objects/{skill}/versions")).Body.GetProperty("items");
        Assert.Equal(2, list.GetArrayLength());
        Assert.Equal("tweak", list[0].GetProperty("sourceRevisionRef").GetString());
        Assert.Equal(first, list[1].GetProperty("id").GetString());
        Assert.Contains("one", (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/config-objects/{skill}/versions/{first}")).Body.GetProperty("item").GetProperty("rawSourceText").GetString());
        Assert.Equal(HttpStatusCode.NotFound, await w.StatusAsync(w.Owner, $"/v1/config-objects/{skill}/versions/cov_01m6797hhce34acegcde4y57bd"));
        // A bad revision is refused whole: the old text stays the latest.
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/config-objects/{skill}/versions", new { input = new { rawSourceText = "nope" } })).Status);
        Assert.Equal(2, (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/config-objects/{skill}/versions")).Body.GetProperty("items").GetArrayLength());
        // Two revisions at the same moment both land, in some order.
        var rs = await Task.WhenAll(Enumerable.Range(0, 5).Select(i => w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/config-objects/{skill}/versions", new { input = new { rawSourceText = LibraryHelpers.Skill("versioned", $"racing {i}") } })));
        Assert.All(rs, r => Assert.Equal(HttpStatusCode.Created, r.Status));
        Assert.Equal(7, (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/config-objects/{skill}/versions")).Body.GetProperty("items").GetArrayLength());
    }

    [Fact]
    public async Task Archived_and_deleted_things_drop_out_where_the_reference_drops_them()
    {
        var w = await Workspace.CreateAsync(_factory);
        var plugin = await w.PluginAsync(w.Owner, "Lifecycle", LibraryHelpers.Skill("keep-me"), LibraryHelpers.Skill("archive-me"));
        var resolved = (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/plugins/{plugin}/resolved")).Body.GetProperty("items");
        var archiveMe = resolved.EnumerateArray().First(i => i.GetProperty("configObject").GetProperty("title").GetString() == "archive-me").GetProperty("configObjectId").GetString()!;
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/config-objects/{archiveMe}/archive")).Status);
        Assert.Single((await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/plugins/{plugin}/resolved")).Body.GetProperty("items").EnumerateArray());
        Assert.Equal(2, (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/plugins/{plugin}/config-objects")).Body.GetProperty("items").GetArrayLength());
        await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/config-objects/{archiveMe}/delete");
        Assert.DoesNotContain(archiveMe, await w.IdsAsync(w.Owner, "/v1/config-objects"));
        Assert.Contains(archiveMe, await w.IdsAsync(w.Owner, "/v1/config-objects?includeDeleted=true"));
        await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/plugins/{plugin}/archive");
        Assert.DoesNotContain(plugin, await w.IdsAsync(w.Owner, "/v1/plugins?status=active"));
        Assert.Contains(plugin, await w.IdsAsync(w.Owner, "/v1/plugins?status=archived"));
        Assert.DoesNotContain(plugin, (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/me/library")).Body.ToString());
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/plugins/{plugin}/restore")).Status);
        Assert.Contains(plugin, (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/me/library")).Body.ToString());
    }

    [Fact]
    public async Task Plugin_lists_page_with_cursors_and_filter_by_what_a_team_or_person_can_see()
    {
        var w = await Workspace.CreateAsync(_factory);
        var ann = await w.AddAsync();
        for (var i = 0; i < 5; i++) await w.PluginAsync(ann, $"Paged {i}");
        var seen = new List<string>();
        string? cursor = null;
        do
        {
            var r = await w.CallAsync(ann, HttpMethod.Get, "/v1/plugins?limit=2&includeTotal=true" + (cursor is null ? "" : $"&cursor={Uri.EscapeDataString(cursor)}"));
            Assert.Equal(5, r.Body.GetProperty("total").GetInt32());
            seen.AddRange(r.Body.GetProperty("items").EnumerateArray().Select(i => i.GetProperty("id").GetString()!));
            cursor = r.Body.GetProperty("nextCursor").GetString();
        } while (cursor is not null);
        Assert.Equal(5, seen.Count);
        Assert.Equal(5, seen.Distinct().Count());
        Assert.Equal(HttpStatusCode.BadRequest, await w.StatusAsync(ann, "/v1/plugins?cursor=%21%21%21"));
        Assert.Equal(HttpStatusCode.BadRequest, await w.StatusAsync(ann, "/v1/plugins?limit=101"));

        var ben = await w.AddAsync();
        var shared = await w.PluginAsync(ann, "Shared with Ben");
        await w.ShareAsync(ann, "plugins", shared, new { orgMembershipId = ben.MemberId });
        var forBen = await w.IdsAsync(w.Owner, $"/v1/plugins?memberId={ben.MemberId}");
        Assert.Equal([shared], forBen);
        var team = await w.TeamAsync("Cats", ben);
        var teamPlugin = await w.PluginAsync(ann, "For cats");
        await w.ShareAsync(ann, "plugins", teamPlugin, new { teamId = team });
        Assert.Equal([teamPlugin], await w.IdsAsync(w.Owner, $"/v1/plugins?teamId={team}"));
        Assert.Equal(HttpStatusCode.BadRequest, await w.StatusAsync(w.Owner, $"/v1/plugins?teamId={team}&memberId={ben.MemberId}"));
        // Someone cannot use these filters to look past their own access: Ben asking about Ann sees only the overlap.
        var overlap = await w.IdsAsync(ben, $"/v1/plugins?memberId={ann.MemberId}");
        Assert.All(overlap, id => Assert.Contains(id, new[] { shared, teamPlugin }));
        Assert.Empty(await w.IdsAsync(w.Owner, $"/v1/plugins?memberId={Missing.Replace("plg", "om")}"));
    }

    [Fact]
    public async Task What_a_team_can_use_is_shown_to_its_people_and_to_those_who_can_view_any_team_only()
    {
        var w = await Workspace.CreateAsync(_factory);
        var member = await w.AddAsync(); var outsider = await w.AddAsync();
        var team = await w.TeamAsync("Viewers", member);
        var plugin = await w.PluginAsync(w.Owner, "Team plugin");
        var grant = await w.ShareAsync(w.Owner, "plugins", plugin, new { teamId = team });
        var items = (await w.CallAsync(member, HttpMethod.Get, $"/v1/teams/{team}/plugin-access")).Body.GetProperty("items");
        Assert.Equal("direct_team", items[0].GetProperty("edge").GetString());
        Assert.Equal(grant.GetProperty("id").GetString(), items[0].GetProperty("grantId").GetString());
        Assert.Equal(HttpStatusCode.Forbidden, await w.StatusAsync(outsider, $"/v1/teams/{team}/plugin-access"));
        Assert.Equal(HttpStatusCode.NotFound, await w.StatusAsync(w.Owner, "/v1/teams/tem_01m6797hhce34acegcde4y57bd/plugin-access"));
        var other = await Workspace.CreateAsync(_factory);
        Assert.Equal(HttpStatusCode.NotFound, await other.StatusAsync(other.Owner, $"/v1/teams/{team}/plugin-access"));
    }

    // ---------- concurrency ----------

    [Fact]
    public async Task Concurrent_requests_cannot_make_duplicates()
    {
        var w = await Workspace.CreateAsync(_factory);
        var ann = await w.AddAsync();
        // The same plugin created six times at once: one wins.
        var made = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => w.CallAsync(ann, HttpMethod.Post, "/v1/plugins", new { name = "Racers" })));
        Assert.Equal(1, made.Count(r => r.Status == HttpStatusCode.Created));
        Assert.Equal(5, made.Count(r => r.Status == HttpStatusCode.Conflict));
        Assert.Single((await w.IdsAsync(ann, "/v1/plugins?q=Racers")));
        var plugin = made.First(r => r.Status == HttpStatusCode.Created).Body.GetProperty("item").GetProperty("id").GetString()!;

        // The same person shared six times at once: one grant, every request answered.
        var grants = await Task.WhenAll(Enumerable.Range(0, 6).Select(i => w.CallAsync(ann, HttpMethod.Post, $"/v1/plugins/{plugin}/access", new { orgMembershipId = w.Owner.MemberId, role = i % 2 == 0 ? "viewer" : "editor" })));
        Assert.All(grants, r => Assert.Equal(HttpStatusCode.Created, r.Status));
        Assert.Single((await w.CallAsync(ann, HttpMethod.Get, $"/v1/plugins/{plugin}/access")).Body.GetProperty("items").EnumerateArray(), g => g.GetProperty("orgMembershipId").GetString() == w.Owner.MemberId);
        Assert.Single(grants.Select(r => r.Body.GetProperty("item").GetProperty("id").GetString()).Distinct());

        // The same skill attached six times at once, and a marketplace key applied six times at once.
        var skill = (await w.CallAsync(ann, HttpMethod.Post, "/v1/config-objects", new { type = "skill", sourceMode = "cloud", input = new { rawSourceText = LibraryHelpers.Skill("attach-race") } })).Body.GetProperty("item").GetProperty("id").GetString()!;
        var attach = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => w.CallAsync(ann, HttpMethod.Post, $"/v1/plugins/{plugin}/config-objects", new { configObjectId = skill })));
        Assert.All(attach, r => Assert.Equal(HttpStatusCode.Created, r.Status));
        Assert.Single((await w.CallAsync(ann, HttpMethod.Get, $"/v1/plugins/{plugin}/config-objects")).Body.GetProperty("items").EnumerateArray());
        var keys = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => w.CallAsync(w.Owner, HttpMethod.Put, "/v1/marketplaces/by-key/race", new { name = "Race" })));
        Assert.All(keys, r => Assert.True(r.Status is HttpStatusCode.OK or HttpStatusCode.Created));
        Assert.Equal(1, keys.Count(r => r.Status == HttpStatusCode.Created));
        Assert.Single((await w.IdsAsync(w.Owner, "/v1/marketplaces?q=Race")));
    }

    [Fact]
    public async Task Revoking_while_reading_never_leaves_the_person_with_access()
    {
        var w = await Workspace.CreateAsync(_factory);
        var ann = await w.AddAsync();
        var plugin = await w.PluginAsync(w.Owner, "Revoke race", LibraryHelpers.Skill("revoked-skill"));
        var grant = await w.ShareAsync(w.Owner, "plugins", plugin, new { orgMembershipId = ann.MemberId });
        var reads = Enumerable.Range(0, 20).Select(_ => w.StatusAsync(ann, $"/v1/plugins/{plugin}")).ToList();
        var revoke = w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/plugins/{plugin}/access/{grant.GetProperty("id").GetString()}");
        await Task.WhenAll(reads.Append(revoke.ContinueWith(_ => HttpStatusCode.OK)));
        Assert.Equal(HttpStatusCode.Forbidden, await w.StatusAsync(ann, $"/v1/plugins/{plugin}"));
    }

    // ---------- usage ----------

    [Fact]
    public async Task Library_usage_is_for_analytics_viewers_and_counts_skills_read_by_agents()
    {
        var w = await Workspace.CreateAsync(_factory);
        var ann = await w.AddAsync();
        var plugin = await w.PluginAsync(w.Owner, "Used plugin", LibraryHelpers.Skill("used-skill", "Counted when read"));
        var skill = await w.SkillIdAsync(w.Owner, plugin);
        await w.ShareAsync(w.Owner, "plugins", plugin, new { orgMembershipId = ann.MemberId });

        var denied = await w.CallAsync(ann, HttpMethod.Get, "/v1/library-usage/skills");
        Assert.Equal("usage_analytics.view", denied.Required());
        Assert.Equal("usage_analytics.view", (await w.CallAsync(ann, HttpMethod.Get, "/v1/library-usage?kind=skills")).Required());
        var before = (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/library-usage/skills")).Body;
        Assert.Equal(JsonValueKind.Null, before.GetProperty("trackingSince").ValueKind);
        var row = before.GetProperty("items").EnumerateArray().Single(i => i.GetProperty("id").GetString() == skill);
        Assert.Equal(0, row.GetProperty("uses").GetInt32());
        Assert.Equal("Used plugin", row.GetProperty("detail").GetString());

        var read = await Capability(w, ann, "tools/call", new { name = "execute_capability", arguments = new { capability_id = $"plugin:{plugin}:{skill}", arguments = new { } } });
        Assert.Contains("Do the thing.", read);
        await Capability(w, ann, "tools/call", new { name = "execute_capability", arguments = new { capability_id = $"plugin:{plugin}:{skill}", arguments = new { } } });
        var after = (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/library-usage/skills")).Body;
        var used = after.GetProperty("items").EnumerateArray().Single(i => i.GetProperty("id").GetString() == skill);
        Assert.Equal(2, used.GetProperty("uses").GetInt32());
        Assert.Equal(1, used.GetProperty("people").GetInt32());
        Assert.NotEqual(JsonValueKind.Null, after.GetProperty("trackingSince").ValueKind);
        var plugins = (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/library-usage/plugins?days=7")).Body.GetProperty("items").EnumerateArray().Single(i => i.GetProperty("id").GetString() == plugin);
        Assert.Equal(2, plugins.GetProperty("uses").GetInt32());
        var breakdown = (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/library-usage?kind=skills&groupBy=item,member&memberId={ann.MemberId}")).Body.GetProperty("rows");
        Assert.Equal(ann.MemberId, breakdown[0].GetProperty("memberId").GetString());
        Assert.Equal(2, breakdown[0].GetProperty("sources").GetProperty("agent").GetInt32());
        Assert.Empty((await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/library-usage?kind=skills&memberId={w.Owner.MemberId}")).Body.GetProperty("rows").EnumerateArray());
        Assert.Equal(HttpStatusCode.BadRequest, await w.StatusAsync(w.Owner, "/v1/library-usage/skills?days=5"));
        Assert.Equal(HttpStatusCode.BadRequest, await w.StatusAsync(w.Owner, "/v1/library-usage/nope"));
        Assert.Equal(HttpStatusCode.BadRequest, await w.StatusAsync(w.Owner, "/v1/library-usage?kind=skills&bogus=1"));
        // Another workspace's usage is its own.
        var other = await Workspace.CreateAsync(_factory);
        Assert.Empty((await other.CallAsync(other.Owner, HttpMethod.Get, "/v1/library-usage/skills")).Body.GetProperty("items").EnumerateArray());
    }

    // ---------- agents ----------

    private async Task<string> Capability(Workspace w, Person p, string method, object parameters)
    {
        var minted = await w.CallAsync(p, HttpMethod.Post, "/v1/mcp/token", new { scopes = new[] { "mcp:read" } });
        var token = minted.Body.GetProperty("token").GetString()!;
        var request = Bearer(HttpMethod.Post, "/mcp/agent", token, new { jsonrpc = "2.0", id = 1, method, @params = parameters });
        request.Headers.Add("Accept", "application/json, text/event-stream");
        var response = await _factory.Plain().SendAsync(request);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return await response.Content.ReadAsStringAsync();
    }

    [Fact]
    public async Task Agents_find_and_read_only_the_skills_shared_with_their_person()
    {
        var w = await Workspace.CreateAsync(_factory);
        var ann = await w.AddAsync(); var ben = await w.AddAsync(); var admin = await w.AddAsync("admin");
        var plugin = await w.PluginAsync(w.Owner, "Agent plugin", LibraryHelpers.Skill("axolotl-habitat", "Tank temperatures for axolotls", "Keep the tank at 16 degrees."));
        var skill = await w.SkillIdAsync(w.Owner, plugin);
        var capability = $"plugin:{plugin}:{skill}";
        Task<string> Search(Person p) => Capability(w, p, "tools/call", new { name = "search_capabilities", arguments = new { query = "axolotl" } });
        Task<string> Read(Person p) => Capability(w, p, "tools/call", new { name = "execute_capability", arguments = new { capability_id = capability, arguments = new { } } });

        Assert.Contains(capability, await Search(w.Owner));              // the maker holds a manager share
        Assert.DoesNotContain(capability, await Search(ann));
        Assert.DoesNotContain(capability, await Search(admin));          // being an admin shows nothing to agents
        var denied = await Read(ann);                                    // knowing the id does not help
        Assert.Contains("unknown_capability", denied);   // not listed for them, so it does not exist for them
        Assert.DoesNotContain("16 degrees", denied);

        var grant = await w.ShareAsync(w.Owner, "plugins", plugin, new { orgMembershipId = ann.MemberId });
        Assert.Contains(capability, await Search(ann));
        Assert.Contains("16 degrees", await Read(ann));
        Assert.DoesNotContain(capability, await Search(ben));
        // Sharing the skill alone is enough, and so is a marketplace holding the plugin.
        await w.ShareAsync(w.Owner, "config-objects", skill, new { orgMembershipId = ben.MemberId });
        Assert.Contains(capability, await Search(ben));
        await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/plugins/{plugin}/access/{grant.GetProperty("id").GetString()}");
        Assert.DoesNotContain(capability, await Search(ann));
        Assert.DoesNotContain("16 degrees", await Read(ann));
        var market = (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/marketplaces", new { name = "Agents shelf" })).Body.GetProperty("item").GetProperty("id").GetString()!;
        await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/marketplaces/{market}/plugins", new { pluginId = plugin });
        await w.ShareAsync(w.Owner, "marketplaces", market, new { orgMembershipId = ann.MemberId });
        Assert.Contains(capability, await Search(ann));
        // An archived plugin or skill disappears for everyone, and so does a skill taken out of the plugin.
        await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/plugins/{plugin}/config-objects/{skill}");
        Assert.DoesNotContain(capability, await Search(w.Owner));
        Assert.DoesNotContain(capability, await Search(ann));
        await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/plugins/{plugin}/config-objects", new { configObjectId = skill });
        Assert.Contains(capability, await Search(ann));
        await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/plugins/{plugin}/archive");
        Assert.DoesNotContain(capability, await Search(w.Owner));
        Assert.DoesNotContain("16 degrees", await Read(w.Owner));
    }

    [Fact]
    public async Task Agents_never_see_another_workspaces_skills_even_with_the_right_id()
    {
        var w = await Workspace.CreateAsync(_factory);
        var other = await Workspace.CreateAsync(_factory);
        var plugin = await w.PluginAsync(w.Owner, "Ours", LibraryHelpers.Skill("our-secret-skill", "Ours only", "Our secret text."));
        var skill = await w.SkillIdAsync(w.Owner, plugin);
        await w.ShareAsync(w.Owner, "plugins", plugin, new { orgWide = true });
        var search = await Capability(other, other.Owner, "tools/call", new { name = "search_capabilities", arguments = new { query = "secret" } });
        Assert.DoesNotContain("our-secret-skill", search);
        var read = await Capability(other, other.Owner, "tools/call", new { name = "execute_capability", arguments = new { capability_id = $"plugin:{plugin}:{skill}", arguments = new { } } });
        Assert.DoesNotContain("Our secret text", read);
    }

    // ---------- GitHub import ----------

    private void SeedRepo()
    {
        var g = _factory.Github.Files;
        g.Clear();
        g[".claude-plugin/marketplace.json"] = """{"name":"Acme Tools","owner":{"name":"Acme"},"metadata":{"version":"1.2"},"plugins":[{"name":"sales","source":"./plugins/sales","description":"Sales helpers"},{"name":"remote","source":{"source":"github","repo":"x/y"}}]}""";
        g["plugins/sales/skills/pitch/SKILL.md"] = LibraryHelpers.Skill("pitch-deck", "Build a pitch deck", "Open with the problem.");
        g["plugins/sales/skills/followup/SKILL.md"] = LibraryHelpers.Skill("follow-up", "Write a follow up", "Be brief.");
        g["plugins/sales/skills/broken/SKILL.md"] = "this has no frontmatter";
        g["plugins/sales/.mcp.json"] = """{"mcpServers":{"crm":{"url":"https://mcp.example.com/crm"},"local":{"command":"npx","args":["x"]}}}""";
        g["README.md"] = "# Acme";
    }

    [Fact]
    public async Task Import_previews_a_repository_it_reads_over_http()
    {
        SeedRepo();
        var w = await Workspace.CreateAsync(_factory);
        var r = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/plugins/import-mcps-from-github-url/preview", new { githubUrl = "https://github.com/o/r" });
        Assert.Equal(HttpStatusCode.OK, r.Status);
        var plan = r.Body.GetProperty("item");
        Assert.Equal("claude_marketplace_repo", plan.GetProperty("classification").GetString());
        Assert.Equal("main", plan.GetProperty("branch").GetString());
        Assert.Equal("o/r", plan.GetProperty("repositoryFullName").GetString());
        Assert.Equal("abc123", plan.GetProperty("sourceRevisionRef").GetString());
        Assert.Equal("Acme Tools", plan.GetProperty("marketplace").GetProperty("name").GetString());
        var plugin = plan.GetProperty("plugins").EnumerateArray().Single();
        Assert.Equal("sales", plugin.GetProperty("name").GetString());
        Assert.Equal(2, plugin.GetProperty("skillCount").GetInt32());
        Assert.Equal(2, plugin.GetProperty("mcpCount").GetInt32());   // two servers declared
        var skills = plan.GetProperty("skills").EnumerateArray().ToList();
        Assert.Equal(3, skills.Count);
        Assert.Equal(2, skills.Count(s => s.GetProperty("supported").GetBoolean()));
        Assert.Equal("invalid_skill", skills.Single(s => !s.GetProperty("supported").GetBoolean()).GetProperty("skippedReason").GetString());
        var servers = plan.GetProperty("servers").EnumerateArray().ToList();
        Assert.Equal("https://mcp.example.com/crm", servers.Single(s => s.GetProperty("supported").GetBoolean()).GetProperty("url").GetString());
        Assert.Equal("local_unsupported", servers.Single(s => !s.GetProperty("supported").GetBoolean()).GetProperty("skippedReason").GetString());
        Assert.NotEmpty(plan.GetProperty("warnings").EnumerateArray());

        // A folder URL reads from that folder.
        var tree = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/plugins/import-mcps-from-github-url/preview", new { githubUrl = "https://github.com/o/r/tree/main/plugins/sales" });
        Assert.Equal("plugins/sales", tree.Body.GetProperty("item").GetProperty("rootPath").GetString());
        Assert.Equal("folder_inferred_repo", tree.Body.GetProperty("item").GetProperty("classification").GetString());
        Assert.Equal(3, tree.Body.GetProperty("item").GetProperty("skills").GetArrayLength());
        // A folder with nothing in it, a private repository, a missing one and GitHub's own limit are each answered plainly.
        Assert.Equal("github_plugin_root_not_found", Workspace.Error((await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/plugins/import-mcps-from-github-url/preview", new { githubUrl = "https://github.com/o/r/tree/main/nothing-here" })).Body));
        Assert.Equal("private_github_repo", Workspace.Error((await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/plugins/import-mcps-from-github-url/preview", new { githubUrl = "https://github.com/o/secret" })).Body));
        Assert.Equal(HttpStatusCode.NotFound, (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/plugins/import-mcps-from-github-url/preview", new { githubUrl = "https://github.com/o/missing" })).Status);
        var limited = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/plugins/import-mcps-from-github-url/preview", new { githubUrl = "https://github.com/o/limited" });
        Assert.Equal(HttpStatusCode.BadGateway, limited.Status);
        Assert.Equal("github_request_failed", Workspace.Error(limited.Body));
        Assert.Equal(HttpStatusCode.NotFound, (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/plugins/import-mcps-from-github-url/preview", new { githubUrl = "https://github.com/o/r/tree/nobranch" })).Status);
        // The address is checked before anything is fetched.
        var before = _factory.Github.Requests;
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/plugins/import-mcps-from-github-url/preview", new { githubUrl = "https://gitlab.com/o/r" })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/plugins/import-mcps-from-github-url/preview", new { githubUrl = "https://github.com/o/r/issues/3" })).Status);
        Assert.Equal(before, _factory.Github.Requests);
    }

    [Fact]
    public async Task Import_creates_a_shared_plugin_updates_it_on_a_second_import_and_archives_what_disappeared()
    {
        SeedRepo();
        var w = await Workspace.CreateAsync(_factory);
        var member = await w.AddAsync(); var nobody = await w.AddAsync();
        var url = "https://github.com/o/r/tree/main/plugins/sales";
        var denied = await w.CallAsync(member, HttpMethod.Post, "/v1/plugins/import-mcps-from-github-url", new { githubUrl = url });
        Assert.Equal(HttpStatusCode.Forbidden, denied.Status);
        Assert.Equal("Only organization owners and admins can import plugins from GitHub.", denied.Message());

        var first = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/plugins/import-mcps-from-github-url", new { githubUrl = url, name = "Sales kit", access = new { orgWide = false, memberIds = new[] { member.MemberId } } });
        Assert.Equal(HttpStatusCode.OK, first.Status);
        var item = first.Body.GetProperty("item");
        Assert.Equal("created", item.GetProperty("mode").GetString());
        Assert.Equal(2, item.GetProperty("importedSkills").GetArrayLength());
        Assert.Equal("broken", item.GetProperty("skippedSkills")[0].GetProperty("sourcePath").GetString()!.Split('/')[^2]);
        Assert.Equal("Sales kit", item.GetProperty("plugin").GetProperty("name").GetString());
        Assert.Equal(url, item.GetProperty("plugin").GetProperty("sourceRepositoryUrl").GetString());
        var plugin = item.GetProperty("plugin").GetProperty("id").GetString()!;
        // Shared with the member only.
        Assert.Equal(HttpStatusCode.OK, await w.StatusAsync(member, $"/v1/plugins/{plugin}"));
        Assert.Equal(HttpStatusCode.Forbidden, await w.StatusAsync(nobody, $"/v1/plugins/{plugin}"));
        var skillIds = item.GetProperty("importedSkills").EnumerateArray().Select(s => s.GetProperty("configObjectId").GetString()!).ToList();
        Assert.Equal(HttpStatusCode.OK, await w.StatusAsync(member, $"/v1/config-objects/{skillIds[0]}"));
        Assert.Equal("import", (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/config-objects/{skillIds[0]}")).Body.GetProperty("item").GetProperty("sourceMode").GetString());

        // Second import, nothing changed.
        var same = (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/plugins/import-mcps-from-github-url", new { githubUrl = url, name = "Sales kit" })).Body.GetProperty("item");
        Assert.Equal("updated", same.GetProperty("mode").GetString());
        Assert.Equal(plugin, same.GetProperty("plugin").GetProperty("id").GetString());
        Assert.Equal(0, same.GetProperty("importedSkills").GetArrayLength());
        Assert.Equal(2, same.GetProperty("unchanged").GetArrayLength());

        // The repository changes: one skill edited, one deleted, one added.
        var files = _factory.Github.Files;
        files["plugins/sales/skills/pitch/SKILL.md"] = LibraryHelpers.Skill("pitch-deck", "Build a better pitch deck", "Open with the customer.");
        files.Remove("plugins/sales/skills/followup/SKILL.md");
        files["plugins/sales/skills/demo/SKILL.md"] = LibraryHelpers.Skill("demo-script", "Run a demo", "Show value fast.");
        var third = (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/plugins/import-mcps-from-github-url", new { githubUrl = url, name = "Sales kit" })).Body.GetProperty("item");
        Assert.Equal("pitch-deck", third.GetProperty("updatedSkills")[0].GetProperty("name").GetString());
        Assert.Equal("demo-script", third.GetProperty("importedSkills")[0].GetProperty("name").GetString());
        Assert.Equal("follow-up", third.GetProperty("removed")[0].GetProperty("name").GetString());
        var current = (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/plugins/{plugin}/resolved")).Body.GetProperty("items").EnumerateArray().Select(i => i.GetProperty("configObject").GetProperty("title").GetString()!).Order().ToArray();
        Assert.Equal(["demo-script", "pitch-deck"], current);
        var removedId = third.GetProperty("removed")[0].GetProperty("configObjectId").GetString()!;
        Assert.Equal("archived", (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/config-objects/{removedId}")).Body.GetProperty("item").GetProperty("status").GetString());   // archived, never deleted
        var pitch = third.GetProperty("updatedSkills")[0].GetProperty("configObjectId").GetString()!;
        Assert.Equal(2, (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/config-objects/{pitch}/versions")).Body.GetProperty("items").GetArrayLength());
        Assert.Single((await w.IdsAsync(w.Owner, "/v1/plugins?q=Sales%20kit")));
    }

    [Fact]
    public async Task Importing_everyone_by_default_and_into_a_marketplace_works_and_nothing_invalid_is_imported()
    {
        SeedRepo();
        var w = await Workspace.CreateAsync(_factory);
        var member = await w.AddAsync();
        var market = (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/marketplaces", new { name = "Imports" })).Body.GetProperty("item").GetProperty("id").GetString()!;
        var url = "https://github.com/o/r/tree/main/plugins/sales";
        var picked = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/plugins/import-mcps-from-github-url", new { githubUrl = url, marketplaceId = market, selectedSkillKeys = new[] { "skills/pitch/SKILL.md" } });
        Assert.True(picked.Status == HttpStatusCode.OK, picked.Body.ToString());
        var item = picked.Body.GetProperty("item");
        Assert.Equal(1, item.GetProperty("importedSkills").GetArrayLength());
        Assert.Equal(market, item.GetProperty("marketplaceId").GetString());
        var plugin = item.GetProperty("plugin").GetProperty("id").GetString()!;
        Assert.Equal(HttpStatusCode.OK, await w.StatusAsync(member, $"/v1/plugins/{plugin}"));   // everyone, by default
        Assert.Equal(1, (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/marketplaces/{market}")).Body.GetProperty("item").GetProperty("pluginCount").GetInt32());
        // Choosing only the broken skill imports nothing and creates nothing.
        var before = (await w.IdsAsync(w.Owner, "/v1/plugins")).Length;
        var none = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/plugins/import-mcps-from-github-url", new { githubUrl = url, name = "Nothing", selectedSkillKeys = new[] { "skills/broken/SKILL.md" } });
        Assert.Equal(HttpStatusCode.BadRequest, none.Status);
        Assert.Equal(before, (await w.IdsAsync(w.Owner, "/v1/plugins")).Length);
        // The marketplace must be one the person may edit, and exist here.
        var other = await Workspace.CreateAsync(_factory);
        Assert.Equal(HttpStatusCode.NotFound, (await other.CallAsync(other.Owner, HttpMethod.Post, "/v1/plugins/import-mcps-from-github-url", new { githubUrl = url, marketplaceId = market })).Status);
    }
}
