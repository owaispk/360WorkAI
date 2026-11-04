using System.Net;
using System.Text.Json;

namespace WorkAI360.Api.Tests;

/// <summary>GET /v1/org/activity: the admin dashboard's five newest additions.</summary>
public sealed class DashboardActivityTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private static async Task<List<JsonElement>> ActivityAsync(Workspace w, Person p)
    {
        var r = await w.SendAsync(w.As(p, HttpMethod.Get, "/v1/org/activity"));
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.Equal("no-store", r.Headers.CacheControl?.ToString());
        return (await ApiFactory.ReadJsonAsync(r)).GetProperty("activity").EnumerateArray().ToList();
    }

    private static async Task ProviderAsync(Workspace w, string name)
    {
        var r = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/llm-providers", new { name, source = "models_dev", providerId = "openai", modelIds = new[] { "gpt-4o" }, apiKey = "k" });
        Assert.Equal(HttpStatusCode.Created, r.Status);
    }

    [Fact]
    public async Task Providers_plugins_added_to_a_marketplace_and_skill_versions_appear_newest_first()
    {
        var w = await Workspace.CreateAsync(factory, "Activity Space");
        Assert.Empty(await ActivityAsync(w, w.Owner));

        await ProviderAsync(w, "Acme Models");
        await Task.Delay(20);
        var plugin = await w.PluginAsync(w.Owner, "Writing Kit", LibraryHelpers.Skill("tone-guide"));
        await Task.Delay(20);
        var market = (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/marketplaces", new { name = "Shelf" })).Body.GetProperty("item").GetProperty("id").GetString()!;
        Assert.Equal(HttpStatusCode.Created, (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/marketplaces/{market}/plugins", new { pluginId = plugin })).Status);

        var activity = await ActivityAsync(w, w.Owner);
        Assert.Equal(["plugin", "skill", "provider"], activity.Select(a => a.GetProperty("kind").GetString()!).ToArray());
        Assert.Equal("Writing Kit was added to the Shelf marketplace", activity[0].GetProperty("title").GetString());
        Assert.Equal("Plugin with 1 skill", activity[0].GetProperty("detail").GetString());
        Assert.Equal(market, activity[0].GetProperty("target").GetProperty("marketplaceId").GetString());
        Assert.Equal("A new version of tone-guide was published", activity[1].GetProperty("title").GetString());
        Assert.Equal("Skill in Writing Kit", activity[1].GetProperty("detail").GetString());
        Assert.Equal(plugin, activity[1].GetProperty("target").GetProperty("pluginId").GetString());
        Assert.Equal("Acme Models was added", activity[2].GetProperty("title").GetString());
        Assert.Equal("Model provider", activity[2].GetProperty("detail").GetString());
        Assert.Equal("openai", activity[2].GetProperty("logo").GetProperty("providerId").GetString());
        Assert.Equal("llm_provider", activity[2].GetProperty("target").GetProperty("type").GetString());
        var times = activity.Select(a => DateTime.Parse(a.GetProperty("occurredAt").GetString()!)).ToList();
        Assert.Equal(times.OrderByDescending(t => t), times);

        // Archiving the plugin removes what it contributed: a snapshot of what exists, not an audit log.
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/plugins/{plugin}/archive")).Status);
        Assert.Equal(["provider"], (await ActivityAsync(w, w.Owner)).Select(a => a.GetProperty("kind").GetString()!).ToArray());
    }

    [Fact]
    public async Task At_most_five_entries_only_this_workspaces_and_only_for_owners_and_admins()
    {
        var w = await Workspace.CreateAsync(factory, "Busy Space");
        // Two sources together exceed five (each source alone is also capped at five), so the overall limit is what holds.
        await w.PluginAsync(w.Owner, "Older Kit", LibraryHelpers.Skill("older-skill"));
        await Task.Delay(20);
        for (var i = 1; i <= 7; i++) await ProviderAsync(w, $"Provider {i}");
        var other = await Workspace.CreateAsync(factory, "Other Space");
        await ProviderAsync(other, "Elsewhere");

        var activity = await ActivityAsync(w, w.Owner);
        Assert.Equal(5, activity.Count);
        Assert.Equal("Provider 7 was added", activity[0].GetProperty("title").GetString());
        Assert.DoesNotContain(activity, a => a.GetProperty("title").GetString()!.Contains("Elsewhere"));

        var admin = await w.AddAsync("admin");
        Assert.Equal(5, (await ActivityAsync(w, admin)).Count);
        var member = await w.AddAsync();
        var denied = await w.SendAsync(w.As(member, HttpMethod.Get, "/v1/org/activity"));
        Assert.Equal(HttpStatusCode.Forbidden, denied.StatusCode);
    }
}
