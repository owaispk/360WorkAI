using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Domain.Workspace;
using WorkAI360.Api.Features.Workspace;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>A server with webhook secrets set and loopback servers reachable (the fake MCP server listens there).</summary>
public class WorkspaceFactory : ConnectionFactory
{
    protected override IEnumerable<KeyValuePair<string, string>> More => [new("Workspace:GithubWebhookSecret", "gh-secret-for-tests"), new("Workspace:StripeWebhookSecret", "whsec_for_tests"), .. Extra];
    protected virtual IEnumerable<KeyValuePair<string, string>> Extra => [];
}

/// <summary>Generated views switched on, and Apps not being their own MCP servers (so views may be activated and saved).</summary>
public sealed class ViewsFactory : WorkspaceFactory
{
    protected override IEnumerable<KeyValuePair<string, string>> Extra => [new("Workspace:GeneratedArtifactViewsEnabled", "true"), new("Workspace:AppMcpServersEnabled", "false")];
}

/// <summary>Generated views on, Apps as MCP servers (the reference default when views are on): views are read-only.</summary>
public sealed class LegacyViewsFactory : WorkspaceFactory
{
    protected override IEnumerable<KeyValuePair<string, string>> Extra => [new("Workspace:GeneratedArtifactViewsEnabled", "true")];
}

/// <summary>Apps as MCP servers switched off: the catalog is empty.</summary>
public sealed class NoAppServersFactory : WorkspaceFactory
{
    protected override IEnumerable<KeyValuePair<string, string>> Extra => [new("Workspace:AppMcpServersEnabled", "false")];
}

public sealed record Seeded(string PluginId, string Id, string VersionId);

public static class WorkflowHelpers
{
    public const string Code = "const n = input.n ?? 1;\nif (n > 5) { return { big: true } }\nreturn { doubled: n * 2, name: 'x' }";
    public static readonly object InSchema = new { type = "object", properties = new { n = new { type = "number" } } };
    public static readonly object OutSchema = new { type = "object" };

    public static object Payload(object? required = null, object? limits = null, string? language = null)
    {
        var d = new Dictionary<string, object?> { ["language"] = language ?? "codemode-js", ["inputSchema"] = InSchema, ["outputSchema"] = OutSchema, ["exampleInput"] = new { n = 2 }, ["requiredCapabilities"] = required ?? Array.Empty<object>() };
        if (limits is not null) d["limits"] = limits;
        return d;
    }

    /// <summary>A plugin holding one Workflow, made through the library's own routes (as an import would). Shared with nobody.</summary>
    public static async Task<Seeded> WorkflowAsync(this Workspace w, Person by, string name = "Doubler", string code = Code, object? payload = null)
    {
        var plugin = await w.CallAsync(by, HttpMethod.Post, "/v1/plugins", new { name = $"{name} plugin {Guid.NewGuid():N}"[..40] });
        Assert.Equal(HttpStatusCode.Created, plugin.Status);
        var pluginId = plugin.Body.GetProperty("item").GetProperty("id").GetString()!;
        var made = await w.CallAsync(by, HttpMethod.Post, "/v1/config-objects", new { type = "workflow", sourceMode = "cloud", pluginIds = new[] { pluginId },
            input = new { rawSourceText = code, normalizedPayloadJson = payload ?? Payload(), schemaVersion = "codemode-script-v1", metadata = new { name, description = "Doubles" } } });
        Assert.True(made.Status == HttpStatusCode.Created, $"workflow: {made.Status} {made.Body}");
        var item = made.Body.GetProperty("item");
        return new Seeded(pluginId, item.GetProperty("id").GetString()!, item.GetProperty("latestVersion").GetProperty("id").GetString()!);
    }

    public static Task ShareAsync(this Workspace w, Person owner, string pluginId, Person to, string role = "viewer") =>
        w.CallAsync(owner, HttpMethod.Post, $"/v1/plugins/{pluginId}/access", new { orgMembershipId = to.MemberId, role });

    /// <summary>A grant on the Workflow itself (a plugin grant gives at most the viewer role on what is inside it).</summary>
    public static Task ShareWorkflowAsync(this Workspace w, Person owner, string configObjectId, Person to, string role = "viewer") =>
        w.CallAsync(owner, HttpMethod.Post, $"/v1/config-objects/{configObjectId}/access", new { orgMembershipId = to.MemberId, role });

    public static Dictionary<string, object?> Draft(Seeded wf, string name = "Doubler", string code = Code, object? example = null, object? required = null, bool withConfigObject = true, bool outputSchema = true)
    {
        var d = new Dictionary<string, object?> { ["name"] = name, ["description"] = "Doubles", ["code"] = code, ["exampleInput"] = example ?? new { n = 3 }, ["inputSchema"] = InSchema, ["requiredCapabilities"] = required ?? Array.Empty<object>() };
        if (outputSchema) d["outputSchema"] = OutSchema;
        if (withConfigObject) d["configObjectId"] = wf.Id;
        return d;
    }

    public static Task<(HttpStatusCode Status, JsonElement Body)> TestAsync(this Workspace w, Person by, Dictionary<string, object?> draft) => w.CallAsync(by, HttpMethod.Post, "/v1/workflows/test", draft);

    /// <summary>Tests the draft and saves it as a new version, returning the version's id.</summary>
    public static async Task<string> NewVersionAsync(this Workspace w, Person by, Seeded wf, Dictionary<string, object?>? draft = null)
    {
        draft ??= Draft(wf);
        var tested = await w.TestAsync(by, draft);
        Assert.True(tested.Status == HttpStatusCode.OK, $"test: {tested.Status} {tested.Body}");
        var body = new Dictionary<string, object?>(draft) { ["receiptId"] = tested.Body.GetProperty("receiptId").GetString() };
        body.Remove("configObjectId");
        var created = await w.CallAsync(by, HttpMethod.Post, $"/v1/workflows/{wf.Id}/versions", body);
        Assert.True(created.Status == HttpStatusCode.Created, $"version: {created.Status} {created.Body}");
        return created.Body.GetProperty("currentVersion").GetProperty("id").GetString()!;
    }

    public static Task<(HttpStatusCode Status, JsonElement Body)> RunAsync(this Workspace w, Person by, Seeded wf, string versionId, object? input = null, string? mode = null, string? timeZone = null)
    {
        var body = new Dictionary<string, object?> { ["pluginId"] = wf.PluginId, ["configObjectVersionId"] = versionId };
        if (input is not null) body["input"] = input;
        if (mode is not null) body["mode"] = mode;
        if (timeZone is not null) body["timeZone"] = timeZone;
        return w.CallAsync(by, HttpMethod.Post, $"/v1/workflows/{wf.Id}/run", body);
    }

    public static string S(this JsonElement e, params string[] path)
    {
        foreach (var p in path) e = e.GetProperty(p);
        return e.ValueKind == JsonValueKind.Null ? "" : e.GetString() ?? e.GetRawText();
    }

    public static string Err(this (HttpStatusCode Status, JsonElement Body) r) => r.Body.ValueKind == JsonValueKind.Object && r.Body.TryGetProperty("error", out var e) ? e.GetString() ?? "" : "";

    public static async Task<(HttpStatusCode Status, JsonElement Body)> RawAsync(this Workspace w, Person by, HttpMethod method, string url, string json)
    {
        var request = w.As(by, method, url);
        request.Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json");
        var r = await w.Http.SendAsync(request);
        var text = await r.Content.ReadAsStringAsync();
        return (r.StatusCode, string.IsNullOrEmpty(text) ? default : JsonDocument.Parse(text).RootElement.Clone());
    }
}

public sealed class WorkflowTests : IClassFixture<WorkspaceFactory>, IAsyncLifetime
{
    private readonly WorkspaceFactory _factory;
    private FakeMcpServer _fake = null!;
    public WorkflowTests(WorkspaceFactory factory) => _factory = factory;
    public async Task InitializeAsync() => _fake = await FakeMcpServer.StartAsync();
    public async Task DisposeAsync() => await _fake.DisposeAsync();

    private static object Cap(string connectionId, string ns, string tool) => new { capabilityName = $"mcp:{connectionId}:{tool}", scriptPath = $"tools.{ns}.{tool}" };

    // ---------- who may see and change a Workflow ----------

    [Fact]
    public async Task A_workflow_in_another_workspace_is_not_found_on_every_route()
    {
        var w = await Workspace.CreateAsync(_factory, "Isolation A");
        var other = await Workspace.CreateAsync(_factory, "Isolation B");
        var wf = await w.WorkflowAsync(w.Owner);
        var version = await w.NewVersionAsync(w.Owner, wf);
        await w.RunAsync(w.Owner, wf, version);
        var snapshot = (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/workflows/{wf.Id}/snapshots")).Body.GetProperty("items")[0].S("receiptId");

        foreach (var (method, url) in new[]
        {
            (HttpMethod.Get, $"/v1/workflows/{wf.Id}"), (HttpMethod.Get, $"/v1/workflows/{wf.Id}/versions"), (HttpMethod.Get, $"/v1/workflows/{wf.Id}/snapshots"),
            (HttpMethod.Get, $"/v1/workflows/{wf.Id}/snapshots/{snapshot}"), (HttpMethod.Delete, $"/v1/workflows/{wf.Id}/snapshots/{snapshot}/content"),
        })
        {
            var r = await other.CallAsync(other.Owner, method, url);
            Assert.Equal(HttpStatusCode.NotFound, r.Status);
            Assert.Equal("workflow_not_found", r.Err());
        }
        var test = await other.TestAsync(other.Owner, WorkflowHelpers.Draft(wf));
        Assert.Equal(HttpStatusCode.NotFound, test.Status);
        var run = await other.RunAsync(other.Owner, wf, version);
        Assert.Equal("unknown_capability", run.Err());
        Assert.Empty((await other.CallAsync(other.Owner, HttpMethod.Get, "/v1/workflows")).Body.GetProperty("items").EnumerateArray());
        Assert.Empty((await other.CallAsync(other.Owner, HttpMethod.Get, "/v1/workflow-runs")).Body.GetProperty("runs").EnumerateArray());
    }

    [Fact]
    public async Task A_person_it_was_not_shared_with_cannot_read_test_or_change_it()
    {
        var w = await Workspace.CreateAsync(_factory, "Roles");
        var bob = await w.AddAsync();
        var wf = await w.WorkflowAsync(w.Owner);
        foreach (var (method, url) in new[] { (HttpMethod.Get, $"/v1/workflows/{wf.Id}"), (HttpMethod.Get, $"/v1/workflows/{wf.Id}/versions"), (HttpMethod.Get, $"/v1/workflows/{wf.Id}/snapshots") })
        {
            var r = await w.CallAsync(bob, method, url);
            Assert.Equal(HttpStatusCode.Forbidden, r.Status);
            Assert.Equal("Missing viewer access for config object.", r.Message());
        }
        var test = await w.TestAsync(bob, WorkflowHelpers.Draft(wf));
        Assert.Equal(HttpStatusCode.Forbidden, test.Status);
        Assert.Equal("Missing manager access for config object.", test.Message());
        var versions = await w.CallAsync(bob, HttpMethod.Post, $"/v1/workflows/{wf.Id}/versions", new Dictionary<string, object?>(WorkflowHelpers.Draft(wf, withConfigObject: false)) { ["receiptId"] = "wfr_01m6797hhce34acegcde4y57bd" });
        Assert.Equal(HttpStatusCode.Forbidden, versions.Status);
    }

    [Fact]
    public async Task A_viewer_reads_the_workflow_without_its_source_example_input_or_graph_labels_and_cannot_manage_it()
    {
        var w = await Workspace.CreateAsync(_factory, "Viewer redaction");
        var bob = await w.AddAsync();
        var wf = await w.WorkflowAsync(w.Owner, code: "if (input.secretFlag) { return { hidden: 1 } }\nreturn { shown: 2 }");
        await w.ShareAsync(w.Owner, wf.PluginId, bob);
        var detail = await w.CallAsync(bob, HttpMethod.Get, $"/v1/workflows/{wf.Id}");
        Assert.Equal(HttpStatusCode.OK, detail.Status);
        var script = detail.Body.GetProperty("script");
        Assert.False(script.GetProperty("canManage").GetBoolean());
        var version = script.GetProperty("currentVersion");
        Assert.Equal(JsonValueKind.Null, version.GetProperty("code").ValueKind);
        Assert.Equal(JsonValueKind.Null, version.GetProperty("exampleInput").ValueKind);
        Assert.DoesNotContain("secretFlag", version.GetProperty("graph").GetProperty("nodes").ToString().Replace("\"fields\":[\"secretFlag\"]", ""));
        Assert.Equal("viewer", detail.Body.GetProperty("workflow").S("role"));
        var versions = await w.CallAsync(bob, HttpMethod.Get, $"/v1/workflows/{wf.Id}/versions");
        Assert.All(versions.Body.GetProperty("items").EnumerateArray(), v => Assert.Equal(JsonValueKind.Null, v.GetProperty("code").ValueKind));
        var owner = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/workflows/{wf.Id}");
        Assert.Contains("secretFlag", owner.Body.GetProperty("script").GetProperty("currentVersion").S("code"));
    }

    [Fact]
    public async Task The_generic_config_object_routes_do_not_leak_a_workflows_source_to_viewers()
    {
        var w = await Workspace.CreateAsync(_factory, "Generic leak");
        var bob = await w.AddAsync();
        var wf = await w.WorkflowAsync(w.Owner, code: "return { leaked: 'no' }");
        await w.ShareAsync(w.Owner, wf.PluginId, bob);
        var generic = await w.CallAsync(bob, HttpMethod.Get, $"/v1/config-objects/{wf.Id}");
        var version = generic.Body.GetProperty("item").GetProperty("latestVersion");
        Assert.Equal(JsonValueKind.Null, version.GetProperty("rawSourceText").ValueKind);
        Assert.False(version.GetProperty("normalizedPayloadJson").TryGetProperty("exampleInput", out _));
        var inPlugin = await w.CallAsync(bob, HttpMethod.Get, $"/v1/plugins/{wf.PluginId}/config-objects");
        Assert.DoesNotContain("leaked", inPlugin.Body.GetRawText());
        Assert.DoesNotContain("exampleInput", inPlugin.Body.GetRawText());
    }

    [Fact]
    public async Task Only_workflows_shared_with_a_person_are_listed_for_them_through_the_workflow_its_plugin_or_everyone()
    {
        var w = await Workspace.CreateAsync(_factory, "Listing");
        var bob = await w.AddAsync();
        var carol = await w.AddAsync();
        var wf = await w.WorkflowAsync(w.Owner, "Listed");
        Assert.Empty((await w.CallAsync(bob, HttpMethod.Get, "/v1/workflows")).Body.GetProperty("items").EnumerateArray());
        await w.ShareAsync(w.Owner, wf.PluginId, bob);
        var seen = (await w.CallAsync(bob, HttpMethod.Get, "/v1/workflows")).Body.GetProperty("items").EnumerateArray().Select(i => i.S("configObjectId")).ToArray();
        Assert.Equal([wf.Id], seen);
        Assert.Empty((await w.CallAsync(carol, HttpMethod.Get, "/v1/workflows")).Body.GetProperty("items").EnumerateArray());
        await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/config-objects/{wf.Id}/access", new { orgWide = true, role = "viewer" });
        Assert.Single((await w.CallAsync(carol, HttpMethod.Get, "/v1/workflows")).Body.GetProperty("items").EnumerateArray());
    }

    [Fact]
    public async Task Archiving_the_plugin_takes_its_workflows_out_of_reach()
    {
        var w = await Workspace.CreateAsync(_factory, "Archived");
        var wf = await w.WorkflowAsync(w.Owner);
        var version = await w.NewVersionAsync(w.Owner, wf);
        Assert.Equal(HttpStatusCode.OK, (await w.RunAsync(w.Owner, wf, version, new { n = 1 })).Status);
        await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/plugins/{wf.PluginId}/archive");
        Assert.Equal(HttpStatusCode.NotFound, (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/workflows/{wf.Id}")).Status);
        Assert.Equal("unknown_capability", (await w.RunAsync(w.Owner, wf, version)).Err());
        Assert.Empty((await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/workflows")).Body.GetProperty("items").EnumerateArray());
    }

    // ---------- running ----------

    [Fact]
    public async Task Running_needs_the_workflow_shared_with_you_and_a_plugin_grant_is_enough()
    {
        var w = await Workspace.CreateAsync(_factory, "Run access");
        var bob = await w.AddAsync();
        var wf = await w.WorkflowAsync(w.Owner);
        var version = await w.NewVersionAsync(w.Owner, wf);
        var denied = await w.RunAsync(bob, wf, version, new { n = 2 });
        Assert.Equal(HttpStatusCode.BadRequest, denied.Status);
        Assert.Equal("forbidden", denied.Err());
        Assert.Equal("You have not been granted access to this plugin capability.", denied.Message());
        await w.ShareAsync(w.Owner, wf.PluginId, bob);
        var ok = await w.RunAsync(bob, wf, version, new { n = 4 });
        Assert.Equal(HttpStatusCode.OK, ok.Status);
        Assert.Equal(8, ok.Body.GetProperty("value").GetProperty("doubled").GetDouble());
    }

    [Fact]
    public async Task A_run_by_marketplace_access_works_too()
    {
        var w = await Workspace.CreateAsync(_factory, "Marketplace run");
        var bob = await w.AddAsync();
        var wf = await w.WorkflowAsync(w.Owner);
        var version = await w.NewVersionAsync(w.Owner, wf);
        var market = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/marketplaces", new { name = "Shelf" });
        var marketId = market.Body.GetProperty("item").S("id");
        await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/marketplaces/{marketId}/plugins", new { pluginId = wf.PluginId });
        Assert.Equal("forbidden", (await w.RunAsync(bob, wf, version, new { n = 1 })).Err());
        await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/marketplaces/{marketId}/access", new { orgMembershipId = bob.MemberId, role = "viewer" });
        Assert.Equal(HttpStatusCode.OK, (await w.RunAsync(bob, wf, version, new { n = 1 })).Status);
    }

    [Fact]
    public async Task A_version_of_another_workflow_cannot_be_run_under_this_one()
    {
        var w = await Workspace.CreateAsync(_factory, "Version mixup");
        var one = await w.WorkflowAsync(w.Owner, "One");
        var two = await w.WorkflowAsync(w.Owner, "Two", code: "return { two: true }");
        var twoVersion = await w.NewVersionAsync(w.Owner, two, WorkflowHelpers.Draft(two, "Two", "return { two: true }"));
        var r = await w.RunAsync(w.Owner, one, twoVersion);
        Assert.Equal("script_not_executable", r.Err());
        Assert.Contains("has not synced content", r.Message());
    }

    [Fact]
    public async Task Each_run_leaves_its_own_receipt_even_when_many_run_at_once()
    {
        var w = await Workspace.CreateAsync(_factory, "Parallel runs");
        var wf = await w.WorkflowAsync(w.Owner);
        var version = await w.NewVersionAsync(w.Owner, wf);
        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(i => w.RunAsync(w.Owner, wf, version, new { n = i })));
        Assert.All(results, r => Assert.Equal(HttpStatusCode.OK, r.Status));
        Assert.Equal(8, results.Select(r => r.Body.S("receiptId")).Distinct().Count());
        var snapshots = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/workflows/{wf.Id}/snapshots?limit=200");
        Assert.Equal(8, snapshots.Body.GetProperty("items").GetArrayLength());
    }

    [Fact]
    public async Task A_live_run_gets_a_runtime_for_the_time_zone_and_cannot_use_tools_that_may_write()
    {
        var w = await Workspace.CreateAsync(_factory, "Live");
        var wf = await w.WorkflowAsync(w.Owner, code: "return { today: input.runtime.today, zone: input.runtime.timeZone, start: input.runtime.dayStart }",
            payload: new { language = "codemode-js", outputSchema = new { type = "object" }, requiredCapabilities = Array.Empty<object>() });
        var r = await w.RunAsync(w.Owner, wf, wf.VersionId, mode: "live", timeZone: "Asia/Tokyo");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal("Asia/Tokyo", r.Body.GetProperty("value").S("zone"));
        Assert.Matches(@"^\d{4}-\d\d-\d\dT15:00:00\.000Z$", r.Body.GetProperty("value").S("start"));
        Assert.Equal("Asia/Tokyo", r.Body.S("timeZone"));
        var bad = await w.RunAsync(w.Owner, wf, wf.VersionId, mode: "live", timeZone: "Mars/Base");
        Assert.Equal("invalid_request", bad.Err());
        Assert.Equal("timeZone: Expected an IANA time zone", bad.Message());
    }

    [Fact]
    public async Task A_workflows_own_limits_stop_a_runaway_script_and_the_failure_is_a_receipt()
    {
        var w = await Workspace.CreateAsync(_factory, "Limits");
        var wf = await w.WorkflowAsync(w.Owner, code: "while (true) {}", payload: WorkflowHelpers.Payload(limits: new { timeoutMs = 300 }));
        var started = DateTime.UtcNow;
        var r = await w.RunAsync(w.Owner, wf, wf.VersionId, new { });
        Assert.Equal(HttpStatusCode.BadRequest, r.Status);
        Assert.Equal("script_failed", r.Err());
        Assert.True(DateTime.UtcNow - started < TimeSpan.FromSeconds(20));
        var snapshots = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/workflows/{wf.Id}/snapshots");
        Assert.Equal("TimeoutExceeded", snapshots.Body.GetProperty("items")[0].S("errorKind"));
    }

    [Fact]
    public async Task A_stored_payload_that_is_malformed_cannot_run_and_says_so()
    {
        var w = await Workspace.CreateAsync(_factory, "Malformed");
        var wf = await w.WorkflowAsync(w.Owner, payload: new { language = "python", requiredCapabilities = Array.Empty<object>() });
        // A version nobody can read is also left out of the lists.
        var r = await w.RunAsync(w.Owner, wf, wf.VersionId);
        Assert.Equal("script_not_executable", r.Err());
        var detail = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/workflows/{wf.Id}");
        Assert.Equal(HttpStatusCode.NotFound, detail.Status);
        Assert.Equal("workflow_version_not_found", detail.Message());
    }

    [Fact]
    public async Task Request_bodies_are_checked_field_by_field_with_every_problem_listed()
    {
        var w = await Workspace.CreateAsync(_factory, "Validation");
        var wf = await w.WorkflowAsync(w.Owner);
        var r = await w.RawAsync(w.Owner, HttpMethod.Post, "/v1/workflows/test", """{"name":"","code":5,"requiredCapabilities":[{"capabilityName":" ","scriptPath":"x"}, 3],"configObjectId":9}""");
        Assert.Equal(HttpStatusCode.BadRequest, r.Status);
        Assert.Equal("invalid_request", r.Err());
        var paths = r.Body.GetProperty("details").EnumerateArray().Select(d => string.Join('.', d.GetProperty("path").EnumerateArray().Select(p => p.ToString()))).ToArray();
        Assert.Equal(["name", "code", "requiredCapabilities.0.capabilityName", "requiredCapabilities.1", "configObjectId"], paths);
        Assert.Equal("name: Too small: expected string to have >=1 characters (and 4 more)", r.Message());
        var run = await w.RawAsync(w.Owner, HttpMethod.Post, $"/v1/workflows/{wf.Id}/run", """{"pluginId":"p","configObjectVersionId":"v","mode":"sometimes"}""");
        Assert.Equal("mode: Invalid option: expected one of \"adhoc\"|\"live\"", run.Message());
        var tooMany = await w.RawAsync(w.Owner, HttpMethod.Post, "/v1/workflows/test", $$"""{"name":"x","code":"return 1","requiredCapabilities":[{{string.Join(",", Enumerable.Repeat("""{"capabilityName":"a","scriptPath":"b"}""", 101))}}],"configObjectId":"x"}""");
        Assert.Equal("requiredCapabilities: Too big: expected array to have <=100 items", tooMany.Message());
        Assert.Equal(HttpStatusCode.BadRequest, (await w.RawAsync(w.Owner, HttpMethod.Post, "/v1/workflows/test", "[]")).Status);
    }

    // ---------- a new version needs the receipt of the exact test ----------

    [Fact]
    public async Task A_receipt_belongs_to_the_person_who_tested_the_draft()
    {
        var w = await Workspace.CreateAsync(_factory, "Receipt owner");
        var bob = await w.AddAsync();
        var wf = await w.WorkflowAsync(w.Owner);
        await w.ShareWorkflowAsync(w.Owner, wf.Id, bob, "manager");
        var tested = await w.TestAsync(w.Owner, WorkflowHelpers.Draft(wf));
        var body = new Dictionary<string, object?>(WorkflowHelpers.Draft(wf, withConfigObject: false)) { ["receiptId"] = tested.Body.S("receiptId") };
        var asBob = await w.CallAsync(bob, HttpMethod.Post, $"/v1/workflows/{wf.Id}/versions", body);
        Assert.Equal(HttpStatusCode.BadRequest, asBob.Status);
        Assert.Equal("workflow_matching_test_receipt_required", asBob.Err());
        Assert.Equal(HttpStatusCode.Created, (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/workflows/{wf.Id}/versions", body)).Status);
    }

    [Fact]
    public async Task A_receipt_older_than_fifteen_minutes_no_longer_makes_a_version()
    {
        var w = await Workspace.CreateAsync(_factory, "Stale receipt");
        var wf = await w.WorkflowAsync(w.Owner);
        var tested = await w.TestAsync(w.Owner, WorkflowHelpers.Draft(wf));
        var receipt = tested.Body.S("receiptId");
        _factory.WithDb(db => db.Set<WorkflowRun>().Where(r => r.Id == receipt).ExecuteUpdate(s => s.SetProperty(r => r.FinishedAt, DateTime.UtcNow.AddMinutes(-16))));
        var body = new Dictionary<string, object?>(WorkflowHelpers.Draft(wf, withConfigObject: false)) { ["receiptId"] = receipt };
        var r = await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/workflows/{wf.Id}/versions", body);
        Assert.Equal("workflow_matching_test_receipt_required", r.Err());
    }

    [Fact]
    public async Task One_receipt_makes_one_version_even_when_two_requests_present_it_together()
    {
        var w = await Workspace.CreateAsync(_factory, "Receipt race");
        var wf = await w.WorkflowAsync(w.Owner);
        var tested = await w.TestAsync(w.Owner, WorkflowHelpers.Draft(wf));
        var body = new Dictionary<string, object?>(WorkflowHelpers.Draft(wf, withConfigObject: false)) { ["receiptId"] = tested.Body.S("receiptId") };
        var results = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/workflows/{wf.Id}/versions", body)));
        Assert.Equal(1, results.Count(r => r.Status == HttpStatusCode.Created));
        Assert.All(results.Where(r => r.Status != HttpStatusCode.Created), r => Assert.Equal("workflow_rejected", r.Err()));
        Assert.DoesNotContain(results, r => (int)r.Status >= 500);
        var versions = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/workflows/{wf.Id}/versions");
        Assert.Equal(2, versions.Body.GetProperty("items").GetArrayLength());
    }

    [Fact]
    public async Task A_new_version_updates_the_name_and_description_and_keeps_the_old_versions_readable()
    {
        var w = await Workspace.CreateAsync(_factory, "Versions");
        var wf = await w.WorkflowAsync(w.Owner);
        var draft = WorkflowHelpers.Draft(wf, name: "Renamed", code: "return { v: 2 }", outputSchema: false);
        draft["description"] = "  Now described  ";
        var version = await w.NewVersionAsync(w.Owner, wf, draft);
        var detail = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/workflows/{wf.Id}");
        Assert.Equal("Renamed", detail.Body.GetProperty("script").S("title"));
        Assert.Equal("Now described", detail.Body.GetProperty("script").S("description"));
        Assert.Equal(version, detail.Body.GetProperty("script").GetProperty("currentVersion").S("id"));
        var all = (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/workflows/{wf.Id}/versions")).Body.GetProperty("items");
        Assert.Equal([version, wf.VersionId], all.EnumerateArray().Select(v => v.S("id")).ToArray());
        Assert.Equal(WorkflowHelpers.Code, all[1].S("code"));
        // The newest version runs by default through the agent capability; an older one stays runnable by id.
        Assert.Equal(1, (await w.RunAsync(w.Owner, wf, wf.VersionId, new { n = 0 })).Body.GetProperty("value").GetProperty("doubled").GetDouble() + 1);
    }

    [Fact]
    public async Task A_version_cannot_be_made_from_source_with_a_literal_credential()
    {
        var w = await Workspace.CreateAsync(_factory, "Version secret");
        var wf = await w.WorkflowAsync(w.Owner);
        var draft = WorkflowHelpers.Draft(wf, code: "const token = 'abcdef123456'; return { ok: true }", outputSchema: false);
        var tested = await w.TestAsync(w.Owner, draft);
        Assert.Equal(HttpStatusCode.OK, tested.Status);
        var body = new Dictionary<string, object?>(draft) { ["receiptId"] = tested.Body.S("receiptId") };
        body.Remove("configObjectId");
        var r = await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/workflows/{wf.Id}/versions", body);
        Assert.Equal("workflow_source_contains_secret", r.Err());
    }

    [Fact]
    public async Task An_example_input_that_breaks_the_schema_cannot_be_saved_as_a_version()
    {
        var w = await Workspace.CreateAsync(_factory, "Example input");
        var wf = await w.WorkflowAsync(w.Owner);
        var bad = WorkflowHelpers.Draft(wf, example: new { n = "text" });
        var r = await w.TestAsync(w.Owner, bad);
        Assert.Equal("invalid_arguments", r.Err());
        var malformed = WorkflowHelpers.Draft(wf);
        malformed["inputSchema"] = new { type = "wat" };
        var s = await w.TestAsync(w.Owner, malformed);
        Assert.Equal(HttpStatusCode.BadRequest, s.Status);
        Assert.Equal("unsupported", s.Err());
        var notObject = WorkflowHelpers.Draft(wf);
        notObject["outputSchema"] = new[] { 1 };
        var t = await w.TestAsync(w.Owner, notObject);
        Assert.Equal("workflow_rejected", t.Err());
        Assert.Equal("workflow_invalid_schema:The Workflow outputSchema must be a JSON Schema object.", t.Message());
    }

    // ---------- tools ----------

    [Fact]
    public async Task A_workflow_calls_the_connections_tools_it_declared_and_the_receipt_names_them()
    {
        var w = await Workspace.CreateAsync(_factory, "Tools");
        var connection = await w.NoneAsync(_fake, "Fake none");
        var required = new[] { Cap(connection, "fake_none", "echo") };
        var code = "const r = await tools.fake_none.echo({ message: input.say ?? 'hi' }); return { echoed: r.echoed }";
        var wf = await w.WorkflowAsync(w.Owner, "Echoer", code, WorkflowHelpers.Payload(required));
        var draft = WorkflowHelpers.Draft(wf, "Echoer", code, new { say = "hello" }, required);
        draft["inputSchema"] = new { type = "object" };
        var tested = await w.TestAsync(w.Owner, draft);
        Assert.True(tested.Status == HttpStatusCode.OK, $"{tested.Status} {tested.Body}");
        Assert.Equal("hello", tested.Body.GetProperty("value").S("echoed"));
        Assert.Equal(1, tested.Body.GetProperty("requiredCapabilities").GetArrayLength());
        Assert.Contains(_fake.McpCalls("none", "tools/call"), c => c.Tool == "echo");
        var version = await w.NewVersionAsync(w.Owner, wf, draft);
        var run = await w.RunAsync(w.Owner, wf, version, new { say = "again" });
        Assert.Equal("again", run.Body.GetProperty("value").S("echoed"));
        var receipt = (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/workflows/{wf.Id}/snapshots/{run.Body.S("receiptId")}")).Body;
        Assert.Equal("fake_none.echo", receipt.GetProperty("toolCalls")[0].S("name"));
        var runs = await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/workflow-runs?limit=1");
        Assert.Equal(1, runs.Body.GetProperty("runs")[0].GetProperty("toolCallCount").GetInt32());
    }

    [Fact]
    public async Task A_tool_that_was_not_declared_is_not_there_for_the_script()
    {
        var w = await Workspace.CreateAsync(_factory, "Undeclared");
        await w.NoneAsync(_fake, "Fake none");
        var code = "return await tools.fake_none.echo({ message: 'x' })";
        var wf = await w.WorkflowAsync(w.Owner, "Sneaky", code);
        var draft = WorkflowHelpers.Draft(wf, "Sneaky", code, outputSchema: false);
        var r = await w.TestAsync(w.Owner, draft);
        Assert.Equal(HttpStatusCode.BadRequest, r.Status);
        Assert.Equal("script_failed", r.Err());
        Assert.StartsWith("Uncaught:", r.Message());
        Assert.DoesNotContain(_fake.McpCalls("none", "tools/call"), c => c.Tool == "echo" && c.Args?["message"]?.ToString() == "x");
    }

    [Fact]
    public async Task Switching_the_tool_off_or_losing_access_makes_the_workflow_unavailable_without_calling_the_service()
    {
        var w = await Workspace.CreateAsync(_factory, "Tool policy");
        var bob = await w.AddAsync();
        var connection = await w.NoneAsync(_fake, "Fake none", ConnectionHelpers.Only(w.Owner.MemberId, bob.MemberId));
        var required = new[] { Cap(connection, "fake_none", "echo") };
        var code = "return await tools.fake_none.echo({ message: 'p' })";
        var wf = await w.WorkflowAsync(w.Owner, "Policed", code, WorkflowHelpers.Payload(required));
        await w.ShareAsync(w.Owner, wf.PluginId, bob);
        var draft = WorkflowHelpers.Draft(wf, "Policed", code, required: required, outputSchema: true);
        draft["inputSchema"] = new { type = "object" };
        var version = await w.NewVersionAsync(w.Owner, wf, draft);
        Assert.Equal(HttpStatusCode.OK, (await w.RunAsync(bob, wf, version, new { })).Status);
        _fake.Reset();

        var revoked = await w.CallAsync(w.Owner, HttpMethod.Put, $"/v1/mcp-connections/{connection}/access", new { access = ConnectionHelpers.Only(w.Owner.MemberId) });
        Assert.Equal(HttpStatusCode.OK, revoked.Status);
        var lost = await w.RunAsync(bob, wf, version, new { });
        Assert.Equal(HttpStatusCode.BadRequest, lost.Status);
        Assert.Equal("capability_unavailable", lost.Err());
        Assert.Contains("tools.fake_none.echo", lost.Message());
        Assert.Empty(_fake.McpCalls("none", "tools/call"));
        var failed = (await w.CallAsync(bob, HttpMethod.Get, $"/v1/workflows/{wf.Id}/snapshots")).Body.GetProperty("items")[0];
        Assert.Equal("failed", failed.S("status"));
        Assert.Equal("CapabilityUnavailable", failed.S("errorKind"));
    }

    [Fact]
    public async Task A_live_run_is_offered_only_read_only_tools_so_a_workflow_that_needs_a_connection_cannot_run_live()
    {
        var w = await Workspace.CreateAsync(_factory, "Live tools");
        var connection = await w.NoneAsync(_fake, "Fake none");
        var required = new[] { Cap(connection, "fake_none", "echo") };
        var code = "return await tools.fake_none.echo({ message: 'p' })";
        var wf = await w.WorkflowAsync(w.Owner, "Live echo", code, WorkflowHelpers.Payload(required));
        var live = await w.RunAsync(w.Owner, wf, wf.VersionId, mode: "live");
        Assert.Equal("capability_unavailable", live.Err());
        var adhoc = await w.RunAsync(w.Owner, wf, wf.VersionId, new { });
        Assert.Equal(HttpStatusCode.OK, adhoc.Status);
    }

    [Fact]
    public async Task The_workspaces_own_read_only_operations_are_tools_too()
    {
        var w = await Workspace.CreateAsync(_factory, "Den tools");
        var required = new[] { new { capabilityName = "openwork.whoami", scriptPath = "tools.den.whoami" } };
        var code = "const me = await tools.den.whoami({}); return { org: me.organization.name, role: me.role }";
        var wf = await w.WorkflowAsync(w.Owner, "Who", code, WorkflowHelpers.Payload(required));
        var live = await w.RunAsync(w.Owner, wf, wf.VersionId, mode: "live");
        Assert.Equal(HttpStatusCode.OK, live.Status);
        Assert.Equal("Den tools", live.Body.GetProperty("value").S("org"));
        Assert.Equal("owner", live.Body.GetProperty("value").S("role"));
    }

    // ---------- receipts ----------

    [Fact]
    public async Task Receipts_are_readable_by_everyone_with_access_only_under_the_standing_source_and_otherwise_by_their_maker()
    {
        var w = await Workspace.CreateAsync(_factory, "Receipt visibility");
        var bob = await w.AddAsync();
        var wf = await w.WorkflowAsync(w.Owner, code: "return { ok: true }", payload: new { language = "codemode-js", outputSchema = new { type = "object" }, requiredCapabilities = Array.Empty<object>() });
        await w.ShareAsync(w.Owner, wf.PluginId, bob, "manager");
        var manual = await w.RunAsync(w.Owner, wf, wf.VersionId);
        var live = await w.RunAsync(w.Owner, wf, wf.VersionId, mode: "live");
        var bobSees = (await w.CallAsync(bob, HttpMethod.Get, $"/v1/workflows/{wf.Id}/snapshots")).Body.GetProperty("items").EnumerateArray().Select(i => i.S("receiptId")).ToArray();
        Assert.Contains(manual.Body.S("receiptId"), bobSees);
        Assert.DoesNotContain(live.Body.S("receiptId"), bobSees);
        Assert.Equal(HttpStatusCode.NotFound, (await w.CallAsync(bob, HttpMethod.Get, $"/v1/workflows/{wf.Id}/snapshots/{live.Body.S("receiptId")}")).Status);
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(bob, HttpMethod.Get, $"/v1/workflows/{wf.Id}/snapshots/{manual.Body.S("receiptId")}")).Status);
    }

    [Fact]
    public async Task Only_the_person_who_made_a_run_can_erase_its_content()
    {
        var w = await Workspace.CreateAsync(_factory, "Erasure");
        var bob = await w.AddAsync();
        var wf = await w.WorkflowAsync(w.Owner);
        await w.ShareAsync(w.Owner, wf.PluginId, bob);
        await w.ShareWorkflowAsync(w.Owner, wf.Id, bob, "manager");
        var run = await w.RunAsync(w.Owner, wf, wf.VersionId, new { n = 1 });
        var id = run.Body.S("receiptId");
        var byBob = await w.CallAsync(bob, HttpMethod.Delete, $"/v1/workflows/{wf.Id}/snapshots/{id}/content");
        Assert.Equal(HttpStatusCode.NotFound, byBob.Status);
        Assert.Equal("workflow_not_found", byBob.Err());
        Assert.Equal("workflow_snapshot_not_found", byBob.Message());
        var mine = await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/workflows/{wf.Id}/snapshots/{id}/content");
        Assert.Equal(HttpStatusCode.OK, mine.Status);
        Assert.Equal(JsonValueKind.Null, mine.Body.GetProperty("value").ValueKind);
        Assert.Equal(JsonValueKind.Null, mine.Body.GetProperty("markdown").ValueKind);
        var row = _factory.WithDb(db => db.Set<WorkflowRun>().AsNoTracking().First(r => r.Id == id));
        Assert.Null(row.ValidatedResultCipher);
        Assert.Null(row.ResultMarkdownCipher);
        Assert.NotNull(row.ArtifactContentDeletedAt);
        Assert.NotNull(row.ResultDigest);
    }

    [Fact]
    public async Task Results_are_encrypted_at_rest_and_the_raw_input_is_never_stored()
    {
        var w = await Workspace.CreateAsync(_factory, "At rest");
        var wf = await w.WorkflowAsync(w.Owner, code: "return { who: 'zebra-quartz-result', saw: input.q }",
            payload: new { language = "codemode-js", outputSchema = new { type = "object" }, requiredCapabilities = Array.Empty<object>() });
        var run = await w.RunAsync(w.Owner, wf, wf.VersionId, new { q = "needle-in-the-input" });
        Assert.Equal(HttpStatusCode.OK, run.Status);
        var row = _factory.WithDb(db => db.Set<WorkflowRun>().AsNoTracking().First(r => r.Id == run.Body.S("receiptId")));
        Assert.NotNull(row.ValidatedResultCipher);
        Assert.DoesNotContain("zebra-quartz-result", row.ValidatedResultCipher);
        Assert.DoesNotContain("zebra-quartz-result", row.ResultMarkdownCipher);
        var all = _factory.WithDb(db => System.Text.Json.JsonSerializer.Serialize(db.Set<WorkflowRun>().AsNoTracking().Where(r => r.Id == row.Id).ToList()));
        Assert.DoesNotContain("needle-in-the-input", all);
        Assert.NotNull(row.ScriptInputDigest);
        // Reading it back through the route decrypts it.
        Assert.Equal("zebra-quartz-result", (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/workflows/{wf.Id}/snapshots/{row.Id}")).Body.GetProperty("value").S("who"));
    }

    [Fact]
    public async Task Snapshots_page_by_cursor_in_a_stable_order_and_a_bad_cursor_is_a_400()
    {
        var w = await Workspace.CreateAsync(_factory, "Paging");
        var wf = await w.WorkflowAsync(w.Owner);
        for (var i = 0; i < 5; i++) await w.RunAsync(w.Owner, wf, wf.VersionId, new { n = i });
        var seen = new List<string>();
        string? cursor = null;
        for (var page = 0; page < 10; page++)
        {
            var r = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/workflows/{wf.Id}/snapshots?limit=2{(cursor is null ? "" : "&cursor=" + cursor)}");
            Assert.Equal(HttpStatusCode.OK, r.Status);
            seen.AddRange(r.Body.GetProperty("items").EnumerateArray().Select(i => i.S("receiptId")));
            cursor = r.Body.GetProperty("nextCursor").ValueKind == JsonValueKind.String ? r.Body.S("nextCursor") : null;
            if (cursor is null) break;
        }
        Assert.Equal(5, seen.Count);
        Assert.Equal(5, seen.Distinct().Count());
        var bad = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/workflows/{wf.Id}/snapshots?cursor=garbage!!");
        Assert.Equal(HttpStatusCode.BadRequest, bad.Status);
        Assert.Equal("cursor: Invalid cursor.", bad.Message());
        var limit = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/workflows/{wf.Id}/snapshots?limit=201");
        Assert.Equal("limit: Too big: expected number to be <=200", limit.Message());
        var nan = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/workflows/{wf.Id}/snapshots?limit=abc");
        Assert.Equal("limit: Invalid input: expected number, received NaN", nan.Message());
    }

    [Fact]
    public async Task The_run_list_is_the_persons_own_with_workflow_titles_and_redacted_graphs_for_non_managers()
    {
        var w = await Workspace.CreateAsync(_factory, "Run list");
        var bob = await w.AddAsync();
        var wf = await w.WorkflowAsync(w.Owner, code: "if (input.hiddenCondition) { return { a: 1 } }\nreturn { b: 2 }");
        await w.ShareAsync(w.Owner, wf.PluginId, bob);
        await w.RunAsync(w.Owner, wf, wf.VersionId, new { hiddenCondition = false });
        await w.RunAsync(bob, wf, wf.VersionId, new { });
        var mine = (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/workflow-runs")).Body.GetProperty("runs");
        Assert.Equal(1, mine.GetArrayLength());
        Assert.Equal(w.Owner.MemberId, mine[0].S("orgMembershipId"));
        Assert.Contains(mine[0].GetProperty("workflow").GetProperty("graph").GetProperty("nodes").EnumerateArray(), n => n.S("label").Contains("hiddenCondition"));
        var his = (await w.CallAsync(bob, HttpMethod.Get, "/v1/workflow-runs")).Body.GetProperty("runs");
        Assert.Equal(1, his.GetArrayLength());
        var branch = his[0].GetProperty("workflow").GetProperty("graph").GetProperty("nodes").EnumerateArray().First(n => n.S("kind") == "branch");
        Assert.Equal("Condition", branch.S("label"));
        // When access is gone the list still shows the run but not the Workflow behind it.
        await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/plugins/{wf.PluginId}/access/{await GrantIdAsync(w, wf.PluginId, bob)}");
        var after = (await w.CallAsync(bob, HttpMethod.Get, "/v1/workflow-runs")).Body.GetProperty("runs");
        Assert.Equal(JsonValueKind.Null, after[0].GetProperty("workflow").ValueKind);
    }

    private static async Task<string> GrantIdAsync(Workspace w, string pluginId, Person who)
    {
        var grants = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/plugins/{pluginId}/access");
        return grants.Body.GetProperty("items").EnumerateArray().First(g => g.TryGetProperty("orgMembershipId", out var m) && m.GetString() == who.MemberId).S("id");
    }

    [Fact]
    public async Task The_legacy_paths_answer_exactly_like_the_new_ones()
    {
        var w = await Workspace.CreateAsync(_factory, "Aliases");
        var wf = await w.WorkflowAsync(w.Owner);
        var viaNew = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/workflows/{wf.Id}/versions");
        var viaScripts = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/codemode-scripts/{wf.Id}/versions");
        var viaPrograms = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/programs/{wf.Id}/versions");
        Assert.Equal(viaNew.Body.GetRawText(), viaScripts.Body.GetRawText());
        Assert.Equal(viaNew.Body.GetRawText(), viaPrograms.Body.GetRawText());
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/codemode-scripts")).Status);
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/codemode-runs")).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/programs")).Status);
    }

    // ---------- my library ----------

    [Fact]
    public async Task My_library_lists_workflows_beside_plugins_in_name_order_with_the_persons_role()
    {
        var w = await Workspace.CreateAsync(_factory, "Library");
        var bob = await w.AddAsync();
        var wf = await w.WorkflowAsync(w.Owner, "Zebra flow");
        var shared = await w.WorkflowAsync(w.Owner, "Alpha flow");
        await w.ShareAsync(w.Owner, shared.PluginId, bob);
        var mine = (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/me/library")).Body.GetProperty("items").EnumerateArray().ToArray();
        var names = mine.Select(i => i.S("name")).ToArray();
        Assert.Equal(names.OrderBy(n => n, StringComparer.InvariantCultureIgnoreCase).ToArray(), names);
        Assert.Contains(mine, i => i.S("type") == "workflow" && i.S("id") == wf.Id && i.S("role") == "manager");
        var his = (await w.CallAsync(bob, HttpMethod.Get, "/v1/me/library")).Body.GetProperty("items").EnumerateArray().Where(i => i.S("type") == "workflow").ToArray();
        Assert.Equal([shared.Id], his.Select(i => i.S("id")).ToArray());
        Assert.Equal("viewer", his[0].S("role"));
    }

    // ---------- saving a run as a Workflow ----------

    private async Task<(string Token, Workspace W)> AuthoringAsync(string name)
    {
        var w = await Workspace.CreateAsync(_factory, name);
        return (await w.MintAsync(w.Owner, "mcp:read", "mcp:write"), w);
    }

    private static JsonElement Structured(JsonElement result) => result.GetProperty("structuredContent");

    [Fact]
    public async Task An_agent_runs_a_script_then_saves_it_with_the_receipt_and_the_saved_workflow_runs()
    {
        var (token, w) = await AuthoringAsync("Authoring");
        var run = await w.AgentAsync(token, "execute_capability_script", new { code = "return { sum: input.a + input.b }", input = new { a = 2, b = 5 }, outputSchema = new { type = "object" } });
        Assert.False(run.TryGetProperty("isError", out var e) && e.GetBoolean(), run.GetRawText());
        var structured = Structured(run);
        Assert.Equal(7, structured.GetProperty("value").GetProperty("sum").GetDouble());
        Assert.True(structured.GetProperty("savable").GetBoolean());
        var receipt = structured.S("receiptId");

        var saved = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/workflows", new { name = "Adder", description = "Adds", receiptId = receipt, currentInput = new { a = 2, b = 5 }, outputSchema = new { type = "object" } });
        Assert.Equal(HttpStatusCode.Created, saved.Status);
        Assert.Equal("flowchart TD", saved.Body.S("mermaid").Split('\n')[0]);
        var id = saved.Body.S("configObjectId");
        var detail = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/workflows/{id}");
        Assert.Equal("Adder", detail.Body.GetProperty("script").S("title"));
        Assert.Equal(5, detail.Body.GetProperty("script").GetProperty("currentVersion").GetProperty("exampleInput").GetProperty("b").GetDouble());
        var again = await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/workflows/{id}/run", new { pluginId = saved.Body.S("pluginId"), configObjectVersionId = saved.Body.S("configObjectVersionId"), input = new { a = 1, b = 1 } });
        Assert.Equal(2, again.Body.GetProperty("value").GetProperty("sum").GetDouble());
    }

    [Fact]
    public async Task A_save_must_present_the_same_source_input_and_schemas_the_run_used()
    {
        var (token, w) = await AuthoringAsync("Authoring match");
        var run = await w.AgentAsync(token, "execute_capability_script", new { code = "return { v: input.v }", input = new { v = 1 }, outputSchema = new { type = "object" } });
        var receipt = Structured(run).S("receiptId");
        string Err((HttpStatusCode Status, JsonElement Body) r) => r.Status == HttpStatusCode.BadRequest ? r.Err() : $"{(int)r.Status}";
        Assert.Equal("workflow_authoring_receipt_required", Err(await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/workflows", new { name = "x", receiptId = receipt, currentInput = new { v = 2 }, outputSchema = new { type = "object" } })));
        Assert.Equal("workflow_authoring_receipt_required", Err(await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/workflows", new { name = "x", receiptId = receipt, currentInput = new { v = 1 } })));
        Assert.Equal("workflow_authoring_receipt_required", Err(await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/workflows", new { name = "x", receiptId = receipt, code = "return { v: 2 }", currentInput = new { v = 1 }, outputSchema = new { type = "object" } })));
        Assert.Equal("201", Err(await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/workflows", new { name = "x", receiptId = receipt, currentInput = new { v = 1 }, outputSchema = new { type = "object" } })));
    }

    [Fact]
    public async Task Another_persons_receipt_cannot_be_saved_and_a_receipt_expires()
    {
        var (token, w) = await AuthoringAsync("Authoring theft");
        var bob = await w.AddAsync();
        var run = await w.AgentAsync(token, "execute_capability_script", new { code = "return 1" });
        var receipt = Structured(run).S("receiptId");
        var stolen = await w.CallAsync(bob, HttpMethod.Post, "/v1/workflows", new { name = "Mine now", receiptId = receipt });
        Assert.Equal("workflow_authoring_receipt_required", stolen.Err());
        var byCode = await w.CallAsync(bob, HttpMethod.Post, "/v1/workflows", new { name = "By code", code = "return 1" });
        Assert.Equal("workflow_recent_receipt_required", byCode.Err());
        _factory.WithDb(db => db.Set<WorkflowRun>().Where(r => r.Id == receipt).ExecuteUpdate(s => s.SetProperty(r => r.FinishedAt, DateTime.UtcNow.AddMinutes(-20))));
        var late = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/workflows", new { name = "Late", code = "return 1" });
        Assert.Equal("workflow_recent_receipt_required", late.Err());
    }

    [Fact]
    public async Task A_saved_workflow_records_the_tools_the_run_called_as_its_required_capabilities()
    {
        var (token, w) = await AuthoringAsync("Authoring tools");
        var connection = await w.NoneAsync(_fake, "Fake none");
        var run = await w.AgentAsync(token, "execute_capability_script", new { code = "const r = await tools.fake_none.add({ a: 1, b: 2 }); return { r }" });
        Assert.False(run.TryGetProperty("isError", out var e) && e.GetBoolean(), run.GetRawText());
        var saved = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/workflows", new { name = "Adder tool", receiptId = Structured(run).S("receiptId") });
        Assert.Equal(HttpStatusCode.Created, saved.Status);
        var versions = (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/workflows/{saved.Body.S("configObjectId")}/versions")).Body.GetProperty("items")[0];
        var cap = versions.GetProperty("requiredCapabilities")[0];
        Assert.Equal($"mcp:{connection}:add", cap.S("capabilityName"));
        Assert.Equal("tools.fake_none.add", cap.S("scriptPath"));
        Assert.Contains(versions.GetProperty("graph").GetProperty("nodes").EnumerateArray(), n => n.S("kind") == "tool");
    }

    [Fact]
    public async Task Saving_into_a_plugin_needs_editor_access_and_the_same_name_makes_a_version_not_a_second_workflow()
    {
        var (token, w) = await AuthoringAsync("Authoring plugin");
        var bob = await w.AddAsync();
        var plugin = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/plugins", new { name = "Team flows" });
        var pluginId = plugin.Body.GetProperty("item").S("id");
        await w.ShareAsync(w.Owner, pluginId, bob, "viewer");
        var code = "return { shared: true }";
        var run = await w.AgentAsync(token, "execute_capability_script", new { code });
        var denied = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/workflows", new { pluginId = "plg_01m6797hhce34acegcde4y57bd", name = "Nope", receiptId = Structured(run).S("receiptId") });
        Assert.Equal(HttpStatusCode.Forbidden, denied.Status);
        var first = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/workflows", new { pluginId, name = "Team flow", code });
        Assert.Equal(HttpStatusCode.Created, first.Status);
        var second = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/workflows", new { pluginId, name = "Team flow", code });
        Assert.Equal(first.Body.S("configObjectId"), second.Body.S("configObjectId"));
        Assert.NotEqual(first.Body.S("configObjectVersionId"), second.Body.S("configObjectVersionId"));
        // The viewer of the plugin does not manage the Workflow, so cannot add a version of it.
        var bobToken = await w.MintAsync(bob, "mcp:read", "mcp:write");
        await w.AgentAsync(bobToken, "execute_capability_script", new { code });
        var byBob = await w.CallAsync(bob, HttpMethod.Post, "/v1/workflows", new { pluginId, name = "Team flow", code });
        Assert.Equal(HttpStatusCode.Forbidden, byBob.Status);
    }

    [Fact]
    public async Task Saving_the_same_name_at_the_same_moment_still_makes_one_workflow()
    {
        var (token, w) = await AuthoringAsync("Authoring race");
        await w.AgentAsync(token, "execute_capability_script", new { code = "return { race: 1 }" });
        var results = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => w.CallAsync(w.Owner, HttpMethod.Post, "/v1/workflows", new { name = "Racer", code = "return { race: 1 }" })));
        Assert.DoesNotContain(results, r => (int)r.Status >= 500);
        var created = results.Where(r => r.Status == HttpStatusCode.Created).ToArray();
        Assert.NotEmpty(created);
        Assert.Single(created.Select(r => r.Body.S("configObjectId")).Distinct());
        var library = (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/me/library")).Body.GetProperty("items").EnumerateArray();
        Assert.Single(library, i => i.S("type") == "workflow" && i.S("name") == "Racer");
        Assert.Single(library, i => i.S("type") == "plugin" && i.S("name") == "My Workflows");
    }

    [Fact]
    public async Task The_authoring_tool_refuses_credentials_checks_scopes_and_reports_script_errors()
    {
        var (token, w) = await AuthoringAsync("Authoring refusals");
        Assert.Equal("workflow_source_contains_secret", (await w.AgentAsync(token, "execute_capability_script", new { code = "const apiKey = 'abcdef123456'; return 1" })).ErrorOf());
        Assert.Equal("script_failed", (await w.AgentAsync(token, "execute_capability_script", new { code = "throw new Error('nope')" })).ErrorOf());
        Assert.Equal("invalid_result", (await w.AgentAsync(token, "execute_capability_script", new { code = "return 5", outputSchema = new { type = "object" } })).ErrorOf());
        Assert.Equal("invalid_capability_arguments", (await w.AgentAsync(token, "execute_capability_script", new { code = "return 1", input = new { n = "x" }, inputSchema = new { type = "object", properties = new { n = new { type = "number" } } } })).ErrorOf());
        Assert.Equal("invalid_request", (await w.AgentAsync(token, "execute_capability_script", new { code = "return 1", mode = "live", input = new { } })).ErrorOf());
        Assert.Equal("invalid_request", (await w.AgentAsync(token, "execute_capability_script", new { code = 5 })).ErrorOf());
        var readOnly = await w.MintAsync(w.Owner, "mcp:read");
        Assert.Equal("insufficient_scope", (await w.AgentAsync(readOnly, "execute_capability_script", new { code = "return 1" })).ErrorOf());
        var live = await w.AgentAsync(readOnly, "execute_capability_script", new { code = "return input.runtime.today", mode = "live" });
        Assert.False(live.TryGetProperty("isError", out var isError) && isError.GetBoolean(), live.GetRawText());
        var tools = await w.Http.SendAsync(Bearer(HttpMethod.Post, "/mcp/agent", token, new { jsonrpc = "2.0", id = 1, method = "tools/list" }));
        var names = (await ReadJsonAsync(tools)).GetProperty("result").GetProperty("tools").EnumerateArray().Select(t => t.S("name")).ToArray();
        Assert.Equal(["search_capabilities", "execute_capability", "execute_capability_script"], names);
    }

    [Fact]
    public async Task A_live_authoring_receipt_forbids_current_input_and_saves_without_example_input()
    {
        var (token, w) = await AuthoringAsync("Authoring live");
        var run = await w.AgentAsync(token, "execute_capability_script", new { code = "return { today: input.runtime.today }", mode = "live", timeZone = "UTC", outputSchema = new { type = "object" } });
        var receipt = Structured(run).S("receiptId");
        var forbidden = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/workflows", new { name = "Live one", receiptId = receipt, currentInput = new { }, outputSchema = new { type = "object" } });
        Assert.Equal("workflow_live_current_input_forbidden", forbidden.Err());
        var saved = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/workflows", new { name = "Live one", receiptId = receipt, outputSchema = new { type = "object" } });
        Assert.Equal(HttpStatusCode.Created, saved.Status);
        var version = (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/workflows/{saved.Body.S("configObjectId")}/versions")).Body.GetProperty("items")[0];
        Assert.Equal(JsonValueKind.Null, version.GetProperty("exampleInput").ValueKind);
        // A live run is never a receipt for saving by code alone (the reference answers as if the code had never run).
        var byCode = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/workflows", new { name = "Live two", code = "return { today: input.runtime.today }", outputSchema = new { type = "object" } });
        Assert.Equal("workflow_recent_receipt_required", byCode.Err());
    }

    // ---------- agents find and run saved workflows ----------

    [Fact]
    public async Task An_agent_finds_the_workflows_shared_with_its_person_and_runs_one_with_a_body()
    {
        var w = await Workspace.CreateAsync(_factory, "Agent capability");
        var bob = await w.AddAsync();
        var wf = await w.WorkflowAsync(w.Owner, "Doubler for agents");
        await w.ShareAsync(w.Owner, wf.PluginId, bob);
        var capability = $"plugin:{wf.PluginId}:{wf.Id}";
        var bobToken = await w.MintAsync(bob, "mcp:read", "mcp:write");
        Assert.Contains(capability, await w.SearchAsync(bobToken, "Doubler"));
        var ran = await w.ExecuteAsync(bobToken, capability, new { n = 4 });
        Assert.False(ran.TryGetProperty("isError", out var e) && e.GetBoolean(), ran.GetRawText());
        Assert.Equal(8, Structured(ran).GetProperty("value").GetProperty("doubled").GetDouble());
        var carol = await w.AddAsync();
        var carolToken = await w.MintAsync(carol, "mcp:read", "mcp:write");
        Assert.DoesNotContain(capability, await w.SearchAsync(carolToken, "Doubler"));
        Assert.Equal("forbidden", (await w.ExecuteAsync(carolToken, capability, new { n = 1 })).ErrorOf() is { Length: > 0 } code ? "forbidden" : "ran");
        var bad = await w.ExecuteAsync(bobToken, capability, new { n = "text" });
        Assert.Equal("invalid_capability_arguments", bad.ErrorOf());
    }

    // ---------- webhooks ----------

    private static string Sign(string secret, string body) => "sha256=" + Convert.ToHexStringLower(System.Security.Cryptography.HMACSHA256.HashData(System.Text.Encoding.UTF8.GetBytes(secret), System.Text.Encoding.UTF8.GetBytes(body)));

    private async Task<(HttpStatusCode Status, string Text)> GithubAsync(string body, string? signature, string? evt = "push", string? delivery = "d-1")
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/v1/webhooks/connectors/github") { Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json") };
        if (signature is not null) request.Headers.Add("x-hub-signature-256", signature);
        if (evt is not null) request.Headers.Add("x-github-event", evt);
        if (delivery is not null) request.Headers.Add("x-github-delivery", delivery);
        var r = await _factory.Plain().SendAsync(request);
        return (r.StatusCode, await r.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task The_github_webhook_checks_the_signature_against_the_raw_body_before_reading_anything()
    {
        const string secret = "gh-secret-for-tests";
        var body = """{"installation":{"id":7},"repository":{"id":1,"full_name":"o/r"},"ref":"refs/heads/main","after":"abc"}""";
        Assert.Equal(HttpStatusCode.Unauthorized, (await GithubAsync(body, null)).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await GithubAsync(body, "sha256=" + new string('0', 64))).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await GithubAsync(body, Sign("another-secret", body))).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await GithubAsync(body, Sign(secret, body + " "))).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await GithubAsync(body, Sign(secret, body)[..^2])).Status);
        var wrongKind = await GithubAsync("not json", Sign("another", "not json"));
        Assert.Equal(HttpStatusCode.Unauthorized, wrongKind.Status);
        Assert.Contains("invalid signature", wrongKind.Text);
        var signed = await GithubAsync(body, Sign(secret, body));
        Assert.Equal(HttpStatusCode.OK, signed.Status);
        Assert.Contains("\"accepted\":false", signed.Text);
        Assert.Contains("event ignored", signed.Text);
    }

    [Theory]
    [InlineData("""{"zen":"x"}""", "ping", "event ignored")]
    [InlineData("""{"zen":"x"}""", "push", "missing installation id")]
    [InlineData("""{"installation":{"id":7},"ref":"refs/heads/main"}""", "push", "missing push metadata")]
    [InlineData("""{"installation":{"id":7},"action":"deleted"}""", "installation", "event ignored")]
    [InlineData("""{"installation":{"id":7},"repository":{"id":1,"full_name":"o/r"},"ref":"refs/heads/main","after":"abc"}""", "push", "event ignored")]
    public async Task A_verified_delivery_is_acknowledged_and_ignored_with_the_reason(string body, string evt, string reason)
    {
        var r = await GithubAsync(body, Sign("gh-secret-for-tests", body), evt);
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Contains($"\"reason\":\"{reason}\"", r.Text);
    }

    [Fact]
    public async Task A_delivery_without_its_event_or_id_headers_and_one_that_is_not_json_are_handled_without_an_error()
    {
        const string secret = "gh-secret-for-tests";
        var body = """{"installation":{"id":7}}""";
        Assert.Contains("event ignored", (await GithubAsync(body, Sign(secret, body), evt: null)).Text);
        Assert.Contains("event ignored", (await GithubAsync(body, Sign(secret, body), delivery: null)).Text);
        var bad = await GithubAsync("{oops", Sign(secret, "{oops"));
        Assert.Equal(HttpStatusCode.BadRequest, bad.Status);
    }

    private async Task<(HttpStatusCode Status, string Text)> StripeAsync(string body, string? header)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/v1/webhooks/stripe") { Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json") };
        if (header is not null) request.Headers.Add("stripe-signature", header);
        var r = await _factory.Plain().SendAsync(request);
        return (r.StatusCode, await r.Content.ReadAsStringAsync());
    }

    private static string StripeHeader(string body, long? at = null, string secret = "whsec_for_tests")
    {
        var t = at ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return $"t={t},v1={Sign(secret, $"{t}.{body}")["sha256=".Length..]}";
    }

    [Fact]
    public async Task The_stripe_webhook_verifies_the_signature_as_stripe_documents_and_acknowledges_the_event()
    {
        var body = """{"id":"evt_1","type":"customer.subscription.updated"}""";
        var ok = await StripeAsync(body, StripeHeader(body));
        Assert.Equal(HttpStatusCode.OK, ok.Status);
        Assert.Contains("\"received\":true", ok.Text);
        Assert.Contains("customer.subscription.updated", ok.Text);
        Assert.Equal("stripe_signature_missing", JsonDocument.Parse((await StripeAsync(body, null)).Text).RootElement.S("error"));
        Assert.Equal(HttpStatusCode.BadRequest, (await StripeAsync(body, StripeHeader(body, secret: "whsec_other"))).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await StripeAsync(body, StripeHeader(body + "x"))).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await StripeAsync(body, "garbage")).Status);
        var old = await StripeAsync(body, StripeHeader(body, DateTimeOffset.UtcNow.AddMinutes(-10).ToUnixTimeSeconds()));
        Assert.Equal(HttpStatusCode.BadRequest, old.Status);
        Assert.Contains("tolerance", old.Text);
    }

    // ---------- the removed Memory Bank and direct uploads ----------

    [Fact]
    public async Task The_memory_routes_keep_answering_in_the_shapes_desktop_builds_tolerate_and_store_nothing()
    {
        var w = await Workspace.CreateAsync(_factory, "Memory");
        var list = await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/memory");
        Assert.Equal(HttpStatusCode.OK, list.Status);
        Assert.Equal(0, list.Body.GetProperty("memories").GetArrayLength());
        Assert.Equal(0, (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/memory/search?q=x")).Body.GetProperty("results").GetArrayLength());
        var gone = await w.CallAsync(w.Owner, HttpMethod.Delete, "/v1/memory/mem_1");
        Assert.Equal(HttpStatusCode.NotFound, gone.Status);
        Assert.Equal("memory_not_found", gone.Err());
        var post = await w.Http.PostAsJsonAsync("/v1/memory", new { text = "remember" });
        Assert.Equal(HttpStatusCode.Gone, post.StatusCode);
        var body = await ReadJsonAsync(post);
        Assert.Equal("deprecated", body.S("error"));
        Assert.Contains("Memory Bank feature has been removed", body.S("message"));
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Http.GetAsync("/v1/memory")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Http.DeleteAsync("/v1/memory/x")).StatusCode);
    }

    [Fact]
    public async Task Direct_uploads_need_a_bearer_token_and_then_say_they_are_not_offered_here()
    {
        var w = await Workspace.CreateAsync(_factory, "Uploads");
        foreach (var path in new[] { "/v1/direct-uploads/google-workspace/drive-files", "/v1/direct-uploads/google-workspace/gmail-drafts", "/v1/direct-uploads/microsoft-365/mail-drafts", "/v1/direct-uploads/microsoft-365/drive-upload-sessions" })
        {
            var anonymous = await w.Http.PostAsJsonAsync(path, new { });
            Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
            Assert.Equal("missing_mcp_token", (await ReadJsonAsync(anonymous)).S("error"));
            var token = await w.MintAsync(w.Owner, "mcp:read", "mcp:write");
            var authed = await w.Http.SendAsync(Bearer(HttpMethod.Post, path, token, new { }));
            Assert.Equal(HttpStatusCode.NotImplemented, authed.StatusCode);
        }
        var token2 = await w.MintAsync(w.Owner, "mcp:read");
        Assert.Equal(HttpStatusCode.NotImplemented, (await w.Http.SendAsync(Bearer(HttpMethod.Put, "/v1/direct-uploads/microsoft-365/drive-upload-sessions/content", token2))).StatusCode);
        Assert.Equal(HttpStatusCode.NotImplemented, (await w.Http.SendAsync(Bearer(HttpMethod.Get, "/v1/direct-uploads/microsoft-365/drive-upload-sessions/content", token2))).StatusCode);
    }
}
