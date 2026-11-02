using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Automations;
using WorkAI360.Api.Features.Automations;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>Leases are short here so expiry can be tested with real time; the scheduler loop is off, so tests tick it themselves.</summary>
public class AutomationFactory : ApiFactory
{
    public const int LeaseMs = 1500;

    protected override IEnumerable<KeyValuePair<string, string>> Settings =>
    [
        new("Automations:SchedulerEnabled", "false"), new("Automations:LeaseMs", LeaseMs.ToString()),
        new("Policy:HeadlessRunnerConfigured", "true"),
    ];

    public async Task<List<string>> TickAsync(long? now = null)
    {
        using var scope = Services.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<AutomationTicker>().TickAsync(now);
    }
}

/// <summary>A deployment with a cloud runtime and the schedule features on.</summary>
public sealed class CloudAutomationFactory : AutomationFactory
{
    protected override IEnumerable<KeyValuePair<string, string>> Settings => base.Settings.Concat(
    [
        new("Features:Overrides:automationIntervalSchedules", "true"), new("Features:Overrides:automationCalendarTriggers", "true"),
    ]);

    protected override void ConfigureWebHost(Microsoft.AspNetCore.Hosting.IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureServices(s =>
        {
            s.RemoveAll<ICloudAutomationRuntime>();
            s.AddSingleton<ICloudAutomationRuntime, AvailableRuntime>();
        });
    }

    private sealed class AvailableRuntime : ICloudAutomationRuntime
    {
        public Task<bool> AgentAvailableAsync(string organizationId, string ownerMemberId) => Task.FromResult(true);
    }
}

public sealed class AutomationTests : IClassFixture<AutomationFactory>
{
    private readonly AutomationFactory _factory;
    public AutomationTests(AutomationFactory factory) => _factory = factory;

    private static readonly object Daily9 = new { kind = "daily", timezone = "UTC", hour = 9, minute = 0 };

    private static object Body(object? schedule = null, object? model = null, string name = "Daily report") =>
        new { name, instructions = "Summarize the inbox", schedule = schedule ?? Daily9, model = model ?? new { providerId = "anthropic", modelId = "claude" } };

    private static async Task<JsonElement> OkAsync(Workspace w, Person p, HttpMethod m, string url, object? body = null, int expected = 200)
    {
        var r = await w.CallAsync(p, m, url, body);
        Assert.True((int)r.Status == expected, $"{m} {url}: {(int)r.Status} {r.Body}");
        return r.Body;
    }

    private static async Task<string> CreateAsync(Workspace w, Person p, object? body = null) =>
        (await OkAsync(w, p, HttpMethod.Post, "/v1/automations", body ?? Body(), 201)).GetProperty("automation").GetProperty("id").GetString()!;

    /// <summary>A desktop runner: its credential, and calls signed with it.</summary>
    private sealed class Runner(Workspace w, string token)
    {
        public string Token { get; } = token;

        public static async Task<Runner> RegisterAsync(Workspace w, Person p, string install, string[]? capabilities = null)
        {
            var r = await w.CallAsync(p, HttpMethod.Post, "/v1/automation-runners/token", new
            {
                runnerId = install, protocolVersion = 1, supportedExecutionTargets = new[] { "desktop" }, capabilities = capabilities ?? ["model_attention_v1"],
                appVersion = "1.0.0", platform = "linux", concurrency = 1,
            });
            Assert.True(r.Status == HttpStatusCode.OK, r.Body.ToString());
            return new Runner(w, r.Body.GetProperty("token").GetString()!);
        }

        public async Task<(HttpStatusCode Status, JsonElement Body)> CallAsync(HttpMethod method, string url, object? body = null)
        {
            var r = await w.SendAsync(Bearer(method, url, Token, body));
            var text = await r.Content.ReadAsStringAsync();
            return (r.StatusCode, string.IsNullOrEmpty(text) ? default : JsonDocument.Parse(text).RootElement.Clone());
        }

        public async Task<JsonElement?> ClaimAsync(string runId)
        {
            var r = await CallAsync(HttpMethod.Post, $"/v1/automation-runs/{runId}/claim");
            Assert.Equal(HttpStatusCode.OK, r.Status);
            var a = r.Body.GetProperty("assignment");
            return a.ValueKind == JsonValueKind.Null ? null : a;
        }

        public Task<(HttpStatusCode Status, JsonElement Body)> HeartbeatAsync(string runId, int attempt = 1) => CallAsync(HttpMethod.Post, $"/v1/automation-runs/{runId}/heartbeat", new { attempt });

        public Task<(HttpStatusCode Status, JsonElement Body)> EventAsync(string runId, int sequence, int attempt = 1) =>
            CallAsync(HttpMethod.Post, $"/v1/automation-runs/{runId}/events", new { attempt, sequence, type = "assistant", payload = new { text = $"step {sequence}" }, createdAt = 1 });

        public Task<(HttpStatusCode Status, JsonElement Body)> CompleteAsync(string runId, string status = "succeeded", int attempt = 1, object? error = null) =>
            CallAsync(HttpMethod.Post, $"/v1/automation-runs/{runId}/complete", new
            {
                attempt, status, sessionId = "session-1", workspaceId = "ws-1", resultSummary = "Done", usage = new { inputTokens = 1, outputTokens = 2, costMicros = (int?)null }, error,
            });
    }

    private static async Task<string> RunNowAsync(Workspace w, Person p, string id, object? body = null) =>
        (await OkAsync(w, p, HttpMethod.Post, $"/v1/automations/{id}/run", body ?? new { }, 202)).GetProperty("run").GetProperty("id").GetString()!;

    private T Db<T>(Func<DenDbContext, T> read) => _factory.WithDb(read);

    private AutomationRun RunRow(string id) => Db(db => db.Set<AutomationRun>().AsNoTracking().First(r => r.Id == id));

    // ---------------------------------------------------------------- creating and ownership

    [Fact]
    public async Task Automations_belong_to_their_owner_alone_and_never_cross_workspaces()
    {
        var w = await Workspace.CreateAsync(_factory);
        var member = await w.AddAsync();
        var admin = await w.AddAsync("admin");
        var id = await CreateAsync(w, w.Owner);
        var runId = await RunNowAsync(w, w.Owner, id);
        foreach (var other in new[] { member, admin })
        {
            Assert.Empty((await OkAsync(w, other, HttpMethod.Get, "/v1/automations")).GetProperty("items").EnumerateArray());
            foreach (var (method, url) in new[]
            {
                (HttpMethod.Get, $"/v1/automations/{id}"), (HttpMethod.Patch, $"/v1/automations/{id}"), (HttpMethod.Post, $"/v1/automations/{id}/activate"),
                (HttpMethod.Post, $"/v1/automations/{id}/deactivate"), (HttpMethod.Post, $"/v1/automations/{id}/run"), (HttpMethod.Delete, $"/v1/automations/{id}"),
            })
            {
                var r = await w.CallAsync(other, method, url, method == HttpMethod.Patch ? new { name = "x" } : null);
                Assert.True(r.Status == HttpStatusCode.NotFound && r.Error() == "automation_not_found", $"{method} {url}: {r.Status} {r.Body}");
            }
            Assert.Equal("automation_run_not_found", (await w.CallAsync(other, HttpMethod.Get, $"/v1/automation-runs/{runId}")).Error());
            Assert.Equal("automation_run_not_found", (await w.CallAsync(other, HttpMethod.Post, $"/v1/automation-runs/{runId}/cancel")).Error());
            Assert.Empty((await OkAsync(w, other, HttpMethod.Get, $"/v1/automations/{id}/runs")).GetProperty("items").EnumerateArray());
        }
        // Another workspace's owner cannot reach it even by naming this workspace's id in their own.
        var elsewhere = await Workspace.CreateAsync(_factory, "Elsewhere");
        Assert.Equal(HttpStatusCode.NotFound, (await elsewhere.CallAsync(elsewhere.Owner, HttpMethod.Get, $"/v1/automations/{id}")).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await elsewhere.CallAsync(elsewhere.Owner, HttpMethod.Get, $"/v1/automation-runs/{runId}")).Status);
        Assert.Empty((await OkAsync(elsewhere, elsewhere.Owner, HttpMethod.Get, "/v1/automations")).GetProperty("items").EnumerateArray());
        // The owner still has theirs, and so does everyone else their own.
        Assert.Single((await OkAsync(w, w.Owner, HttpMethod.Get, "/v1/automations")).GetProperty("items").EnumerateArray());
        await CreateAsync(w, member);
        Assert.Single((await OkAsync(w, member, HttpMethod.Get, "/v1/automations")).GetProperty("items").EnumerateArray());
    }

    [Fact]
    public async Task Signed_out_requests_are_refused()
    {
        var w = await Workspace.CreateAsync(_factory);
        foreach (var url in new[] { "/v1/automations", "/v1/automation-runs?from=0&to=1", "/v1/automation-runners", "/v1/automation-runners/presence" })
            Assert.Equal(HttpStatusCode.Unauthorized, (await w.Http.GetAsync(url)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Http.PostAsJsonAsync("/v1/automations", Body())).StatusCode);
    }

    [Fact]
    public async Task Creating_validates_the_request_and_stores_the_first_revision()
    {
        var w = await Workspace.CreateAsync(_factory);
        async Task<(HttpStatusCode Status, JsonElement Body)> Post(object body) => await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/automations", body);
        Assert.Equal("invalid_request", (await Post(new { name = "" })).Error());
        Assert.Equal("schedule.timezone: Expected a valid IANA timezone", (await Post(Body(new { kind = "daily", timezone = "Nope/Zone", hour = 9, minute = 0 }))).Message());
        Assert.Equal("name: Too small: expected string to have >=1 characters", (await Post(Body(name: " "))).Message());
        Assert.Equal("name: Too big: expected string to have <=120 characters", (await Post(Body(name: new string('x', 121)))).Message());
        Assert.Equal("model.providerId: Invalid input: expected string, received undefined", (await Post(new { name = "n", instructions = "i", schedule = Daily9, model = new { modelId = "m" } })).Message());
        Assert.Equal("instructions: Too small: expected string to have >=1 characters", (await Post(new { name = "n", instructions = " ", schedule = Daily9, model = new { providerId = "a", modelId = "m" } })).Message());
        Assert.Equal(HttpStatusCode.BadRequest, (await Post(new { name = "n" })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.Http.SendAsync(w.As(w.Owner, HttpMethod.Post, "/v1/automations"))).StatusCode);

        var created = await OkAsync(w, w.Owner, HttpMethod.Post, "/v1/automations", Body(model: new { providerId = "anthropic", modelId = "claude", variant = "high" }), 201);
        Assert.Equal("active", created.GetProperty("automation").GetProperty("state").GetString());
        Assert.Equal(JsonValueKind.Null, created.GetProperty("latestRun").ValueKind);
        var revision = created.GetProperty("revision");
        Assert.Equal(1, revision.GetProperty("version").GetInt32());
        Assert.Equal("desktop", revision.GetProperty("executionTarget").GetString());
        Assert.Equal(900_000, revision.GetProperty("maximumRuntimeMs").GetInt32());
        Assert.Equal("high", revision.GetProperty("model").GetProperty("variant").GetString());
        Assert.Equal("agent", revision.GetProperty("action").GetProperty("kind").GetString());
        var next = created.GetProperty("automation").GetProperty("nextDueAt").GetInt64();
        Assert.Equal(9, DateTimeOffset.FromUnixTimeMilliseconds(next).Hour);
        Assert.True(next > AutomationService.Now());
        // Its owner is the creator, in this workspace.
        Assert.Equal(w.Owner.MemberId, created.GetProperty("automation").GetProperty("ownerMemberId").GetString());
        Assert.Equal(w.OrgId, created.GetProperty("automation").GetProperty("organizationId").GetString());
    }

    [Fact]
    public async Task Models_this_build_cannot_reach_are_refused_and_the_free_model_depends_on_the_client()
    {
        var w = await Workspace.CreateAsync(_factory);
        async Task<(HttpStatusCode Status, JsonElement Body)> Post(object model, bool attention = false)
        {
            var request = w.As(w.Owner, HttpMethod.Post, "/v1/automations", Body(model: model));
            if (attention) request.Headers.Add("x-openwork-automation-model-attention", "model_attention_v1");
            var r = await w.SendAsync(request);
            return (r.StatusCode, JsonDocument.Parse(await r.Content.ReadAsStringAsync()).RootElement.Clone());
        }
        Assert.Equal("provider_unavailable", (await Post(new { providerId = "lpr_01h2xcejqtf2nbrexx3vqjhp41", modelId = "x" })).Error());
        Assert.Equal("model_access_lost", (await Post(new { providerId = "openwork", modelId = "x" })).Error());
        Assert.Equal("model_access_lost", (await Post(new { providerId = "openwork-cloud", modelId = "default" })).Error());
        Assert.Equal(HttpStatusCode.Created, (await Post(new { providerId = "opencode", modelId = "big-pickle" })).Status);
        Assert.Equal("model_access_lost", (await Post(new { providerId = "opencode", modelId = "big-pickle" }, attention: true)).Error());
        Assert.Equal(HttpStatusCode.Created, (await Post(new { providerId = "ollama", modelId = "llama" }, attention: true)).Status);
    }

    [Fact]
    public async Task A_model_that_stopped_working_pauses_the_Automation_when_a_modern_client_reads_it()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await CreateAsync(w, w.Owner, Body(model: new { providerId = "opencode", modelId = "big-pickle" }));
        Assert.Equal("active", (await OkAsync(w, w.Owner, HttpMethod.Get, $"/v1/automations/{id}")).GetProperty("automation").GetProperty("state").GetString());
        var request = w.As(w.Owner, HttpMethod.Get, "/v1/automations");
        request.Headers.Add("x-openwork-automation-model-attention", "model_attention_v1");
        var list = JsonDocument.Parse(await (await w.SendAsync(request)).Content.ReadAsStringAsync()).RootElement;
        var automation = list.GetProperty("items")[0].GetProperty("automation");
        Assert.Equal("needs_attention", automation.GetProperty("state").GetString());
        Assert.Equal("model_access_lost", automation.GetProperty("needsAttentionReason").GetProperty("code").GetString());
        Assert.Equal(JsonValueKind.Null, automation.GetProperty("nextDueAt").ValueKind);
        // A manual run of a paused Automation is recorded as skipped with the reason, not run.
        var run = (await OkAsync(w, w.Owner, HttpMethod.Post, $"/v1/automations/{id}/run", new { }, 202)).GetProperty("run");
        Assert.Equal("skipped", run.GetProperty("status").GetString());
        Assert.Equal("model_access_lost", run.GetProperty("error").GetProperty("code").GetString());
    }

    [Fact]
    public async Task Schedules_are_stored_normalized_and_next_run_times_are_computed()
    {
        var w = await Workspace.CreateAsync(_factory);
        var weekly = await OkAsync(w, w.Owner, HttpMethod.Post, "/v1/automations", Body(new { kind = "weekly", timezone = "Europe/Paris", daysOfWeek = new[] { 3, 1, 3 }, hour = 7, minute = 30 }), 201);
        Assert.Equal("[1,3]", weekly.GetProperty("revision").GetProperty("schedule").GetProperty("daysOfWeek").GetRawText().Replace(" ", ""));
        var past = await OkAsync(w, w.Owner, HttpMethod.Post, "/v1/automations", Body(new { kind = "once", timezone = "UTC", at = 1000 }), 201);
        Assert.Equal(JsonValueKind.Null, past.GetProperty("automation").GetProperty("nextDueAt").ValueKind);
        var at = AutomationService.Now() + 3 * 86_400_000L;
        var future = await OkAsync(w, w.Owner, HttpMethod.Post, "/v1/automations", Body(new { kind = "once", timezone = "UTC", at }), 201);
        Assert.Equal(at, future.GetProperty("automation").GetProperty("nextDueAt").GetInt64());
        // Interval and calendar schedules need their features and are off by default.
        Assert.Equal("automation_interval_schedule_disabled", (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/automations", Body(new { kind = "interval", timezone = "UTC", everyHours = 3 }))).Error());
        Assert.Equal("automation_calendar_trigger_cloud_only", (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/automations", Body(new { kind = "calendar", timezone = "UTC", edge = "start", offsetMinutes = 0 }))).Error());
    }

    // ---------------------------------------------------------------- changing

    [Fact]
    public async Task A_behavior_change_makes_a_new_revision_and_a_rename_or_repeat_does_not()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await CreateAsync(w, w.Owner);
        var renamed = await OkAsync(w, w.Owner, HttpMethod.Patch, $"/v1/automations/{id}", new { name = "Renamed" });
        Assert.Equal("Renamed", renamed.GetProperty("automation").GetProperty("name").GetString());
        Assert.Equal(1, renamed.GetProperty("revision").GetProperty("version").GetInt32());
        var changed = await OkAsync(w, w.Owner, HttpMethod.Patch, $"/v1/automations/{id}", new { instructions = "New", schedule = new { kind = "daily", timezone = "UTC", hour = 10, minute = 0 } });
        Assert.Equal(2, changed.GetProperty("revision").GetProperty("version").GetInt32());
        Assert.Equal("New", changed.GetProperty("revision").GetProperty("instructions").GetString());
        Assert.Equal(changed.GetProperty("revision").GetProperty("id").GetString(), changed.GetProperty("automation").GetProperty("currentRevisionId").GetString());
        Assert.Equal(10, DateTimeOffset.FromUnixTimeMilliseconds(changed.GetProperty("automation").GetProperty("nextDueAt").GetInt64()).Hour);
        var same = await OkAsync(w, w.Owner, HttpMethod.Patch, $"/v1/automations/{id}", new { instructions = "New" });
        Assert.Equal(2, same.GetProperty("revision").GetProperty("version").GetInt32());
        // The first revision is still stored: runs name the revision they ran.
        Assert.Equal(2, Db(db => db.Set<AutomationRevision>().Count(r => r.AutomationId == id)));
        // A model change is a behavior change too; the instructions stay.
        var model = await OkAsync(w, w.Owner, HttpMethod.Patch, $"/v1/automations/{id}", new { model = new { providerId = "anthropic", modelId = "other" } });
        Assert.Equal(3, model.GetProperty("revision").GetProperty("version").GetInt32());
        Assert.Equal("New", model.GetProperty("revision").GetProperty("instructions").GetString());
    }

    [Fact]
    public async Task Changes_are_validated()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await CreateAsync(w, w.Owner);
        Assert.Equal("At least one behavior-changing field is required", (await w.CallAsync(w.Owner, HttpMethod.Patch, $"/v1/automations/{id}", new { })).Message());
        Assert.Equal("Unrecognized key: \"nope\"", (await w.CallAsync(w.Owner, HttpMethod.Patch, $"/v1/automations/{id}", new { nope = 1 })).Message());
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Patch, $"/v1/automations/{id}", new { schedule = new { kind = "daily", timezone = "UTC", hour = 99, minute = 0 } })).Status);
        Assert.Equal("automation_calendar_trigger_cloud_only", (await w.CallAsync(w.Owner, HttpMethod.Patch, $"/v1/automations/{id}", new { schedule = new { kind = "calendar", timezone = "UTC", edge = "end", offsetMinutes = 0 } })).Error());
        // Moving to the cloud needs what creating a cloud Automation needs: here a runtime that does not exist.
        Assert.Equal("automation_cloud_worker_required", (await w.CallAsync(w.Owner, HttpMethod.Patch, $"/v1/automations/{id}", new { executionTarget = "cloud" })).Error());
        Assert.Equal("automation_cloud_worker_required", (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/automations/{id}/run", new { executionTarget = "cloud" })).Error());
    }

    [Fact]
    public async Task Deactivating_activating_and_archiving_move_the_schedule_and_archived_ones_stay_readable()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await CreateAsync(w, w.Owner);
        var off = (await OkAsync(w, w.Owner, HttpMethod.Post, $"/v1/automations/{id}/deactivate")).GetProperty("automation");
        Assert.Equal("inactive", off.GetProperty("state").GetString());
        Assert.Equal(JsonValueKind.Null, off.GetProperty("nextDueAt").ValueKind);
        var on = (await OkAsync(w, w.Owner, HttpMethod.Post, $"/v1/automations/{id}/activate")).GetProperty("automation");
        Assert.Equal("active", on.GetProperty("state").GetString());
        Assert.True(on.GetProperty("nextDueAt").GetInt64() > AutomationService.Now());
        // An inactive Automation can still be run by hand; an archived one cannot be changed or run.
        await OkAsync(w, w.Owner, HttpMethod.Post, $"/v1/automations/{id}/deactivate");
        await RunNowAsync(w, w.Owner, id);
        var archived = (await OkAsync(w, w.Owner, HttpMethod.Delete, $"/v1/automations/{id}")).GetProperty("automation");
        Assert.Equal("archived", archived.GetProperty("state").GetString());
        Assert.True(archived.GetProperty("archivedAt").GetInt64() > 0);
        Assert.Equal(HttpStatusCode.NotFound, (await w.CallAsync(w.Owner, HttpMethod.Patch, $"/v1/automations/{id}", new { name = "x" })).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/automations/{id}/run", new { })).Status);
        Assert.Single((await OkAsync(w, w.Owner, HttpMethod.Get, $"/v1/automations/{id}/runs")).GetProperty("items").EnumerateArray());
        Assert.Equal("archived", (await OkAsync(w, w.Owner, HttpMethod.Get, $"/v1/automations/{id}")).GetProperty("automation").GetProperty("state").GetString());
    }

    [Fact]
    public async Task The_organizations_switches_decide_what_can_be_created_run_and_claimed()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await CreateAsync(w, w.Owner);
        var runner = await Runner.RegisterAsync(w, w.Owner, "install-switch-1");
        var runId = await RunNowAsync(w, w.Owner, id);
        await OkAsync(w, w.Owner, HttpMethod.Put, "/v1/org/automation-settings", new { desktop = false });
        Assert.Equal("automation_desktop_disabled", (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/automations", Body())).Error());
        Assert.Equal("automation_desktop_disabled", (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/automations/{id}/run", new { })).Error());
        // The desktop is told there is no work and cannot claim what was already queued.
        Assert.Empty((await runner.CallAsync(HttpMethod.Get, "/v1/automation-runner/work")).Body.GetProperty("items").EnumerateArray());
        Assert.Null(await runner.ClaimAsync(runId));
        await OkAsync(w, w.Owner, HttpMethod.Put, "/v1/org/automation-settings", new { desktop = true });
        Assert.NotNull(await runner.ClaimAsync(runId));
    }

    [Fact]
    public async Task Cloud_Automations_answer_like_the_reference_when_no_cloud_runtime_exists()
    {
        var w = await Workspace.CreateAsync(_factory);
        var cloud = new { name = "c", schedule = Daily9, action = new { kind = "agent", instructions = "x", model = new { providerId = "openwork-cloud", modelId = "default" } } };
        Assert.Equal("automation_cloud_worker_required", (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/cloud-automations", cloud)).Error());
        Assert.Equal("automation_cloud_worker_required", (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/automations", new { cloud.name, cloud.schedule, cloud.action, executionTarget = "cloud" })).Error());
        await OkAsync(w, w.Owner, HttpMethod.Put, "/v1/org/automation-settings", new { cloud = false });
        Assert.Equal("automation_cloud_disabled", (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/cloud-automations", cloud)).Error());
        Assert.Equal("Unrecognized key: \"executionTarget\"", (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/cloud-automations", new { cloud.name, cloud.schedule, cloud.action, executionTarget = "desktop" })).Message());
        // Workflows (saved scripts) are not built: they answer as an unavailable version.
        var workflow = new { name = "w", schedule = Daily9, action = new { kind = "saved_script", script = new { pluginId = "p", configObjectId = "c", configObjectVersionId = "v" } } };
        await OkAsync(w, w.Owner, HttpMethod.Put, "/v1/org/automation-settings", new { cloud = true });
        Assert.Equal("automation_saved_script_version_not_found", (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/cloud-automations", workflow)).Error());
        // The execution targets say the cloud is not available.
        var targets = await OkAsync(w, w.Owner, HttpMethod.Get, "/v1/automation-runners");
        var item = targets.GetProperty("items").EnumerateArray().Single(i => i.GetProperty("kind").GetString() == "cloud");
        Assert.False(item.GetProperty("available").GetBoolean());
    }

    // ---------------------------------------------------------------- runs

    [Fact]
    public async Task Run_now_queues_one_run_and_overlapping_ones_are_skipped()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await CreateAsync(w, w.Owner);
        var first = (await OkAsync(w, w.Owner, HttpMethod.Post, $"/v1/automations/{id}/run", null, 202)).GetProperty("run");
        Assert.Equal("queued", first.GetProperty("status").GetString());
        Assert.Equal("manual", first.GetProperty("trigger").GetString());
        Assert.Equal(0, first.GetProperty("attemptCount").GetInt32());
        var second = (await OkAsync(w, w.Owner, HttpMethod.Post, $"/v1/automations/{id}/run", new { }, 202)).GetProperty("run");
        Assert.Equal("skipped", second.GetProperty("status").GetString());
        Assert.Equal("Skipped because another occurrence is already active.", second.GetProperty("resultSummary").GetString());
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/automations/{id}/run", new { executionTarget = "mars" })).Status);
        var runs = (await OkAsync(w, w.Owner, HttpMethod.Get, $"/v1/automations/{id}/runs")).GetProperty("items");
        Assert.Equal(2, runs.GetArrayLength());
        Assert.Equal("skipped", runs[0].GetProperty("status").GetString());   // newest first
        var latest = (await OkAsync(w, w.Owner, HttpMethod.Get, $"/v1/automations/{id}")).GetProperty("latestRun");
        Assert.Equal(runs[0].GetProperty("id").GetString(), latest.GetProperty("id").GetString());
    }

    [Fact]
    public async Task Run_history_pages_and_the_calendar_range_filters_by_time()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await CreateAsync(w, w.Owner);
        for (var i = 0; i < 3; i++) await RunNowAsync(w, w.Owner, id);
        var p1 = await OkAsync(w, w.Owner, HttpMethod.Get, $"/v1/automations/{id}/runs?limit=2");
        Assert.Equal(2, p1.GetProperty("items").GetArrayLength());
        var cursor = p1.GetProperty("nextCursor").GetString();
        var p2 = await OkAsync(w, w.Owner, HttpMethod.Get, $"/v1/automations/{id}/runs?limit=2&cursor={cursor}");
        Assert.Equal(1, p2.GetProperty("items").GetArrayLength());
        Assert.Equal(JsonValueKind.Null, p2.GetProperty("nextCursor").ValueKind);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/automations/{id}/runs?limit=0")).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/automations?limit=101")).Status);

        var now = AutomationService.Now();
        Assert.Equal(3, (await OkAsync(w, w.Owner, HttpMethod.Get, $"/v1/automation-runs?from={now - 60_000}&to={now + 60_000}")).GetProperty("items").GetArrayLength());
        Assert.Empty((await OkAsync(w, w.Owner, HttpMethod.Get, "/v1/automation-runs?from=0&to=1000")).GetProperty("items").EnumerateArray());
        Assert.Equal("to: The range may cover at most 45 days", (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/automation-runs?from=0&to={46 * 86_400_000L}")).Message());
        Assert.Equal("to: to must be after from", (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/automation-runs?from=2000&to=1000")).Message());
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/automation-runs")).Status);
        // Someone else's range shows nothing of this person's runs.
        var member = await w.AddAsync();
        Assert.Empty((await OkAsync(w, member, HttpMethod.Get, $"/v1/automation-runs?from={now - 60_000}&to={now + 60_000}")).GetProperty("items").EnumerateArray());
    }

    [Fact]
    public async Task Cancelling_a_queued_run_ends_it_and_a_running_one_is_told_on_its_next_heartbeat()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await CreateAsync(w, w.Owner);
        var runner = await Runner.RegisterAsync(w, w.Owner, "install-cancel-1");
        var queued = await RunNowAsync(w, w.Owner, id);
        var cancelled = (await OkAsync(w, w.Owner, HttpMethod.Post, $"/v1/automation-runs/{queued}/cancel")).GetProperty("run");
        Assert.Equal("cancelled", cancelled.GetProperty("status").GetString());
        Assert.True(cancelled.GetProperty("finishedAt").GetInt64() > 0);
        Assert.Null(await runner.ClaimAsync(queued));   // a cancelled run is no longer claimable

        var running = await RunNowAsync(w, w.Owner, id);
        Assert.NotNull(await runner.ClaimAsync(running));
        var asked = (await OkAsync(w, w.Owner, HttpMethod.Post, $"/v1/automation-runs/{running}/cancel")).GetProperty("run");
        Assert.Equal("running", asked.GetProperty("status").GetString());
        var beat = await runner.HeartbeatAsync(running);
        Assert.True(beat.Body.GetProperty("cancelRequested").GetBoolean());
        var done = await runner.CompleteAsync(running, "cancelled");
        Assert.Equal("cancelled", done.Body.GetProperty("run").GetProperty("status").GetString());
    }

    // ---------------------------------------------------------------- the runner protocol

    [Fact]
    public async Task Runner_credentials_are_checked_on_every_call()
    {
        var w = await Workspace.CreateAsync(_factory);
        var member = await w.AddAsync();
        var id = await CreateAsync(w, w.Owner);
        var runId = await RunNowAsync(w, w.Owner, id);
        var runner = await Runner.RegisterAsync(w, w.Owner, "install-auth-1");
        async Task<HttpStatusCode> With(string? token, HttpMethod method, string url, object? body = null)
        {
            var request = new HttpRequestMessage(method, url);
            if (token is not null) request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
            if (body is not null) request.Content = System.Net.Http.Json.JsonContent.Create(body);
            return (await w.SendAsync(request)).StatusCode;
        }
        Assert.Equal(HttpStatusCode.Unauthorized, await With(null, HttpMethod.Get, "/v1/automation-runner/work"));
        Assert.Equal(HttpStatusCode.Unauthorized, await With("not.a.token", HttpMethod.Get, "/v1/automation-runner/work"));
        Assert.Equal(HttpStatusCode.Unauthorized, await With(runner.Token[..^3] + "xyz", HttpMethod.Post, $"/v1/automation-runs/{runId}/claim"));
        Assert.Equal(HttpStatusCode.Unauthorized, await With(w.Owner.Token, HttpMethod.Get, "/v1/automation-runner/work"));   // a session is not a runner credential
        Assert.Equal(HttpStatusCode.OK, await With(runner.Token, HttpMethod.Get, "/v1/automation-runner/work"));
        // The token of someone else's desktop sees nothing of this owner's runs.
        var theirs = await Runner.RegisterAsync(w, member, "install-auth-2");
        Assert.Empty((await theirs.CallAsync(HttpMethod.Get, "/v1/automation-runner/work")).Body.GetProperty("items").EnumerateArray());
        Assert.Null(await theirs.ClaimAsync(runId));
        // Registration is validated.
        var bad = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/automation-runners/token", new { runnerId = "short", protocolVersion = 1, supportedExecutionTargets = new[] { "desktop" }, appVersion = "1", platform = "linux", concurrency = 1 });
        Assert.Equal(HttpStatusCode.BadRequest, bad.Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/automation-runners/token", new { runnerId = "runner-12345678", protocolVersion = 1, supportedExecutionTargets = new[] { "desktop" }, appVersion = "1", platform = "amiga", concurrency = 1 })).Status);
    }

    [Fact]
    public async Task A_runner_token_stops_working_when_its_person_leaves()
    {
        var w = await Workspace.CreateAsync(_factory);
        var member = await w.AddAsync();
        var runner = await Runner.RegisterAsync(w, member, "install-leaves-1");
        Assert.Equal(HttpStatusCode.OK, (await runner.CallAsync(HttpMethod.Get, "/v1/automation-runner/work")).Status);
        await OkAsync(w, w.Owner, HttpMethod.Delete, $"/v1/members/{member.MemberId}", null, 204);
        Assert.Equal(HttpStatusCode.Unauthorized, (await runner.CallAsync(HttpMethod.Get, "/v1/automation-runner/work")).Status);
    }

    [Fact]
    public async Task Presence_follows_registration_and_work_polls()
    {
        var w = await Workspace.CreateAsync(_factory);
        var member = await w.AddAsync();
        var none = await OkAsync(w, w.Owner, HttpMethod.Get, "/v1/automation-runners/presence");
        Assert.False(none.GetProperty("connected").GetBoolean());
        Assert.Equal(JsonValueKind.Null, none.GetProperty("lastSeenAt").ValueKind);
        await Runner.RegisterAsync(w, w.Owner, "install-presence-1");
        var seen = await OkAsync(w, w.Owner, HttpMethod.Get, "/v1/automation-runners/presence");
        Assert.True(seen.GetProperty("connected").GetBoolean());
        Assert.True(seen.GetProperty("lastSeenAt").GetInt64() > AutomationService.Now() - 60_000);
        // Presence is per person, and a session-only runner (remote sessions) is not an Automation desktop.
        Assert.False((await OkAsync(w, member, HttpMethod.Get, "/v1/automation-runners/presence")).GetProperty("connected").GetBoolean());
        await Runner.RegisterAsync(w, member, "install-presence-2", ["remote_session_only_v1"]);
        Assert.False((await OkAsync(w, member, HttpMethod.Get, "/v1/automation-runners/presence")).GetProperty("connected").GetBoolean());
        var items = (await OkAsync(w, w.Owner, HttpMethod.Get, "/v1/automation-runners")).GetProperty("items").EnumerateArray().ToList();
        Assert.Single(items, i => i.GetProperty("kind").GetString() == "desktop");
        Assert.StartsWith("rnr_", items[0].GetProperty("id").GetString());
        // Registering the same install again is one desktop, not two.
        await Runner.RegisterAsync(w, w.Owner, "install-presence-1");
        Assert.Equal(1, (await OkAsync(w, w.Owner, HttpMethod.Get, "/v1/automation-runners")).GetProperty("items").EnumerateArray().Count(i => i.GetProperty("kind").GetString() == "desktop"));
    }

    [Fact]
    public async Task A_run_goes_from_claim_to_a_final_result_with_its_events_in_order()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await CreateAsync(w, w.Owner, new { name = "Pinned", instructions = "Do it", schedule = Daily9, model = new { providerId = "anthropic", modelId = "claude" }, workspaceId = "ws-pinned" });
        var runner = await Runner.RegisterAsync(w, w.Owner, "install-flow-1");
        var runId = await RunNowAsync(w, w.Owner, id);
        var items = (await runner.CallAsync(HttpMethod.Get, "/v1/automation-runner/work")).Body;
        Assert.Equal(runId, items.GetProperty("items")[0].GetProperty("runId").GetString());
        Assert.Equal("ws-pinned", items.GetProperty("items")[0].GetProperty("workspaceId").GetString());
        var assignment = (await runner.ClaimAsync(runId))!.Value;
        Assert.Equal("Do it", assignment.GetProperty("instructions").GetString());
        Assert.Equal(1, assignment.GetProperty("attempt").GetInt32());
        Assert.Equal("ws-pinned", assignment.GetProperty("workspaceId").GetString());
        Assert.Equal(900_000, assignment.GetProperty("timeoutMs").GetInt32());
        // Claimed work is no longer offered.
        Assert.Empty((await runner.CallAsync(HttpMethod.Get, "/v1/automation-runner/work")).Body.GetProperty("items").EnumerateArray());
        for (var i = 1; i <= 3; i++) Assert.Equal(HttpStatusCode.OK, (await runner.EventAsync(runId, i)).Status);
        var done = await runner.CompleteAsync(runId);
        var run = done.Body.GetProperty("run");
        Assert.Equal("succeeded", run.GetProperty("status").GetString());
        Assert.Equal("Done", run.GetProperty("resultSummary").GetString());
        Assert.Equal("session-1", run.GetProperty("executionThread").GetProperty("nativeThreadId").GetString());
        Assert.Equal(JsonValueKind.Null, run.GetProperty("leaseExpiresAt").ValueKind);
        var receipt = await OkAsync(w, w.Owner, HttpMethod.Get, $"/v1/automation-runs/{runId}");
        Assert.Equal([1, 2, 3], receipt.GetProperty("events").EnumerateArray().Select(e => e.GetProperty("sequence").GetInt32()));
        Assert.Equal("step 1", receipt.GetProperty("events")[0].GetProperty("payload").GetProperty("text").GetString());
        // The run is over: nothing more can be said about it.
        Assert.Equal("runner_lease_lost", (await runner.HeartbeatAsync(runId)).Body.GetProperty("error").GetString());
        Assert.Equal("runner_lease_lost", (await runner.EventAsync(runId, 4)).Body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task Only_the_holder_can_touch_a_run_and_nobody_else_changes_its_state()
    {
        var w = await Workspace.CreateAsync(_factory);
        var member = await w.AddAsync();
        var id = await CreateAsync(w, w.Owner);
        var holder = await Runner.RegisterAsync(w, w.Owner, "install-touch-1");
        var other = await Runner.RegisterAsync(w, w.Owner, "install-touch-2");
        var stranger = await Runner.RegisterAsync(w, member, "install-touch-3");
        var runId = await RunNowAsync(w, w.Owner, id);
        // Someone else's desktop cannot take a queued run: it stays queued, unclaimed.
        Assert.Null(await stranger.ClaimAsync(runId));
        var untouched = RunRow(runId);
        Assert.Equal("queued", untouched.Status);
        Assert.Equal(0, untouched.AttemptCount);
        Assert.Null(untouched.LeaseOwner);
        await holder.ClaimAsync(runId);
        var before = RunRow(runId);
        // Another desktop of the same owner, and another person's desktop, can neither extend, record into, nor end it; the row does not change.
        foreach (var intruder in new[] { other, stranger })
        {
            Assert.Equal(HttpStatusCode.Conflict, (await intruder.HeartbeatAsync(runId)).Status);
            Assert.Equal(HttpStatusCode.Conflict, (await intruder.EventAsync(runId, 1)).Status);
            Assert.Equal(HttpStatusCode.Conflict, (await intruder.CompleteAsync(runId)).Status);
            Assert.Null(await intruder.ClaimAsync(runId));
        }
        var after = RunRow(runId);
        Assert.Equal("running", after.Status);
        Assert.Equal(before.LeaseOwner, after.LeaseOwner);
        Assert.Equal(before.LeaseExpiresAt, after.LeaseExpiresAt);
        Assert.Equal(before.HeartbeatAt, after.HeartbeatAt);
        Assert.Equal(0, after.EngineSequence);
        Assert.Equal(0, Db(db => db.Set<AutomationRunEvent>().Count(e => e.RunId == runId)));
    }

    [Fact]
    public async Task Events_must_arrive_in_order_and_a_repeat_returns_the_event_it_made()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await CreateAsync(w, w.Owner);
        var runner = await Runner.RegisterAsync(w, w.Owner, "install-events-1");
        var runId = await RunNowAsync(w, w.Owner, id);
        await runner.ClaimAsync(runId);
        Assert.Equal("automation_runner_event_sequence_gap", (await runner.EventAsync(runId, 2)).Body.GetProperty("error").GetString());
        var one = await runner.EventAsync(runId, 1);
        var again = await runner.EventAsync(runId, 1);
        Assert.Equal(one.Body.GetProperty("event").GetProperty("id").GetString(), again.Body.GetProperty("event").GetProperty("id").GetString());
        Assert.Equal(1, Db(db => db.Set<AutomationRunEvent>().Count(e => e.RunId == runId)));
        // A bad type and a wrong attempt are refused.
        Assert.Equal(HttpStatusCode.BadRequest, (await runner.CallAsync(HttpMethod.Post, $"/v1/automation-runs/{runId}/events", new { attempt = 1, sequence = 2, type = "nope", payload = new { }, createdAt = 1 })).Status);
        Assert.Equal("runner_lease_lost", (await runner.EventAsync(runId, 2, attempt: 2)).Body.GetProperty("error").GetString());
        Assert.Equal(HttpStatusCode.BadRequest, (await runner.CallAsync(HttpMethod.Post, $"/v1/automation-runs/{runId}/events", new { attempt = 1, sequence = 0, type = "user", payload = new { }, createdAt = 1 })).Status);
    }

    [Fact]
    public async Task Results_are_validated_and_only_the_holder_of_the_lease_may_end_a_run()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await CreateAsync(w, w.Owner);
        var holder = await Runner.RegisterAsync(w, w.Owner, "install-result-1");
        var other = await Runner.RegisterAsync(w, w.Owner, "install-result-2");
        var runId = await RunNowAsync(w, w.Owner, id);
        await holder.ClaimAsync(runId);
        Assert.Equal(HttpStatusCode.BadRequest, (await holder.CallAsync(HttpMethod.Post, $"/v1/automation-runs/{runId}/complete", new { attempt = 1 })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await holder.CallAsync(HttpMethod.Post, $"/v1/automation-runs/{runId}/complete", new { attempt = 1, status = "weird", sessionId = (string?)null, workspaceId = (string?)null, resultSummary = (string?)null, usage = new { inputTokens = (int?)null, outputTokens = (int?)null, costMicros = (int?)null }, error = (object?)null })).Status);
        Assert.Equal("runner_lease_lost", (await other.CompleteAsync(runId)).Body.GetProperty("error").GetString());
        Assert.Equal("runner_lease_lost", (await holder.CompleteAsync(runId, attempt: 2)).Body.GetProperty("error").GetString());
        Assert.Equal("running", RunRow(runId).Status);
        var failed = await holder.CompleteAsync(runId, "failed", error: new { code = "execution_failed", message = "It broke", retryable = false });
        Assert.Equal("failed", failed.Body.GetProperty("run").GetProperty("status").GetString());
        Assert.Equal("execution_failed", failed.Body.GetProperty("run").GetProperty("error").GetProperty("code").GetString());
    }

    [Fact]
    public async Task Completing_is_final_and_idempotent()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await CreateAsync(w, w.Owner);
        var runner = await Runner.RegisterAsync(w, w.Owner, "install-final-1");
        var runId = await RunNowAsync(w, w.Owner, id);
        await runner.ClaimAsync(runId);
        var first = await runner.CompleteAsync(runId);
        var again = await runner.CompleteAsync(runId);
        Assert.Equal(HttpStatusCode.OK, again.Status);
        Assert.Equal(first.Body.GetProperty("run").GetProperty("finishedAt").GetInt64(), again.Body.GetProperty("run").GetProperty("finishedAt").GetInt64());
        var conflict = await runner.CompleteAsync(runId, "failed", error: new { code = "execution_failed", message = "no", retryable = false });
        Assert.Equal(HttpStatusCode.Conflict, conflict.Status);
        Assert.Equal("terminal_result_conflict", conflict.Body.GetProperty("error").GetString());
        Assert.Equal("succeeded", RunRow(runId).Status);
    }

    [Fact]
    public async Task A_model_error_from_the_desktop_pauses_the_Automation()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await CreateAsync(w, w.Owner);
        var runner = await Runner.RegisterAsync(w, w.Owner, "install-model-1");
        var runId = await RunNowAsync(w, w.Owner, id);
        await runner.ClaimAsync(runId);
        await runner.CompleteAsync(runId, "failed", error: new { code = "model_access_lost", message = "No such model", retryable = false });
        var automation = (await OkAsync(w, w.Owner, HttpMethod.Get, $"/v1/automations/{id}")).GetProperty("automation");
        Assert.Equal("needs_attention", automation.GetProperty("state").GetString());
        Assert.Equal("No such model", automation.GetProperty("needsAttentionReason").GetProperty("message").GetString());
        // Activating again (a person's decision) lifts it.
        Assert.Equal("active", (await OkAsync(w, w.Owner, HttpMethod.Post, $"/v1/automations/{id}/activate")).GetProperty("automation").GetProperty("state").GetString());
    }

    // ---------------------------------------------------------------- leases, recovery and the scheduler

    [Fact]
    public async Task A_heartbeat_extends_the_lease_and_a_silent_runner_loses_it()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await CreateAsync(w, w.Owner);
        var slow = await Runner.RegisterAsync(w, w.Owner, "install-lease-1");
        var runId = await RunNowAsync(w, w.Owner, id);
        var first = (await slow.ClaimAsync(runId))!.Value.GetProperty("leaseExpiresAt").GetInt64();
        await Task.Delay(AutomationFactory.LeaseMs / 2);
        var beat = (await slow.HeartbeatAsync(runId)).Body;
        Assert.True(beat.GetProperty("leaseExpiresAt").GetInt64() > first, "a heartbeat moves the deadline forward");
        // Heartbeating keeps it alive past the original deadline...
        await Task.Delay(AutomationFactory.LeaseMs / 2 + 300);
        Assert.Equal(HttpStatusCode.OK, (await slow.HeartbeatAsync(runId)).Status);
        // ...and a recovery pass at this moment leaves it alone.
        await _factory.TickAsync();
        Assert.Equal("running", RunRow(runId).Status);
        // Silence past the lease: the heartbeat, the events and the result are all refused.
        await Task.Delay(AutomationFactory.LeaseMs + 300);
        Assert.Equal(HttpStatusCode.Conflict, (await slow.HeartbeatAsync(runId)).Status);
        Assert.Equal(HttpStatusCode.Conflict, (await slow.EventAsync(runId, 1)).Status);
        Assert.Equal(HttpStatusCode.Conflict, (await slow.CompleteAsync(runId)).Status);
    }

    [Fact]
    public async Task An_expired_lease_is_recovered_once_then_another_desktop_takes_over_and_the_first_is_shut_out()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await CreateAsync(w, w.Owner);
        var first = await Runner.RegisterAsync(w, w.Owner, "install-recover-1");
        var second = await Runner.RegisterAsync(w, w.Owner, "install-recover-2");
        var runId = await RunNowAsync(w, w.Owner, id);
        await first.ClaimAsync(runId);
        await first.EventAsync(runId, 1);
        var now = AutomationService.Now();
        // Time passes beyond the lease (the tick takes the clock as an argument).
        await _factory.TickAsync(now + AutomationFactory.LeaseMs + 1000);
        var requeued = RunRow(runId);
        Assert.Equal("queued", requeued.Status);
        Assert.Null(requeued.LeaseOwner);
        Assert.Equal(1, requeued.AttemptCount);
        Assert.Equal(0, requeued.EngineSequence);
        // Doing it again changes nothing (recovery is idempotent).
        await _factory.TickAsync(now + AutomationFactory.LeaseMs + 1000);
        Assert.Equal("queued", RunRow(runId).Status);
        // Another desktop claims it as attempt 2, and the first desktop can no longer touch it.
        var assignment = await second.ClaimAsync(runId);
        Assert.NotNull(assignment);
        Assert.Equal(2, assignment!.Value.GetProperty("attempt").GetInt32());
        Assert.Equal(HttpStatusCode.Conflict, (await first.HeartbeatAsync(runId, 1)).Status);
        Assert.Equal(HttpStatusCode.Conflict, (await first.HeartbeatAsync(runId, 2)).Status);
        Assert.Equal(HttpStatusCode.Conflict, (await first.CompleteAsync(runId, attempt: 1)).Status);
        Assert.Equal(HttpStatusCode.Conflict, (await first.CompleteAsync(runId, attempt: 2)).Status);
        // Events of attempt 2 start over at 1; the old attempt's event stays in the receipt.
        Assert.Equal(HttpStatusCode.OK, (await second.EventAsync(runId, 1, attempt: 2)).Status);
        Assert.Equal(HttpStatusCode.OK, (await second.CompleteAsync(runId, attempt: 2)).Status);
        var receipt = await OkAsync(w, w.Owner, HttpMethod.Get, $"/v1/automation-runs/{runId}");
        Assert.Equal([(1, 1), (2, 1)], receipt.GetProperty("events").EnumerateArray().Select(e => (e.GetProperty("attempt").GetInt32(), e.GetProperty("sequence").GetInt32())));
    }

    [Fact]
    public async Task After_the_second_expired_attempt_the_run_fails_and_the_next_one_can_start()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await CreateAsync(w, w.Owner);
        var runner = await Runner.RegisterAsync(w, w.Owner, "install-fail-1");
        var runId = await RunNowAsync(w, w.Owner, id);
        var now = AutomationService.Now();
        await runner.ClaimAsync(runId);
        await _factory.TickAsync(now + 10_000);
        Assert.Equal("queued", RunRow(runId).Status);
        await runner.ClaimAsync(runId);
        await _factory.TickAsync(now + 20_000);
        var run = RunRow(runId);
        Assert.Equal("failed", run.Status);
        Assert.Contains("lease_lost", run.ErrorJson);
        Assert.Equal(RunQueue.InterruptedMessage, run.ResultSummary);
        Assert.NotNull(run.FinishedAt);
        // A failed run no longer blocks the Automation.
        Assert.Equal("queued", (await OkAsync(w, w.Owner, HttpMethod.Post, $"/v1/automations/{id}/run", new { }, 202)).GetProperty("run").GetProperty("status").GetString());
    }

    [Fact]
    public async Task A_run_nobody_claims_in_time_is_recorded_as_missed_with_the_reason()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await CreateAsync(w, w.Owner);
        var runId = await RunNowAsync(w, w.Owner, id);
        var now = AutomationService.Now();
        // Inside the window it is still claimable; past it, it is missed ("no desktop was connected": none ever registered).
        await _factory.TickAsync(now + 60_000);
        Assert.Equal("queued", RunRow(runId).Status);
        await _factory.TickAsync(now + RunQueue.ManualClaimWindowMs + 1000);
        var run = RunRow(runId);
        Assert.Equal("skipped", run.Status);
        Assert.Equal("Missed — no desktop was connected.", run.ResultSummary);
        Assert.Contains("runner_unavailable", run.ErrorJson);
        // A run past its window cannot be claimed even before the tick records it.
        var late = await RunNowAsync(w, w.Owner, id);
        var runner = await Runner.RegisterAsync(w, w.Owner, "install-late-1");
        Db(db => db.Set<AutomationRun>().Where(r => r.Id == late).ExecuteUpdate(s => s.SetProperty(r => r.ClaimDeadlineAt, (long?)1)));
        Assert.Null(await runner.ClaimAsync(late));
        Assert.Empty((await runner.CallAsync(HttpMethod.Get, "/v1/automation-runner/work")).Body.GetProperty("items").EnumerateArray());
        await _factory.TickAsync();
        Assert.Equal("Missed — the connected desktop did not pick this up in time.", RunRow(late).ResultSummary);
    }

    private void MakeDue(string automationId) => Db(db => db.Set<Automation>().Where(a => a.Id == automationId).ExecuteUpdate(s => s.SetProperty(a => a.NextDueAt, (long?)AutomationService.Now() - 1000)));

    [Fact]
    public async Task The_scheduler_starts_a_due_occurrence_once_and_moves_the_schedule_on()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await CreateAsync(w, w.Owner);
        MakeDue(id);
        var due = Db(db => db.Set<Automation>().Single(a => a.Id == id).NextDueAt)!.Value;
        var started = await _factory.TickAsync();
        Assert.Single(started);
        var run = RunRow(started[0]);
        Assert.Equal("queued", run.Status);
        Assert.Equal("scheduled", run.Trigger);
        Assert.Equal(due, run.ScheduledFor);
        Assert.True(Db(db => db.Set<Automation>().Single(a => a.Id == id).NextDueAt) > AutomationService.Now());
        // A second tick finds nothing due.
        Assert.Empty(await _factory.TickAsync());
        Assert.Equal(1, Db(db => db.Set<AutomationRun>().Count(r => r.AutomationId == id)));
        // The desktop sees it as work.
        var runner = await Runner.RegisterAsync(w, w.Owner, "install-sched-1");
        Assert.Equal(run.Id, (await runner.CallAsync(HttpMethod.Get, "/v1/automation-runner/work")).Body.GetProperty("items")[0].GetProperty("runId").GetString());
    }

    [Fact]
    public async Task Two_schedulers_ticking_at_once_start_one_run_per_occurrence()
    {
        var w = await Workspace.CreateAsync(_factory);
        var ids = new List<string>();
        for (var i = 0; i < 4; i++) { var id = await CreateAsync(w, w.Owner, Body(name: $"Auto {i}")); MakeDue(id); ids.Add(id); }
        var now = AutomationService.Now();
        var ticks = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => Task.Run(() => _factory.TickAsync(now))));
        Assert.Equal(4, ticks.SelectMany(t => t).Count());
        foreach (var id in ids) Assert.Equal(1, Db(db => db.Set<AutomationRun>().Count(r => r.AutomationId == id)));
    }

    [Fact]
    public async Task A_due_occurrence_while_a_run_is_active_is_recorded_as_skipped()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await CreateAsync(w, w.Owner);
        var manual = await RunNowAsync(w, w.Owner, id);
        MakeDue(id);
        Assert.Empty(await _factory.TickAsync());
        var runs = Db(db => db.Set<AutomationRun>().Where(r => r.AutomationId == id).OrderBy(r => r.Id).ToList());
        Assert.Equal(2, runs.Count);
        Assert.Equal(manual, runs[0].Id);
        Assert.Equal("skipped", runs[1].Status);
        Assert.Equal("scheduled", runs[1].Trigger);
        // Inactive and archived Automations are never started by the scheduler.
        var other = await CreateAsync(w, w.Owner);
        await OkAsync(w, w.Owner, HttpMethod.Post, $"/v1/automations/{other}/deactivate");
        Db(db => db.Set<Automation>().Where(a => a.Id == other).ExecuteUpdate(s => s.SetProperty(a => a.NextDueAt, (long?)1)));
        Assert.Empty(await _factory.TickAsync());
        Assert.Equal(0, Db(db => db.Set<AutomationRun>().Count(r => r.AutomationId == other)));
    }

    [Fact]
    public async Task A_due_Automation_whose_owner_left_is_paused_and_a_model_gone_skips_the_occurrence()
    {
        var w = await Workspace.CreateAsync(_factory);
        var member = await w.AddAsync();
        var id = await CreateAsync(w, member, Body(model: new { providerId = "ollama", modelId = "llama" }));
        MakeDue(id);
        // A desktop-only provider is fine for the desktop; now the owner leaves.
        await OkAsync(w, w.Owner, HttpMethod.Delete, $"/v1/members/{member.MemberId}", null, 204);
        var started = await _factory.TickAsync();
        Assert.Empty(started);
        var automation = Db(db => db.Set<Automation>().Single(a => a.Id == id));
        Assert.Equal("needs_attention", automation.State);
        Assert.Contains("owner_membership_lost", automation.NeedsAttentionJson);
        Assert.Equal("skipped", Db(db => db.Set<AutomationRun>().Single(r => r.AutomationId == id)).Status);
    }

    // ---------------------------------------------------------------- races

    [Fact]
    public async Task Many_desktops_racing_for_one_run_produce_exactly_one_winner()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await CreateAsync(w, w.Owner);
        var runners = new List<Runner>();
        for (var i = 0; i < 8; i++) runners.Add(await Runner.RegisterAsync(w, w.Owner, $"install-race-{i}"));
        for (var round = 0; round < 3; round++)
        {
            var runId = await RunNowAsync(w, w.Owner, id);
            var results = await Task.WhenAll(runners.Select(r => Task.Run(() => r.ClaimAsync(runId))));
            Assert.Equal(1, results.Count(a => a is not null));
            var row = RunRow(runId);
            Assert.Equal("running", row.Status);
            Assert.Equal(1, row.AttemptCount);
            // The winner holds the lease: it is the only one whose heartbeat works.
            var winner = runners[Array.FindIndex(results, a => a is not null)];
            var beats = await Task.WhenAll(runners.Select(r => r.HeartbeatAsync(runId)));
            Assert.Equal(1, beats.Count(b => b.Status == HttpStatusCode.OK));
            Assert.Equal(HttpStatusCode.OK, (await winner.HeartbeatAsync(runId)).Status);
            await winner.CompleteAsync(runId);
        }
    }

    [Fact]
    public async Task The_same_desktop_asking_twice_at_once_gets_one_attempt()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await CreateAsync(w, w.Owner);
        var runner = await Runner.RegisterAsync(w, w.Owner, "install-twice-1");
        var runId = await RunNowAsync(w, w.Owner, id);
        var results = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => Task.Run(() => runner.ClaimAsync(runId))));
        Assert.All(results, a => Assert.NotNull(a));
        Assert.All(results, a => Assert.Equal(1, a!.Value.GetProperty("attempt").GetInt32()));
        Assert.Equal(1, RunRow(runId).AttemptCount);
    }

    [Fact]
    public async Task Concurrent_completes_end_the_run_once_and_conflicting_results_cannot_both_win()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await CreateAsync(w, w.Owner);
        var runner = await Runner.RegisterAsync(w, w.Owner, "install-complete-1");
        var same = await RunNowAsync(w, w.Owner, id);
        await runner.ClaimAsync(same);
        var results = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => Task.Run(() => runner.CompleteAsync(same))));
        Assert.All(results, r => Assert.Equal(HttpStatusCode.OK, r.Status));
        Assert.Single(results.Select(r => r.Body.GetProperty("run").GetProperty("finishedAt").GetInt64()).Distinct());

        var mixed = await RunNowAsync(w, w.Owner, id);
        await runner.ClaimAsync(mixed);
        var calls = await Task.WhenAll(new[] { "succeeded", "failed", "cancelled", "succeeded", "failed", "cancelled" }.Select(s => Task.Run(() => runner.CompleteAsync(mixed, s))));
        var winners = calls.Where(c => c.Status == HttpStatusCode.OK).Select(c => c.Body.GetProperty("run").GetProperty("status").GetString()).Distinct().ToList();
        Assert.Single(winners);
        Assert.Equal(winners[0], RunRow(mixed).Status);
        Assert.All(calls.Where(c => c.Status != HttpStatusCode.OK), c => Assert.Equal("terminal_result_conflict", c.Body.GetProperty("error").GetString()));
    }

    [Fact]
    public async Task Concurrent_events_keep_the_sequence_gapless_and_a_repeated_step_is_made_once()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await CreateAsync(w, w.Owner);
        var runner = await Runner.RegisterAsync(w, w.Owner, "install-seq-1");
        var runId = await RunNowAsync(w, w.Owner, id);
        await runner.ClaimAsync(runId);
        // The same step six times at once is one event.
        var repeated = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => Task.Run(() => runner.EventAsync(runId, 1))));
        Assert.All(repeated, r => Assert.Equal(HttpStatusCode.OK, r.Status));
        Assert.Single(repeated.Select(r => r.Body.GetProperty("event").GetProperty("id").GetString()).Distinct());
        // Steps 2..7 sent all at once, each retried while the one before it has not landed: they end up recorded exactly once each, in order.
        var sent = await Task.WhenAll(Enumerable.Range(2, 6).Select(seq => Task.Run(async () =>
        {
            for (var tries = 0; tries < 200; tries++)
            {
                var r = await runner.EventAsync(runId, seq);
                if (r.Status == HttpStatusCode.OK) return r.Body.GetProperty("event").GetProperty("sequence").GetInt32();
                Assert.Equal("automation_runner_event_sequence_gap", r.Body.GetProperty("error").GetString());
                await Task.Delay(5);
            }
            return -1;
        })));
        Assert.Equal([2, 3, 4, 5, 6, 7], sent.Order());
        var stored = Db(db => db.Set<AutomationRunEvent>().Where(e => e.RunId == runId).OrderBy(e => e.Sequence).Select(e => e.Sequence).ToList());
        Assert.Equal([1, 2, 3, 4, 5, 6, 7], stored);
        Assert.Equal(7, RunRow(runId).EngineSequence);
    }

    [Fact]
    public async Task Run_now_pressed_many_times_at_once_leaves_one_active_run()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await CreateAsync(w, w.Owner);
        var calls = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(() => w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/automations/{id}/run", new { }))));
        Assert.All(calls, c => Assert.Equal(HttpStatusCode.Accepted, c.Status));
        var statuses = calls.Select(c => c.Body.GetProperty("run").GetProperty("status").GetString()).ToList();
        Assert.Equal(1, statuses.Count(s => s == "queued"));
        Assert.Equal(7, statuses.Count(s => s == "skipped"));
        Assert.Equal(1, Db(db => db.Set<AutomationRun>().Count(r => r.AutomationId == id && r.Status == "queued")));
    }

    [Fact]
    public async Task A_heartbeat_racing_a_recovery_either_keeps_the_run_or_loses_it_never_both()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await CreateAsync(w, w.Owner);
        var runner = await Runner.RegisterAsync(w, w.Owner, "install-hb-race-1");
        var runId = await RunNowAsync(w, w.Owner, id);
        await runner.ClaimAsync(runId);
        // Expire the lease in the database, then race the runner's heartbeat against recovery.
        Db(db => db.Set<AutomationRun>().Where(r => r.Id == runId).ExecuteUpdate(s => s.SetProperty(r => r.LeaseExpiresAt, (long?)AutomationService.Now() - 1)));
        var beat = Task.Run(() => runner.HeartbeatAsync(runId));
        var tick = Task.Run(() => _factory.TickAsync());
        await Task.WhenAll(beat, tick);
        // An expired lease cannot be revived by a heartbeat, so the run was recovered.
        Assert.Equal(HttpStatusCode.Conflict, (await beat).Status);
        Assert.Equal("queued", RunRow(runId).Status);
    }

    // ---------------------------------------------------------------- housekeeping

    [Fact]
    public async Task Deleting_the_workspace_removes_its_Automations_runs_and_telemetry()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await CreateAsync(w, w.Owner);
        var runId = await RunNowAsync(w, w.Owner, id);
        await Runner.RegisterAsync(w, w.Owner, "install-purge-1");
        await OkAsync(w, w.Owner, HttpMethod.Post, "/v1/telemetry/ingest", new { events = new[] { new { type = "user.active", timestamp = DateTime.UtcNow.ToString("O") } } }, 204);
        Assert.Equal(1, Db(db => db.Set<TelemetryEvent>().Count(e => e.OrganizationId == w.OrgId)));
        var r = await w.CallAsync(w.Owner, HttpMethod.Delete, "/v1/org");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal(0, Db(db => db.Set<Automation>().Count(a => a.Id == id)));
        Assert.Equal(0, Db(db => db.Set<AutomationRun>().Count(a => a.Id == runId)));
        Assert.Equal(0, Db(db => db.Set<AutomationRunner>().Count(a => a.OrganizationId == w.OrgId)));
        Assert.Equal(0, Db(db => db.Set<TelemetryEvent>().Count(e => e.OrganizationId == w.OrgId)));
    }

    // ---------------------------------------------------------------- telemetry

    private static string Iso(TimeSpan ago) => (DateTime.UtcNow - ago).ToString("yyyy-MM-ddTHH:mm:ss.fff'Z'");

    private static object Ev(string type, TimeSpan ago, string? session = null, int? duration = null, object[]? dimensions = null) =>
        new Dictionary<string, object?> { ["type"] = type, ["timestamp"] = Iso(ago), ["source"] = "app", ["sessionId"] = session, ["durationMs"] = duration, ["dimensions"] = dimensions }
            .Where(kv => kv.Value is not null).ToDictionary(kv => kv.Key, kv => kv.Value);

    [Fact]
    public async Task Ingest_keeps_known_events_drops_the_rest_and_validates_the_batch()
    {
        var w = await Workspace.CreateAsync(_factory);
        var member = await w.AddAsync();
        var ok = await w.CallAsync(member, HttpMethod.Post, "/v1/telemetry/ingest", new { events = new[]
        {
            Ev("user.active", TimeSpan.FromMinutes(1)), Ev("bogus.type", TimeSpan.FromMinutes(1)), Ev("workbot.signed_in", TimeSpan.FromMinutes(1)),
            Ev("connection.connected", TimeSpan.FromMinutes(1)), Ev("activation.first_response", TimeSpan.FromMinutes(1)), Ev("task.completed", TimeSpan.FromMinutes(1), "s1", 50),
        } });
        Assert.Equal(HttpStatusCode.NoContent, ok.Status);
        var types = Db(db => db.Set<TelemetryEvent>().Where(e => e.OrganizationId == w.OrgId).Select(e => e.EventType).ToList());
        Assert.Equal(["task.completed", "user.active"], types.Order());
        var row = Db(db => db.Set<TelemetryEvent>().Single(e => e.OrganizationId == w.OrgId && e.EventType == "task.completed"));
        Assert.Equal(member.MemberId, row.MemberId);   // attributed to the sender, never to a member named in the payload
        Assert.Equal("app", row.Source);
        Assert.Equal(50, row.DurationMs);
        async Task<string> Bad(object body) => (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/telemetry/ingest", body)).Message();
        Assert.Equal("events: Too small: expected array to have >=1 items", await Bad(new { events = Array.Empty<object>() }));
        Assert.Equal("events: Invalid input: expected array, received undefined", await Bad(new { }));
        Assert.Equal("events: Too big: expected array to have <=50 items", await Bad(new { events = Enumerable.Range(0, 51).Select(_ => Ev("user.active", TimeSpan.Zero)).ToArray() }));
        Assert.Equal("events.0.timestamp: Invalid ISO datetime", await Bad(new { events = new[] { new { type = "user.active", timestamp = "yesterday" } } }));
        Assert.Equal("events.0.durationMs: Too big: expected number to be <=86400000", await Bad(new { events = new[] { new { type = "task.completed", timestamp = Iso(TimeSpan.Zero), durationMs = 86_400_001 } } }));
        Assert.StartsWith("events.0.dimensions.0.type: Dimension type must start with a lowercase letter", await Bad(new { events = new[] { new { type = "task.failed", timestamp = Iso(TimeSpan.Zero), dimensions = new[] { new { type = "Bad Type!", label = "x" } } } } }));
        Assert.Equal("events.0.source: Too big: expected string to have <=32 characters", await Bad(new { events = new[] { new { type = "user.active", timestamp = Iso(TimeSpan.Zero), source = new string('x', 33) } } }));
        // A failed batch stores nothing.
        Assert.Equal(2, Db(db => db.Set<TelemetryEvent>().Count(e => e.OrganizationId == w.OrgId)));
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Http.PostAsJsonAsync("/v1/telemetry/ingest", new { events = new[] { Ev("user.active", TimeSpan.Zero) } })).StatusCode);
    }

    [Fact]
    public async Task Analytics_count_people_sessions_and_tasks_by_window_and_week_and_need_the_permission()
    {
        var w = await Workspace.CreateAsync(_factory);
        var member = await w.AddAsync();
        await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/telemetry/ingest", new { events = new[]
        {
            Ev("session.started", TimeSpan.FromSeconds(1), "s1"), Ev("task.completed", TimeSpan.FromSeconds(2), "s1", 1000), Ev("task.completed", TimeSpan.FromSeconds(3), "s1", 2001),
            Ev("task.failed", TimeSpan.FromSeconds(4), "s2"), Ev("user.active", TimeSpan.FromDays(3)), Ev("task.completed", TimeSpan.FromDays(20), "s3", 10),
            Ev("task.completed", TimeSpan.FromDays(200), "old", 10),   // older than the trend: counted nowhere
        } });
        await w.CallAsync(member, HttpMethod.Post, "/v1/telemetry/ingest", new { events = new[] { Ev("user.active", TimeSpan.FromMinutes(1)) } });
        var a = await OkAsync(w, w.Owner, HttpMethod.Get, "/v1/telemetry/analytics");
        Assert.Equal(2, a.GetProperty("members").GetInt32());
        Assert.Equal(2, a.GetProperty("activeMembers7d").GetInt32());
        Assert.Equal(2, a.GetProperty("sessions7d").GetInt32());
        Assert.Equal(3, a.GetProperty("sessions30d").GetInt32());
        Assert.Equal(2, a.GetProperty("tasksCompleted7d").GetInt32());
        Assert.Equal(1, a.GetProperty("tasksFailed7d").GetInt32());
        Assert.Equal(3, a.GetProperty("tasksCompleted30d").GetInt32());
        Assert.Equal(1004, a.GetProperty("avgTaskDurationMs30d").GetInt32());
        var weeks = a.GetProperty("weekly");
        Assert.Equal(12, weeks.GetArrayLength());
        Assert.Equal(2, weeks[11].GetProperty("tasksCompleted").GetInt32());
        Assert.Equal(1, weeks[9].GetProperty("tasksCompleted").GetInt32());   // 20 days ago falls in the third-to-last week
        Assert.Equal(3, weeks.EnumerateArray().Sum(x => x.GetProperty("tasksCompleted").GetInt32()));
        var daily = a.GetProperty("daily");
        Assert.Equal(30, daily.GetArrayLength());
        Assert.Equal(DateTime.UtcNow.ToString("yyyy-MM-dd"), daily[29].GetProperty("day").GetString());
        var adoption = await OkAsync(w, w.Owner, HttpMethod.Get, "/v1/telemetry/adoption");
        Assert.Equal(2, adoption.GetProperty("members").GetInt32());
        Assert.Equal(12, adoption.GetProperty("weeklyTrend").GetArrayLength());
        Assert.Equal(2, adoption.GetProperty("weeklyTrend")[11].GetInt32());
        // Without the permission: 403 naming it. With it granted by an admin role: allowed.
        foreach (var url in new[] { "/v1/telemetry/analytics", "/v1/telemetry/adoption", "/v1/telemetry/dimensions?type=project" })
            Assert.Equal("usage_analytics.view", (await w.CallAsync(member, HttpMethod.Get, url)).Required());
        // Another workspace sees none of it.
        var elsewhere = await Workspace.CreateAsync(_factory, "Elsewhere");
        var empty = await OkAsync(elsewhere, elsewhere.Owner, HttpMethod.Get, "/v1/telemetry/analytics");
        Assert.Equal(0, empty.GetProperty("sessions30d").GetInt32());
        Assert.Equal(JsonValueKind.Null, empty.GetProperty("avgTaskDurationMs30d").ValueKind);
    }

    [Fact]
    public async Task Dimensions_label_sessions_and_filter_the_analytics()
    {
        var w = await Workspace.CreateAsync(_factory);
        object Project(string label) => new { type = "project", label };
        await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/telemetry/ingest", new { events = new[]
        {
            Ev("session.started", TimeSpan.FromSeconds(1), "s1", null, [Project("Alpha Project"), new { type = "model", label = "Claude X", value = "claude-x" }, new { type = "model_selection", label = "default", value = "default" }]),
            Ev("task.completed", TimeSpan.FromSeconds(2), "s1", 100), Ev("task.failed", TimeSpan.FromSeconds(3), "s2"),
            Ev("task.completed", TimeSpan.FromSeconds(4), "s3", 10, [Project("Beta")]),
        } });
        var list = (await OkAsync(w, w.Owner, HttpMethod.Get, "/v1/telemetry/dimensions?type=project")).GetProperty("items");
        Assert.Equal(2, list.GetArrayLength());
        var alpha = list.EnumerateArray().Single(i => i.GetProperty("label").GetString() == "Alpha Project");
        Assert.Equal(TelemetryRules.DeriveDimensionValue("project", "Alpha Project"), alpha.GetProperty("value").GetString());
        Assert.Equal(1, alpha.GetProperty("sessionCount").GetInt32());
        var filtered = await OkAsync(w, w.Owner, HttpMethod.Get, $"/v1/telemetry/analytics?dimensionType=project&dimensionValue={alpha.GetProperty("value").GetString()}");
        Assert.Equal(1, filtered.GetProperty("sessions30d").GetInt32());
        Assert.Equal(1, filtered.GetProperty("tasksCompleted30d").GetInt32());
        Assert.Equal(0, filtered.GetProperty("tasksFailed30d").GetInt32());
        var models = (await OkAsync(w, w.Owner, HttpMethod.Get, "/v1/telemetry/analytics")).GetProperty("models");
        Assert.Equal("claude-x", models.GetProperty("usage30d")[0].GetProperty("id").GetString());
        Assert.Equal(1, models.GetProperty("selection30d").GetProperty("default").GetInt32());
        Assert.Equal(0, models.GetProperty("selection30d").GetProperty("manual").GetInt32());
        Assert.Equal("dimensionType and dimensionValue must be supplied together.", (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/telemetry/analytics?dimensionType=project")).Message());
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/telemetry/dimensions")).Status);
        // A second sighting of the same session refreshes the label and keeps the row; it never makes a second one.
        await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/telemetry/ingest", new { events = new[] { Ev("session.active", TimeSpan.FromSeconds(1), "s1", null, [new { type = "project", label = "Alpha Renamed" }]) } });
        Assert.Equal(1, Db(db => db.Set<TelemetrySessionDimension>().Count(d => d.OrganizationId == w.OrgId && d.SessionId == "s1" && d.DimensionType == "project")));
        Assert.Equal("Alpha Renamed", Db(db => db.Set<TelemetrySessionDimension>().Single(d => d.OrganizationId == w.OrgId && d.SessionId == "s1" && d.DimensionType == "project").DimensionLabel));
    }

    [Fact]
    public async Task Racing_batches_for_one_session_leave_one_dimension_row()
    {
        var w = await Workspace.CreateAsync(_factory);
        var calls = await Task.WhenAll(Enumerable.Range(0, 8).Select(i => Task.Run(() => w.CallAsync(w.Owner, HttpMethod.Post, "/v1/telemetry/ingest",
            new { events = new[] { Ev("session.active", TimeSpan.FromSeconds(1), "race", null, [new { type = "project", label = $"Name {i}" }]) } }))));
        Assert.All(calls, c => Assert.Equal(HttpStatusCode.NoContent, c.Status));
        Assert.Equal(1, Db(db => db.Set<TelemetrySessionDimension>().Count(d => d.OrganizationId == w.OrgId && d.SessionId == "race")));
        Assert.Equal(8, Db(db => db.Set<TelemetryEvent>().Count(e => e.OrganizationId == w.OrgId)));
    }
}

public sealed class CloudAutomationTests : IClassFixture<CloudAutomationFactory>
{
    private readonly CloudAutomationFactory _factory;
    public CloudAutomationTests(CloudAutomationFactory factory) => _factory = factory;

    private static readonly object Daily9 = new { kind = "daily", timezone = "UTC", hour = 9, minute = 0 };
    private static object Cloud(object? schedule = null) => new { name = "Cloud one", schedule = schedule ?? Daily9, action = new { kind = "agent", instructions = "x", model = new { providerId = "openwork-cloud", modelId = "default" } } };

    [Fact]
    public async Task With_a_cloud_runtime_cloud_Automations_are_stored_and_run_now_queues_a_cloud_run()
    {
        var w = await Workspace.CreateAsync(_factory);
        var created = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/cloud-automations", Cloud());
        Assert.Equal(HttpStatusCode.Created, created.Status);
        Assert.Equal("cloud", created.Body.GetProperty("revision").GetProperty("executionTarget").GetString());
        Assert.Equal("openwork-cloud", created.Body.GetProperty("revision").GetProperty("model").GetProperty("providerId").GetString());
        var id = created.Body.GetProperty("automation").GetProperty("id").GetString()!;
        var run = await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/automations/{id}/run", new { });
        Assert.Equal(HttpStatusCode.Accepted, run.Status);
        Assert.Equal("queued", run.Body.GetProperty("run").GetProperty("status").GetString());
        Assert.Equal("cloud", run.Body.GetProperty("run").GetProperty("executionTarget").GetString());
        // A desktop never sees a cloud run as work.
        var token = (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/automation-runners/token", new { runnerId = "runner-cloud-1", protocolVersion = 1, supportedExecutionTargets = new[] { "desktop" }, appVersion = "1", platform = "linux", concurrency = 1 })).Body.GetProperty("token").GetString()!;
        var work = await w.SendAsync(Bearer(HttpMethod.Get, "/v1/automation-runner/work", token));
        Assert.Empty((await ApiFactory.ReadJsonAsync(work)).GetProperty("items").EnumerateArray());
        var targets = (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/automation-runners")).Body.GetProperty("items").EnumerateArray().Single(i => i.GetProperty("kind").GetString() == "cloud");
        Assert.True(targets.GetProperty("available").GetBoolean());
        Assert.Equal("headless", targets.GetProperty("runtime").GetString());
        // The cloud default model is for the cloud only.
        var desktop = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/automations", new { name = "d", instructions = "i", schedule = Daily9, model = new { providerId = "openwork-cloud", modelId = "default" } });
        Assert.Equal("model_access_lost", desktop.Error());
    }

    [Fact]
    public async Task Calendar_triggers_are_stored_for_the_cloud_and_have_no_clock_time()
    {
        var w = await Workspace.CreateAsync(_factory);
        var r = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/cloud-automations", Cloud(new { kind = "calendar", timezone = "UTC", edge = "end", offsetMinutes = 5, rule = new { withExternalAttendees = true, titleIncludes = "standup" } }));
        Assert.Equal(HttpStatusCode.Created, r.Status);
        Assert.Equal(JsonValueKind.Null, r.Body.GetProperty("automation").GetProperty("nextDueAt").ValueKind);
        Assert.True(r.Body.GetProperty("revision").GetProperty("schedule").GetProperty("rule").GetProperty("withExternalAttendees").GetBoolean());
    }

    [Fact]
    public async Task Interval_schedules_work_when_the_feature_is_on_and_released_desktops_do_not_see_them()
    {
        var w = await Workspace.CreateAsync(_factory);
        var body = new { name = "Hourly", instructions = "i", schedule = new { kind = "interval", timezone = "UTC", everyHours = 3, startHour = 9, endHour = 18 }, model = new { providerId = "ollama", modelId = "llama" } };
        var created = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/automations", body);
        Assert.Equal(HttpStatusCode.Created, created.Status);
        var schedule = created.Body.GetProperty("revision").GetProperty("schedule");
        Assert.Equal(9, schedule.GetProperty("startHour").GetInt32());
        Assert.Equal(7, schedule.GetProperty("daysOfWeek").GetArrayLength());
        var hour = DateTimeOffset.FromUnixTimeMilliseconds(created.Body.GetProperty("automation").GetProperty("nextDueAt").GetInt64()).Hour;
        Assert.Contains(hour, new[] { 9, 12, 15 });
        var id = created.Body.GetProperty("automation").GetProperty("id").GetString()!;
        // A first-party desktop that sends the model-attention header but does not name the newer kinds reads only once, daily and weekly.
        var legacy = w.As(w.Owner, HttpMethod.Get, "/v1/automations");
        legacy.Headers.Add("x-openwork-automation-model-attention", "model_attention_v1");
        Assert.Empty((await ApiFactory.ReadJsonAsync(await w.SendAsync(legacy))).GetProperty("items").EnumerateArray());
        var legacyGet = w.As(w.Owner, HttpMethod.Get, $"/v1/automations/{id}");
        legacyGet.Headers.Add("x-openwork-automation-model-attention", "model_attention_v1");
        Assert.Equal(HttpStatusCode.NotFound, (await w.SendAsync(legacyGet)).StatusCode);
        // One that names the kind it reads sees it; so does everyone who sends no desktop headers.
        var modern = w.As(w.Owner, HttpMethod.Get, "/v1/automations");
        modern.Headers.Add("x-openwork-automation-model-attention", "model_attention_v1");
        modern.Headers.Add("x-openwork-automation-schedule-kinds", "once,daily,weekly,interval");
        Assert.Single((await ApiFactory.ReadJsonAsync(await w.SendAsync(modern))).GetProperty("items").EnumerateArray());
        Assert.Single((await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/automations")).Body.GetProperty("items").EnumerateArray());
    }
}
