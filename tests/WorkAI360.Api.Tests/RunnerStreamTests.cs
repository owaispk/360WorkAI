using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Domain.Automations;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>Automations with a fast runner stream (short poll, keepalive and owner-check intervals), so the stream can be watched in a test.</summary>
public sealed class RunnerStreamFactory : AutomationFactory
{
    protected override IEnumerable<KeyValuePair<string, string>> Settings => base.Settings.Concat(
    [
        new("Automations:StreamPollMinMs", "40"), new("Automations:StreamPollMaxMs", "160"),
        new("Automations:StreamKeepaliveMs", "400"), new("Automations:StreamOwnerCheckMs", "150"),
    ]);
}

/// <summary>GET /v1/automation-runners/events and PUT /v1/automation-runner/inventory.</summary>
public sealed class RunnerStreamTests(RunnerStreamFactory factory) : IClassFixture<RunnerStreamFactory>
{
    private static readonly object Daily9 = new { kind = "daily", timezone = "UTC", hour = 9, minute = 0 };

    private static async Task<string> RunnerTokenAsync(Workspace w, Person p, string install, string[]? capabilities = null)
    {
        var r = await w.CallAsync(p, HttpMethod.Post, "/v1/automation-runners/token", new
        {
            runnerId = install, protocolVersion = 1, supportedExecutionTargets = new[] { "desktop" }, capabilities = capabilities ?? ["model_attention_v1"],
            appVersion = "1.0.0", platform = "linux", concurrency = 1,
        });
        Assert.True(r.Status == HttpStatusCode.OK, r.Body.ToString());
        Assert.Equal("/v1/automation-runners/events", r.Body.GetProperty("eventsPath").GetString());
        return r.Body.GetProperty("token").GetString()!;
    }

    private static async Task<string> AutomationAsync(Workspace w, Person p)
    {
        var r = await w.CallAsync(p, HttpMethod.Post, "/v1/automations", new { name = "Report", instructions = "Summarize", schedule = Daily9, model = new { providerId = "anthropic", modelId = "claude" } });
        Assert.True(r.Status == HttpStatusCode.Created, r.Body.ToString());
        return r.Body.GetProperty("automation").GetProperty("id").GetString()!;
    }

    private static async Task<string> RunNowAsync(Workspace w, Person p, string automationId)
    {
        var r = await w.CallAsync(p, HttpMethod.Post, $"/v1/automations/{automationId}/run", new { });
        Assert.True(r.Status == HttpStatusCode.Accepted, r.Body.ToString());
        return r.Body.GetProperty("run").GetProperty("id").GetString()!;
    }

    private sealed record Sse(string? Id, string Event, string Data);

    /// <summary>An open runner stream: reads events as they arrive.</summary>
    private sealed class Stream : IAsyncDisposable
    {
        private readonly HttpResponseMessage _response;
        private readonly StreamReader _reader;
        private readonly CancellationTokenSource _cts = new();
        public HttpStatusCode Status => _response.StatusCode;
        public string? ContentType => _response.Content.Headers.ContentType?.MediaType;

        private Stream(HttpResponseMessage response, StreamReader reader) { _response = response; _reader = reader; }

        public static async Task<Stream> OpenAsync(HttpClient http, string token, string? lastEventId = null, bool push = false)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "/v1/automation-runners/events");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            if (lastEventId is not null) request.Headers.Add("Last-Event-ID", lastEventId);
            if (push) request.Headers.Add("x-openwork-remote-session-push", "1");
            var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
            return new Stream(response, new StreamReader(await response.Content.ReadAsStreamAsync()));
        }

        /// <summary>The next event, or null when the stream ended or nothing came in time.</summary>
        public async Task<Sse?> NextAsync(int timeoutMs = 5000)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
            timeout.CancelAfter(timeoutMs);
            string? id = null, type = null, data = null;
            try
            {
                while (true)
                {
                    var line = await _reader.ReadLineAsync(timeout.Token);
                    if (line is null) return null;
                    if (line.Length == 0) { if (type is not null) return new Sse(id, type, data ?? ""); continue; }
                    if (line.StartsWith("id: ", StringComparison.Ordinal)) id = line[4..];
                    else if (line.StartsWith("event: ", StringComparison.Ordinal)) type = line[7..];
                    else if (line.StartsWith("data: ", StringComparison.Ordinal)) data = line[6..];
                }
            }
            catch (OperationCanceledException) { return null; }
        }

        /// <summary>The next event that is not a keepalive.</summary>
        public async Task<Sse?> NextSignalAsync(int timeoutMs = 5000)
        {
            var deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
            while (DateTime.UtcNow < deadline)
            {
                var e = await NextAsync((int)Math.Max(1, (deadline - DateTime.UtcNow).TotalMilliseconds));
                if (e is null) return null;
                if (e.Event != "keepalive") return e;
            }
            return null;
        }

        /// <summary>True when the server closed the stream within the time.</summary>
        public async Task<bool> EndsAsync(int timeoutMs = 5000)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
            timeout.CancelAfter(timeoutMs);
            try
            {
                while (await _reader.ReadLineAsync(timeout.Token) is not null) { }
                return true;
            }
            catch (OperationCanceledException) { return false; }
        }

        public async ValueTask DisposeAsync()
        {
            await _cts.CancelAsync();
            _reader.Dispose();
            _response.Dispose();
            _cts.Dispose();
        }
    }

    [Fact]
    public async Task The_stream_announces_queued_work_and_cancellations_with_a_resumable_cursor()
    {
        var w = await Workspace.CreateAsync(factory);
        var token = await RunnerTokenAsync(w, w.Owner, "install-stream-1");
        var http = factory.Plain();
        await using var stream = await Stream.OpenAsync(http, token);
        Assert.Equal(HttpStatusCode.OK, stream.Status);
        Assert.Equal("text/event-stream", stream.ContentType);

        var automation = await AutomationAsync(w, w.Owner);
        var runId = await RunNowAsync(w, w.Owner, automation);
        var work = await stream.NextSignalAsync();
        Assert.NotNull(work);
        Assert.Equal("automation_work_available", work!.Event);
        var payload = JsonDocument.Parse(work.Data).RootElement;
        Assert.Equal("automation_work_available", payload.GetProperty("type").GetString());
        Assert.Equal(work.Id, payload.GetProperty("cursor").GetString());

        // The runner claims it; cancelling the held run is announced too (a queued one is cancelled on the spot and announces nothing).
        var claim = await w.SendAsync(Bearer(HttpMethod.Post, $"/v1/automation-runs/{runId}/claim", token));
        Assert.Equal(HttpStatusCode.OK, claim.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/automation-runs/{runId}/cancel")).Status);
        var cancel = await stream.NextSignalAsync();
        Assert.Equal("automation_cancellation_available", cancel!.Event);
        Assert.True(long.Parse(cancel.Id!) > long.Parse(work.Id!));

        // Reconnecting with the last cursor replays nothing already seen; one from before the cancellation gets just that.
        await using var resumed = await Stream.OpenAsync(http, token, cancel.Id);
        Assert.Null(await resumed.NextSignalAsync(700));
        await using var behind = await Stream.OpenAsync(http, token, work.Id);
        var replayed = await behind.NextSignalAsync();
        Assert.Equal(cancel.Id, replayed!.Id);
        Assert.Equal("automation_cancellation_available", replayed.Event);
    }

    [Fact]
    public async Task An_idle_stream_sends_keepalives_and_never_another_persons_or_workspaces_work()
    {
        var w = await Workspace.CreateAsync(factory);
        var other = await w.AddAsync();
        var elsewhere = await Workspace.CreateAsync(factory, "Elsewhere");
        var token = await RunnerTokenAsync(w, w.Owner, "install-idle-1");
        await using var stream = await Stream.OpenAsync(factory.Plain(), token);

        await RunNowAsync(w, other, await AutomationAsync(w, other));
        await RunNowAsync(elsewhere, elsewhere.Owner, await AutomationAsync(elsewhere, elsewhere.Owner));
        var seen = new List<Sse>();
        for (var i = 0; i < 3; i++) if (await stream.NextAsync(2000) is { } e) seen.Add(e);
        Assert.NotEmpty(seen);
        Assert.All(seen, e => Assert.Equal("keepalive", e.Event));
        Assert.All(seen, e => Assert.Null(e.Id));
    }

    [Fact]
    public async Task Refusals_a_session_only_runner_and_the_owner_leaving()
    {
        var w = await Workspace.CreateAsync(factory);
        Assert.Equal(HttpStatusCode.Unauthorized, (await factory.Plain().GetAsync("/v1/automation-runners/events")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.SendAsync(Bearer(HttpMethod.Get, "/v1/automation-runners/events", "not-a-runner-token"))).StatusCode);

        // A desktop asking for remote-session pushes learns the feature is off (remote sessions are not part of this build).
        var pushing = await RunnerTokenAsync(w, w.Owner, "install-push-1", ["remote_session_v1"]);
        await using (var push = await Stream.OpenAsync(factory.Plain(), pushing, push: true))
            Assert.Equal(HttpStatusCode.NotFound, push.Status);

        // A session-only runner keeps a stream but never hears about Automation work.
        var member = await w.AddAsync();
        var sessionOnly = await RunnerTokenAsync(w, member, "install-session-1", ["remote_session_only_v1"]);
        await using (var quiet = await Stream.OpenAsync(factory.Plain(), sessionOnly))
        {
            await RunNowAsync(w, member, await AutomationAsync(w, member));
            Assert.Null(await quiet.NextSignalAsync(800));
        }

        // The owner leaving ends the stream at the next owner check.
        var leaver = await w.AddAsync();
        var leaverToken = await RunnerTokenAsync(w, leaver, "install-leaver-1");
        await using var leaving = await Stream.OpenAsync(factory.Plain(), leaverToken);
        Assert.Equal(HttpStatusCode.OK, leaving.Status);
        Assert.Equal(HttpStatusCode.NoContent, (await w.SendAsync(w.As(w.Owner, HttpMethod.Delete, $"/v1/members/{leaver.MemberId}"))).StatusCode);
        Assert.True(await leaving.EndsAsync());
    }

    [Fact]
    public async Task Hints_older_than_a_week_are_pruned_by_the_scheduler()
    {
        var w = await Workspace.CreateAsync(factory);
        await RunnerTokenAsync(w, w.Owner, "install-prune-1");
        var runId = await RunNowAsync(w, w.Owner, await AutomationAsync(w, w.Owner));
        Assert.Equal(1, factory.WithDb(db => db.Set<AutomationRunnerNotification>().Count(n => n.RunId == runId)));
        await factory.TickAsync(DateTimeOffset.UtcNow.AddDays(6).ToUnixTimeMilliseconds());
        Assert.Equal(1, factory.WithDb(db => db.Set<AutomationRunnerNotification>().Count(n => n.RunId == runId)));
        await factory.TickAsync(DateTimeOffset.UtcNow.AddDays(8).ToUnixTimeMilliseconds());
        Assert.Equal(0, factory.WithDb(db => db.Set<AutomationRunnerNotification>().Count(n => n.RunId == runId)));
    }

    [Fact]
    public async Task A_desktop_run_is_audited_once_however_often_the_runner_reports_its_end()
    {
        var w = await Workspace.CreateAsync(factory);
        var token = await RunnerTokenAsync(w, w.Owner, "install-audit-1");
        var automation = await AutomationAsync(w, w.Owner);
        var runId = await RunNowAsync(w, w.Owner, automation);
        Assert.Equal(HttpStatusCode.OK, (await w.SendAsync(Bearer(HttpMethod.Post, $"/v1/automation-runs/{runId}/claim", token))).StatusCode);
        var result = new { attempt = 1, status = "succeeded", sessionId = "s-1", workspaceId = "ws-1", resultSummary = "Done", usage = new { inputTokens = 1, outputTokens = 2, costMicros = (int?)null }, error = (object?)null };
        for (var i = 0; i < 3; i++)
            Assert.Equal(HttpStatusCode.OK, (await w.SendAsync(Bearer(HttpMethod.Post, $"/v1/automation-runs/{runId}/complete", token, result))).StatusCode);
        var events = factory.WithDb(db => db.Set<WorkAI360.Api.Domain.OrgAdmin.AuditEvent>().AsNoTracking().Where(e => e.OrganizationId == w.OrgId).Select(e => new { e.Action, e.EnvelopeJson }).ToList());
        var completed = Assert.Single(events, e => e.Action == "automation_run.completed");
        Assert.Contains(w.Owner.UserId, completed.EnvelopeJson); // the owner's desktop reported it
        Assert.DoesNotContain("Done", completed.EnvelopeJson); // never the summary
        Assert.Contains(events, e => e.Action == "automation.create");
        Assert.Contains(events, e => e.Action == "automation.run.start");
    }

    private static object Inventory(int workspaces = 1, int models = 1, string platform = "darwin") => new
    {
        computer = new { label = "Avery's MacBook", platform, appVersion = "1.4.0", extra = "kept" },
        workspaces = Enumerable.Range(0, workspaces).Select(i => new
        {
            workspaceId = $"ws-{i}", name = $"Workspace {i}", active = i == 0, engine = "v2",
            defaultModel = i == 0 ? new { providerId = "anthropic", modelId = "claude", variant = "fast" } : null,
            models = Enumerable.Range(0, models).Select(j => new { providerId = "anthropic", modelId = $"m{j}", name = $"Model {j}" }).ToArray(),
        }).ToArray(),
    };

    [Fact]
    public async Task Inventory_is_stored_per_runner_validated_and_needs_a_registration()
    {
        var w = await Workspace.CreateAsync(factory);
        var token = await RunnerTokenAsync(w, w.Owner, "install-inventory-1");
        var r = await w.SendAsync(Bearer(HttpMethod.Put, "/v1/automation-runner/inventory", token, Inventory(2, 3)));
        var text = await r.Content.ReadAsStringAsync();
        Assert.True(r.StatusCode == HttpStatusCode.OK, text);
        var body = JsonDocument.Parse(text).RootElement;
        Assert.True(body.GetProperty("ok").GetBoolean());
        Assert.True(body.GetProperty("updatedAt").GetInt64() > 0);
        Assert.Equal("no-store", r.Headers.CacheControl?.ToString());
        var stored = factory.WithDb(db => db.Set<AutomationRunner>().AsNoTracking().Single(x => x.InstallId == "install-inventory-1" && x.OwnerMemberId == w.Owner.MemberId));
        var saved = JsonDocument.Parse(stored.InventoryJson!).RootElement;
        Assert.Equal("Avery's MacBook", saved.GetProperty("computer").GetProperty("label").GetString());
        Assert.Equal("kept", saved.GetProperty("computer").GetProperty("extra").GetString()); // objects are not strict
        Assert.Equal(2, saved.GetProperty("workspaces").GetArrayLength());
        Assert.NotNull(stored.InventoryUpdatedAt);

        async Task<string> Refused(object inventory)
        {
            var bad = await w.SendAsync(Bearer(HttpMethod.Put, "/v1/automation-runner/inventory", token, inventory));
            Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
            return JsonDocument.Parse(await bad.Content.ReadAsStringAsync()).RootElement.GetProperty("message").GetString()!;
        }
        Assert.Equal("computer.platform: Invalid option: expected one of \"darwin\"|\"win32\"|\"linux\"", await Refused(Inventory(platform: "amiga")));
        Assert.Equal("workspaces: Too big: expected array to have <=50 items", await Refused(Inventory(51)));
        Assert.Equal("workspaces.0.models: Too big: expected array to have <=200 items", await Refused(Inventory(1, 201)));
        Assert.Equal("computer: Invalid input: expected object, received undefined", await Refused(new { workspaces = Array.Empty<object>() }));
        Assert.Equal("workspaces.0.active: Invalid input: expected boolean, received undefined",
            await Refused(new { computer = new { label = "x", platform = "linux", appVersion = "1" }, workspaces = new[] { new { workspaceId = "a", name = "b", engine = "v1", defaultModel = (object?)null, models = Array.Empty<object>() } } }));

        Assert.Equal(HttpStatusCode.Unauthorized, (await w.SendAsync(Bearer(HttpMethod.Put, "/v1/automation-runner/inventory", "nope", Inventory()))).StatusCode);
        // A runner whose registration is gone must register again.
        factory.WithDb(db => db.Set<AutomationRunner>().Where(x => x.InstallId == "install-inventory-1" && x.OwnerMemberId == w.Owner.MemberId).ExecuteDelete());
        var gone = await w.SendAsync(Bearer(HttpMethod.Put, "/v1/automation-runner/inventory", token, Inventory()));
        Assert.Equal(HttpStatusCode.NotFound, gone.StatusCode);
        Assert.Contains("runner_not_registered", await gone.Content.ReadAsStringAsync());
    }
}
