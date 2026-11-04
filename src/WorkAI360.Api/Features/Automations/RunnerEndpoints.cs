using System.Text.Json;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Features.Library;
using LibraryZod = WorkAI360.Api.Features.Library.Zod;

namespace WorkAI360.Api.Features.Automations;

/// <summary>What a desktop runner calls: register for a credential, look for work, claim a run, keep its lease, report steps, finish.</summary>
public static class RunnerEndpoints
{
    private static readonly string[] EventTypes = ["user", "assistant", "capability_search", "capability_execution", "usage", "warning", "terminal"];
    private static readonly string[] ErrorCodes =
    [
        "owner_membership_lost", "model_access_lost", "provider_unavailable", "connect_access_unavailable", "openwork_web_access_required", "execution_runtime_unavailable",
        "execution_failed", "execution_timed_out", "runner_unavailable", "cancelled", "lease_lost", "internal_error",
    ];

    private static IResult Json(object body, int status = 200) => Results.Json(body, statusCode: status);

    /// <summary>Authenticates the runner from its bearer token (401 <c>runner_unauthorized</c> otherwise) and answers the reference's error shapes.</summary>
    private static async Task<IResult> RunAsync(HttpContext ctx, RunnerAuth auth, Func<RunnerIdentity, Task<IResult>> handler)
    {
        var identity = await auth.AuthenticateAsync(ctx);
        if (identity is null) return Json(new { error = "runner_unauthorized" }, 401);
        try { return await handler(identity); }
        catch (Invalid invalid) { return invalid.ToResult(); }
        catch (AutomationFailure failed) { return failed.ToResult(); }
    }

    /// <summary>The server's own address as the runner reaches it: the credential is only good for the Den it was minted by.</summary>
    private static string Audience(HttpContext ctx)
    {
        var prefix = ctx.Request.Headers["x-forwarded-prefix"].ToString().TrimEnd('/');
        return $"{ctx.Request.Scheme}://{ctx.Request.Host}{(prefix == "/api/den" ? prefix : "")}";
    }

    private static int PositiveInt(JsonElement body, string name)
    {
        try { return (int)Reader.Int(body, name, [], 1, int.MaxValue); }
        catch (Invalid e) when (e.Issues[0].Code == "too_small") { throw new Invalid(name, "Too small: expected number to be >0", "too_small"); }
    }

    private static string? NullableStr(JsonElement body, string name, int max)
    {
        if (!body.TryGetProperty(name, out var v)) throw new Invalid(name, "Invalid input: expected string, received undefined");
        return v.ValueKind == JsonValueKind.Null ? null : Reader.Str(body, name, [], 1, max);
    }

    public static void Map(WebApplication app)
    {
        app.MapPost("/v1/automation-runners/token", async (HttpContext ctx, OrgAccess access, RunnerAuth auth, RunnerRegistry registry) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            try
            {
                var registration = ParseRegistration(await LibraryZod.BodyAsync(ctx));
                await registry.RegisterAsync(context!.Organization.Id, context.Member.Id, registration, AutomationService.Now());
                var (token, expiresAt) = auth.Issue(context.Organization.Id, context.Member.Id, registration.RunnerId, registration.Capabilities, Audience(ctx));
                return Json(new { token, expiresAt, eventsPath = "/v1/automation-runners/events" });
            }
            catch (Invalid invalid) { return invalid.ToResult(); }
        });

        app.MapGet("/v1/automation-runner/work", (HttpContext ctx, RunnerAuth auth, RunnerRegistry registry, RunQueue queue, AutomationService service) =>
            RunAsync(ctx, auth, async who =>
            {
                var now = AutomationService.Now();
                // Asking for work is what keeps a desktop "connected".
                await registry.TouchAsync(who, now);
                var items = new List<object>();
                if (!await registry.SessionOnlyAsync(who) && await service.TargetAllowedAsync(who.OrganizationId, "desktop"))
                    items.AddRange(await queue.DiscoverAsync(who, now, 20));
                ctx.Response.Headers.CacheControl = "no-store";
                // OpenCode v2 is the default engine for every desktop.
                return Json(new { items, enginePolicy = new { upgrade = true } });
            }));

        // The stream the token response names. A desktop runner hears when work or a cancellation is waiting (it then polls `work` or its heartbeat);
        // idle streams send keepalives and never write presence. The cursor (Last-Event-ID) is the database id of the last hint, so a reconnect to any
        // instance resumes in order.
        app.MapGet("/v1/automation-runners/events", async (HttpContext ctx, RunnerAuth auth, RunnerRegistry registry, AutomationService service, IOptions<AutomationOptions> options) =>
        {
            var who = await auth.AuthenticateAsync(ctx);
            if (who is null) return Json(new { error = "runner_unauthorized" }, 401);
            // Remote sessions are not part of this build, so a desktop asking for their pushes learns at once that the feature is off and keeps polling.
            if (ctx.Request.Headers["x-openwork-remote-session-push"].ToString() == "1" && who.Capabilities.Contains("remote_session_v1"))
                return Json(new { error = "feature_disabled", message = "Remote-session push is not enabled for this organization." }, 404);
            var requested = ctx.Request.Headers["Last-Event-ID"].ToString();
            var cursor = long.TryParse(requested, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var c) && c >= 0 ? c : 0;
            var sessionOnly = await registry.SessionOnlyAsync(who);
            await StreamAsync(ctx, who, cursor, sessionOnly, registry, service, options.Value);
            return Results.Empty;
        });

        app.MapPut("/v1/automation-runner/inventory", (HttpContext ctx, RunnerAuth auth, RunnerRegistry registry) =>
            RunAsync(ctx, auth, async who =>
            {
                var body = await LibraryZod.BodyAsync(ctx);
                ValidateInventory(body);
                var now = AutomationService.Now();
                if (!await registry.SaveInventoryAsync(who, body.GetRawText(), now)) return Json(new { error = "runner_not_registered" }, 404);
                ctx.Response.Headers.CacheControl = "no-store";
                return Json(new { ok = true, updatedAt = now, enginePolicy = new { upgrade = true } });
            }));

        app.MapPost("/v1/automation-runs/{id}/claim", (string id, HttpContext ctx, RunnerAuth auth, RunnerRegistry registry, RunnerService runners) =>
            RunAsync(ctx, auth, async who =>
            {
                if (await registry.SessionOnlyAsync(who) || !await runners.DesktopAllowedAsync(who)) return Json(new { assignment = (object?)null });
                return Json(new { assignment = await runners.ClaimAsync(who, id) });
            }));

        app.MapPost("/v1/automation-runs/{id}/heartbeat", (string id, HttpContext ctx, RunnerAuth auth, RunQueue queue) =>
            RunAsync(ctx, auth, async who =>
            {
                var body = await LibraryZod.BodyAsync(ctx);
                var attempt = PositiveInt(body, "attempt");
                var beat = await queue.HeartbeatAsync(who, id, attempt, AutomationService.Now());
                return beat is { } b ? Json(new { attempt = b.Attempt, leaseValid = true, cancelRequested = b.CancelRequested, leaseExpiresAt = b.LeaseExpiresAt }) : Json(new { error = "runner_lease_lost" }, 409);
            }));

        app.MapPost("/v1/automation-runs/{id}/events", (string id, HttpContext ctx, RunnerAuth auth, RunQueue queue) =>
            RunAsync(ctx, auth, async who =>
            {
                var body = await LibraryZod.BodyAsync(ctx);
                var attempt = PositiveInt(body, "attempt");
                var sequence = PositiveInt(body, "sequence");
                var type = Reader.Str(body, "type", [], 1, 64, trim: false);
                if (!EventTypes.Contains(type)) throw new Invalid("type", $"Invalid option: expected one of {string.Join("|", EventTypes.Select(t => $"\"{t}\""))}", "invalid_value");
                if (!body.TryGetProperty("payload", out var payload)) throw new Invalid("payload", "Invalid input: expected record, received undefined");
                if (payload.ValueKind != JsonValueKind.Object) throw new Invalid("payload", $"Invalid input: expected record, received {Reader.Kind(payload)}");
                Reader.Int(body, "createdAt", [], 0, long.MaxValue);
                var created = await queue.AppendEventAsync(who, id, attempt, sequence, type, payload.GetRawText(), AutomationService.Now());
                return Json(new { @event = AutomationWire.Of(created) });
            }));

        app.MapPost("/v1/automation-runs/{id}/complete", (string id, HttpContext ctx, RunnerAuth auth, RunnerService runners) =>
            RunAsync(ctx, auth, async who =>
            {
                var result = ParseResult(await LibraryZod.BodyAsync(ctx));
                return Json(new { run = AutomationWire.Of(await runners.CompleteAsync(who, id, result)) });
            }));
    }

    /// <summary>The event loop of one runner stream (the reference's timings: poll 1 s doubling to 15 s while idle, keepalive every 15 s).</summary>
    private static async Task StreamAsync(HttpContext ctx, RunnerIdentity who, long cursor, bool sessionOnly, RunnerRegistry registry, AutomationService service, AutomationOptions options)
    {
        var response = ctx.Response;
        response.StatusCode = 200;
        response.ContentType = "text/event-stream";
        response.Headers.CacheControl = "no-cache";
        response.Headers["X-Accel-Buffering"] = "no";
        var aborted = ctx.RequestAborted;
        long lastKeepalive = 0;
        var lastOwnerCheck = Environment.TickCount64;
        var delay = options.StreamPollMinMs;
        try
        {
            await response.Body.FlushAsync(aborted);
            while (!aborted.IsCancellationRequested)
            {
                if (AutomationService.Now() >= who.ExpiresAt) break;
                if (Environment.TickCount64 - lastOwnerCheck >= options.StreamOwnerCheckMs)
                {
                    // A runner forgotten, or an owner who left, ends the stream; the desktop reconnects and is refused.
                    if (!await registry.RegisteredAsync(who) || !await service.OwnerActiveAsync(who.OrganizationId, who.OwnerMemberId)) break;
                    lastOwnerCheck = Environment.TickCount64;
                }
                var notifications = sessionOnly ? [] : await registry.NotificationsAsync(who, cursor);
                foreach (var n in notifications)
                {
                    cursor = n.Id;
                    var type = n.EventType == "work_available" ? "automation_work_available" : "automation_cancellation_available";
                    var id = n.Id.ToString(System.Globalization.CultureInfo.InvariantCulture);
                    await WriteEventAsync(response, id, type, JsonSerializer.Serialize(new { type, cursor = id }), aborted);
                }
                if (notifications.Count == 0 && Environment.TickCount64 - lastKeepalive >= options.StreamKeepaliveMs)
                {
                    await WriteEventAsync(response, null, "keepalive", "{}", aborted);
                    lastKeepalive = Environment.TickCount64;
                }
                delay = notifications.Count > 0 ? options.StreamPollMinMs : Math.Min(options.StreamPollMaxMs, Math.Max(options.StreamPollMinMs, delay) * 2);
                var untilKeepalive = options.StreamKeepaliveMs - (Environment.TickCount64 - lastKeepalive);
                var wait = (int)Math.Min(delay, Math.Max(options.StreamPollMinMs, untilKeepalive));
                await Task.Delay(wait, aborted);
            }
        }
        catch (OperationCanceledException) { /* the desktop went away */ }
        catch (IOException) { /* the connection broke while writing */ }
    }

    private static async Task WriteEventAsync(HttpResponse response, string? id, string type, string data, CancellationToken ct)
    {
        var text = (id is null ? "" : $"id: {id}\n") + $"event: {type}\ndata: {data}\n\n";
        await response.WriteAsync(text, ct);
        await response.Body.FlushAsync(ct);
    }

    private static readonly string[] Platforms = ["darwin", "win32", "linux"];

    /// <summary>The reference's inventory schema: a computer and up to 50 workspaces with up to 200 models each. Objects are not strict, so either side can add fields.</summary>
    private static void ValidateInventory(JsonElement body)
    {
        if (!body.TryGetProperty("computer", out var computer)) throw new Invalid("computer", "Invalid input: expected object, received undefined");
        if (computer.ValueKind != JsonValueKind.Object) throw new Invalid("computer", $"Invalid input: expected object, received {Reader.Kind(computer)}");
        Reader.Str(computer, "label", ["computer"], 1, 120);
        var platform = Reader.Str(computer, "platform", ["computer"], 1, 16, trim: false);
        if (!Platforms.Contains(platform)) throw new Invalid("computer.platform", "Invalid option: expected one of \"darwin\"|\"win32\"|\"linux\"", "invalid_value");
        Reader.Str(computer, "appVersion", ["computer"], 1, 80);
        if (!body.TryGetProperty("workspaces", out var workspaces)) throw new Invalid("workspaces", "Invalid input: expected array, received undefined");
        if (workspaces.ValueKind != JsonValueKind.Array) throw new Invalid("workspaces", $"Invalid input: expected array, received {Reader.Kind(workspaces)}");
        if (workspaces.GetArrayLength() > 50) throw new Invalid([(["workspaces"], "too_big", "Too big: expected array to have <=50 items")]);
        var i = 0;
        foreach (var w in workspaces.EnumerateArray())
        {
            string[] at = ["workspaces", i.ToString(System.Globalization.CultureInfo.InvariantCulture)];
            var path = string.Join('.', at);
            if (w.ValueKind != JsonValueKind.Object) throw new Invalid(path, $"Invalid input: expected object, received {Reader.Kind(w)}");
            Reader.Str(w, "workspaceId", at, 1, 240);
            Reader.Str(w, "name", at, 1, 120);
            if (!w.TryGetProperty("active", out var active) || active.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                throw new Invalid($"{path}.active", $"Invalid input: expected boolean, received {(w.TryGetProperty("active", out var a) ? Reader.Kind(a) : "undefined")}");
            var engine = Reader.Str(w, "engine", at, 1, 8, trim: false);
            if (engine is not ("v1" or "v2")) throw new Invalid($"{path}.engine", "Invalid option: expected one of \"v1\"|\"v2\"", "invalid_value");
            if (!w.TryGetProperty("defaultModel", out var dm)) throw new Invalid($"{path}.defaultModel", "Invalid input: expected object, received undefined");
            if (dm.ValueKind != JsonValueKind.Null)
            {
                if (dm.ValueKind != JsonValueKind.Object) throw new Invalid($"{path}.defaultModel", $"Invalid input: expected object, received {Reader.Kind(dm)}");
                string[] dmAt = [.. at, "defaultModel"];
                Reader.Str(dm, "providerId", dmAt, 1, 160);
                Reader.Str(dm, "modelId", dmAt, 1, 160);
                if (Reader.HasValue(dm, "variant")) Reader.Str(dm, "variant", dmAt, 1, 60);
            }
            if (!w.TryGetProperty("models", out var models)) throw new Invalid($"{path}.models", "Invalid input: expected array, received undefined");
            if (models.ValueKind != JsonValueKind.Array) throw new Invalid($"{path}.models", $"Invalid input: expected array, received {Reader.Kind(models)}");
            if (models.GetArrayLength() > 200) throw new Invalid([([.. at, "models"], "too_big", "Too big: expected array to have <=200 items")]);
            var j = 0;
            foreach (var m in models.EnumerateArray())
            {
                string[] mAt = [.. at, "models", j.ToString(System.Globalization.CultureInfo.InvariantCulture)];
                if (m.ValueKind != JsonValueKind.Object) throw new Invalid(string.Join('.', mAt), $"Invalid input: expected object, received {Reader.Kind(m)}");
                Reader.Str(m, "providerId", mAt, 1, 160);
                Reader.Str(m, "modelId", mAt, 1, 160);
                Reader.Str(m, "name", mAt, 1, 200);
                j++;
            }
            i++;
        }
    }

    private static RunnerRegistration ParseRegistration(JsonElement body)
    {
        var runnerId = Reader.Str(body, "runnerId", [], 8, 160);
        if (!body.TryGetProperty("protocolVersion", out var p)) throw new Invalid("protocolVersion", "Invalid input: expected 1, received undefined");
        if (p.ValueKind != JsonValueKind.Number || !p.TryGetInt32(out var version) || version != 1) throw new Invalid("protocolVersion", "Invalid input: expected 1", "invalid_value");
        if (!body.TryGetProperty("supportedExecutionTargets", out var targets)) throw new Invalid("supportedExecutionTargets", "Invalid input: expected array, received undefined");
        if (targets.ValueKind != JsonValueKind.Array) throw new Invalid("supportedExecutionTargets", $"Invalid input: expected array, received {Reader.Kind(targets)}");
        if (targets.GetArrayLength() != 1) throw new Invalid([(["supportedExecutionTargets"], "too_small", "Too small: expected array to have >=1 items")]);
        if (targets[0].ValueKind != JsonValueKind.String || targets[0].GetString() != "desktop") throw new Invalid("supportedExecutionTargets.0", "Invalid input: expected \"desktop\"", "invalid_value");
        var capabilities = new List<string>();
        if (body.TryGetProperty("capabilities", out var caps))
        {
            if (caps.ValueKind != JsonValueKind.Array) throw new Invalid("capabilities", $"Invalid input: expected array, received {Reader.Kind(caps)}");
            if (caps.GetArrayLength() > 5) throw new Invalid([(["capabilities"], "too_big", "Too big: expected array to have <=5 items")]);
            foreach (var cap in caps.EnumerateArray())
            {
                var value = cap.ValueKind == JsonValueKind.String ? cap.GetString()! : "";
                if (!RunnerCapability.All.Contains(value)) throw new Invalid("capabilities", $"Invalid option: expected one of {string.Join("|", RunnerCapability.All.Select(c => $"\"{c}\""))}", "invalid_value");
                capabilities.Add(value);
            }
        }
        var appVersion = Reader.Str(body, "appVersion", [], 1, 80);
        var platform = Reader.Str(body, "platform", [], 1, 16, trim: false);
        if (platform is not ("darwin" or "win32" or "linux")) throw new Invalid("platform", "Invalid option: expected one of \"darwin\"|\"win32\"|\"linux\"", "invalid_value");
        var concurrency = (int)Reader.Int(body, "concurrency", [], 1, 4);
        return new RunnerRegistration(runnerId, 1, capabilities, appVersion, platform, concurrency);
    }

    private static RunnerResult ParseResult(JsonElement body)
    {
        var attempt = PositiveInt(body, "attempt");
        var status = Reader.Str(body, "status", [], 1, 16, trim: false);
        if (status is not ("succeeded" or "failed" or "cancelled")) throw new Invalid("status", "Invalid option: expected one of \"succeeded\"|\"failed\"|\"cancelled\"", "invalid_value");
        var sessionId = NullableStr(body, "sessionId", 240);
        var workspaceId = NullableStr(body, "workspaceId", 240);
        string? summary = null;
        if (!body.TryGetProperty("resultSummary", out var s)) throw new Invalid("resultSummary", "Invalid input: expected string, received undefined");
        if (s.ValueKind != JsonValueKind.Null)
        {
            summary = Reader.Str(body, "resultSummary", [], 0, 20_000, trim: false);
        }
        if (!body.TryGetProperty("usage", out var usage)) throw new Invalid("usage", "Invalid input: expected object, received undefined");
        if (usage.ValueKind != JsonValueKind.Object) throw new Invalid("usage", $"Invalid input: expected object, received {Reader.Kind(usage)}");
        var usageValues = new Dictionary<string, long?>();
        foreach (var name in new[] { "inputTokens", "outputTokens", "costMicros" })
        {
            if (!usage.TryGetProperty(name, out var v)) throw new Invalid($"usage.{name}", "Invalid input: expected number, received undefined");
            usageValues[name] = v.ValueKind == JsonValueKind.Null ? null : Reader.Int(usage, name, ["usage"], 0, long.MaxValue);
        }
        string? errorJson = null;
        string? errorCode = null;
        string? errorMessage = null;
        if (!body.TryGetProperty("error", out var error)) throw new Invalid("error", "Invalid input: expected object, received undefined");
        if (error.ValueKind != JsonValueKind.Null)
        {
            if (error.ValueKind != JsonValueKind.Object) throw new Invalid("error", $"Invalid input: expected object, received {Reader.Kind(error)}");
            errorCode = Reader.Str(error, "code", ["error"], 1, 64, trim: false);
            if (!ErrorCodes.Contains(errorCode)) throw new Invalid("error.code", $"Invalid option: expected one of {string.Join("|", ErrorCodes.Select(c => $"\"{c}\""))}", "invalid_value");
            errorMessage = Reader.Str(error, "message", ["error"], 1, 2000);
            if (!error.TryGetProperty("retryable", out var retry)) throw new Invalid("error.retryable", "Invalid input: expected boolean, received undefined");
            if (retry.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) throw new Invalid("error.retryable", $"Invalid input: expected boolean, received {Reader.Kind(retry)}");
            errorJson = JsonSerializer.Serialize(new { code = errorCode, message = errorMessage, retryable = retry.GetBoolean() });
        }
        return new RunnerResult(attempt, status, sessionId, workspaceId, summary, JsonSerializer.Serialize(new { inputTokens = usageValues["inputTokens"], outputTokens = usageValues["outputTokens"], costMicros = usageValues["costMicros"] }), errorJson, errorCode, errorMessage);
    }
}

public sealed record RunnerResult(int Attempt, string Status, string? SessionId, string? WorkspaceId, string? Summary, string UsageJson, string? ErrorJson, string? ErrorCode, string? ErrorMessage);
