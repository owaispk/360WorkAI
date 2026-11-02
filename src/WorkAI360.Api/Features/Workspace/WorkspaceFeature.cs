using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Features.Library;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Features.Workspace;

/// <summary>
/// Workflows, run receipts, generated views and apps, the Apps catalog, the removed Memory Bank's answers, and webhook ingress. See
/// docs/features/workspace.md for what each route does and what this build leaves out.
/// </summary>
public sealed class WorkspaceFeature : IFeature
{
    public void AddServices(IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<WorkspaceOptions>(configuration.GetSection(WorkspaceOptions.Section));
        services.AddSingleton<AuthoringSources>();
        services.AddScoped<WorkflowTools>();
        services.AddScoped<WorkflowService>();
        services.AddScoped<ArtifactViewService>();
        services.AddScoped<McpAppCatalog>();
        services.AddScoped<IMyLibrarySource, WorkflowLibrarySource>();
        services.AddScoped<WorkspaceRunner>();
        services.AddScoped<ICapabilityProvider, WorkflowCapabilityProvider>();
        services.AddScoped<IMcpToolProvider, WorkflowAuthoringTools>();
    }

    public void MapEndpoints(WebApplication app)
    {
        MapMemory(app);
        MapWorkflows(app);
        MapViews(app);
        MapApps(app);
        MapWebhooks(app);
        MapDirectUploads(app);
    }

    private static IResult Ok(JsonNode body, int status = 200) => Results.Json(body, statusCode: status);

    // ---------------------------------------------------------------- the removed Memory Bank

    private const string MemoryRemoved = "The Memory Bank feature has been removed. Saved memories no longer exist and new memories cannot be created.";

    /// <summary>
    /// The Memory Bank was removed, but published desktop builds still call these routes, so they answer in the shapes those builds tolerate: an
    /// empty list (a clean empty state), a 404 for any delete (the builds treat it as "already gone"), and 410 for a write, so nothing can believe a
    /// memory was saved. Nothing is stored.
    /// </summary>
    private static void MapMemory(WebApplication app)
    {
        app.MapGet("/v1/memory", async (HttpContext ctx, OrgAccess access) => (await access.ResolveUserAsync(ctx)).Failure ?? Results.Json(new { memories = Array.Empty<object>() }));
        app.MapGet("/v1/memory/search", async (HttpContext ctx, OrgAccess access) => (await access.ResolveUserAsync(ctx)).Failure ?? Results.Json(new { results = Array.Empty<object>() }));
        app.MapDelete("/v1/memory/{id}", async (string id, HttpContext ctx, OrgAccess access) => (await access.ResolveUserAsync(ctx)).Failure ?? Results.Json(new { error = "memory_not_found" }, statusCode: 404));
        app.MapPost("/v1/memory", () => Results.Json(new { error = "deprecated", message = MemoryRemoved }, statusCode: 410));
    }

    // ---------------------------------------------------------------- reading request bodies and queries

    private static List<(string[] Path, string Code, string Message)> Collect(params Action[] reads)
    {
        var issues = new List<(string[] Path, string Code, string Message)>();
        foreach (var read in reads)
        {
            try { read(); }
            catch (Invalid invalid) { issues.AddRange(invalid.Issues); }
        }
        return issues;
    }

    private static void ThrowIf(List<(string[] Path, string Code, string Message)> issues)
    {
        if (issues.Count > 0) throw new Invalid(issues);
    }

    private static JsonNode? Node(JsonElement body, string name) => body.TryGetProperty(name, out var v) ? JsonNode.Parse(v.GetRawText()) : null;

    private static List<RequiredCapability> ReadCapabilities(JsonElement body)
    {
        var list = new List<RequiredCapability>();
        if (!body.TryGetProperty("requiredCapabilities", out var raw)) throw new Invalid("requiredCapabilities", "Invalid input: expected array, received undefined");
        if (raw.ValueKind != JsonValueKind.Array) throw new Invalid("requiredCapabilities", $"Invalid input: expected array, received {Zod.Kind(raw)}");
        if (raw.GetArrayLength() > 100) throw new Invalid("requiredCapabilities", "Too big: expected array to have <=100 items", "too_big");
        var issues = new List<(string[] Path, string Code, string Message)>();
        var index = 0;
        foreach (var item in raw.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object) { issues.Add((["requiredCapabilities", index.ToString(CultureInfo.InvariantCulture)], "invalid_type", $"Invalid input: expected object, received {Zod.Kind(item)}")); index++; continue; }
            string? name = null, path = null;
            issues.AddRange(Collect(
                () => name = Zod.Str(item, "capabilityName", max: 255, path: $"requiredCapabilities.{index}.capabilityName"),
                () => path = Zod.Str(item, "scriptPath", max: 255, path: $"requiredCapabilities.{index}.scriptPath")));
            if (name is not null && path is not null) list.Add(new RequiredCapability(name, path));
            index++;
        }
        ThrowIf(issues);
        return list;
    }

    private static WorkflowService.Draft ReadDraft(JsonElement body, out string? configObjectId, out string? receiptId, bool withConfigObjectId, bool withReceipt)
    {
        string? name = null, description = null, code = null;
        List<RequiredCapability> required = [];
        configObjectId = null;
        receiptId = null;
        string? cob = null, rcp = null;
        var issues = Collect(
            () => name = Zod.Str(body, "name", max: 255),
            () => description = Zod.Str(body, "description", required: false, min: 0, max: 4000),
            () => code = Zod.Str(body, "code", trim: false, max: 200_000),
            () => required = ReadCapabilities(body),
            () => { if (withConfigObjectId) cob = Zod.Str(body, "configObjectId", trim: false, max: 160); },
            () => { if (withReceipt) rcp = Zod.Str(body, "receiptId", trim: false, max: 160); });
        // The reference lists the issues in the order of its schema, requiredCapabilities after the optional JSON fields.
        ThrowIf(issues);
        configObjectId = cob;
        receiptId = rcp;
        return new WorkflowService.Draft(name!, description, code!, Node(body, "exampleInput"), body.TryGetProperty("exampleInput", out _), Node(body, "inputSchema"), Node(body, "outputSchema"), required);
    }

    private static int? CoerceInt(HttpContext ctx, string name, int min, int max)
    {
        if (!ctx.Request.Query.ContainsKey(name)) return null;
        var raw = ctx.Request.Query[name].ToString();
        var d = 0d;
        if (raw.Trim().Length > 0 && !double.TryParse(raw.Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out d)) throw new Invalid(name, "Invalid input: expected number, received NaN");
        if (d != Math.Floor(d)) throw new Invalid(name, "Invalid input: expected int, received number");
        if (d < min) throw new Invalid(name, $"Too small: expected number to be >={min}", "too_small");
        if (d > max) throw new Invalid(name, $"Too big: expected number to be <={max}", "too_big");
        return (int)d;
    }

    private static long? CoerceLong(HttpContext ctx, string name, long min, long max)
    {
        if (!ctx.Request.Query.ContainsKey(name)) return null;
        var raw = ctx.Request.Query[name].ToString();
        var d = 0d;
        if (raw.Trim().Length > 0 && !double.TryParse(raw.Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out d)) throw new Invalid(name, "Invalid input: expected number, received NaN");
        if (d != Math.Floor(d)) throw new Invalid(name, "Invalid input: expected int, received number");
        if (d < min) throw new Invalid(name, $"Too small: expected number to be >={min}", "too_small");
        if (d > max) throw new Invalid(name, $"Too big: expected number to be <={max}", "too_big");
        return (long)d;
    }

    private static Keyset.Cursor? ReadCursor(HttpContext ctx)
    {
        if (!ctx.Request.Query.ContainsKey("cursor")) return null;
        var raw = ctx.Request.Query["cursor"].ToString();
        if (raw.Length < 1) throw new Invalid("cursor", "Too small: expected string to have >=1 characters", "too_small");
        if (raw.Length > 200) throw new Invalid("cursor", "Too big: expected string to have <=200 characters", "too_big");
        return Keyset.Decode(raw) ?? throw new Invalid("cursor", "Invalid cursor.", "custom");
    }

    private static string? ReadTimeZone(JsonElement body, string name = "timeZone")
    {
        if (!body.TryGetProperty(name, out _)) return null;
        var zone = Zod.Str(body, name, trim: false, min: 1, max: 100);
        if (zone is not null && !ArtifactRuntime.ValidZone(zone)) throw new Invalid(name, "Expected an IANA time zone", "custom");
        return zone;
    }

    private static bool IdTooLong(string value) => value.Length is < 1 or > 160;

    // ---------------------------------------------------------------- workflows

    private static void MapWorkflows(WebApplication app)
    {
        // The reference keeps two one-release aliases for these routes (/v1/codemode-scripts, and /v1/programs/* without its own root).
        foreach (var prefix in new[] { "/v1/workflows", "/v1/codemode-scripts", "/v1/programs" }) MapWorkflowRoutes(app, prefix);

        app.MapGet("/v1/workflow-runs", (HttpContext ctx, WorkspaceRunner run, WorkflowService svc) => run.RunAsync(ctx, async a => await RunsAsync(ctx, a, svc)));
        // One-release compatibility alias the reference keeps.
        app.MapGet("/v1/codemode-runs", (HttpContext ctx, WorkspaceRunner run, WorkflowService svc) => run.RunAsync(ctx, async a => await RunsAsync(ctx, a, svc)));
    }

    private static void MapWorkflowRoutes(WebApplication app, string prefix)
    {
        var root = prefix == "/v1/programs" ? null : prefix;
        if (root is not null) app.MapGet(root, (HttpContext ctx, WorkspaceRunner run, WorkflowService svc) => run.RunAsync(ctx, async a => Ok(new JsonObject { ["items"] = await svc.ListAccessibleAsync(a) })));

        if (root is not null) app.MapPost(root, (HttpContext ctx, WorkspaceRunner run, WorkflowService svc) => run.RunAsync(ctx, async a =>
        {
            var body = await Zod.BodyAsync(ctx);
            string? pluginId = null, name = null, description = null, code = null, receiptId = null;
            var issues = Collect(
                () => pluginId = Zod.Str(body, "pluginId", required: false, max: 160),
                () => name = Zod.Str(body, "name", max: 255),
                () => description = Zod.Str(body, "description", required: false, min: 0, max: 4000),
                () => code = Zod.Str(body, "code", required: false, trim: false, max: 200_000),
                () => receiptId = Zod.Str(body, "receiptId", required: false, trim: false, max: 160));
            if (issues.Count == 0 && code is null && receiptId is null) issues.Add(([], "custom", "Provide code or receiptId."));
            ThrowIf(issues);
            var saved = await svc.SaveAsync(a, new WorkflowService.SaveRequest(pluginId, name!, description, code, receiptId, body.TryGetProperty("currentInput", out _), Node(body, "currentInput"), Node(body, "inputSchema"), Node(body, "outputSchema")));
            return Ok(saved, 201);
        }));

        app.MapPost(prefix + "/test", (HttpContext ctx, WorkspaceRunner run, WorkflowService svc) => run.RunAsync(ctx, async a =>
        {
            var body = await Zod.BodyAsync(ctx);
            var draft = ReadDraft(body, out var configObjectId, out _, withConfigObjectId: true, withReceipt: false);
            var outcome = await svc.TestDraftAsync(a, configObjectId!, draft, ctx.RequestAborted);
            if (outcome.Execution is not WorkflowExecution.Succeeded ok) return FailureResult(outcome.Execution);
            return Ok(new JsonObject
            {
                ["receiptId"] = ok.ReceiptId, ["value"] = ok.Value?.DeepClone(), ["markdown"] = ok.Markdown, ["codeDigest"] = WorkflowArtifacts.CodeDigest(draft.Code), ["resultDigest"] = ok.ResultDigest,
                ["inputSchemaDigest"] = ok.InputSchemaDigest, ["outputSchemaDigest"] = ok.OutputSchemaDigest, ["rendererVersion"] = WorkflowArtifacts.RendererVersion,
                ["requiredCapabilities"] = WorkflowService.RequiredJson(outcome.Required!), ["finishedAt"] = outcome.FinishedAt,
            });
        }));

        app.MapGet(prefix + "/{configObjectId}", (string configObjectId, HttpContext ctx, WorkspaceRunner run, WorkflowService svc, ArtifactViewService views, LibraryUsage usage) => run.RunAsync(ctx, async a =>
        {
            var maxAge = CoerceLong(ctx, "maxAgeMs", 60_000, 30L * 24 * 60 * 60_000);
            if (IdTooLong(configObjectId)) return Results.Json(new { error = "invalid_request", message = "Invalid Workflow id." }, statusCode: 400);
            return Ok(await DetailWithLibraryAsync(a, configObjectId, maxAge, svc, views));
        }));

        app.MapGet(prefix + "/{configObjectId}/versions", (string configObjectId, HttpContext ctx, WorkspaceRunner run, WorkflowService svc) => run.RunAsync(ctx, async a =>
        {
            if (IdTooLong(configObjectId)) return Results.Json(new { error = "invalid_request", message = "Invalid Workflow id." }, statusCode: 400);
            return Ok(new JsonObject { ["items"] = await svc.ListVersionsAsync(a, configObjectId) });
        }));

        app.MapPost(prefix + "/{configObjectId}/versions", (string configObjectId, HttpContext ctx, WorkspaceRunner run, WorkflowService svc) => run.RunAsync(ctx, async a =>
        {
            var body = await Zod.BodyAsync(ctx);
            var draft = ReadDraft(body, out _, out var receiptId, withConfigObjectId: false, withReceipt: true);
            if (IdTooLong(configObjectId)) return Results.Json(new { error = "invalid_request", message = "Invalid Workflow id." }, statusCode: 400);
            return Ok(await svc.CreateVersionAsync(a, configObjectId, receiptId!, draft), 201);
        }));

        app.MapGet(prefix + "/{configObjectId}/snapshots", (string configObjectId, HttpContext ctx, WorkspaceRunner run, WorkflowService svc) => run.RunAsync(ctx, async a =>
        {
            var issues = new List<(string[] Path, string Code, string Message)>();
            Keyset.Cursor? cursor = null;
            int? limit = null;
            issues.AddRange(Collect(() => cursor = ReadCursor(ctx), () => limit = CoerceInt(ctx, "limit", 1, 200)));
            ThrowIf(issues);
            if (IdTooLong(configObjectId)) return Results.Json(new { error = "invalid_request", message = "Invalid Workflow id." }, statusCode: 400);
            return Ok(await svc.SnapshotPageAsync(a, configObjectId, limit, cursor));
        }));

        app.MapGet(prefix + "/{configObjectId}/snapshots/{receiptId}", (string configObjectId, string receiptId, HttpContext ctx, WorkspaceRunner run, WorkflowService svc) => run.RunAsync(ctx, async a =>
        {
            if (IdTooLong(configObjectId) || IdTooLong(receiptId)) return Results.Json(new { error = "invalid_request", message = "Invalid snapshot id." }, statusCode: 400);
            var snapshot = await svc.GetSnapshotAsync(a, configObjectId, receiptId);
            return snapshot is null ? Results.Json(new { error = "workflow_snapshot_not_found" }, statusCode: 404) : Ok(snapshot);
        }));

        app.MapDelete(prefix + "/{configObjectId}/snapshots/{receiptId}/content", (string configObjectId, string receiptId, HttpContext ctx, WorkspaceRunner run, WorkflowService svc) => run.RunAsync(ctx, async a =>
        {
            if (IdTooLong(configObjectId) || IdTooLong(receiptId)) return Results.Json(new { error = "invalid_request", message = "Invalid snapshot id." }, statusCode: 400);
            var snapshot = await svc.DeleteSnapshotContentAsync(a, configObjectId, receiptId);
            return snapshot is null ? Results.Json(new { error = "workflow_snapshot_not_found" }, statusCode: 404) : Ok(snapshot);
        }));

        app.MapPost(prefix + "/{configObjectId}/run", (string configObjectId, HttpContext ctx, WorkspaceRunner run, WorkflowService svc) => run.RunAsync(ctx, async a =>
        {
            var body = await Zod.BodyAsync(ctx);
            string? pluginId = null, versionId = null, mode = "adhoc", zone = null;
            var issues = Collect(
                () => pluginId = Zod.Str(body, "pluginId", trim: false, max: 160),
                () => versionId = Zod.Str(body, "configObjectVersionId", trim: false, max: 160),
                () => { if (body.TryGetProperty("mode", out _)) mode = Zod.Enum(body, "mode", ["adhoc", "live"]); },
                () => zone = ReadTimeZone(body));
            if (issues.Count == 0)
            {
                if (mode == "live" && body.TryGetProperty("input", out _)) issues.Add((["input"], "custom", "Live runs generate input.runtime; omit caller input."));
                if (mode != "live" && zone is not null) issues.Add((["timeZone"], "custom", "timeZone is only supported in live mode."));
            }
            ThrowIf(issues);
            if (IdTooLong(configObjectId)) return Results.Json(new { error = "invalid_request", message = "Invalid Workflow id." }, statusCode: 400);
            var live = mode == "live";
            var (error, message, found) = await svc.FindRunnableAsync(a, pluginId!, configObjectId, versionId!);
            if (found is null)
            {
                if (error == "content_not_synced")
                    return Results.Json(new { error = "script_not_executable", message = await svc.NotSyncedHintAsync(a, pluginId!, configObjectId) }, statusCode: 400);
                return Results.Json(new { error, message }, statusCode: 400);
            }
            var execution = await svc.RunSavedAsync(a, found.Value, live ? null : Node(body, "input"), live, zone, ctx.RequestAborted);
            if (execution is not WorkflowExecution.Succeeded ok)
            {
                if (execution is WorkflowExecution.Unsupported u)
                    return Results.Json(new { error = "script_not_executable", message = $"Plugin \"{found.Value.Plugin.Name}\" holds a Workflow \"{found.Value.Object.Title}\" that cannot run: {u.Message}" }, statusCode: 400);
                return RunFailureResult(execution!);
            }
            var result = new JsonObject { ["status"] = "succeeded", ["executionType"] = "saved-workflow", ["mode"] = mode, ["fetchedAt"] = Responses.IsoUtc(WorkflowService.Now()) };
            if (live) result["timeZone"] = zone ?? "UTC";
            result["value"] = ok.Value?.DeepClone();
            result["markdown"] = ok.Markdown;
            result["receiptId"] = ok.ReceiptId;
            result["resultDigest"] = ok.ResultDigest;
            result["inputSchemaDigest"] = ok.InputSchemaDigest;
            result["outputSchemaDigest"] = ok.OutputSchemaDigest;
            result["rendererVersion"] = WorkflowArtifacts.RendererVersion;
            return Ok(result);
        }));

    }

    private static async Task<IResult> RunsAsync(HttpContext ctx, Actor a, WorkflowService svc)
    {
        var issues = new List<(string[] Path, string Code, string Message)>();
        Keyset.Cursor? cursor = null;
        int? limit = null;
        issues.AddRange(Collect(() => cursor = ReadCursor(ctx), () => limit = CoerceInt(ctx, "limit", 1, 200)));
        ThrowIf(issues);
        return Ok(await svc.RunsAsync(a, limit ?? 50, cursor));
    }

    private static async Task<JsonObject> DetailWithLibraryAsync(Actor a, string configObjectId, long? maxAgeMs, WorkflowService svc, ArtifactViewService views)
    {
        var script = await svc.DetailAsync(a, configObjectId, maxAgeMs);
        var id = script["configObjectId"]!.GetValue<string>();
        var card = (await svc.CardsAsync(a, id)).FirstOrDefault() ?? throw new WorkflowException("workflow_not_found");
        var viewList = views.Enabled ? (await views.ListForWorkflowAsync(a, id)).Select(v => (JsonObject)v!.DeepClone()).ToList() : [];
        script["canRun"] = true;
        return new JsonObject
        {
            ["workflow"] = WorkflowCardJson(card, viewList),
            ["script"] = script,
            ["views"] = new JsonArray(viewList.Select(v => (JsonNode)v).ToArray()),
        };
    }

    /// <summary>The library card of a Workflow (also a row of "my library"): its role, readiness, result freshness, view state and how many Automations run it.</summary>
    public static JsonObject WorkflowCardJson(WorkflowService.Card card, List<JsonObject> views)
    {
        string viewState = "default";
        string? activeTitle = null;
        var active = views.FirstOrDefault(v => v["status"]!.GetValue<string>() == "active" && v["activeRevisionId"] is not null);
        if (active is not null) { viewState = "custom_active"; activeTitle = active["title"]!.GetValue<string>(); }
        else if (views.Any(v => v["status"]!.GetValue<string>() == "active" && v["revisions"]!.AsArray().Any(r => r!["buildStatus"]!.GetValue<string>() == "failed"))) viewState = "build_failed";
        else if (views.Count > 0 && views.All(v => v["status"]!.GetValue<string>() == "retired")) viewState = "retired";
        return new JsonObject
        {
            ["type"] = "workflow", ["id"] = card.Id, ["plugin"] = card.Plugin is null ? null : new JsonObject { ["id"] = card.Plugin.Id, ["name"] = card.Plugin.Name },
            ["name"] = card.Name, ["description"] = card.Description, ["role"] = RoleNames.Name(card.Role), ["edges"] = JsonSerializer.SerializeToNode(card.Edges),
            ["state"] = card.State, ["resultState"] = card.ResultState, ["latestSuccessfulAt"] = card.LatestSuccessfulAt, ["viewState"] = viewState, ["activeViewTitle"] = activeTitle,
            ["automationCount"] = card.AutomationCount, ["source"] = new JsonObject { ["kind"] = "created" },
        };
    }

    private static IResult FailureResult(WorkflowExecution execution)
    {
        var (error, message) = execution switch
        {
            WorkflowExecution.Unsupported u => ("unsupported", u.Message),
            WorkflowExecution.Invalid i => (i.Error, i.Message),
            WorkflowExecution.CapabilityUnavailable c => ("capability_unavailable", c.Message),
            WorkflowExecution.ScriptFailed f => ("script_failed", f.Message),
            _ => ("script_failed", "The Workflow could not run."),
        };
        return Results.Json(new { error, message }, statusCode: 400);
    }

    private static IResult RunFailureResult(WorkflowExecution execution)
    {
        var (error, message) = execution switch
        {
            WorkflowExecution.Invalid i => ("invalid_capability_arguments", i.Message),
            WorkflowExecution.CapabilityUnavailable c => ("capability_unavailable", c.Message),
            WorkflowExecution.ScriptFailed f => ("script_failed", f.Message),
            _ => ("script_failed", "The Workflow could not run."),
        };
        return Results.Json(new { error, message }, statusCode: 400);
    }

    // ---------------------------------------------------------------- generated views

    private static void MapViews(WebApplication app)
    {
        app.MapGet("/v1/workflows/{configObjectId}/views", (string configObjectId, HttpContext ctx, WorkspaceRunner run, ArtifactViewService views) => run.RunAsync(ctx, async a =>
        {
            if (IdTooLong(configObjectId)) return Results.Json(new { error = "invalid_request", message = "Invalid Workflow id." }, statusCode: 400);
            if (!views.Enabled) return Ok(new JsonObject { ["items"] = new JsonArray() });
            return Ok(new JsonObject { ["items"] = await views.ListForWorkflowAsync(a, configObjectId) });
        }));

        app.MapPost("/v1/artifact-views/{artifactViewId}/revisions/{revisionId}/activate", (string artifactViewId, string revisionId, HttpContext ctx, WorkspaceRunner run, ArtifactViewService views) => run.RunAsync(ctx, async a =>
        {
            if (!views.Enabled) return Results.Json(new { error = "artifact_view_not_found" }, statusCode: 404);
            if (artifactViewId.Trim().Length is < 1 or > 160 || revisionId.Trim().Length is < 1 or > 160) return Results.Json(new { error = "invalid_request", message = "Invalid view revision." }, statusCode: 400);
            return Ok(await views.ActivateAsync(a, artifactViewId.Trim(), revisionId.Trim()));
        }));

        app.MapPost("/v1/artifact-views/{artifactViewId}/retire", (string artifactViewId, HttpContext ctx, WorkspaceRunner run, ArtifactViewService views) => run.RunAsync(ctx, async a =>
        {
            if (!views.Enabled) return Results.Json(new { error = "artifact_view_not_found" }, statusCode: 404);
            if (artifactViewId.Trim().Length is < 1 or > 160) return Results.Json(new { error = "invalid_request", message = "Invalid view." }, statusCode: 400);
            return Ok(await views.RetireAsync(a, artifactViewId.Trim()));
        }));
    }

    // ---------------------------------------------------------------- saved apps and the Apps catalog

    private static void MapApps(WebApplication app)
    {
        app.MapGet("/v1/apps", (HttpContext ctx, WorkspaceRunner run, ArtifactViewService views) => run.RunAsync(ctx, async a =>
        {
            if (!views.Enabled) return Ok(new JsonObject { ["enabled"] = false, ["sharingEnabled"] = false, ["items"] = new JsonArray() });
            return Ok(new JsonObject { ["enabled"] = true, ["sharingEnabled"] = true, ["items"] = await views.ListSavedAsync(a) });
        }, appErrors: true));

        app.MapPost("/v1/apps/{appId}/share", (string appId, HttpContext ctx, WorkspaceRunner run, ArtifactViewService views) => run.RunAsync(ctx, async a =>
        {
            var body = await Zod.BodyAsync(ctx);
            var email = Zod.Str(body, "email", max: 320)!;
            if (!System.Text.RegularExpressions.Regex.IsMatch(email, @"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"))
                throw new Invalid("email", "Invalid email address", "invalid_format");
            if (!views.Enabled) return Results.Json(new { error = "artifact_view_not_found" }, statusCode: 404);
            await views.ShareAsync(a, appId, email);
            return Ok(new JsonObject { ["ok"] = true });
        }, appErrors: true));

        app.MapGet("/v1/apps/{appId}", (string appId, HttpContext ctx, WorkspaceRunner run, ArtifactViewService views) => run.RunAsync(ctx, async a =>
        {
            string? zone = null, revisionId = null, receiptId = null;
            if (ctx.Request.Query.ContainsKey("timeZone"))
            {
                zone = ctx.Request.Query["timeZone"].ToString();
                if (zone.Length is < 1 or > 100) throw new Invalid("timeZone", zone.Length < 1 ? "Too small: expected string to have >=1 characters" : "Too big: expected string to have <=100 characters", zone.Length < 1 ? "too_small" : "too_big");
                if (!ArtifactRuntime.ValidZone(zone)) throw new Invalid("timeZone", "Expected an IANA time zone", "custom");
            }
            if (ctx.Request.Query.ContainsKey("revisionId")) revisionId = Zod.QueryString(ctx, "revisionId", 160);
            if (ctx.Request.Query.ContainsKey("receiptId")) receiptId = Zod.QueryString(ctx, "receiptId", 160);
            if (!views.Enabled) return Results.Json(new { error = "artifact_view_not_found" }, statusCode: 404);
            ctx.Response.Headers.CacheControl = "private, no-store";
            return Ok(await views.GetSavedAsync(a, appId, revisionId, receiptId, zone, ctx.RequestAborted));
        }, appErrors: true));

        app.MapPost("/v1/apps/{appId}/dashboard", (string appId, HttpContext ctx, WorkspaceRunner run, ArtifactViewService views) => run.RunAsync(ctx, async a =>
        {
            var body = await Zod.BodyAsync(ctx);
            if (!body.TryGetProperty("added", out var added)) throw new Invalid("added", "Invalid input: expected boolean, received undefined");
            if (added.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) throw new Invalid("added", $"Invalid input: expected boolean, received {Zod.Kind(added)}");
            if (!views.Enabled) return Results.Json(new { error = "artifact_view_not_found" }, statusCode: 404);
            await views.SetOnDashboardAsync(a, appId, added.GetBoolean());
            return Ok(new JsonObject { ["ok"] = true });
        }, appErrors: true));

        app.MapPost("/v1/apps/{appId}/save", (string appId, HttpContext ctx, WorkspaceRunner run, ArtifactViewService views) => run.RunAsync(ctx, async a =>
        {
            var body = await Zod.BodyAsync(ctx);
            string? revisionId = null, title = null, expected = null;
            bool use = false;
            var issues = Collect(
                () => revisionId = Zod.Str(body, "revisionId", max: 160),
                () => title = Zod.Str(body, "title", max: 255),
                () => use = Zod.Bool(body, "useInWorkflow") ?? throw new Invalid("useInWorkflow", "Invalid input: expected boolean, received undefined"),
                () =>
                {
                    if (!body.TryGetProperty("expectedActiveRevisionId", out var e)) throw new Invalid("expectedActiveRevisionId", "Invalid input: expected string, received undefined");
                    if (e.ValueKind != JsonValueKind.Null) expected = Zod.Str(body, "expectedActiveRevisionId", max: 160);
                });
            ThrowIf(issues);
            if (!views.Enabled) return Results.Json(new { error = "artifact_view_not_found" }, statusCode: 404);
            return Ok(await views.ActivateAsync(a, appId, revisionId!, (title!, use, expected)));
        }, appErrors: true));

        app.MapGet("/v1/mcp-apps", (HttpContext ctx, WorkspaceRunner run, McpAppCatalog catalog) => run.RunAsync(ctx, async a => Ok(new JsonObject { ["apps"] = await catalog.ListAsync(a) })));
    }

    // ---------------------------------------------------------------- webhooks

    private static string Hmac(string secret, string text) => Convert.ToHexStringLower(HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(text)));

    private static async Task<string> ReadBodyAsync(HttpContext ctx)
    {
        using var reader = new StreamReader(ctx.Request.Body, Encoding.UTF8);
        return await reader.ReadToEndAsync();
    }

    private static void MapWebhooks(WebApplication app)
    {
        // GitHub App webhooks. The signature is checked against the raw body before anything in it is read. This build keeps no GitHub App
        // installations, so every verified delivery is acknowledged and ignored (never 202).
        app.MapPost("/v1/webhooks/connectors/github", async (HttpContext ctx, IOptions<WorkspaceOptions> options) =>
        {
            var secret = options.Value.GithubWebhookSecret;
            if (string.IsNullOrEmpty(secret)) return Results.StatusCode(503);
            var raw = await ReadBodyAsync(ctx);
            var signature = ctx.Request.Headers["x-hub-signature-256"].ToString().Trim();
            if (signature.Length == 0) return Results.Json(new { ok = false, error = "invalid signature" }, statusCode: 401);
            var expected = "sha256=" + Hmac(secret, raw);
            if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(signature), Encoding.UTF8.GetBytes(expected)) || signature.Length != expected.Length)
                return Results.Json(new { ok = false, error = "invalid signature" }, statusCode: 401);
            var ignored = Results.Json(new { ok = true, accepted = false, reason = "event ignored" });
            var eventName = ctx.Request.Headers["x-github-event"].ToString().Trim();
            var delivery = ctx.Request.Headers["x-github-delivery"].ToString().Trim();
            if (eventName.Length == 0 || delivery.Length == 0) return ignored;
            if (eventName is not ("push" or "installation" or "installation_repositories" or "repository")) return ignored;
            JsonObject payload;
            try { payload = JsonNode.Parse(raw) as JsonObject ?? throw new JsonException(); }
            catch (JsonException) { return Results.Json(new { ok = false, error = "invalid payload" }, statusCode: 400); }
            var installation = payload["installation"] is JsonObject i && i["id"] is JsonValue iv && WorkflowArtifacts.El(iv).ValueKind == JsonValueKind.Number ? WorkflowArtifacts.El(iv).GetInt64() : (long?)null;
            if (installation is null) return Results.Json(new { ok = true, accepted = false, reason = "missing installation id" });
            if (eventName == "push")
            {
                var repo = payload["repository"] as JsonObject;
                var hasRepo = repo?["full_name"] is JsonValue fv && fv.TryGetValue<string>(out var full) && full.Length > 0 && repo["id"] is JsonValue idv && WorkflowArtifacts.El(idv).ValueKind == JsonValueKind.Number;
                var hasRef = payload["ref"] is JsonValue rv && rv.TryGetValue<string>(out var r) && r.Length > 0;
                var hasSha = payload["after"] is JsonValue av && av.TryGetValue<string>(out var s) && s.Length > 0;
                if (!hasRepo || !hasRef || !hasSha) return Results.Json(new { ok = true, accepted = false, reason = "missing push metadata" });
            }
            return ignored;
        });

        // Stripe webhooks. Signatures are verified as Stripe documents (t=…,v1=… over "t.body", five minutes of tolerance); billing itself is not
        // part of this build, so a verified event is acknowledged and not applied.
        app.MapPost("/v1/webhooks/stripe", async (HttpContext ctx, IOptions<WorkspaceOptions> options) =>
        {
            var secret = options.Value.StripeWebhookSecret;
            if (string.IsNullOrEmpty(secret)) return Results.Json(new { error = "stripe_webhook_secret_missing" }, statusCode: 400);
            var header = ctx.Request.Headers["stripe-signature"].ToString();
            if (header.Length == 0) return Results.Json(new { error = "stripe_signature_missing" }, statusCode: 400);
            var raw = await ReadBodyAsync(ctx);
            var timestamp = header.Split(',').Select(p => p.Split('=', 2)).Where(p => p.Length == 2 && p[0].Trim() == "t").Select(p => p[1].Trim()).FirstOrDefault();
            var candidates = header.Split(',').Select(p => p.Split('=', 2)).Where(p => p.Length == 2 && p[0].Trim() == "v1").Select(p => p[1].Trim()).ToList();
            if (timestamp is null || !long.TryParse(timestamp, out var t) || candidates.Count == 0)
                return Results.Json(new { error = "Unable to extract timestamp and signatures from header" }, statusCode: 400);
            var expected = Hmac(secret, $"{timestamp}.{raw}");
            if (!candidates.Any(c => c.Length == expected.Length && CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(c), Encoding.UTF8.GetBytes(expected))))
                return Results.Json(new { error = "No signatures found matching the expected signature for payload. Are you passing the raw request body you received from Stripe?" }, statusCode: 400);
            if (Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - t) > 300) return Results.Json(new { error = "Timestamp outside the tolerance zone" }, statusCode: 400);
            string type;
            try { type = JsonNode.Parse(raw)?["type"]?.GetValue<string>() ?? throw new JsonException(); }
            catch (Exception e) when (e is JsonException or InvalidOperationException) { return Results.Json(new { error = "Webhook payload must be valid JSON" }, statusCode: 400); }
            return Results.Json(new { received = true, type });
        });
    }

    // ---------------------------------------------------------------- direct uploads

    /// <summary>
    /// Direct uploads hand a person's file bytes straight to Google Drive, Gmail or OneDrive/Outlook, with an MCP bearer token. This build connects
    /// to none of those services: a request without a bearer token gets the reference's 401, and any other is answered 501 (nothing is stored or forwarded).
    /// </summary>
    private static void MapDirectUploads(WebApplication app)
    {
        foreach (var (method, path) in new[]
        {
            ("POST", "/v1/direct-uploads/google-workspace/drive-upload-sessions"), ("POST", "/v1/direct-uploads/google-workspace/drive-files"), ("POST", "/v1/direct-uploads/google-workspace/gmail-drafts"),
            ("POST", "/v1/direct-uploads/microsoft-365/mail-drafts"), ("POST", "/v1/direct-uploads/microsoft-365/drive-upload-sessions"),
            ("PUT", "/v1/direct-uploads/microsoft-365/drive-upload-sessions/content"), ("GET", "/v1/direct-uploads/microsoft-365/drive-upload-sessions/content"),
        })
            app.MapMethods(path, [method], (HttpContext ctx) =>
            {
                var auth = ctx.Request.Headers.Authorization.ToString();
                if (!auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) || auth.Length <= 7)
                    return Results.Json(new { error = "missing_mcp_token", message = "Provide a Bearer token with MCP scope to access this resource.", referenceId = "unknown" }, statusCode: 401);
                return Results.Json(new { error = "not_supported", message = "Direct uploads need a connected Google Workspace or Microsoft 365 account, which this deployment does not offer." }, statusCode: 501);
            });
    }
}

/// <summary>Resolves the workspace and caller, runs a handler, and turns failures into the reference's answers.</summary>
public sealed class WorkspaceRunner(OrgAccess access, LibraryAccess lib)
{
    public async Task<IResult> RunAsync(HttpContext ctx, Func<Actor, Task<IResult>> handler, bool appErrors = false)
    {
        var (context, failure) = await access.ResolveAsync(ctx);
        if (failure is not null) return failure;
        try { return await handler(await lib.ActorAsync(context!)); }
        catch (Invalid invalid) { return invalid.ToResult(); }
        catch (Exception e) when (e is WorkflowException or LibraryForbidden or LibraryFailure)
        {
            var (status, body) = appErrors ? WorkflowFailures.MapApp(e) : WorkflowFailures.Map(e);
            return Results.Json(body, statusCode: status);
        }
        catch (DbUpdateException)
        {
            // Two requests changed the same thing at once and the database let one through: this one is told to try again.
            return Results.Json(new { error = "conflict", message = "This changed at the same moment elsewhere. Reload and try again." }, statusCode: 409);
        }
    }
}

/// <summary>Workflows in "my library": a card for each Workflow the person can read, beside the plugins.</summary>
public sealed class WorkflowLibrarySource(WorkflowService workflows, ArtifactViewService views) : IMyLibrarySource
{
    public async Task<IReadOnlyList<MyLibraryItem>> ItemsAsync(Actor a)
    {
        var cards = await workflows.CardsAsync(a);
        var byWorkflow = await views.ListForWorkflowsAsync(a, cards.Select(c => c.Id).ToList());
        return cards.Select(c => new MyLibraryItem(c.Name, c.Id, WorkspaceFeature.WorkflowCardJson(c, byWorkflow.GetValueOrDefault(c.Id) ?? []))).ToList();
    }
}
