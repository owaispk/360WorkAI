using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Connections;
using WorkAI360.Api.Features.Library;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Features.Connections;

/// <summary>
/// External MCP servers a workspace connects, who may use them, their tool policy, and agents using them through the gateway.
/// See docs/features/connections.md.
/// </summary>
public sealed partial class ConnectionsFeature : IFeature
{
    public void AddServices(IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<ConnectionsOptions>(configuration.GetSection(ConnectionsOptions.Section));
        services.AddSingleton<GuardedHttp>();
        services.AddSingleton<SecretBox>();
        services.AddSingleton<McpClient>();
        services.AddSingleton<McpOAuth>();
        services.AddSingleton<McpDiscovery>();
        services.AddScoped<ConnectionService>();
        services.AddScoped<ICapabilityProvider, ConnectionCapabilityProvider>();
    }

    private const string NotFoundMessage = "Unknown connection.";
    private const int ToolArgumentLimit = 1024 * 1024;

    private static IResult Ok(object body, int status = 200) => Results.Json(body, statusCode: status);
    private static IResult Forbidden(string message) => Results.Json(new { error = "forbidden", message }, statusCode: 403);
    private static IResult Bad(string message) => Results.Json(new { error = "invalid_request", message }, statusCode: 400);
    private static IResult NotFound() => Results.Json(new { error = "connection_not_found", message = NotFoundMessage }, statusCode: 404);
    private static IResult Conflict(string message) => Results.Json(new { error = "connection_conflict", message }, statusCode: 409);
    private static DateTime Now() => new(DateTime.UtcNow.Ticks / TimeSpan.TicksPerMillisecond * TimeSpan.TicksPerMillisecond, DateTimeKind.Utc);
    private static bool SameMillisecond(DateTime a, DateTime b) => a.Ticks / TimeSpan.TicksPerMillisecond == b.Ticks / TimeSpan.TicksPerMillisecond;

    /// <summary>Resolves the workspace and caller, runs the handler, and turns request-reading failures into the reference's 400.</summary>
    private static async Task<IResult> Run(HttpContext ctx, Func<Caller, ConnectionService, Task<IResult>> handler)
    {
        var access = ctx.RequestServices.GetRequiredService<OrgAccess>();
        var service = ctx.RequestServices.GetRequiredService<ConnectionService>();
        var (context, failure) = await access.ResolveAsync(ctx);
        if (failure is not null) return failure;
        try { return await handler(await service.CallerAsync(context!), service); }
        catch (Invalid invalid) { return invalid.ToResult(); }
    }

    private static IResult? Need(HttpContext ctx, Caller caller, string permission) => ctx.RequestServices.GetRequiredService<OrgAccess>().Require(caller.Context, permission);

    private static bool Fresh(HttpContext ctx, Caller caller) => ctx.RequestServices.GetRequiredService<OrgAccess>().IsFresh(caller.Context.Auth.Session);

    private static IResult Reauth() => OrgAccess.ReauthRequired();

    private bool AllowPrivate(HttpContext ctx) => ctx.RequestServices.GetRequiredService<GuardedHttp>().AllowPrivate;

    public void MapEndpoints(WebApplication app)
    {
        MapCore(app);
        MapCredentials(app);
        MapOAuthRoutes(app);
        MapDiscovery(app);
    }

    // ---------- reading ----------

    private static void MapCore(WebApplication app)
    {
        app.MapGet("/v1/mcp-connections/presets", (HttpContext ctx, IConfiguration config) => Run(ctx, async (caller, service) =>
        {
            var expanded = config.GetValue<bool>("Connections:ExpandedPresets");
            return Ok(new { presets = McpPresets.ForCatalog(expanded).Select(p => McpPresets.ToJson(p, service.CallbackUrl)).ToList() });
        }));

        app.MapGet("/v1/mcp-connections", (HttpContext ctx, ConnectionService _) => Run(ctx, async (caller, service) =>
        {
            var scope = Zod.QueryEnum(ctx, "scope", ["usable", "manageable"]) ?? "usable";
            if (scope == "manageable")
            {
                if (!caller.Has("connections.view")) return Forbidden("Only workspace owners and admins can list all MCP connections.");
                var names = await service.MemberNamesAsync(caller.OrgId);
                var rows = await service.ListAllAsync(caller.OrgId);
                var list = new List<Dictionary<string, object?>>();
                foreach (var row in rows) list.Add(await service.ToJsonAsync(row, caller, true, true, names));
                return Ok(new { connections = list });
            }
            var usable = await service.UsableAsync(caller.OrgId, caller.MemberId, caller.TeamIds);
            var usableNames = await service.MemberNamesAsync(caller.OrgId);
            var result = new List<Dictionary<string, object?>>();
            foreach (var row in usable) result.Add(await service.ToJsonAsync(row, caller, row.CreatedByMemberId == caller.MemberId, false, usableNames));
            return Ok(new { connections = result });
        }));

        app.MapGet("/v1/mcp-connections/{connectionId}", (string connectionId, HttpContext ctx) => Run(ctx, async (caller, service) =>
        {
            if (Need(ctx, caller, "connections.view") is { } denied) return denied;
            Zod.TypeId(connectionId, "emc", "connectionId");
            var c = await service.FindAsync(caller.OrgId, connectionId);
            if (c is null) return NotFound();
            return Ok(await service.ToJsonAsync(c, caller, true, caller.Has("connections.view"), await service.MemberNamesAsync(caller.OrgId)));
        }));

        // ---------- tool policy ----------

        app.MapGet("/v1/mcp-connections/{connectionId}/tool-policy", (string connectionId, HttpContext ctx) => Run(ctx, async (caller, service) =>
        {
            if (Need(ctx, caller, "connections.view") is { } denied) return denied;
            Zod.TypeId(connectionId, "emc", "connectionId");
            var c = await service.FindAsync(caller.OrgId, connectionId);
            return c is null ? NotFound() : Ok(new { policy = service.PolicyJson(c, true) });
        }));

        app.MapPut("/v1/mcp-connections/{connectionId}/tool-policy", (string connectionId, HttpContext ctx) => Run(ctx, async (caller, service) =>
        {
            if (Need(ctx, caller, "connections.manage") is { } denied) return denied;
            Zod.TypeId(connectionId, "emc", "connectionId");
            var body = await Zod.BodyAsync(ctx);
            var all = Zod.Bool(body, "allDisabled") ?? throw new Invalid("allDisabled", "Invalid input: expected boolean, received undefined");
            var raw = Zod.Array(body, "disabledTools", 500) ?? throw new Invalid("disabledTools", "Invalid input: expected array, received undefined");
            var tools = new List<string>();
            for (var i = 0; i < raw.Count; i++)
            {
                if (raw[i].ValueKind != JsonValueKind.String) throw new Invalid($"disabledTools.{i}", $"Invalid input: expected string, received {Zod.Kind(raw[i])}");
                var s = raw[i].GetString()!.Trim();
                if (s.Length is < 1 or > 255) throw new Invalid($"disabledTools.{i}", s.Length < 1 ? "Too small: expected string to have >=1 characters" : "Too big: expected string to have <=255 characters", s.Length < 1 ? "too_small" : "too_big");
                tools.Add(s);
            }
            var c = await service.FindAsync(caller.OrgId, connectionId);
            if (c is null) return NotFound();
            var names = await service.MemberNamesAsync(caller.OrgId);
            var editor = names.TryGetValue(caller.MemberId, out var n) ? n : null;
            c.ToolPolicyJson = new JsonObject
            {
                ["version"] = 1, ["allDisabled"] = all, ["disabledTools"] = new JsonArray(tools.Distinct().Select(t => (JsonNode)t).ToArray()),
                ["updatedByOrgMembershipId"] = caller.MemberId, ["updatedByName"] = editor, ["updatedAt"] = Responses.IsoUtc(Now()),
            }.ToJsonString();
            await ctx.RequestServices.GetRequiredService<DenDbContext>().SaveChangesAsync();
            return Ok(new { policy = service.PolicyJson(c, true) });
        }));

        // ---------- tools ----------

        app.MapGet("/v1/mcp-connections/{connectionId}/tools", (string connectionId, HttpContext ctx) => Run(ctx, async (caller, service) =>
        {
            Zod.TypeId(connectionId, "emc", "connectionId");
            var c = await service.FindAsync(caller.OrgId, connectionId);
            if (c is null) return NotFound();
            var canViewAny = caller.Has("connections.view");
            if (!canViewAny && !await service.CanUseAsync(c, caller.MemberId, caller.TeamIds)) return Forbidden($"You have not been granted access to \"{c.Name}\".");
            var credential = await service.ResolveCredentialAsync(c, caller.MemberId, ctx.RequestAborted);
            if (!credential.Ok) return Results.Json(new { error = "connection_not_ready", message = credential.Message }, statusCode: 409);
            try
            {
                var tools = await service.ListToolsAsync(c, credential, ctx.RequestAborted);
                return Ok(new { tools = tools.Select(ToolJson).ToList(), policy = service.PolicyJson(c, canViewAny) });
            }
            catch (McpException e)
            {
                var d = ConnectionService.Diagnose(e, "MCP_TOOL_DISCOVERY");
                return Ok(new { error = "tool_catalog_failed", message = $"Could not inspect \"{c.Name}\": {d.Message} Reference: {d.ReferenceId}.", diagnostic = d.ToJson() }, 502);
            }
        }));

        app.MapGet("/v1/mcp-connections/{connectionId}/mcp-apps", (string connectionId, HttpContext ctx) => Run(ctx, async (caller, service) =>
        {
            if (Need(ctx, caller, "connections.view") is { } denied) return denied;
            Zod.TypeId(connectionId, "emc", "connectionId");
            var c = await service.FindAsync(caller.OrgId, connectionId);
            if (c is null) return NotFound();
            var credential = await service.ResolveCredentialAsync(c, caller.MemberId, ctx.RequestAborted);
            if (!credential.Ok) return Results.Json(new { error = "connection_not_ready", message = credential.Message }, statusCode: 409);
            try
            {
                var tools = await service.ListToolsAsync(c, credential, ctx.RequestAborted);
                var serverName = "openwork-app-host-connect-" + Ids.Sha256Hex(c.Id)[..12];
                var apps = tools.Select(t => (Tool: t, Uri: t.Meta?["ui"]?["resourceUri"]?.GetValue<string>() ?? t.Meta?["ui/resourceUri"]?.GetValue<string>()))
                    .Where(x => x.Uri is not null && (x.Tool.Meta?["ui"]?["visibility"] is not JsonArray v || v.Any(e => e?.GetValue<string>() == "app")) && !service.Evaluate(c, x.Tool.Name).Blocked)
                    .Select(x =>
                    {
                        var required = (x.Tool.InputSchema["required"] as JsonArray)?.Select(e => e!.GetValue<string>()).ToList() ?? [];
                        return new
                        {
                            serverName, connectionId = c.Id, toolName = x.Tool.Name, projectedToolName = $"{serverName}_{System.Text.RegularExpressions.Regex.Replace(x.Tool.Name, "[^a-zA-Z0-9_-]", "_")}",
                            resourceUri = x.Uri, title = x.Tool.Title, description = x.Tool.Description, requiresInput = required.Count > 0, requiredInputKeys = required, requiresApproval = x.Tool.Annotations?["readOnlyHint"]?.GetValue<bool>() != true,
                        };
                    }).ToList();
                return Ok(new { apps });
            }
            catch (McpException e)
            {
                var d = ConnectionService.Diagnose(e, "MCP_TOOL_DISCOVERY");
                return Ok(new { error = "tool_catalog_failed", message = $"Could not inspect \"{c.Name}\": {d.Message} Reference: {d.ReferenceId}.", diagnostic = d.ToJson() }, 502);
            }
        }));

        app.MapPost("/v1/mcp-connections/{connectionId}/tools/call", (string connectionId, HttpContext ctx) => Run(ctx, async (caller, service) =>
        {
            if (Need(ctx, caller, "connections.manage") is { } denied) return denied;
            Zod.TypeId(connectionId, "emc", "connectionId");
            var (text, tooLarge) = await ReadLimitedAsync(ctx.Request.Body, ToolArgumentLimit);
            if (tooLarge) return Ok(new { error = "payload_too_large", message = "Tool arguments must fit within 1 MB." }, 413);
            JsonElement body;
            try { using var doc = JsonDocument.Parse(text); body = doc.RootElement.Clone(); }
            catch (JsonException) { throw new Invalid("", "Invalid input: expected object, received undefined"); }
            if (body.ValueKind != JsonValueKind.Object) throw new Invalid("", $"Invalid input: expected object, received {Zod.Kind(body)}");
            var tool = Zod.Str(body, "toolName", max: 255)!;
            var args = Zod.Object(body, "arguments");
            var c = await service.FindAsync(caller.OrgId, connectionId);
            if (c is null) return NotFound();
            if (!await service.CanUseAsync(c, caller.MemberId, caller.TeamIds)) return Forbidden($"You have not been granted access to \"{c.Name}\".");
            var credential = await service.ResolveCredentialAsync(c, caller.MemberId, ctx.RequestAborted);
            if (!credential.Ok) return Results.Json(new { error = "connection_not_ready", message = credential.Message }, statusCode: 409);
            var policy = service.Evaluate(c, tool);
            if (policy.Blocked) return Results.Json(new { error = "policy_blocked", message = $"{tool} is disabled for your organization.", disabledBy = policy.By, disabledAt = policy.At }, statusCode: 403);

            var started = DateTime.UtcNow;
            var request = new JsonObject { ["jsonrpc"] = "2.0", ["id"] = 1, ["method"] = "tools/call", ["params"] = new JsonObject { ["name"] = tool, ["arguments"] = JsonNode.Parse(args.GetRawText()) } }.ToJsonString();
            var requestInfo = new
            {
                method = "POST", url = c.Url, startedAt = Responses.IsoUtc(started),
                headers = new object[] { new { name = "accept", value = "application/json, text/event-stream", redacted = false }, new { name = "content-type", value = "application/json", redacted = false }, new { name = "authorization", value = "[redacted]", redacted = true } },
                body = new { text = request, bytes = Encoding.UTF8.GetByteCount(request), truncated = false },
            };
            var reference = Ids.New("req");
            try
            {
                var result = await service.CallToolAsync(c, credential, tool, JsonNode.Parse(args.GetRawText())!.AsObject(), ctx.RequestAborted);
                var ms = (long)(DateTime.UtcNow - started).TotalMilliseconds;
                var resultText = result.ToJsonString();
                return Ok(new
                {
                    referenceId = reference, durationMs = ms, result,
                    inspection = new
                    {
                        request = requestInfo,
                        response = new { status = 200, statusText = "OK", durationMs = ms, headers = Array.Empty<object>(), body = new { text = resultText.Length > 16384 ? resultText[..16384] : resultText, bytes = Encoding.UTF8.GetByteCount(resultText), truncated = resultText.Length > 16384 } },
                        diagnosis = new { status = "succeeded", layer = "mcp_tool", summary = "The remote MCP received tools/call and returned a successful tool result." },
                    },
                });
            }
            catch (McpException e)
            {
                var d = ConnectionService.Diagnose(e, "MCP_TOOL_EXECUTION");
                return Ok(new
                {
                    error = "tool_execution_failed", message = $"Could not run \"{tool}\" on \"{c.Name}\": {d.Message} Reference: {d.ReferenceId}.", diagnostic = d.ToJson(),
                    inspection = new { request = requestInfo, diagnosis = new { status = "failed", layer = e.Kind == McpFailure.Tool ? "mcp_tool" : e.Kind == McpFailure.Unauthorized ? "mcp_connection" : "network", summary = d.Message } },
                }, 502);
            }
        }));

        app.MapPost("/v1/mcp-connections/{connectionId}/check", (string connectionId, HttpContext ctx) => Run(ctx, async (caller, service) =>
        {
            if (Need(ctx, caller, "connections.manage") is { } denied) return denied;
            Zod.TypeId(connectionId, "emc", "connectionId");
            var c = await service.FindAsync(caller.OrgId, connectionId);
            if (c is null) return NotFound();
            var credential = await service.ResolveCredentialAsync(c, caller.MemberId, ctx.RequestAborted);
            if (!credential.Ok) return Results.Json(new { error = "connection_not_ready", message = credential.Message }, statusCode: 409);
            return Ok(new { readiness = await service.CheckAsync(c, caller.MemberId, ctx.RequestAborted) });
        }));

        app.MapPost("/v1/mcp-connections/readiness-checks", (HttpContext ctx, ConnectionService _) => Run(ctx, async (caller, service) =>
        {
            if (Need(ctx, caller, "connections.manage") is { } denied) return denied;
            var body = await Zod.BodyAsync(ctx);
            var raw = Zod.Array(body, "connectionIds", 50) ?? throw new Invalid("connectionIds", "Invalid input: expected array, received undefined");
            if (raw.Count < 1) throw new Invalid("connectionIds", "Too small: expected array to have >=1 items", "too_small");
            var ids = new List<string>();
            for (var i = 0; i < raw.Count; i++)
            {
                if (raw[i].ValueKind != JsonValueKind.String) throw new Invalid($"connectionIds.{i}", $"Invalid input: expected string, received {Zod.Kind(raw[i])}");
                var s = raw[i].GetString()!;
                if (s.Length is < 1 or > 64) throw new Invalid($"connectionIds.{i}", s.Length < 1 ? "Too small: expected string to have >=1 characters" : "Too big: expected string to have <=64 characters", s.Length < 1 ? "too_small" : "too_big");
                ids.Add(s);
            }
            var results = new List<object>();
            foreach (var id in ids.Distinct())
            {
                var c = await service.FindAsync(caller.OrgId, id);
                if (c is null) { results.Add(new { connectionId = id, outcome = "not_found" }); continue; }
                if (c.ReadinessJson is not null) { results.Add(new { connectionId = id, outcome = "already_checked" }); continue; }
                var credential = await service.ResolveCredentialAsync(c, caller.MemberId, ctx.RequestAborted);
                if (!credential.Ok) { results.Add(new { connectionId = id, outcome = "not_checkable" }); continue; }
                await service.CheckAsync(c, caller.MemberId, ctx.RequestAborted);
                results.Add(new { connectionId = id, outcome = "checked" });
            }
            return Ok(new { results });
        }));

        MapWrites(app);
    }

    private static object ToolJson(McpTool t)
    {
        var d = new Dictionary<string, object?> { ["name"] = t.Name };
        if (!string.IsNullOrEmpty(t.Title)) d["title"] = t.Title;
        if (!string.IsNullOrEmpty(t.Description)) d["description"] = t.Description;
        d["inputSchema"] = t.InputSchema;
        if (t.OutputSchema is not null) d["outputSchema"] = t.OutputSchema;
        if (t.Annotations is JsonObject a)
        {
            var keep = new JsonObject();
            foreach (var key in new[] { "title", "readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint" }) if (a[key] is { } v) keep[key] = v.DeepClone();
            if (keep.Count > 0) d["annotations"] = keep;
        }
        return d;
    }

    private static async Task<(string Text, bool TooLarge)> ReadLimitedAsync(Stream body, int limit)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[16 * 1024];
        int read;
        while ((read = await body.ReadAsync(chunk)) > 0)
        {
            buffer.Write(chunk, 0, read);
            if (buffer.Length > limit) return ("", true);
        }
        return (Encoding.UTF8.GetString(buffer.ToArray()), false);
    }
}
