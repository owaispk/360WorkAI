using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;

namespace WorkAI360.Api.OAuth;

public sealed record McpTokenBody(string[]? Scopes);

/// <summary>
/// The MCP server agents connect to (`/mcp/agent`, Streamable HTTP, JSON responses) and the first-party token mint the desktop app uses.
/// It exposes the two tools the reference does: `search_capabilities` and `execute_capability`.
/// </summary>
public static class McpEndpoints
{
    private static readonly string[] ProtocolVersions = ["2025-06-18", "2025-03-26", "2024-11-05"];
    private static readonly TimeSpan FirstPartyLifetime = TimeSpan.FromDays(7);
    private const int MaxBodyBytes = 1024 * 1024;

    public static void MapMcpEndpoints(this WebApplication app)
    {
        app.MapPost("/v1/mcp/token", MintFirstPartyTokenAsync);
        app.MapPost("/mcp/agent", HandleAsync);
        // The endpoint answers POST only; GET would open a server-to-client stream, which this server does not offer.
        app.MapMethods("/mcp/agent", ["GET", "DELETE"], (HttpContext ctx) =>
        {
            ctx.Response.Headers.Allow = "POST";
            return Results.StatusCode(StatusCodes.Status405MethodNotAllowed);
        });
    }

    private static async Task<IResult> MintFirstPartyTokenAsync(McpTokenBody? body, HttpContext ctx, SessionService sessions, DenDbContext db)
    {
        var current = await sessions.ResolveAsync(ctx);
        if (current is null) return Responses.Unauthorized();

        var requested = ctx.Request.Headers["x-openwork-org-id"].ToString();
        var orgId = string.IsNullOrWhiteSpace(requested) ? current.Session.ActiveOrganizationId : requested.Trim();
        if (orgId is null) return Responses.Error(400, "invalid_request", "Select a workspace first.");
        if (!await db.Members.AnyAsync(m => m.OrganizationId == orgId && m.UserId == current.User.Id))
            return Responses.Error(403, "forbidden", "You are not a member of this organization.");

        var scopes = body?.Scopes is { Length: > 0 } s ? s.Distinct().ToArray() : [OAuthConstants.ReadScope];
        if (scopes.Any(x => x is not (OAuthConstants.ReadScope or OAuthConstants.WriteScope)))
            return Responses.Error(400, "invalid_request", "Scopes must be mcp:read and/or mcp:write.");

        var now = DateTime.UtcNow;
        var expiresAt = now + FirstPartyLifetime;
        string Mint(string kind)
        {
            var token = OAuthConstants.AccessTokenPrefix + Ids.RandomAlnum(43);
            db.McpAccessTokens.Add(new McpAccessToken { Id = Ids.Sha256Hex(token), Kind = kind, UserId = current.User.Id, OrganizationId = orgId, Scope = OAuthConstants.JoinScope(scopes), CreatedAt = now, ExpiresAt = expiresAt });
            return token;
        }
        var token = Mint("first-party");
        var appHostToken = Mint("app-host");
        await db.SaveChangesAsync();
        return Results.Json(new { token, appHostToken, expiresAt = Responses.IsoUtc(expiresAt), scopes, organizationId = orgId });
    }

    private static async Task<IResult> HandleAsync(HttpContext ctx, McpAuthenticator authenticator, OAuthUrls urls, IOptions<AuthOptions> options)
    {
        // Browsers must not be able to drive this endpoint from an arbitrary site (DNS-rebinding protection from the MCP spec).
        var origin = ctx.Request.Headers.Origin.ToString();
        if (origin.Length > 0 && !OriginAllowed(origin, urls)) return Results.Json(new { error = "forbidden_origin" }, statusCode: 403);

        var principal = await authenticator.AuthenticateAsync(ctx.Request);
        if (principal is null)
        {
            ctx.Response.Headers.WWWAuthenticate = authenticator.DpopFailure is { } dpopFailure
                ? $"DPoP error=\"{dpopFailure.Code}\", error_description=\"{dpopFailure.Message.Replace('"', '\'')}\", algs=\"{string.Join(' ', DpopVerifier.SigningAlgorithms)}\""
                : $"Bearer resource_metadata=\"{urls.ProtectedResourceMetadata}\", scope=\"{OAuthConstants.DefaultScope}\"";
            return Results.Json(new { error = "unauthorized", error_description = "A valid OAuth access token is required." }, statusCode: 401);
        }

        string text;
        using (var reader = new StreamReader(ctx.Request.Body))
        {
            var buffer = new char[MaxBodyBytes + 1];
            var read = await reader.ReadBlockAsync(buffer, 0, buffer.Length);
            if (read > MaxBodyBytes) return Results.Json(new { error = "request_too_large" }, statusCode: 413);
            text = new string(buffer, 0, read);
        }

        JsonNode? root;
        try { root = JsonNode.Parse(text); }
        catch (JsonException) { return Results.Json(RpcError(null, -32700, "Parse error"), statusCode: 400); }

        if (root is JsonArray batch)
        {
            var replies = new JsonArray();
            foreach (var item in batch)
                if (await DispatchAsync(item, principal, ctx.RequestServices) is { } reply) replies.Add(reply);
            return replies.Count == 0 ? Results.StatusCode(202) : Results.Json(replies);
        }
        var single = await DispatchAsync(root, principal, ctx.RequestServices);
        return single is null ? Results.StatusCode(202) : Results.Json(single);
    }

    private static bool OriginAllowed(string origin, OAuthUrls urls)
    {
        if (string.Equals(origin.TrimEnd('/'), urls.Web, StringComparison.OrdinalIgnoreCase) || string.Equals(origin.TrimEnd('/'), urls.Api, StringComparison.OrdinalIgnoreCase)) return true;
        return Uri.TryCreate(origin, UriKind.Absolute, out var uri) && RedirectPolicy.IsLoopback(uri.Host);
    }

    /// <summary>One JSON-RPC message. Notifications (no id) get no reply.</summary>
    private static async Task<JsonNode?> DispatchAsync(JsonNode? message, McpPrincipal principal, IServiceProvider services)
    {
        if (message is not JsonObject obj || obj["method"] is not JsonValue methodValue || !methodValue.TryGetValue<string>(out var method))
            return RpcError(null, -32600, "Invalid Request");
        var id = obj["id"]?.DeepClone();
        var isNotification = obj["id"] is null;
        var parameters = obj["params"] as JsonObject;

        switch (method)
        {
            case "initialize":
            {
                var asked = parameters?["protocolVersion"]?.GetValue<string>();
                var version = asked is not null && ProtocolVersions.Contains(asked) ? asked : ProtocolVersions[0];
                return RpcResult(id, new JsonObject
                {
                    ["protocolVersion"] = version,
                    ["capabilities"] = new JsonObject { ["tools"] = new JsonObject { ["listChanged"] = false } },
                    ["serverInfo"] = new JsonObject { ["name"] = "openwork-agent", ["title"] = "OpenWork Cloud", ["version"] = "0.1.0" },
                    ["instructions"] = "Use search_capabilities to find what you can do in this workspace, then execute_capability to do it.",
                });
            }
            case "notifications/initialized" or "notifications/cancelled":
                return null;
            case "ping":
                return isNotification ? null : RpcResult(id, new JsonObject());
            case "tools/list":
                return RpcResult(id, new JsonObject { ["tools"] = ToolDefinitions(services) });
            case "tools/call":
                return RpcResult(id, await CallToolAsync(parameters, principal, services));
            default:
                return isNotification ? null : RpcError(id, -32601, $"Method not found: {method}");
        }
    }

    private static JsonArray ToolDefinitions(IServiceProvider services)
    {
        var tools = BuiltInToolDefinitions();
        foreach (var provider in services.GetServices<IMcpToolProvider>())
            foreach (var tool in provider.Tools)
                tools.Add(new JsonObject { ["name"] = tool.Name, ["description"] = tool.Description, ["inputSchema"] = tool.InputSchema.DeepClone() });
        return tools;
    }

    private static JsonArray BuiltInToolDefinitions() => new()
    {
        new JsonObject
        {
            ["name"] = "search_capabilities",
            ["description"] = "Search what this workspace lets you do. Returns capability ids, descriptions and input schemas.",
            ["inputSchema"] = JsonNode.Parse("""{"type":"object","properties":{"query":{"type":"string","description":"Words describing what you want to do. Empty lists everything."}},"additionalProperties":false}"""),
        },
        new JsonObject
        {
            ["name"] = "execute_capability",
            ["description"] = "Run a capability found with search_capabilities.",
            ["inputSchema"] = JsonNode.Parse("""{"type":"object","properties":{"name":{"type":"string"},"body":{"type":"object"},"capability_id":{"type":"string"},"arguments":{"type":"object"}},"additionalProperties":false}"""),
        },
    };

    private static async Task<JsonObject> CallToolAsync(JsonObject? parameters, McpPrincipal principal, IServiceProvider services)
    {
        var name = parameters?["name"]?.GetValue<string>();
        var arguments = parameters?["arguments"] as JsonObject ?? new JsonObject();
        var providers = services.GetServices<ICapabilityProvider>().ToList();

        switch (name)
        {
            case "search_capabilities":
            {
                if (!principal.Scopes.Contains(OAuthConstants.ReadScope)) return ToolError("insufficient_scope", "This token needs the mcp:read scope.");
                var query = arguments["query"]?.GetValue<string>() ?? "";
                var words = query.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                var all = new List<CapabilityInfo>();
                foreach (var provider in providers) all.AddRange(await provider.ListAsync(principal, services));
                var hits = all.Where(c => words.All(w => c.Id.Contains(w, StringComparison.OrdinalIgnoreCase) || c.Description.Contains(w, StringComparison.OrdinalIgnoreCase))).ToList();
                var list = new JsonArray(hits.Select(c => (JsonNode)new JsonObject { ["id"] = c.Id, ["description"] = c.Description, ["requiredScope"] = c.RequiredScope, ["inputSchema"] = c.InputSchema.DeepClone() }).ToArray());
                return ToolResult(new JsonObject { ["query"] = query, ["capabilities"] = list });
            }
            case "execute_capability":
            {
                // The reference calls the id "name" and the arguments "body"; the first names this server used are still accepted.
                var id = (arguments["name"] ?? arguments["capability_id"])?.GetValue<string>();
                var capabilityArguments = (arguments["body"] ?? arguments["arguments"]) as JsonObject ?? new JsonObject();
                foreach (var provider in providers)
                {
                    var capability = await provider.ResolveAsync(id ?? "", principal, services);
                    if (capability is null) continue;
                    if (!principal.Scopes.Contains(capability.RequiredScope)) return ToolError("insufficient_scope", $"This capability needs the {capability.RequiredScope} scope.");
                    var outcome = await provider.ExecuteAsync(capability.Id, capabilityArguments, principal, services);
                    return outcome.Result is { } result ? (outcome.Passthrough ? result : ToolResult(result)) : ToolError(outcome.ErrorCode ?? "capability_failed", outcome.ErrorMessage ?? "The capability failed.");
                }
                return ToolError("unknown_capability", $"No capability named '{id}'. Use search_capabilities to list them.");
            }
            default:
                // Areas can add tools of their own (see IMcpToolProvider).
                foreach (var provider in services.GetServices<IMcpToolProvider>())
                    if (provider.Tools.Any(t => t.Name == name))
                        return await provider.CallAsync(name!, arguments, principal, services);
                return ToolError("unknown_tool", $"No tool named '{name}'.");
        }
    }

    public static JsonObject ToolResult(JsonObject structured) => new()
    {
        ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = structured.ToJsonString() }),
        ["structuredContent"] = structured,
        ["isError"] = false,
    };

    public static JsonObject ToolError(string code, string message) => new()
    {
        ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = new JsonObject { ["error"] = code, ["message"] = message }.ToJsonString() }),
        ["isError"] = true,
    };

    private static JsonObject RpcResult(JsonNode? id, JsonObject result) => new() { ["jsonrpc"] = "2.0", ["id"] = id, ["result"] = result };

    private static JsonObject RpcError(JsonNode? id, int code, string message) =>
        new() { ["jsonrpc"] = "2.0", ["id"] = id, ["error"] = new JsonObject { ["code"] = code, ["message"] = message } };
}
