using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace WorkAI360.Api.Features.Connections;

/// <summary>Where and how to talk to one MCP server: its address and the headers to send (credential and administrator headers).</summary>
public sealed record McpTarget(string Url, IReadOnlyList<(string Name, string Value)> Headers);

public enum McpFailure { Unauthorized, Http, Network, Timeout, Protocol, Tool, TooLarge, Refused }

/// <summary>A failed exchange with a remote MCP server. Messages never carry the server's own text unless marked as its words.</summary>
public sealed class McpException(McpFailure kind, string message, int? httpStatus = null, int? jsonRpcCode = null, string? providerMessage = null, string? wwwAuthenticate = null)
    : Exception(message)
{
    public McpFailure Kind { get; } = kind;
    public int? HttpStatus { get; } = httpStatus;
    public int? JsonRpcCode { get; } = jsonRpcCode;
    public string? ProviderMessage { get; } = providerMessage;
    public string? WwwAuthenticate { get; } = wwwAuthenticate;
}

public sealed record McpTool(string Name, string? Title, string? Description, JsonNode InputSchema, JsonNode? OutputSchema, JsonNode? Annotations, JsonNode? Meta);

/// <summary>
/// A client for MCP over Streamable HTTP: <c>initialize</c>, the <c>initialized</c> notification, <c>tools/list</c> (all pages) and <c>tools/call</c>.
/// Replies may be plain JSON or an event stream; the session id the server gives is sent back on every later request.
/// </summary>
public sealed class McpClient(GuardedHttp http)
{
    public const string LatestProtocol = "2025-06-18";
    private const int MaxPages = 20;
    private const int MaxTools = 1000;

    private sealed class Session(McpTarget target, GuardedHttp http, TimeSpan timeout, CancellationToken ct)
    {
        private int _next;
        public string? SessionId;
        public string Protocol = LatestProtocol;

        public async Task<JsonObject> RequestAsync(string method, JsonObject? parameters)
        {
            var id = ++_next;
            var message = new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id, ["method"] = method };
            if (parameters is not null) message["params"] = parameters;
            var reply = await PostAsync(message);
            var parsed = Parse(reply, id) ?? throw new McpException(McpFailure.Protocol, "The server did not answer the request.");
            if (parsed["error"] is JsonObject error)
            {
                var code = error["code"]?.GetValueKind() == JsonValueKind.Number ? error["code"]!.GetValue<int>() : (int?)null;
                var text = error["message"]?.GetValueKind() == JsonValueKind.String ? error["message"]!.GetValue<string>() : null;
                throw new McpException(McpFailure.Tool, "The server returned an error.", reply.Status == 0 ? null : (int)reply.Status, code, text);
            }
            return parsed["result"]?.DeepClone() as JsonObject ?? throw new McpException(McpFailure.Protocol, "The server's answer had no result.");
        }

        public async Task NotifyAsync(string method) => await PostAsync(new JsonObject { ["jsonrpc"] = "2.0", ["method"] = method }, expectBody: false);

        private async Task<GuardedHttp.Reply> PostAsync(JsonObject message, bool expectBody = true)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, target.Url) { Content = new StringContent(message.ToJsonString(), Encoding.UTF8, "application/json") };
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
            foreach (var (name, value) in target.Headers) request.Headers.TryAddWithoutValidation(name, value);
            if (SessionId is not null) request.Headers.TryAddWithoutValidation("Mcp-Session-Id", SessionId);
            if (message["method"]?.GetValue<string>() != "initialize") request.Headers.TryAddWithoutValidation("MCP-Protocol-Version", Protocol);
            GuardedHttp.Reply reply;
            try { reply = await http.SendAsync(request, timeout, ct); }
            catch (UrlRefusedException e) { throw new McpException(McpFailure.Refused, e.Message); }
            catch (ResponseTooLargeException e) { throw new McpException(McpFailure.TooLarge, e.Message); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { throw new McpException(McpFailure.Timeout, "The server took too long to answer."); }
            catch (HttpRequestException e) when (e.InnerException is UrlRefusedException refused) { throw new McpException(McpFailure.Refused, refused.Message); }
            catch (HttpRequestException) { throw new McpException(McpFailure.Network, "The server could not be reached."); }
            if (reply.Headers.TryGetValues("Mcp-Session-Id", out var sid)) SessionId ??= sid.First();
            if (reply.Status is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
                throw new McpException(McpFailure.Unauthorized, $"The server rejected the supplied authorization (HTTP {(int)reply.Status}).", (int)reply.Status,
                    wwwAuthenticate: reply.Headers.WwwAuthenticate.Count > 0 ? string.Join(", ", reply.Headers.WwwAuthenticate.Select(h => h.ToString())) : null);
            if ((int)reply.Status is < 200 or >= 300) throw new McpException(McpFailure.Http, $"The server answered HTTP {(int)reply.Status}.", (int)reply.Status);
            if (!expectBody) return reply;
            return reply;
        }

        /// <summary>The JSON-RPC message with this id from a JSON body, a batch, or an event stream.</summary>
        private static JsonObject? Parse(GuardedHttp.Reply reply, int id)
        {
            var text = reply.Text;
            IEnumerable<string> payloads = reply.ContentType == "text/event-stream" ? EventData(text) : [text];
            foreach (var payload in payloads)
            {
                JsonNode? node;
                try { node = JsonNode.Parse(payload); }
                catch (JsonException) { continue; }
                foreach (var candidate in node is JsonArray arr ? arr.OfType<JsonObject>() : node is JsonObject o ? [o] : [])
                    if (candidate["id"]?.GetValueKind() == JsonValueKind.Number && candidate["id"]!.GetValue<int>() == id && (candidate.ContainsKey("result") || candidate.ContainsKey("error"))) return candidate;
            }
            return null;
        }

        private static IEnumerable<string> EventData(string stream)
        {
            var data = new StringBuilder();
            foreach (var line in stream.Replace("\r\n", "\n").Split('\n'))
            {
                if (line.Length == 0) { if (data.Length > 0) { yield return data.ToString(); data.Clear(); } continue; }
                if (!line.StartsWith("data:", StringComparison.Ordinal)) continue;
                if (data.Length > 0) data.Append('\n');
                data.Append(line[5..].TrimStart(' '));
            }
            if (data.Length > 0) yield return data.ToString();
        }
    }

    private async Task<Session> OpenAsync(McpTarget target, CancellationToken ct)
    {
        var session = new Session(target, http, http.ToolTimeout, ct);
        var init = await session.RequestAsync("initialize", new JsonObject
        {
            ["protocolVersion"] = LatestProtocol,
            ["capabilities"] = new JsonObject(),
            ["clientInfo"] = new JsonObject { ["name"] = "openwork-den", ["title"] = "OpenWork", ["version"] = "0.1.0" },
        });
        if (init["protocolVersion"]?.GetValueKind() == JsonValueKind.String) session.Protocol = init["protocolVersion"]!.GetValue<string>();
        await session.NotifyAsync("notifications/initialized");
        return session;
    }

    /// <summary>Opens a session only to prove the server speaks MCP with this credential.</summary>
    public async Task<string?> InitializeAsync(McpTarget target, CancellationToken ct = default) => (await OpenAsync(target, ct)).Protocol;

    public async Task<IReadOnlyList<McpTool>> ListToolsAsync(McpTarget target, CancellationToken ct = default)
    {
        var session = await OpenAsync(target, ct);
        var tools = new List<McpTool>();
        string? cursor = null;
        for (var page = 0; page < MaxPages; page++)
        {
            var result = await session.RequestAsync("tools/list", cursor is null ? null : new JsonObject { ["cursor"] = cursor });
            foreach (var item in (result["tools"] as JsonArray)?.OfType<JsonObject>() ?? [])
            {
                if (item["name"]?.GetValueKind() != JsonValueKind.String) continue;
                string? S(string key) => item[key]?.GetValueKind() == JsonValueKind.String ? item[key]!.GetValue<string>() : null;
                tools.Add(new McpTool(S("name")!, S("title"), S("description"), item["inputSchema"]?.DeepClone() ?? JsonNode.Parse("""{"type":"object"}""")!, item["outputSchema"]?.DeepClone(), item["annotations"]?.DeepClone(), item["_meta"]?.DeepClone()));
                if (tools.Count >= MaxTools) return tools;
            }
            cursor = result["nextCursor"]?.GetValueKind() == JsonValueKind.String ? result["nextCursor"]!.GetValue<string>() : null;
            if (string.IsNullOrEmpty(cursor)) break;
        }
        return tools;
    }

    public async Task<JsonObject> CallToolAsync(McpTarget target, string name, JsonObject arguments, CancellationToken ct = default)
    {
        var session = await OpenAsync(target, ct);
        return await session.RequestAsync("tools/call", new JsonObject { ["name"] = name, ["arguments"] = arguments.DeepClone() });
    }
}
