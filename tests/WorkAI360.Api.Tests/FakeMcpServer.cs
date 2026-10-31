using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WorkAI360.Api.Tests;

/// <summary>
/// A real MCP server (Streamable HTTP) plus an OAuth provider, listening on 127.0.0.1 on a free port, for the connection tests.
/// <c>/none/mcp</c> needs no sign-in, <c>/key/mcp</c> needs <c>Bearer {Key}</c>, <c>/oauth/mcp</c> needs a token this server's own provider issued,
/// <c>/sse/mcp</c> answers as an event stream, <c>/paged/mcp</c> lists tools in pages, <c>/redirect/mcp</c> answers 302. It records what it receives.
/// </summary>
public sealed class FakeMcpServer : IAsyncDisposable
{
    public const string Key = "fake-key-0123456789";
    public sealed record Call(string Server, string Method, string Auth, string? Tool, JsonNode? Args, Dictionary<string, string> Headers);
    public sealed record OAuthCall(string Kind, string? Grant = null, bool HasVerifier = false, string? Challenge = null, string? Resource = null, string? Scope = null, string? RedirectUri = null);

    public ConcurrentQueue<Call> Calls { get; } = new();
    public ConcurrentQueue<OAuthCall> OAuthCalls { get; } = new();
    public ConcurrentQueue<string> Other { get; } = new();
    public volatile bool RejectRefresh;
    /// <summary>When set the provider accepts an authorization code more than once (so a test can prove OUR state is single use).</summary>
    public volatile bool ReusableCodes;
    public volatile int SlowMs;
    public volatile bool BigBody;
    public volatile int TokenLifetimeSeconds = 3600;
    public volatile string? AuthorizationEndpointOverride;
    public volatile string? IssuerOverride;

    private readonly WebApplication _app;
    private readonly ConcurrentDictionary<string, (string Challenge, string RedirectUri)> _codes = new();
    private readonly ConcurrentDictionary<string, DateTime> _access = new();
    private readonly ConcurrentDictionary<string, byte> _refresh = new();
    private int _counter;
    public string Origin { get; private set; } = "";

    private static readonly JsonArray Tools = JsonNode.Parse("""
    [{"name":"echo","description":"Echo a message back.","inputSchema":{"type":"object","properties":{"message":{"type":"string"}},"required":["message"]},"annotations":{"readOnlyHint":true}},
     {"name":"add","description":"Add two numbers.","inputSchema":{"type":"object","properties":{"a":{"type":"number"},"b":{"type":"number"}},"required":["a","b"]},"annotations":{"readOnlyHint":true}},
     {"name":"delete_everything","description":"A dangerous tool a policy should be able to switch off.","inputSchema":{"type":"object","properties":{}},"annotations":{"destructiveHint":true}}]
    """)!.AsArray();

    private FakeMcpServer(WebApplication app) { _app = app; }

    public string Url(string kind) => $"{Origin}/{kind}/mcp";

    public static async Task<FakeMcpServer> StartAsync()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        var app = builder.Build();
        var fake = new FakeMcpServer(app);
        app.Run(fake.HandleAsync);
        await app.StartAsync();
        fake.Origin = app.Urls.First().Replace("localhost", "127.0.0.1");
        return fake;
    }

    public IReadOnlyList<Call> McpCalls(string? server = null, string? method = null) => Calls.Where(c => (server is null || c.Server == server) && (method is null || c.Method == method)).ToList();
    public void Reset() { Calls.Clear(); OAuthCalls.Clear(); Other.Clear(); }
    public void ExpireAllTokens() { foreach (var key in _access.Keys) _access[key] = DateTime.MinValue; }

    private static async Task Json(HttpContext ctx, int status, JsonNode body, Dictionary<string, string>? headers = null)
    {
        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = "application/json";
        foreach (var (k, v) in headers ?? []) ctx.Response.Headers[k] = v;
        await ctx.Response.WriteAsync(body.ToJsonString());
    }

    private string NewAccess()
    {
        var token = $"at_{Interlocked.Increment(ref _counter)}_{Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant()}";
        _access[token] = DateTime.UtcNow.AddSeconds(TokenLifetimeSeconds);
        return token;
    }

    private async Task HandleAsync(HttpContext ctx)
    {
        var path = ctx.Request.Path.Value ?? "";
        string body;
        using (var reader = new StreamReader(ctx.Request.Body)) body = await reader.ReadToEndAsync();

        // ---- OAuth provider ----
        if (path == "/.well-known/oauth-protected-resource/oauth/mcp")
            { await Json(ctx, 200, new JsonObject { ["resource"] = $"{Origin}/oauth/mcp", ["authorization_servers"] = new JsonArray(Origin), ["scopes_supported"] = new JsonArray("mcp") }); return; }
        if (path is "/.well-known/oauth-authorization-server")
        {
            await Json(ctx, 200, new JsonObject
            {
                ["issuer"] = IssuerOverride ?? Origin, ["authorization_endpoint"] = AuthorizationEndpointOverride ?? $"{Origin}/authorize", ["token_endpoint"] = $"{Origin}/token", ["registration_endpoint"] = $"{Origin}/register",
                ["response_types_supported"] = new JsonArray("code"), ["grant_types_supported"] = new JsonArray("authorization_code", "refresh_token"), ["code_challenge_methods_supported"] = new JsonArray("S256"),
                ["token_endpoint_auth_methods_supported"] = new JsonArray("none"),
            });
            return;
        }
        if (path == "/register" && ctx.Request.Method == "POST")
        {
            var meta = JsonNode.Parse(body)!.AsObject();
            OAuthCalls.Enqueue(new OAuthCall("register", RedirectUri: meta["redirect_uris"]?[0]?.GetValue<string>()));
            meta["client_id"] = "client_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(6)).ToLowerInvariant();
            { await Json(ctx, 201, meta); return; }
        }
        if (path == "/authorize")
        {
            var q = ctx.Request.Query;
            OAuthCalls.Enqueue(new OAuthCall("authorize", Challenge: q["code_challenge"], Resource: q["resource"], Scope: q["scope"], RedirectUri: q["redirect_uri"]));
            var redirect = q["redirect_uri"].ToString();
            var state = Uri.EscapeDataString(q["state"].ToString());
            if (q.ContainsKey("deny")) { ctx.Response.Redirect($"{redirect}?error=access_denied&state={state}"); return; }
            var code = "code_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();
            _codes[code] = (q["code_challenge"].ToString(), redirect);
            var iss = q.ContainsKey("wrong_iss") ? "&iss=" + Uri.EscapeDataString("https://evil.example") : "";
            ctx.Response.Redirect($"{redirect}?code={code}&state={state}{iss}");
            return;
        }
        if (path == "/token" && ctx.Request.Method == "POST")
        {
            var form = body.Split('&', StringSplitOptions.RemoveEmptyEntries).Select(p => p.Split('=', 2)).ToDictionary(p => Uri.UnescapeDataString(p[0]), p => Uri.UnescapeDataString(p.ElementAtOrDefault(1) ?? ""));
            OAuthCalls.Enqueue(new OAuthCall("token", form.GetValueOrDefault("grant_type"), form.ContainsKey("code_verifier"), Resource: form.GetValueOrDefault("resource")));
            if (form.GetValueOrDefault("grant_type") == "authorization_code")
            {
                var codeKey = form.GetValueOrDefault("code") ?? "";
                if (!(ReusableCodes ? _codes.TryGetValue(codeKey, out var issued) : _codes.TryRemove(codeKey, out issued))) { await Json(ctx, 400, new JsonObject { ["error"] = "invalid_grant" }); return; }
                var challenge = Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(form.GetValueOrDefault("code_verifier") ?? ""))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
                if (challenge != issued.Challenge || form.GetValueOrDefault("redirect_uri") != issued.RedirectUri) { await Json(ctx, 400, new JsonObject { ["error"] = "invalid_grant", ["error_description"] = "pkce or redirect mismatch" }); return; }
                var refresh = "rt_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant(); _refresh[refresh] = 0;
                { await Json(ctx, 200, new JsonObject { ["access_token"] = NewAccess(), ["token_type"] = "Bearer", ["expires_in"] = TokenLifetimeSeconds, ["refresh_token"] = refresh, ["scope"] = "mcp" }); return; }
            }
            if (form.GetValueOrDefault("grant_type") == "refresh_token")
            {
                if (SlowMs > 0) await Task.Delay(200);   // widen the window in which two refreshes could overlap
                if (RejectRefresh || !_refresh.ContainsKey(form.GetValueOrDefault("refresh_token") ?? "")) { await Json(ctx, 400, new JsonObject { ["error"] = "invalid_grant" }); return; }
                { await Json(ctx, 200, new JsonObject { ["access_token"] = NewAccess(), ["token_type"] = "Bearer", ["expires_in"] = TokenLifetimeSeconds, ["refresh_token"] = form["refresh_token"], ["scope"] = "mcp" }); return; }
            }
            { await Json(ctx, 400, new JsonObject { ["error"] = "unsupported_grant_type" }); return; }
        }
        if (path == "/secret") { Other.Enqueue("secret"); ctx.Response.StatusCode = 200; await ctx.Response.WriteAsync("internal"); return; }

        // ---- MCP ----
        var kind = path switch { "/none/mcp" => "none", "/key/mcp" => "key", "/oauth/mcp" => "oauth", "/sse/mcp" => "sse", "/paged/mcp" => "paged", "/redirect/mcp" => "redirect", _ => null };
        if (kind is null) { ctx.Response.StatusCode = 404; return; }
        if (kind == "redirect") { Other.Enqueue("redirect-hit"); ctx.Response.Redirect($"{Origin}/secret"); return; }
        if (ctx.Request.Method != "POST") { ctx.Response.StatusCode = 405; return; }
        var auth = ctx.Request.Headers.Authorization.ToString();
        JsonObject message;
        try { message = JsonNode.Parse(body)!.AsObject(); } catch { await Json(ctx, 400, new JsonObject { ["jsonrpc"] = "2.0", ["id"] = null, ["error"] = new JsonObject { ["code"] = -32700, ["message"] = "Parse error" } }); return; }
        var method = message["method"]!.GetValue<string>();
        var headers = ctx.Request.Headers.Where(h => h.Key.StartsWith("x-test-", StringComparison.OrdinalIgnoreCase)).ToDictionary(h => h.Key.ToLowerInvariant(), h => h.Value.ToString());
        Calls.Enqueue(new Call(kind, method, auth, message["params"]?["name"]?.GetValue<string>(), message["params"]?["arguments"]?.DeepClone(), headers));
        if (kind == "key" && auth != $"Bearer {Key}") { await Json(ctx, 401, new JsonObject { ["error"] = "unauthorized" }); return; }
        if (kind == "oauth")
        {
            var token = auth.StartsWith("Bearer ") ? auth[7..] : "";
            if (!_access.TryGetValue(token, out var expiry) || expiry < DateTime.UtcNow)
            {
                await Json(ctx, 401, new JsonObject { ["error"] = "invalid_token" }, new() { ["WWW-Authenticate"] = $"Bearer resource_metadata=\"{Origin}/.well-known/oauth-protected-resource/oauth/mcp\"" });
                return;
            }
        }
        if (SlowMs > 0 && method == "tools/call") await Task.Delay(SlowMs);
        if (message["id"] is null) { ctx.Response.StatusCode = 202; return; }
        var id = message["id"]!.DeepClone();
        async Task Reply(JsonObject result)
        {
            var envelope = new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id, ["result"] = result }.ToJsonString();
            ctx.Response.Headers["Mcp-Session-Id"] = "fake-session";
            if (kind == "sse")
            {
                ctx.Response.ContentType = "text/event-stream";
                await ctx.Response.WriteAsync($"event: message\ndata: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{{}}}}\n\nevent: message\ndata: {envelope}\n\n");
            }
            else { ctx.Response.ContentType = "application/json"; await ctx.Response.WriteAsync(envelope); }
        }
        switch (method)
        {
            case "initialize": await Reply(new JsonObject { ["protocolVersion"] = message["params"]?["protocolVersion"]?.DeepClone() ?? "2025-06-18", ["capabilities"] = new JsonObject { ["tools"] = new JsonObject() }, ["serverInfo"] = new JsonObject { ["name"] = "fake", ["version"] = "1" } }); break;
            case "tools/list":
                if (kind == "paged")
                {
                    var cursor = message["params"]?["cursor"]?.GetValue<string>();
                    var page = cursor is null ? new JsonArray(Tools[0]!.DeepClone()) : new JsonArray(Tools[1]!.DeepClone(), Tools[2]!.DeepClone());
                    await Reply(cursor is null ? new JsonObject { ["tools"] = page, ["nextCursor"] = "page2" } : new JsonObject { ["tools"] = page });
                }
                else await Reply(new JsonObject { ["tools"] = Tools.DeepClone() });
                break;
            case "tools/call":
            {
                var name = message["params"]?["name"]?.GetValue<string>();
                var args = message["params"]?["arguments"]?.AsObject();
                if (BigBody) { await Reply(new JsonObject { ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = new string('x', 6 * 1024 * 1024) }) }); break; }
                if (name == "echo") await Reply(new JsonObject { ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = $"echo: {args?["message"]}" }), ["structuredContent"] = new JsonObject { ["echoed"] = args?["message"]?.DeepClone() } });
                else if (name == "add") await Reply(new JsonObject { ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = ((double)(args?["a"] ?? 0) + (double)(args?["b"] ?? 0)).ToString() }) });
                else if (name == "delete_everything") await Reply(new JsonObject { ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = "everything deleted" }) });
                else await Json(ctx, 200, new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id, ["error"] = new JsonObject { ["code"] = -32602, ["message"] = $"Unknown tool: {name}" } });
                break;
            }
            default: await Json(ctx, 200, new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id, ["error"] = new JsonObject { ["code"] = -32601, ["message"] = "Method not found" } }); break;
        }
    }

    public async ValueTask DisposeAsync() { await _app.StopAsync(); await _app.DisposeAsync(); }
}
