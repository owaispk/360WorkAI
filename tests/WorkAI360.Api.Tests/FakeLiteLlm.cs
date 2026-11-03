using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace WorkAI360.Api.Tests;

/// <summary>
/// A fake LiteLLM proxy for the gateway tests, on 127.0.0.1 with a free port: the management routes Den calls (teams, keys, model lists, request
/// logs) and chat completions that honour each key's models, so a test can prove a key Den issued really works or really stopped working.
/// </summary>
public sealed class FakeLiteLlm : IAsyncDisposable
{
    public const string MasterKey = "sk-fake-master";
    public const string ModelOnlyKey = "sk-fake-model-only";

    public sealed class Key
    {
        public required string Value { get; init; }
        public required string Hash { get; init; }
        public string? TeamId { get; set; }
        public string? UserId { get; set; }
        public string? Alias { get; set; }
        public List<string> Models { get; set; } = [];
        public List<string> AllowedRoutes { get; set; } = [];
        public JsonObject? Metadata { get; set; }
    }

    public ConcurrentDictionary<string, Key> Keys { get; } = new();
    public ConcurrentDictionary<string, List<string>> Teams { get; } = new();
    public List<string> Models { get; } = ["fake-large", "fake-small", "text-embed"];
    public ConcurrentQueue<JsonObject> SpendRows { get; } = new();
    public ConcurrentQueue<string> Calls { get; } = new();
    public volatile bool FailKeyDelete;
    /// <summary>Answer /spend/logs/v2 without applying team_id, as a proxy that ignores the filter would.</summary>
    public volatile bool IgnoreTeamFilter;
    public volatile bool Down;

    private readonly WebApplication _app;
    public string Origin { get; private set; } = "";

    private FakeLiteLlm(WebApplication app) { _app = app; }

    public static async Task<FakeLiteLlm> StartAsync()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        var app = builder.Build();
        var fake = new FakeLiteLlm(app);
        fake.Map(app);
        await app.StartAsync();
        fake.Origin = app.Urls.First().TrimEnd('/');
        return fake;
    }

    public static string HashOf(string key) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key))).ToLowerInvariant();

    private string? Bearer(HttpContext ctx) => ctx.Request.Headers.Authorization.ToString() is var h && h.StartsWith("Bearer ") ? h[7..] : null;
    private bool IsAdmin(HttpContext ctx) => Bearer(ctx) == MasterKey;

    private static async Task<JsonObject> BodyAsync(HttpContext ctx) => JsonNode.Parse(await new StreamReader(ctx.Request.Body).ReadToEndAsync())?.AsObject() ?? [];

    private void Map(WebApplication app)
    {
        app.Use(async (ctx, next) =>
        {
            Calls.Enqueue($"{ctx.Request.Method} {ctx.Request.Path}");
            if (Down) { ctx.Response.StatusCode = 503; return; }
            var key = Bearer(ctx);
            var known = key == MasterKey || key == ModelOnlyKey || (key is not null && Keys.ContainsKey(HashOf(key)));
            if (!known) { ctx.Response.StatusCode = 401; await ctx.Response.WriteAsJsonAsync(new { error = "invalid key" }); return; }
            var adminRoute = !ctx.Request.Path.StartsWithSegments("/v1");
            if (adminRoute && !IsAdmin(ctx)) { ctx.Response.StatusCode = 403; await ctx.Response.WriteAsJsonAsync(new { error = "not admin" }); return; }
            await next();
        });

        app.MapGet("/team/list", () => Results.Json(Teams.Select(t => new { team_id = t.Key, team_alias = "openwork", models = t.Value })));
        app.MapGet("/v1/models", (HttpContext ctx) =>
        {
            var key = Bearer(ctx)!;
            var models = Keys.TryGetValue(HashOf(key), out var k) ? k.Models : Models;
            return Results.Json(new { data = models.Select(m => new { id = m, @object = "model" }).Append(new { id = "openai/*", @object = "model" }) });
        });
        app.MapGet("/model_group/info", () => Results.Json(new
        {
            data = Models.Select(m => new JsonObject
            {
                ["model_group"] = m, ["mode"] = m.StartsWith("text-embed") ? "embedding" : "chat",
                ["max_input_tokens"] = m == "fake-large" ? 200000 : 8000, ["max_output_tokens"] = 4096,
                ["input_cost_per_token"] = m == "fake-large" ? 0.000003 : 0, ["output_cost_per_token"] = m == "fake-large" ? 0.000015 : 0,
                ["supports_function_calling"] = true,
            }),
        }));
        app.MapGet("/team/info", (string team_id) => Teams.ContainsKey(team_id) ? Results.Json(new { team_id }) : Results.NotFound());
        app.MapPost("/team/new", async (HttpContext ctx) =>
        {
            var body = await BodyAsync(ctx);
            var id = Guid.NewGuid().ToString();
            Teams[id] = body["models"]!.AsArray().Select(m => (string)m!).ToList();
            return Results.Json(new { team_id = id, models = Teams[id] });
        });
        app.MapPost("/team/update", async (HttpContext ctx) =>
        {
            var body = await BodyAsync(ctx);
            var id = (string)body["team_id"]!;
            if (!Teams.ContainsKey(id)) return Results.NotFound();
            Teams[id] = body["models"]!.AsArray().Select(m => (string)m!).ToList();
            return Results.Json(new { team_id = id });
        });
        app.MapPost("/team/delete", async (HttpContext ctx) =>
        {
            var body = await BodyAsync(ctx);
            foreach (var id in body["team_ids"]!.AsArray()) Teams.TryRemove((string)id!, out _);
            return Results.Json(new { deleted = true });
        });
        app.MapPost("/key/generate", async (HttpContext ctx) =>
        {
            var body = await BodyAsync(ctx);
            var value = "sk-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
            var key = new Key
            {
                Value = value, Hash = HashOf(value), TeamId = (string?)body["team_id"], UserId = (string?)body["user_id"], Alias = (string?)body["key_alias"],
                Models = body["models"]?.AsArray().Select(m => (string)m!).ToList() ?? [], AllowedRoutes = body["allowed_routes"]?.AsArray().Select(m => (string)m!).ToList() ?? [],
                Metadata = body["metadata"]?.AsObject(),
            };
            Keys[key.Hash] = key;
            return Results.Json(new { key = value, token_id = key.Hash });
        });
        app.MapPost("/key/update", async (HttpContext ctx) =>
        {
            var body = await BodyAsync(ctx);
            if (!Keys.TryGetValue((string)body["key"]!, out var key)) return Results.NotFound();
            key.Models = body["models"]!.AsArray().Select(m => (string)m!).ToList();
            return Results.Json(new { key = key.Hash });
        });
        app.MapPost("/key/delete", async (HttpContext ctx) =>
        {
            if (FailKeyDelete) return Results.StatusCode(500);
            var body = await BodyAsync(ctx);
            foreach (var h in body["keys"]!.AsArray()) Keys.TryRemove((string)h!, out _);
            return Results.Json(new { deleted_keys = body["keys"] });
        });
        app.MapGet("/spend/logs/v2", (HttpContext ctx) =>
        {
            var team = IgnoreTeamFilter ? "" : ctx.Request.Query["team_id"].ToString();
            var rows = SpendRows.Where(r => team.Length == 0 || (string?)r["team_id"] == team).Select(r => r.DeepClone()).ToArray();
            return Results.Json(new JsonObject { ["data"] = new JsonArray(rows), ["total"] = rows.Length, ["page"] = 1, ["page_size"] = 100, ["total_pages"] = 1 });
        });
        app.MapPost("/v1/chat/completions", async (HttpContext ctx) =>
        {
            var body = await BodyAsync(ctx);
            var model = (string?)body["model"];
            var key = Bearer(ctx)!;
            if (Keys.TryGetValue(HashOf(key), out var k) && !k.Models.Contains(model!)) return Results.StatusCode(403);
            return Results.Json(new { id = "chatcmpl-fake", choices = new[] { new { index = 0, message = new { role = "assistant", content = "pong" } } }, usage = new { prompt_tokens = 7, completion_tokens = 3, total_tokens = 10 } });
        });
    }

    /// <summary>A logged request, as /spend/logs/v2 returns it.</summary>
    public void Log(string keyHash, string? teamId, string model, long tokens, double spend, string status = "success", DateTime? at = null) =>
        SpendRows.Enqueue(new JsonObject
        {
            ["api_key"] = keyHash, ["team_id"] = teamId ?? "", ["model_group"] = model, ["total_tokens"] = tokens, ["spend"] = spend, ["status"] = status,
            ["startTime"] = (at ?? DateTime.UtcNow).ToString("yyyy-MM-ddTHH:mm:ss.fff+00:00"),
        });

    public async ValueTask DisposeAsync() => await _app.DisposeAsync();
}
