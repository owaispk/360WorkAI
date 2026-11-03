using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Features.Connections;

namespace WorkAI360.Api.Features.Gateway;

/// <summary>Settings for the AI Gateway (<c>Gateway:*</c>).</summary>
public sealed class GatewayOptions
{
    public const string Section = "Gateway";

    /// <summary>Gateway management is on for this deployment (the reference's GATEWAY_ENABLED). Off: management routes answer 403 gateway_not_enabled.</summary>
    public bool Enabled { get; set; }

    public LiteLlmDeploymentOptions LiteLlm { get; set; } = new();

    public sealed class LiteLlmDeploymentOptions
    {
        /// <summary>The deployment's own LiteLLM proxy root (e.g. http://litellm:4000). Trusted: it is the operator's, usually on a private network.</summary>
        public string? BaseUrl { get; set; }
        /// <summary>Its master key (or a proxy admin key). Never returned.</summary>
        public string? MasterKey { get; set; }
        /// <summary>The address people's desktops use to reach it, when it differs from <see cref="BaseUrl"/> (e.g. https://ai.example.com).</summary>
        public string? PublicUrl { get; set; }
        public int TimeoutSeconds { get; set; } = 10;
    }

    public bool HasDeploymentProxy => !string.IsNullOrWhiteSpace(LiteLlm.BaseUrl) && !string.IsNullOrWhiteSpace(LiteLlm.MasterKey);
}

/// <summary>A failed LiteLLM call. Messages are written here and never contain a key.</summary>
public sealed class LiteLlmException(string code, string message, int? status = null) : Exception(message)
{
    /// <summary>invalid_base_url | unreachable | unauthorized | forbidden | not_admin | bad_response | no_models</summary>
    public string Code { get; } = code;
    public int? HttpStatus { get; } = status;
}

public sealed record LiteLlmModel(string Id, JsonObject Config);
public sealed record LiteLlmIssued(string Key, string TokenHash);
public sealed record LiteLlmSpendRow(string TokenHash, string? TeamId, string? Model, long TotalTokens, double Spend, string Status, DateTime StartTime);

/// <summary>
/// The LiteLLM management API (the reference's <c>llm/litellm.ts</c>), for one proxy and one admin key. Every call is time-boxed, never follows a
/// redirect and never echoes a key. Calls to the operator's proxy go out directly; calls to a workspace's proxy go through the outbound guard.
/// </summary>
public sealed class LiteLlmClient
{
    private static readonly HashSet<string> NonChatModes = ["embedding", "image_generation", "image_edit", "audio_transcription", "audio_speech", "rerank", "moderation", "video_generation", "ocr", "search"];
    private readonly string _root;
    private readonly string _key;
    private readonly Func<HttpRequestMessage, TimeSpan, CancellationToken, Task<(HttpStatusCode Status, string Body)>> _send;
    private readonly TimeSpan _timeout;

    public LiteLlmClient(string root, string key, Func<HttpRequestMessage, TimeSpan, CancellationToken, Task<(HttpStatusCode, string)>> send, TimeSpan timeout)
    {
        _root = root.TrimEnd('/');
        _key = key;
        _send = send;
        _timeout = timeout;
    }

    public string InferenceBaseUrl => _root + "/v1";

    /// <summary>
    /// Accepts the proxy root or its /v1 base (or a pasted /chat/completions or /models address); returns the root. No credentials, query or fragment.
    /// </summary>
    public static string NormalizeRoot(string raw)
    {
        if (!Uri.TryCreate(raw.Trim(), UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https"))
            throw new LiteLlmException("invalid_base_url", "Enter the LiteLLM proxy URL, for example https://litellm.example.com.");
        if (!string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment))
            throw new LiteLlmException("invalid_base_url", "The LiteLLM URL must not include credentials, a query string or a fragment.");
        var path = uri.AbsolutePath.TrimEnd('/');
        foreach (var suffix in new[] { "/chat/completions", "/models" })
            if (path.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)) path = path[..^suffix.Length];
        if (path.EndsWith("/v1", StringComparison.OrdinalIgnoreCase)) path = path[..^3];
        return $"{uri.Scheme}://{uri.Authority}{path}";
    }

    private async Task<JsonNode?> RequestAsync(string path, JsonObject? body, CancellationToken ct, bool notFoundIsNull = false)
    {
        using var request = new HttpRequestMessage(body is null ? HttpMethod.Get : HttpMethod.Post, _root + path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _key);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (body is not null) request.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
        var name = path.Split('?')[0];
        (HttpStatusCode status, string text) reply;
        try { reply = await _send(request, _timeout, ct); }
        catch (UrlRefusedException e) { throw new LiteLlmException("invalid_base_url", e.Message); }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or OperationCanceledException or IOException or ResponseTooLargeException)
        {
            throw new LiteLlmException("unreachable", "OpenWork could not reach the LiteLLM proxy. Check the URL and that it accepts connections from OpenWork.");
        }
        var code = (int)reply.status;
        if (code == 401) throw new LiteLlmException("unauthorized", "LiteLLM rejected the key.", 401);
        if (code == 403) throw new LiteLlmException("forbidden", "The LiteLLM key is not allowed to call this endpoint.", 403);
        if (code == 404 && notFoundIsNull) return null;
        if (code is >= 300 and < 400) throw new LiteLlmException("bad_response", $"LiteLLM redirected {name}; OpenWork does not follow redirects.", code);
        if (code is < 200 or >= 300) throw new LiteLlmException("bad_response", $"LiteLLM returned HTTP {code} for {name}.", code);
        try { return JsonNode.Parse(reply.text); }
        catch (JsonException) { throw new LiteLlmException("bad_response", $"LiteLLM returned invalid JSON for {name}."); }
    }

    private static string? Str(JsonNode? n) => n is JsonValue v && v.TryGetValue<string>(out var s) && !string.IsNullOrWhiteSpace(s) ? s.Trim() : null;
    private static double? Num(JsonNode? n) => n is JsonValue v && v.TryGetValue<double>(out var d) && double.IsFinite(d) ? d : null;

    /// <summary>Proves the key can manage LiteLLM: admin routes answer a valid non-admin key with 401 or 403.</summary>
    public async Task RequireAdminAsync(CancellationToken ct)
    {
        try { await RequestAsync("/team/list", null, ct); }
        catch (LiteLlmException e) when (e.Code is "unauthorized" or "forbidden")
        {
            throw new LiteLlmException("not_admin", "This LiteLLM key can call models but can't manage LiteLLM. Use the master key or a proxy admin key.", e.HttpStatus);
        }
    }

    /// <summary>Chat-capable models the proxy serves, with models.dev-shaped configs from LiteLLM's public model-group facts.</summary>
    public async Task<List<LiteLlmModel>> ListModelsAsync(CancellationToken ct)
    {
        var listed = await RequestAsync("/v1/models", null, ct);
        if (listed?["data"] is not JsonArray data) throw new LiteLlmException("bad_response", "LiteLLM /v1/models returned an unexpected shape.");
        var ids = data.Select(e => Str(e?["id"])).Where(id => id is not null && !id.Contains('*')).Select(id => id!).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList();
        var info = new Dictionary<string, JsonObject>(StringComparer.Ordinal);
        try
        {
            if ((await RequestAsync("/model_group/info", null, ct))?["data"] is JsonArray rows)
                foreach (var row in rows.OfType<JsonObject>())
                    if (Str(row["model_group"]) is { } g && !info.ContainsKey(g)) info[g] = row;
        }
        catch (LiteLlmException e) when (e.Code != "unreachable") { /* best effort: older proxies or locked-down keys refuse it */ }
        var models = new List<LiteLlmModel>();
        foreach (var id in ids)
        {
            info.TryGetValue(id, out var facts);
            if (Str(facts?["mode"]) is { } mode && NonChatModes.Contains(mode)) continue;
            models.Add(new LiteLlmModel(id, ModelConfig(id, facts)));
        }
        return models;
    }

    /// <summary>Costs as USD per 1M tokens; unknown facts are omitted, never guessed (the reference's liteLlmModelConfig).</summary>
    public static JsonObject ModelConfig(string id, JsonObject? info)
    {
        var config = new JsonObject { ["id"] = id, ["name"] = id };
        if (info is null) return config;
        double? Positive(string name) => Num(info[name]) is double d && d > 0 ? d : null;
        var context = Positive("max_input_tokens") ?? Positive("max_tokens");
        var output = Positive("max_output_tokens");
        if (context is null && Str(info["mode"]) is null) return config;
        if (context is not null && output is not null) config["limit"] = new JsonObject { ["context"] = context, ["output"] = output };
        var input = Num(info["input_cost_per_token"]);
        var outputPrice = Num(info["output_cost_per_token"]);
        if (input is >= 0 && outputPrice is >= 0 && input + outputPrice > 0)
            config["cost"] = new JsonObject { ["input"] = Math.Round(input.Value * 1_000_000, 6), ["output"] = Math.Round(outputPrice.Value * 1_000_000, 6) };
        if (info["supports_function_calling"] is JsonValue fc && fc.TryGetValue<bool>(out var tool)) config["tool_call"] = tool;
        if (info["supports_reasoning"] is JsonValue r && r.TryGetValue<bool>(out var reasoning)) config["reasoning"] = reasoning;
        if (info["supports_vision"] is JsonValue vi && vi.TryGetValue<bool>(out var vision)) config["attachment"] = vision;
        config["modalities"] = new JsonObject { ["input"] = new JsonArray(info["supports_vision"] is JsonValue v2 && v2.TryGetValue<bool>(out var vv) && vv ? ["text", "image"] : (JsonNode[])["text"]), ["output"] = new JsonArray("text") };
        return config;
    }

    /// <summary>Creates (or, when <paramref name="teamId"/> exists, updates) the provider's team with the models its keys may use.</summary>
    public async Task<string> EnsureTeamAsync(string? teamId, string alias, IReadOnlyCollection<string> models, CancellationToken ct)
    {
        var list = new JsonArray(models.Select(m => (JsonNode)m).ToArray());
        if (teamId is not null)
        {
            var info = await RequestAsync($"/team/info?team_id={Uri.EscapeDataString(teamId)}", null, ct, notFoundIsNull: true);
            if (info is not null)
            {
                await RequestAsync("/team/update", new JsonObject { ["team_id"] = teamId, ["models"] = list }, ct);
                return teamId;
            }
        }
        var created = await RequestAsync("/team/new", new JsonObject { ["team_alias"] = alias, ["models"] = list, ["metadata"] = new JsonObject { ["source"] = "openwork" } }, ct);
        return Str(created?["team_id"]) ?? throw new LiteLlmException("bad_response", "LiteLLM /team/new returned no team.");
    }

    public async Task DeleteTeamAsync(string teamId, CancellationToken ct) =>
        await RequestAsync("/team/delete", new JsonObject { ["team_ids"] = new JsonArray(teamId) }, ct, notFoundIsNull: true);

    /// <summary>
    /// A key owned by the member, in the provider's team, limited to <paramref name="models"/> and to model calls only (<c>llm_api_routes</c>), so a key
    /// never carries admin rights. No budget or rate limit is set.
    /// </summary>
    public async Task<LiteLlmIssued> IssueKeyAsync(string userId, string? teamId, string alias, IReadOnlyCollection<string> models, JsonObject metadata, CancellationToken ct)
    {
        var body = new JsonObject
        {
            ["user_id"] = userId, ["key_alias"] = alias, ["metadata"] = metadata, ["allowed_routes"] = new JsonArray("llm_api_routes"),
            ["models"] = new JsonArray(models.Select(m => (JsonNode)m).ToArray()),
        };
        if (teamId is not null) body["team_id"] = teamId;
        var reply = await RequestAsync("/key/generate", body, ct);
        var key = Str(reply?["key"]);
        var token = Str(reply?["token_id"]) ?? Str(reply?["token"]);
        if (key is null || token is null) throw new LiteLlmException("bad_response", "LiteLLM /key/generate returned no key.");
        return new LiteLlmIssued(key, token);
    }

    /// <summary>Changes the models of an issued key in place (the person keeps the same key).</summary>
    public async Task UpdateKeyModelsAsync(string tokenHash, IReadOnlyCollection<string> models, CancellationToken ct) =>
        await RequestAsync("/key/update", new JsonObject { ["key"] = tokenHash, ["models"] = new JsonArray(models.Select(m => (JsonNode)m).ToArray()) }, ct);

    /// <summary>Deletes keys by LiteLLM token hash; keys already gone count as deleted.</summary>
    public async Task DeleteKeysAsync(IReadOnlyCollection<string> tokenHashes, CancellationToken ct)
    {
        if (tokenHashes.Count == 0) return;
        await RequestAsync("/key/delete", new JsonObject { ["keys"] = new JsonArray(tokenHashes.Select(t => (JsonNode)t).ToArray()) }, ct, notFoundIsNull: true);
    }

    /// <summary>Request logs between two UTC days (inclusive start, exclusive end), optionally for one team, all pages up to a cap.</summary>
    public async Task<List<LiteLlmSpendRow>> SpendLogsAsync(DateOnly from, DateOnly toExclusive, string? teamId, CancellationToken ct, int maxRows = 50_000)
    {
        var rows = new List<LiteLlmSpendRow>();
        for (var page = 1; rows.Count < maxRows; page++)
        {
            var path = $"/spend/logs/v2?start_date={Uri.EscapeDataString(from.ToString("yyyy-MM-dd") + " 00:00:00")}&end_date={Uri.EscapeDataString(toExclusive.ToString("yyyy-MM-dd") + " 00:00:00")}&page={page}&page_size=100"
                + (teamId is null ? "" : $"&team_id={Uri.EscapeDataString(teamId)}");
            var reply = await RequestAsync(path, null, ct);
            if (reply?["data"] is not JsonArray data) throw new LiteLlmException("bad_response", "LiteLLM /spend/logs/v2 returned an unexpected shape.");
            foreach (var r in data.OfType<JsonObject>())
            {
                if (Str(r["api_key"]) is not { } hash) continue;

                var started = DateTime.TryParse(Str(r["startTime"]), null, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out var s) ? s : DateTime.MinValue;
                rows.Add(new LiteLlmSpendRow(hash, Str(r["team_id"]), Str(r["model_group"]) ?? Str(r["model"]), (long)(Num(r["total_tokens"]) ?? 0), Num(r["spend"]) ?? 0, Str(r["status"]) ?? "success", started));
            }
            var pages = (int)(Num(reply["total_pages"]) ?? 1);
            if (page >= pages || data.Count == 0) break;
        }
        return rows;
    }
}

/// <summary>Builds clients for a provider: the operator's proxy directly, a workspace's proxy through the outbound guard.</summary>
public sealed class LiteLlmClients(IOptions<GatewayOptions> options, GuardedHttp guarded, IHttpClientFactory factory)
{
    public const string HttpClientName = "litellm-deployment";

    public LiteLlmClient Deployment()
    {
        var o = options.Value.LiteLlm;
        if (!options.Value.HasDeploymentProxy) throw new LiteLlmException("invalid_base_url", "This deployment has no LiteLLM proxy configured.");
        var client = factory.CreateClient(HttpClientName);
        return new LiteLlmClient(LiteLlmClient.NormalizeRoot(o.BaseUrl!), o.MasterKey!, async (request, timeout, ct) =>
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeout);
            using var response = await client.SendAsync(request, cts.Token);
            return (response.StatusCode, await response.Content.ReadAsStringAsync(cts.Token));
        }, TimeSpan.FromSeconds(Math.Clamp(o.TimeoutSeconds, 1, 120)));
    }

    public LiteLlmClient Workspace(string root, string key) =>
        new(root, key, async (request, timeout, ct) =>
        {
            var reply = await guarded.SendAsync(request, timeout, ct);
            return (reply.Status, reply.Text);
        }, TimeSpan.FromSeconds(Math.Clamp(options.Value.LiteLlm.TimeoutSeconds, 1, 120)));

    /// <summary>The base URL people's desktops call: the operator's public URL for the deployment proxy, else the workspace proxy's own /v1.</summary>
    public string InferenceBaseFor(bool deployment, string? workspaceRoot)
    {
        if (!deployment) return LiteLlmClient.NormalizeRoot(workspaceRoot!) + "/v1";
        var o = options.Value.LiteLlm;
        return LiteLlmClient.NormalizeRoot(string.IsNullOrWhiteSpace(o.PublicUrl) ? o.BaseUrl! : o.PublicUrl) + "/v1";
    }
}
