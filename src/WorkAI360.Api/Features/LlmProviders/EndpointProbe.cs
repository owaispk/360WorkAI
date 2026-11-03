using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using WorkAI360.Api.Features.Connections;

namespace WorkAI360.Api.Features.LlmProviders;

public sealed record ProbeResult(bool Ok, string Vendor, string? NormalizedApi, List<string> Attempted, List<string> Models, string? Hint, int? Status)
{
    public object ToJson() => new { ok = Ok, vendor = Vendor, normalizedApi = NormalizedApi, attempted = Attempted, models = Models.Select(id => new { id }), hint = Hint, status = Status };
}

public sealed record ModelVerification(string Id, string Status, string Npm, string? Message)
{
    public object ToJson() => new { id = Id, status = Status, npm = Npm, message = Message };
}

/// <summary>
/// "Test connection" for a custom provider (the reference's <c>endpoint-probe.ts</c>): normalize common base-URL mistakes, call the OpenAI-compatible
/// <c>GET /models</c>, and return the model ids the endpoint serves (on Azure, the deployment names). Every request goes through
/// <see cref="GuardedHttp"/>: the address is resolved and checked before connecting, redirects are never followed, responses are size-capped
/// and time-boxed. Nothing is stored.
/// </summary>
public sealed partial class EndpointProbe(GuardedHttp http)
{
    private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(8);
    private static readonly TimeSpan VerifyTimeout = TimeSpan.FromSeconds(20);
    private const string AzureDeploymentsApiVersion = "2023-03-15-preview";
    private static readonly string[] StripSuffixes = ["/chat/completions", "/completions", "/responses", "/models"];

    public static string DetectVendor(string url) =>
        Uri.TryCreate(url.Trim(), UriKind.Absolute, out var u) && AzureHost().IsMatch(u.Host) ? "azure" : "openai-compatible";

    public static string? NormalizeBase(string raw)
    {
        var trimmed = raw.Trim();
        if (trimmed.Length == 0 || !Uri.TryCreate(trimmed, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https")) return null;
        var path = uri.AbsolutePath.TrimEnd('/');
        foreach (var suffix in StripSuffixes)
            if (path.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)) { path = path[..^suffix.Length]; break; }
        var builder = new UriBuilder(uri) { Path = path, Query = "", Fragment = "" };
        return builder.Uri.ToString().TrimEnd('/');
    }

    private static string? AzureTwin(string baseUrl)
    {
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var u)) return null;
        string? host = null;
        if (u.Host.EndsWith(".openai.azure.com", StringComparison.OrdinalIgnoreCase)) host = u.Host[..^".openai.azure.com".Length] + ".services.ai.azure.com";
        else if (u.Host.EndsWith(".services.ai.azure.com", StringComparison.OrdinalIgnoreCase)) host = u.Host[..^".services.ai.azure.com".Length] + ".openai.azure.com";
        return host is null ? null : new UriBuilder(u) { Host = host }.Uri.ToString().TrimEnd('/');
    }

    private static string? WithAzureV1Path(string baseUrl)
    {
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var u) || !AzureHost().IsMatch(u.Host)) return null;
        return u.AbsolutePath is "" or "/" ? new UriBuilder(u) { Path = "/openai/v1" }.Uri.ToString().TrimEnd('/') : null;
    }

    /// <summary>The user's (normalized) URL first, then the Azure rewrites real people need: the bare origin's /openai/v1 and the host twin.</summary>
    public static List<string> CandidateBaseUrls(string raw)
    {
        if (NormalizeBase(raw) is not { } first) return [];
        var list = new List<string> { first };
        if (WithAzureV1Path(first) is { } v1) list.Add(v1);
        if (AzureTwin(first) is { } twin)
        {
            list.Add(twin);
            if (WithAzureV1Path(twin) is { } twinV1) list.Add(twinV1);
        }
        return list.Distinct().Take(6).ToList();
    }

    public async Task<ProbeResult> ProbeAsync(string api, string apiKey, CancellationToken ct)
    {
        var vendor = DetectVendor(api);
        var candidates = CandidateBaseUrls(api);
        var attempted = new List<string>();
        if (candidates.Count == 0) return new(false, vendor, null, attempted, [], "Enter a valid http(s) base URL.", null);
        int? lastStatus = null;
        foreach (var baseUrl in candidates)
        {
            attempted.Add(baseUrl);
            try { await http.AssertPublicAsync(baseUrl, ct); }
            catch (UrlRefusedException) { return new(false, vendor, null, attempted, [], $"Probing {new Uri(baseUrl).Host} is not allowed.", null); }
            try
            {
                var reply = await http.SendAsync(Get($"{baseUrl}/models", apiKey), ProbeTimeout, ct);
                lastStatus = (int)reply.Status;
                if ((int)reply.Status is < 200 or >= 300) continue;
                if (ModelIds(reply.Text) is not { } ids) continue;
                var deployments = vendor == "azure" ? await AzureDeploymentsAsync(baseUrl, apiKey, ct) : null;
                return new(true, vendor, baseUrl, attempted, deployments ?? ids, null, (int)reply.Status);
            }
            catch (Exception e) when (e is HttpRequestException or TaskCanceledException or OperationCanceledException or UrlRefusedException or ResponseTooLargeException) { }
        }
        if (vendor == "azure")
        {
            foreach (var origin in candidates.Select(c => new Uri(c).GetLeftPart(UriPartial.Authority)).Distinct())
                if (await AzureDeploymentsAsync(origin + "/openai/v1", apiKey, ct) is { } deployments)
                    return new(true, vendor, origin + "/openai/v1", attempted, deployments, null, 200);
        }
        return new(false, vendor, null, attempted, [], Hint(vendor, lastStatus), lastStatus);
    }

    private async Task<List<string>?> AzureDeploymentsAsync(string baseUrl, string apiKey, CancellationToken ct)
    {
        try
        {
            var origin = new Uri(baseUrl).GetLeftPart(UriPartial.Authority);
            var reply = await http.SendAsync(Get($"{origin}/openai/deployments?api-version={AzureDeploymentsApiVersion}", apiKey), ProbeTimeout, ct);
            return (int)reply.Status is >= 200 and < 300 && ModelIds(reply.Text) is { Count: > 0 } ids ? ids : null;
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or OperationCanceledException or UrlRefusedException or ResponseTooLargeException or UriFormatException) { return null; }
    }

    /// <summary>One tiny completion per model (at most 8) to find the request shape it accepts: GPT-5/o-series on Azure need max_completion_tokens.</summary>
    public async Task<List<ModelVerification>> VerifyAsync(string api, string apiKey, IEnumerable<string> modelIds, CancellationToken ct)
    {
        var baseUrl = NormalizeBase(api);
        var ids = modelIds.Select(i => i.Trim()).Where(i => i.Length > 0).Distinct().Take(8).ToList();
        if (baseUrl is null || ids.Count == 0) return [];
        await http.AssertPublicAsync(baseUrl, ct);
        var results = new List<ModelVerification>();
        foreach (var id in ids)
        {
            var first = await AttemptAsync(baseUrl, apiKey, id, "max_tokens", ct);
            if (first.Ok) { results.Add(new(id, "ok", "@ai-sdk/openai-compatible", null)); continue; }
            if (first.NeedsCompletionTokens)
            {
                var second = await AttemptAsync(baseUrl, apiKey, id, "max_completion_tokens", ct);
                results.Add(second.Ok
                    ? new(id, "adjusted", "@ai-sdk/openai", "Model requires max_completion_tokens; using the OpenAI request shape.")
                    : new(id, "failed", "@ai-sdk/openai", second.Message));
                continue;
            }
            results.Add(new(id, "failed", "@ai-sdk/openai-compatible", first.Message));
        }
        return results;
    }

    private async Task<(bool Ok, bool NeedsCompletionTokens, string? Message)> AttemptAsync(string baseUrl, string apiKey, string modelId, string tokenParam, CancellationToken ct)
    {
        try
        {
            var body = new JsonObject
            {
                ["model"] = modelId,
                ["messages"] = new JsonArray(new JsonObject { ["role"] = "user", ["content"] = "Reply with the single word: ok" }),
                [tokenParam] = 16,
            };
            var request = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/chat/completions") { Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json") };
            AddAuth(request, apiKey);
            var reply = await http.SendAsync(request, VerifyTimeout, ct);
            if ((int)reply.Status is >= 200 and < 300) return (true, false, null);
            string message = "", param = "";
            try
            {
                if (JsonNode.Parse(reply.Text) is JsonObject o && o["error"] is JsonObject err)
                {
                    message = err["message"] is JsonValue m && m.TryGetValue<string>(out var ms) ? ms : "";
                    param = err["param"] is JsonValue p && p.TryGetValue<string>(out var ps) ? ps : "";
                }
            }
            catch (JsonException) { }
            var needs = (int)reply.Status == 400 && (param == "max_tokens" || message.Contains("max_completion_tokens", StringComparison.OrdinalIgnoreCase));
            return (false, needs, Truncate(message.Length > 0 ? message : $"HTTP {(int)reply.Status}"));
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or OperationCanceledException or UrlRefusedException or ResponseTooLargeException)
        {
            return (false, false, Truncate(e is TaskCanceledException or OperationCanceledException ? "The request timed out." : e.Message));
        }
    }

    private static HttpRequestMessage Get(string url, string apiKey)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, url);
        AddAuth(request, apiKey);
        return request;
    }

    // Azure accepts either header; OpenAI-compatible servers ignore the extra one.
    private static void AddAuth(HttpRequestMessage request, string apiKey)
    {
        request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {apiKey}");
        request.Headers.TryAddWithoutValidation("api-key", apiKey);
    }

    public static List<string>? ModelIds(string text)
    {
        try
        {
            if (JsonNode.Parse(text) is not JsonObject o || o["data"] is not JsonArray data) return null;
            return data.Select(e => e is JsonObject m && m["id"] is JsonValue v && v.TryGetValue<string>(out var s) ? s.Trim() : "")
                .Where(s => s.Length > 0).Distinct().Order(StringComparer.Ordinal).ToList();
        }
        catch (JsonException) { return null; }
    }

    private static string Hint(string vendor, int? status) => status switch
    {
        401 or 403 => vendor == "azure"
            ? "The endpoint rejected the key. Check Keys & Endpoint on the Azure resource — the key must belong to the same resource as the base URL."
            : "The endpoint rejected the key. Double-check the credential for this endpoint.",
        404 => vendor == "azure"
            ? "No OpenAI-compatible /models endpoint found. Azure base URLs usually end in /openai/v1 — copy the endpoint from the Azure portal and check the resource name."
            : "No /models endpoint found at this base URL. Most OpenAI-compatible endpoints end in /v1.",
        { } s => $"The endpoint answered /models with HTTP {s}.",
        null => "Could not reach the endpoint. Check the URL, network access, and that the endpoint allows requests from OpenWork Cloud.",
    };

    private static string Truncate(string value) => value.Length <= 300 ? value : value[..297] + "...";

    [GeneratedRegex(@"\.(openai\.azure\.com|services\.ai\.azure\.com|cognitiveservices\.azure\.com)$", RegexOptions.IgnoreCase)]
    private static partial Regex AzureHost();
}
