using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Options;

namespace WorkAI360.Api.Features.LlmProviders;

public sealed class LlmProviderOptions
{
    public const string Section = "LlmProviders";

    /// <summary>The models.dev-format catalog (the reference's mirror by default). Empty: use the bundled snapshot only (offline deployments, tests).</summary>
    public string CatalogUrl { get; set; } = "https://models.openworklabs.com/api.json";

    /// <summary>A catalog file on disk to use instead of the URL and the bundled snapshot (same format).</summary>
    public string? CatalogFile { get; set; }

    public int CatalogCacheMinutes { get; set; } = 10;

    /// <summary>When the URL cannot be read, answer from the bundled snapshot (logged) instead of <c>502 provider_catalog_unavailable</c>.</summary>
    public bool CatalogFallbackToSnapshot { get; set; } = true;
}

public sealed record CatalogModel(string Id, string Name, JsonObject Config);

public sealed record CatalogProvider(string Id, string Name, string? Npm, List<string> Env, string? Doc, string? Api, JsonObject Config, List<CatalogModel> Models);

public sealed class CatalogUnavailableException(string message) : Exception(message);

/// <summary>
/// The provider catalog (the reference's <c>models-dev.ts</c>): read from the configured URL, cached, with one refresh at a time. A bundled snapshot
/// of common providers (<c>models-catalog-snapshot.json</c>, taken from the same catalog) serves offline deployments and tests.
/// </summary>
public sealed class ModelCatalog(IHttpClientFactory http, IOptions<LlmProviderOptions> options, ILogger<ModelCatalog> log)
{
    public const string HttpClientName = "llm-provider-catalog";
    private readonly SemaphoreSlim _refresh = new(1, 1);
    private (DateTime ExpiresAt, List<CatalogProvider> Providers, Dictionary<string, CatalogProvider> ById)? _cache;

    public async Task<List<CatalogProvider>> ListAsync(CancellationToken ct = default) => (await LoadAsync(ct)).Providers;

    public async Task<CatalogProvider?> FindAsync(string providerId, CancellationToken ct = default) => (await LoadAsync(ct)).ById.GetValueOrDefault(providerId);

    private async Task<(DateTime ExpiresAt, List<CatalogProvider> Providers, Dictionary<string, CatalogProvider> ById)> LoadAsync(CancellationToken ct)
    {
        if (_cache is { } fresh && fresh.ExpiresAt > DateTime.UtcNow) return fresh;
        await _refresh.WaitAsync(ct);
        try
        {
            if (_cache is { } again && again.ExpiresAt > DateTime.UtcNow) return again;
            var providers = Parse(await ReadAsync(ct));
            var loaded = (DateTime.UtcNow.AddMinutes(Math.Max(1, options.Value.CatalogCacheMinutes)), providers, providers.ToDictionary(p => p.Id, StringComparer.Ordinal));
            _cache = loaded;
            return loaded;
        }
        finally { _refresh.Release(); }
    }

    private async Task<JsonObject> ReadAsync(CancellationToken ct)
    {
        var o = options.Value;
        if (!string.IsNullOrWhiteSpace(o.CatalogFile)) return AsObject(JsonNode.Parse(await File.ReadAllTextAsync(o.CatalogFile, ct)));
        if (string.IsNullOrWhiteSpace(o.CatalogUrl)) return Snapshot();
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, o.CatalogUrl);
            request.Headers.Accept.ParseAdd("application/json");
            request.Headers.UserAgent.ParseAdd("WorkAI360-Den-API");
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(10));
            using var response = await http.CreateClient(HttpClientName).SendAsync(request, cts.Token);
            if (!response.IsSuccessStatusCode) throw new CatalogUnavailableException($"models.dev returned {(int)response.StatusCode}");
            return AsObject(JsonNode.Parse(await response.Content.ReadAsStringAsync(cts.Token)));
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or JsonException or CatalogUnavailableException)
        {
            if (!o.CatalogFallbackToSnapshot) throw new CatalogUnavailableException(e is CatalogUnavailableException ? e.Message : "Could not load the models.dev catalog.");
            log.LogWarning("The provider catalog at {Url} could not be read ({Reason}); using the bundled snapshot.", o.CatalogUrl, e.GetType().Name);
            return Snapshot();
        }
    }

    private static JsonObject AsObject(JsonNode? node) => node as JsonObject ?? throw new CatalogUnavailableException("models.dev returned an invalid payload");

    public static JsonObject Snapshot()
    {
        using var stream = typeof(ModelCatalog).Assembly.GetManifestResourceStream("WorkAI360.Api.LlmProviders.models-catalog-snapshot.json")
            ?? throw new CatalogUnavailableException("The bundled provider catalog is missing.");
        return AsObject(JsonNode.Parse(stream));
    }

    public static List<CatalogProvider> Parse(JsonObject payload)
    {
        var providers = new List<CatalogProvider>();
        foreach (var (key, raw) in payload)
        {
            if (raw is not JsonObject provider) throw new CatalogUnavailableException("models.dev returned an invalid provider");
            if (provider["models"] is not JsonObject models) throw new CatalogUnavailableException("models.dev returned an invalid model catalog");
            var id = Text(provider, "id") ?? key;
            var config = new JsonObject();
            foreach (var (k, v) in provider) if (k != "models") config[k] = v?.DeepClone();
            var list = new List<CatalogModel>();
            foreach (var (modelKey, rawModel) in models)
            {
                if (rawModel is not JsonObject model) throw new CatalogUnavailableException("models.dev returned an invalid model");
                var modelId = Text(model, "id") ?? modelKey;
                list.Add(new CatalogModel(modelId, Text(model, "name") ?? modelId, (JsonObject)model.DeepClone()));
            }
            list.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.InvariantCulture));
            var env = provider["env"] is JsonArray e ? e.Select(x => x is JsonValue v && v.TryGetValue<string>(out var s) && s.Trim().Length > 0 ? s : null).OfType<string>().ToList() : [];
            providers.Add(new CatalogProvider(id, Text(provider, "name") ?? id, Text(provider, "npm"), env, Text(provider, "doc"), Text(provider, "api"), config, list));
        }
        providers.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.InvariantCulture));
        return providers;
    }

    private static string? Text(JsonObject o, string name) => o[name] is JsonValue v && v.TryGetValue<string>(out var s) && s.Trim().Length > 0 ? s : null;
}
