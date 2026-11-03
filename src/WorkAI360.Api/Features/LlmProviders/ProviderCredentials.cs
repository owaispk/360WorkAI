using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace WorkAI360.Api.Features.LlmProviders;

/// <summary>A credential that cannot be saved (an unknown env name, a Bedrock key without a region); answered as <c>400 invalid_api_keys</c>.</summary>
public sealed class ProviderCredentialException(string message) : Exception(message);

/// <summary>The decoded form of a stored credential: one value, or a map of env name to value.</summary>
public sealed record DecodedCredential(string? ApiKey, Dictionary<string, string>? ApiKeys);

/// <summary>
/// Credential encoding and env names, as the reference's <c>provider-credentials.ts</c> and <c>managed-provider-config.ts</c>. A provider with one
/// env key stores the bare credential; several are a JSON object of env name to value. The stored value describes itself, so nothing else is needed
/// to decode it.
/// </summary>
public static partial class ProviderCredentials
{
    /// <summary>The constructor option each bundled AI SDK fills from an env name (the reference's <c>aiSdkEnvSettings</c>).</summary>
    private static readonly Dictionary<string, string> SdkSettings = new(StringComparer.Ordinal)
    {
        ["AI_GATEWAY_API_KEY"] = "apiKey", ["ALIBABA_API_KEY"] = "apiKey", ["ANTHROPIC_API_KEY"] = "apiKey", ["ANTHROPIC_BASE_URL"] = "baseURL",
        ["AWS_ACCESS_KEY_ID"] = "accessKeyId", ["AWS_BEARER_TOKEN_BEDROCK"] = "apiKey", ["AWS_REGION"] = "region", ["AWS_SECRET_ACCESS_KEY"] = "secretAccessKey",
        ["AWS_SESSION_TOKEN"] = "sessionToken", ["AZURE_API_KEY"] = "apiKey", ["AZURE_RESOURCE_NAME"] = "resourceName", ["CEREBRAS_API_KEY"] = "apiKey",
        ["COHERE_API_KEY"] = "apiKey", ["DEEPINFRA_API_KEY"] = "apiKey", ["GITLAB_TOKEN"] = "apiKey", ["GOOGLE_GENERATIVE_AI_API_KEY"] = "apiKey",
        ["GOOGLE_VERTEX_API_KEY"] = "apiKey", ["GOOGLE_VERTEX_LOCATION"] = "location", ["GOOGLE_VERTEX_PROJECT"] = "project", ["GROQ_API_KEY"] = "apiKey",
        ["MISTRAL_API_KEY"] = "apiKey", ["OPENAI_API_KEY"] = "apiKey", ["OPENAI_BASE_URL"] = "baseURL", ["OPENROUTER_API_KEY"] = "apiKey",
        ["PERPLEXITY_API_KEY"] = "apiKey", ["VENICE_API_KEY"] = "apiKey", ["VERCEL_API_KEY"] = "apiKey", ["XAI_API_KEY"] = "apiKey",
    };

    public static List<string> EnvNames(JsonObject providerConfig) =>
        providerConfig["env"] is JsonArray env
            ? env.Select(e => e is JsonValue v && v.TryGetValue<string>(out var s) && s.Trim().Length > 0 ? s : null).OfType<string>().ToList()
            : [];

    private static int? Rank(string name)
    {
        var n = name.Trim().ToUpperInvariant();
        if (ApiKeyRegex().IsMatch(n)) return 0;
        if (AccessKeyRegex().IsMatch(n)) return 1;
        if (BearerRegex().IsMatch(n) || TokenRegex().IsMatch(n)) return 2;
        if (KeyRegex().IsMatch(n)) return 3;
        return null;
    }

    public static string? PrimaryEnvName(IReadOnlyList<string> envNames, IEnumerable<string> available)
    {
        var have = available.Where(n => n.Trim().Length > 0).ToHashSet(StringComparer.Ordinal);
        var ordered = envNames.Where(have.Contains).ToList();
        var ranked = ordered.Select((name, index) => (name, index, rank: Rank(name))).Where(e => e.rank is not null).OrderBy(e => e.rank).ThenBy(e => e.index).ToList();
        if (ranked.Count > 0) return ranked[0].name;
        if (envNames.Count > 1 && envNames.Any(n => Rank(n) is not null)) return null;
        return ordered.FirstOrDefault();
    }

    public static string? LegacyScalarEnvName(IReadOnlyList<string> envNames) => PrimaryEnvName(envNames, envNames) ?? envNames.FirstOrDefault();

    public static DecodedCredential Decode(string? stored)
    {
        var trimmed = stored?.Trim() ?? "";
        if (trimmed.Length == 0) return new(null, null);
        if (trimmed.StartsWith('{'))
        {
            try
            {
                if (JsonNode.Parse(trimmed) is JsonObject obj && obj.Count > 0 && obj.All(p => p.Value is JsonValue v && v.TryGetValue<string>(out _)))
                    return new(null, obj.ToDictionary(p => p.Key, p => p.Value!.GetValue<string>(), StringComparer.Ordinal));
            }
            catch (JsonException) { }
        }
        return new(trimmed, null);
    }

    public static List<string> ConfiguredEnvKeys(string? stored, IReadOnlyList<string> envNames)
    {
        var credential = Decode(stored);
        if (credential.ApiKeys is { } keys)
            return [.. envNames.Where(keys.ContainsKey), .. keys.Keys.Where(k => !envNames.Contains(k))];
        if (credential.ApiKey is not null && LegacyScalarEnvName(envNames) is { } name) return [name];
        return [];
    }

    /// <summary>
    /// The next stored credential for a write: <paramref name="apiKeys"/> merges per env name (a value sets, an empty value clears, an absent name
    /// keeps); <paramref name="apiKey"/> replaces the whole credential; neither keeps what is stored.
    /// </summary>
    public static string? Resolve(IReadOnlyList<string> envNames, string? existingValue, IReadOnlyList<string> existingEnvNames, string? apiKey, IReadOnlyDictionary<string, string>? apiKeys)
    {
        if (apiKeys is not null)
        {
            foreach (var key in apiKeys.Keys)
                if (!envNames.Contains(key))
                    throw new ProviderCredentialException($"{key} is not one of this provider's env keys ({(envNames.Count > 0 ? string.Join(", ", envNames) : "none")}).");
            var existing = Decode(existingValue);
            var values = new Dictionary<string, string>(existing.ApiKeys ?? [], StringComparer.Ordinal);
            if (existing.ApiKeys is null && existing.ApiKey is not null && LegacyScalarEnvName(existingEnvNames) is { } legacy) values[legacy] = existing.ApiKey;
            foreach (var (key, value) in apiKeys)
            {
                var trimmed = value.Trim();
                if (trimmed.Length > 0) values[key] = trimmed; else values.Remove(key);
            }
            foreach (var key in values.Keys.Where(k => !envNames.Contains(k)).ToList()) values.Remove(key);
            if (envNames.Count <= 1) return envNames.Count == 1 && values.TryGetValue(envNames[0], out var single) ? single : null;
            var ordered = new JsonObject();
            foreach (var name in envNames) if (values.TryGetValue(name, out var v) && v.Length > 0) ordered[name] = v;
            return ordered.Count > 0 ? ordered.ToJsonString() : null;
        }
        if (apiKey is not null) return apiKey.Trim() is { Length: > 0 } t ? t : null;
        return existingValue;
    }

    /// <summary>Bedrock cannot reach any endpoint without a region, so a Bedrock credential without a valid AWS_REGION is refused when saved.</summary>
    public static string? BedrockError(JsonObject providerConfig, string? stored)
    {
        if (Str(providerConfig, "npm") != "@ai-sdk/amazon-bedrock" || stored is null) return null;
        var region = Decode(stored).ApiKeys?.GetValueOrDefault("AWS_REGION");
        return region is not null && region.Length <= 32 && AwsRegionRegex().IsMatch(region)
            ? null : "Amazon Bedrock requires AWS_REGION set to an AWS region code such as us-east-1.";
    }

    /// <summary>Catalog providers leave Den under names scoped to the row (<c>LPR_ABCDE_OPENAI_API_KEY</c>), so one workspace provider cannot shadow a person's own key.</summary>
    public static bool UsesRuntimeTag(string source) => source is "models_dev" or "openwork_gateway";

    public static string RuntimeTag(string providerRowId)
    {
        if (providerRowId.StartsWith("ipr_", StringComparison.Ordinal)) return NonAlnumUnderscore().Replace(providerRowId.ToUpperInvariant(), "_");
        var tail = NonAlnum().Replace(providerRowId, "").ToUpperInvariant();
        return "LPR_" + (tail.Length > 5 ? tail[^5..] : tail);
    }

    public static string RuntimeEnvName(string id, string source, string declared) => UsesRuntimeTag(source) ? $"{RuntimeTag(id)}_{declared}" : declared;

    public static List<string> RuntimeEnvNames(string id, string source, JsonObject providerConfig) =>
        EnvNames(providerConfig).Select(n => RuntimeEnvName(id, source, n)).ToList();

    /// <summary>
    /// The provider configuration and credential map as a person's machine receives them: env names rewritten to their runtime names and, for a
    /// provider with several env names, each SDK option bound to its runtime name (<c>{env:NAME}</c>). The stored row is never rewritten.
    /// </summary>
    public static (JsonObject Config, Dictionary<string, string>? ApiKeys) ToRuntime(string id, string source, JsonObject providerConfig, Dictionary<string, string>? apiKeys)
    {
        if (!UsesRuntimeTag(source) || !providerConfig.ContainsKey("env")) return (providerConfig, apiKeys);
        var declared = EnvNames(providerConfig);
        var config = (JsonObject)providerConfig.DeepClone();
        config["env"] = new JsonArray(declared.Select(n => (JsonNode?)JsonValue.Create(RuntimeEnvName(id, source, n))).ToArray());
        var sdkOptions = new JsonObject();
        if (declared.Count >= 2 && apiKeys is not null)
            foreach (var name in declared)
                if (SdkSettings.TryGetValue(name, out var setting) && !sdkOptions.ContainsKey(setting) && apiKeys.TryGetValue(name, out var value) && value.Trim().Length > 0)
                    sdkOptions[setting] = $"{{env:{RuntimeEnvName(id, source, name)}}}";
        if (sdkOptions.Count > 0)
        {
            // An option the provider already sets explicitly keeps precedence.
            if (config["options"] is JsonObject declaredOptions) foreach (var (k, v) in declaredOptions) sdkOptions[k] = v?.DeepClone();
            config["options"] = sdkOptions;
        }
        var runtimeKeys = apiKeys?.ToDictionary(p => RuntimeEnvName(id, source, p.Key), p => p.Value, StringComparer.Ordinal);
        return (config, runtimeKeys);
    }

    public static string? Str(JsonObject o, string name) => o[name] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;

    [GeneratedRegex("(^|_)API_KEY$")] private static partial Regex ApiKeyRegex();
    [GeneratedRegex("(^|_)ACCESS_KEY_ID$")] private static partial Regex AccessKeyRegex();
    [GeneratedRegex("(^|_)BEARER_TOKEN(_|$)")] private static partial Regex BearerRegex();
    [GeneratedRegex("(^|_)TOKEN$")] private static partial Regex TokenRegex();
    [GeneratedRegex("(^|_)KEY$")] private static partial Regex KeyRegex();
    [GeneratedRegex(@"^[a-z]{2}(?:-[a-z]+)+-\d{1,2}$")] private static partial Regex AwsRegionRegex();
    [GeneratedRegex("[^A-Z0-9]")] private static partial Regex NonAlnumUnderscore();
    [GeneratedRegex("[^0-9A-Za-z]")] private static partial Regex NonAlnum();
}
