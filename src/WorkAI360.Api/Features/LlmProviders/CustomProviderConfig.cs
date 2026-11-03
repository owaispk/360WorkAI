using System.Text.Json;
using System.Text.Json.Nodes;

namespace WorkAI360.Api.Features.LlmProviders;

public sealed class CustomProviderConfigException(string message) : Exception(message);

public sealed record NormalizedCustomProvider(string ProviderId, JsonObject ProviderConfig, List<CatalogModel> Models);

/// <summary>
/// A pasted provider block (the reference's <c>custom-provider.ts</c>): JSON or JSONC, optionally wrapped in an OpenCode <c>{"provider": {...}}</c>
/// object, with models as an array or a map. Checked like the reference's schema (id, name, npm, env with at least one name, optional doc and api,
/// at least one model with id and name); unknown fields are kept.
/// </summary>
public static class CustomProviderConfig
{
    private static readonly JsonDocumentOptions Jsonc = new() { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true };

    public static NormalizedCustomProvider Normalize(string? text, JsonNode? config)
    {
        JsonNode? raw;
        if (text is not null)
        {
            try { raw = JsonNode.Parse(text, documentOptions: Jsonc); }
            catch (JsonException) { throw new CustomProviderConfigException("Custom provider config must be valid JSON or JSONC."); }
        }
        else raw = config?.DeepClone();

        var provider = Unwrap(raw);
        var issues = new List<string>();
        if (provider is not JsonObject obj)
        {
            throw new CustomProviderConfigException($"config: Invalid input: expected object, received {Kind(provider)}");
        }
        if (obj["models"] is JsonNode models) obj["models"] = NormalizeModels(models);

        string? Required(JsonObject o, string name, int max, string path)
        {
            if (o[name] is not JsonValue v || !v.TryGetValue<string>(out var s)) { issues.Add($"{path}: Invalid input: expected string, received {Kind(o[name], o.ContainsKey(name))}"); return null; }
            s = s.Trim();
            if (s.Length < 1) { issues.Add($"{path}: Too small: expected string to have >=1 characters"); return null; }
            if (s.Length > max) { issues.Add($"{path}: Too big: expected string to have <={max} characters"); return null; }
            o[name] = s;
            return s;
        }
        void Optional(JsonObject o, string name, int max)
        {
            if (!o.ContainsKey(name)) return;
            Required(o, name, max, name);
        }

        var id = Required(obj, "id", 255, "id");
        Required(obj, "name", 255, "name");
        Required(obj, "npm", 255, "npm");
        if (obj["env"] is not JsonArray env) issues.Add($"env: Invalid input: expected array, received {Kind(obj["env"], obj.ContainsKey("env"))}");
        else if (env.Count == 0) issues.Add("env: Too small: expected array to have >=1 items");
        else for (var i = 0; i < env.Count; i++)
        {
            if (env[i] is not JsonValue v || !v.TryGetValue<string>(out var s)) { issues.Add($"env.{i}: Invalid input: expected string, received {Kind(env[i])}"); continue; }
            s = s.Trim();
            if (s.Length < 1) issues.Add($"env.{i}: Too small: expected string to have >=1 characters");
            else if (s.Length > 255) issues.Add($"env.{i}: Too big: expected string to have <=255 characters");
            else env[i] = s;
        }
        Optional(obj, "doc", 2048);
        Optional(obj, "api", 2048);
        var list = new List<CatalogModel>();
        if (obj["models"] is not JsonArray modelArray) issues.Add($"models: Invalid input: expected array, received {Kind(obj["models"], obj.ContainsKey("models"))}");
        else if (modelArray.Count == 0) issues.Add("models: Too small: expected array to have >=1 items");
        else for (var i = 0; i < modelArray.Count; i++)
        {
            if (modelArray[i] is not JsonObject model) { issues.Add($"models.{i}: Invalid input: expected object, received {Kind(modelArray[i])}"); continue; }
            var mid = Required(model, "id", 255, $"models.{i}.id");
            var mname = Required(model, "name", 255, $"models.{i}.name");
            if (mid is not null && mname is not null) list.Add(new CatalogModel(mid, mname, (JsonObject)model.DeepClone()));
        }
        if (issues.Count > 0) throw new CustomProviderConfigException(string.Join("; ", issues.Take(3)));

        var providerConfig = new JsonObject();
        foreach (var (k, v) in obj) if (k != "models") providerConfig[k] = v?.DeepClone();
        return new NormalizedCustomProvider(id!, providerConfig, list);
    }

    private static JsonNode? Unwrap(JsonNode? value)
    {
        if (value is not JsonObject o || o["provider"] is not JsonObject providers) return value;
        var blocks = providers.Where(p => p.Value is JsonObject).ToList();
        if (blocks.Count == 1) return blocks[0].Value!.DeepClone();
        if (blocks.Count == 0) throw new CustomProviderConfigException("provider must contain one provider block.");
        throw new CustomProviderConfigException("Custom provider config contains multiple providers. Paste one provider block or remove the others.");
    }

    private static JsonNode NormalizeModels(JsonNode models)
    {
        if (models is JsonArray array)
            return new JsonArray(array.Select(m => m is JsonValue v && v.TryGetValue<string>(out var s) ? new JsonObject { ["id"] = s, ["name"] = s } : m?.DeepClone()).ToArray());
        if (models is JsonObject map)
        {
            var result = new JsonArray();
            foreach (var (key, m) in map)
            {
                if (m is not JsonObject model) { result.Add(new JsonObject { ["id"] = key, ["name"] = key }); continue; }
                var copy = (JsonObject)model.DeepClone();
                copy["id"] = NonEmpty(model["id"]) ?? key;
                copy["name"] = NonEmpty(model["name"]) ?? key;
                result.Add(copy);
            }
            return result;
        }
        return models.DeepClone();
    }

    private static string? NonEmpty(JsonNode? n) => n is JsonValue v && v.TryGetValue<string>(out var s) && s.Trim().Length > 0 ? s.Trim() : null;

    private static string Kind(JsonNode? n, bool present = true) => !present ? "undefined" : n switch
    {
        null => "null",
        JsonArray => "array",
        JsonObject => "object",
        JsonValue v when v.TryGetValue<string>(out _) => "string",
        JsonValue v when v.TryGetValue<bool>(out _) => "boolean",
        _ => "number",
    };
}
