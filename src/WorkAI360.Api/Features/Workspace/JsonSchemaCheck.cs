using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace WorkAI360.Api.Features.Workspace;

/// <summary>
/// Checks a value against a JSON Schema (the draft 7 / 2020-12 keywords Workflow authors use: <c>type</c>, <c>enum</c>, <c>const</c>,
/// <c>properties</c>, <c>required</c>, <c>additionalProperties</c>, <c>patternProperties</c>, <c>items</c>, <c>prefixItems</c>, length, size and range limits,
/// <c>pattern</c>, <c>allOf</c> / <c>anyOf</c> / <c>oneOf</c> / <c>not</c>, <c>if</c> / <c>then</c> / <c>else</c>, and local <c>$ref</c>). <c>format</c> is not enforced.
/// A schema that is not an object or boolean, or uses an unsupported <c>type</c>, is reported as invalid, never as a pass.
/// </summary>
public static class JsonSchemaCheck
{
    public sealed record Result(bool SchemaValid, List<string> Errors)
    {
        public bool Ok => SchemaValid && Errors.Count == 0;
    }

    private static readonly string[] Types = ["string", "number", "integer", "boolean", "object", "array", "null"];
    private const int MaxDepth = 64;

    /// <summary>True when the schema asks for asynchronous validation (<c>$async</c>), which the reference refuses.</summary>
    public static bool HasAsync(JsonNode? schema) => schema switch
    {
        JsonObject o => o.Any(p => p.Key == "$async" || HasAsync(p.Value)),
        JsonArray a => a.Any(HasAsync),
        _ => false,
    };

    public static Result Validate(JsonNode schema, JsonNode? value)
    {
        var errors = new List<string>();
        try { Check(schema, schema, value, "", errors, 0); }
        catch (SchemaException) { return new Result(false, []); }
        return new Result(true, errors);
    }

    private sealed class SchemaException : Exception;

    private static string Describe(JsonNode? v) => v switch
    {
        null => "null",
        JsonObject => "object",
        JsonArray => "array",
        JsonValue j => WorkflowArtifacts.El(j).ValueKind switch { JsonValueKind.String => "string", JsonValueKind.Number => "number", JsonValueKind.True or JsonValueKind.False => "boolean", _ => "null" },
        _ => "null",
    };

    private static bool IsType(JsonNode? v, string type)
    {
        var kind = Describe(v);
        if (type == "integer") return kind == "number" && v is JsonValue j && WorkflowArtifacts.El(j).GetDouble() is var d && d == Math.Floor(d) && !double.IsInfinity(d);
        return kind == type;
    }

    private static bool Equal(JsonNode? a, JsonNode? b) => WorkflowArtifacts.Canonical(a) == WorkflowArtifacts.Canonical(b);

    private static void Check(JsonNode root, JsonNode schema, JsonNode? value, string path, List<string> errors, int depth)
    {
        if (depth > MaxDepth) throw new SchemaException();
        if (schema is JsonValue sv && WorkflowArtifacts.El(sv).ValueKind is JsonValueKind.True or JsonValueKind.False)
        {
            if (!sv.GetValue<bool>()) errors.Add($"data{path} must not exist");
            return;
        }
        if (schema is not JsonObject s) throw new SchemaException();
        var at = $"data{path}";

        if (s["$ref"] is JsonValue refValue && refValue.TryGetValue<string>(out var reference))
        {
            Check(root, Resolve(root, reference), value, path, errors, depth + 1);
            return;
        }

        if (s["type"] is { } typeNode)
        {
            var wanted = typeNode switch
            {
                JsonValue t when t.TryGetValue<string>(out var one) => [one],
                JsonArray arr => arr.Select(x => x is JsonValue xv && xv.TryGetValue<string>(out var n) ? n : throw new SchemaException()).ToList(),
                _ => throw new SchemaException(),
            };
            if (wanted.Any(w => !Types.Contains(w))) throw new SchemaException();
            if (!wanted.Any(w => IsType(value, w))) { errors.Add($"{at} must be {string.Join(",", wanted)}"); return; }
        }
        if (s["enum"] is JsonArray en && !en.Any(e => Equal(e, value))) errors.Add($"{at} must be equal to one of the allowed values");
        if (s.ContainsKey("const") && !Equal(s["const"], value)) errors.Add($"{at} must be equal to constant");

        if (s["allOf"] is JsonArray all) foreach (var sub in all) Check(root, sub!, value, path, errors, depth + 1);
        if (s["anyOf"] is JsonArray any && !any.Any(sub => Passes(root, sub!, value, path, depth))) errors.Add($"{at} must match a schema in anyOf");
        if (s["oneOf"] is JsonArray oneOf)
        {
            var matches = oneOf.Count(sub => Passes(root, sub!, value, path, depth));
            if (matches != 1) errors.Add($"{at} must match exactly one schema in oneOf");
        }
        if (s["not"] is { } not && Passes(root, not, value, path, depth)) errors.Add($"{at} must NOT be valid");
        if (s["if"] is { } cond)
        {
            if (Passes(root, cond, value, path, depth)) { if (s["then"] is { } then) Check(root, then, value, path, errors, depth + 1); }
            else if (s["else"] is { } otherwise) Check(root, otherwise, value, path, errors, depth + 1);
        }

        switch (value)
        {
            case JsonObject o: CheckObject(root, s, o, path, errors, depth); break;
            case JsonArray a: CheckArray(root, s, a, path, errors, depth); break;
            case JsonValue v when Describe(v) == "string": CheckString(s, WorkflowArtifacts.El(v).GetString()!, at, errors); break;
            case JsonValue v when Describe(v) == "number": CheckNumber(s, WorkflowArtifacts.El(v).GetDouble(), at, errors); break;
        }
    }

    private static bool Passes(JsonNode root, JsonNode schema, JsonNode? value, string path, int depth)
    {
        var inner = new List<string>();
        Check(root, schema, value, path, inner, depth + 1);
        return inner.Count == 0;
    }

    private static JsonNode Resolve(JsonNode root, string reference)
    {
        if (reference == "#") return root;
        if (!reference.StartsWith("#/", StringComparison.Ordinal)) throw new SchemaException();
        JsonNode? current = root;
        foreach (var raw in reference[2..].Split('/'))
        {
            var key = Uri.UnescapeDataString(raw).Replace("~1", "/").Replace("~0", "~");
            current = current switch { JsonObject o => o[key], JsonArray a when int.TryParse(key, out var i) && i >= 0 && i < a.Count => a[i], _ => null };
            if (current is null) throw new SchemaException();
        }
        return current;
    }

    private static void CheckString(JsonObject s, string text, string at, List<string> errors)
    {
        var codePoints = text.EnumerateRunes().Count();
        if (Limit(s, "minLength") is { } min && codePoints < min) errors.Add($"{at} must NOT have fewer than {min} characters");
        if (Limit(s, "maxLength") is { } max && codePoints > max) errors.Add($"{at} must NOT have more than {max} characters");
        if (s["pattern"] is JsonValue p && p.TryGetValue<string>(out var pattern))
        {
            try { if (!Regex.IsMatch(text, pattern, RegexOptions.ECMAScript, TimeSpan.FromMilliseconds(200))) errors.Add($"{at} must match pattern \"{pattern}\""); }
            catch (ArgumentException) { throw new SchemaException(); }
            catch (RegexMatchTimeoutException) { errors.Add($"{at} must match pattern \"{pattern}\""); }
        }
    }

    private static double? Number(JsonObject s, string key) => s[key] is JsonValue v && WorkflowArtifacts.El(v).ValueKind == JsonValueKind.Number ? WorkflowArtifacts.El(v).GetDouble() : null;

    private static long? Limit(JsonObject s, string key) => Number(s, key) is { } d ? (long)d : null;

    private static void CheckNumber(JsonObject s, double n, string at, List<string> errors)
    {
        if (Number(s, "minimum") is { } min && n < min) errors.Add($"{at} must be >= {WorkflowArtifacts.Number(min)}");
        if (Number(s, "maximum") is { } max && n > max) errors.Add($"{at} must be <= {WorkflowArtifacts.Number(max)}");
        if (Number(s, "exclusiveMinimum") is { } emin && n <= emin) errors.Add($"{at} must be > {WorkflowArtifacts.Number(emin)}");
        if (Number(s, "exclusiveMaximum") is { } emax && n >= emax) errors.Add($"{at} must be < {WorkflowArtifacts.Number(emax)}");
        if (Number(s, "multipleOf") is { } m and > 0 && Math.Abs(n / m - Math.Round(n / m)) > 1e-9) errors.Add($"{at} must be multiple of {WorkflowArtifacts.Number(m)}");
    }

    private static void CheckArray(JsonNode root, JsonObject s, JsonArray a, string path, List<string> errors, int depth)
    {
        var at = $"data{path}";
        if (Limit(s, "minItems") is { } min && a.Count < min) errors.Add($"{at} must NOT have fewer than {min} items");
        if (Limit(s, "maxItems") is { } max && a.Count > max) errors.Add($"{at} must NOT have more than {max} items");
        if (s["uniqueItems"] is JsonValue u && u.TryGetValue<bool>(out var unique) && unique)
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            if (a.Any(x => !seen.Add(WorkflowArtifacts.Canonical(x)))) errors.Add($"{at} must NOT have duplicate items");
        }
        var offset = 0;
        var tuple = s["prefixItems"] as JsonArray ?? (s["items"] as JsonArray);
        if (tuple is not null)
        {
            for (var i = 0; i < tuple.Count && i < a.Count; i++) Check(root, tuple[i]!, a[i], $"{path}/{i}", errors, depth + 1);
            offset = tuple.Count;
        }
        // `items` as a schema covers every element (after any prefix); with the older tuple form of `items`, `additionalItems` covers the rest.
        var rest = s["items"] is JsonArray ? s["additionalItems"] : s["items"];
        if (rest is not null && rest is not JsonArray)
            for (var i = offset; i < a.Count; i++) Check(root, rest, a[i], $"{path}/{i}", errors, depth + 1);
        if (s["contains"] is { } contains && !a.Any(x => Passes(root, contains, x, path, depth))) errors.Add($"{at} must contain at least 1 valid item");
    }

    private static void CheckObject(JsonNode root, JsonObject s, JsonObject o, string path, List<string> errors, int depth)
    {
        var at = $"data{path}";
        if (s["required"] is JsonArray required)
            foreach (var r in required)
                if (r is JsonValue rv && rv.TryGetValue<string>(out var name) && !o.ContainsKey(name)) errors.Add($"{at} must have required property '{name}'");
        if (Limit(s, "minProperties") is { } min && o.Count < min) errors.Add($"{at} must NOT have fewer than {min} properties");
        if (Limit(s, "maxProperties") is { } max && o.Count > max) errors.Add($"{at} must NOT have more than {max} properties");
        var properties = s["properties"] as JsonObject;
        var patterns = s["patternProperties"] as JsonObject;
        foreach (var (key, child) in o)
        {
            var matched = false;
            if (properties is not null && properties.ContainsKey(key)) { matched = true; Check(root, properties[key]!, child, $"{path}/{key}", errors, depth + 1); }
            if (patterns is not null)
                foreach (var (pattern, sub) in patterns)
                {
                    bool hit;
                    try { hit = Regex.IsMatch(key, pattern, RegexOptions.ECMAScript, TimeSpan.FromMilliseconds(200)); }
                    catch (ArgumentException) { throw new SchemaException(); }
                    if (hit) { matched = true; Check(root, sub!, child, $"{path}/{key}", errors, depth + 1); }
                }
            if (!matched && s["additionalProperties"] is { } additional)
            {
                if (additional is JsonValue av && WorkflowArtifacts.El(av).ValueKind is JsonValueKind.False) errors.Add($"{at} must NOT have additional properties");
                else if (additional is JsonObject) Check(root, additional, child, $"{path}/{key}", errors, depth + 1);
            }
        }
    }
}
