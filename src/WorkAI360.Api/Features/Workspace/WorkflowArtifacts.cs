using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace WorkAI360.Api.Features.Workspace;

/// <summary>
/// Canonical JSON, digests, the Markdown rendering of a result and freshness: the reference's <c>workflow-artifacts.ts</c>. The canonical form
/// sorts object keys by UTF-16 code units and prints numbers and strings the way JavaScript's <c>JSON.stringify</c> does, so a digest computed
/// here equals the one the reference computes for the same value.
/// </summary>
public static class WorkflowArtifacts
{
    public const string RendererVersion = "codemode-markdown-v1";

    /// <summary>The element behind a value node, whether it was parsed from text or built in code.</summary>
    public static JsonElement El(JsonValue v) => v.TryGetValue<JsonElement>(out var e) ? e : JsonSerializer.SerializeToElement(v);

    public static string Canonical(JsonNode? value)
    {
        var sb = new StringBuilder();
        Write(sb, value);
        return sb.ToString();
    }

    private static void Write(StringBuilder sb, JsonNode? node)
    {
        switch (node)
        {
            case null: sb.Append("null"); break;
            case JsonObject o:
                sb.Append('{');
                var first = true;
                foreach (var key in o.Select(p => p.Key).OrderBy(k => k, StringComparer.Ordinal))
                {
                    if (!first) sb.Append(',');
                    first = false;
                    Quote(sb, key);
                    sb.Append(':');
                    Write(sb, o[key]);
                }
                sb.Append('}');
                break;
            case JsonArray a:
                sb.Append('[');
                for (var i = 0; i < a.Count; i++)
                {
                    if (i > 0) sb.Append(',');
                    Write(sb, a[i]);
                }
                sb.Append(']');
                break;
            case JsonValue v:
                var e = El(v);
                switch (e.ValueKind)
                {
                    case JsonValueKind.String: Quote(sb, e.GetString()!); break;
                    case JsonValueKind.Number: sb.Append(Number(e.GetDouble())); break;
                    case JsonValueKind.True: sb.Append("true"); break;
                    case JsonValueKind.False: sb.Append("false"); break;
                    default: sb.Append("null"); break;
                }
                break;
        }
    }

    /// <summary>A number the way JavaScript prints it (no trailing zeros, exponent form from 1e21).</summary>
    public static string Number(double d)
    {
        if (double.IsNaN(d) || double.IsInfinity(d)) return "null";
        if (d == 0) return "0";
        if (d == Math.Floor(d) && Math.Abs(d) < 1e21) return d.ToString("0", CultureInfo.InvariantCulture);
        var r = d.ToString("R", CultureInfo.InvariantCulture);
        if (r.Contains('E'))
        {
            var parts = r.Split('E');
            var exp = int.Parse(parts[1], CultureInfo.InvariantCulture);
            if (exp is >= -6 and < 21) return d.ToString("0.####################", CultureInfo.InvariantCulture);
            return $"{parts[0]}e{(exp < 0 ? "-" : "+")}{Math.Abs(exp)}";
        }
        return r;
    }

    private static void Quote(StringBuilder sb, string s)
    {
        sb.Append('"');
        for (var i = 0; i < s.Length; i++)
        {
            var c = s[i];
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\f': sb.Append("\\f"); break;
                case '\n': sb.Append("\\n"); break;
                case '\r': sb.Append("\\r"); break;
                case '\t': sb.Append("\\t"); break;
                default:
                    if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else if (char.IsSurrogate(c) && !(char.IsHighSurrogate(c) && i + 1 < s.Length && char.IsLowSurrogate(s[i + 1])) && !(char.IsLowSurrogate(c) && i > 0 && char.IsHighSurrogate(s[i - 1])))
                        sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
    }

    public static string Sha256(string text) => "sha256:" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    /// <summary>The digest of the canonical form of a value (null and absent both digest as <c>null</c>).</summary>
    public static string Digest(JsonNode? value) => Sha256(Canonical(value));

    public static string? OptionalDigest(JsonNode? value) => value is null ? null : Digest(value);

    /// <summary>The digest of a script's source text (the reference's <c>codemodeCodeDigest</c>).</summary>
    public static string CodeDigest(string code) => Sha256(code);

    private static bool IsScalar(JsonNode? n) => n is null || (n is JsonValue v && El(v).ValueKind is JsonValueKind.String or JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False or JsonValueKind.Null);

    private static string EscapeHtml(string v) => v.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;");

    private static string Cell(JsonNode? value)
    {
        string rendered = value is null ? "null" : value is JsonValue v && El(v) is { ValueKind: JsonValueKind.String } s ? s.GetString()! : ScalarText(value);
        return EscapeHtml(rendered).Replace("\\", "\\\\").Replace("|", "\\|").Replace("\r\n", "\\n").Replace("\n", "\\n");
    }

    private static string ScalarText(JsonNode value)
    {
        var e = El((JsonValue)value);
        return e.ValueKind switch { JsonValueKind.Number => Number(e.GetDouble()), JsonValueKind.True => "true", JsonValueKind.False => "false", _ => "null" };
    }

    private static string Table(IEnumerable<string> headers, IEnumerable<IEnumerable<JsonNode?>> rows)
    {
        var h = headers.ToList();
        var lines = new List<string> { $"| {string.Join(" | ", h.Select(x => Cell(JsonValue.Create(x))))} |", $"| {string.Join(" | ", h.Select(_ => "---"))} |" };
        lines.AddRange(rows.Select(r => $"| {string.Join(" | ", r.Select(Cell))} |"));
        return string.Join("\n", lines);
    }

    /// <summary>The Markdown shown for a result: a string as it is, a flat object or a list of same-shaped flat objects as a table, anything else as fenced JSON.</summary>
    public static string RenderMarkdown(JsonNode? value)
    {
        if (value is JsonValue sv && El(sv) is { ValueKind: JsonValueKind.String } str) return EscapeHtml(str.GetString()!);
        if (value is JsonObject o && o.All(p => IsScalar(p.Value)))
            return Table(["Key", "Value"], o.Select(p => p.Key).OrderBy(k => k, StringComparer.Ordinal).Select(k => (IEnumerable<JsonNode?>)[JsonValue.Create(k), o[k]]));
        if (value is JsonArray a && a.Count > 0 && a.All(x => x is JsonObject))
        {
            var objects = a.Select(x => (JsonObject)x!).ToList();
            var keys = objects[0].Select(p => p.Key).OrderBy(k => k, StringComparer.Ordinal).ToList();
            var homogeneous = objects.All(x => x.Select(p => p.Key).OrderBy(k => k, StringComparer.Ordinal).SequenceEqual(keys) && x.All(p => IsScalar(p.Value)));
            if (homogeneous) return Table(keys, objects.Select(x => keys.Select(k => x[k])));
        }
        return $"```json\n{Canonical(value)}\n```";
    }

    /// <summary>How current a Workflow's latest result is (the reference's <c>artifactFreshness</c>).</summary>
    public static JsonObject Freshness(DateTime? latestFinishedAt, string? latestStatus, DateTime? latestSuccessfulFinishedAt, string? latestSuccessfulReceiptId, long maxAgeMs, string? failureReason, DateTime? now = null)
    {
        var at = now ?? DateTime.UtcNow;
        if (latestFinishedAt is null || latestStatus is null) return new JsonObject { ["state"] = "never_run" };
        long? successfulAge = latestSuccessfulFinishedAt is { } s ? Math.Max(0, (long)(at - s).TotalMilliseconds) : null;
        if (latestStatus == "failed")
            return new JsonObject
            {
                ["state"] = "needs_attention", ["ageMs"] = successfulAge, ["lastSuccessfulReceiptId"] = latestSuccessfulReceiptId,
                ["reason"] = string.IsNullOrWhiteSpace(failureReason) ? "The latest refresh failed." : failureReason!.Trim(),
            };
        var age = Math.Max(0, (long)(at - latestFinishedAt.Value).TotalMilliseconds);
        return age > maxAgeMs
            ? new JsonObject { ["state"] = "stale", ["ageMs"] = age, ["maxAgeMs"] = maxAgeMs }
            : new JsonObject { ["state"] = "fresh", ["ageMs"] = age };
    }

    /// <summary>Parses text into a node the way JSON does, with numbers kept as doubles.</summary>
    public static JsonNode? Parse(string? json) => string.IsNullOrEmpty(json) ? null : JsonNode.Parse(json);
}
