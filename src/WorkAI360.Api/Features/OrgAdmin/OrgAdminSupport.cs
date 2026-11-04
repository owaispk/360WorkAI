using System.Text.Json;

namespace WorkAI360.Api.Features.OrgAdmin;

/// <summary>Settings for this area. Everything defaults to "on" the way a self-hosted installation would run.</summary>
public sealed class OrgAdminOptions
{
    public const string Section = "OrgAdmin";

    public AuditOptions Audit { get; set; } = new();

    public sealed class AuditOptions
    {
        /// <summary>False answers every audit route with 403 audit_visibility_disabled (the reference's DEN_AUDIT_VISIBILITY_ENABLED).</summary>
        public bool Visible { get; set; } = true;

        /// <summary>True is the reference's "explicit self-hosted entitlement" (DEN_AUDIT_SELF_HOSTED_ENABLED): audit logs may be turned on. False reports no entitlement.</summary>
        public bool SelfHosted { get; set; } = true;

        /// <summary>The reference's DEN_AUDIT_CAPTURE_ENABLED: whether events are recorded at all.</summary>
        public bool CaptureAvailable { get; set; } = true;

        /// <summary>Exports leave out the newest seconds so an event still being written cannot land behind a page already read (the reference uses 5).</summary>
        public int ExportSettleSeconds { get; set; } = 5;

        /// <summary>
        /// Days of audit history to keep; older operations, events and their resource rows are deleted by the housekeeping job. Unset (the default)
        /// keeps everything, as the reference does (its retention is preview-only, with no deletion).
        /// </summary>
        public int? RetentionDays { get; set; }
    }
}

/// <summary>One validation problem, in the shape of the reference's zod issues.</summary>
public sealed record ZodIssue(string Code, string[] Path, string Message);

/// <summary>Reading JSON bodies and answering validation errors exactly like the reference (<c>400 {error, message, details}</c>).</summary>
public static class Zod
{
    public static IResult Respond(IReadOnlyList<ZodIssue> issues)
    {
        var first = issues[0];
        var prefix = first.Path.Length > 0 ? string.Join('.', first.Path) + ": " : "";
        var more = issues.Count > 1 ? $" (and {issues.Count - 1} more)" : "";
        return Results.Json(new
        {
            error = "invalid_request",
            message = $"{prefix}{first.Message}{more}",
            details = issues.Select(i => new { code = i.Code, path = i.Path, message = i.Message }),
        }, statusCode: 400);
    }

    public static IResult Respond(string field, string message, string code = "invalid_type") => Respond([new ZodIssue(code, [field], message)]);

    /// <summary>Parses the body as an object. A missing, broken or non-object body is answered as the first required field being absent.</summary>
    public static async Task<(JsonElement Root, IResult? Failure)> ReadObjectAsync(HttpContext ctx, string firstField)
    {
        try
        {
            using var doc = await JsonDocument.ParseAsync(ctx.Request.Body);
            var root = doc.RootElement.Clone();
            if (root.ValueKind != JsonValueKind.Object) return (default, Respond([new ZodIssue("invalid_type", [], $"Invalid input: expected object, received {Kind(root)}")]));
            return (root, null);
        }
        catch (JsonException)
        {
            return (default, Respond([new ZodIssue("invalid_type", [], "Invalid input: expected object, received undefined")]));
        }
    }

    public static string Kind(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.Null => "null",
        JsonValueKind.Number => "number",
        JsonValueKind.String => "string",
        JsonValueKind.Array => "array",
        JsonValueKind.Object => "object",
        JsonValueKind.Undefined => "undefined",
        _ => "boolean",
    };

    /// <summary>The issue for keys outside the schema (the reference's schemas are strict).</summary>
    public static ZodIssue? Unrecognized(JsonElement root, params string[] allowed)
    {
        var extra = root.EnumerateObject().Select(p => p.Name).Where(n => !allowed.Contains(n)).ToList();
        if (extra.Count == 0) return null;
        var list = string.Join(", ", extra.Select(n => $"\"{n}\""));
        return new ZodIssue("unrecognized_keys", [], extra.Count == 1 ? $"Unrecognized key: {list}" : $"Unrecognized keys: {list}");
    }

    /// <summary>A required or optional string field, trimmed, with length bounds. Null means "absent".</summary>
    public static ZodIssue? String(JsonElement root, string name, int min, int max, bool required, out string? value, bool nullable = false)
    {
        value = null;
        if (!root.TryGetProperty(name, out var e))
            return required ? new ZodIssue("invalid_type", [name], "Invalid input: expected string, received undefined") : null;
        if (nullable && e.ValueKind == JsonValueKind.Null) return null;
        if (e.ValueKind != JsonValueKind.String) return new ZodIssue("invalid_type", [name], $"Invalid input: expected string, received {Kind(e)}");
        var text = e.GetString()!.Trim();
        if (text.Length < min) return new ZodIssue("too_small", [name], $"Too small: expected string to have >={min} characters");
        if (text.Length > max) return new ZodIssue("too_big", [name], $"Too big: expected string to have <={max} characters");
        value = text;
        return null;
    }
}
