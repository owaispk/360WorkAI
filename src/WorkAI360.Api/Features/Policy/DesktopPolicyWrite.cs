using System.Text.Json;
using WorkAI360.Api.Features.Library;

namespace WorkAI360.Api.Features.Policy;

/// <summary>The policy document of a create or update request, validated. Unknown keys are dropped (as the reference's schema does).</summary>
public sealed class PolicyDocumentWrite
{
    public Dictionary<string, bool> Values { get; } = new();
    public TeamAccess? Access { get; set; }
    public ExecutionPolicy? Execution { get; set; }
    /// <summary>Absent, explicitly null (clear them), or a list.</summary>
    public bool PromptsPresent { get; set; }
    public List<string>? Prompts { get; set; }
    public bool DescriptionsPresent { get; set; }
    public List<string>? Descriptions { get; set; }
}

/// <summary>Reads the policy document of a request with the reference's zod messages, and merges it with what is stored.</summary>
public static class DesktopPolicyWrites
{
    private static string Kind(JsonElement e) => Zod.Kind(e);

    private static bool IsBool(JsonElement e) => e.ValueKind is JsonValueKind.True or JsonValueKind.False;

    private static Invalid TypeError(string path, string expected, JsonElement actual) => new(path, $"Invalid input: expected {expected}, received {Kind(actual)}");

    public static PolicyDocumentWrite Parse(JsonElement policy, string path = "policy")
    {
        var write = new PolicyDocumentWrite();
        foreach (var key in DesktopPolicyRules.Keys)
        {
            if (!policy.TryGetProperty(key, out var v) || v.ValueKind == JsonValueKind.Undefined) continue;
            if (!IsBool(v)) throw TypeError($"{path}.{key}", "boolean", v);
            write.Values[key] = v.GetBoolean();
        }
        if (policy.TryGetProperty("access", out var access)) write.Access = ParseAccess(access, $"{path}.access");
        if (policy.TryGetProperty("execution", out var execution)) write.Execution = ParseExecution(execution, $"{path}.execution");
        if (policy.TryGetProperty("onboardingPrompts", out var prompts))
        {
            write.PromptsPresent = true;
            write.Prompts = ParseTextList(prompts, $"{path}.onboardingPrompts", 500, requireNonEmpty: true);
        }
        if (policy.TryGetProperty("onboardingPromptDescriptions", out var descriptions))
        {
            write.DescriptionsPresent = true;
            write.Descriptions = ParseTextList(descriptions, $"{path}.onboardingPromptDescriptions", 120, requireNonEmpty: false);
        }
        return write;
    }

    private static TeamAccess ParseAccess(JsonElement access, string path)
    {
        if (access.ValueKind != JsonValueKind.Object) throw TypeError(path, "object", access);
        if (!access.TryGetProperty("mode", out var mode) || mode.ValueKind != JsonValueKind.String || mode.GetString() is not ("custom" or "locked"))
            throw new Invalid($"{path}.mode", "Invalid option: expected one of \"custom\"|\"locked\"", "invalid_value");
        if (!access.TryGetProperty("capabilities", out var caps)) throw new Invalid($"{path}.capabilities", "Invalid input: expected object, received undefined");
        if (caps.ValueKind != JsonValueKind.Object) throw TypeError($"{path}.capabilities", "object", caps);
        var values = new Dictionary<string, bool>();
        foreach (var key in DesktopPolicyRules.Keys)
        {
            if (!caps.TryGetProperty(key, out var v)) continue;
            if (!IsBool(v)) throw TypeError($"{path}.capabilities.{key}", "boolean", v);
            values[key] = v.GetBoolean();
        }
        return new TeamAccess(mode.GetString()!, values);
    }

    private static ExecutionPolicy ParseExecution(JsonElement e, string path)
    {
        if (e.ValueKind != JsonValueKind.Object) throw TypeError(path, "object", e);
        foreach (var p in e.EnumerateObject())
            if (p.Name is not ("commands" or "blockedCommands" or "browserOrigins" or "blockBrowserUploads"))
                throw new Invalid(path, $"Unrecognized key: \"{p.Name}\"", "unrecognized_keys");
        var commands = "allow";
        if (e.TryGetProperty("commands", out var c))
        {
            if (c.ValueKind != JsonValueKind.String || c.GetString() is not ("allow" or "deny"))
                throw new Invalid($"{path}.commands", "Invalid option: expected one of \"allow\"|\"deny\"", "invalid_value");
            commands = c.GetString()!;
        }
        var blocked = e.TryGetProperty("blockedCommands", out var b) ? ParseList(b, $"{path}.blockedCommands", 100, i => ParseText(i, $"{path}.blockedCommands", 500, true)) : [];
        List<string>? origins = e.TryGetProperty("browserOrigins", out var o) ? ParseList(o, $"{path}.browserOrigins", 100, (i, index) => ParseOrigin(i, $"{path}.browserOrigins.{index}")) : null;
        var uploads = false;
        if (e.TryGetProperty("blockBrowserUploads", out var u))
        {
            if (!IsBool(u)) throw TypeError($"{path}.blockBrowserUploads", "boolean", u);
            uploads = u.GetBoolean();
        }
        return new ExecutionPolicy(commands, blocked, origins, uploads);
    }

    private static string ParseText(JsonElement item, string path, int max, bool nonEmpty)
    {
        if (item.ValueKind != JsonValueKind.String) throw TypeError(path, "string", item);
        var s = item.GetString()!.Trim();
        if (nonEmpty && s.Length < 1) throw new Invalid(path, "Too small: expected string to have >=1 characters", "too_small");
        if (s.Length > max) throw new Invalid(path, $"Too big: expected string to have <={max} characters", "too_big");
        return s;
    }

    private static List<string> ParseList(JsonElement array, string path, int max, Func<JsonElement, string> item) =>
        ParseList(array, path, max, (e, _) => item(e));

    private static List<string> ParseList(JsonElement array, string path, int max, Func<JsonElement, int, string> item)
    {
        if (array.ValueKind != JsonValueKind.Array) throw TypeError(path, "array", array);
        if (array.GetArrayLength() > max) throw new Invalid(path, $"Too big: expected array to have <={max} items", "too_big");
        return array.EnumerateArray().Select((e, i) => item(e, i)).ToList();
    }

    /// <summary>2 or 3 trimmed texts, or null (which clears them).</summary>
    private static List<string>? ParseTextList(JsonElement v, string path, int max, bool requireNonEmpty)
    {
        if (v.ValueKind == JsonValueKind.Null) return null;
        if (v.ValueKind != JsonValueKind.Array) throw TypeError(path, "array", v);
        var length = v.GetArrayLength();
        if (length < 2) throw new Invalid(path, "Too small: expected array to have >=2 items", "too_small");
        if (length > 3) throw new Invalid(path, "Too big: expected array to have <=3 items", "too_big");
        return v.EnumerateArray().Select((e, i) => ParseText(e, $"{path}.{i}", max, requireNonEmpty)).ToList();
    }

    /// <summary>An HTTP or HTTPS site without a path, credentials, query or fragment, as its origin (lowercase, default port left out).</summary>
    private static string ParseOrigin(JsonElement item, string path)
    {
        if (item.ValueKind != JsonValueKind.String) throw TypeError(path, "string", item);
        var s = item.GetString()!;
        if (s.Length > 2048) throw new Invalid(path, "Too big: expected string to have <=2048 characters", "too_big");
        if (!Uri.TryCreate(s, UriKind.Absolute, out var url) || !s.Contains("://")) throw new Invalid(path, "Invalid URL", "invalid_format");
        if ((url.Scheme != "http" && url.Scheme != "https") || url.UserInfo.Length > 0 || url.AbsolutePath != "/" || url.Query.Length > 0 || url.Fragment.Length > 0)
            throw new Invalid(path, "Use an HTTP or HTTPS site without a path, credentials, or query.", "custom");
        return url.GetLeftPart(UriPartial.Authority).ToLowerInvariant();
    }

    /// <summary>
    /// What gets stored for a write. Named booleans are replaced (a default policy fills the rest from the catalog); access and execution the write
    /// leaves out are kept from the stored document; onboarding prompts are kept too unless <paramref name="replace"/> (a declarative PUT) says the
    /// write is the whole document. Descriptions survive only when their count matches the prompts and one is not empty.
    /// </summary>
    public static DesktopPolicyDocument Merge(PolicyDocumentWrite write, string? existingJson, bool isDefault, bool replace)
    {
        var existing = DesktopPolicyRules.Read(existingJson);
        var values = isDefault ? DesktopPolicyRules.WithDefaults(write.Values) : write.Values;

        IReadOnlyList<string>? prompts = write.Prompts is not null ? write.Prompts : !write.PromptsPresent && !replace ? existing.Onboarding?.Prompts : null;
        IReadOnlyList<string>? descriptions = null;
        if (prompts is not null)
        {
            var source = write.Descriptions is not null ? write.Descriptions
                : !write.DescriptionsPresent && !write.PromptsPresent && !replace ? existing.Onboarding?.Descriptions : null;
            if (source is not null && source.Count == prompts.Count && source.Any(d => d.Length > 0)) descriptions = source;
        }
        return new DesktopPolicyDocument(
            new Dictionary<string, bool>(values),
            write.Access ?? existing.Access,
            write.Execution ?? existing.Execution,
            prompts is null ? null : new OnboardingPrompts(prompts, descriptions));
    }
}
