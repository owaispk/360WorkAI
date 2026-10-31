using System.Text.Json;
using System.Text.Json.Nodes;

namespace WorkAI360.Api.Features.Policy;

public sealed record DesktopPolicyDefinition(string Id, string TeamLabel, string Group, string Name, string Description, string UserNotice, bool DefaultValue, bool? RestrictedValue);

/// <summary>"custom": the listed capabilities apply as written. "locked": the restricted values apply as well.</summary>
public sealed record TeamAccess(string Mode, IReadOnlyDictionary<string, bool> Capabilities);

/// <summary>Execution limits. Several of them combine by intersection (see <see cref="DesktopPolicyRules.ResolveExecution"/>).</summary>
public sealed record ExecutionPolicy(string Commands, IReadOnlyList<string> BlockedCommands, IReadOnlyList<string>? BrowserOrigins, bool BlockBrowserUploads);

public sealed record OnboardingPrompts(IReadOnlyList<string> Prompts, IReadOnlyList<string>? Descriptions);

/// <summary>A stored policy document, read tolerantly: only booleans for known keys, a valid access, execution and onboarding prompts survive.</summary>
public sealed record DesktopPolicyDocument(IReadOnlyDictionary<string, bool> Values, TeamAccess? Access, ExecutionPolicy? Execution, OnboardingPrompts? Onboarding);

/// <summary>A policy that matched a person, as the resolver needs it.</summary>
public sealed record AssignedPolicy(string Id, int Priority, DateTime CreatedAt, DesktopPolicyDocument Document);

/// <summary>
/// Desktop policies: the catalog, how a stored document reads, and who gets what when several policies apply. Pure functions, ported from the
/// reference's <c>packages/types/src/den/desktop-policies.ts</c>.
/// </summary>
public static class DesktopPolicyRules
{
    public static readonly IReadOnlyList<DesktopPolicyDefinition> Definitions =
    [
        new("allowCustomProviders", "Add AI providers", "ai", "Custom providers", "Allow users to add and use models that are not deployed through OpenWork Cloud.", "Your organization administrator has disabled adding custom providers.", true, false),
        new("allowZenModel", "Use the free starter model", "ai", "Free starter model (Auto)", "Allow users to use OpenWork's free, rate-limited Auto model. OpenCode Zen models are retired and never offered.", "Your administrator has turned off the free starter model.", true, false),
        new("allowMultipleWorkspaces", "Create more workspaces", "app", "Multiple workspaces", "Allow users to create or configure more than one workspace on their machine.", "Your organization administrator has restricted access to adding additional workspaces.", true, false),
        new("allowControlSettings", "Change app settings", "app", "Control Settings", "Allow users to access and change the desktop app settings.", "Your organization administrator has disabled changing desktop app settings.", true, false),
        new("allowManageExtensions", "Add local tools, skills & MCP servers", "tools", "Manage Extensions", "Allow users to install and manage extensions locally.", "Your organization administrator has disabled local extension management.", true, false),
        new("allowBuiltInExtensions", "Use built-in extensions", "tools", "Built-in Extensions", "Allow users to see and use OpenWork's built-in extensions, including browser, image, and local-provider extensions.", "Your organization administrator has disabled built-in OpenWork extensions.", true, false),
        new("allowAlphaUpdates", "Try experimental updates", "app", "Alpha updates", "Allow users to opt into experimental Alpha desktop updates.", "Your organization administrator has disabled Alpha desktop updates.", true, false),
        new("showWelcomePage", "Show welcome page", "display", "Welcome Page", "Show the Getting Started page to new users.", "Your organization administrator has disabled the Getting Started page.", true, null),
    ];

    public static readonly IReadOnlyList<string> Keys = Definitions.Select(d => d.Id).ToList();
    public static readonly IReadOnlyList<string> AssignmentRoles = ["owner", "admin", "member"];

    public static Dictionary<string, bool> All(bool value) => Keys.ToDictionary(k => k, _ => value);

    // ---------------------------------------------------------------- reading stored JSON (tolerant)

    private static JsonElement? Parse(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try { return JsonDocument.Parse(json).RootElement.Clone(); }
        catch (JsonException) { return null; }
    }

    private static Dictionary<string, bool> ReadValues(JsonElement? obj)
    {
        var result = new Dictionary<string, bool>();
        if (obj is not { ValueKind: JsonValueKind.Object } o) return result;
        foreach (var key in Keys)
            if (o.TryGetProperty(key, out var v) && v.ValueKind is JsonValueKind.True or JsonValueKind.False) result[key] = v.GetBoolean();
        return result;
    }

    private static bool IsBoolean(JsonElement v) => v.ValueKind is JsonValueKind.True or JsonValueKind.False;

    /// <summary>A valid access (mode custom|locked and a capabilities object whose known keys are all booleans), else null.</summary>
    private static TeamAccess? ReadAccess(JsonElement? doc)
    {
        if (doc is not { ValueKind: JsonValueKind.Object } d || !d.TryGetProperty("access", out var a) || a.ValueKind != JsonValueKind.Object) return null;
        if (!a.TryGetProperty("mode", out var mode) || mode.ValueKind != JsonValueKind.String || mode.GetString() is not ("custom" or "locked")) return null;
        if (!a.TryGetProperty("capabilities", out var caps) || caps.ValueKind != JsonValueKind.Object) return null;
        foreach (var key in Keys) if (caps.TryGetProperty(key, out var v) && !IsBoolean(v)) return null;
        return new TeamAccess(mode.GetString()!, ReadValues(caps));
    }

    private static ExecutionPolicy? ReadExecution(JsonElement? doc)
    {
        if (doc is not { ValueKind: JsonValueKind.Object } d || !d.TryGetProperty("execution", out var e) || e.ValueKind != JsonValueKind.Object) return null;
        var commands = e.TryGetProperty("commands", out var c) && c.ValueKind == JsonValueKind.String ? c.GetString()! : "allow";
        var blocked = StringList(e, "blockedCommands") ?? [];
        var origins = StringList(e, "browserOrigins");
        var uploads = e.TryGetProperty("blockBrowserUploads", out var u) && u.ValueKind == JsonValueKind.True;
        return new ExecutionPolicy(commands == "deny" ? "deny" : "allow", blocked, origins, uploads);
    }

    private static List<string>? StringList(JsonElement obj, string name)
    {
        if (!obj.TryGetProperty(name, out var v) || v.ValueKind != JsonValueKind.Array) return null;
        return v.EnumerateArray().Where(i => i.ValueKind == JsonValueKind.String).Select(i => i.GetString()!).ToList();
    }

    /// <summary>The onboarding prompts when 2 or 3 valid ones are stored; descriptions only when they match in number and one is not empty.</summary>
    private static OnboardingPrompts? ReadOnboarding(JsonElement? doc)
    {
        if (doc is not { ValueKind: JsonValueKind.Object } d) return null;
        var prompts = StringList(d, "onboardingPrompts");
        if (prompts is null || prompts.Count is < 2 or > 3 || prompts.Any(p => p.Trim().Length is < 1 or > 500)) return null;
        prompts = prompts.Select(p => p.Trim()).ToList();
        var descriptions = StringList(d, "onboardingPromptDescriptions");
        if (descriptions is null || descriptions.Count is < 2 or > 3 || descriptions.Any(x => x.Trim().Length > 120)) return new OnboardingPrompts(prompts, null);
        descriptions = descriptions.Select(x => x.Trim()).ToList();
        return descriptions.Count == prompts.Count && descriptions.Any(x => x.Length > 0) ? new OnboardingPrompts(prompts, descriptions) : new OnboardingPrompts(prompts, null);
    }

    public static DesktopPolicyDocument Read(string? json)
    {
        var doc = Parse(json);
        return new DesktopPolicyDocument(ReadValues(doc), ReadAccess(doc), ReadExecution(doc), ReadOnboarding(doc));
    }

    /// <summary>A default policy always has a value for every key (the catalog default when the stored document lacks one).</summary>
    public static Dictionary<string, bool> WithDefaults(IReadOnlyDictionary<string, bool> values) =>
        Definitions.ToDictionary(d => d.Id, d => values.TryGetValue(d.Id, out var v) ? v : d.DefaultValue);

    // ---------------------------------------------------------------- writing

    /// <summary>The document as stored: the booleans (all keys for the default policy), the access and execution (the existing ones when the write names none) and prompts.</summary>
    public static string Serialize(DesktopPolicyDocument doc, bool isDefault)
    {
        var o = new JsonObject();
        var values = isDefault ? WithDefaults(doc.Values) : doc.Values;
        foreach (var key in Keys) if (values.TryGetValue(key, out var v)) o[key] = v;
        if (doc.Access is not null)
        {
            var caps = new JsonObject();
            foreach (var key in Keys) if (doc.Access.Capabilities.TryGetValue(key, out var v)) caps[key] = v;
            o["access"] = new JsonObject { ["mode"] = doc.Access.Mode, ["capabilities"] = caps };
        }
        if (doc.Execution is not null) o["execution"] = ExecutionNode(doc.Execution);
        if (doc.Onboarding is not null)
        {
            o["onboardingPrompts"] = new JsonArray(doc.Onboarding.Prompts.Select(p => (JsonNode)p).ToArray());
            if (doc.Onboarding.Descriptions is not null) o["onboardingPromptDescriptions"] = new JsonArray(doc.Onboarding.Descriptions.Select(p => (JsonNode)p).ToArray());
        }
        return o.ToJsonString();
    }

    public static JsonObject ExecutionNode(ExecutionPolicy e)
    {
        var o = new JsonObject
        {
            ["commands"] = e.Commands,
            ["blockedCommands"] = new JsonArray(e.BlockedCommands.Select(c => (JsonNode)c).ToArray()),
        };
        if (e.BrowserOrigins is not null) o["browserOrigins"] = new JsonArray(e.BrowserOrigins.Select(c => (JsonNode)c).ToArray());
        o["blockBrowserUploads"] = e.BlockBrowserUploads;
        return o;
    }

    // ---------------------------------------------------------------- effective policy

    /// <summary>The restricted value for every key that has one; display preferences keep the value given.</summary>
    public static Dictionary<string, bool> ApplyRestricted(IReadOnlyDictionary<string, bool> value) =>
        Definitions.ToDictionary(d => d.Id, d => d.RestrictedValue ?? value[d.Id]);

    /// <summary>The capabilities a team's access applies, including the locked mode (restricted values).</summary>
    public static Dictionary<string, bool> AccessCapabilities(TeamAccess access)
    {
        var capabilities = WithDefaults(access.Capabilities);
        return access.Mode == "locked" ? ApplyRestricted(capabilities) : capabilities;
    }

    /// <summary>
    /// What a person may do on the desktop. Grants are a union: a key is on when the default policy (or, with no enabled default, the catalog
    /// default) or any policy assigned to the person turns it on. Then every explicit access limit (custom or locked) switches its restricted keys
    /// off, whatever the grants said. With no policies at all in the workspace everything is on.
    /// </summary>
    public static Dictionary<string, bool> CalculateEffective(int orgPolicyCount, DesktopPolicyDocument? defaultPolicy, IReadOnlyList<DesktopPolicyDocument> assigned)
    {
        if (orgPolicyCount == 0) return All(true);
        var calculated = All(false);
        var grants = new List<IReadOnlyDictionary<string, bool>> { WithDefaults(defaultPolicy?.Values ?? new Dictionary<string, bool>()) };
        grants.AddRange(assigned.Select(a => a.Values));
        foreach (var grant in grants)
            foreach (var key in Keys)
                if (grant.TryGetValue(key, out var on) && on) calculated[key] = true;

        foreach (var doc in new[] { defaultPolicy }.Concat(assigned))
        {
            if (doc?.Access is null) continue;
            var capabilities = AccessCapabilities(doc.Access);
            foreach (var d in Definitions)
                if (d.RestrictedValue is not null && !capabilities[d.Id]) calculated[d.Id] = false;
        }
        return calculated;
    }

    /// <summary>
    /// Execution limits intersect across the person's policies: commands deny wins, blocked commands add up, browser uploads are blocked when any
    /// policy blocks them, and browser origins narrow to the sites every policy that lists origins allows.
    /// </summary>
    public static ExecutionPolicy ResolveExecution(IEnumerable<DesktopPolicyDocument?> documents)
    {
        var commands = "allow";
        var blocked = new List<string>();
        var uploads = false;
        List<string>? origins = null;
        foreach (var doc in documents)
        {
            var e = doc?.Execution;
            if (e is null) continue;
            if (e.Commands == "deny") commands = "deny";
            foreach (var c in e.BlockedCommands) if (!blocked.Contains(c)) blocked.Add(c);
            uploads |= e.BlockBrowserUploads;
            if (e.BrowserOrigins is not null) origins = origins is null ? [.. e.BrowserOrigins] : origins.Where(o => e.BrowserOrigins.Contains(o)).ToList();
        }
        return new ExecutionPolicy(commands, blocked, origins, uploads);
    }

    /// <summary>
    /// The onboarding suggestions: the highest-priority assigned policy that has some wins (ties go to the older, then the smaller id); with none,
    /// the default policy's.
    /// </summary>
    public static OnboardingPrompts? SelectOnboarding(DesktopPolicyDocument? defaultPolicy, IEnumerable<AssignedPolicy> assigned)
    {
        var unique = assigned.GroupBy(a => a.Id).Select(g => g.First()).Where(a => a.Document.Onboarding is not null);
        var winner = unique
            .OrderByDescending(a => a.Priority)
            .ThenBy(a => a.CreatedAt)
            .ThenBy(a => a.Id, StringComparer.Ordinal)
            .FirstOrDefault();
        return winner?.Document.Onboarding ?? defaultPolicy?.Onboarding;
    }

    /// <summary>
    /// The assignment roles a person matches: an owner also matches admin, everyone matches member, and admin matches effective admins: a direct
    /// admin role or an Admin team (<paramref name="adminViaTeam"/>). The role may be a list such as "member,admin".
    /// </summary>
    public static IReadOnlyList<string> MatchingAssignmentRoles(string memberRole, bool adminViaTeam)
    {
        static int Level(string role) => role switch { "owner" => 2, "admin" => 1, "member" => 0, _ => -1 };
        var roles = memberRole.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).ToList();
        if (adminViaTeam) roles.Add("admin");
        return AssignmentRoles.Where(required => required == "member" || roles.Any(r => Level(r) >= Level(required))).ToList();
    }
}
