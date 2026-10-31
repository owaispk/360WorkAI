using System.Text.RegularExpressions;

namespace WorkAI360.Api.Features.Policy;

/// <summary>One family of agent actions an admin can allow, ask about or block (the reference's catalog, key for key).</summary>
public sealed record AgentPermissionDefinition(string Key, string Section, string Label, string Description, string Action, string Control, string? Patterns, string? PatternNoun)
{
    public bool IsToggle => Control == "toggle";
    public IReadOnlyList<string> Decisions => IsToggle ? ["allow", "deny"] : ["allow", "ask", "deny"];
}

/// <summary>What an admin saved for one permission: a decision and/or lists of patterns. Null decision means "not set".</summary>
public sealed record AgentSetting(string? Decision, IReadOnlyList<string> Allow, IReadOnlyList<string> Block)
{
    public static readonly IReadOnlyList<string> None = [];
}

/// <summary>A rule an app enforces, checked in order with the last match deciding (OpenCode's permission rules).</summary>
public sealed record AgentRule(string Action, string Resource, string Effect, string Source);

/// <summary>One policy's settings and the name shown where it decides: "Everyone" or a team's name.</summary>
public sealed record AgentPolicySettings(string Source, IReadOnlyDictionary<string, AgentSetting> Settings);

public sealed record AgentPattern(string Pattern, string Source);

public sealed record ResolvedAgentPermission(AgentPermissionDefinition Definition, string Decision, string? DecisionSource, IReadOnlyList<AgentPattern> Allow, IReadOnlyList<AgentPattern> Block);

/// <summary>
/// Agent permissions: what agents may do on members' computers. Pure functions (no database), ported from the reference's
/// <c>packages/types/src/den/agent-permissions.ts</c>: pattern validation, how a person's teams combine, and the ordered rules the desktop gets.
/// </summary>
public static class AgentPermissionRules
{
    public const string Everyone = "Everyone";
    public const string DefaultDecision = "allow";
    public const int ListMax = 100;
    private const int PatternMax = 300;

    public static readonly IReadOnlyList<string> Decisions = ["allow", "ask", "deny"];
    public static readonly IReadOnlyList<(string Id, string Label)> Sections =
        [("commands", "Commands"), ("files", "Files"), ("web", "Web"), ("extensions", "Skills and MCP servers")];

    public static readonly IReadOnlyList<AgentPermissionDefinition> Definitions =
    [
        new("commands", "commands", "Run commands", "Commands the agent runs in a terminal on the member's computer.", "shell", "choice", "command", "command"),
        new("fileEdits", "files", "Edit files", "Creating, changing and deleting files in the member's workspace. Blocking it also blocks running commands, since any command can change files.", "edit", "choice", null, null),
        new("websites", "web", "Open websites", "Pages the agent fetches, and pages the desktop app's built-in browser opens.", "webfetch", "choice", "website", "website"),
        new("webSearch", "web", "Search the web", "Web searches the agent runs.", "websearch", "toggle", null, null),
        new("localSkills", "extensions", "Use local skills", "Skills installed on the member's computer. The organization's skills in OpenWork Cloud are not affected.", "skill", "toggle", null, null),
        new("localMcpServers", "extensions", "Use local MCP servers", "MCP servers added on the member's computer. The organization's connections in OpenWork Cloud are not affected.", "mcp", "toggle", null, null),
    ];

    public static AgentPermissionDefinition? Definition(string key) => Definitions.FirstOrDefault(d => d.Key == key);

    public const string CommandPatternError = "Enter a command, using * for any text.";
    public const string WebsitePatternError = "Enter a site like docs.example.com, *.example.com or example.com/docs.";

    public static string PatternError(string kind) => kind == "website" ? WebsitePatternError : CommandPatternError;

    // ---------------------------------------------------------------- patterns

    private sealed record WebsitePattern(bool Any, string? Scheme, string Host, bool Subdomains, string? Port, string Path);

    private static readonly Regex SchemeMatch = new(@"^([A-Za-z][A-Za-z0-9+.-]*):\/\/", RegexOptions.Compiled);
    private static readonly Regex ForbiddenInPattern = new(@"[\s?#@\\]", RegexOptions.Compiled);
    private static readonly Regex PortSuffix = new(@":(\d{1,5})$", RegexOptions.Compiled);
    private const string ForbiddenHostChars = "\0\t\n\r #/:<>?@[\\]^|%";

    private static WebsitePattern? ParseWebsite(string input)
    {
        var value = input.Trim();
        if (value == "*") return new WebsitePattern(true, null, "", false, null, "");
        if (value.Length == 0 || ForbiddenInPattern.IsMatch(value)) return null;
        var m = SchemeMatch.Match(value);
        string? scheme = null;
        if (m.Success)
        {
            var s = m.Groups[1].Value.ToLowerInvariant();
            if (s != "http" && s != "https") return null;
            scheme = s;
        }
        var rest = m.Success ? value[m.Length..] : value;
        var slash = rest.IndexOf('/');
        var authority = slash == -1 ? rest : rest[..slash];
        // A trailing "/*" or "/" adds nothing: paths match as prefixes.
        var path = slash == -1 ? "" : rest[slash..];
        if (path.EndsWith("/*")) path = path[..^2];
        path = path.TrimEnd('/');
        if (path.Contains('*')) return null;
        var subdomains = authority.StartsWith("*.");
        var hostAndPort = subdomains ? authority[2..] : authority;
        if (hostAndPort.Length == 0 || hostAndPort.Contains('*')) return null;

        string? explicitPort = null;
        var host = hostAndPort;
        var pm = PortSuffix.Match(hostAndPort);
        if (pm.Success)
        {
            var port = int.Parse(pm.Groups[1].Value);
            if (port > 65535) return null;
            explicitPort = port.ToString();
            host = hostAndPort[..pm.Index];
        }
        else if (hostAndPort.Contains(':') && !hostAndPort.StartsWith('[')) return null;
        if (host.Length == 0) return null;
        if (!host.StartsWith('[') && host.IndexOfAny(ForbiddenHostChars.ToCharArray()) >= 0) return null;
        if (!Uri.TryCreate($"http://{host}", UriKind.Absolute, out var uri)) return null;
        if (uri.AbsolutePath != "/" || uri.UserInfo.Length > 0) return null;
        var hostname = uri.IdnHost.ToLowerInvariant();
        if (hostname.EndsWith('.')) hostname = hostname[..^1];
        return new WebsitePattern(false, scheme, hostname, subdomains, explicitPort, path);
    }

    private static string FormatWebsite(WebsitePattern p) =>
        p.Any ? "*" : $"{(p.Scheme is null ? "" : p.Scheme + "://")}{(p.Subdomains ? "*." : "")}{p.Host}{(p.Port is null ? "" : ":" + p.Port)}{p.Path}";

    /// <summary>The pattern in its stored form, or null when it is not a valid pattern of that kind ("command" or "website").</summary>
    public static string? NormalizePattern(string kind, string input)
    {
        var value = input.Trim();
        if (value.Length == 0 || value.Length > PatternMax || value.Contains('\r') || value.Contains('\n')) return null;
        if (kind == "website")
        {
            var site = ParseWebsite(value);
            return site is null ? null : FormatWebsite(site);
        }
        return value;
    }

    /// <summary>OpenCode's wildcard match: * is any text, ? one character, case-sensitive, \ read as /; a pattern ending in " *" also matches the command alone.</summary>
    public static bool WildcardMatch(string value, string pattern)
    {
        var text = value.Replace('\\', '/');
        var glob = pattern.Replace('\\', '/');
        if (glob.EndsWith(" *") && GlobMatches(glob[..^2], text)) return true;
        return GlobMatches(glob, text);
    }

    private static bool GlobMatches(string pattern, string value)
    {
        int pi = 0, vi = 0, star = -1, retry = 0;
        while (vi < value.Length)
        {
            var token = pi < pattern.Length ? pattern[pi] : (char?)null;
            if (token == '?' || (token is not null && token != '*' && token == value[vi])) { pi++; vi++; }
            else if (token == '*') { star = pi++; retry = vi; }
            else if (star >= 0) { pi = star + 1; vi = ++retry; }
            else return false;
        }
        while (pi < pattern.Length && pattern[pi] == '*') pi++;
        return pi == pattern.Length;
    }

    private static readonly Regex PercentEscape = new("%([0-9a-fA-F]{2})", RegexOptions.Compiled);
    private static readonly Regex Slashes = new("/{2,}", RegexOptions.Compiled);

    /// <summary>A path as a server may route it: encoded unreserved characters and separators decoded, dot segments resolved, repeated slashes collapsed.</summary>
    private static string CanonicalPath(string path)
    {
        var decoded = PercentEscape.Replace(path, m =>
        {
            var c = (char)Convert.ToInt32(m.Groups[1].Value, 16);
            if (c is '/' or '\\') return "/";
            return (c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '_' or '~' or '-') ? c.ToString() : m.Value.ToUpperInvariant();
        });
        decoded = Slashes.Replace(decoded, "/");
        return Uri.TryCreate(new Uri("http://host"), decoded, out var resolved) ? resolved.AbsolutePath : decoded;
    }

    /// <summary>Whether a website pattern covers a URL: host (and subdomains for *.host), the port and scheme when named, and the path as a prefix.</summary>
    public static bool WebsitePatternMatches(string url, string pattern)
    {
        var site = ParseWebsite(pattern);
        if (site is null) return false;
        if (site.Any) return true;
        if (!Uri.TryCreate(url, UriKind.Absolute, out var target)) return false;
        if (target.Scheme != "http" && target.Scheme != "https") return false;
        if (site.Scheme is not null && target.Scheme != site.Scheme) return false;
        var host = target.IdnHost.ToLowerInvariant();
        if (host.EndsWith('.')) host = host[..^1];
        if (site.Subdomains ? !host.EndsWith("." + site.Host) : host != site.Host) return false;
        if (site.Port is not null && target.Port.ToString() != site.Port) return false;
        if (site.Path.Length == 0) return true;
        var prefix = CanonicalPath(site.Path).TrimEnd('/');
        var path = CanonicalPath(target.AbsolutePath);
        return prefix.Length == 0 || path == prefix || path.StartsWith(prefix + "/");
    }

    // ---------------------------------------------------------------- settings

    /// <summary>
    /// One permission's setting in stored form, or null when it sets nothing. Settings saved before a permission lost its lists or its Ask first never
    /// read as looser: a switch saved as Ask first blocks, and so does one that blocked any names. Lists it no longer has are dropped.
    /// </summary>
    public static AgentSetting? NormalizeSetting(AgentPermissionDefinition definition, string? decision, IEnumerable<string>? allow, IEnumerable<string>? block)
    {
        var blockedNames = definition.Patterns is null && block is not null && block.Any();
        var stored = definition.IsToggle && (decision == "ask" || blockedNames) ? "deny" : decision;
        var chosen = stored is not null && definition.Decisions.Contains(stored) ? stored : null;
        var allowList = NormalizeList(definition.Patterns, allow);
        var blockList = NormalizeList(definition.Patterns, block);
        if (chosen is null && allowList.Count == 0 && blockList.Count == 0) return null;
        return new AgentSetting(chosen, allowList, blockList);
    }

    private static List<string> NormalizeList(string? kind, IEnumerable<string>? values)
    {
        if (kind is null || values is null) return [];
        var seen = new HashSet<string>();
        var result = new List<string>();
        foreach (var v in values)
        {
            var p = NormalizePattern(kind, v);
            if (p is not null && seen.Add(p)) result.Add(p);
        }
        return result.Take(ListMax).ToList();
    }

    // ---------------------------------------------------------------- resolution

    private static int Strictness(string decision) => decision switch { "ask" => 1, "deny" => 2, _ => 0 };

    public static string Stricter(string left, string right) => Strictness(right) > Strictness(left) ? right : left;

    private sealed record Scope(string Decision, string? DecisionSource, List<AgentPattern> Allow);

    /// <summary>
    /// A member's effective permissions. Each of the member's teams has its own decision, else everyone's, and everyone's allowed patterns plus its
    /// own; a member in no team has everyone's. The strictest decision of the member's teams applies, and an allowed pattern is an exception to it
    /// only when every team that restricts the permission allows it, so no team's list undoes another team's decision. Blocked patterns add up.
    /// </summary>
    public static List<ResolvedAgentPermission> Resolve(AgentPolicySettings? everyone, IReadOnlyList<AgentPolicySettings> teams)
    {
        var policies = new List<AgentPolicySettings>();
        if (everyone is not null) policies.Add(everyone);
        policies.AddRange(teams);

        return Definitions.Select(definition =>
        {
            static AgentSetting? Get(AgentPolicySettings? p, string key) => p is not null && p.Settings.TryGetValue(key, out var s) ? s : null;
            List<AgentPattern> Listed(AgentPolicySettings? policy, bool allow) =>
                (allow ? Get(policy, definition.Key)?.Allow : Get(policy, definition.Key)?.Block)?.Select(p => new AgentPattern(p, policy!.Source)).ToList() ?? [];

            var scopes = (teams.Count > 0 ? teams.Cast<AgentPolicySettings?>() : [null]).Select(team =>
            {
                var teamDecision = Get(team, definition.Key)?.Decision;
                var everyoneDecision = Get(everyone, definition.Key)?.Decision;
                return new Scope(
                    teamDecision ?? everyoneDecision ?? DefaultDecision,
                    teamDecision is not null ? team!.Source : everyoneDecision is not null ? everyone!.Source : null,
                    [.. Listed(everyone, true), .. Listed(team, true)]);
            }).ToList();

            var strictest = scopes[0];
            foreach (var scope in scopes)
                if (Stricter(strictest.Decision, scope.Decision) != strictest.Decision) strictest = scope;
            var restricting = scopes.Where(s => s.Decision != "allow").ToList();
            var seen = new HashSet<string>();
            var allow = strictest.Allow.Where(a => seen.Add(a.Pattern) && restricting.All(s => s.Allow.Any(e => e.Pattern == a.Pattern))).ToList();
            // seen.Add runs first: a pattern is looked at once, at its first place, even when it is then refused (as the reference does).
            var blocked = new HashSet<string>();
            var block = policies.SelectMany(p => Listed(p, false)).Where(b => blocked.Add(b.Pattern)).ToList();
            return new ResolvedAgentPermission(definition, strictest.Decision, strictest.DecisionSource, allow, block);
        }).ToList();
    }

    /// <summary>
    /// OpenCode rules for resolved permissions, in order. A decision other than Allow becomes a * rule, its allowed patterns follow as exceptions,
    /// and blocked patterns come last so they always win. A permission that allows adds no rules. Blocking file edits also blocks every command.
    /// </summary>
    public static List<AgentRule> ToRules(IReadOnlyList<ResolvedAgentPermission> resolved)
    {
        var rules = new List<AgentRule>();
        foreach (var r in resolved)
        {
            var action = r.Definition.Action;
            var restricted = r.Decision != "allow" && r.DecisionSource is not null;
            if (restricted) rules.Add(new AgentRule(action, "*", r.Decision, r.DecisionSource!));
            if (restricted) rules.AddRange(r.Allow.Select(a => new AgentRule(action, a.Pattern, "allow", a.Source)));
            rules.AddRange(r.Block.Select(b => new AgentRule(action, b.Pattern, "deny", b.Source)));
        }
        var edits = resolved.FirstOrDefault(r => r.Definition.Action == "edit");
        if (edits is { Decision: "deny", DecisionSource: not null }) rules.Add(new AgentRule("shell", "*", "deny", edits.DecisionSource));
        return rules;
    }

    public static List<AgentRule> ResolveRules(AgentPolicySettings? everyone, IReadOnlyList<AgentPolicySettings> teams) => ToRules(Resolve(everyone, teams));

    // ---------------------------------------------------------------- enforcement (what the desktop does with the rules)

    private static bool RuleMatches(AgentRule rule, string resource) =>
        rule.Action == "webfetch" ? WebsitePatternMatches(resource, rule.Resource) : WildcardMatch(resource, rule.Resource);

    /// <summary>The last rule for this action that matches the resource, as OpenCode evaluates permission rules.</summary>
    public static AgentRule? MatchingRule(IReadOnlyList<AgentRule>? rules, string action, string resource)
    {
        for (var i = (rules?.Count ?? 0) - 1; i >= 0; i--)
        {
            var rule = rules![i];
            if (rule.Action == action && RuleMatches(rule, resource)) return rule;
        }
        return null;
    }

    public sealed record Decided(string Effect, AgentRule? Rule, string Resource);

    /// <summary>The organization's decision for an action on several resources: the strictest of them.</summary>
    public static Decided Decide(IReadOnlyList<AgentRule>? rules, string action, IReadOnlyList<string> resources)
    {
        Decided? result = null;
        foreach (var resource in resources.Count > 0 ? resources : ["*"])
        {
            var rule = MatchingRule(rules, action, resource);
            var effect = rule?.Effect ?? "allow";
            if (result is null || Strictness(effect) > Strictness(result.Effect) || (effect == result.Effect && result.Rule is null && rule is not null))
                result = new Decided(effect, rule, resource);
        }
        return result ?? new Decided("allow", null, "*");
    }
}
