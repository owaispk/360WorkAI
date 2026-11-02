using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Connections;
using WorkAI360.Api.Features.Connections;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Features.Workspace;

/// <summary>The tools a person's scripts may call, and how they are named: the manifest is what a Workflow's required capabilities are matched against.</summary>
public sealed record BuiltTools(IReadOnlyList<CodeModeTool> Tools)
{
    public static readonly BuiltTools Empty = new([]);
    public IEnumerable<(string ScriptPath, string CapabilityName, bool ReadOnly)> Manifest => Tools.Select(t => (t.ScriptPath, t.CapabilityName, t.ReadOnly));
}

/// <summary>
/// Builds the <c>tools</c> tree for one person from what their agents can already do through <c>/mcp/agent</c> (the capability providers): the
/// workspace's own read-only operations as <c>tools.den.*</c>, and each connected MCP server the person may use as <c>tools.&lt;connection&gt;.*</c>.
/// Every call is authorized as that person when it runs. A live (read-only) run is offered only the tools that need no write scope.
/// </summary>
public sealed partial class WorkflowTools(IServiceProvider services, DenDbContext db)
{
    public const string ClientId = "workflow";
    private static readonly string[] Reserved = ["den", "skills", "marketplace", "admin", "$codemode", "__proto__", "constructor", "prototype"];

    [GeneratedRegex("[^a-z0-9_]+")]
    private static partial Regex NonIdentifier();

    public static string Sanitize(string name)
    {
        var s = NonIdentifier().Replace(name.ToLowerInvariant(), "_");
        if (s.Length == 0) return "_";
        return s[0] is >= 'a' and <= 'z' or '_' ? s : "_" + s;
    }

    public async Task<BuiltTools> BuildAsync(string userId, string organizationId, bool readOnly, CancellationToken ct)
    {
        var scopes = readOnly ? new[] { OAuthConstants.ReadScope } : [OAuthConstants.ReadScope, OAuthConstants.WriteScope];
        var principal = new McpPrincipal(userId, organizationId, scopes, ClientId);
        var providers = services.GetServices<ICapabilityProvider>().ToList();
        var listed = new List<(ICapabilityProvider Provider, CapabilityInfo Info)>();
        foreach (var provider in providers)
        {
            IReadOnlyList<CapabilityInfo> infos;
            try { infos = await provider.ListAsync(principal, services); }
            catch (Exception e) when (e is not OperationCanceledException) { continue; }
            foreach (var info in infos) listed.Add((provider, info));
        }

        var connectionIds = listed.Select(l => ConnectionCapabilityProvider.Parse(l.Info.Id)).Where(p => p is not null).Select(p => p!.Value.ConnectionId).Distinct().ToList();
        var names = connectionIds.Count == 0 ? [] : await db.Set<ExternalMcpConnection>().AsNoTracking().Where(c => c.OrganizationId == organizationId && connectionIds.Contains(c.Id))
            .OrderBy(c => c.Name).ThenBy(c => c.Id).Select(c => new { c.Id, c.Name }).ToListAsync(ct);
        var used = new HashSet<string>(Reserved, StringComparer.Ordinal);
        var namespaces = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var c in names)
        {
            var baseName = Sanitize(c.Name);
            var ns = baseName;
            for (var n = 2; used.Contains(ns); n++) ns = $"{baseName}_{n}";
            used.Add(ns);
            namespaces[c.Id] = ns;
        }

        var tools = new List<CodeModeTool>();
        foreach (var (provider, info) in listed)
        {
            if (!scopes.Contains(info.RequiredScope)) continue;
            string ns, name;
            if (info.Id.StartsWith("openwork.", StringComparison.Ordinal)) { ns = "den"; name = info.Id["openwork.".Length..].Replace('.', '_'); }
            else if (ConnectionCapabilityProvider.Parse(info.Id) is { } parsed && parsed.Tool != ConnectionCapabilityProvider.StatusTool && namespaces.TryGetValue(parsed.ConnectionId, out var cns)) { ns = cns; name = parsed.Tool; }
            else continue;
            var id = info.Id;
            var readsOnly = info.RequiredScope == OAuthConstants.ReadScope;
            tools.Add(new CodeModeTool(ns, name, id, readsOnly, async (args, token) =>
            {
                var outcome = await provider.ExecuteAsync(id, args, principal, services);
                if (outcome.Result is null) throw new InvalidOperationException(outcome.ErrorMessage ?? "The capability failed.");
                return outcome.Passthrough ? Unwrap(outcome.Result) : outcome.Result;
            }));
        }
        return new BuiltTools(tools);
    }

    /// <summary>The value an MCP tool result carries for a script: its structured content, else its text (parsed as JSON when it is), failing when the server flagged an error.</summary>
    public static JsonNode? Unwrap(JsonObject result)
    {
        var text = result["content"] is JsonArray parts
            ? string.Concat(parts.OfType<JsonObject>().Where(p => p["type"]?.GetValue<string>() == "text").Select(p => p["text"]?.GetValue<string>()))
            : "";
        if (result["isError"] is JsonValue e && e.TryGetValue<bool>(out var isError) && isError)
            throw new InvalidOperationException(text.Length > 0 ? text : "The tool reported an error.");
        if (result["structuredContent"] is { } structured) return structured.DeepClone();
        if (text.Length == 0) return null;
        try { return JsonNode.Parse(text); }
        catch (System.Text.Json.JsonException) { return JsonValue.Create(text); }
    }

    /// <summary>The tools a Workflow declared it needs, if each is still offered under the same capability; what is not offered is reported.</summary>
    public static (List<CodeModeTool> Tools, List<RequiredCapability> Missing) Restrict(BuiltTools built, IEnumerable<RequiredCapability> required)
    {
        var tools = new List<CodeModeTool>();
        var missing = new List<RequiredCapability>();
        foreach (var r in required)
        {
            var match = built.Tools.FirstOrDefault(t => t.ScriptPath == r.ScriptPath && t.CapabilityName == r.CapabilityName);
            if (match is null) missing.Add(r);
            else if (!tools.Contains(match)) tools.Add(match);
        }
        return (tools, missing);
    }

    /// <summary>The name a run records for a call, for a script path: <c>tools.docs["search-pages"]</c> becomes <c>docs.search-pages</c>.</summary>
    public static string CallName(string scriptPath)
    {
        var s = scriptPath.StartsWith("tools.", StringComparison.Ordinal) ? scriptPath["tools.".Length..] : scriptPath;
        return Regex.Replace(s, "\\[\"((?:[^\"\\\\]|\\\\.)*)\"\\]", m => "." + System.Text.Json.JsonSerializer.Deserialize<string>("\"" + m.Groups[1].Value + "\""));
    }
}
