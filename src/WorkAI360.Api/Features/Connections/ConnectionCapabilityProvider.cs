using System.Collections.Concurrent;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Connections;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Features.Connections;

/// <summary>
/// The tools of connected MCP servers as capabilities <c>mcp:&lt;connectionId&gt;:&lt;toolName&gt;</c> (the reference's ids). A person sees and runs only tools of
/// connections granted to them (everyone, them or one of their teams; being an admin grants nothing here), that are not switched off by
/// the connection's tool policy, and runs them with their own credential for per-member connections. Running any tool needs the
/// <c>mcp:write</c> scope (a server's own hints cannot prove a tool only reads). The grant and the policy are checked again at execution.
/// A connection that needs a person to sign in is listed as one status row <c>mcp:&lt;id&gt;:*</c> instead of being hidden.
/// </summary>
public sealed class ConnectionCapabilityProvider : ICapabilityProvider
{
    public const string Prefix = "mcp:";
    public const string StatusTool = "*";
    private static readonly TimeSpan ListDeadline = TimeSpan.FromSeconds(8);
    private static readonly TimeSpan CatalogLifetime = TimeSpan.FromSeconds(30);
    private static readonly JsonNode NoArguments = JsonNode.Parse("""{"type":"object","properties":{},"additionalProperties":false}""")!;

    // A short-lived tool list per person and connection settings, so running a tool right after finding it does not ask the server twice.
    private static readonly ConcurrentDictionary<string, (DateTime At, IReadOnlyList<McpTool> Tools)> Catalogs = new();

    public static string IdOf(string connectionId, string tool) => $"{Prefix}{connectionId}:{tool}";

    public static (string ConnectionId, string Tool)? Parse(string id)
    {
        if (!id.StartsWith(Prefix, StringComparison.Ordinal)) return null;
        var rest = id[Prefix.Length..];
        var i = rest.IndexOf(':');
        return i <= 0 ? null : (rest[..i], rest[(i + 1)..]);
    }

    private static async Task<(string MemberId, HashSet<string> Teams)?> MemberAsync(McpPrincipal principal, DenDbContext db)
    {
        var member = await db.Members.AsNoTracking().FirstOrDefaultAsync(m => m.OrganizationId == principal.OrganizationId && m.UserId == principal.UserId);
        if (member is null) return null;
        var teams = await db.TeamMembers.AsNoTracking().Where(t => t.MemberId == member.Id).Select(t => t.TeamId).ToListAsync();
        return (member.Id, teams.ToHashSet());
    }

    private static string CatalogKey(ExternalMcpConnection c, string memberId, Credential credential) =>
        $"{c.Id}|{memberId}|{c.UpdatedAt.Ticks}|{credential.AccessToken?.GetHashCode()}|{credential.ApiKey?.GetHashCode()}";

    private static async Task<IReadOnlyList<McpTool>> ToolsAsync(ConnectionService service, ExternalMcpConnection c, string memberId, Credential credential, CancellationToken ct)
    {
        var key = CatalogKey(c, memberId, credential);
        if (Catalogs.TryGetValue(key, out var hit) && DateTime.UtcNow - hit.At < CatalogLifetime) return hit.Tools;
        try
        {
            var tools = await service.ListToolsAsync(c, credential, ct);
            Catalogs[key] = (DateTime.UtcNow, tools);
            if (Catalogs.Count > 2000) foreach (var old in Catalogs.Where(e => DateTime.UtcNow - e.Value.At > CatalogLifetime).Select(e => e.Key).ToList()) Catalogs.TryRemove(old, out _);
            return tools;
        }
        catch { Catalogs.TryRemove(key, out _); throw; }
    }

    public async Task<IReadOnlyList<CapabilityInfo>> ListAsync(McpPrincipal principal, IServiceProvider services)
    {
        var db = services.GetRequiredService<DenDbContext>();
        if (await MemberAsync(principal, db) is not { } who) return [];
        var usable = await services.GetRequiredService<ConnectionService>().UsableAsync(principal.OrganizationId, who.MemberId, who.Teams);
        if (usable.Count == 0) return [];

        // Each connection is asked on its own scope (a database context is not shared between tasks) and on its own deadline.
        var scopeFactory = services.GetRequiredService<IServiceScopeFactory>();
        var tasks = usable.Select(c => Task.Run(async () =>
        {
            using var scope = scopeFactory.CreateScope();
            var service = scope.ServiceProvider.GetRequiredService<ConnectionService>();
            using var cts = new CancellationTokenSource(ListDeadline);
            var fresh = await service.FindAsync(c.OrganizationId, c.Id);
            if (fresh is null) return (IReadOnlyList<CapabilityInfo>)[];
            return await ListOneAsync(service, fresh, who.MemberId, cts.Token);
        })).ToArray();
        var all = new List<CapabilityInfo>();
        foreach (var t in await Task.WhenAll(tasks)) all.AddRange(t);
        return all;
    }

    private static async Task<IReadOnlyList<CapabilityInfo>> ListOneAsync(ConnectionService service, ExternalMcpConnection c, string memberId, CancellationToken ct)
    {
        CapabilityInfo Status(string text) => new(IdOf(c.Id, StatusTool), $"[{c.Name}] {text}", OAuthConstants.WriteScope, NoArguments);
        var credential = await service.ResolveCredentialAsync(c, memberId, ct);
        if (!credential.Ok) return [Status(c.CredentialMode == "per_member" ? $"You haven't connected your {c.Name} account yet." : $"{c.Name} is not connected yet. Ask an admin to connect it.")];
        IReadOnlyList<McpTool> tools;
        try { tools = await ToolsAsync(service, c, memberId, credential, ct); }
        catch (Exception e) when (e is McpException or OperationCanceledException) { return [Status($"{c.Name} did not list its tools. Try again in a moment.")]; }
        return tools.Where(t => !service.Evaluate(c, t.Name).Blocked)
            .Select(t => new CapabilityInfo(IdOf(c.Id, t.Name), $"[{c.Name}] {(string.IsNullOrWhiteSpace(t.Description) ? t.Title ?? t.Name : t.Description)}", OAuthConstants.WriteScope, t.InputSchema.DeepClone()))
            .ToList();
    }

    /// <summary>Any <c>mcp:</c> id is ours to answer (grants, policy and existence are checked in <see cref="ExecuteAsync"/>); it needs the write scope.</summary>
    public Task<CapabilityInfo?> ResolveAsync(string id, McpPrincipal principal, IServiceProvider services) =>
        Task.FromResult(Parse(id) is { } p ? new CapabilityInfo(id, "", OAuthConstants.WriteScope, NoArguments) : null);

    public async Task<CapabilityOutcome> ExecuteAsync(string id, JsonObject arguments, McpPrincipal principal, IServiceProvider services)
    {
        if (Parse(id) is not var (connectionId, tool)) return CapabilityOutcome.Fail("unknown_capability", $"No capability named '{id}'.");
        var db = services.GetRequiredService<DenDbContext>();
        var service = services.GetRequiredService<ConnectionService>();
        if (await MemberAsync(principal, db) is not { } who) return CapabilityOutcome.Fail("forbidden", "You are not a member of this organization.");
        var c = await service.FindAsync(principal.OrganizationId, connectionId);
        if (c is null) return CapabilityOutcome.Fail("unknown_capability", $"No external MCP connection \"{connectionId}\" in this organization.");
        if (!await service.CanUseAsync(c, who.MemberId, who.Teams)) return CapabilityOutcome.Fail("forbidden", $"You have not been granted access to \"{c.Name}\".");

        using var cts = new CancellationTokenSource(services.GetRequiredService<GuardedHttp>().ToolTimeout);
        var credential = await service.ResolveCredentialAsync(c, who.MemberId, cts.Token);
        if (tool == StatusTool)
            return credential.Ok
                ? CapabilityOutcome.Ok(new JsonObject { ["connectionId"] = c.Id, ["connectionName"] = c.Name, ["state"] = "connected", ["message"] = $"{c.Name} is connected." })
                : CapabilityOutcome.Ok(new JsonObject { ["connectionId"] = c.Id, ["connectionName"] = c.Name, ["state"] = "needs_connection", ["message"] = credential.Message, ["url"] = $"{service.WebUrl}/dashboard/your-connections?connectionId={c.Id}" });

        // The tool policy is checked on every call, whatever the agent saw when it searched.
        var policy = service.Evaluate(c, tool);
        if (policy.Blocked) return CapabilityOutcome.Fail("policy_blocked", $"{tool} is disabled for your organization{(policy.By is null ? "" : $" by {policy.By}")}.");
        if (!credential.Ok) return CapabilityOutcome.Fail("needs_connection", $"{credential.Message} Open OpenWork Cloud -> Your Connections and click Connect on \"{c.Name}\".");
        try
        {
            var tools = await ToolsAsync(service, c, who.MemberId, credential, cts.Token);
            if (tools.All(t => t.Name != tool)) return CapabilityOutcome.Fail("unknown_capability", $"No current tool named \"{tool}\" exists on \"{c.Name}\". Call search_capabilities again.");
            return CapabilityOutcome.Raw(await service.CallToolAsync(c, credential, tool, arguments, cts.Token));
        }
        catch (McpException e)
        {
            var d = ConnectionService.Diagnose(e, "MCP_TOOL_EXECUTION");
            var code = e.Kind switch { McpFailure.Tool when e.JsonRpcCode == -32602 => "invalid_capability_arguments", McpFailure.Tool => "provider_error", _ => "connection_failed" };
            return CapabilityOutcome.Fail(code, $"{d.Message} {d.OperatorAction} Diagnostic reference: {d.ReferenceId}.");
        }
        catch (OperationCanceledException) { return CapabilityOutcome.Fail("connection_failed", $"\"{c.Name}\" took too long to answer."); }
    }
}
