using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Data;

namespace WorkAI360.Api.OAuth;

/// <summary>One thing an agent can do, as listed by <c>search_capabilities</c>.</summary>
public sealed record CapabilityInfo(string Id, string Description, string RequiredScope, JsonNode InputSchema);

/// <summary>What running a capability gave back: a result, or an error code and message the agent can read.</summary>
public sealed record CapabilityOutcome(JsonObject? Result, string? ErrorCode = null, string? ErrorMessage = null)
{
    public static CapabilityOutcome Ok(JsonObject result) => new(result);
    public static CapabilityOutcome Fail(string code, string message) => new(null, code, message);
}

/// <summary>
/// A source of capabilities for <c>/mcp/agent</c>. Register an implementation with <c>services.AddScoped&lt;ICapabilityProvider, T&gt;()</c>
/// (from an <see cref="Features.IFeature"/>); the endpoint asks every provider to list what the caller may use and to run what they ask for.
/// <see cref="ListAsync"/> must only return capabilities this principal may see (their workspace, their access); <see cref="ExecuteAsync"/>
/// is called only with an id that provider listed.
/// </summary>
public interface ICapabilityProvider
{
    Task<IReadOnlyList<CapabilityInfo>> ListAsync(McpPrincipal principal, IServiceProvider services);

    Task<CapabilityOutcome> ExecuteAsync(string id, JsonObject arguments, McpPrincipal principal, IServiceProvider services);
}

/// <summary>The capabilities that read from the workspace itself.</summary>
public sealed class BuiltInCapabilities : ICapabilityProvider
{
    private static readonly JsonNode NoArguments = JsonNode.Parse("""{"type":"object","properties":{},"additionalProperties":false}""")!;

    private static readonly CapabilityInfo[] All =
    [
        new("openwork.whoami", "Describe the signed-in person, their workspace and role.", OAuthConstants.ReadScope, NoArguments),
        new("openwork.workspace.members", "List the members of the workspace with their roles.", OAuthConstants.ReadScope, NoArguments),
    ];

    public Task<IReadOnlyList<CapabilityInfo>> ListAsync(McpPrincipal principal, IServiceProvider services) => Task.FromResult<IReadOnlyList<CapabilityInfo>>(All);

    public async Task<CapabilityOutcome> ExecuteAsync(string id, JsonObject arguments, McpPrincipal principal, IServiceProvider services)
    {
        var db = services.GetRequiredService<DenDbContext>();
        var org = await db.Organizations.AsNoTracking().FirstAsync(o => o.Id == principal.OrganizationId);
        if (id == "openwork.whoami")
        {
            var user = await db.Users.AsNoTracking().FirstAsync(u => u.Id == principal.UserId);
            var role = await db.Members.AsNoTracking().Where(m => m.OrganizationId == org.Id && m.UserId == user.Id).Select(m => m.Role).FirstAsync();
            return CapabilityOutcome.Ok(new JsonObject
            {
                ["user"] = new JsonObject { ["id"] = user.Id, ["name"] = user.Name, ["email"] = user.Email },
                ["organization"] = new JsonObject { ["id"] = org.Id, ["name"] = org.Name, ["slug"] = org.Slug },
                ["role"] = role,
                ["scopes"] = new JsonArray(principal.Scopes.Select(s => (JsonNode)JsonValue.Create(s)!).ToArray()),
            });
        }
        var members = await (from m in db.Members.AsNoTracking()
                             join u in db.Users.AsNoTracking() on m.UserId equals u.Id
                             where m.OrganizationId == org.Id
                             orderby m.CreatedAt
                             select new { u.Name, u.Email, m.Role }).ToListAsync();
        return CapabilityOutcome.Ok(new JsonObject
        {
            ["organization"] = org.Name,
            ["members"] = new JsonArray(members.Select(m => (JsonNode)new JsonObject { ["name"] = m.Name, ["email"] = m.Email, ["role"] = m.Role }).ToArray()),
        });
    }
}
