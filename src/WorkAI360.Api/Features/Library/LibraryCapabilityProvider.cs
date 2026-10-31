using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Library;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Features.Library;

/// <summary>
/// The skills an agent may read, as capabilities <c>plugin:&lt;pluginId&gt;:&lt;skillId&gt;</c> (the reference's ids). A skill is listed only when it
/// is active, sits in an active plugin, and was shared with this person, their team or everyone (on the skill, on its plugin, or on a
/// marketplace that holds the plugin). Unlike the dashboard, being an admin shows nothing here: agents follow explicit sharing only.
/// Reading one records a use for the library usage report.
/// </summary>
public sealed class LibraryCapabilityProvider : ICapabilityProvider
{
    private static readonly JsonNode NoArguments = JsonNode.Parse("""{"type":"object","properties":{},"additionalProperties":false}""")!;

    private sealed record Visible(Plugin Plugin, ConfigObject Skill, string? MarketplaceName);

    private static async Task<List<Visible>> VisibleSkillsAsync(McpPrincipal principal, DenDbContext db, string? onlyId = null)
    {
        var member = await db.Members.AsNoTracking().FirstOrDefaultAsync(m => m.OrganizationId == principal.OrganizationId && m.UserId == principal.UserId);
        if (member is null) return [];
        var teamIds = (await db.TeamMembers.AsNoTracking().Where(t => t.MemberId == member.Id).Select(t => t.TeamId).ToListAsync()).ToHashSet();
        var org = principal.OrganizationId;

        var rows = await (from m in db.Set<PluginConfigObject>().AsNoTracking()
                          join p in db.Set<Plugin>().AsNoTracking() on m.PluginId equals p.Id
                          join o in db.Set<ConfigObject>().AsNoTracking() on m.ConfigObjectId equals o.Id
                          where m.OrganizationId == org && m.RemovedAt == null && p.OrganizationId == org && p.Status == "active" && p.DeletedAt == null
                                && o.OrganizationId == org && o.ObjectType == "skill" && o.Status == "active" && o.DeletedAt == null
                          select new { Plugin = p, Skill = o }).ToListAsync();
        if (rows.Count == 0) return [];

        var grants = (await db.Set<LibraryGrant>().AsNoTracking().Where(g => g.OrganizationId == org && g.RemovedAt == null).ToListAsync())
            .Where(g => g.OrgWide || g.MemberId == member.Id || (g.TeamId is not null && teamIds.Contains(g.TeamId))).ToList();
        var skillGrants = grants.Where(g => g.ResourceKind == GrantKinds.ConfigObject).Select(g => g.ResourceId).ToHashSet();
        var pluginGrants = grants.Where(g => g.ResourceKind == GrantKinds.Plugin).Select(g => g.ResourceId).ToHashSet();
        var marketGrants = grants.Where(g => g.ResourceKind == GrantKinds.Marketplace).Select(g => g.ResourceId).ToHashSet();
        var pluginIds = rows.Select(r => r.Plugin.Id).Distinct().ToList();
        var marketplaces = (await (from mp in db.Set<MarketplacePlugin>().AsNoTracking()
                                   join m in db.Set<Marketplace>().AsNoTracking() on mp.MarketplaceId equals m.Id
                                   where mp.OrganizationId == org && pluginIds.Contains(mp.PluginId) && mp.RemovedAt == null && m.OrganizationId == org && m.Status == "active" && m.DeletedAt == null
                                   select new { mp.PluginId, m.Id, m.Name }).ToListAsync()).ToLookup(x => x.PluginId);

        var result = new List<Visible>();
        foreach (var r in rows)
        {
            if (onlyId is not null && r.Skill.Id != onlyId) continue;
            var viaMarketplace = marketplaces[r.Plugin.Id].FirstOrDefault(m => marketGrants.Contains(m.Id));
            var allowed = skillGrants.Contains(r.Skill.Id) || pluginGrants.Contains(r.Plugin.Id) || viaMarketplace is not null;
            if (!allowed) continue;
            result.Add(new Visible(r.Plugin, r.Skill, (viaMarketplace ?? marketplaces[r.Plugin.Id].FirstOrDefault())?.Name));
        }
        return result.OrderBy(v => v.Plugin.Name, StringComparer.Ordinal).ThenBy(v => v.Skill.Title, StringComparer.Ordinal).ThenBy(v => v.Skill.Id, StringComparer.Ordinal).ToList();
    }

    private static string Capability(Visible v) => $"plugin:{v.Plugin.Id}:{v.Skill.Id}";

    public async Task<IReadOnlyList<CapabilityInfo>> ListAsync(McpPrincipal principal, IServiceProvider services)
    {
        var db = services.GetRequiredService<DenDbContext>();
        var seen = new HashSet<string>();
        var list = new List<CapabilityInfo>();
        foreach (var v in await VisibleSkillsAsync(principal, db))
        {
            if (!seen.Add(Capability(v))) continue;
            var description = v.Skill.Description?.Trim();
            var prefix = v.MarketplaceName is null ? $"[{v.Plugin.Name}] {v.Skill.Title}" : $"[{v.MarketplaceName} / {v.Plugin.Name}] {v.Skill.Title}";
            list.Add(new CapabilityInfo(Capability(v), string.IsNullOrEmpty(description) ? prefix : $"{prefix}: {description}", OAuthConstants.ReadScope, NoArguments));
        }
        return list;
    }

    public async Task<CapabilityOutcome> ExecuteAsync(string id, JsonObject arguments, McpPrincipal principal, IServiceProvider services)
    {
        var db = services.GetRequiredService<DenDbContext>();
        var parts = id.Split(':');
        if (parts.Length != 3) return CapabilityOutcome.Fail("unknown_capability", "No such capability.");
        var visible = (await VisibleSkillsAsync(principal, db, parts[2])).FirstOrDefault(v => v.Plugin.Id == parts[1]);
        // Shared with them a moment ago and withdrawn since: the same answer as never shared.
        if (visible is null) return CapabilityOutcome.Fail("forbidden", "You have not been granted access to this plugin capability.");

        var version = (await db.Set<ConfigObjectVersion>().AsNoTracking().Where(v => v.ConfigObjectId == visible.Skill.Id).ToListAsync())
            .OrderByDescending(v => v.CreatedAt).ThenByDescending(v => v.Id, StringComparer.Ordinal).FirstOrDefault();
        var provenance = $"Content from plugin {visible.Plugin.Name} in your organization's library.";
        var result = new JsonObject
        {
            ["kind"] = "skill",
            ["plugin"] = visible.Plugin.Name,
            ["marketplace"] = visible.MarketplaceName,
            ["name"] = visible.Skill.Title,
            ["description"] = visible.Skill.Description,
            ["provenance"] = provenance,
        };
        if (version is null)
        {
            result["status"] = "content_not_synced";
            result["hint"] = $"Marketplace plugin \"{visible.Plugin.Name}\" has not synced content for \"{visible.Skill.Title}\" yet. Connect or sync the source, then try again.";
            return CapabilityOutcome.Ok(result);
        }
        result["content"] = version.RawSourceText ?? "";
        var member = await db.Members.AsNoTracking().FirstAsync(m => m.OrganizationId == principal.OrganizationId && m.UserId == principal.UserId);
        await services.GetRequiredService<LibraryUsage>().RecordSkillUseAsync(principal.OrganizationId, member.Id, visible.Plugin.Id, visible.Skill.Id);
        return CapabilityOutcome.Ok(result);
    }
}
