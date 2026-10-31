using System.Text.Json;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Domain.Library;

namespace WorkAI360.Api.Features.Library;

/// <summary>The shapes plugins, skills, marketplaces and grants take on the wire (the reference's, key for key).</summary>
public static class LibraryJson
{
    public static string Iso(DateTime v) => Responses.IsoUtc(v);
    public static string? Iso(DateTime? v) => v is null ? null : Responses.IsoUtc(v.Value);

    public static Dictionary<string, object?> Version(ConfigObjectVersion v) => new()
    {
        ["configObjectId"] = v.ConfigObjectId,
        ["connectorSyncEventId"] = null,
        ["createdAt"] = Iso(v.CreatedAt),
        ["createdByOrgMembershipId"] = v.CreatedByMemberId,
        ["createdVia"] = v.CreatedVia,
        ["id"] = v.Id,
        ["isDeletedVersion"] = v.IsDeletedVersion,
        ["normalizedPayloadJson"] = v.NormalizedPayloadJson is null ? null : JsonSerializer.Deserialize<JsonElement>(v.NormalizedPayloadJson),
        ["rawSourceText"] = v.RawSourceText,
        ["schemaVersion"] = v.SchemaVersion,
        ["sourceRevisionRef"] = v.SourceRevisionRef,
    };

    public static Dictionary<string, object?> ConfigObject(ConfigObject o, ConfigObjectVersion? latest) => new()
    {
        ["connectorInstanceId"] = null,
        ["createdAt"] = Iso(o.CreatedAt),
        ["createdByOrgMembershipId"] = o.CreatedByMemberId,
        ["currentFileExtension"] = null,
        ["currentFileName"] = null,
        ["currentRelativePath"] = o.CurrentRelativePath,
        ["deletedAt"] = Iso(o.DeletedAt),
        ["description"] = o.Description,
        ["id"] = o.Id,
        ["latestVersion"] = latest is null ? null : Version(latest),
        ["objectType"] = o.ObjectType,
        ["organizationId"] = o.OrganizationId,
        ["searchText"] = o.SearchText,
        ["sourceMode"] = o.SourceMode,
        ["status"] = o.Status,
        ["title"] = o.Title,
        ["updatedAt"] = Iso(o.UpdatedAt),
    };

    private static string SourceFormat(Plugin p) => p.SourceFormat is "agent-plugin" or "claude-plugin" or "manual" or "mcp-directory" or "opencode-plugin" or "openwork-extension-manifest" ? p.SourceFormat : "claude-plugin";

    private static string ResourceType(string objectType) => objectType is "skill" or "agent" or "command" or "tool" or "mcp" or "hook" or "context" ? objectType : "file";

    private static object Extension(Plugin p, IReadOnlyDictionary<string, int> counts)
    {
        var format = SourceFormat(p);
        var agent = format == "agent-plugin";
        var resources = counts.Where(c => c.Value > 0).Select(c => (object)new Dictionary<string, object?>
        {
            ["type"] = ResourceType(c.Key),
            ["id"] = $"{p.Id}:{c.Key}",
            ["label"] = $"{c.Value} {c.Key}{(c.Value == 1 ? "" : "s")}",
            ["required"] = true,
        }).ToList();
        return new Dictionary<string, object?>
        {
            ["description"] = p.Description,
            ["id"] = p.Id,
            ["manifest"] = new Dictionary<string, object?>
            {
                ["schemaVersion"] = 1,
                ["id"] = p.Id,
                ["name"] = p.Name,
                ["description"] = string.IsNullOrWhiteSpace(p.Description) ? $"{p.Name} extension" : p.Description.Trim(),
                ["source"] = new Dictionary<string, object?> { ["format"] = format, ["origin"] = "den", ["reference"] = p.Id, ["trusted"] = false },
                ["resources"] = resources,
                ["contributions"] = new[]
                {
                    new Dictionary<string, object?>
                    {
                        ["type"] = "setup-instructions",
                        ["ref"] = agent ? "den.agentPlugin.setup" : "den.claudePlugin.setup",
                        ["label"] = agent ? "Agent Plugin import" : "Claude-compatible plugin import",
                        ["location"] = "settings-detail",
                    },
                },
                ["setup"] = new Dictionary<string, object?>
                {
                    ["instructions"] = agent
                        ? $"Imported from Agent Plugins {p.SourceSchemaVersion ?? "v1"}. OpenWork installs supported skills and remote MCP resources into this workspace."
                        : "Imported from a Claude-compatible plugin. OpenWork installs its resources into this workspace as extension components.",
                },
                ["lifecycle"] = new Dictionary<string, object?> { ["detection"] = counts.Keys.Select(k => $"{k}:{p.Id}").ToList() },
            },
            ["name"] = p.Name,
            ["sourceFormat"] = format,
        };
    }

    public static Dictionary<string, object?> Plugin(Plugin p, int? memberCount = null, IReadOnlyList<object>? marketplaces = null, IReadOnlyDictionary<string, int>? counts = null)
    {
        var d = new Dictionary<string, object?>
        {
            ["createdAt"] = Iso(p.CreatedAt),
            ["createdByOrgMembershipId"] = p.CreatedByMemberId,
            ["deletedAt"] = Iso(p.DeletedAt),
            ["description"] = p.Description,
            ["id"] = p.Id,
            ["extension"] = Extension(p, counts ?? new Dictionary<string, int>()),
            ["marketplaces"] = marketplaces ?? [],
        };
        if (memberCount is not null) d["memberCount"] = memberCount;
        d["name"] = p.Name;
        d["organizationId"] = p.OrganizationId;
        d["sourceRepositoryUrl"] = p.SourceRepositoryUrl;
        d["sourceFormat"] = p.SourceFormat;
        d["sourceSchemaVersion"] = p.SourceSchemaVersion;
        d["status"] = p.Status;
        d["updatedAt"] = Iso(p.UpdatedAt);
        return d;
    }

    public static Dictionary<string, object?> Marketplace(Marketplace m, int? pluginCount = null)
    {
        var d = new Dictionary<string, object?>
        {
            ["createdAt"] = Iso(m.CreatedAt),
            ["createdByOrgMembershipId"] = m.CreatedByMemberId,
            ["deletedAt"] = Iso(m.DeletedAt),
            ["description"] = m.Description,
            ["id"] = m.Id,
            ["externalKey"] = m.ExternalKey,
            ["logoUrl"] = m.LogoUrl,
            ["name"] = m.Name,
            ["organizationId"] = m.OrganizationId,
        };
        if (pluginCount is not null) d["pluginCount"] = pluginCount;
        d["status"] = m.Status;
        d["updatedAt"] = Iso(m.UpdatedAt);
        return d;
    }

    public static Dictionary<string, object?> Membership(PluginConfigObject m, object? configObject = null)
    {
        var d = new Dictionary<string, object?>();
        if (configObject is not null) d["configObject"] = configObject;
        d["configObjectId"] = m.ConfigObjectId;
        d["connectorMappingId"] = null;
        d["createdAt"] = Iso(m.CreatedAt);
        d["createdByOrgMembershipId"] = m.CreatedByMemberId;
        d["id"] = m.Id;
        d["membershipSource"] = m.MembershipSource;
        d["pluginId"] = m.PluginId;
        d["removedAt"] = Iso(m.RemovedAt);
        return d;
    }

    public static Dictionary<string, object?> MarketplaceMembership(MarketplacePlugin m, object? plugin = null)
    {
        var d = new Dictionary<string, object?>
        {
            ["createdAt"] = Iso(m.CreatedAt),
            ["createdByOrgMembershipId"] = m.CreatedByMemberId,
            ["id"] = m.Id,
            ["marketplaceId"] = m.MarketplaceId,
            ["membershipSource"] = m.MembershipSource,
        };
        if (plugin is not null) d["plugin"] = plugin;
        d["pluginId"] = m.PluginId;
        d["removedAt"] = Iso(m.RemovedAt);
        return d;
    }

    public static Dictionary<string, object?> Grant(LibraryGrant g) => new()
    {
        ["createdAt"] = Iso(g.CreatedAt),
        ["createdByOrgMembershipId"] = g.CreatedByMemberId,
        ["id"] = g.Id,
        ["orgMembershipId"] = g.MemberId,
        ["orgWide"] = g.OrgWide,
        ["removedAt"] = Iso(g.RemovedAt),
        ["role"] = g.Role,
        ["teamId"] = g.TeamId,
    };
}
