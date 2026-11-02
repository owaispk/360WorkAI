using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.OrgAdmin;

namespace WorkAI360.Api.Features.OrgAdmin;

/// <summary>Organization settings (PATCH /v1/org), deleting a workspace, and the small read routes the dashboard and desktop app poll.</summary>
public static class OrgSettingsEndpoints
{
    private static readonly string[] PatchFields = ["name", "allowedEmailDomains", "allowedDesktopVersions", "requireSso", "brandAppName", "brandLogoUrl", "brandIconUrl", "brandAccentColor"];

    public static void MapOrgSettingsEndpoints(this WebApplication app)
    {
        app.MapPatch("/v1/org", async (HttpContext ctx, OrgAccess access, DenDbContext db, IAuditLog audit) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "organization.update") is { } denied) return denied;

            var (root, invalid) = await Zod.ReadObjectAsync(ctx, "name");
            if (invalid is not null) return invalid;
            var issues = new List<ZodIssue>();
            if (Zod.String(root, "name", 2, 120, false, out var name) is { } i1) issues.Add(i1);
            var domains = ReadStrings(root, "allowedEmailDomains", 1, 255, 100, issues, out var domainsPresent);
            var versions = ReadStrings(root, "allowedDesktopVersions", 1, 32, 200, issues, out var versionsPresent);
            bool? requireSso = null;
            if (root.TryGetProperty("requireSso", out var sso))
            {
                if (sso.ValueKind is JsonValueKind.True or JsonValueKind.False) requireSso = sso.GetBoolean();
                else issues.Add(new("invalid_type", ["requireSso"], $"Invalid input: expected boolean, received {Zod.Kind(sso)}"));
            }
            var brand = new Dictionary<string, string?>();
            var brandPresent = new HashSet<string>();
            foreach (var (field, max, isUrl) in new[] { ("brandAppName", 64, false), ("brandLogoUrl", 2048, true), ("brandIconUrl", 2048, true), ("brandAccentColor", 32, false) })
            {
                if (!root.TryGetProperty(field, out var element)) continue;
                brandPresent.Add(field);
                if (element.ValueKind == JsonValueKind.Null) { brand[field] = null; continue; }
                if (Zod.String(root, field, 1, max, false, out var text, nullable: true) is { } issue) { issues.Add(issue); continue; }
                if (isUrl && !Uri.TryCreate(text, UriKind.Absolute, out _)) { issues.Add(new("invalid_format", [field], "Invalid URL")); continue; }
                brand[field] = text;
            }
            if (Zod.Unrecognized(root, PatchFields) is { } extra) issues.Add(extra);
            var nothing = name is null && !domainsPresent && !versionsPresent && requireSso is null && brandPresent.Count == 0;
            if (nothing && issues.All(i => i.Code == "unrecognized_keys")) issues.Add(new("custom", [], "Provide at least one organization field to update."));
            if (issues.Count > 0) return Zod.Respond(issues);

            string[]? normalizedDomains = null;
            if (domainsPresent)
            {
                var (good, bad) = OrgSettings.NormalizeDomains(domains);
                if (bad.Count > 0) return Results.Json(new { error = "invalid_email_domain", message = "Enter valid email domains like company.com.", invalidDomains = bad }, statusCode: 400);
                normalizedDomains = good;
            }

            var organizationId = context!.Organization.Id;
            var now = DateTime.UtcNow;
            var settings = await db.Set<OrganizationSettings>().FirstOrDefaultAsync(s => s.OrganizationId == organizationId);
            var before = Describe(context.Organization, settings);
            if (settings is null)
            {
                settings = new OrganizationSettings { OrganizationId = organizationId, UpdatedAt = now };
                db.Set<OrganizationSettings>().Add(settings);
            }
            var metadata = OrgSettings.Metadata(settings);
            if (domainsPresent) settings.AllowedEmailDomainsJson = normalizedDomains is null ? null : JsonSerializer.Serialize(normalizedDomains);
            if (versionsPresent)
            {
                if (versions is null || versions.Count == 0) metadata.Remove("allowedDesktopVersions");
                else metadata["allowedDesktopVersions"] = new JsonArray(versions.Select(v => (JsonNode)JsonValue.Create(v)!).ToArray());
            }
            if (requireSso is { } r) metadata["requireSso"] = r;
            foreach (var (field, value) in brand)
            {
                if (value is null) metadata.Remove(field);
                else metadata[field] = value;
                // A hosted URL typed in by hand replaces any stored (uploaded) image of that kind.
                if (field == "brandLogoUrl") metadata.Remove("brandLogoAsset");
                if (field == "brandIconUrl") metadata.Remove("brandIconAsset");
            }
            settings.MetadataJson = metadata.ToJsonString();
            settings.UpdatedAt = now;
            if (name is not null)
            {
                var org = await db.Organizations.FirstAsync(o => o.Id == organizationId);
                org.Name = name;
            }
            await db.SaveChangesAsync();

            var updatedOrg = await db.Organizations.AsNoTracking().FirstAsync(o => o.Id == organizationId);
            await audit.RecordAsync(context, new AuditEntry(AuditActions.OrganizationSettingsUpdated, [new("organization", organizationId, "target", updatedOrg.Name)],
                Before: before, After: Describe(updatedOrg, settings)));
            return Results.Json(new
            {
                organization = new
                {
                    id = updatedOrg.Id, name = updatedOrg.Name, slug = updatedOrg.Slug, logo = (string?)null,
                    allowedEmailDomains = OrgSettings.Domains(settings), desktopAppRestrictions = new { },
                    // The reference returns the metadata as an object here and as a JSON string in GET /v1/org.
                    metadata = JsonNode.Parse(metadata.ToJsonString()),
                    teamMembershipRevision = Guid.NewGuid().ToString(),
                    createdAt = Responses.IsoUtc(updatedOrg.CreatedAt), updatedAt = Responses.IsoUtc(now),
                },
            });
        });

        app.MapDelete("/v1/org", async (HttpContext ctx, OrgAccess access, DenDbContext db) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.RequireOwner(context!) is { } denied) return denied;
            // Deleting a workspace needs a person: unlike the reference, an API key (which could be leaked or scripted) is refused.
            if (context!.ApiKeyId is not null) return Results.Json(new { error = "forbidden", message = "Use a signed-in user session for this operation." }, statusCode: 403);
            var organizationId = context.Organization.Id;
            var name = context.Organization.Name;
            if (!await PurgeAsync(db, organizationId)) return Results.Json(new { error = "organization_not_found" }, statusCode: 404);
            return Results.Json(new { ok = true, organization = new { id = organizationId, name } });
        });

        app.MapGet("/v1/org/activity", async (HttpContext ctx, OrgAccess access) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (!context!.IsOwner && !context.IsAdmin)
            {
                ctx.Response.Headers.WWWAuthenticate = "Bearer error=\"insufficient_scope\"";
                return access.Forbidden("Only workspace owners and admins can do this. Ask one of them, or have them change your role.");
            }
            ctx.Response.Headers.CacheControl = "no-store";
            // The reference lists the newest connections, providers, plugins and skills; none of those exist in this build yet.
            return Results.Json(new { activity = Array.Empty<object>() });
        });

        app.MapGet("/v1/org/inventory-revision", async (HttpContext ctx, OrgAccess access, DenDbContext db, IOptions<AuthOptions> auth) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            ctx.Response.Headers.CacheControl = "no-store";
            return Results.Json(new { revision = await InventoryRevisionAsync(db, context!.Organization.Id) });
        });

        app.MapPost("/v1/org/feature-usage", async (HttpContext ctx, OrgAccess access) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            var (root, invalid) = await Zod.ReadObjectAsync(ctx, "features");
            if (invalid is not null) return invalid;
            var issues = new List<ZodIssue>();
            if (!root.TryGetProperty("features", out var features)) issues.Add(new("invalid_type", ["features"], "Invalid input: expected array, received undefined"));
            else if (features.ValueKind != JsonValueKind.Array) issues.Add(new("invalid_type", ["features"], $"Invalid input: expected array, received {Zod.Kind(features)}"));
            else
            {
                if (features.GetArrayLength() > 100) issues.Add(new("too_big", ["features"], "Too big: expected array to have <=100 items"));
                var index = 0;
                foreach (var item in features.EnumerateArray())
                {
                    if (item.ValueKind != JsonValueKind.String) issues.Add(new("invalid_type", ["features", index.ToString()], $"Invalid input: expected string, received {Zod.Kind(item)}"));
                    else if (item.GetString()!.Length > 64) issues.Add(new("too_big", ["features", index.ToString()], "Too big: expected string to have <=64 characters"));
                    index++;
                }
            }
            if (Zod.Unrecognized(root, "features") is { } extra) issues.Add(extra);
            if (issues.Count > 0) return Zod.Respond(issues);
            // The reference stores member, feature and day for platform admins. There is no platform-admin view here, so reports are accepted and dropped.
            return Results.Json(new { ok = true });
        });

        app.MapGet("/v1/features", async (HttpContext ctx, WorkAI360.Api.Features.PlatformAdmin.FeatureResolver resolver) =>
        {
            ctx.Response.Headers.CacheControl = "public, max-age=60, stale-if-error=86400";
            // The deployment-wide state: configuration locks, then what platform admins set for everyone (no workspace is named here).
            var effective = await resolver.EffectiveAsync(null);
            var features = new Dictionary<string, bool>();
            foreach (var key in FeatureDefaults.Public) features[key] = effective.GetValueOrDefault(key);
            features["engineV2ForceUpgrade"] = true;
            return Results.Json(new { version = 1, deployment = "self_hosted", features });
        });
    }

    private static List<string>? ReadStrings(JsonElement root, string name, int min, int max, int maxItems, List<ZodIssue> issues, out bool present)
    {
        present = root.TryGetProperty(name, out var element);
        if (!present) return null;
        if (element.ValueKind == JsonValueKind.Null) return null;
        if (element.ValueKind != JsonValueKind.Array) { issues.Add(new("invalid_type", [name], $"Invalid input: expected array, received {Zod.Kind(element)}")); return null; }
        if (element.GetArrayLength() > maxItems) { issues.Add(new("too_big", [name], $"Too big: expected array to have <={maxItems} items")); return null; }
        var list = new List<string>();
        var index = 0;
        foreach (var item in element.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String) issues.Add(new("invalid_type", [name, index.ToString()], $"Invalid input: expected string, received {Zod.Kind(item)}"));
            else
            {
                var text = item.GetString()!.Trim();
                if (text.Length < min) issues.Add(new("too_small", [name, index.ToString()], $"Too small: expected string to have >={min} characters"));
                else if (text.Length > max) issues.Add(new("too_big", [name, index.ToString()], $"Too big: expected string to have <={max} characters"));
                else list.Add(text);
            }
            index++;
        }
        return list;
    }

    private static JsonObject Describe(Organization org, OrganizationSettings? settings)
    {
        var metadata = OrgSettings.Metadata(settings);
        var domains = OrgSettings.Domains(settings);
        return new JsonObject
        {
            ["name"] = org.Name,
            ["allowedEmailDomains"] = domains is null ? null : new JsonArray(domains.Select(d => (JsonNode)JsonValue.Create(d)!).ToArray()),
            ["allowedDesktopVersions"] = metadata["allowedDesktopVersions"]?.DeepClone(),
            ["requireSso"] = metadata["requireSso"]?.DeepClone(),
            ["brandAppName"] = metadata["brandAppName"]?.DeepClone(),
            ["brandLogoUrl"] = metadata["brandLogoUrl"]?.DeepClone(),
            ["brandIconUrl"] = metadata["brandIconUrl"]?.DeepClone(),
            ["brandAccentColor"] = metadata["brandAccentColor"]?.DeepClone(),
        };
    }

    /// <summary>
    /// An opaque value that changes whenever what members can use may have changed here (members, teams, roles and their permissions, settings):
    /// clients compare it with the one they last loaded and skip reloading when it is unchanged.
    /// </summary>
    public static async Task<string> InventoryRevisionAsync(DenDbContext db, string organizationId)
    {
        var members = (await db.Members.AsNoTracking().Where(m => m.OrganizationId == organizationId).Select(m => new { m.Id, m.Role }).ToListAsync()).Select(m => $"{m.Id}:{m.Role}").Order(StringComparer.Ordinal).ToList();
        var teams = (await db.Teams.AsNoTracking().Where(t => t.OrganizationId == organizationId).Select(t => new { t.Id, t.UpdatedAt, t.GrantsOrganizationAdmin }).ToListAsync()).Select(t => $"{t.Id}:{t.UpdatedAt.Ticks}:{t.GrantsOrganizationAdmin}").Order(StringComparer.Ordinal).ToList();
        var teamIds = await db.Teams.AsNoTracking().Where(t => t.OrganizationId == organizationId).Select(t => t.Id).ToListAsync();
        var links = (await db.TeamMembers.AsNoTracking().Where(l => teamIds.Contains(l.TeamId)).Select(l => new { l.TeamId, l.MemberId }).ToListAsync()).Select(l => $"{l.TeamId}:{l.MemberId}").Order(StringComparer.Ordinal).ToList();
        var sets = await db.PermissionSets.AsNoTracking().Where(s => s.OrganizationId == organizationId).Select(s => s.Id).ToListAsync();
        var permissions = await db.PermissionSetPermissions.AsNoTracking().Where(p => sets.Contains(p.PermissionSetId)).CountAsync();
        var lastPermission = permissions == 0 ? 0 : (await db.PermissionSetPermissions.AsNoTracking().Where(p => sets.Contains(p.PermissionSetId)).MaxAsync(p => p.CreatedAt)).Ticks;
        var roleLinks = (await db.PermissionSetTeams.AsNoTracking().Where(l => sets.Contains(l.PermissionSetId)).Select(l => new { l.PermissionSetId, l.TeamId, Removed = l.RemovedAt != null }).ToListAsync()).Select(l => $"{l.PermissionSetId}:{l.TeamId}:{l.Removed}").Order(StringComparer.Ordinal).ToList();
        var settings = (await db.Set<OrganizationSettings>().AsNoTracking().Where(s => s.OrganizationId == organizationId).Select(s => s.UpdatedAt).FirstOrDefaultAsync()).Ticks;
        var text = string.Join('|', members.Concat(teams).Concat(links).Concat(roleLinks).Append($"p{permissions}:{lastPermission}").Append($"s{settings}").Append(sets.Count.ToString()));
        return Convert.ToHexStringLower(MD5.HashData(Encoding.UTF8.GetBytes(text)));
    }

    /// <summary>Removes the workspace and everything scoped to it, in one transaction. False when it was already gone.</summary>
    public static async Task<bool> PurgeAsync(DenDbContext db, string organizationId)
    {
        await using var tx = await db.Database.BeginTransactionAsync();
        var teamIds = db.Teams.Where(t => t.OrganizationId == organizationId).Select(t => t.Id);
        var setIds = db.PermissionSets.Where(s => s.OrganizationId == organizationId).Select(s => s.Id);
        await db.PermissionSetTeams.Where(l => setIds.Contains(l.PermissionSetId) || teamIds.Contains(l.TeamId)).ExecuteDeleteAsync();
        await db.PermissionSetPermissions.Where(p => setIds.Contains(p.PermissionSetId)).ExecuteDeleteAsync();
        await db.PermissionSets.Where(s => s.OrganizationId == organizationId).ExecuteDeleteAsync();
        await db.TeamMembers.Where(l => teamIds.Contains(l.TeamId)).ExecuteDeleteAsync();
        await db.Teams.Where(t => t.OrganizationId == organizationId).ExecuteDeleteAsync();
        await db.Invitations.Where(i => i.OrganizationId == organizationId).ExecuteDeleteAsync();
        await db.RefreshTokens.Where(t => t.OrganizationId == organizationId).ExecuteDeleteAsync();
        await db.OAuthConsents.Where(c => c.OrganizationId == organizationId).ExecuteDeleteAsync();
        await db.McpAccessTokens.Where(t => t.OrganizationId == organizationId).ExecuteDeleteAsync();
        await db.AuthorizationCodes.Where(c => c.OrganizationId == organizationId).ExecuteDeleteAsync();
        await db.DeviceCodes.Where(d => d.OrganizationId == organizationId).ExecuteDeleteAsync();
        await db.HandoffGrants.Where(g => g.OrganizationId == organizationId).ExecuteDeleteAsync();
        await db.Set<ApiKey>().Where(k => k.OrganizationId == organizationId).ExecuteDeleteAsync();
        await db.Set<OrganizationWebOrigin>().Where(o => o.OrganizationId == organizationId).ExecuteDeleteAsync();
        await db.Set<BrandAsset>().Where(a => a.OrganizationId == organizationId).ExecuteDeleteAsync();
        await db.Set<OrganizationSettings>().Where(s => s.OrganizationId == organizationId).ExecuteDeleteAsync();
        // The workspace's audit history goes with it.
        await db.Set<AuditEventResource>().Where(r => r.OrganizationId == organizationId).ExecuteDeleteAsync();
        await db.Set<AuditEvent>().Where(e => e.OrganizationId == organizationId).ExecuteDeleteAsync();
        await db.Set<AuditOperation>().Where(o => o.OrganizationId == organizationId).ExecuteDeleteAsync();
        await db.Set<AuditPolicy>().Where(p => p.OrganizationId == organizationId).ExecuteDeleteAsync();
        // Anyone whose session was pointing at it signs in again (as in the reference), and lands in a workspace they still belong to.
        await db.Sessions.Where(s => s.ActiveOrganizationId == organizationId).ExecuteDeleteAsync();
        await db.Members.Where(m => m.OrganizationId == organizationId).ExecuteDeleteAsync();
        var removed = await db.Organizations.Where(o => o.Id == organizationId).ExecuteDeleteAsync();
        if (removed == 0) { await tx.RollbackAsync(); return false; }
        await tx.CommitAsync();
        return true;
    }
}

/// <summary>Whether a feature is on: the reference's default, unless configuration says otherwise (<c>Features:Overrides:&lt;key&gt;</c>).</summary>
public static class FeatureState
{
    /// <summary>On in the reference, but they need server routes this build does not have yet (checklist, gateway, connectors, remote sessions, analytics): reported off until those exist.</summary>
    private static readonly HashSet<string> NeedsUnbuiltServerAreas =
    [
        "activationChecklist", "customConnectorSetup", "expandedMcpPresets", "gatewayProviderAuthErrors", "gatewayProviderRemovalLimits",
        "gatewayProviderTest", "guidedSlackSetup", "libraryConnectorNavigation", "libraryConnectorOrgSetup", "liveProviderSync", "mcpAppLibraries",
        "providerCredentialStatus", "remoteSessionAnswers", "remoteSessionSubagents", "slackSendAsBot",
    ];

    public static bool Resolve(IConfiguration configuration, string key)
    {
        var overridden = configuration.GetSection("Features:Overrides")[key];
        if (overridden is not null && bool.TryParse(overridden, out var value)) return value;
        return Default(key);
    }

    /// <summary>This build's default for a feature: the reference's, unless it needs server areas this build lacks. Platform admins change it per deployment and per workspace (Features/PlatformAdmin).</summary>
    public static bool Default(string key) => !NeedsUnbuiltServerAreas.Contains(key) && FeatureDefaults.Organization.TryGetValue(key, out var state) && state;

    public static Dictionary<string, bool> All(IConfiguration configuration)
    {
        var map = new Dictionary<string, bool>();
        foreach (var key in FeatureDefaults.Organization.Keys.Order(StringComparer.Ordinal)) map[key] = Resolve(configuration, key);
        map["engineV2ForceUpgrade"] = true;
        return map;
    }
}
