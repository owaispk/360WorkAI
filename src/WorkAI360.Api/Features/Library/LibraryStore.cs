using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Library;
using WorkAI360.Api.Features.PluginConnections;

namespace WorkAI360.Api.Features.Library;

/// <summary>What a skill or other component is made of when it is created or revised.</summary>
public sealed record ConfigInput(string? RawSourceText, string? NormalizedPayloadJson, string? SchemaVersion, JsonElement Metadata, JsonElement Payload);

/// <summary>Reading and changing plugins, config objects (skills), marketplaces, their memberships and who may use them.</summary>
public sealed class LibraryStore(DenDbContext db, LibraryAccess lib, PermissionService permissions, PluginReadiness readiness)
{
    public static readonly string[] ObjectTypes = ["skill", "agent", "command", "tool", "mcp", "hook", "context", "custom", "script", "workflow", "app"];
    public static readonly string[] ObjectStatuses = ["active", "inactive", "deleted", "archived", "ingestion_error"];
    public static readonly string[] SourceModes = ["cloud", "import", "connector"];
    public static readonly string[] MembershipSources = ["manual", "connector", "api", "system"];
    public static readonly string[] PluginStatuses = ["active", "inactive", "deleted", "archived"];
    public static readonly string[] Roles = ["viewer", "editor", "manager"];

    /// <summary>Timestamps are kept to the millisecond, like the reference's, so list cursors compare exactly.</summary>
    public static DateTime Now() { var n = DateTime.UtcNow; return new DateTime(n.Ticks - n.Ticks % TimeSpan.TicksPerMillisecond, DateTimeKind.Utc); }

    // ---------- input ----------

    public static ConfigInput ReadInput(JsonElement input, string path = "input")
    {
        if (input.ValueKind != JsonValueKind.Object) throw new Invalid(path, $"Invalid input: expected object, received {Zod.Kind(input)}");
        var raw = Zod.Str(input, "rawSourceText", required: false, path: $"{path}.rawSourceText");
        if (raw is not null && Encoding.UTF8.GetByteCount(raw) > Projections.InputMaxBytes)
            throw new Invalid($"{path}.rawSourceText", $"rawSourceText must be at most {Projections.InputMaxBytes} bytes (1 MiB) after UTF-8 encoding.", "custom");
        string? payload = null;
        JsonElement payloadEl = default;
        if (input.TryGetProperty("normalizedPayloadJson", out var p))
        {
            if (p.ValueKind != JsonValueKind.Object) throw new Invalid($"{path}.normalizedPayloadJson", $"Invalid input: expected object, received {Zod.Kind(p)}");
            payload = p.GetRawText();
            payloadEl = p;
            if (Encoding.UTF8.GetByteCount(payload) > Projections.InputMaxBytes)
                throw new Invalid($"{path}.normalizedPayloadJson", $"normalizedPayloadJson must stringify to at most {Projections.InputMaxBytes} bytes (1 MiB) after UTF-8 encoding.", "custom");
        }
        Zod.Str(input, "parserMode", required: false, max: 100, path: $"{path}.parserMode");
        var schemaVersion = Zod.Str(input, "schemaVersion", required: false, max: 100, path: $"{path}.schemaVersion");
        var metadata = default(JsonElement);
        if (input.TryGetProperty("metadata", out var m))
        {
            if (m.ValueKind != JsonValueKind.Object) throw new Invalid($"{path}.metadata", $"Invalid input: expected object, received {Zod.Kind(m)}");
            metadata = m;
        }
        if (raw is null && payload is null) throw new Invalid($"{path}.rawSourceText", "Provide either rawSourceText or normalizedPayloadJson.", "custom");
        return new ConfigInput(raw, payload, schemaVersion, metadata, payloadEl);
    }

    // ---------- config objects ----------

    private async Task<Dictionary<string, ConfigObjectVersion>> LatestVersionsAsync(IReadOnlyCollection<string> ids)
    {
        var result = new Dictionary<string, ConfigObjectVersion>();
        if (ids.Count == 0) return result;
        var versions = await db.Set<ConfigObjectVersion>().AsNoTracking().Where(v => ids.Contains(v.ConfigObjectId)).ToListAsync();
        foreach (var g in versions.GroupBy(v => v.ConfigObjectId))
            result[g.Key] = g.OrderByDescending(v => v.CreatedAt).ThenByDescending(v => v.Id, StringComparer.Ordinal).First();
        return result;
    }

    public async Task<object> ConfigObjectJsonAsync(ConfigObject o) => LibraryJson.ConfigObject(o, (await LatestVersionsAsync([o.Id])).GetValueOrDefault(o.Id));

    public async Task<ConfigObject> CreateConfigObjectAsync(Actor a, string type, string sourceMode, IReadOnlyList<string> pluginIds, ConfigInput input, string? sourcePath = null, bool saveNow = true, string? createdVia = null, string? revision = null)
    {
        if (sourceMode == "connector") throw new LibraryFailure(400, "invalid_request", "Connector-managed config objects must be created through connector sync.");
        foreach (var pluginId in pluginIds) await lib.PluginAsync(a, pluginId, LibRole.Editor);
        var projection = Projections.Derive(type, input.RawSourceText, input.Payload, input.Metadata);
        var now = Now();
        var o = new ConfigObject
        {
            Id = Ids.New("cob"), OrganizationId = a.OrgId, ObjectType = type, SourceMode = sourceMode, Title = projection.Title, Description = projection.Description,
            SearchText = projection.SearchText, CurrentRelativePath = sourcePath, Status = "active", CreatedByMemberId = a.MemberId, CreatedAt = now, UpdatedAt = now,
        };
        db.Add(o);
        db.Add(new ConfigObjectVersion
        {
            Id = Ids.New("cov"), OrganizationId = a.OrgId, ConfigObjectId = o.Id, NormalizedPayloadJson = input.NormalizedPayloadJson, RawSourceText = input.RawSourceText,
            SchemaVersion = input.SchemaVersion, CreatedVia = createdVia ?? sourceMode, CreatedByMemberId = a.MemberId, SourceRevisionRef = revision, CreatedAt = now,
        });
        // The maker manages what they make.
        db.Add(NewGrant(a, GrantKinds.ConfigObject, o.Id, "m:" + a.MemberId, a.MemberId, null, false, "manager", "coa", now));
        foreach (var pluginId in pluginIds.Distinct())
            db.Add(new PluginConfigObject { Id = Ids.New("pco"), OrganizationId = a.OrgId, PluginId = pluginId, ConfigObjectId = o.Id, MembershipSource = "manual", CreatedByMemberId = a.MemberId, CreatedAt = now });
        if (saveNow) await db.SaveChangesAsync();
        return o;
    }

    public async Task<object> ListConfigObjectsAsync(Actor a, HttpContext ctx)
    {
        var type = Zod.QueryEnum(ctx, "type", ObjectTypes);
        var status = Zod.QueryEnum(ctx, "status", ObjectStatuses);
        var sourceMode = Zod.QueryEnum(ctx, "sourceMode", SourceModes);
        var pluginId = ctx.Request.Query.ContainsKey("pluginId") ? Zod.TypeId(ctx.Request.Query["pluginId"].ToString(), "plg", "pluginId") : null;
        var includeDeleted = Zod.QueryBool(ctx, "includeDeleted") ?? false;
        var q = Zod.QueryString(ctx, "q");
        var cursor = Zod.QueryString(ctx, "cursor");
        var limit = Zod.QueryInt(ctx, "limit", 1, 100);
        if (pluginId is not null) await lib.PluginAsync(a, pluginId, LibRole.Viewer);

        var rows = (await db.Set<ConfigObject>().AsNoTracking().Where(o => o.OrganizationId == a.OrgId).ToListAsync())
            .OrderByDescending(o => o.UpdatedAt).ThenByDescending(o => o.Id, StringComparer.Ordinal).ToList();
        var roles = await lib.ConfigObjectRolesAsync(a.Aud, rows.Select(r => r.Id).ToList());
        HashSet<string>? inPlugin = pluginId is null ? null : (await db.Set<PluginConfigObject>().AsNoTracking().Where(m => m.PluginId == pluginId && m.RemovedAt == null).Select(m => m.ConfigObjectId).ToListAsync()).ToHashSet();
        var versions = await LatestVersionsAsync(rows.Select(r => r.Id).ToList());
        var items = new List<Dictionary<string, object?>>();
        foreach (var row in rows)
        {
            if (!roles.ContainsKey(row.Id)) continue;
            if (type is not null && row.ObjectType != type) continue;
            if (status is not null && row.Status != status) continue;
            if (sourceMode is not null && row.SourceMode != sourceMode) continue;
            if (!includeDeleted && row.Status == "deleted") continue;
            if (q is not null && !$"{row.Title}\n{row.Description ?? ""}\n{row.SearchText ?? ""}".Contains(q, StringComparison.OrdinalIgnoreCase)) continue;
            if (inPlugin is not null && !inPlugin.Contains(row.Id)) continue;
            items.Add(LibraryJson.ConfigObject(row, versions.GetValueOrDefault(row.Id)));
        }
        return PageById(items, cursor, limit);
    }

    /// <summary>The reference pages these lists by "items after this id".</summary>
    public static object PageById(List<Dictionary<string, object?>> items, string? cursor, int? limit)
    {
        var size = limit ?? 50;
        var start = cursor is null ? 0 : Math.Max(items.FindIndex(i => (string?)i["id"] == cursor) + 1, 0);
        var page = items.Skip(start).Take(size).ToList();
        var next = items.Count > start + size ? (string?)page[^1]["id"] : null;
        return new { items = page, nextCursor = next };
    }

    public async Task<ConfigObject> CreateVersionAsync(Actor a, string id, ConfigInput input, string? reason)
    {
        var row = await db.Set<ConfigObject>().FirstOrDefaultAsync(o => o.OrganizationId == a.OrgId && o.Id == id) ?? throw new LibraryFailure(404, "config_object_not_found", "Config object not found.");
        if (row.ObjectType == "app") throw new LibraryFailure(400, "reserved_mcp_app_schema", "Apps cannot be written through this route.");
        if ((await lib.ConfigObjectRoleAsync(a, id)) is not { } role || role < LibRole.Editor) throw new LibraryForbidden("Missing editor access for config object.");
        var projection = Projections.Derive(row.ObjectType, input.RawSourceText, input.Payload, input.Metadata);
        var now = Now();
        db.Add(new ConfigObjectVersion
        {
            Id = Ids.New("cov"), OrganizationId = a.OrgId, ConfigObjectId = row.Id, NormalizedPayloadJson = input.NormalizedPayloadJson, RawSourceText = input.RawSourceText,
            SchemaVersion = input.SchemaVersion, CreatedVia = row.SourceMode, CreatedByMemberId = a.MemberId, SourceRevisionRef = Projections.Trimmed(reason), CreatedAt = now,
        });
        row.Description = projection.Description;
        row.SearchText = projection.SearchText;
        row.Title = projection.Title;
        row.UpdatedAt = now;
        await db.SaveChangesAsync();
        return row;
    }

    public async Task<ConfigObject> SetConfigObjectLifecycleAsync(Actor a, string id, string action)
    {
        var row = await lib.ConfigObjectAsync(a, id, LibRole.Manager);
        var now = Now();
        row.Status = action switch { "archive" => "archived", "delete" => "deleted", _ => "active" };
        row.DeletedAt = action == "delete" ? now : null;
        row.UpdatedAt = now;
        await db.SaveChangesAsync();
        return row;
    }

    public async Task<PluginConfigObject> AttachAsync(Actor a, string configObjectId, string pluginId, string? source)
    {
        var configObject = await lib.ConfigObjectAsync(a, configObjectId, LibRole.Viewer);
        // Adding a workflow or script to a plugin can widen its audience, so its manager decides.
        if (configObject.ObjectType is "workflow" or "script" or "app") await lib.ConfigObjectAsync(a, configObjectId, LibRole.Manager);
        await lib.PluginAsync(a, pluginId, LibRole.Editor);
        var existing = await db.Set<PluginConfigObject>().FirstOrDefaultAsync(m => m.PluginId == pluginId && m.ConfigObjectId == configObjectId);
        if (existing is not null)
        {
            existing.MembershipSource = source ?? existing.MembershipSource;
            existing.RemovedAt = null;
            await db.SaveChangesAsync();
            return existing;
        }
        var row = new PluginConfigObject { Id = Ids.New("pco"), OrganizationId = a.OrgId, PluginId = pluginId, ConfigObjectId = configObjectId, MembershipSource = source ?? "manual", CreatedByMemberId = a.MemberId, CreatedAt = Now() };
        db.Add(row);
        try { await db.SaveChangesAsync(); }
        catch (DbUpdateException)
        {
            // Another request attached it at the same moment: the membership exists, which is what was asked for.
            db.Entry(row).State = EntityState.Detached;
            var winner = await db.Set<PluginConfigObject>().FirstAsync(m => m.PluginId == pluginId && m.ConfigObjectId == configObjectId);
            winner.RemovedAt = null;
            await db.SaveChangesAsync();
            return winner;
        }
        return row;
    }

    public async Task DetachAsync(Actor a, string configObjectId, string pluginId)
    {
        var configObject = await lib.ConfigObjectAsync(a, configObjectId, LibRole.Viewer);
        if (configObject.ObjectType is "workflow" or "script") await lib.ConfigObjectAsync(a, configObjectId, LibRole.Manager);
        await lib.PluginAsync(a, pluginId, LibRole.Editor);
        var row = await db.Set<PluginConfigObject>().FirstOrDefaultAsync(m => m.PluginId == pluginId && m.ConfigObjectId == configObjectId && m.RemovedAt == null)
            ?? throw new LibraryFailure(404, "plugin_membership_not_found", "Plugin membership not found.");
        row.RemovedAt = Now();
        await db.SaveChangesAsync();
    }

    // ---------- plugins ----------

    private async Task<Dictionary<string, int>> MemberCountsAsync(IReadOnlyCollection<string> pluginIds)
    {
        var rows = await db.Set<PluginConfigObject>().AsNoTracking().Where(m => pluginIds.Contains(m.PluginId) && m.RemovedAt == null).GroupBy(m => m.PluginId).Select(g => new { Id = g.Key, N = g.Count() }).ToListAsync();
        return rows.ToDictionary(r => r.Id, r => r.N);
    }

    private async Task<Dictionary<string, List<object>>> MarketplaceSummariesAsync(string orgId, IReadOnlyCollection<string> pluginIds)
    {
        var rows = await (from mp in db.Set<MarketplacePlugin>().AsNoTracking()
                          join m in db.Set<Marketplace>().AsNoTracking() on mp.MarketplaceId equals m.Id
                          where m.OrganizationId == orgId && mp.RemovedAt == null && m.DeletedAt == null && pluginIds.Contains(mp.PluginId)
                          select new { mp.PluginId, m.Id, m.Name }).ToListAsync();
        return rows.GroupBy(r => r.PluginId).ToDictionary(g => g.Key, g => g.Select(r => (object)new { id = r.Id, name = r.Name }).ToList());
    }

    public async Task<object> PluginJsonAsync(Plugin p)
    {
        var counts = await MemberCountsAsync([p.Id]);
        var markets = await MarketplaceSummariesAsync(p.OrganizationId, [p.Id]);
        return LibraryJson.Plugin(p, counts.GetValueOrDefault(p.Id), markets.GetValueOrDefault(p.Id));
    }

    public async Task<Plugin> CreatePluginAsync(Actor a, string name, string? description, string? sourceRepositoryUrl, string? sourceFormat, string? sourceSchemaVersion,
        IReadOnlyList<(string Type, ConfigInput Input)> components, bool orgWide, string? marketplaceId, List<string>? objectIds = null)
    {
        if (orgWide && !a.Has("sharing.share_org_wide")) throw new LibraryForbidden("Only organization owners and admins can create org-wide plugins.");
        // Check what the components say before creating anything, so a bad one leaves nothing behind.
        foreach (var c in components) Projections.Derive(c.Type, c.Input.RawSourceText, c.Input.Payload, c.Input.Metadata);
        if (marketplaceId is not null) await lib.MarketplaceAsync(a, marketplaceId, LibRole.Editor);

        var duplicate = await db.Set<Plugin>().AsNoTracking().FirstOrDefaultAsync(p => p.OrganizationId == a.OrgId && p.CreatedByMemberId == a.MemberId && p.Name == name && p.Status == "active" && p.DeletedAt == null);
        if (duplicate is not null) throw Duplicate(name, duplicate.Id);

        var now = Now();
        var plugin = new Plugin
        {
            Id = Ids.New("plg"), OrganizationId = a.OrgId, Name = name, Description = description, SourceRepositoryUrl = sourceRepositoryUrl, SourceFormat = sourceFormat,
            SourceSchemaVersion = sourceSchemaVersion, Status = "active", CreatedByMemberId = a.MemberId, CreatedAt = now, UpdatedAt = now,
        };
        var activeKey = Plugin.ComputeActiveKey(a.OrgId, a.MemberId, name);
        db.Add(plugin);
        db.Add(NewGrant(a, GrantKinds.Plugin, plugin.Id, "m:" + a.MemberId, a.MemberId, null, false, "manager", "pag", now));
        foreach (var c in components)
        {
            var o = await CreateConfigObjectAsync(a, c.Type, "cloud", [], c.Input, saveNow: false);
            objectIds?.Add(o.Id);
            db.Add(new PluginConfigObject { Id = Ids.New("pco"), OrganizationId = a.OrgId, PluginId = plugin.Id, ConfigObjectId = o.Id, MembershipSource = "manual", CreatedByMemberId = a.MemberId, CreatedAt = now });
            if (orgWide) db.Add(NewGrant(a, GrantKinds.ConfigObject, o.Id, "org", null, null, true, "viewer", "coa", now));
        }
        if (orgWide) db.Add(NewGrant(a, GrantKinds.Plugin, plugin.Id, "org", null, null, true, "viewer", "pag", now));
        if (marketplaceId is not null)
            db.Add(new MarketplacePlugin { Id = Ids.New("mkp"), OrganizationId = a.OrgId, MarketplaceId = marketplaceId, PluginId = plugin.Id, MembershipSource = "manual", CreatedByMemberId = a.MemberId, CreatedAt = now });
        try { await db.SaveChangesAsync(); }
        catch (DbUpdateException)
        {
            // Two requests made the same plugin at once: the unique index let one through.
            db.ChangeTracker.Clear();
            var winner = await db.Set<Plugin>().AsNoTracking().FirstOrDefaultAsync(p => p.ActiveKey == activeKey);
            if (winner is null) throw;
            throw Duplicate(name, winner.Id);
        }
        return plugin;
    }

    private static LibraryFailure Duplicate(string name, string id) =>
        new(409, "duplicate_plugin", $"You already have an active plugin named \"{name}\" ({id}). Update it instead of creating a duplicate.");

    public async Task<Plugin> UpdatePluginAsync(Actor a, string id, (bool Present, string? Value) name, (bool Present, string? Value) description)
    {
        var row = await lib.PluginAsync(a, id, LibRole.Editor);
        if (name.Present && name.Value is not null) row.Name = name.Value;
        if (description.Present) row.Description = description.Value;
        row.UpdatedAt = Now();
        try { await db.SaveChangesAsync(); }
        catch (DbUpdateException) { throw Duplicate(row.Name, "another plugin"); }
        return row;
    }

    public async Task<Plugin> SetPluginLifecycleAsync(Actor a, string id, string action)
    {
        var row = await lib.PluginAsync(a, id, LibRole.Viewer);
        await lib.PluginAsync(a, id, LibRole.Manager);
        row.DeletedAt = action == "archive" ? row.DeletedAt : null;
        row.Status = action == "archive" ? "archived" : "active";
        row.UpdatedAt = Now();
        try { await db.SaveChangesAsync(); }
        catch (DbUpdateException) { throw new LibraryFailure(409, "duplicate_plugin", $"You already have an active plugin named \"{row.Name}\". Rename one of them first."); }
        return row;
    }

    public async Task<object> ListPluginsAsync(Actor a, HttpContext ctx)
    {
        var limit = Zod.QueryInt(ctx, "limit", 1, 100) ?? 50;
        var cursorText = ctx.Request.Query["cursor"].ToString();
        (long At, string Id)? cursor = null;
        if (cursorText.Length > 0) cursor = DecodeCursor(cursorText);
        var status = Zod.QueryEnum(ctx, "status", PluginStatuses);
        var q = Zod.QueryString(ctx, "q");
        var name = Zod.QueryString(ctx, "name");
        var teamId = ctx.Request.Query.ContainsKey("teamId") ? Zod.TypeId(ctx.Request.Query["teamId"].ToString(), "tem", "teamId") : null;
        var memberId = ctx.Request.Query.ContainsKey("memberId") ? Zod.TypeId(ctx.Request.Query["memberId"].ToString(), "om", "memberId") : null;
        var includeAccess = Zod.QueryBool(ctx, "includeAccess") ?? false;
        var includeTotal = Zod.QueryBool(ctx, "includeTotal") ?? false;
        var ownerId = ctx.Request.Query.ContainsKey("ownerId") ? Zod.TypeId(ctx.Request.Query["ownerId"].ToString(), "om", "ownerId") : null;
        var includeFacets = Zod.QueryBool(ctx, "includeFacets") ?? false;
        if (teamId is not null && memberId is not null) throw new Invalid("", "Choose a team or a member, not both.", "custom");

        // An audience filter shows what a team or another person could see; a team or person from elsewhere shows nothing.
        Audience? audience = null;
        if (memberId is not null || teamId is not null)
        {
            if (memberId is not null)
            {
                var target = await db.Members.AsNoTracking().FirstOrDefaultAsync(m => m.OrganizationId == a.OrgId && m.Id == memberId);
                if (target is null) return Empty(includeTotal);
                var teams = await db.TeamMembers.AsNoTracking().Where(t => t.MemberId == memberId).Select(t => t.TeamId).ToListAsync();
                var manageAll = await permissions.ResolveAsync(a.OrgId, target);
                audience = new Audience(a.OrgId, memberId, teams.ToHashSet(), manageAll.Has("sharing.manage_all"));
            }
            else
            {
                if (!await db.Teams.AsNoTracking().AnyAsync(t => t.OrganizationId == a.OrgId && t.Id == teamId)) return Empty(includeTotal);
                audience = new Audience(a.OrgId, "", [teamId!], false);
            }
        }

        var all = await db.Set<Plugin>().AsNoTracking().Where(p => p.OrganizationId == a.OrgId).ToListAsync();
        var baseRows = all.Where(p => (status is null || p.Status == status)
                && (q is null || p.Name.Contains(q, StringComparison.OrdinalIgnoreCase) || (p.Description ?? "").Contains(q, StringComparison.OrdinalIgnoreCase))
                && (name is null || p.Name.Contains(name, StringComparison.OrdinalIgnoreCase))).ToList();
        var callerRoles = await lib.PluginRolesAsync(a.Aud, baseRows.Select(p => p.Id).ToList());
        baseRows = baseRows.Where(p => callerRoles.ContainsKey(p.Id)).ToList();
        var audienceRoles = audience is null || audience.ManageAll ? null : await lib.PluginRolesAsync(audience, baseRows.Select(p => p.Id).ToList());
        var inAudience = audienceRoles is null ? baseRows : baseRows.Where(p => audienceRoles.ContainsKey(p.Id)).ToList();
        var filtered = inAudience.Where(p => ownerId is null || p.CreatedByMemberId == ownerId)
            .OrderByDescending(p => p.UpdatedAt).ThenByDescending(p => p.Id, StringComparer.Ordinal).ToList();

        var afterCursor = cursor is null ? filtered : filtered.Where(p => { var at = new DateTimeOffset(p.UpdatedAt).ToUnixTimeMilliseconds(); return at < cursor.Value.At || (at == cursor.Value.At && string.CompareOrdinal(p.Id, cursor.Value.Id) < 0); }).ToList();
        var page = afterCursor.Take(limit).ToList();
        string? next = afterCursor.Count > limit && page.Count > 0 ? EncodeCursor(page[^1]) : null;

        var ids = page.Select(p => p.Id).ToList();
        var counts = await MemberCountsAsync(ids);
        var markets = await MarketplaceSummariesAsync(a.OrgId, ids);
        var managed = page.Where(p => callerRoles.GetValueOrDefault(p.Id) == LibRole.Manager).Select(p => p.Id).ToList();
        Dictionary<string, List<object>>? access = null;
        if (includeAccess && managed.Count > 0)
        {
            var grants = await db.Set<LibraryGrant>().AsNoTracking().Where(g => g.OrganizationId == a.OrgId && g.ResourceKind == GrantKinds.Plugin && managed.Contains(g.ResourceId) && g.RemovedAt == null).ToListAsync();
            access = grants.OrderByDescending(g => g.CreatedAt).GroupBy(g => g.ResourceId).ToDictionary(g => g.Key, g => g.Select(x => (object)LibraryJson.Grant(x)).ToList());
        }
        var items = page.Select(p =>
        {
            var d = LibraryJson.Plugin(p, counts.GetValueOrDefault(p.Id), markets.GetValueOrDefault(p.Id));
            if (includeAccess && callerRoles.GetValueOrDefault(p.Id) == LibRole.Manager) d["access"] = access?.GetValueOrDefault(p.Id) ?? [];
            return d;
        }).ToList();

        var result = new Dictionary<string, object?> { ["items"] = items, ["nextCursor"] = next };
        if (includeTotal) result["total"] = filtered.Count;
        if (includeFacets)
        {
            var teamCounts = new List<object>();
            foreach (var team in await db.Teams.AsNoTracking().Where(t => t.OrganizationId == a.OrgId).Select(t => t.Id).ToListAsync())
            {
                var roles = await lib.PluginRolesAsync(new Audience(a.OrgId, "", [team], false), baseRows.Select(p => p.Id).ToList());
                teamCounts.Add(new { id = team, count = baseRows.Count(p => roles.ContainsKey(p.Id) && (ownerId is null || p.CreatedByMemberId == ownerId)) });
            }
            result["teamCounts"] = teamCounts;
            result["ownerCounts"] = inAudience.GroupBy(p => p.CreatedByMemberId).Select(g => (object)new { id = g.Key, count = g.Count() }).ToList();
        }
        return result;
    }

    private static object Empty(bool includeTotal)
    {
        var d = new Dictionary<string, object?> { ["items"] = Array.Empty<object>(), ["nextCursor"] = null };
        if (includeTotal) d["total"] = 0;
        return d;
    }

    private static string EncodeCursor(Plugin p) =>
        Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(new { at = new DateTimeOffset(p.UpdatedAt).ToUnixTimeMilliseconds(), id = p.Id })).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static (long, string) DecodeCursor(string text)
    {
        try
        {
            var padded = text.Replace('-', '+').Replace('_', '/');
            padded = padded.PadRight(padded.Length + (4 - padded.Length % 4) % 4, '=');
            using var doc = JsonDocument.Parse(Convert.FromBase64String(padded));
            var at = doc.RootElement.GetProperty("at").GetInt64();
            var id = doc.RootElement.GetProperty("id").GetString();
            if (string.IsNullOrEmpty(id)) throw new FormatException();
            return (at, id);
        }
        catch (Exception e) when (e is FormatException or JsonException or KeyNotFoundException or InvalidOperationException)
        {
            throw new Invalid("cursor", "Invalid cursor.", "custom");
        }
    }

    public async Task<object> PluginMembershipsAsync(Actor a, string pluginId, bool includeConfigObjects, bool onlyActive, bool legacyWorkflowType)
    {
        await lib.PluginAsync(a, pluginId, LibRole.Viewer);
        return new { items = await SerializeMembershipsAsync(await db.Set<PluginConfigObject>().AsNoTracking().Where(m => m.PluginId == pluginId && (!onlyActive || m.RemovedAt == null)).ToListAsync(), includeConfigObjects, onlyActive, legacyWorkflowType), nextCursor = (string?)null };
    }

    private async Task<List<Dictionary<string, object?>>> SerializeMembershipsAsync(List<PluginConfigObject> memberships, bool includeConfigObjects, bool onlyActive, bool legacyWorkflowType)
    {
        memberships = memberships.OrderByDescending(m => m.CreatedAt).ThenByDescending(m => m.Id, StringComparer.Ordinal).ToList();
        if (!includeConfigObjects) return memberships.Select(m => LibraryJson.Membership(m)).ToList();
        var ids = memberships.Select(m => m.ConfigObjectId).Distinct().ToList();
        var objects = await db.Set<ConfigObject>().AsNoTracking().Where(o => ids.Contains(o.Id)).ToListAsync();
        if (onlyActive) objects = objects.Where(o => o.Status == "active" && o.DeletedAt == null).ToList();
        var byId = objects.ToDictionary(o => o.Id);
        var versions = await LatestVersionsAsync(byId.Keys.ToList());
        var result = new List<Dictionary<string, object?>>();
        foreach (var m in memberships)
        {
            if (!byId.TryGetValue(m.ConfigObjectId, out var o)) { if (onlyActive) continue; result.Add(LibraryJson.Membership(m)); continue; }
            var json = LibraryJson.ConfigObject(o, versions.GetValueOrDefault(o.Id));
            if (legacyWorkflowType && o.ObjectType == "workflow") json["objectType"] = "script";
            result.Add(LibraryJson.Membership(m, json));
        }
        return result;
    }

    /// <summary>Many plugins' resolved contents at once: the ones the caller can view, and why the rest are missing.</summary>
    public async Task<object> ResolvedPluginsAsync(Actor a, IReadOnlyList<string> pluginIds)
    {
        var roles = await lib.PluginRolesAsync(a.Aud, pluginIds);
        var visible = pluginIds.Where(roles.ContainsKey).ToList();
        var hidden = pluginIds.Where(id => !roles.ContainsKey(id)).ToList();
        var existing = hidden.Count == 0 ? [] : (await db.Set<Plugin>().AsNoTracking().Where(p => p.OrganizationId == a.OrgId && hidden.Contains(p.Id)).Select(p => p.Id).ToListAsync()).ToHashSet();
        var memberships = visible.Count == 0 ? [] : await db.Set<PluginConfigObject>().AsNoTracking().Where(m => visible.Contains(m.PluginId) && m.RemovedAt == null).ToListAsync();
        var items = await SerializeMembershipsAsync(memberships, true, true, true);
        var plugins = new Dictionary<string, object>();
        var lists = visible.ToDictionary(id => id, _ => new List<Dictionary<string, object?>>());
        foreach (var item in items) lists[(string)item["pluginId"]!].Add(item);
        foreach (var id in visible) plugins[id] = new { items = lists[id], nextCursor = (string?)null };
        var failures = new Dictionary<string, object>();
        foreach (var id in hidden)
            failures[id] = existing.Contains(id)
                ? new { status = 403, error = "forbidden", message = "Missing viewer access for plugin." }
                : new { status = 404, error = "plugin_not_found", message = "Plugin not found." };
        return new { plugins, failures };
    }

    // ---------- marketplaces ----------

    public async Task<Marketplace> CreateMarketplaceAsync(Actor a, string name, string? description, string? logoUrl, string? externalKey = null)
    {
        var now = Now();
        var row = new Marketplace { Id = Ids.New("mkt"), OrganizationId = a.OrgId, ExternalKey = externalKey, Name = name, Description = description, LogoUrl = logoUrl, Status = "active", CreatedByMemberId = a.MemberId, CreatedAt = now, UpdatedAt = now };
        db.Add(row);
        db.Add(NewGrant(a, GrantKinds.Marketplace, row.Id, "m:" + a.MemberId, a.MemberId, null, false, "manager", "mag", now));
        await db.SaveChangesAsync();
        return row;
    }

    public async Task<Marketplace> UpdateMarketplaceAsync(Actor a, Marketplace row, string? name, (bool Present, string? Value) description, (bool Present, string? Value) logo)
    {
        if (name is not null) row.Name = name;
        if (description.Present) row.Description = description.Value;
        if (logo.Present) row.LogoUrl = logo.Value;
        row.UpdatedAt = Now();
        await db.SaveChangesAsync();
        return row;
    }

    private async Task<int> PluginCountAsync(string marketplaceId) =>
        await db.Set<MarketplacePlugin>().AsNoTracking().CountAsync(m => m.MarketplaceId == marketplaceId && m.RemovedAt == null);

    public async Task<object> MarketplaceJsonAsync(Marketplace m) => LibraryJson.Marketplace(m, await PluginCountAsync(m.Id));

    public async Task<object> ListMarketplacesAsync(Actor a, HttpContext ctx)
    {
        var status = Zod.QueryEnum(ctx, "status", PluginStatuses);
        var q = Zod.QueryString(ctx, "q");
        var cursor = Zod.QueryString(ctx, "cursor");
        var limit = Zod.QueryInt(ctx, "limit", 1, 100);
        var rows = (await db.Set<Marketplace>().AsNoTracking().Where(m => m.OrganizationId == a.OrgId).ToListAsync()).OrderByDescending(m => m.UpdatedAt).ThenByDescending(m => m.Id, StringComparer.Ordinal).ToList();
        var roles = await lib.MarketplaceRolesAsync(a.Aud, rows.Select(r => r.Id).ToList());
        var counts = (await db.Set<MarketplacePlugin>().AsNoTracking().Where(m => m.OrganizationId == a.OrgId && m.RemovedAt == null).GroupBy(m => m.MarketplaceId).Select(g => new { g.Key, N = g.Count() }).ToListAsync()).ToDictionary(x => x.Key, x => x.N);
        var items = rows.Where(r => roles.ContainsKey(r.Id) && (status is null || r.Status == status)
                && (q is null || $"{r.Name}\n{r.Description ?? ""}".Contains(q, StringComparison.OrdinalIgnoreCase)))
            .Select(r => LibraryJson.Marketplace(r, counts.GetValueOrDefault(r.Id))).ToList();
        return PageById(items, cursor, limit);
    }

    public async Task<Marketplace> SetMarketplaceLifecycleAsync(Actor a, string id, string action)
    {
        var row = await lib.MarketplaceAsync(a, id, LibRole.Manager);
        var now = Now();
        if (action == "delete")
        {
            var memberships = await db.Set<MarketplacePlugin>().Where(m => m.MarketplaceId == id).ToListAsync();
            if (memberships.Any(m => m.RemovedAt == null && m.MembershipSource is "system" or "connector"))
                throw new LibraryFailure(409, "managed_marketplace_cannot_be_deleted", "Built-in and connected marketplaces cannot be deleted here.");
            db.RemoveRange(await db.Set<LibraryGrant>().Where(g => g.ResourceKind == GrantKinds.Marketplace && g.ResourceId == id).ToListAsync());
            db.RemoveRange(memberships);
            db.Remove(row);
            await db.SaveChangesAsync();
            row.DeletedAt = now; row.Status = "deleted"; row.UpdatedAt = now;
            return row;
        }
        row.DeletedAt = action == "restore" ? null : row.DeletedAt;
        row.Status = action == "archive" ? "archived" : "active";
        row.UpdatedAt = now;
        await db.SaveChangesAsync();
        return row;
    }

    public async Task<MarketplacePlugin> AttachPluginToMarketplaceAsync(Actor a, string marketplaceId, string pluginId, string? source)
    {
        await lib.PluginAsync(a, pluginId, LibRole.Viewer);
        await lib.MarketplaceAsync(a, marketplaceId, LibRole.Editor);
        var existing = await db.Set<MarketplacePlugin>().FirstOrDefaultAsync(m => m.MarketplaceId == marketplaceId && m.PluginId == pluginId);
        if (existing is not null)
        {
            existing.MembershipSource = source ?? existing.MembershipSource;
            existing.RemovedAt = null;
            await db.SaveChangesAsync();
            return existing;
        }
        var row = new MarketplacePlugin { Id = Ids.New("mkp"), OrganizationId = a.OrgId, MarketplaceId = marketplaceId, PluginId = pluginId, MembershipSource = source ?? "manual", CreatedByMemberId = a.MemberId, CreatedAt = Now() };
        db.Add(row);
        try { await db.SaveChangesAsync(); }
        catch (DbUpdateException)
        {
            db.Entry(row).State = EntityState.Detached;
            var winner = await db.Set<MarketplacePlugin>().FirstAsync(m => m.MarketplaceId == marketplaceId && m.PluginId == pluginId);
            winner.RemovedAt = null;
            await db.SaveChangesAsync();
            return winner;
        }
        return row;
    }

    public async Task DetachPluginFromMarketplaceAsync(Actor a, string marketplaceId, string pluginId)
    {
        await lib.PluginAsync(a, pluginId, LibRole.Viewer);
        await lib.MarketplaceAsync(a, marketplaceId, LibRole.Editor);
        var row = await db.Set<MarketplacePlugin>().FirstOrDefaultAsync(m => m.MarketplaceId == marketplaceId && m.PluginId == pluginId && m.RemovedAt == null)
            ?? throw new LibraryFailure(404, "marketplace_membership_not_found", "Marketplace membership not found.");
        row.RemovedAt = Now();
        await db.SaveChangesAsync();
    }

    public async Task<object> MarketplaceMembershipsAsync(Actor a, string marketplaceId)
    {
        await lib.MarketplaceAsync(a, marketplaceId, LibRole.Viewer);
        var memberships = (await db.Set<MarketplacePlugin>().AsNoTracking().Where(m => m.MarketplaceId == marketplaceId).ToListAsync()).OrderByDescending(m => m.CreatedAt).ToList();
        var ids = memberships.Select(m => m.PluginId).ToList();
        var plugins = (await db.Set<Plugin>().AsNoTracking().Where(p => ids.Contains(p.Id)).ToListAsync()).ToDictionary(p => p.Id, p => (object)LibraryJson.Plugin(p));
        return new { items = memberships.Select(m => LibraryJson.MarketplaceMembership(m, plugins.GetValueOrDefault(m.PluginId))).ToList(), nextCursor = (string?)null };
    }

    public async Task<object> MarketplaceResolvedAsync(Actor a, string marketplaceId)
    {
        var row = await lib.MarketplaceAsync(a, marketplaceId, LibRole.Viewer);
        var memberships = (await db.Set<MarketplacePlugin>().AsNoTracking().Where(m => m.MarketplaceId == row.Id && m.RemovedAt == null).ToListAsync()).OrderByDescending(m => m.CreatedAt).ToList();
        var pluginIds = memberships.Select(m => m.PluginId).ToList();
        var plugins = await db.Set<Plugin>().AsNoTracking().Where(p => pluginIds.Contains(p.Id)).ToListAsync();
        var typeCounts = (await (from m in db.Set<PluginConfigObject>().AsNoTracking()
                                 join o in db.Set<ConfigObject>().AsNoTracking() on m.ConfigObjectId equals o.Id
                                 where pluginIds.Contains(m.PluginId) && m.RemovedAt == null
                                 select new { m.PluginId, o.ObjectType }).ToListAsync()).GroupBy(x => x.PluginId).ToDictionary(g => g.Key, g => g.GroupBy(x => x.ObjectType).ToDictionary(t => t.Key, t => t.Count()));
        var ready = await readiness.ForPluginsAsync(a.Context, a.Aud, plugins.Select(p => p.Id).ToList());
        var items = plugins.Select(p =>
        {
            var counts = typeCounts.GetValueOrDefault(p.Id) ?? new Dictionary<string, int>();
            var d = LibraryJson.Plugin(p, counts.Values.Sum(), [], counts);
            d["componentCounts"] = counts;
            if (ready.TryGetValue(p.Id, out var r)) d["cloudReadiness"] = r.ToJson();
            return d;
        }).ToList();
        var market = LibraryJson.Marketplace(row, items.Count);
        market["canDelete"] = memberships.All(m => m.MembershipSource == "manual");
        return new { marketplace = market, plugins = items, source = (object?)null };
    }

    // ---------- access grants ----------

    public static LibraryGrant NewGrant(Actor a, string kind, string resourceId, string subject, string? memberId, string? teamId, bool orgWide, string role, string prefix, DateTime now) => new()
    {
        Id = Ids.New(prefix), OrganizationId = a.OrgId, ResourceKind = kind, ResourceId = resourceId, SubjectKey = subject, MemberId = memberId, TeamId = teamId, OrgWide = orgWide,
        Role = role, CreatedByMemberId = a.MemberId, CreatedAt = now,
    };

    private static string Prefix(string kind) => kind switch { GrantKinds.Plugin => "pag", GrantKinds.Marketplace => "mag", _ => "coa" };
    private static string NotFoundError(string kind) => kind switch { GrantKinds.Plugin => "plugin_not_found", GrantKinds.Marketplace => "marketplace_not_found", _ => "config_object_not_found" };
    private static string Label(string kind) => kind switch { GrantKinds.Plugin => "Plugin", GrantKinds.Marketplace => "Marketplace", _ => "Config object" };

    /// <summary>Makes sure the thing is in this workspace (404 otherwise) before anything about its access is decided, then needs manager access.</summary>
    private async Task RequireManagerAsync(Actor a, string kind, string id)
    {
        bool exists = kind switch
        {
            GrantKinds.Plugin => await db.Set<Plugin>().AnyAsync(p => p.OrganizationId == a.OrgId && p.Id == id),
            GrantKinds.Marketplace => await db.Set<Marketplace>().AnyAsync(p => p.OrganizationId == a.OrgId && p.Id == id),
            _ => await db.Set<ConfigObject>().AnyAsync(p => p.OrganizationId == a.OrgId && p.Id == id),
        };
        if (!exists) throw new LibraryFailure(404, NotFoundError(kind), $"{Label(kind)} not found.");
        var role = kind switch
        {
            GrantKinds.Plugin => await lib.PluginRoleAsync(a, id),
            GrantKinds.Marketplace => await lib.MarketplaceRoleAsync(a, id),
            _ => await lib.ConfigObjectRoleAsync(a, id),
        };
        if (role is not LibRole.Manager) throw new LibraryForbidden($"Missing manager access for {Label(kind).ToLowerInvariant()}.");
    }

    public async Task<object> ListGrantsAsync(Actor a, string kind, string id)
    {
        await RequireManagerAsync(a, kind, id);
        var rows = (await db.Set<LibraryGrant>().AsNoTracking().Where(g => g.ResourceKind == kind && g.ResourceId == id).ToListAsync()).OrderByDescending(g => g.CreatedAt).ToList();
        return new { items = rows.Select(LibraryJson.Grant).ToList(), nextCursor = (string?)null };
    }

    public async Task<LibraryGrant> GrantAsync(Actor a, string kind, string id, string? memberId, string? teamId, bool orgWide, string role)
    {
        await RequireManagerAsync(a, kind, id);
        if (orgWide && !a.Has("sharing.share_org_wide")) throw new LibraryForbidden("Only organization owners and admins can grant org-wide access.");
        if (memberId is not null && !await db.Members.AnyAsync(m => m.OrganizationId == a.OrgId && m.Id == memberId)) throw new LibraryFailure(404, "member_not_found", "Member not found.");
        if (teamId is not null && !await db.Teams.AnyAsync(t => t.OrganizationId == a.OrgId && t.Id == teamId)) throw new LibraryFailure(404, "team_not_found", "Team not found.");
        var subject = memberId is not null ? "m:" + memberId : teamId is not null ? "t:" + teamId : "org";
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var existing = await db.Set<LibraryGrant>().FirstOrDefaultAsync(g => g.ResourceKind == kind && g.ResourceId == id && g.SubjectKey == subject);
            if (existing is not null)
            {
                existing.CreatedByMemberId = a.MemberId;
                existing.Role = role;
                existing.RemovedAt = null;
                await db.SaveChangesAsync();
                return existing;
            }
            var row = NewGrant(a, kind, id, subject, memberId, teamId, orgWide, role, Prefix(kind), Now());
            db.Add(row);
            try { await db.SaveChangesAsync(); return row; }
            catch (DbUpdateException) { db.Entry(row).State = EntityState.Detached; }   // someone shared it at the same moment: update theirs
        }
        throw new LibraryFailure(409, "conflict", "Could not save the access grant. Try again.");
    }

    public async Task RevokeGrantAsync(Actor a, string kind, string id, string grantId)
    {
        await RequireManagerAsync(a, kind, id);
        var row = await db.Set<LibraryGrant>().FirstOrDefaultAsync(g => g.Id == grantId && g.ResourceKind == kind && g.ResourceId == id)
            ?? throw new LibraryFailure(404, "access_grant_not_found", "Access grant not found.");
        row.RemovedAt = Now();
        await db.SaveChangesAsync();
    }
}
