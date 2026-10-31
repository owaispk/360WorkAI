using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Library;

namespace WorkAI360.Api.Features.Library;

/// <summary>An answer the library gives instead of a result: the reference's <c>{error, message}</c> with a status.</summary>
public sealed class LibraryFailure(int status, string error, string message) : Exception(message)
{
    public int Status { get; } = status;
    public string Error { get; } = error;
}

/// <summary>The reference's 403 for library actions: <c>{error, reason?, message}</c> (not the permission-key shape).</summary>
public sealed class LibraryForbidden(string message) : Exception(message);

/// <summary>A request that does not match the schema; answered as the reference's zod <c>invalid_request</c>.</summary>
public sealed class Invalid(IReadOnlyList<(string[] Path, string Code, string Message)> issues) : Exception(issues[0].Message)
{
    public IReadOnlyList<(string[] Path, string Code, string Message)> Issues { get; } = issues;
    public Invalid(string path, string message, string code = "invalid_type") : this([(path.Length == 0 ? [] : path.Split('.'), code, message)]) { }

    public IResult ToResult()
    {
        var first = Issues[0];
        var field = string.Join('.', first.Path);
        var message = (field.Length > 0 ? $"{field}: " : "") + first.Message + (Issues.Count > 1 ? $" (and {Issues.Count - 1} more)" : "");
        return Results.Json(new { error = "invalid_request", message, details = Issues.Select(i => new { code = i.Code, path = i.Path, message = i.Message }) }, statusCode: 400);
    }
}

public enum LibRole { Viewer = 1, Editor = 2, Manager = 3 }

public static class RoleNames
{
    public static string Name(LibRole role) => role.ToString().ToLowerInvariant();
    public static LibRole? Parse(string value) => value switch { "viewer" => LibRole.Viewer, "editor" => LibRole.Editor, "manager" => LibRole.Manager, _ => null };
}

/// <summary>Whose access is being worked out: a person (or, for "what can this team see", just a team) in one workspace.</summary>
public sealed record Audience(string OrgId, string MemberId, HashSet<string> TeamIds, bool ManageAll);

/// <summary>Who is asking, in which workspace, with which teams.</summary>
public sealed record Actor(OrgContext Context, HashSet<string> TeamIds)
{
    public Audience Aud => new(OrgId, MemberId, TeamIds, ManageAll);
    public string OrgId => Context.Organization.Id;
    public string MemberId => Context.Member.Id;
    /// <summary>Holders of "Manage everything shared" act as manager on every plugin, marketplace and skill.</summary>
    public bool ManageAll => Context.Permissions.Has("sharing.manage_all");
    public bool Has(string permission) => Context.Permissions.Has(permission);
}

/// <summary>
/// The access rules for plugins, marketplaces and config objects (ported from the reference). A person's role on a thing is the
/// highest of: manager if they hold "Manage everything shared"; manager if they created the plugin; any grant to them, their team or
/// everyone. Failing those, a plugin is viewable through a marketplace that holds it and is shared with them, and a skill through a
/// plugin that holds it and that they created or were given. Nothing else: being an admin shows nothing by itself.
/// </summary>
public sealed class LibraryAccess(DenDbContext db)
{
    public async Task<Actor> ActorAsync(OrgContext context)
    {
        var teamIds = await (from tm in db.TeamMembers.AsNoTracking()
                             join t in db.Teams.AsNoTracking() on tm.TeamId equals t.Id
                             where tm.MemberId == context.Member.Id && t.OrganizationId == context.Organization.Id
                             select tm.TeamId).ToListAsync();
        return new Actor(context, teamIds.ToHashSet());
    }

    private static bool Applies(LibraryGrant g, Audience a) =>
        g.RemovedAt is null && (g.OrgWide || g.MemberId == a.MemberId || (g.TeamId is not null && a.TeamIds.Contains(g.TeamId)));

    private static LibRole? Best(IEnumerable<LibraryGrant> grants, Audience a)
    {
        LibRole? best = null;
        foreach (var g in grants)
        {
            if (!Applies(g, a)) continue;
            var role = RoleNames.Parse(g.Role)!.Value;
            if (best is null || role > best) best = role;
        }
        return best;
    }

    private async Task<ILookup<string, LibraryGrant>> GrantsAsync(Audience a, string kind, IReadOnlyCollection<string> ids) =>
        (await db.Set<LibraryGrant>().AsNoTracking().Where(g => g.OrganizationId == a.OrgId && g.ResourceKind == kind && ids.Contains(g.ResourceId)).ToListAsync())
        .ToLookup(g => g.ResourceId);

    /// <summary>Roles on plugins of this workspace; ids that do not exist here (or are not reachable) are absent.</summary>
    public async Task<Dictionary<string, LibRole>> PluginRolesAsync(Audience a, IReadOnlyCollection<string> ids)
    {
        var result = new Dictionary<string, LibRole>();
        if (ids.Count == 0) return result;
        var plugins = await db.Set<Plugin>().AsNoTracking().Where(p => p.OrganizationId == a.OrgId && ids.Contains(p.Id)).Select(p => new { p.Id, p.CreatedByMemberId }).ToListAsync();
        if (plugins.Count == 0) return result;
        if (a.ManageAll)
        {
            foreach (var p in plugins) result[p.Id] = LibRole.Manager;
            return result;
        }
        var grants = await GrantsAsync(a, GrantKinds.Plugin, plugins.Select(p => p.Id).ToList());
        var unresolved = new List<string>();
        foreach (var p in plugins)
        {
            if (p.CreatedByMemberId == a.MemberId) { result[p.Id] = LibRole.Manager; continue; }
            if (Best(grants[p.Id], a) is { } role) result[p.Id] = role; else unresolved.Add(p.Id);
        }
        if (unresolved.Count == 0) return result;

        var memberships = await db.Set<MarketplacePlugin>().AsNoTracking().Where(m => m.OrganizationId == a.OrgId && unresolved.Contains(m.PluginId) && m.RemovedAt == null)
            .Select(m => new { m.MarketplaceId, m.PluginId }).ToListAsync();
        if (memberships.Count == 0) return result;
        var marketplaceIds = memberships.Select(m => m.MarketplaceId).Distinct().ToList();
        var inOrg = await db.Set<Marketplace>().AsNoTracking().Where(m => m.OrganizationId == a.OrgId && marketplaceIds.Contains(m.Id)).Select(m => m.Id).ToListAsync();
        var marketGrants = await GrantsAsync(a, GrantKinds.Marketplace, inOrg);
        var visible = inOrg.Where(id => Best(marketGrants[id], a) is not null).ToHashSet();
        foreach (var m in memberships) if (visible.Contains(m.MarketplaceId)) result[m.PluginId] = LibRole.Viewer;
        return result;
    }

    public async Task<Dictionary<string, LibRole>> MarketplaceRolesAsync(Audience a, IReadOnlyCollection<string> ids)
    {
        var result = new Dictionary<string, LibRole>();
        if (ids.Count == 0) return result;
        var inOrg = await db.Set<Marketplace>().AsNoTracking().Where(m => m.OrganizationId == a.OrgId && ids.Contains(m.Id)).Select(m => m.Id).ToListAsync();
        if (inOrg.Count == 0) return result;
        if (a.ManageAll) { foreach (var id in inOrg) result[id] = LibRole.Manager; return result; }
        var grants = await GrantsAsync(a, GrantKinds.Marketplace, inOrg);
        foreach (var id in inOrg) if (Best(grants[id], a) is { } role) result[id] = role;
        return result;
    }

    public async Task<Dictionary<string, LibRole>> ConfigObjectRolesAsync(Audience a, IReadOnlyCollection<string> ids)
    {
        var result = new Dictionary<string, LibRole>();
        if (ids.Count == 0) return result;
        var inOrg = await db.Set<ConfigObject>().AsNoTracking().Where(o => o.OrganizationId == a.OrgId && ids.Contains(o.Id)).Select(o => o.Id).ToListAsync();
        if (inOrg.Count == 0) return result;
        if (a.ManageAll) { foreach (var id in inOrg) result[id] = LibRole.Manager; return result; }
        var grants = await GrantsAsync(a, GrantKinds.ConfigObject, inOrg);
        var unresolved = new List<string>();
        foreach (var id in inOrg) if (Best(grants[id], a) is { } role) result[id] = role; else unresolved.Add(id);
        if (unresolved.Count == 0) return result;

        // A skill with no grant of its own is visible through a plugin that holds it, when the person made or was given that plugin.
        // Marketplace access alone does not count.
        var memberships = await db.Set<PluginConfigObject>().AsNoTracking().Where(m => m.OrganizationId == a.OrgId && unresolved.Contains(m.ConfigObjectId) && m.RemovedAt == null)
            .Select(m => new { m.ConfigObjectId, m.PluginId }).ToListAsync();
        if (memberships.Count == 0) return result;
        var pluginIds = memberships.Select(m => m.PluginId).Distinct().ToList();
        var plugins = await db.Set<Plugin>().AsNoTracking().Where(p => p.OrganizationId == a.OrgId && pluginIds.Contains(p.Id)).Select(p => new { p.Id, p.CreatedByMemberId }).ToListAsync();
        var pluginGrants = await GrantsAsync(a, GrantKinds.Plugin, plugins.Select(p => p.Id).ToList());
        var reachable = plugins.Where(p => p.CreatedByMemberId == a.MemberId || Best(pluginGrants[p.Id], a) is not null).Select(p => p.Id).ToHashSet();
        foreach (var m in memberships) if (reachable.Contains(m.PluginId)) result[m.ConfigObjectId] = LibRole.Viewer;
        return result;
    }

    public async Task<LibRole?> PluginRoleAsync(Actor a, string id) => (await PluginRolesAsync(a.Aud, [id])).TryGetValue(id, out var r) ? r : null;
    public async Task<LibRole?> MarketplaceRoleAsync(Actor a, string id) => (await MarketplaceRolesAsync(a.Aud, [id])).TryGetValue(id, out var r) ? r : null;
    public async Task<LibRole?> ConfigObjectRoleAsync(Actor a, string id) => (await ConfigObjectRolesAsync(a.Aud, [id])).TryGetValue(id, out var r) ? r : null;

    private static string Missing(LibRole need, string what) => $"Missing {RoleNames.Name(need)} access for {what}.";

    public async Task<Plugin> PluginAsync(Actor a, string id, LibRole need)
    {
        var row = await db.Set<Plugin>().FirstOrDefaultAsync(p => p.OrganizationId == a.OrgId && p.Id == id) ?? throw new LibraryFailure(404, "plugin_not_found", "Plugin not found.");
        if ((await PluginRoleAsync(a, id)) is not { } role || role < need) throw new LibraryForbidden(Missing(need, "plugin"));
        return row;
    }

    public async Task<Marketplace> MarketplaceAsync(Actor a, string id, LibRole need)
    {
        var row = await db.Set<Marketplace>().FirstOrDefaultAsync(m => m.OrganizationId == a.OrgId && m.Id == id) ?? throw new LibraryFailure(404, "marketplace_not_found", "Marketplace not found.");
        if ((await MarketplaceRoleAsync(a, id)) is not { } role || role < need) throw new LibraryForbidden(Missing(need, "marketplace"));
        return row;
    }

    public async Task<ConfigObject> ConfigObjectAsync(Actor a, string id, LibRole need)
    {
        var row = await db.Set<ConfigObject>().FirstOrDefaultAsync(o => o.OrganizationId == a.OrgId && o.Id == id) ?? throw new LibraryFailure(404, "config_object_not_found", "Config object not found.");
        if ((await ConfigObjectRoleAsync(a, id)) is not { } role || role < need) throw new LibraryForbidden(Missing(need, "config object"));
        return row;
    }

    /// <summary>What the caller may do without owning anything: make a plugin or skill (anyone), make a marketplace (needs marketplaces.manage).</summary>
    public static void RequireCapability(Actor a, string capability)
    {
        if (capability == "marketplace.create" && !a.Has("marketplaces.manage")) throw new LibraryForbidden($"Missing organization capability: {capability}");
    }
}

/// <summary>Zod-style reading of request bodies, queries and ids, with the reference's messages.</summary>
public static class Zod
{
    private static readonly Regex StructuralTypeId = new(@"^([a-z]([a-z_]*[a-z])?_)?[0-7][0-9a-hjkmnp-tv-z]{25}$", RegexOptions.Compiled);
    private const string Base32 = "0123456789abcdefghjkmnpqrstvwxyz";

    public static string Kind(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.Null => "null",
        JsonValueKind.Number => "number",
        JsonValueKind.String => "string",
        JsonValueKind.Array => "array",
        JsonValueKind.Object => "object",
        JsonValueKind.Undefined => "undefined",
        _ => "boolean",
    };

    public static async Task<JsonElement> BodyAsync(HttpContext ctx)
    {
        try
        {
            using var doc = await JsonDocument.ParseAsync(ctx.Request.Body);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) throw new Invalid("", $"Invalid input: expected object, received {Kind(doc.RootElement)}");
            return doc.RootElement.Clone();
        }
        catch (JsonException) { throw new Invalid("", "Invalid input: expected object, received undefined"); }
    }

    /// <summary>A path id: <c>prefix_</c> plus 26 base32 characters, with the reference's wording when it is not.</summary>
    public static string TypeId(string value, string prefix, string field)
    {
        var size = prefix.Length + 27;
        var issues = new List<(string[] Path, string Code, string Message)>();
        string[] path = field.Split('.');
        if (value.Length < size) issues.Add((path, "too_small", $"TypeID must be {size} characters ({prefix}_<26 char suffix>)"));
        else if (value.Length > size) issues.Add((path, "too_big", $"TypeID must be {size} characters ({prefix}_<26 char suffix>)"));
        if (!value.StartsWith(prefix + "_")) issues.Add((path, "custom", $"TypeID must start with '{prefix}_'"));
        var suffix = value[(value.LastIndexOf('_') + 1)..];
        if (suffix.Any(c => !Base32.Contains(c))) issues.Add((path, "custom", "TypeID suffix contains invalid base32 characters"));
        if (!StructuralTypeId.IsMatch(value)) issues.Add((path, "custom", "TypeID is structurally invalid"));
        if (issues.Count > 0) throw new Invalid(issues);
        return value;
    }

    public static string Id(JsonElement el, string name, string prefix, string? path = null)
    {
        var s = Str(el, name, trim: false, path: path)!;
        return TypeId(s, prefix, path ?? name);
    }

    public static bool Has(JsonElement el, string name) => el.TryGetProperty(name, out _);

    /// <summary>A string field. Trimmed first, as the reference's schemas do; <paramref name="min"/> counts after trimming.</summary>
    public static string? Str(JsonElement el, string name, bool required = true, bool trim = true, int min = 1, int max = int.MaxValue, string? path = null)
    {
        var p = path ?? name;
        if (!el.TryGetProperty(name, out var v) || v.ValueKind == JsonValueKind.Undefined)
        {
            if (required) throw new Invalid(p, "Invalid input: expected string, received undefined");
            return null;
        }
        if (v.ValueKind != JsonValueKind.String) throw new Invalid(p, $"Invalid input: expected string, received {Kind(v)}");
        var s = v.GetString()!;
        if (trim) s = s.Trim();
        if (s.Length < min) throw new Invalid(p, $"Too small: expected string to have >={min} character{(min == 1 ? "" : "s")}", "too_small");
        if (s.Length > max) throw new Invalid(p, $"Too big: expected string to have <={max} characters", "too_big");
        return s;
    }

    /// <summary>A nullable string field: absent is "leave alone" (Present false), null clears, text must be non-empty after trimming.</summary>
    public static (bool Present, string? Value) NullableStr(JsonElement el, string name, int max = int.MaxValue)
    {
        if (!el.TryGetProperty(name, out var v)) return (false, null);
        if (v.ValueKind == JsonValueKind.Null) return (true, null);
        return (true, Str(el, name, max: max));
    }

    public static string Enum(JsonElement el, string name, string[] values, string? path = null, bool required = true)
    {
        var p = path ?? name;
        var raw = Str(el, name, required, trim: false, min: 0, path: p);
        if (raw is null) return "";
        if (!values.Contains(raw)) throw new Invalid(p, $"Invalid option: expected one of {string.Join("|", values.Select(v => $"\"{v}\""))}", "invalid_value");
        return raw;
    }

    public static bool? Bool(JsonElement el, string name)
    {
        if (!el.TryGetProperty(name, out var v)) return null;
        if (v.ValueKind is JsonValueKind.True or JsonValueKind.False) return v.GetBoolean();
        throw new Invalid(name, $"Invalid input: expected boolean, received {Kind(v)}");
    }

    public static List<JsonElement>? Array(JsonElement el, string name, int max = int.MaxValue)
    {
        if (!el.TryGetProperty(name, out var v)) return null;
        if (v.ValueKind != JsonValueKind.Array) throw new Invalid(name, $"Invalid input: expected array, received {Kind(v)}");
        if (v.GetArrayLength() > max) throw new Invalid(name, $"Too big: expected array to have <={max} items", "too_big");
        return v.EnumerateArray().ToList();
    }

    public static JsonElement Object(JsonElement el, string name, bool required = true)
    {
        if (!el.TryGetProperty(name, out var v))
        {
            if (required) throw new Invalid(name, "Invalid input: expected object, received undefined");
            return default;
        }
        if (v.ValueKind != JsonValueKind.Object) throw new Invalid(name, $"Invalid input: expected object, received {Kind(v)}");
        return v;
    }

    /// <summary>An optional integer query value within bounds.</summary>
    public static int? QueryInt(HttpContext ctx, string name, int min, int max)
    {
        var raw = ctx.Request.Query[name].ToString();
        if (raw.Length == 0) return null;
        if (!double.TryParse(raw, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var d) || d != Math.Floor(d))
            throw new Invalid(name, "Invalid input: expected int, received number");
        if (d < min) throw new Invalid(name, $"Too small: expected number to be >={min}", "too_small");
        if (d > max) throw new Invalid(name, $"Too big: expected number to be <={max}", "too_big");
        return (int)d;
    }

    public static string? QueryString(HttpContext ctx, string name, int max = 255)
    {
        var raw = ctx.Request.Query[name].ToString();
        if (ctx.Request.Query.ContainsKey(name) is false) return null;
        var s = raw.Trim();
        if (s.Length < 1) throw new Invalid(name, "Too small: expected string to have >=1 characters", "too_small");
        if (s.Length > max) throw new Invalid(name, $"Too big: expected string to have <={max} characters", "too_big");
        return s;
    }

    public static bool? QueryBool(HttpContext ctx, string name)
    {
        if (!ctx.Request.Query.ContainsKey(name)) return null;
        var raw = ctx.Request.Query[name].ToString();
        return raw switch { "true" => true, "false" => false, _ => throw new Invalid(name, "Invalid option: expected one of \"true\"|\"false\"", "invalid_value") };
    }

    public static string? QueryEnum(HttpContext ctx, string name, string[] values)
    {
        if (!ctx.Request.Query.ContainsKey(name)) return null;
        var raw = ctx.Request.Query[name].ToString();
        if (!values.Contains(raw)) throw new Invalid(name, $"Invalid option: expected one of {string.Join("|", values.Select(v => $"\"{v}\""))}", "invalid_value");
        return raw;
    }
}

/// <summary>Resolves the workspace and caller, runs a handler, and turns failures into the reference's answers.</summary>
public sealed class LibraryRunner(OrgAccess access, LibraryAccess lib)
{
    public async Task<IResult> RunAsync(HttpContext ctx, Func<Actor, Task<IResult>> handler)
    {
        var (context, failure) = await access.ResolveAsync(ctx);
        if (failure is not null) return failure;
        try { return await handler(await lib.ActorAsync(context!)); }
        catch (Invalid invalid) { return invalid.ToResult(); }
        catch (LibraryFailure f) { return Results.Json(new { error = f.Error, message = f.Message }, statusCode: f.Status); }
        catch (LibraryForbidden f) { return Results.Json(new { error = "forbidden", message = f.Message }, statusCode: 403); }
    }
}
