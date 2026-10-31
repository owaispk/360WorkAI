using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Library;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Features.Library;

/// <summary>
/// The library: plugins, skills (config objects), marketplaces, who may see and use them, importing from GitHub, usage, and the skills
/// agents can read through <c>/mcp/agent</c>. See docs/features/library.md.
/// </summary>
public sealed class LibraryFeature : IFeature
{
    public void AddServices(IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<LibraryOptions>(configuration.GetSection(LibraryOptions.Section));
        services.AddScoped<LibraryAccess>();
        services.AddScoped<LibraryRunner>();
        services.AddScoped<LibraryStore>();
        services.AddScoped<LibraryUsage>();
        services.AddScoped<GithubImporter>();
        services.AddHttpClient(GithubImporter.ClientName);
        services.AddScoped<ICapabilityProvider, LibraryCapabilityProvider>();
    }

    public void MapEndpoints(WebApplication app)
    {
        MapPlugins(app);
        MapConfigObjects(app);
        MapMarketplaces(app);
        MapMe(app);
        MapUsage(app);
        MapImport(app);
    }

    private static readonly Regex ExternalKey = new("^[a-z0-9][a-z0-9._-]{0,127}$", RegexOptions.Compiled);

    private static IResult Ok(object body, int status = 200) => Results.Json(body, statusCode: status);

    private static string? OptionalId(JsonElement body, string name, string prefix) => Zod.Has(body, name) ? Zod.Id(body, name, prefix) : null;

    // ---------- plugins ----------

    private static void MapPlugins(WebApplication app)
    {
        app.MapGet("/v1/plugins", (HttpContext ctx, LibraryRunner run, LibraryStore store) =>
            run.RunAsync(ctx, async a => Ok(await store.ListPluginsAsync(a, ctx))));

        app.MapPost("/v1/plugins", (HttpContext ctx, LibraryRunner run, LibraryStore store) => run.RunAsync(ctx, async a =>
        {
            var body = await Zod.BodyAsync(ctx);
            var name = Zod.Str(body, "name", max: 255)!;
            var description = Zod.NullableStr(body, "description");
            var repo = Zod.Str(body, "sourceRepositoryUrl", required: false, max: 1024);
            var components = new List<(string, ConfigInput)>();
            var raw = Zod.Array(body, "components", 100);
            for (var i = 0; raw is not null && i < raw.Count; i++)
            {
                var c = raw[i];
                if (c.ValueKind != JsonValueKind.Object) throw new Invalid($"components.{i}", $"Invalid input: expected object, received {Zod.Kind(c)}");
                var type = Zod.Enum(c, "type", LibraryStore.ObjectTypes, $"components.{i}.type");
                if (Zod.Has(c, "connection") || Zod.Has(c, "connectionId"))
                    throw new LibraryFailure(400, "connections_not_supported", "Connecting MCP servers to a plugin is not available yet. Create the plugin without a connection.");
                if (!Zod.Has(c, "input")) throw new Invalid($"components.{i}.input", "input is required unless connectionId is provided.", "custom");
                components.Add((type, LibraryStore.ReadInput(c.GetProperty("input"), $"components.{i}.input")));
            }
            var orgWide = Zod.Bool(body, "orgWide") ?? false;
            var marketplaceId = OptionalId(body, "marketplaceId", "mkt");
            var plugin = await store.CreatePluginAsync(a, name, description.Value, repo, null, null, components, orgWide, marketplaceId);
            return Ok(new { ok = true, item = await store.PluginJsonAsync(plugin) }, 201);
        }));

        app.MapGet("/v1/plugins/{pluginId}", (string pluginId, HttpContext ctx, LibraryRunner run, LibraryStore store, LibraryAccess lib) => run.RunAsync(ctx, async a =>
        {
            Zod.TypeId(pluginId, "plg", "pluginId");
            return Ok(new { item = await store.PluginJsonAsync(await lib.PluginAsync(a, pluginId, LibRole.Viewer)) });
        }));

        app.MapPatch("/v1/plugins/{pluginId}", (string pluginId, HttpContext ctx, LibraryRunner run, LibraryStore store) => run.RunAsync(ctx, async a =>
        {
            Zod.TypeId(pluginId, "plg", "pluginId");
            var body = await Zod.BodyAsync(ctx);
            var name = Zod.Str(body, "name", required: false, max: 255);
            var description = Zod.NullableStr(body, "description");
            if (name is null && !description.Present) throw new Invalid("name", "Provide at least one field to update.", "custom");
            return Ok(new { ok = true, item = await store.PluginJsonAsync(await store.UpdatePluginAsync(a, pluginId, (name is not null, name), description)) });
        }));

        foreach (var action in new[] { "archive", "restore" })
            app.MapPost($"/v1/plugins/{{pluginId}}/{action}", (string pluginId, HttpContext ctx, LibraryRunner run, LibraryStore store) => run.RunAsync(ctx, async a =>
            {
                Zod.TypeId(pluginId, "plg", "pluginId");
                return Ok(new { ok = true, item = await store.PluginJsonAsync(await store.SetPluginLifecycleAsync(a, pluginId, action)) });
            }));

        app.MapGet("/v1/plugins/{pluginId}/config-objects", (string pluginId, HttpContext ctx, LibraryRunner run, LibraryStore store) => run.RunAsync(ctx, async a =>
        {
            Zod.TypeId(pluginId, "plg", "pluginId");
            return Ok(await store.PluginMembershipsAsync(a, pluginId, includeConfigObjects: true, onlyActive: false, legacyWorkflowType: false));
        }));

        app.MapGet("/v1/plugins/{pluginId}/resolved", (string pluginId, HttpContext ctx, LibraryRunner run, LibraryStore store) => run.RunAsync(ctx, async a =>
        {
            Zod.TypeId(pluginId, "plg", "pluginId");
            return Ok(await store.PluginMembershipsAsync(a, pluginId, includeConfigObjects: true, onlyActive: true, legacyWorkflowType: true));
        }));

        app.MapPost("/v1/plugins/{pluginId}/config-objects", (string pluginId, HttpContext ctx, LibraryRunner run, LibraryStore store) => run.RunAsync(ctx, async a =>
        {
            Zod.TypeId(pluginId, "plg", "pluginId");
            var body = await Zod.BodyAsync(ctx);
            var configObjectId = Zod.Id(body, "configObjectId", "cob");
            var source = Zod.Has(body, "membershipSource") ? Zod.Enum(body, "membershipSource", LibraryStore.MembershipSources) : null;
            return Ok(new { ok = true, item = LibraryJson.Membership(await store.AttachAsync(a, configObjectId, pluginId, source)) }, 201);
        }));

        app.MapDelete("/v1/plugins/{pluginId}/config-objects/{configObjectId}", (string pluginId, string configObjectId, HttpContext ctx, LibraryRunner run, LibraryStore store) => run.RunAsync(ctx, async a =>
        {
            Zod.TypeId(pluginId, "plg", "pluginId");
            Zod.TypeId(configObjectId, "cob", "configObjectId");
            await store.DetachAsync(a, configObjectId, pluginId);
            return Results.NoContent();
        }));

        app.MapGet("/v1/resolved-plugins", (HttpContext ctx, LibraryRunner run, LibraryStore store) => run.RunAsync(ctx, async a =>
        {
            if (!ctx.Request.Query.ContainsKey("pluginIds")) throw new Invalid("pluginIds", "Invalid input: expected string, received undefined");
            var ids = ctx.Request.Query["pluginIds"].ToString().Split(',').Select(s => s.Trim()).Where(s => s.Length > 0).Distinct().ToList();
            if (ids.Count < 1) throw new Invalid("pluginIds", "Too small: expected array to have >=1 items", "too_small");
            if (ids.Count > 100) throw new Invalid("pluginIds", "Too big: expected array to have <=100 items", "too_big");
            foreach (var id in ids) Zod.TypeId(id, "plg", "pluginIds.0");
            return Ok(await store.ResolvedPluginsAsync(a, ids));
        }));

        MapAccess(app, "/v1/plugins/{pluginId}", "pluginId", "plg", GrantKinds.Plugin);
    }

    // ---------- config objects ----------

    private static void MapConfigObjects(WebApplication app)
    {
        app.MapGet("/v1/config-objects", (HttpContext ctx, LibraryRunner run, LibraryStore store) => run.RunAsync(ctx, async a => Ok(await store.ListConfigObjectsAsync(a, ctx))));

        app.MapPost("/v1/config-objects", (HttpContext ctx, LibraryRunner run, LibraryStore store) => run.RunAsync(ctx, async a =>
        {
            var body = await Zod.BodyAsync(ctx);
            var type = Zod.Enum(body, "type", LibraryStore.ObjectTypes);
            var sourceMode = Zod.Enum(body, "sourceMode", LibraryStore.SourceModes);
            var pluginIds = new List<string>();
            var raw = Zod.Array(body, "pluginIds", 100);
            for (var i = 0; raw is not null && i < raw.Count; i++)
            {
                if (raw[i].ValueKind != JsonValueKind.String) throw new Invalid($"pluginIds.{i}", $"Invalid input: expected string, received {Zod.Kind(raw[i])}");
                pluginIds.Add(Zod.TypeId(raw[i].GetString()!, "plg", $"pluginIds.{i}"));
            }
            var input = LibraryStore.ReadInput(Zod.Object(body, "input"));
            var created = await store.CreateConfigObjectAsync(a, type, sourceMode, pluginIds, input);
            return Ok(new { ok = true, item = await store.ConfigObjectJsonAsync(created) }, 201);
        }));

        app.MapGet("/v1/config-objects/{configObjectId}", (string configObjectId, HttpContext ctx, LibraryRunner run, LibraryStore store, LibraryAccess lib) => run.RunAsync(ctx, async a =>
        {
            Zod.TypeId(configObjectId, "cob", "configObjectId");
            return Ok(new { item = await store.ConfigObjectJsonAsync(await lib.ConfigObjectAsync(a, configObjectId, LibRole.Viewer)) });
        }));

        foreach (var action in new[] { "archive", "delete", "restore" })
            app.MapPost($"/v1/config-objects/{{configObjectId}}/{action}", (string configObjectId, HttpContext ctx, LibraryRunner run, LibraryStore store) => run.RunAsync(ctx, async a =>
            {
                Zod.TypeId(configObjectId, "cob", "configObjectId");
                return Ok(new { ok = true, item = await store.ConfigObjectJsonAsync(await store.SetConfigObjectLifecycleAsync(a, configObjectId, action)) });
            }));

        app.MapGet("/v1/config-objects/{configObjectId}/versions", (string configObjectId, HttpContext ctx, LibraryRunner run, LibraryAccess lib, DenDbContext db) => run.RunAsync(ctx, async a =>
        {
            Zod.TypeId(configObjectId, "cob", "configObjectId");
            var cursor = Zod.QueryString(ctx, "cursor");
            var limit = Zod.QueryInt(ctx, "limit", 1, 100);
            var includeDeleted = Zod.QueryBool(ctx, "includeDeleted") ?? false;
            var row = await lib.ConfigObjectAsync(a, configObjectId, LibRole.Viewer);
            var versions = (await db.Set<ConfigObjectVersion>().AsNoTracking().Where(v => v.ConfigObjectId == row.Id).ToListAsync())
                .OrderByDescending(v => v.CreatedAt).ThenByDescending(v => v.Id, StringComparer.Ordinal).Where(v => includeDeleted || !v.IsDeletedVersion)
                .Select(LibraryJson.Version).ToList();
            return Ok(LibraryStore.PageById(versions, cursor, limit));
        }));

        // Registered as a literal so "latest" is not read as a version id.
        app.MapGet("/v1/config-objects/{configObjectId}/versions/latest", (string configObjectId, HttpContext ctx, LibraryRunner run, LibraryAccess lib, DenDbContext db) => run.RunAsync(ctx, async a =>
        {
            Zod.TypeId(configObjectId, "cob", "configObjectId");
            await lib.ConfigObjectAsync(a, configObjectId, LibRole.Viewer);
            var latest = (await db.Set<ConfigObjectVersion>().AsNoTracking().Where(v => v.ConfigObjectId == configObjectId).ToListAsync())
                .OrderByDescending(v => v.CreatedAt).ThenByDescending(v => v.Id, StringComparer.Ordinal).FirstOrDefault()
                ?? throw new LibraryFailure(404, "config_object_version_not_found", "Config object version not found.");
            return Ok(new { item = LibraryJson.Version(latest) });
        }));

        app.MapGet("/v1/config-objects/{configObjectId}/versions/{versionId}", (string configObjectId, string versionId, HttpContext ctx, LibraryRunner run, LibraryAccess lib, DenDbContext db) => run.RunAsync(ctx, async a =>
        {
            Zod.TypeId(configObjectId, "cob", "configObjectId");
            Zod.TypeId(versionId, "cov", "versionId");
            await lib.ConfigObjectAsync(a, configObjectId, LibRole.Viewer);
            var version = await db.Set<ConfigObjectVersion>().AsNoTracking().FirstOrDefaultAsync(v => v.Id == versionId && v.ConfigObjectId == configObjectId)
                ?? throw new LibraryFailure(404, "config_object_version_not_found", "Config object version not found.");
            return Ok(new { item = LibraryJson.Version(version) });
        }));

        app.MapPost("/v1/config-objects/{configObjectId}/versions", (string configObjectId, HttpContext ctx, LibraryRunner run, LibraryStore store) => run.RunAsync(ctx, async a =>
        {
            Zod.TypeId(configObjectId, "cob", "configObjectId");
            var body = await Zod.BodyAsync(ctx);
            var input = LibraryStore.ReadInput(Zod.Object(body, "input"));
            var reason = Zod.Str(body, "reason", required: false, max: 255);
            return Ok(new { ok = true, item = await store.ConfigObjectJsonAsync(await store.CreateVersionAsync(a, configObjectId, input, reason)) }, 201);
        }));

        app.MapGet("/v1/config-objects/{configObjectId}/plugins", (string configObjectId, HttpContext ctx, LibraryRunner run, LibraryStore store, LibraryAccess lib, DenDbContext db) => run.RunAsync(ctx, async a =>
        {
            Zod.TypeId(configObjectId, "cob", "configObjectId");
            var row = await lib.ConfigObjectAsync(a, configObjectId, LibRole.Viewer);
            var json = await store.ConfigObjectJsonAsync(row);
            var memberships = (await db.Set<PluginConfigObject>().AsNoTracking().Where(m => m.ConfigObjectId == row.Id).ToListAsync()).OrderByDescending(m => m.CreatedAt).ToList();
            var roles = await lib.PluginRolesAsync(a.Aud, memberships.Select(m => m.PluginId).ToList());
            return Ok(new { items = memberships.Where(m => roles.ContainsKey(m.PluginId)).Select(m => LibraryJson.Membership(m, json)).ToList(), nextCursor = (string?)null });
        }));

        app.MapPost("/v1/config-objects/{configObjectId}/plugins", (string configObjectId, HttpContext ctx, LibraryRunner run, LibraryStore store) => run.RunAsync(ctx, async a =>
        {
            Zod.TypeId(configObjectId, "cob", "configObjectId");
            var body = await Zod.BodyAsync(ctx);
            var pluginId = Zod.Id(body, "pluginId", "plg");
            var source = Zod.Has(body, "membershipSource") ? Zod.Enum(body, "membershipSource", LibraryStore.MembershipSources) : null;
            return Ok(new { ok = true, item = LibraryJson.Membership(await store.AttachAsync(a, configObjectId, pluginId, source)) }, 201);
        }));

        app.MapDelete("/v1/config-objects/{configObjectId}/plugins/{pluginId}", (string configObjectId, string pluginId, HttpContext ctx, LibraryRunner run, LibraryStore store) => run.RunAsync(ctx, async a =>
        {
            Zod.TypeId(configObjectId, "cob", "configObjectId");
            Zod.TypeId(pluginId, "plg", "pluginId");
            await store.DetachAsync(a, configObjectId, pluginId);
            return Results.NoContent();
        }));

        MapAccess(app, "/v1/config-objects/{configObjectId}", "configObjectId", "cob", GrantKinds.ConfigObject);
    }

    // ---------- shared access routes ----------

    private static void MapAccess(WebApplication app, string basePath, string idName, string idPrefix, string kind)
    {
        var grantPrefix = kind switch { GrantKinds.Plugin => "pag", GrantKinds.Marketplace => "mag", _ => "coa" };
        app.MapGet(basePath + "/access", (HttpContext ctx, LibraryRunner run, LibraryStore store) => run.RunAsync(ctx, async a =>
        {
            var id = Zod.TypeId((string)ctx.Request.RouteValues[idName]!, idPrefix, idName);
            return Ok(await store.ListGrantsAsync(a, kind, id));
        }));

        app.MapPost(basePath + "/access", (HttpContext ctx, LibraryRunner run, LibraryStore store) => run.RunAsync(ctx, async a =>
        {
            var id = Zod.TypeId((string)ctx.Request.RouteValues[idName]!, idPrefix, idName);
            var body = await Zod.BodyAsync(ctx);
            var memberId = OptionalId(body, "orgMembershipId", "om");
            var teamId = OptionalId(body, "teamId", "tem");
            var orgWide = Zod.Bool(body, "orgWide") ?? false;
            var role = Zod.Enum(body, "role", LibraryStore.Roles);
            var targets = (memberId is not null ? 1 : 0) + (teamId is not null ? 1 : 0) + (orgWide ? 1 : 0);
            if (targets != 1) throw new Invalid("orgMembershipId", "Provide exactly one of orgMembershipId, teamId, or orgWide=true.", "custom");
            return Ok(new { ok = true, item = LibraryJson.Grant(await store.GrantAsync(a, kind, id, memberId, teamId, orgWide, role)) }, 201);
        }));

        app.MapDelete(basePath + "/access/{grantId}", (HttpContext ctx, LibraryRunner run, LibraryStore store) => run.RunAsync(ctx, async a =>
        {
            var id = Zod.TypeId((string)ctx.Request.RouteValues[idName]!, idPrefix, idName);
            var grantId = Zod.TypeId((string)ctx.Request.RouteValues["grantId"]!, grantPrefix, "grantId");
            await store.RevokeGrantAsync(a, kind, id, grantId);
            return Results.NoContent();
        }));
    }

    // ---------- marketplaces ----------

    private static (bool Present, string? Value) LogoUrl(JsonElement body)
    {
        var logo = Zod.NullableStr(body, "logoUrl", 1024);
        if (logo.Value is { } v && !(v.StartsWith('/') ? !v.StartsWith("//") : Regex.IsMatch(v, "^https://", RegexOptions.IgnoreCase)))
            throw new Invalid("logoUrl", "Logo URL must be an https:// URL or a root-relative path.", "custom");
        return logo;
    }

    private static void MapMarketplaces(WebApplication app)
    {
        app.MapGet("/v1/marketplaces", (HttpContext ctx, LibraryRunner run, LibraryStore store) => run.RunAsync(ctx, async a => Ok(await store.ListMarketplacesAsync(a, ctx))));

        app.MapPost("/v1/marketplaces", (HttpContext ctx, LibraryRunner run, LibraryStore store) => run.RunAsync(ctx, async a =>
        {
            var body = await Zod.BodyAsync(ctx);
            var name = Zod.Str(body, "name", max: 255)!;
            var description = Zod.NullableStr(body, "description");
            var logo = LogoUrl(body);
            LibraryAccess.RequireCapability(a, "marketplace.create");
            var row = await store.CreateMarketplaceAsync(a, name, description.Value, logo.Value);
            return Ok(new { ok = true, item = await store.MarketplaceJsonAsync(row) }, 201);
        }));

        app.MapGet("/v1/marketplaces/{marketplaceId}", (string marketplaceId, HttpContext ctx, LibraryRunner run, LibraryStore store, LibraryAccess lib) => run.RunAsync(ctx, async a =>
        {
            Zod.TypeId(marketplaceId, "mkt", "marketplaceId");
            return Ok(new { item = await store.MarketplaceJsonAsync(await lib.MarketplaceAsync(a, marketplaceId, LibRole.Viewer)) });
        }));

        app.MapPatch("/v1/marketplaces/{marketplaceId}", (string marketplaceId, HttpContext ctx, LibraryRunner run, LibraryStore store, LibraryAccess lib) => run.RunAsync(ctx, async a =>
        {
            Zod.TypeId(marketplaceId, "mkt", "marketplaceId");
            var body = await Zod.BodyAsync(ctx);
            var name = Zod.Str(body, "name", required: false, max: 255);
            var description = Zod.NullableStr(body, "description");
            var logo = LogoUrl(body);
            if (name is null && !description.Present && !logo.Present) throw new Invalid("name", "Provide at least one field to update.", "custom");
            var row = await lib.MarketplaceAsync(a, marketplaceId, LibRole.Editor);
            return Ok(new { ok = true, item = await store.MarketplaceJsonAsync(await store.UpdateMarketplaceAsync(a, row, name, description, logo)) });
        }));

        foreach (var action in new[] { "archive", "delete", "restore" })
            app.MapPost($"/v1/marketplaces/{{marketplaceId}}/{action}", (string marketplaceId, HttpContext ctx, LibraryRunner run, LibraryStore store) => run.RunAsync(ctx, async a =>
            {
                Zod.TypeId(marketplaceId, "mkt", "marketplaceId");
                var row = await store.SetMarketplaceLifecycleAsync(a, marketplaceId, action);
                return Ok(new { ok = true, item = action == "delete" ? LibraryJson.Marketplace(row, 0) : await store.MarketplaceJsonAsync(row) });
            }));

        app.MapGet("/v1/marketplaces/{marketplaceId}/plugins", (string marketplaceId, HttpContext ctx, LibraryRunner run, LibraryStore store) => run.RunAsync(ctx, async a =>
        {
            Zod.TypeId(marketplaceId, "mkt", "marketplaceId");
            return Ok(await store.MarketplaceMembershipsAsync(a, marketplaceId));
        }));

        app.MapGet("/v1/marketplaces/{marketplaceId}/resolved", (string marketplaceId, HttpContext ctx, LibraryRunner run, LibraryStore store) => run.RunAsync(ctx, async a =>
        {
            Zod.TypeId(marketplaceId, "mkt", "marketplaceId");
            return Ok(new { ok = true, item = await store.MarketplaceResolvedAsync(a, marketplaceId) });
        }));

        app.MapPost("/v1/marketplaces/{marketplaceId}/plugins", (string marketplaceId, HttpContext ctx, LibraryRunner run, LibraryStore store) => run.RunAsync(ctx, async a =>
        {
            Zod.TypeId(marketplaceId, "mkt", "marketplaceId");
            var body = await Zod.BodyAsync(ctx);
            var pluginId = Zod.Id(body, "pluginId", "plg");
            var source = Zod.Has(body, "membershipSource") ? Zod.Enum(body, "membershipSource", LibraryStore.MembershipSources) : null;
            return Ok(new { ok = true, item = LibraryJson.MarketplaceMembership(await store.AttachPluginToMarketplaceAsync(a, marketplaceId, pluginId, source)) }, 201);
        }));

        app.MapDelete("/v1/marketplaces/{marketplaceId}/plugins/{pluginId}", (string marketplaceId, string pluginId, HttpContext ctx, LibraryRunner run, LibraryStore store) => run.RunAsync(ctx, async a =>
        {
            Zod.TypeId(marketplaceId, "mkt", "marketplaceId");
            Zod.TypeId(pluginId, "plg", "pluginId");
            await store.DetachPluginFromMarketplaceAsync(a, marketplaceId, pluginId);
            return Results.NoContent();
        }));

        MapAccess(app, "/v1/marketplaces/{marketplaceId}", "marketplaceId", "mkt", GrantKinds.Marketplace);

        // Declarative provisioning: a marketplace known by a stable key.
        static string Key(HttpContext ctx)
        {
            var key = (string)ctx.Request.RouteValues["externalKey"]!;
            if (!ExternalKey.IsMatch(key)) throw new Invalid(new[] { (new[] { "externalKey" }, "invalid_format", "Invalid string: must match pattern /^[a-z0-9][a-z0-9._-]{0,127}$/") });
            return key;
        }

        app.MapGet("/v1/marketplaces/by-key/{externalKey}", (HttpContext ctx, LibraryRunner run, LibraryStore store, LibraryAccess lib, DenDbContext db) => run.RunAsync(ctx, async a =>
        {
            var key = Key(ctx);
            var row = await db.Set<Marketplace>().AsNoTracking().FirstOrDefaultAsync(m => m.OrganizationId == a.OrgId && m.ExternalKey == key);
            if (row is null) return Ok(new { error = "marketplace_not_found" }, 404);
            return Ok(new { item = await store.MarketplaceJsonAsync(await lib.MarketplaceAsync(a, row.Id, LibRole.Viewer)) });
        }));

        app.MapPut("/v1/marketplaces/by-key/{externalKey}", (HttpContext ctx, LibraryRunner run, LibraryStore store, LibraryAccess lib, DenDbContext db, OrgAccess access) => run.RunAsync(ctx, async a =>
        {
            var key = Key(ctx);
            var body = await Zod.BodyAsync(ctx);
            var name = Zod.Str(body, "name", max: 255)!;
            var description = Zod.NullableStr(body, "description");
            var logo = LogoUrl(body);
            if (access.Require(a.Context, "marketplaces.manage") is { } denied) return denied;
            if (!access.IsFresh(a.Context.Auth.Session)) return OrgAccess.ReauthRequired();
            if (ctx.Request.Headers.ContainsKey("If-Match") || ctx.Request.Headers.ContainsKey("If-None-Match")) return Ok(new { error = "unsupported_precondition" }, 400);

            async Task<IResult> Replace(Marketplace existing)
            {
                if (existing.Status != "active") return Ok(new { error = "marketplace_inactive", message = "Restore this marketplace before applying its configuration." }, 409);
                var row = await lib.MarketplaceAsync(a, existing.Id, LibRole.Editor);
                // Applying replaces the metadata: what is left out is cleared.
                var updated = await store.UpdateMarketplaceAsync(a, row, name, (true, description.Value), (true, logo.Value));
                return Ok(new { ok = true, item = await store.MarketplaceJsonAsync(updated) });
            }

            var found = await db.Set<Marketplace>().FirstOrDefaultAsync(m => m.OrganizationId == a.OrgId && m.ExternalKey == key);
            if (found is not null) return await Replace(found);
            LibraryAccess.RequireCapability(a, "marketplace.create");
            try
            {
                var created = await store.CreateMarketplaceAsync(a, name, description.Value, logo.Value, key);
                return Ok(new { ok = true, item = await store.MarketplaceJsonAsync(created) }, 201);
            }
            catch (DbUpdateException)
            {
                // Another request created the same key first: replace that one, as if we had come second on purpose.
                db.ChangeTracker.Clear();
                var winner = await db.Set<Marketplace>().FirstOrDefaultAsync(m => m.OrganizationId == a.OrgId && m.ExternalKey == key) ?? throw new LibraryFailure(409, "conflict", "Could not apply the marketplace. Try again.");
                return await Replace(winner);
            }
        }));

        app.MapDelete("/v1/marketplaces/by-key/{externalKey}", (HttpContext ctx, LibraryRunner run, LibraryStore store, DenDbContext db, OrgAccess access) => run.RunAsync(ctx, async a =>
        {
            var key = Key(ctx);
            if (access.Require(a.Context, "marketplaces.manage") is { } denied) return denied;
            if (!access.IsFresh(a.Context.Auth.Session)) return OrgAccess.ReauthRequired();
            var existing = await db.Set<Marketplace>().AsNoTracking().FirstOrDefaultAsync(m => m.OrganizationId == a.OrgId && m.ExternalKey == key);
            if (existing is null) return Ok(new { ok = true, deleted = false });
            await store.SetMarketplaceLifecycleAsync(a, existing.Id, "delete");
            return Ok(new { ok = true, deleted = true });
        }));
    }

    // ---------- what I can use ----------

    private static void MapMe(WebApplication app)
    {
        app.MapGet("/v1/me/plugin-access", (HttpContext ctx, LibraryRunner run, LibraryUsage usage) => run.RunAsync(ctx, async a =>
        {
            var items = await usage.EffectiveAccessAsync(a);
            return Ok(new
            {
                items = items.Select(i => new
                {
                    plugin = new { id = i.Plugin.Id, name = i.Plugin.Name, description = i.Plugin.Description, componentCount = i.ComponentCount, sourceRepositoryUrl = i.Plugin.SourceRepositoryUrl },
                    edges = i.Edges,
                    role = RoleNames.Name(i.Role),
                }).ToList(),
            });
        }));

        app.MapGet("/v1/me/library", (HttpContext ctx, LibraryRunner run, LibraryUsage usage) => run.RunAsync(ctx, async a =>
        {
            var items = await usage.EffectiveAccessAsync(a);
            return Ok(new
            {
                items = items.Select(i => new
                {
                    type = "plugin",
                    id = i.Plugin.Id,
                    name = i.Plugin.Name,
                    description = i.Plugin.Description,
                    componentCount = i.ComponentCount,
                    componentKinds = i.ComponentKinds,
                    sourceRepositoryUrl = i.Plugin.SourceRepositoryUrl,
                    edges = i.Edges,
                    role = RoleNames.Name(i.Role),
                }).ToList(),
            });
        }));

        app.MapGet("/v1/teams/{teamId}/plugin-access", (string teamId, HttpContext ctx, LibraryRunner run, LibraryUsage usage) => run.RunAsync(ctx, async a =>
        {
            Zod.TypeId(teamId, "tem", "teamId");
            return Ok(new { items = await usage.TeamAccessAsync(a, teamId) });
        }));
    }

    // ---------- usage ----------

    private static void MapUsage(WebApplication app)
    {
        app.MapGet("/v1/library-usage/{kind}", (string kind, HttpContext ctx, LibraryRunner run, LibraryUsage usage, OrgAccess access) => run.RunAsync(ctx, async a =>
        {
            if (access.Require(a.Context, "usage_analytics.view") is { } denied) return denied;
            if (!LibraryUsage.Kinds.Contains(kind)) throw new Invalid("kind", $"Invalid option: expected one of {string.Join("|", LibraryUsage.Kinds.Select(k => $"\"{k}\""))}", "invalid_value");
            var days = LibraryUsage.Days(ctx);
            return Ok(await usage.ReportAsync(a, kind, days));
        }));

        app.MapGet("/v1/library-usage", (HttpContext ctx, LibraryRunner run, LibraryUsage usage, OrgAccess access) => run.RunAsync(ctx, async a =>
        {
            if (access.Require(a.Context, "usage_analytics.view") is { } denied) return denied;
            return await usage.BreakdownAsync(a, ctx);
        }));
    }

    // ---------- GitHub import ----------

    private static void MapImport(WebApplication app)
    {
        app.MapPost("/v1/plugins/import-mcps-from-github-url/preview", (HttpContext ctx, LibraryRunner run, GithubImporter importer) => run.RunAsync(ctx, async a =>
        {
            var body = await Zod.BodyAsync(ctx);
            var url = GithubImporter.ReadUrl(body);
            return Ok(new { ok = true, item = await importer.PreviewAsync(url) });
        }));

        app.MapPost("/v1/plugins/import-mcps-from-github-url", (HttpContext ctx, LibraryRunner run, GithubImporter importer) => run.RunAsync(ctx, async a =>
        {
            var body = await Zod.BodyAsync(ctx);
            var request = GithubImporter.ReadImport(body);
            return Ok(new { ok = true, item = await importer.ImportAsync(a, request) });
        }));
    }
}

public sealed class LibraryOptions
{
    public const string Section = "Library";
    /// <summary>Where the GitHub API is read from (tests point this at a local server).</summary>
    public string GithubApiBase { get; set; } = "https://api.github.com";
    public string GithubRawBase { get; set; } = "https://raw.githubusercontent.com";
}
