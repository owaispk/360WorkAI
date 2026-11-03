using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Gateway;
using WorkAI360.Api.Features.Library;
using LibZod = WorkAI360.Api.Features.Library.Zod;

namespace WorkAI360.Api.Features.Gateway;

/// <summary>
/// The AI Gateway over LiteLLM (the reference's <c>/v1/inference-providers*</c> for LiteLLM providers, usage, and the platform dashboard's AI usage).
/// See docs/features/gateway.md.
/// </summary>
public sealed class GatewayFeature : IFeature
{
    private const string View = "gateway_providers.view";
    private const string Manage = "gateway_providers.manage";
    private const string SecureEntryMessage = "Do not send keys through the agent or an API key. Leave the key out; the person adds it in a private field in OpenWork.";

    public void AddServices(IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<GatewayOptions>(configuration.GetSection(GatewayOptions.Section));
        services.AddHttpClient(LiteLlmClients.HttpClientName).ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false, UseProxy = false })
            .ConfigureHttpClient(c => c.Timeout = Timeout.InfiniteTimeSpan);
        services.AddScoped<LiteLlmClients>();
        services.AddScoped<GatewayService>();
        services.AddScoped<GatewayUsage>();
        services.AddScoped<IMemberAccessEnded, GatewayAccessEnded>();
    }

    public void MapEndpoints(WebApplication app)
    {
        app.MapGet("/v1/inference-providers", (HttpContext ctx, OrgAccess access, GatewayService gateway, DenDbContext db) => RunAsync(ctx, access, async c =>
        {
            var scope = LibZod.QueryEnum(ctx, "scope", ["usable", "manageable"]) ?? "usable";
            var providers = await db.Set<GatewayProvider>().AsNoTracking().Where(p => p.OrganizationId == c.Organization.Id).OrderByDescending(p => p.UpdatedAt).ThenBy(p => p.Id).ToListAsync();
            var list = new JsonArray();
            if (scope == "manageable")
            {
                if (Management(access, c, gateway, write: false) is { } refused) return refused;
                foreach (var p in providers) list.Add(await gateway.DetailsAsync(p, c.Permissions.Has(Manage)));
            }
            else
            {
                var teamIds = await gateway.TeamIdsAsync(c.Member.Id);
                foreach (var p in providers.Where(p => p.Status == "active"))
                {
                    var models = await gateway.EffectiveModelsAsync(p, c.Member.Id, teamIds);
                    if (models.Count > 0) list.Add(await gateway.SummaryAsync(p, models));
                }
            }
            return Results.Json(new { inferenceProviders = list });
        }));

        app.MapGet("/v1/inference-providers/model-management", (HttpContext ctx, OrgAccess access, GatewayService gateway, DenDbContext db) => RunAsync(ctx, access, async c =>
        {
            if (Management(access, c, gateway, write: false) is { } refused) return refused;
            var providers = await db.Set<GatewayProvider>().AsNoTracking().Where(p => p.OrganizationId == c.Organization.Id).ToListAsync();
            var list = new List<object>();
            foreach (var p in providers)
            {
                var details = await gateway.DetailsAsync(p, identities: false);
                list.Add(new { id = p.Id, name = p.Name, providerId = p.ProviderId, status = p.Status, modelIds = Array.Empty<string>(), modelGroups = details["modelGroups"]!.AsArray().Select(g => new { id = (string?)g!["id"], name = (string?)g["name"], status = (string?)g["status"], modelIds = g["modelIds"] }) });
            }
            return Results.Json(new { inferenceProviders = list });
        }));

        app.MapGet("/v1/inference-providers/usage", (HttpContext ctx, OrgAccess access, GatewayService gateway, GatewayUsage usage) => RunAsync(ctx, access, async c =>
        {
            ctx.Response.Headers.CacheControl = "private, no-store";
            if (!gateway.Options.Enabled) return NotEnabled();
            Unrecognized(ctx.Request.Query.Keys, "groupBy", "days", "filterIds", "memberId");
            var groupBy = LibZod.QueryEnum(ctx, "groupBy", ["model", "team", "person"]) ?? "model";
            var daysText = ctx.Request.Query["days"].ToString();
            var days = 31;
            if (daysText.Length > 0 && (daysText.Length > 3 || !int.TryParse(daysText, out days) || days < 1 || days > 366 || daysText.StartsWith('0'))) throw new Invalid("days", "Choose between 1 and 366 days.", "invalid_value");
            var memberId = ctx.Request.Query["memberId"].ToString() is { Length: > 0 } m ? m : null;
            if (memberId is not null && !memberId.StartsWith("om_", StringComparison.Ordinal)) throw new Invalid("memberId", "memberId must be an organization member ID.", "custom");
            if (memberId is not null && groupBy == "team") throw new Invalid("memberId", "memberId cannot be combined with team grouping.", "custom");
            var filterIds = ctx.Request.Query["filterIds"].ToString().Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();
            if (filterIds.Count > 100) throw new Invalid("filterIds", "Too big: expected array to have <=100 items", "too_big");
            var prefix = groupBy switch { "person" => "om_", "team" => "tem_", _ => "ipr_" };
            if (filterIds.Any(f => !f.StartsWith(prefix, StringComparison.Ordinal))) throw new Invalid("filterIds", "Filter IDs must match the selected grouping.", "custom");
            // People may read their own usage; everyone else's needs View Gateway usage.
            if (memberId != c.Member.Id && access.Require(c, "gateway_usage.view") is { } refused) return refused;
            try { return Results.Json(await usage.WorkspaceAsync(c.Organization.Id, groupBy, days, filterIds, memberId, ctx.RequestAborted)); }
            catch (GatewayError) { return Results.Json(new { error = "gateway_usage_unavailable", message = "Gateway usage accounting is temporarily unavailable." }, statusCode: 503); }
        }));

        app.MapPost("/v1/inference-providers/litellm", (HttpContext ctx, OrgAccess access, GatewayService gateway) => RunAsync(ctx, access, async c =>
        {
            var body = await LibZod.BodyAsync(ctx);
            if (c.ApiKeyId is not null && CarriesSecret(body, "apiKey")) return SecureEntry();
            if (Management(access, c, gateway, write: true) is { } refused) return refused;
            Unrecognized(body, "name", "baseUrl", "mode", "issueStrategy", "mirrorFallback", "apiKey", "allMembers", "memberIds", "teamIds", "useDeploymentProxy");
            var name = LibZod.Str(body, "name", required: false, max: 255) ?? "LiteLLM";
            var mode = LibZod.Str(body, "mode", required: false) ?? "issued";
            if (mode is not ("org" or "member" or "issued")) throw new Invalid("mode", "Invalid option: expected one of \"org\"|\"member\"|\"issued\"", "invalid_value");
            if (mode != "issued") return Results.Json(new { error = "litellm_mode_unsupported", message = "This deployment supports mode \"issued\": OpenWork creates each allowed person's LiteLLM key." }, statusCode: 400);
            if (LibZod.Str(body, "issueStrategy", required: false) is { } strategy && strategy != "per_team")
                return Results.Json(new { error = "litellm_mode_unsupported", message = "OpenWork creates one key per person in the provider's LiteLLM team (issueStrategy \"per_team\")." }, statusCode: 400);
            var deployment = LibZod.Bool(body, "useDeploymentProxy") ?? false;
            string? root = null, apiKey = null;
            if (deployment)
            {
                if (!gateway.Options.HasDeploymentProxy) return Results.Json(new { error = "litellm_deployment_proxy_unavailable", message = "This deployment has no LiteLLM proxy. Enter your LiteLLM URL and admin key." }, statusCode: 409);
                if (body.TryGetProperty("baseUrl", out _) || body.TryGetProperty("apiKey", out _)) throw new Invalid("baseUrl", "useDeploymentProxy replaces baseUrl and apiKey.", "custom");
            }
            else
            {
                var raw = LibZod.Str(body, "baseUrl", max: 2048)!;
                apiKey = LibZod.Str(body, "apiKey", max: 4096)!;
                root = await GatewayService.CallAsync(() => Task.FromResult(LiteLlmClient.NormalizeRoot(raw)));
            }
            var audiences = Audiences(body);
            var (provider, sync) = await gateway.CreateAsync(c, name, deployment, root, apiKey, audiences, ctx.RequestAborted);
            return Results.Json(new { inferenceProvider = await gateway.DetailsAsync(provider, c.Permissions.Has(Manage)), sync = sync.ToJson() }, statusCode: 201);
        }));

        app.MapGet("/v1/inference-providers/{inferenceProviderId}", (string inferenceProviderId, HttpContext ctx, OrgAccess access, GatewayService gateway) => RunAsync(ctx, access, async c =>
        {
            if (Management(access, c, gateway, write: false) is { } refused) return refused;
            var p = await gateway.GetAsync(c.Organization.Id, inferenceProviderId);
            return Results.Json(new { inferenceProvider = await gateway.DetailsAsync(p, c.Permissions.Has(Manage)) });
        }));

        app.MapGet("/v1/inference-providers/{inferenceProviderId}/connect", (string inferenceProviderId, HttpContext ctx, OrgAccess access, GatewayService gateway) => RunAsync(ctx, access, async c =>
        {
            ctx.Response.Headers.CacheControl = "no-store";
            if (c.ApiKeyId is not null) return Results.Json(new { error = "forbidden", message = "A person's gateway key is only given to that person's own session." }, statusCode: 403);
            var p = await gateway.GetAsync(c.Organization.Id, inferenceProviderId);
            if (p.Status != "active") throw new GatewayError(404, "inference_provider_not_found");
            var models = await gateway.EffectiveModelsAsync(p, c.Member.Id);
            if (models.Count == 0) throw new GatewayError(403, "forbidden");
            var (key, _) = await gateway.EnsureKeyAsync(p, c, models, ctx.RequestAborted);
            var summary = await gateway.SummaryAsync(p, models);
            summary["apiKey"] = key;
            summary["apiKeys"] = new JsonObject { [GatewayService.EnvName] = key };
            summary["baseUrl"] = gateway.InferenceBase(p);
            return Results.Json(new { inferenceProvider = summary });
        }));

        app.MapPatch("/v1/inference-providers/{inferenceProviderId}", (string inferenceProviderId, HttpContext ctx, OrgAccess access, GatewayService gateway, DenDbContext db) => RunAsync(ctx, access, async c =>
        {
            if (Management(access, c, gateway, write: true) is { } refused) return refused;
            var body = await LibZod.BodyAsync(ctx);
            Unrecognized(body, "name", "status");
            var p = await gateway.GetAsync(c.Organization.Id, inferenceProviderId);
            if (LibZod.Str(body, "name", required: false, max: 255) is { } name) p.Name = name;
            var statusChanged = false;
            if (body.TryGetProperty("status", out _))
            {
                var status = LibZod.Enum(body, "status", ["active", "disabled"]);
                statusChanged = status != p.Status;
                p.Status = status;
            }
            p.UpdatedAt = DateTime.UtcNow;
            await db.SaveChangesAsync();
            // Disabling takes every person's key away in LiteLLM; enabling lets them be issued again on next use.
            if (statusChanged) await gateway.ReconcileAsync(p, ctx.RequestAborted);
            return Results.Json(new { inferenceProvider = await gateway.DetailsAsync(p, c.Permissions.Has(Manage)) });
        }));

        app.MapDelete("/v1/inference-providers/{inferenceProviderId}", (string inferenceProviderId, HttpContext ctx, OrgAccess access, GatewayService gateway) => RunAsync(ctx, access, async c =>
        {
            if (Management(access, c, gateway, write: true) is { } refused) return refused;
            var p = await gateway.GetAsync(c.Organization.Id, inferenceProviderId);
            await gateway.DeleteAsync(p, ctx.RequestAborted);
            return Results.NoContent();
        }));

        app.MapPost("/v1/inference-providers/{inferenceProviderId}/litellm/sync", (string inferenceProviderId, HttpContext ctx, OrgAccess access, GatewayService gateway) => RunAsync(ctx, access, async c =>
        {
            if (Management(access, c, gateway, write: true) is { } refused) return refused;
            var p = await gateway.GetAsync(c.Organization.Id, inferenceProviderId);
            var sync = await gateway.SyncAsync(p, ctx.RequestAborted);
            return Results.Json(new { inferenceProvider = await gateway.DetailsAsync(p, c.Permissions.Has(Manage)), sync = sync.ToJson() });
        }));

        app.MapPatch("/v1/inference-providers/{inferenceProviderId}/litellm", (string inferenceProviderId, HttpContext ctx, OrgAccess access, GatewayService gateway, LiteLlmClients clients, Connections.SecretBox box, DenDbContext db) => RunAsync(ctx, access, async c =>
        {
            var body = await LibZod.BodyAsync(ctx);
            if (c.ApiKeyId is not null && CarriesSecret(body, "apiKey")) return SecureEntry();
            if (Management(access, c, gateway, write: true) is { } refused) return refused;
            Unrecognized(body, "apiKey", "issueStrategy", "mirrorFallback");
            var p = await gateway.GetAsync(c.Organization.Id, inferenceProviderId);
            if (body.TryGetProperty("issueStrategy", out _) || body.TryGetProperty("mirrorFallback", out _))
                return Results.Json(new { error = "litellm_mode_unsupported", message = "OpenWork creates one key per person in the provider's LiteLLM team (issueStrategy \"per_team\")." }, statusCode: 400);
            var apiKey = LibZod.Str(body, "apiKey", max: 4096)!;
            if (p.UsesDeploymentProxy) return Results.Json(new { error = "litellm_deployment_proxy", message = "This provider uses the deployment's LiteLLM proxy; its key is set by the operator." }, statusCode: 409);
            // Prove the new key manages the same proxy before it replaces the old one.
            await GatewayService.CallAsync(async () => { var probe = clients.Workspace(p.AdminBaseUrl!, apiKey); await probe.RequireAdminAsync(ctx.RequestAborted); await probe.ListModelsAsync(ctx.RequestAborted); return true; });
            p.AdminKeyEnc = box.Encrypt(apiKey);
            p.UpdatedAt = DateTime.UtcNow;
            await db.SaveChangesAsync();
            var sync = await gateway.SyncAsync(p, ctx.RequestAborted);
            return Results.Json(new { inferenceProvider = await gateway.DetailsAsync(p, c.Permissions.Has(Manage)), sync = sync.ToJson() });
        }));

        app.MapGet("/v1/inference-providers/{inferenceProviderId}/models", (string inferenceProviderId, HttpContext ctx, OrgAccess access, GatewayService gateway, DenDbContext db) => RunAsync(ctx, access, async c =>
        {
            if (Management(access, c, gateway, write: false) is { } refused) return refused;
            var p = await gateway.GetAsync(c.Organization.Id, inferenceProviderId);
            var models = await db.Set<GatewayProviderModel>().AsNoTracking().Where(m => m.GatewayProviderId == p.Id).OrderBy(m => m.ModelId).ToListAsync();
            return Results.Json(new { models = models.Select(m => new { id = m.ModelId, name = m.Name, config = JsonNode.Parse(m.ConfigJson) }) });
        }));

        MapGroups(app);
        MapGrants(app);
    }

    private static void MapGroups(WebApplication app)
    {
        app.MapGet("/v1/inference-providers/{inferenceProviderId}/model-groups", (string inferenceProviderId, HttpContext ctx, OrgAccess access, GatewayService gateway) => RunAsync(ctx, access, async c =>
        {
            if (Management(access, c, gateway, write: false) is { } refused) return refused;
            var p = await gateway.GetAsync(c.Organization.Id, inferenceProviderId);
            return Results.Json(new { modelGroups = (await gateway.DetailsAsync(p, false))["modelGroups"] });
        }));

        app.MapPost("/v1/inference-providers/{inferenceProviderId}/model-groups", (string inferenceProviderId, HttpContext ctx, OrgAccess access, GatewayService gateway, DenDbContext db) => RunAsync(ctx, access, async c =>
        {
            if (Management(access, c, gateway, write: true) is { } refused) return refused;
            var p = await gateway.GetAsync(c.Organization.Id, inferenceProviderId);
            var body = await LibZod.BodyAsync(ctx);
            Unrecognized(body, "name", "description", "modelIds", "status");
            var now = DateTime.UtcNow;
            var group = new GatewayModelGroup { Id = Ids.New("gmg"), GatewayProviderId = p.Id, Name = LibZod.Str(body, "name", max: 255)!, Description = Description(body), Status = Status(body) ?? "active", CreatedAt = now, UpdatedAt = now };
            db.Set<GatewayModelGroup>().Add(group);
            await SetGroupModelsAsync(db, p, group, ModelIds(body, required: true)!);
            await db.SaveChangesAsync();
            await gateway.ReconcileAsync(p, ctx.RequestAborted);
            return Results.Json(new { modelGroup = GroupJson((await gateway.DetailsAsync(p, false))["modelGroups"]!, group.Id) }, statusCode: 201);
        }));

        app.MapPatch("/v1/inference-providers/{inferenceProviderId}/model-groups/{groupId}", (string inferenceProviderId, string groupId, HttpContext ctx, OrgAccess access, GatewayService gateway, DenDbContext db) => RunAsync(ctx, access, async c =>
        {
            if (Management(access, c, gateway, write: true) is { } refused) return refused;
            var p = await gateway.GetAsync(c.Organization.Id, inferenceProviderId);
            var group = await db.Set<GatewayModelGroup>().FirstOrDefaultAsync(g => g.Id == groupId && g.GatewayProviderId == p.Id) ?? throw new GatewayError(404, "model_group_not_found");
            var body = await LibZod.BodyAsync(ctx);
            Unrecognized(body, "name", "description", "modelIds", "status");
            if (LibZod.Str(body, "name", required: false, max: 255) is { } name) group.Name = name;
            if (body.TryGetProperty("description", out _)) group.Description = Description(body);
            if (Status(body) is { } status) group.Status = status;
            if (ModelIds(body, required: false) is { } ids) await SetGroupModelsAsync(db, p, group, ids);
            group.UpdatedAt = DateTime.UtcNow;
            await db.SaveChangesAsync();
            await gateway.ReconcileAsync(p, ctx.RequestAborted);
            return Results.Json(new { modelGroup = GroupJson((await gateway.DetailsAsync(p, false))["modelGroups"]!, group.Id) });
        }));

        app.MapDelete("/v1/inference-providers/{inferenceProviderId}/model-groups/{groupId}", (string inferenceProviderId, string groupId, HttpContext ctx, OrgAccess access, GatewayService gateway, DenDbContext db) => RunAsync(ctx, access, async c =>
        {
            if (Management(access, c, gateway, write: true) is { } refused) return refused;
            var p = await gateway.GetAsync(c.Organization.Id, inferenceProviderId);
            var group = await db.Set<GatewayModelGroup>().FirstOrDefaultAsync(g => g.Id == groupId && g.GatewayProviderId == p.Id) ?? throw new GatewayError(404, "model_group_not_found");
            await db.Set<GatewayAccessGrant>().Where(a => a.ModelGroupId == group.Id).ExecuteDeleteAsync();
            await db.Set<GatewayModelGroupModel>().Where(l => l.ModelGroupId == group.Id).ExecuteDeleteAsync();
            db.Set<GatewayModelGroup>().Remove(group);
            await db.SaveChangesAsync();
            await gateway.ReconcileAsync(p, ctx.RequestAborted);
            return Results.NoContent();
        }));
    }

    private static void MapGrants(WebApplication app)
    {
        app.MapGet("/v1/inference-providers/{inferenceProviderId}/access-grants", (string inferenceProviderId, HttpContext ctx, OrgAccess access, GatewayService gateway) => RunAsync(ctx, access, async c =>
        {
            if (Management(access, c, gateway, write: false) is { } refused) return refused;
            var p = await gateway.GetAsync(c.Organization.Id, inferenceProviderId);
            return Results.Json(new { accessGrants = (await gateway.DetailsAsync(p, c.Permissions.Has(Manage)))["accessGrants"] });
        }));

        app.MapPost("/v1/inference-providers/{inferenceProviderId}/access-grants", (string inferenceProviderId, HttpContext ctx, OrgAccess access, GatewayService gateway, DenDbContext db) => RunAsync(ctx, access, async c =>
        {
            if (Management(access, c, gateway, write: true) is { } refused) return refused;
            var p = await gateway.GetAsync(c.Organization.Id, inferenceProviderId);
            var body = await LibZod.BodyAsync(ctx);
            Unrecognized(body, "modelGroupId", "audience", "credentialSetId");
            var groupId = LibZod.Str(body, "modelGroupId", max: 64)!;
            if (!await db.Set<GatewayModelGroup>().AnyAsync(g => g.Id == groupId && g.GatewayProviderId == p.Id)) throw new GatewayError(404, "model_group_not_found");
            var audience = Audience(LibZod.Object(body, "audience"), "audience");
            await gateway.CheckAudiencesAsync(c.Organization.Id, [audience]);
            if (await db.Set<GatewayAccessGrant>().AnyAsync(a => a.GatewayProviderId == p.Id && a.ModelGroupId == groupId && a.AudienceKey == audience.Key)) throw new GatewayError(409, "access_grant_exists");
            var grant = gateway.NewGrant(p.Id, groupId, audience);
            db.Set<GatewayAccessGrant>().Add(grant);
            try { await db.SaveChangesAsync(); }
            catch (DbUpdateException) { throw new GatewayError(409, "access_grant_exists"); }
            await gateway.ReconcileAsync(p, ctx.RequestAborted);
            var json = (await gateway.DetailsAsync(p, c.Permissions.Has(Manage)))["accessGrants"]!.AsArray().First(g => (string?)g!["id"] == grant.Id);
            return Results.Json(new { accessGrant = json!.DeepClone() }, statusCode: 201);
        }));

        app.MapDelete("/v1/inference-providers/{inferenceProviderId}/access-grants/{grantId}", (string inferenceProviderId, string grantId, HttpContext ctx, OrgAccess access, GatewayService gateway, DenDbContext db) => RunAsync(ctx, access, async c =>
        {
            if (Management(access, c, gateway, write: true) is { } refused) return refused;
            var p = await gateway.GetAsync(c.Organization.Id, inferenceProviderId);
            var removed = await db.Set<GatewayAccessGrant>().Where(a => a.Id == grantId && a.GatewayProviderId == p.Id).ExecuteDeleteAsync();
            if (removed == 0) throw new GatewayError(404, "access_grant_not_found");
            // Losing the grant takes the models (or the whole key) away in LiteLLM now, not at the next sync.
            await gateway.ReconcileAsync(p, ctx.RequestAborted);
            return Results.NoContent();
        }));
    }

    // ---- helpers ---------------------------------------------------------------------------------------------------------------------------------

    private static async Task<IResult> RunAsync(HttpContext ctx, OrgAccess access, Func<OrgContext, Task<IResult>> handler)
    {
        var (context, failure) = await access.ResolveAsync(ctx);
        if (failure is not null) return failure;
        try { return await handler(context!); }
        catch (Invalid invalid) { return invalid.ToResult(); }
        catch (GatewayError e) { return e.ToResult(); }
        catch (LiteLlmException e) { return GatewayError.From(e).ToResult(); }
    }

    /// <summary>Gateway management: on for this deployment, then View (reads) or Manage (writes; sensitive, so a recent sign-in) Gateway providers.</summary>
    private static IResult? Management(OrgAccess access, OrgContext c, GatewayService gateway, bool write)
    {
        if (access.Require(c, write ? Manage : View) is { } refused) return refused;
        return gateway.Options.Enabled ? null : NotEnabled();
    }

    private static IResult NotEnabled() => Results.Json(new { error = "gateway_not_enabled", message = "Gateway management is not enabled on this deployment. Ask your administrator to configure GATEWAY_ENABLED=true." }, statusCode: 403);

    private static IResult SecureEntry() => Results.Json(new { error = "secure_entry_required", message = SecureEntryMessage }, statusCode: 400);

    private static bool CarriesSecret(JsonElement body, string field) =>
        body.ValueKind == JsonValueKind.Object && body.TryGetProperty(field, out var v) && v.ValueKind is not (JsonValueKind.Null or JsonValueKind.Undefined) && !(v.ValueKind == JsonValueKind.String && v.GetString() == "");

    private static void Unrecognized(JsonElement body, params string[] allowed)
    {
        if (body.ValueKind != JsonValueKind.Object) return;
        Unrecognized(body.EnumerateObject().Select(p => p.Name), allowed);
    }

    private static void Unrecognized(IEnumerable<string> keys, params string[] allowed)
    {
        var extra = keys.Where(k => !allowed.Contains(k)).ToList();
        if (extra.Count > 0) throw new Invalid("", extra.Count == 1 ? $"Unrecognized key: \"{extra[0]}\"" : $"Unrecognized keys: {string.Join(", ", extra.Select(e => $"\"{e}\""))}", "unrecognized_keys");
    }

    private static List<GatewayAudience> Audiences(JsonElement body)
    {
        var list = new List<GatewayAudience>();
        if (LibZod.Bool(body, "allMembers") == true) list.Add(new GatewayAudience("organization", null));
        foreach (var (field, type, prefix) in new[] { ("memberIds", "member", "om_"), ("teamIds", "team", "tem_") })
        {
            var items = LibZod.Array(body, field, max: 500) ?? [];
            for (var i = 0; i < items.Count; i++)
            {
                if (items[i].ValueKind != JsonValueKind.String || items[i].GetString() is not { } id || !id.StartsWith(prefix, StringComparison.Ordinal)) throw new Invalid($"{field}.{i}", $"Invalid {type} ID.", "custom");
                list.Add(new GatewayAudience(type, id));
            }
        }
        return list;
    }

    private static GatewayAudience Audience(JsonElement el, string path)
    {
        var type = LibZod.Enum(el, "type", ["organization", "team", "member"], path: $"{path}.type");
        string? Id(string field, string prefix)
        {
            var id = LibZod.Str(el, field, max: 64, path: $"{path}.{field}")!;
            if (!id.StartsWith(prefix, StringComparison.Ordinal)) throw new Invalid($"{path}.{field}", $"Invalid {type} ID.", "custom");
            return id;
        }
        return type switch
        {
            "team" => new GatewayAudience("team", Id("teamId", "tem_")),
            "member" => new GatewayAudience("member", Id("memberId", "om_")),
            _ => new GatewayAudience("organization", null),
        };
    }

    private static string? Description(JsonElement body)
    {
        if (!body.TryGetProperty("description", out var d) || d.ValueKind == JsonValueKind.Null) return null;
        if (d.ValueKind != JsonValueKind.String) throw new Invalid("description", $"Invalid input: expected string, received {LibZod.Kind(d)}");
        var text = d.GetString()!;
        if (text.Length > 10000) throw new Invalid("description", "Too big: expected string to have <=10000 characters", "too_big");
        return text;
    }

    private static string? Status(JsonElement body) => body.TryGetProperty("status", out _) ? LibZod.Enum(body, "status", ["active", "disabled"]) : null;

    private static List<string>? ModelIds(JsonElement body, bool required)
    {
        var items = LibZod.Array(body, "modelIds", max: 500);
        if (items is null) return required ? throw new Invalid("modelIds", "Invalid input: expected array, received undefined") : null;
        var ids = new List<string>();
        for (var i = 0; i < items.Count; i++)
        {
            if (items[i].ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(items[i].GetString())) throw new Invalid($"modelIds.{i}", "Invalid input: expected string, received " + LibZod.Kind(items[i]));
            ids.Add(items[i].GetString()!.Trim());
        }
        return ids.Distinct(StringComparer.Ordinal).ToList();
    }

    /// <summary>Replaces a group's models with synced models of the same provider; an unknown id is refused (nothing is changed).</summary>
    private static async Task SetGroupModelsAsync(DenDbContext db, GatewayProvider p, GatewayModelGroup group, List<string> modelIds)
    {
        var rows = await db.Set<GatewayProviderModel>().Where(m => m.GatewayProviderId == p.Id && modelIds.Contains(m.ModelId)).ToListAsync();
        var unknown = modelIds.Except(rows.Select(r => r.ModelId), StringComparer.Ordinal).ToList();
        if (unknown.Count > 0) throw new GatewayError(400, "model_not_found", $"These models are not served by the LiteLLM proxy (sync first?): {string.Join(", ", unknown.Take(5))}.");
        await db.Set<GatewayModelGroupModel>().Where(l => l.ModelGroupId == group.Id).ExecuteDeleteAsync();
        foreach (var r in rows) db.Set<GatewayModelGroupModel>().Add(new GatewayModelGroupModel { ModelGroupId = group.Id, GatewayProviderModelId = r.Id });
    }

    private static JsonNode GroupJson(JsonNode groups, string id) => groups.AsArray().First(g => (string?)g!["id"] == id)!.DeepClone();
}
