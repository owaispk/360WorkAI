using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.LlmProviders;
using WorkAI360.Api.Endpoints;
using WorkAI360.Api.Features.Library;
using LibZod = WorkAI360.Api.Features.Library.Zod;

namespace WorkAI360.Api.Features.LlmProviders;

/// <summary>
/// Model providers ("bring your own keys"): a workspace saves providers from the models.dev catalog or pasted custom configurations, decides who may
/// use them, and people's desktops fetch what they need through <c>/connect</c>. See docs/features/llm-providers.md.
/// </summary>
public sealed partial class LlmProvidersFeature : IFeature
{
    public void AddServices(IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<LlmProviderOptions>(configuration.GetSection(LlmProviderOptions.Section));
        services.AddHttpClient(ModelCatalog.HttpClientName);
        services.AddSingleton<ModelCatalog>();
        services.AddScoped<LlmProviderService>();
        services.AddScoped<EndpointProbe>();
    }

    private const string SecureEntryMessage = "Do not send keys through the agent or an API key. Leave the key out; the person adds it in a private field in OpenWork.";
    private const string NoAccess = "You do not have access to this provider.";

    public void MapEndpoints(WebApplication app)
    {
        app.MapGet("/v1/llm-provider-catalog", (HttpContext ctx, OrgAccess access, ModelCatalog catalog) => RunAsync(ctx, access, async _ =>
        {
            try
            {
                var providers = await catalog.ListAsync(ctx.RequestAborted);
                return Results.Json(new { providers = providers.Select(p => new { id = p.Id, name = p.Name, npm = p.Npm, env = p.Env, doc = p.Doc, api = p.Api, modelCount = p.Models.Count }) });
            }
            catch (CatalogUnavailableException e) { return Results.Json(new { error = "provider_catalog_unavailable", message = e.Message }, statusCode: 502); }
        }));

        app.MapGet("/v1/llm-provider-catalog/{providerId}", (string providerId, HttpContext ctx, OrgAccess access, ModelCatalog catalog) => RunAsync(ctx, access, async _ =>
        {
            var id = providerId.Trim();
            if (id.Length < 1) throw new Invalid("providerId", "Too small: expected string to have >=1 characters", "too_small");
            if (id.Length > 255) throw new Invalid("providerId", "Too big: expected string to have <=255 characters", "too_big");
            try
            {
                if (await catalog.FindAsync(id, ctx.RequestAborted) is not { } p) return Results.Json(new { error = "provider_not_found" }, statusCode: 404);
                return Results.Json(new { provider = new { id = p.Id, name = p.Name, npm = p.Npm, env = p.Env, doc = p.Doc, api = p.Api, config = p.Config, models = p.Models.Select(m => new { id = m.Id, name = m.Name, config = m.Config }) } });
            }
            catch (CatalogUnavailableException e) { return Results.Json(new { error = "provider_catalog_unavailable", message = e.Message }, statusCode: 502); }
        }));

        app.MapPost("/v1/llm-providers/test-connection", (HttpContext ctx, OrgAccess access, EndpointProbe probe) => RunAsync(ctx, access, async c =>
        {
            var body = await LibZod.BodyAsync(ctx);
            if (c.ApiKeyId is not null && CarriesSecret(body, "apiKey")) return SecureEntry();
            var api = LibZod.Str(body, "api", max: 2048)!;
            var apiKey = LibZod.Str(body, "apiKey", required: false, min: 0, max: 65535);
            var modelIds = LibZod.Array(body, "modelIds", max: 8)?.Select((e, i) => ArrayString(e, $"modelIds.{i}")).ToList();
            var result = await probe.ProbeAsync(api, apiKey ?? "", ctx.RequestAborted);
            if (result.Ok && result.NormalizedApi is not null && modelIds is { Count: > 0 })
            {
                var verifications = await probe.VerifyAsync(result.NormalizedApi, apiKey ?? "", modelIds, ctx.RequestAborted);
                return Results.Json(new { result = result.ToJson(), verifications = verifications.Select(v => v.ToJson()) });
            }
            return Results.Json(new { result = result.ToJson() });
        }));

        app.MapGet("/v1/llm-providers", (HttpContext ctx, OrgAccess access, LlmProviderService service) => RunAsync(ctx, access, async c =>
        {
            var scope = LibZod.QueryEnum(ctx, "scope", ["usable", "manageable"]) ?? "usable";
            var updateAll = c.Permissions.Has("llm_providers.update");
            var providers = await service.LoadAsync(c.Organization.Id, c.Member.Id, await service.TeamIdsAsync(c.Member.Id), c.Permissions.Has("llm_providers.view"), updateAll, scope);
            foreach (var p in providers) p["canManage"] = updateAll || (string?)p["createdByOrgMembershipId"] == c.Member.Id;
            return Results.Json(new { llmProviders = providers });
        }));

        app.MapGet("/v1/llm-providers/by-key/{externalKey}", (string externalKey, HttpContext ctx, OrgAccess access, LlmProviderService service, DenDbContext db) => RunAsync(ctx, access, async c =>
        {
            if (access.Require(c, "llm_providers.view") is { } denied) return denied;
            ValidateExternalKey(externalKey);
            var row = await db.Set<LlmProvider>().AsNoTracking().FirstOrDefaultAsync(p => p.OrganizationId == c.Organization.Id && p.ExternalKey == externalKey);
            return row is null ? NotFound() : await SingleAsync(c, service, row.Id);
        }));

        app.MapGet("/v1/llm-providers/{llmProviderId}", (string llmProviderId, HttpContext ctx, OrgAccess access, LlmProviderService service, DenDbContext db) => RunAsync(ctx, access, async c =>
        {
            if (access.Require(c, "llm_providers.view") is { } denied) return denied;
            LibZod.TypeId(llmProviderId, "lpr", "llmProviderId");
            if (!await db.Set<LlmProvider>().AnyAsync(p => p.OrganizationId == c.Organization.Id && p.Id == llmProviderId)) return NotFound();
            return await SingleAsync(c, service, llmProviderId);
        }));

        app.MapPut("/v1/llm-providers/by-key/{externalKey}", (string externalKey, HttpContext ctx, OrgAccess access, LlmProviderService service, DenDbContext db) => RunAsync(ctx, access, async c =>
        {
            if (access.Require(c, "llm_providers.update") is { } denied) return denied;
            var body = await LibZod.BodyAsync(ctx);
            if (c.ApiKeyId is not null && CarriesSecret(body, "apiKey", "apiKeys")) return SecureEntry();
            ValidateExternalKey(externalKey);
            var input = ParseWrite(body);
            if (ctx.Request.Headers.ContainsKey("If-Match") || ctx.Request.Headers.ContainsKey("If-None-Match"))
                return Results.Json(new { error = "unsupported_precondition", message = "This endpoint uses last-write-wins. Serialize configuration writers." }, statusCode: 400);
            // A blank key from a provisioning client is almost always an unresolved secret: refuse it rather than save an unusable provider.
            if (input.ApiKey == "")
                return Results.Json(new { error = "invalid_api_keys", message = "apiKey is blank. Omit apiKey to keep the stored credential, or clear it explicitly with apiKeys." }, statusCode: 400);
            var existing = await db.Set<LlmProvider>().FirstOrDefaultAsync(p => p.OrganizationId == c.Organization.Id && p.ExternalKey == externalKey);
            if (existing is not null) return await UpdateAsync(ctx, access, c, service, existing, input);
            try
            {
                var created = await service.CreateAsync(c, input, externalKey);
                return Results.Json(new { llmProvider = service.WriteJson(created) }, statusCode: 201);
            }
            catch (DbUpdateException)
            {
                // A concurrent writer created the same key first: apply this write to it instead of making a second provider.
                db.ChangeTracker.Clear();
                var winner = await db.Set<LlmProvider>().FirstOrDefaultAsync(p => p.OrganizationId == c.Organization.Id && p.ExternalKey == externalKey);
                if (winner is not null) return await UpdateAsync(ctx, access, c, service, winner, input);
                return Results.Json(new { error = "resource_conflict", message = "The resource name is already in use by another identity." }, statusCode: 409);
            }
        }));

        app.MapDelete("/v1/llm-providers/by-key/{externalKey}", (string externalKey, HttpContext ctx, OrgAccess access, LlmProviderService service, DenDbContext db) => RunAsync(ctx, access, async c =>
        {
            if (access.Require(c, "llm_providers.delete") is { } denied) return denied;
            ValidateExternalKey(externalKey);
            var existing = await db.Set<LlmProvider>().FirstOrDefaultAsync(p => p.OrganizationId == c.Organization.Id && p.ExternalKey == externalKey);
            if (existing is null) return Results.Json(new { ok = true, deleted = false });
            if (AuthorizeChange(access, c, existing, "llm_providers.delete", "Only the provider creator or a workspace admin can delete providers.") is { } refused) return refused;
            await service.DeleteAsync(existing);
            return Results.Json(new { ok = true, deleted = true });
        }));

        app.MapPost("/v1/llm-providers", (HttpContext ctx, OrgAccess access, LlmProviderService service) => RunAsync(ctx, access, async c =>
        {
            var body = await LibZod.BodyAsync(ctx);
            if (c.ApiKeyId is not null && CarriesSecret(body, "apiKey", "apiKeys")) return SecureEntry();
            var created = await service.CreateAsync(c, ParseWrite(body), null);
            return Results.Json(new { llmProvider = service.WriteJson(created) }, statusCode: 201);
        }));

        app.MapPatch("/v1/llm-providers/{llmProviderId}", (string llmProviderId, HttpContext ctx, OrgAccess access, LlmProviderService service) => RunAsync(ctx, access, async c =>
        {
            var body = await LibZod.BodyAsync(ctx);
            if (c.ApiKeyId is not null && CarriesSecret(body, "apiKey", "apiKeys")) return SecureEntry();
            LibZod.TypeId(llmProviderId, "lpr", "llmProviderId");
            var input = ParseWrite(body);
            if (await service.FindAsync(c.Organization.Id, llmProviderId) is not { } provider) return NotFound();
            return await UpdateAsync(ctx, access, c, service, provider, input);
        }));

        app.MapDelete("/v1/llm-providers/{llmProviderId}", (string llmProviderId, HttpContext ctx, OrgAccess access, LlmProviderService service) => RunAsync(ctx, access, async c =>
        {
            LibZod.TypeId(llmProviderId, "lpr", "llmProviderId");
            if (await service.FindAsync(c.Organization.Id, llmProviderId) is not { } provider) return NotFound();
            if (AuthorizeChange(access, c, provider, "llm_providers.delete", "Only the provider creator or a workspace admin can delete providers.") is { } refused) return refused;
            await service.DeleteAsync(provider);
            return Results.NoContent();
        }));

        app.MapDelete("/v1/llm-providers/{llmProviderId}/access/{accessId}", (string llmProviderId, string accessId, HttpContext ctx, OrgAccess access, LlmProviderService service, DenDbContext db) => RunAsync(ctx, access, async c =>
        {
            LibZod.TypeId(llmProviderId, "lpr", "llmProviderId");
            LibZod.TypeId(accessId, "lpa", "accessId");
            if (await service.FindAsync(c.Organization.Id, llmProviderId) is not { } provider) return NotFound();
            if (AuthorizeChange(access, c, provider, "llm_providers.update", "Only the provider creator or a workspace admin can manage access.") is { } refused) return refused;
            var row = await db.Set<LlmProviderAccess>().FirstOrDefaultAsync(a => a.Id == accessId && a.LlmProviderId == provider.Id);
            if (row is null) return Results.Json(new { error = "llm_provider_access_not_found" }, statusCode: 404);
            if (row.MemberId == provider.CreatedByMemberId)
                return Results.Json(new { error = "protected_access", message = "The provider creator always keeps direct access." }, statusCode: 409);
            db.Remove(row);
            await db.SaveChangesAsync();
            return Results.NoContent();
        }));

        // What a granted person's desktop fetches to call the provider. Stays 200 for granted callers even without a usable credential: published
        // desktops fail their whole sync on an error here, while a null credential only makes them skip this provider.
        app.MapGet("/v1/llm-providers/{llmProviderId}/connect", (string llmProviderId, HttpContext ctx, OrgAccess access, LlmProviderService service) => RunAsync(ctx, access, async c =>
        {
            LibZod.TypeId(llmProviderId, "lpr", "llmProviderId");
            if (await service.FindAsync(c.Organization.Id, llmProviderId) is not { } provider) return NotFound();
            if (!await service.CanUseAsync(c.Organization.Id, provider.Id, c.Member.Id, await service.TeamIdsAsync(c.Member.Id)))
                return Results.Json(new { error = "forbidden", message = NoAccess }, statusCode: 403);
            ctx.Response.Headers.CacheControl = "no-store";
            return Results.Json(new { llmProvider = await service.ConnectJsonAsync(provider, c.Member.Id) });
        }));

        app.MapPut("/v1/llm-providers/{llmProviderId}/my-credential", (string llmProviderId, HttpContext ctx, OrgAccess access, LlmProviderService service) => RunAsync(ctx, access, async c =>
        {
            var body = await LibZod.BodyAsync(ctx);
            if (c.ApiKeyId is not null && CarriesSecret(body, "apiKey", "apiKeys")) return SecureEntry();
            LibZod.TypeId(llmProviderId, "lpr", "llmProviderId");
            var (apiKey, apiKeys) = ParseMemberCredential(body);
            if (await service.FindAsync(c.Organization.Id, llmProviderId) is not { } provider) return NotFound();
            if (!await service.CanUseAsync(c.Organization.Id, provider.Id, c.Member.Id, await service.TeamIdsAsync(c.Member.Id)))
                return Results.Json(new { error = "forbidden", message = NoAccess }, statusCode: 403);
            if (provider.CredentialMode != "per_member") return Results.Json(new { error = "not_per_member" }, statusCode: 400);
            var secret = MemberSecret(service, provider, apiKey, apiKeys);
            var (outcome, credential) = await service.UpsertMemberCredentialAsync(c.Organization.Id, provider.Id, c.Member.Id, secret, "member", allowBlockedOverwrite: false);
            if (outcome == LlmProviderService.WriteOutcome.Blocked) return Results.Json(new { error = "credential_blocked" }, statusCode: 409);
            return Results.Json(LlmProviderService.CredentialSummary(credential!));
        }));

        app.MapDelete("/v1/llm-providers/{llmProviderId}/my-credential", (string llmProviderId, HttpContext ctx, OrgAccess access, LlmProviderService service) => RunAsync(ctx, access, async c =>
        {
            LibZod.TypeId(llmProviderId, "lpr", "llmProviderId");
            if (await service.FindAsync(c.Organization.Id, llmProviderId) is not { } provider) return NotFound();
            if (!await service.CanUseAsync(c.Organization.Id, provider.Id, c.Member.Id, await service.TeamIdsAsync(c.Member.Id)))
                return Results.Json(new { error = "forbidden", message = NoAccess }, statusCode: 403);
            if (provider.CredentialMode != "per_member") return Results.Json(new { error = "not_per_member" }, statusCode: 400);
            if (!await service.DeleteOwnCredentialAsync(c.Organization.Id, provider.Id, c.Member.Id)) return Results.Json(new { error = "credential_blocked" }, statusCode: 409);
            return Results.Json(new { ok = true });
        }));

        app.MapGet("/v1/llm-providers/{llmProviderId}/member-credentials", (string llmProviderId, HttpContext ctx, OrgAccess access, LlmProviderService service) => RunAsync(ctx, access, async c =>
        {
            if (access.Require(c, "llm_provider_credentials.manage") is { } denied) return denied;
            LibZod.TypeId(llmProviderId, "lpr", "llmProviderId");
            if (await service.FindAsync(c.Organization.Id, llmProviderId) is not { } provider) return NotFound();
            return Results.Json(new { memberCredentials = await service.MemberCredentialsAsync(c.Organization.Id, provider.Id) });
        }));

        app.MapPut("/v1/llm-providers/{llmProviderId}/member-credentials/{orgMembershipId}", (string llmProviderId, string orgMembershipId, HttpContext ctx, OrgAccess access, LlmProviderService service, DenDbContext db) => RunAsync(ctx, access, async c =>
        {
            if (access.Require(c, "llm_provider_credentials.manage") is { } denied) return denied;
            var body = await LibZod.BodyAsync(ctx);
            if (c.ApiKeyId is not null && CarriesSecret(body, "apiKey", "apiKeys")) return SecureEntry();
            LibZod.TypeId(llmProviderId, "lpr", "llmProviderId");
            LibZod.TypeId(orgMembershipId, "om", "orgMembershipId");
            var (apiKey, apiKeys) = ParseMemberCredential(body);
            var principal = LibZod.Str(body, "externalPrincipalId", required: false, max: 255);
            var credentialId = LibZod.Str(body, "externalCredentialId", required: false, max: 255);
            int? expectedVersion = null;
            if (body.TryGetProperty("expectedVersion", out var ev))
            {
                if (ev.ValueKind != JsonValueKind.Number) throw new Invalid("expectedVersion", $"Invalid input: expected number, received {LibZod.Kind(ev)}");
                var d = ev.GetDouble();
                if (d != Math.Floor(d)) throw new Invalid("expectedVersion", "Invalid input: expected int, received number");
                if (d <= 0) throw new Invalid("expectedVersion", "Too small: expected number to be >0", "too_small");
                expectedVersion = (int)Math.Min(d, int.MaxValue);
            }
            if (await service.FindAsync(c.Organization.Id, llmProviderId) is not { } provider) return NotFound();
            if (provider.CredentialMode != "per_member") return Results.Json(new { error = "not_per_member" }, statusCode: 400);
            if (!await db.Members.AnyAsync(m => m.OrganizationId == c.Organization.Id && m.Id == orgMembershipId)) return Results.Json(new { error = "member_not_found" }, statusCode: 404);
            var secret = MemberSecret(service, provider, apiKey, apiKeys);
            var (outcome, credential) = await service.UpsertMemberCredentialAsync(c.Organization.Id, provider.Id, orgMembershipId, secret, "admin", allowBlockedOverwrite: true, principal, credentialId, expectedVersion);
            if (outcome == LlmProviderService.WriteOutcome.VersionConflict) return Results.Json(new { error = "version_conflict" }, statusCode: 409);
            return Results.Json(LlmProviderService.CredentialSummary(credential!));
        }));

        app.MapPost("/v1/llm-providers/{llmProviderId}/member-credentials/{orgMembershipId}/block", (string llmProviderId, string orgMembershipId, HttpContext ctx, OrgAccess access, LlmProviderService service) => RunAsync(ctx, access, async c =>
        {
            if (access.Require(c, "llm_provider_credentials.manage") is { } denied) return denied;
            LibZod.TypeId(llmProviderId, "lpr", "llmProviderId");
            LibZod.TypeId(orgMembershipId, "om", "orgMembershipId");
            if (await service.FindAsync(c.Organization.Id, llmProviderId) is not { } provider) return NotFound();
            var blocked = await service.BlockAsync(c.Organization.Id, provider.Id, orgMembershipId);
            return blocked is null ? Results.Json(new { error = "member_credential_not_found" }, statusCode: 404) : Results.Json(LlmProviderService.CredentialSummary(blocked));
        }));
    }

    // ---- helpers ---------------------------------------------------------------------------------------------------------------------------

    private static async Task<IResult> RunAsync(HttpContext ctx, OrgAccess access, Func<OrgContext, Task<IResult>> handler)
    {
        var (context, failure) = await access.ResolveAsync(ctx);
        if (failure is not null) return failure;
        try { return await handler(context!); }
        catch (Invalid invalid) { return invalid.ToResult(); }
        catch (ProviderFailure f) { return f.ToResult(); }
    }

    private static IResult NotFound() => Results.Json(new { error = "llm_provider_not_found" }, statusCode: 404);

    private static IResult SecureEntry() => Results.Json(new { error = "secure_entry_required", message = SecureEntryMessage }, statusCode: 400);

    private static async Task<IResult> SingleAsync(OrgContext c, LlmProviderService service, string providerId)
    {
        var providers = await service.LoadAsync(c.Organization.Id, c.Member.Id, await service.TeamIdsAsync(c.Member.Id), viewAll: true, c.Permissions.Has("llm_providers.update"), "manageable");
        var value = providers.FirstOrDefault(p => (string?)p["id"] == providerId);
        return value is null ? NotFound() : Results.Json(new { llmProvider = value });
    }

    /// <summary>
    /// The creator may always change their provider. Anyone else needs <paramref name="key"/> (sensitive: a recent sign-in too). Admins always need a
    /// recent sign-in, even for their own provider; other creators do not.
    /// </summary>
    private static IResult? AuthorizeChange(OrgAccess access, OrgContext c, LlmProvider provider, string key, string message)
    {
        if (c.Permissions.Has(key)) return access.Require(c, key);
        if (provider.CreatedByMemberId != c.Member.Id) return Results.Json(new { error = "forbidden", message }, statusCode: 403);
        if ((c.IsAdmin || c.IsOwner) && !access.IsFresh(c.Auth.Session)) return OrgAccess.ReauthRequired();
        return null;
    }

    private static async Task<IResult> UpdateAsync(HttpContext ctx, OrgAccess access, OrgContext c, LlmProviderService service, LlmProvider provider, ProviderWrite input)
    {
        if (AuthorizeChange(access, c, provider, "llm_providers.update", "Only the provider creator or a workspace admin can update providers.") is { } refused) return refused;
        var updated = await service.UpdateAsync(c, provider, input);
        return Results.Json(new { llmProvider = service.WriteJson(updated) });
    }

    private static string MemberSecret(LlmProviderService service, LlmProvider provider, string? apiKey, Dictionary<string, string>? apiKeys) =>
        service.ResolveCredential(LlmProviderService.Config(provider), null, apiKey, apiKeys)
            ?? throw new ProviderFailure(400, "invalid_api_keys", "Provide a non-empty credential.");

    /// <summary>Whether a top-level field carries a value (the reference refuses keys from API keys and agents, whatever else the body says).</summary>
    private static bool CarriesSecret(JsonElement body, params string[] fields) =>
        fields.Any(f => body.TryGetProperty(f, out var v) && v.ValueKind is not (JsonValueKind.Null or JsonValueKind.Undefined) && !(v.ValueKind == JsonValueKind.String && v.GetString() == ""));

    private static void ValidateExternalKey(string key)
    {
        if (!ExternalKeyRegex().IsMatch(key)) throw new Invalid("externalKey", "Invalid string: must match pattern /^[a-z0-9][a-z0-9._-]{0,127}$/", "invalid_format");
    }

    private static string ArrayString(JsonElement e, string path)
    {
        if (e.ValueKind != JsonValueKind.String) throw new Invalid(path, $"Invalid input: expected string, received {LibZod.Kind(e)}");
        var s = e.GetString()!.Trim();
        if (s.Length < 1) throw new Invalid(path, "Too small: expected string to have >=1 characters", "too_small");
        if (s.Length > 255) throw new Invalid(path, "Too big: expected string to have <=255 characters", "too_big");
        return s;
    }

    private static Dictionary<string, string>? StringRecord(JsonElement body, string name, bool nonEmptyValues)
    {
        if (!body.TryGetProperty(name, out var v)) return null;
        if (v.ValueKind != JsonValueKind.Object) throw new Invalid(name, $"Invalid input: expected record, received {LibZod.Kind(v)}");
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var p in v.EnumerateObject())
        {
            var key = p.Name.Trim();
            if (key.Length < 1) throw new Invalid(name, "Too small: expected string to have >=1 characters", "too_small");
            if (key.Length > 255) throw new Invalid(name, "Too big: expected string to have <=255 characters", "too_big");
            if (p.Value.ValueKind != JsonValueKind.String) throw new Invalid($"{name}.{p.Name}", $"Invalid input: expected string, received {LibZod.Kind(p.Value)}");
            var value = p.Value.GetString()!.Trim();
            if (nonEmptyValues && value.Length < 1) throw new Invalid($"{name}.{p.Name}", "Too small: expected string to have >=1 characters", "too_small");
            if (value.Length > 65535) throw new Invalid($"{name}.{p.Name}", "Too big: expected string to have <=65535 characters", "too_big");
            result[key] = value;
        }
        return result;
    }

    private static List<string> TypeIds(JsonElement body, string name, string prefix)
    {
        var items = LibZod.Array(body, name, max: 500);
        if (items is null) return [];
        return items.Select((e, i) =>
        {
            if (e.ValueKind != JsonValueKind.String) throw new Invalid($"{name}.{i}", $"Invalid input: expected string, received {LibZod.Kind(e)}");
            return LibZod.TypeId(e.GetString()!, prefix, $"{name}.{i}");
        }).ToList();
    }

    /// <summary>The reference's <c>llmProviderWriteSchema</c> (unknown fields are ignored, as zod strips them).</summary>
    public static ProviderWrite ParseWrite(JsonElement body)
    {
        var name = LibZod.Str(body, "name", max: 255)!;
        var source = LibZod.Enum(body, "source", ["models_dev", "custom"]);
        var providerId = LibZod.Str(body, "providerId", required: false, max: 255);
        List<string>? modelIds = null;
        if (LibZod.Array(body, "modelIds") is { } models)
        {
            if (models.Count < 1) throw new Invalid("modelIds", "Too small: expected array to have >=1 items", "too_small");
            modelIds = models.Select((e, i) => ArrayString(e, $"modelIds.{i}")).ToList();
        }
        var customText = LibZod.Str(body, "customConfigText", required: false);
        var hasCustom = body.TryGetProperty("customConfig", out var customElement);
        var credentialMode = LibZod.Enum(body, "credentialMode", ["shared", "per_member"], required: false);
        if (credentialMode.Length == 0) credentialMode = "shared";
        var apiKey = LibZod.Str(body, "apiKey", required: false, min: 0, max: 65535);
        var apiKeys = StringRecord(body, "apiKeys", nonEmptyValues: false);
        var memberIds = TypeIds(body, "memberIds", "om");
        var teamIds = TypeIds(body, "teamIds", "tem");
        var allMembers = LibZod.Bool(body, "allMembers") ?? false;
        if (source == "models_dev")
        {
            if (providerId is null) throw new Invalid("providerId", "Select a provider.", "custom");
            if (modelIds is not { Count: > 0 }) throw new Invalid("modelIds", "Select at least one model.", "custom");
        }
        if (source == "custom" && customText is null && !hasCustom) throw new Invalid("customConfigText", "Paste a custom provider config.", "custom");
        return new ProviderWrite(name, source, providerId, modelIds, customText, hasCustom ? JsonNode.Parse(customElement.GetRawText()) : null, hasCustom,
            credentialMode, apiKey, apiKeys, memberIds, teamIds, allMembers);
    }

    /// <summary>Exactly one of <c>apiKey</c> (non-empty) or <c>apiKeys</c> (at least one non-empty value).</summary>
    private static (string? ApiKey, Dictionary<string, string>? ApiKeys) ParseMemberCredential(JsonElement body)
    {
        var apiKey = LibZod.Str(body, "apiKey", required: false, max: 65535);
        var apiKeys = StringRecord(body, "apiKeys", nonEmptyValues: true);
        if (apiKeys is { Count: 0 }) throw new Invalid("apiKeys", "Provide at least one credential.", "custom");
        if ((apiKey is null) == (apiKeys is null)) throw new Invalid("", "Provide exactly one of apiKey or apiKeys.", "custom");
        return (apiKey, apiKeys);
    }

    [GeneratedRegex("^[a-z0-9][a-z0-9._-]{0,127}$")]
    private static partial Regex ExternalKeyRegex();
}
