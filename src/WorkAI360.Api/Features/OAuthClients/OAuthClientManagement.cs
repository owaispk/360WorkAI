using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.OAuthExtras;
using WorkAI360.Api.Domain.Oidc;
using WorkAI360.Api.Endpoints;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Features.OAuthClients;

/// <summary>
/// The descriptive RFC 7591 fields a client may register beyond what the base tables carry. Kept as given (strings, bounded) so they can be
/// shown back; nothing in the flows reads them.
/// </summary>
public static class ClientDescriptiveMetadata
{
    private static readonly string[] StringFields = ["client_uri", "tos_uri", "policy_uri", "software_id", "software_version", "software_statement", "application_type"];
    private const int MaxLength = 2048;

    /// <summary>The fields present in <paramref name="body"/> as a JSON object (null when none), or the reason they are refused.</summary>
    public static (string? Json, string? Problem) Read(JsonElement body)
    {
        var o = new JsonObject();
        foreach (var name in StringFields)
        {
            if (!body.TryGetProperty(name, out var v) || v.ValueKind == JsonValueKind.Null) continue;
            if (v.ValueKind != JsonValueKind.String || v.GetString()!.Length > MaxLength) return (null, $"{name} must be a string of at most {MaxLength} characters");
            o[name] = v.GetString();
        }
        if (o["application_type"] is { } type && type.GetValue<string>() is not ("web" or "native")) return (null, "application_type must be web or native");
        foreach (var name in new[] { "client_uri", "tos_uri", "policy_uri" })
            if (o[name] is { } url && !(Uri.TryCreate(url.GetValue<string>(), UriKind.Absolute, out var u) && u.Scheme is "https" or "http" && string.IsNullOrEmpty(u.UserInfo)))
                return (null, $"{name} must be an http(s) URL");
        if (body.TryGetProperty("contacts", out var contacts) && contacts.ValueKind != JsonValueKind.Null)
        {
            if (contacts.ValueKind != JsonValueKind.Array || contacts.GetArrayLength() is 0 or > 20
                || contacts.EnumerateArray().Any(c => c.ValueKind != JsonValueKind.String || c.GetString()!.Length is 0 or > 320))
                return (null, "contacts must list 1 to 20 strings");
            o["contacts"] = new JsonArray(contacts.EnumerateArray().Select(c => (JsonNode?)JsonValue.Create(c.GetString())).ToArray());
        }
        return (o.Count == 0 ? null : o.ToJsonString(), null);
    }

    /// <summary>Merges new descriptive fields over stored ones (an update only replaces what it names).</summary>
    public static string? Merge(string? stored, string? updates)
    {
        if (updates is null) return stored;
        var merged = stored is null ? new JsonObject() : (JsonNode.Parse(stored) as JsonObject ?? []);
        foreach (var (key, value) in (JsonNode.Parse(updates) as JsonObject)!) merged[key] = value?.DeepClone();
        return merged.Count == 0 ? null : merged.ToJsonString();
    }

    public static void AddTo(IDictionary<string, object?> response, string? json)
    {
        if (json is null || JsonNode.Parse(json) is not JsonObject o) return;
        foreach (var (key, value) in o) response[key] = value is null ? null : JsonSerializer.Deserialize<JsonElement>(value.ToJsonString());
    }
}

/// <summary>
/// Client management for the people who registered clients (Better Auth's <c>/oauth2/create-client</c>, <c>get-client</c>, <c>get-clients</c>,
/// <c>public-client</c>, <c>update-client</c>, <c>client/rotate-secret</c>, <c>delete-client</c>, served under <c>/api/auth</c> as in the reference).
/// Den configures neither <c>clientReference</c> nor <c>clientPrivileges</c>, so a client belongs to the signed-in person who registered it, and only
/// they may read, change, rotate or delete it; a client registered anonymously is managed by nobody. The <c>/admin/oauth2/*</c> variants are server-only
/// in the reference (not reachable over HTTP) and are not served.
/// </summary>
public static class OAuthClientManagementEndpoints
{
    private static IResult Unauthorized() => Responses.AuthError(401, "Unauthorized", "UNAUTHORIZED");
    private static IResult NotFound() => Results.Json(new { error = "not_found", error_description = "client not found" }, statusCode: 404);
    private static IResult Invalid(string description) => Results.Json(new { error = "invalid_client_metadata", error_description = description }, statusCode: 400);
    private static IResult Validation(string field) => Results.Json(new { code = "VALIDATION_ERROR", message = $"[body.{field}] Invalid input: expected string, received undefined" }, statusCode: 400);

    public static void MapOAuthClientManagementEndpoints(this WebApplication app)
    {
        app.MapPost("/api/auth/oauth2/create-client", async (HttpContext ctx, DenDbContext db, SessionService sessions, ClientJwksStore jwksStore, TrustedUrls trusted) =>
        {
            var current = await sessions.ResolveAsync(ctx);
            if (current is null) return Unauthorized();
            var (body, failure) = await ReadObjectAsync(ctx);
            if (failure is not null) return failure;
            return await OAuthEndpoints.RegisterFromBodyAsync(body, ctx, db, current.User, jwksStore, trusted);
        });

        app.MapGet("/api/auth/oauth2/get-client", async (HttpContext ctx, DenDbContext db, SessionService sessions) =>
        {
            var current = await sessions.ResolveAsync(ctx);
            if (current is null) return Unauthorized();
            var clientId = ctx.Request.Query["client_id"].ToString();
            if (clientId.Length == 0) return Results.Json(new { code = "VALIDATION_ERROR", message = "[query.client_id] Invalid input: expected string, received undefined" }, statusCode: 400);
            var (client, extras, settings) = await LoadAsync(db, clientId);
            if (client is null) return NotFound();
            if (extras?.OwnerUserId != current.User.Id) return Unauthorized();
            ctx.Response.Headers.CacheControl = "no-store";
            return Results.Json(ClientJson(client, extras, settings, secret: null));
        });

        app.MapGet("/api/auth/oauth2/get-clients", async (HttpContext ctx, DenDbContext db, SessionService sessions) =>
        {
            var current = await sessions.ResolveAsync(ctx);
            if (current is null) return Unauthorized();
            var owned = await (from x in db.Set<OAuthClientExtras>().AsNoTracking()
                               join c in db.OAuthClients.AsNoTracking() on x.ClientId equals c.Id
                               where x.OwnerUserId == current.User.Id
                               orderby c.CreatedAt, c.Id
                               select new { c, x }).ToListAsync();
            var ids = owned.Select(o => o.c.Id).ToList();
            var settings = await db.Set<OidcClientSettings>().AsNoTracking().Where(s => ids.Contains(s.ClientId)).ToDictionaryAsync(s => s.ClientId);
            ctx.Response.Headers.CacheControl = "no-store";
            return Results.Json(owned.Select(o => ClientJson(o.c, o.x, settings.GetValueOrDefault(o.c.Id), secret: null)));
        });

        // Public fields for any signed-in person (the sign-in and consent pages show who is asking).
        app.MapGet("/api/auth/oauth2/public-client", async (HttpContext ctx, DenDbContext db, SessionService sessions) =>
        {
            if (await sessions.ResolveAsync(ctx) is null) return Unauthorized();
            var clientId = ctx.Request.Query["client_id"].ToString();
            if (clientId.Length == 0) return Results.Json(new { code = "VALIDATION_ERROR", message = "[query.client_id] Invalid input: expected string, received undefined" }, statusCode: 400);
            var (client, extras, _) = await LoadAsync(db, clientId);
            if (client is null) return NotFound();
            var response = new Dictionary<string, object?> { ["client_id"] = client.Id, ["client_name"] = client.Name, ["redirect_uris"] = Array.Empty<string>() };
            if (client.LogoUri is not null) response["logo_uri"] = client.LogoUri;
            if (extras?.MetadataJson is { } json && JsonNode.Parse(json) is JsonObject o)
                foreach (var key in new[] { "client_uri", "contacts", "tos_uri", "policy_uri" })
                    if (o[key] is { } value) response[key] = JsonSerializer.Deserialize<JsonElement>(value.ToJsonString());
            return Results.Json(response);
        });

        app.MapPost("/api/auth/oauth2/update-client", async (HttpContext ctx, DenDbContext db, SessionService sessions) =>
        {
            var current = await sessions.ResolveAsync(ctx);
            if (current is null) return Unauthorized();
            var (body, failure) = await ReadObjectAsync(ctx);
            if (failure is not null) return failure;
            if (!body.TryGetProperty("client_id", out var idValue) || idValue.ValueKind != JsonValueKind.String) return Validation("client_id");
            if (!body.TryGetProperty("update", out var update) || update.ValueKind != JsonValueKind.Object)
                return Results.Json(new { code = "VALIDATION_ERROR", message = "[body.update] Invalid input: expected object, received undefined" }, statusCode: 400);

            var clientId = idValue.GetString()!;
            var client = await db.OAuthClients.FirstOrDefaultAsync(c => c.Id == clientId);
            if (client is null) return NotFound();
            var extras = await db.Set<OAuthClientExtras>().FirstOrDefaultAsync(x => x.ClientId == clientId);
            if (extras?.OwnerUserId != current.User.Id) return Unauthorized();
            var settings = await db.Set<OidcClientSettings>().FirstOrDefaultAsync(s => s.ClientId == clientId);

            if (await ApplyUpdateAsync(update, client, extras, settings, db) is { } problem) return problem;
            extras.UpdatedAt = DateTime.UtcNow;
            await db.SaveChangesAsync();
            settings = await db.Set<OidcClientSettings>().AsNoTracking().FirstOrDefaultAsync(s => s.ClientId == clientId);
            return Results.Json(ClientJson(client, extras, settings, secret: null));
        });

        app.MapPost("/api/auth/oauth2/client/rotate-secret", async (HttpContext ctx, DenDbContext db, SessionService sessions) =>
        {
            var current = await sessions.ResolveAsync(ctx);
            if (current is null) return Unauthorized();
            var (body, failure) = await ReadObjectAsync(ctx);
            if (failure is not null) return failure;
            if (!body.TryGetProperty("client_id", out var idValue) || idValue.ValueKind != JsonValueKind.String) return Validation("client_id");
            var clientId = idValue.GetString()!;
            var client = await db.OAuthClients.FirstOrDefaultAsync(c => c.Id == clientId);
            if (client is null) return NotFound();
            var extras = await db.Set<OAuthClientExtras>().FirstOrDefaultAsync(x => x.ClientId == clientId);
            if (extras?.OwnerUserId != current.User.Id) return Unauthorized();
            if (client.AuthMethod is not ("client_secret_basic" or "client_secret_post") || client.SecretHash is null)
                return Results.Json(new { error = "invalid_client", error_description = "secret rotation is only available for clients using client_secret authentication" }, statusCode: 400);

            // The old secret stops working at once: only its hash was stored, and it is replaced.
            var secret = OAuthConstants.ClientSecretPrefix + Ids.RandomAlnum(40);
            client.SecretHash = Ids.Sha256Hex(secret);
            extras.UpdatedAt = DateTime.UtcNow;
            await db.SaveChangesAsync();
            var settings = await db.Set<OidcClientSettings>().AsNoTracking().FirstOrDefaultAsync(s => s.ClientId == clientId);
            ctx.Response.Headers.CacheControl = "no-store";
            return Results.Json(ClientJson(client, extras, settings, secret));
        });

        app.MapPost("/api/auth/oauth2/delete-client", async (HttpContext ctx, DenDbContext db, SessionService sessions) =>
        {
            var current = await sessions.ResolveAsync(ctx);
            if (current is null) return Unauthorized();
            var (body, failure) = await ReadObjectAsync(ctx);
            if (failure is not null) return failure;
            if (!body.TryGetProperty("client_id", out var idValue) || idValue.ValueKind != JsonValueKind.String) return Validation("client_id");
            var clientId = idValue.GetString()!;
            if (!await db.OAuthClients.AnyAsync(c => c.Id == clientId)) return NotFound();
            if (!await db.Set<OAuthClientExtras>().AnyAsync(x => x.ClientId == clientId && x.OwnerUserId == current.User.Id)) return Unauthorized();
            await DeleteClientAsync(db, clientId);
            return Results.Json<object?>(null);
        });
    }

    /// <summary>
    /// Removes a client and everything issued to it: consents, unused authorization codes, refresh tokens (and their DPoP bindings) and OpenID Connect
    /// grants. Access tokens already issued are JWTs; they stop being renewable and run out within their lifetime, as in the reference.
    /// </summary>
    public static async Task DeleteClientAsync(DenDbContext db, string clientId)
    {
        await using var tx = await db.Database.BeginTransactionAsync();
        var families = await db.RefreshTokens.Where(r => r.ClientId == clientId).Select(r => r.FamilyId).Distinct().ToListAsync();
        await db.Set<OAuthDpopBinding>().Where(b => families.Contains(b.Id)).ExecuteDeleteAsync();
        await db.RefreshTokens.Where(r => r.ClientId == clientId).ExecuteDeleteAsync();
        await db.AuthorizationCodes.Where(c => c.ClientId == clientId).ExecuteDeleteAsync();
        await db.OAuthConsents.Where(c => c.ClientId == clientId).ExecuteDeleteAsync();
        await db.Set<OidcGrant>().Where(g => g.ClientId == clientId).ExecuteDeleteAsync();
        await db.Set<OidcClientSettings>().Where(s => s.ClientId == clientId).ExecuteDeleteAsync();
        await db.Set<OAuthClientExtras>().Where(x => x.ClientId == clientId).ExecuteDeleteAsync();
        await db.OAuthClients.Where(c => c.Id == clientId).ExecuteDeleteAsync();
        await tx.CommitAsync();
    }

    private static async Task<(JsonElement Body, IResult? Failure)> ReadObjectAsync(HttpContext ctx)
    {
        try
        {
            var body = (await JsonDocument.ParseAsync(ctx.Request.Body)).RootElement.Clone();
            if (body.ValueKind != JsonValueKind.Object) return (default, Results.Json(new { code = "VALIDATION_ERROR", message = "Invalid input: expected object" }, statusCode: 400));
            return (body, null);
        }
        catch (JsonException) { return (default, Results.Json(new { code = "VALIDATION_ERROR", message = "Invalid input: expected object" }, statusCode: 400)); }
    }

    private static async Task<(OAuthClient? Client, OAuthClientExtras? Extras, OidcClientSettings? Settings)> LoadAsync(DenDbContext db, string clientId)
    {
        var client = await db.OAuthClients.AsNoTracking().FirstOrDefaultAsync(c => c.Id == clientId);
        if (client is null) return (null, null, null);
        var extras = await db.Set<OAuthClientExtras>().AsNoTracking().FirstOrDefaultAsync(x => x.ClientId == clientId);
        var settings = await db.Set<OidcClientSettings>().AsNoTracking().FirstOrDefaultAsync(s => s.ClientId == clientId);
        return (client, extras, settings);
    }

    /// <summary>
    /// Applies an <c>update</c> object with the same rules registration uses. Only the fields the reference lets an owner change are read (redirect URIs,
    /// scope, names and descriptive URLs, contacts, software fields, post-logout URIs, application type, grant and response types); the authentication
    /// method, keys and DPoP binding are not changed this way. Returns the refusal, or null.
    /// </summary>
    private static async Task<IResult?> ApplyUpdateAsync(JsonElement update, OAuthClient client, OAuthClientExtras extras, OidcClientSettings? settings, DenDbContext db)
    {
        static List<string>? Strings(JsonElement e, string name) =>
            e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Array ? v.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).ToList() : null;

        var grantTypes = Strings(update, "grant_types") ?? (extras.GrantTypesJson is null ? [.. OAuthExtrasService.DefaultGrants] : JsonSerializer.Deserialize<List<string>>(extras.GrantTypesJson)!);
        if (grantTypes.Count == 0) return Invalid("grant_types must list at least one grant type");
        if (grantTypes.FirstOrDefault(g => g is not ("authorization_code" or "refresh_token" or "client_credentials")) is { } unsupported) return Invalid($"unsupported grant_type {unsupported}");
        var responseTypes = Strings(update, "response_types");
        if (responseTypes is not null && responseTypes.Any(r => r != "code")) return Invalid("Only the code response type is supported.");
        if (responseTypes is not null && responseTypes.Contains("code") && !grantTypes.Contains("authorization_code"))
            return Invalid("When 'code' response type is used, 'authorization_code' grant type must be included");

        var redirectUris = Strings(update, "redirect_uris") ?? JsonSerializer.Deserialize<List<string>>(client.RedirectUrisJson) ?? [];
        if (update.TryGetProperty("redirect_uris", out _) && redirectUris.Count == 0 || redirectUris.Count > 10)
            return Results.Json(new { error = "invalid_redirect_uri", error_description = "redirect_uris must list between 1 and 10 URIs." }, statusCode: 400);
        if (grantTypes.Contains("authorization_code") && redirectUris.Count == 0)
            return Results.Json(new { error = "invalid_redirect_uri", error_description = "redirect_uris must list between 1 and 10 URIs." }, statusCode: 400);
        if (redirectUris.Any(u => !RedirectPolicy.IsAllowed(u))) return Results.Json(new { error = "invalid_redirect_uri", error_description = RedirectPolicy.ErrorDescription }, statusCode: 400);

        string? scope = null;
        if (update.TryGetProperty("scope", out var scopeValue) && scopeValue.ValueKind == JsonValueKind.String)
        {
            var scopes = OAuthConstants.SplitScope(scopeValue.GetString());
            if (scopes.Length == 0 || scopes.Any(s => !OAuthConstants.Scopes.Contains(s))) return Invalid("Unsupported scope requested.");
            scope = OAuthConstants.JoinScope(scopes);
        }

        string? name = null;
        if (update.TryGetProperty("client_name", out var nameValue) && nameValue.ValueKind == JsonValueKind.String)
        {
            name = nameValue.GetString()!.Trim();
            if (name.Length > 120) return Invalid("client_name is too long.");
        }
        string? logo = client.LogoUri;
        if (update.TryGetProperty("logo_uri", out var logoValue) && logoValue.ValueKind == JsonValueKind.String)
            logo = Uri.TryCreate(logoValue.GetString(), UriKind.Absolute, out var logoUri) && logoUri.Scheme == "https" ? logoValue.GetString() : null;

        var postLogout = Strings(update, "post_logout_redirect_uris");
        if (postLogout is not null && (postLogout.Count is 0 or > 10 || postLogout.Any(u => !RedirectPolicy.IsAllowed(u))))
            return Results.Json(new { error = "invalid_redirect_uri", error_description = "post_logout_redirect_uris must use HTTPS callbacks or HTTP loopback callbacks and must not include fragments." }, statusCode: 400);

        var (descriptive, problem) = ClientDescriptiveMetadata.Read(update);
        if (problem is not null) return Invalid(problem);

        client.RedirectUrisJson = JsonSerializer.Serialize(redirectUris);
        if (scope is not null) client.Scope = scope;
        if (name is not null) client.Name = name;
        client.LogoUri = logo;
        extras.GrantTypesJson = JsonSerializer.Serialize(grantTypes);
        extras.MetadataJson = ClientDescriptiveMetadata.Merge(extras.MetadataJson, descriptive);
        // A client that can no longer use client_credentials (or never could, being public) keeps no scopes for it, as in the reference.
        if (!grantTypes.Contains("client_credentials") || client.AuthMethod == "none") extras.ClientCredentialsScope = null;
        if (postLogout is not null)
        {
            if (settings is null) db.Set<OidcClientSettings>().Add(new OidcClientSettings { ClientId = client.Id, PostLogoutRedirectUrisJson = JsonSerializer.Serialize(postLogout) });
            else settings.PostLogoutRedirectUrisJson = JsonSerializer.Serialize(postLogout);
        }
        await Task.CompletedTask;
        return null;
    }

    /// <summary>The client as RFC 7591 metadata (the reference's <c>schemaToOAuth</c>). The secret appears only when one was just issued.</summary>
    public static Dictionary<string, object?> ClientJson(OAuthClient c, OAuthClientExtras? x, OidcClientSettings? s, string? secret)
    {
        var grantTypes = x?.GrantTypesJson is null ? [.. OAuthExtrasService.DefaultGrants] : JsonSerializer.Deserialize<List<string>>(x.GrantTypesJson)!;
        var d = new Dictionary<string, object?>
        {
            ["client_id"] = c.Id,
            ["scope"] = c.Scope,
            ["client_id_issued_at"] = new DateTimeOffset(DateTime.SpecifyKind(c.CreatedAt, DateTimeKind.Utc)).ToUnixTimeSeconds(),
            ["client_name"] = c.Name,
            ["redirect_uris"] = JsonSerializer.Deserialize<List<string>>(c.RedirectUrisJson) ?? [],
            ["token_endpoint_auth_method"] = c.AuthMethod,
            ["grant_types"] = grantTypes,
            ["response_types"] = grantTypes.Contains("authorization_code") ? new[] { "code" } : Array.Empty<string>(),
        };
        if (c.SecretHash is not null) d["client_secret_expires_at"] = 0;
        if (secret is not null) d["client_secret"] = secret;
        if (x?.OwnerUserId is not null) d["user_id"] = x.OwnerUserId;
        if (c.LogoUri is not null) d["logo_uri"] = c.LogoUri;
        if (x?.JwksJson is not null) d["jwks"] = JsonSerializer.Deserialize<JsonElement>(x.JwksJson);
        if (x?.JwksUri is not null) d["jwks_uri"] = x.JwksUri;
        if (x?.DpopBoundAccessTokens is true) d["dpop_bound_access_tokens"] = true;
        if (s?.PostLogoutRedirectUrisJson is not null) d["post_logout_redirect_uris"] = JsonSerializer.Deserialize<List<string>>(s.PostLogoutRedirectUrisJson);
        if (s?.EnableEndSession is true) d["enable_end_session"] = true;
        ClientDescriptiveMetadata.AddTo(d, x?.MetadataJson);
        return d;
    }
}

public sealed class OAuthClientsFeature : IFeature
{
    public void AddServices(IServiceCollection services, IConfiguration configuration) { }
    public void MapEndpoints(WebApplication app) => app.MapOAuthClientManagementEndpoints();
}
