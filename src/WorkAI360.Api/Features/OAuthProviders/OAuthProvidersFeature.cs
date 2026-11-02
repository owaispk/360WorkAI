using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.OAuthProviders;
using WorkAI360.Api.Features.Connections;
using WorkAI360.Api.Features.Library;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Features.OAuthProviders;

/// <summary>A provider a workspace may bring its own OAuth app for (the reference's native providers).</summary>
public sealed record NativeProvider(string ProviderId, string DisplayName, string[] DefaultScopes, string[] DefaultFeatures, IReadOnlyDictionary<string, string[]> Optional, bool TenantScoped)
{
    public IEnumerable<string> Features(string? json)
    {
        if (json is null) return DefaultFeatures.Where(Optional.ContainsKey);
        JsonArray? array;
        try { array = JsonNode.Parse(json) as JsonArray; } catch (JsonException) { array = null; }
        if (array is null) return DefaultFeatures.Where(Optional.ContainsKey);
        var seen = new List<string>();
        foreach (var node in array)
            if (node is JsonValue v && v.TryGetValue<string>(out var f) && Optional.ContainsKey(f) && !seen.Contains(f)) seen.Add(f);
        return seen;
    }

    /// <summary>The default scopes plus those of each chosen feature, without repeats, in order.</summary>
    public List<string> Scopes(IEnumerable<string> features)
    {
        var scopes = new List<string>(DefaultScopes);
        foreach (var feature in features)
            if (Optional.TryGetValue(feature, out var more)) foreach (var s in more) if (!scopes.Contains(s)) scopes.Add(s);
        return scopes;
    }
}

public static class NativeProviders
{
    private const string G = "https://www.googleapis.com/auth/";

    public static readonly IReadOnlyList<NativeProvider> All =
    [
        new("google-workspace", "Google Workspace", ["openid", G + "userinfo.email", G + "userinfo.profile"], ["calendarRead", "gmailDraft", "driveFile"],
            new Dictionary<string, string[]>
            {
                ["calendarRead"] = [G + "calendar.readonly"], ["calendarWrite"] = [G + "calendar.events"], ["gmailDraft"] = [G + "gmail.compose"], ["gmailSend"] = [G + "gmail.compose"],
                ["gmailRead"] = [G + "gmail.readonly"], ["gmailManage"] = [G + "gmail.modify"], ["gmailLabels"] = [G + "gmail.labels"], ["sheetsRead"] = [G + "spreadsheets.readonly"],
                ["sheetsWrite"] = [G + "spreadsheets"], ["driveFile"] = [G + "drive.file"], ["driveRead"] = [G + "drive.readonly"], ["driveFull"] = [G + "drive"],
                ["chat"] = [G + "chat.spaces.readonly", G + "chat.messages.readonly", G + "chat.messages.create"],
            }, false),
        new("microsoft-365", "Microsoft 365", ["openid", "profile", "email", "offline_access", "User.Read"], ["mailRead", "calendarRead", "filesRead"],
            new Dictionary<string, string[]>
            {
                ["mailRead"] = ["Mail.Read"], ["mailDraft"] = ["Mail.ReadWrite"], ["mailSend"] = ["Mail.Send"], ["mailManage"] = ["Mail.ReadWrite"], ["calendarRead"] = ["Calendars.Read"],
                ["calendarWrite"] = ["Calendars.ReadWrite"], ["filesRead"] = ["Files.Read"], ["filesWrite"] = ["Files.ReadWrite"], ["filesReadAll"] = ["Files.Read.All"], ["filesFull"] = ["Files.ReadWrite.All"],
                ["sitesRead"] = ["Sites.Read.All"], ["teamsChatRead"] = ["Chat.Read"], ["teamsChatSend"] = ["Chat.Read", "ChatMessage.Send"],
            }, true),
    ];

    public static NativeProvider? Find(string id) => All.FirstOrDefault(p => p.ProviderId == id);

    private static readonly Regex TenantGuid = new("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
    private static readonly Regex TenantDomain = new(@"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>A Microsoft Entra tenant: a GUID or a verified domain, lowercased; the shared authorities (common, organizations, consumers) are not allowed.</summary>
    public static string? NormalizeTenant(string? value)
    {
        var v = value?.Trim().ToLowerInvariant();
        if (string.IsNullOrEmpty(v) || v is "common" or "organizations" or "consumers") return null;
        return TenantGuid.IsMatch(v) || TenantDomain.IsMatch(v) ? v : null;
    }

    /// <summary>The Google APIs the connector calls and which permissions need each (used to say what to turn on in Google Cloud).</summary>
    public static readonly (string Id, string Name, string Service, string[] Features)[] GoogleApis =
    [
        ("drive", "Google Drive API", "drive.googleapis.com", ["driveFile", "driveRead", "driveFull"]),
        ("docs", "Google Docs API", "docs.googleapis.com", ["driveFile", "driveRead", "driveFull"]),
        ("sheets", "Google Sheets API", "sheets.googleapis.com", ["sheetsRead", "sheetsWrite", "driveFile", "driveRead", "driveFull"]),
        ("gmail", "Gmail API", "gmail.googleapis.com", ["gmailDraft", "gmailSend", "gmailRead", "gmailManage", "gmailLabels"]),
        ("calendar", "Google Calendar API", "calendar-json.googleapis.com", ["calendarRead", "calendarWrite"]),
        ("chat", "Google Chat API", "chat.googleapis.com", ["chat"]),
    ];
}

/// <summary>
/// Organization-owned OAuth apps for providers such as Google Workspace. See docs/features/gaps.md for what is and is not built
/// (saving the app, reading it back without its secret, status and disconnect; the browser sign-in itself is not built).
/// </summary>
public sealed class OAuthProvidersFeature : IFeature
{
    private static readonly TimeSpan ReadWindow = TimeSpan.FromHours(24);

    public void AddServices(IServiceCollection services, IConfiguration configuration) { }

    private static IResult Ok(object body, int status = 200) => Results.Json(body, statusCode: status);
    private static IResult Unknown(string providerId, bool googleOnly = false) =>
        Results.Json(new { error = "unknown_oauth_provider", message = googleOnly ? $"\"{providerId}\" is not a Google Workspace connector." : $"\"{providerId}\" is not a known native OAuth provider." }, statusCode: 404);
    private static IResult BadRequest(string message) => Results.Json(new { error = "invalid_request", message }, statusCode: 400);

    private static string ProviderParam(string value)
    {
        var s = value.Trim();
        if (s.Length < 1) throw new Invalid("providerId", "Too small: expected string to have >=1 characters", "too_small");
        if (s.Length > 255) throw new Invalid("providerId", "Too big: expected string to have <=255 characters", "too_big");
        return s;
    }

    public void MapEndpoints(WebApplication app)
    {
        app.MapPost("/v1/oauth-providers/{providerId}/client", async (string providerId, HttpContext ctx, OrgAccess access, DenDbContext db, SecretBox box) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "oauth_clients.manage") is { } denied) return denied;
            try
            {
                providerId = ProviderParam(providerId);
                var body = await Zod.BodyAsync(ctx);
                var clientId = Zod.Str(body, "clientId", required: false, max: 512);
                var clientSecret = Zod.Str(body, "clientSecret", required: false, max: 4096);
                var tenantId = Zod.Str(body, "tenantId", required: false, max: 253);
                List<string>? features = null;
                if (Zod.Array(body, "features") is { } list)
                {
                    features = [];
                    for (var i = 0; i < list.Count; i++)
                    {
                        if (list[i].ValueKind != JsonValueKind.String) throw new Invalid($"features.{i}", $"Invalid input: expected string, received {Zod.Kind(list[i])}");
                        var f = list[i].GetString()!.Trim();
                        if (f.Length < 1) throw new Invalid($"features.{i}", "Too small: expected string to have >=1 characters", "too_small");
                        if (f.Length > 128) throw new Invalid($"features.{i}", "Too big: expected string to have <=128 characters", "too_big");
                        features.Add(f);
                    }
                }

                var provider = NativeProviders.Find(providerId);
                if (provider is null) return Unknown(providerId);
                var orgId = context!.Organization.Id;

                // First setup of two at once, or two edits at once, queue up behind the workspace row.
                await using var tx = await db.Database.BeginTransactionAsync();
                await db.LockOrganizationAsync(orgId);
                var existing = await db.Set<OrgOAuthClient>().FirstOrDefaultAsync(c => c.OrganizationId == orgId && c.ProviderId == provider.ProviderId);
                if (existing is null && clientId is null) return BadRequest("clientId is required for first-time setup.");
                if (features is not null)
                {
                    var unknown = features.Where(f => !provider.Optional.ContainsKey(f)).ToList();
                    if (unknown.Count > 0) return BadRequest($"Unknown optional feature(s): {string.Join(", ", unknown)}.");
                }
                if (tenantId is not null && !provider.TenantScoped) return BadRequest($"tenantId is not supported for \"{providerId}\".");
                string? tenant = null;
                if (provider.TenantScoped)
                {
                    tenant = tenantId is not null ? NativeProviders.NormalizeTenant(tenantId) : NativeProviders.NormalizeTenant(existing?.TenantId);
                    if (tenant is null) return BadRequest("A valid Microsoft Entra tenant ID (GUID) or verified tenant domain is required.");
                }
                var now = DateTime.UtcNow;
                if (existing is null)
                {
                    existing = new OrgOAuthClient { Id = Ids.New("ooc"), OrganizationId = orgId, ProviderId = provider.ProviderId, ClientId = clientId!, CreatedByMemberId = context.Member.Id, CreatedAt = now, UpdatedAt = now };
                    db.Add(existing);
                }
                else { if (clientId is not null) existing.ClientId = clientId; existing.UpdatedAt = now; }
                if (clientSecret is not null) existing.ClientSecretEnc = box.Encrypt(clientSecret);
                if (features is not null) existing.FeaturesJson = JsonSerializer.Serialize(features);
                if (provider.TenantScoped) existing.TenantId = tenant;
                await db.SaveChangesAsync();
                await tx.CommitAsync();
                return Ok(new { ok = true, providerId, clientId = existing.ClientId, features = provider.Features(existing.FeaturesJson).ToList(), tenantId = provider.TenantScoped ? existing.TenantId : null });
            }
            catch (Invalid invalid) { return invalid.ToResult(); }
        });

        app.MapGet("/v1/oauth-providers/{providerId}/client", async (string providerId, HttpContext ctx, OrgAccess access, DenDbContext db, OAuthUrls urls) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "oauth_clients.view") is { } denied) return denied;
            try { providerId = ProviderParam(providerId); } catch (Invalid invalid) { return invalid.ToResult(); }
            if (DateTime.UtcNow - context!.Auth.Session.CreatedAt > ReadWindow) return OrgAccess.ReauthRequired();
            var provider = NativeProviders.Find(providerId);
            if (provider is null) return Unknown(providerId);
            ctx.Response.Headers.CacheControl = "no-store";
            var client = await db.Set<OrgOAuthClient>().AsNoTracking().FirstOrDefaultAsync(c => c.OrganizationId == context.Organization.Id && c.ProviderId == provider.ProviderId);
            var features = provider.Features(client?.FeaturesJson).ToList();
            return Ok(new
            {
                providerId, configured = client is not null, clientId = client?.ClientId, features, scopes = provider.Scopes(features),
                redirectUri = $"{urls.Api}/v1/oauth-providers/{Uri.EscapeDataString(provider.ProviderId)}/connect/callback", tenantId = provider.TenantScoped ? client?.TenantId : null,
            });
        });

        // Lists the Google APIs the saved permissions call. Checking each against Google needs a person's own Google sign-in, which is not built, so they read as unchecked.
        app.MapGet("/v1/oauth-providers/{providerId}/api-check", async (string providerId, HttpContext ctx, OrgAccess access, DenDbContext db) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "oauth_clients.view") is { } denied) return denied;
            try { providerId = ProviderParam(providerId); } catch (Invalid invalid) { return invalid.ToResult(); }
            if (DateTime.UtcNow - context!.Auth.Session.CreatedAt > ReadWindow) return OrgAccess.ReauthRequired();
            if (providerId != "google-workspace") return Unknown(providerId, googleOnly: true);
            ctx.Response.Headers.CacheControl = "no-store";
            var provider = NativeProviders.Find(providerId)!;
            var client = await db.Set<OrgOAuthClient>().AsNoTracking().FirstOrDefaultAsync(c => c.OrganizationId == context.Organization.Id && c.ProviderId == providerId);
            var features = provider.Features(client?.FeaturesJson).ToList();
            var apis = NativeProviders.GoogleApis.Select(a => new { a.Id, a.Name, a.Service, Features = a.Features.Where(features.Contains).ToList() }).Where(a => a.Features.Count > 0)
                .Select(a => new { id = a.Id, name = a.Name, service = a.Service, features = a.Features, status = "unknown", enableUrl = (string?)null, detail = (string?)null }).ToList();
            return Ok(new { providerId, @checked = false, apis });
        });

        app.MapGet("/v1/oauth-providers/{providerId}/status", async (string providerId, HttpContext ctx, OrgAccess access) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            try { providerId = ProviderParam(providerId); } catch (Invalid invalid) { return invalid.ToResult(); }
            if (NativeProviders.Find(providerId) is null) return Unknown(providerId);
            // Signing in with the provider is not built, so nobody has an account connected.
            _ = context;
            return Ok(new { providerId, connected = false, externalAccountId = (string?)null, scopes = (string[]?)null });
        });

        app.MapPost("/v1/oauth-providers/{providerId}/disconnect", async (string providerId, HttpContext ctx, OrgAccess access) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            try { providerId = ProviderParam(providerId); } catch (Invalid invalid) { return invalid.ToResult(); }
            if (NativeProviders.Find(providerId) is null) return Unknown(providerId);
            _ = context;
            return Ok(new { error = "not_found", message = "Nothing was connected." }, 404);
        });
    }
}
