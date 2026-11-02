using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.OAuthExtras;
using WorkAI360.Api.Features.PlatformAdmin;
using WorkAI360.Api.Features.Sso;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Features.OAuthExtras;

/// <summary>
/// OAuth provider extras the reference's OAuth provider has: the <c>client_credentials</c> grant, <c>private_key_jwt</c> client authentication and DPoP (RFC 9449) at
/// the token endpoint, userinfo and the MCP endpoint. Registration, token and discovery changes live in <c>OAuth/</c>; this wires the services and adds the one operator
/// route (granting a client its <c>client_credentials</c> scopes). See docs/features/oauth-extras.md.
/// </summary>
public sealed class OAuthExtrasFeature : IFeature
{
    public void AddServices(IServiceCollection services, IConfiguration configuration)
    {
        services.AddScoped<DpopVerifier>();
        services.AddScoped<ClientJwksStore>();
        services.AddScoped<ClientAssertionVerifier>();
        services.AddScoped<OAuthExtrasService>();
        // Fetching a client's jwks_uri: no redirects, a short timeout, and (unless the deployment allows private addresses) never a private address, even after DNS.
        services.AddHttpClient(ClientJwksStore.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(sp => IdpHttp.CreateHandler(sp.GetRequiredService<IOptions<OAuthClientMetadataOptions>>().Value.AllowPrivateUrls))
            .ConfigureHttpClient(c => c.Timeout = TimeSpan.FromSeconds(5));
    }

    public void MapEndpoints(WebApplication app)
    {
        // The reference accepts client_credentials registrations but has no way to give such a client scopes (it configures no `clientPrivileges`), so every
        // client_credentials request there answers `unauthorized_client`. Here a platform administrator can grant them; until then the answer is the same.
        app.MapPut("/v1/admin/oauth-clients/{clientId}/client-credentials-scopes", async (string clientId, HttpContext ctx, PlatformAdminGuard guard, DenDbContext db) =>
        {
            var (_, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            var body = await AdminBody.ReadAsync(ctx);
            if (AdminBody.NotObject(body) is { } notObject) return AdminSupport.Invalid(notObject);
            var root = body!.Value;
            var extra = root.EnumerateObject().Select(p => p.Name).Where(n => n != "scopes").ToList();
            if (extra.Count > 0) return AdminSupport.Invalid(extra.Count == 1 ? $"Unrecognized key: \"{extra[0]}\"" : $"Unrecognized keys: {string.Join(", ", extra.Select(n => $"\"{n}\""))}");
            if (!root.TryGetProperty("scopes", out var list) || list.ValueKind != JsonValueKind.Array) return AdminSupport.Invalid($"Invalid input: expected array, received {AdminBody.Kind(AdminBody.Get(root, "scopes"))}");
            var scopes = new List<string>();
            foreach (var item in list.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.String) return AdminSupport.Invalid($"Invalid input: expected string, received {AdminBody.Kind(item)}");
                scopes.Add(item.GetString()!.Trim());
            }
            scopes = [.. scopes.Where(s => s.Length > 0).Distinct()];
            var invalid = scopes.Where(s => !OAuthConstants.Scopes.Contains(s) || OAuthExtrasService.UserDelegatedScopes.Contains(s)).ToList();
            if (invalid.Count > 0) return Results.Json(new { error = "invalid_scope", message = $"The following client_credentials scopes are invalid: {string.Join(", ", invalid)}" }, statusCode: 400);

            var client = await db.OAuthClients.AsNoTracking().FirstOrDefaultAsync(c => c.Id == clientId);
            if (client is null) return AdminSupport.NotFound("OAuth client not found.");
            var extras = await db.Set<OAuthClientExtras>().FirstOrDefaultAsync(e => e.ClientId == clientId);
            if (scopes.Count > 0)
            {
                if (!OAuthExtrasService.AllowsGrant(extras, "client_credentials")) return AdminSupport.Invalid("client_credentials_scopes requires the client_credentials grant");
                if (client.AuthMethod == "none") return AdminSupport.Invalid("public clients cannot be assigned client_credentials scopes");
            }
            if (extras is null)
            {
                if (scopes.Count == 0) return Results.Json(new { clientId, scopes });
                extras = new OAuthClientExtras { ClientId = clientId };
                db.Set<OAuthClientExtras>().Add(extras);
            }
            extras.ClientCredentialsScope = scopes.Count == 0 ? null : OAuthConstants.JoinScope(scopes);
            try { await db.SaveChangesAsync(); }
            catch (DbUpdateException) { return Results.Json(new { error = "conflict", message = "The client changed at the same time. Try again." }, statusCode: 409); }
            return Results.Json(new { clientId, scopes });
        });
    }
}
