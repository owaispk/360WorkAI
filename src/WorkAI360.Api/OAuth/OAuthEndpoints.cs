using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;

namespace WorkAI360.Api.OAuth;

public sealed record AuthorizeRequest(OAuthClient Client, string RedirectUri, string Scope, string Resource, string CodeChallenge, string? State, string? Prompt, List<KeyValuePair<string, string>> Parameters);

/// <summary>
/// OAuth 2.1 authorization server for MCP clients: discovery (RFC 8414), dynamic registration (RFC 7591), authorization code
/// with PKCE S256, resource indicators (RFC 8707), refresh-token rotation and revocation (RFC 7009).
/// </summary>
public static class OAuthEndpoints
{
    public static void MapOAuthEndpoints(this WebApplication app)
    {
        // ---------- Discovery ----------
        foreach (var path in new[] { "/api/auth/.well-known/oauth-authorization-server", "/.well-known/oauth-authorization-server", "/.well-known/oauth-authorization-server/api/auth",
                                     "/api/auth/.well-known/openid-configuration", "/.well-known/openid-configuration", "/.well-known/openid-configuration/api/auth" })
        {
            app.MapGet(path, (OAuthUrls urls) => Results.Json(AuthorizationServerMetadata(urls)));
        }

        foreach (var path in new[] { "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource/mcp/agent",
                                     "/mcp/.well-known/oauth-protected-resource", "/mcp/agent/.well-known/oauth-protected-resource" })
        {
            app.MapGet(path, (OAuthUrls urls) => Results.Json(ProtectedResourceMetadata(urls)));
        }

        app.MapGet("/api/auth/jwks", async (SigningKeyStore keys) =>
            Results.Json(new { keys = (await keys.KeysAsync()).Select(k => new { kty = "EC", crv = "P-256", alg = "ES256", use = "sig", kid = k.Kid, x = k.X, y = k.Y }) }));

        // ---------- Dynamic client registration ----------
        app.MapPost("/register", RegisterAsync);
        app.MapPost("/api/auth/oauth2/register", RegisterAsync);

        // ---------- Authorization ----------
        app.MapGet("/api/auth/oauth2/authorize", AuthorizeAsync);
        app.MapPost("/api/auth/oauth2/public-client-prelogin", PreloginAsync);
        app.MapPost("/api/auth/oauth2/consent", ConsentAsync);

        // ---------- Tokens ----------
        app.MapPost("/api/auth/oauth2/token", TokenAsync);
        app.MapPost("/api/auth/oauth2/revoke", RevokeAsync);
    }

    // ============================== metadata ==============================

    public static object AuthorizationServerMetadata(OAuthUrls urls) => new
    {
        issuer = urls.Issuer,
        authorization_endpoint = urls.AuthorizationEndpoint,
        token_endpoint = urls.TokenEndpoint,
        registration_endpoint = urls.RegistrationEndpoint,
        revocation_endpoint = urls.RevocationEndpoint,
        jwks_uri = urls.JwksUri,
        scopes_supported = OAuthConstants.Scopes,
        response_types_supported = new[] { "code" },
        response_modes_supported = new[] { "query" },
        grant_types_supported = new[] { "authorization_code", "refresh_token" },
        token_endpoint_auth_methods_supported = new[] { "none", "client_secret_basic", "client_secret_post" },
        revocation_endpoint_auth_methods_supported = new[] { "none", "client_secret_basic", "client_secret_post" },
        code_challenge_methods_supported = new[] { "S256" },
        authorization_response_iss_parameter_supported = false,
        client_id_metadata_document_supported = false,
    };

    public static object ProtectedResourceMetadata(OAuthUrls urls) => new
    {
        resource = urls.CanonicalResource,
        authorization_servers = new[] { urls.Issuer },
        scopes_supported = OAuthConstants.Scopes,
        bearer_methods_supported = new[] { "header" },
    };

    // ============================== registration ==============================

    private static async Task<IResult> RegisterAsync(HttpContext ctx, DenDbContext db)
    {
        JsonElement body;
        try { body = (await JsonDocument.ParseAsync(ctx.Request.Body)).RootElement.Clone(); }
        catch (JsonException) { return Error(400, "invalid_client_metadata", "Registration request body must be valid JSON."); }
        if (body.ValueKind != JsonValueKind.Object) return Error(400, "invalid_client_metadata", "Registration request body must be a JSON object.");

        static List<string> Strings(JsonElement e, string name) =>
            e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Array ? v.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).ToList() : [];
        static string? Str(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

        var redirectUris = Strings(body, "redirect_uris");
        if (redirectUris.Count == 0 || redirectUris.Count > 10) return Error(400, "invalid_redirect_uri", "redirect_uris must list between 1 and 10 URIs.");
        if (redirectUris.Any(u => !RedirectPolicy.IsAllowed(u))) return Error(400, "invalid_redirect_uri", RedirectPolicy.ErrorDescription);

        var grantTypes = Strings(body, "grant_types");
        if (grantTypes.Count == 0) grantTypes = ["authorization_code", "refresh_token"];
        if (grantTypes.Any(g => g is not ("authorization_code" or "refresh_token"))) return Error(400, "invalid_client_metadata", "Only the authorization_code and refresh_token grants are supported.");
        var responseTypes = Strings(body, "response_types");
        if (responseTypes.Any(r => r != "code")) return Error(400, "invalid_client_metadata", "Only the code response type is supported.");

        var method = Str(body, "token_endpoint_auth_method") ?? "none";
        if (method is not ("none" or "client_secret_basic" or "client_secret_post")) return Error(400, "invalid_client_metadata", "Unsupported token_endpoint_auth_method.");

        var scopes = OAuthConstants.SplitScope(Str(body, "scope") ?? OAuthConstants.DefaultScope);
        if (scopes.Any(s => !OAuthConstants.Scopes.Contains(s))) return Error(400, "invalid_client_metadata", "Unsupported scope requested.");

        var name = (Str(body, "client_name") ?? "").Trim();
        if (name.Length > 120) return Error(400, "invalid_client_metadata", "client_name is too long.");
        var logo = Str(body, "logo_uri");
        if (logo is not null && !(Uri.TryCreate(logo, UriKind.Absolute, out var logoUri) && logoUri.Scheme == "https")) logo = null;

        var clientId = Ids.RandomAlnum(32);
        string? secret = method == "none" ? null : OAuthConstants.ClientSecretPrefix + Ids.RandomAlnum(40);
        var now = DateTime.UtcNow;
        db.OAuthClients.Add(new OAuthClient
        {
            Id = clientId,
            Name = name,
            RedirectUrisJson = JsonSerializer.Serialize(redirectUris),
            Scope = OAuthConstants.JoinScope(scopes),
            AuthMethod = method,
            SecretHash = secret is null ? null : Ids.Sha256Hex(secret),
            LogoUri = logo,
            CreatedAt = now,
        });
        await db.SaveChangesAsync();

        var response = new Dictionary<string, object?>
        {
            ["client_id"] = clientId,
            ["client_id_issued_at"] = new DateTimeOffset(now).ToUnixTimeSeconds(),
            ["client_name"] = name,
            ["redirect_uris"] = redirectUris,
            ["token_endpoint_auth_method"] = method,
            ["grant_types"] = grantTypes,
            ["response_types"] = new[] { "code" },
            ["scope"] = OAuthConstants.JoinScope(scopes),
        };
        if (secret is not null) { response["client_secret"] = secret; response["client_secret_expires_at"] = 0; }
        if (logo is not null) response["logo_uri"] = logo;
        ctx.Response.Headers.CacheControl = "no-store";
        return Results.Json(response, statusCode: 201);
    }

    // ============================== authorize ==============================

    /// <summary>Checks an authorization request. Returns the request, or the response to send instead.</summary>
    private static async Task<(AuthorizeRequest? Request, IResult? Failure)> ValidateAsync(IReadOnlyDictionary<string, string> p, DenDbContext db, OAuthUrls urls, bool signed)
    {
        p.TryGetValue("client_id", out var clientId);
        var client = string.IsNullOrEmpty(clientId) ? null : await db.OAuthClients.AsNoTracking().FirstOrDefaultAsync(c => c.Id == clientId);
        if (client is null) return (null, Error(400, "invalid_client", "Unknown client."));

        var registered = JsonSerializer.Deserialize<List<string>>(client.RedirectUrisJson) ?? [];
        p.TryGetValue("redirect_uri", out var redirectUri);
        if (string.IsNullOrEmpty(redirectUri) && registered.Count == 1) redirectUri = registered[0];
        if (string.IsNullOrEmpty(redirectUri) || !RedirectPolicy.IsAllowed(redirectUri) || !RedirectPolicy.Matches(registered, redirectUri))
            return (null, Error(400, "invalid_redirect_uri", "The redirect_uri does not match a registered URI."));

        // From here the redirect URI is trusted, so further problems go back to the client as an error redirect.
        p.TryGetValue("state", out var state);
        IResult Redirect(string error, string description) =>
            Results.Redirect(QueryHelpers.AddQueryString(redirectUri, ErrorParams(error, description, state)));

        var resource = urls.NormalizeResource(p.GetValueOrDefault("resource"));
        if (resource is null)
            return (null, Results.Json(new { error = "invalid_target", error_description = "MCP OAuth requests must include a protected resource this deployment recognizes." }, statusCode: 400));

        if (p.GetValueOrDefault("response_type") != "code") return (null, Redirect("unsupported_response_type", "Only response_type=code is supported."));

        var challenge = p.GetValueOrDefault("code_challenge");
        if (string.IsNullOrEmpty(challenge) || p.GetValueOrDefault("code_challenge_method") != "S256" || challenge.Length is < 43 or > 128)
            return (null, Redirect("invalid_request", "PKCE with code_challenge_method=S256 is required."));

        var requested = OAuthConstants.SplitScope(p.GetValueOrDefault("scope"));
        if (requested.Length == 0) requested = OAuthConstants.SplitScope(client.Scope);
        var allowed = OAuthConstants.SplitScope(client.Scope);
        if (requested.Any(s => !OAuthConstants.Scopes.Contains(s) || !allowed.Contains(s))) return (null, Redirect("invalid_scope", "The requested scope is not allowed for this client."));

        var parameters = p.Where(x => x.Key is not ("exp" or "sig")).Select(x => new KeyValuePair<string, string>(x.Key, x.Value)).ToList();
        _ = signed;
        return (new AuthorizeRequest(client, redirectUri, OAuthConstants.JoinScope(requested), resource, challenge, state, p.GetValueOrDefault("prompt"), parameters), null);
    }

    private static async Task<IResult> AuthorizeAsync(HttpContext ctx, DenDbContext db, SessionService sessions, SignedQuery signedQuery, OAuthUrls urls)
    {
        var raw = ctx.Request.Query.Where(q => q.Value.Count == 1).ToDictionary(q => q.Key, q => q.Value[0]!);
        if (ctx.Request.Query.Any(q => q.Value.Count != 1)) return Error(400, "invalid_request", "Repeated parameters are not allowed.");

        // The sign-in and consent pages send the person back here with the query this endpoint signed earlier.
        var signed = raw.ContainsKey("sig");
        var parameters = raw;
        if (signed)
        {
            var verified = signedQuery.Verify(ctx.Request.QueryString.Value);
            if (verified is null) return Error(400, "invalid_signature", "The OAuth request failed.");
            parameters = verified;
        }

        var (request, failure) = await ValidateAsync(parameters, db, urls, signed);
        if (failure is not null) return failure;
        var req = request!;
        var query = signedQuery.Sign(req.Parameters, OAuthConstants.AuthorizationRequestLifetime);

        var current = await sessions.ResolveAsync(ctx);
        if (current is null) return Results.Redirect($"{urls.Web}/?{query}");

        var orgId = current.Session.ActiveOrganizationId;
        var isMember = orgId is not null && await db.Members.AnyAsync(m => m.OrganizationId == orgId && m.UserId == current.User.Id);
        if (orgId is null || !isMember) return Results.Redirect($"{urls.Web}/mcp/select-organization?{query}");

        // Already allowed in this workspace and not asked to re-prompt: skip the consent screen.
        if (req.Prompt != "consent")
        {
            var consent = await db.OAuthConsents.AsNoTracking().FirstOrDefaultAsync(c => c.ClientId == req.Client.Id && c.UserId == current.User.Id && c.OrganizationId == orgId);
            if (consent is not null && OAuthConstants.SplitScope(req.Scope).All(OAuthConstants.SplitScope(consent.Scope).Contains))
                return Results.Redirect(await IssueCodeRedirectAsync(db, req, current.User.Id, orgId));
        }
        return Results.Redirect($"{urls.Web}/mcp/consent?{query}");
    }

    private static async Task<IResult> PreloginAsync(HttpContext ctx, DenDbContext db, SignedQuery signedQuery)
    {
        var body = await ReadParamsAsync(ctx.Request);
        var parameters = signedQuery.Verify(body.GetValueOrDefault("oauth_query"));
        if (parameters is null || parameters.GetValueOrDefault("client_id") != body.GetValueOrDefault("client_id")) return Error(400, "invalid_signature", "The OAuth request failed.");
        var client = await db.OAuthClients.AsNoTracking().FirstOrDefaultAsync(c => c.Id == parameters["client_id"]);
        if (client is null) return Error(400, "invalid_client", "Unknown client.");
        return Results.Json(new { client_id = client.Id, client_name = client.Name, logo_uri = client.LogoUri });
    }

    private static async Task<IResult> ConsentAsync(HttpContext ctx, DenDbContext db, SessionService sessions, SignedQuery signedQuery, OAuthUrls urls)
    {
        var current = await sessions.ResolveAsync(ctx);
        if (current is null) return Error(401, "unauthorized", "Sign in to continue.");

        JsonElement body;
        try { body = (await JsonDocument.ParseAsync(ctx.Request.Body)).RootElement.Clone(); }
        catch (JsonException) { return Error(400, "invalid_request", "Request body must be JSON."); }
        if (body.ValueKind != JsonValueKind.Object) return Error(400, "invalid_request", "Request body must be a JSON object.");

        var query = body.TryGetProperty("oauth_query", out var q) && q.ValueKind == JsonValueKind.String ? q.GetString() : null;
        var parameters = signedQuery.Verify(query);
        if (parameters is null) return Error(400, "invalid_signature", "The OAuth request failed.");

        var (request, failure) = await ValidateAsync(parameters, db, urls, signed: true);
        if (failure is not null) return failure;
        var req = request!;

        var accept = body.TryGetProperty("accept", out var a) && a.ValueKind == JsonValueKind.True;
        if (!accept)
            return Results.Json(new { url = QueryHelpers.AddQueryString(req.RedirectUri, ErrorParams("access_denied", "The person denied the request.", req.State)) });

        var granted = OAuthConstants.SplitScope(body.TryGetProperty("scope", out var s) && s.ValueKind == JsonValueKind.String ? s.GetString() : req.Scope);
        var requested = OAuthConstants.SplitScope(req.Scope);
        if (granted.Length == 0) granted = requested;
        if (granted.Any(x => !requested.Contains(x))) return Error(400, "invalid_scope", "The granted scope exceeds what the client asked for.");

        var orgId = current.Session.ActiveOrganizationId;
        if (orgId is null) return Error(400, "invalid_request", "Select an organization before authorizing MCP access.");
        if (!await db.Members.AnyAsync(m => m.OrganizationId == orgId && m.UserId == current.User.Id)) return Error(403, "access_denied", "You are not a member of this organization.");

        var scope = OAuthConstants.JoinScope(granted);
        var now = DateTime.UtcNow;
        var consent = await db.OAuthConsents.FirstOrDefaultAsync(c => c.ClientId == req.Client.Id && c.UserId == current.User.Id && c.OrganizationId == orgId);
        if (consent is null)
            db.OAuthConsents.Add(new OAuthConsent { Id = Ids.New("ocn"), ClientId = req.Client.Id, UserId = current.User.Id, OrganizationId = orgId, Scope = scope, CreatedAt = now, UpdatedAt = now });
        else { consent.Scope = OAuthConstants.JoinScope(OAuthConstants.SplitScope(consent.Scope).Concat(granted)); consent.UpdatedAt = now; }
        await db.SaveChangesAsync();

        return Results.Json(new { url = await IssueCodeRedirectAsync(db, req with { Scope = scope }, current.User.Id, orgId) });
    }

    private static async Task<string> IssueCodeRedirectAsync(DenDbContext db, AuthorizeRequest req, string userId, string orgId)
    {
        var code = Ids.RandomAlnum(48);
        db.AuthorizationCodes.Add(new AuthorizationCode
        {
            Id = Ids.Sha256Hex(code),
            ClientId = req.Client.Id,
            UserId = userId,
            OrganizationId = orgId,
            RedirectUri = req.RedirectUri,
            Scope = req.Scope,
            Resource = req.Resource,
            CodeChallenge = req.CodeChallenge,
            ExpiresAt = DateTime.UtcNow + OAuthConstants.CodeLifetime,
        });
        await db.SaveChangesAsync();
        var ps = new Dictionary<string, string?> { ["code"] = code };
        if (req.State is not null) ps["state"] = req.State;
        return QueryHelpers.AddQueryString(req.RedirectUri, ps);
    }

    // ============================== tokens ==============================

    private static async Task<IResult> TokenAsync(HttpContext ctx, DenDbContext db, TokenService tokens, OAuthUrls urls)
    {
        ctx.Response.Headers.CacheControl = "no-store";
        ctx.Response.Headers.Pragma = "no-cache";
        var form = await ReadParamsAsync(ctx.Request);

        var (client, clientFailure) = await AuthenticateClientAsync(ctx, db, form);
        if (clientFailure is not null) return clientFailure;

        return form.GetValueOrDefault("grant_type") switch
        {
            "authorization_code" => await AuthorizationCodeGrantAsync(client!, form, db, tokens, urls),
            "refresh_token" => await RefreshGrantAsync(client!, form, db, tokens, urls),
            _ => Error(400, "unsupported_grant_type", "Only authorization_code and refresh_token are supported."),
        };
    }

    private static async Task<IResult> AuthorizationCodeGrantAsync(OAuthClient client, Dictionary<string, string> form, DenDbContext db, TokenService tokens, OAuthUrls urls)
    {
        var code = form.GetValueOrDefault("code");
        if (string.IsNullOrEmpty(code)) return Error(400, "invalid_request", "code is required.");
        var hash = Ids.Sha256Hex(code);
        var row = await db.AuthorizationCodes.AsNoTracking().FirstOrDefaultAsync(c => c.Id == hash);
        if (row is null || row.ClientId != client.Id) return Error(400, "invalid_grant", "Invalid authorization code.");

        // A code presented twice means it may have been stolen: revoke what the first use produced.
        if (row.ConsumedAt is not null)
        {
            await tokens.RevokeByCodeAsync(hash);
            return Error(400, "invalid_grant", "This authorization code was already used.");
        }
        if (row.ExpiresAt <= DateTime.UtcNow) return Error(400, "invalid_grant", "The authorization code has expired.");
        if (form.TryGetValue("redirect_uri", out var redirect) && redirect != row.RedirectUri) return Error(400, "invalid_grant", "redirect_uri does not match the authorization request.");

        var verifier = form.GetValueOrDefault("code_verifier");
        if (verifier is null || verifier.Length is < 43 or > 128 || !verifier.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '~'))
            return Error(400, "invalid_grant", "A valid code_verifier is required.");
        var expected = SigningKeyStore.Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(expected), Encoding.ASCII.GetBytes(row.CodeChallenge)))
            return Error(400, "invalid_grant", "The code_verifier does not match the code_challenge.");

        if (form.TryGetValue("resource", out var requestedResource) && urls.NormalizeResource(requestedResource) != row.Resource)
            return Error(400, "invalid_target", "The requested resource does not match the authorization request.");

        // Exactly one caller can flip ConsumedAt from null.
        var claimed = await db.AuthorizationCodes.Where(c => c.Id == hash && c.ConsumedAt == null).ExecuteUpdateAsync(s => s.SetProperty(c => c.ConsumedAt, DateTime.UtcNow));
        if (claimed == 0)
        {
            await tokens.RevokeByCodeAsync(hash);
            return Error(400, "invalid_grant", "This authorization code was already used.");
        }

        if (!await db.Members.AnyAsync(m => m.OrganizationId == row.OrganizationId && m.UserId == row.UserId))
            return Error(400, "invalid_grant", "The person is no longer a member of this organization.");

        return Results.Json(await tokens.IssueAsync(client.Id, row.UserId, row.OrganizationId, row.Scope, row.Resource, hash));
    }

    private static async Task<IResult> RefreshGrantAsync(OAuthClient client, Dictionary<string, string> form, DenDbContext db, TokenService tokens, OAuthUrls urls)
    {
        var presented = form.GetValueOrDefault("refresh_token");
        if (string.IsNullOrEmpty(presented)) return Error(400, "invalid_request", "refresh_token is required.");
        var row = await db.RefreshTokens.FirstOrDefaultAsync(t => t.Id == Ids.Sha256Hex(presented));
        if (row is null || row.ClientId != client.Id || row.RevokedAt is not null || row.ExpiresAt <= DateTime.UtcNow)
            return Error(400, "invalid_grant", "Invalid refresh token.");

        var now = DateTime.UtcNow;
        if (row.RotatedAt is { } rotatedAt && now - rotatedAt > OAuthConstants.RefreshReuseInterval)
        {
            // A token that was already exchanged is back: assume theft and end the whole family.
            await tokens.RevokeFamilyAsync(row.FamilyId);
            return Error(400, "invalid_grant", "This refresh token was already used.");
        }

        if (form.TryGetValue("resource", out var resource) && urls.NormalizeResource(resource) != row.Resource)
            return Error(400, "invalid_target", "The requested resource does not match the original grant.");

        var scope = row.Scope;
        if (form.TryGetValue("scope", out var requestedScope))
        {
            var narrowed = OAuthConstants.SplitScope(requestedScope);
            if (narrowed.Any(s => !OAuthConstants.SplitScope(row.Scope).Contains(s))) return Error(400, "invalid_scope", "A refresh cannot add scopes.");
            if (narrowed.Length > 0) scope = OAuthConstants.JoinScope(narrowed);
        }

        if (!await db.Members.AnyAsync(m => m.OrganizationId == row.OrganizationId && m.UserId == row.UserId))
        {
            await tokens.RevokeFamilyAsync(row.FamilyId);
            return Error(400, "invalid_grant", "The person is no longer a member of this organization.");
        }

        row.RotatedAt ??= now;
        await db.SaveChangesAsync();
        // The new token keeps offline_access so the client can keep refreshing.
        var issuedScope = OAuthConstants.SplitScope(row.Scope).Contains(OAuthConstants.OfflineScope) ? OAuthConstants.JoinScope(OAuthConstants.SplitScope(scope).Append(OAuthConstants.OfflineScope)) : scope;
        return Results.Json(await tokens.IssueAsync(client.Id, row.UserId, row.OrganizationId, issuedScope, row.Resource, row.CodeHash, row.FamilyId));
    }

    private static async Task<IResult> RevokeAsync(HttpContext ctx, DenDbContext db, TokenService tokens)
    {
        var form = await ReadParamsAsync(ctx.Request);
        var (client, failure) = await AuthenticateClientAsync(ctx, db, form);
        if (failure is not null) return failure;

        // RFC 7009: the response never reveals whether the token existed.
        if (form.GetValueOrDefault("token") is { Length: > 0 } token)
        {
            var hash = Ids.Sha256Hex(token);
            var refresh = await db.RefreshTokens.AsNoTracking().FirstOrDefaultAsync(t => t.Id == hash && t.ClientId == client!.Id);
            if (refresh is not null) await tokens.RevokeFamilyAsync(refresh.FamilyId);
            else await db.McpAccessTokens.Where(t => t.Id == hash).ExecuteDeleteAsync();
        }
        return Results.Json(new { });
    }

    // ============================== helpers ==============================

    private static async Task<(OAuthClient? Client, IResult? Failure)> AuthenticateClientAsync(HttpContext ctx, DenDbContext db, Dictionary<string, string> form)
    {
        string? id = form.GetValueOrDefault("client_id"), secret = form.GetValueOrDefault("client_secret");
        var header = ctx.Request.Headers.Authorization.ToString();
        if (header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(header[6..].Trim()));
                var colon = decoded.IndexOf(':');
                if (colon > 0) { id = Uri.UnescapeDataString(decoded[..colon]); secret = Uri.UnescapeDataString(decoded[(colon + 1)..]); }
            }
            catch (FormatException) { return (null, InvalidClient()); }
        }
        if (string.IsNullOrEmpty(id)) return (null, Error(400, "invalid_request", "client_id is required."));

        var client = await db.OAuthClients.AsNoTracking().FirstOrDefaultAsync(c => c.Id == id);
        if (client is null) return (null, InvalidClient());
        if (client.AuthMethod != "none")
        {
            if (string.IsNullOrEmpty(secret) || client.SecretHash is null
                || !CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Ids.Sha256Hex(secret)), Encoding.ASCII.GetBytes(client.SecretHash)))
                return (null, InvalidClient());
        }
        return (client, null);
    }

    private static IResult InvalidClient() => Results.Json(new { error = "invalid_client", error_description = "Client authentication failed." }, statusCode: 401);

    /// <summary>Reads form-encoded or JSON parameters (token and revocation endpoints accept both in practice).</summary>
    private static async Task<Dictionary<string, string>> ReadParamsAsync(HttpRequest request)
    {
        var result = new Dictionary<string, string>();
        if (request.HasFormContentType)
        {
            foreach (var (key, value) in await request.ReadFormAsync()) if (value.Count == 1) result[key] = value[0]!;
            return result;
        }
        try
        {
            using var doc = await JsonDocument.ParseAsync(request.Body);
            if (doc.RootElement.ValueKind == JsonValueKind.Object)
                foreach (var p in doc.RootElement.EnumerateObject()) if (p.Value.ValueKind == JsonValueKind.String) result[p.Name] = p.Value.GetString()!;
        }
        catch (JsonException) { }
        return result;
    }

    private static Dictionary<string, string?> ErrorParams(string error, string description, string? state)
    {
        var ps = new Dictionary<string, string?> { ["error"] = error, ["error_description"] = description };
        if (state is not null) ps["state"] = state;
        return ps;
    }

    private static IResult Error(int status, string error, string description) =>
        Results.Json(new { error, error_description = description }, statusCode: status);
}
