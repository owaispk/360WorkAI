using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.Sso;
using WorkAI360.Api.Endpoints;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Features.Sso;

/// <summary>
/// OpenID Connect sign-in (authorization code with PKCE). Each attempt has a state value that works once, for one connection, in the
/// browser that started it; the ID token must carry the attempt's nonce; the code is exchanged server to server with the stored secret.
/// </summary>
public sealed class OidcFlow(
    DenDbContext db, SsoService sso, SecretProtector secrets, IHttpClientFactory http, SessionService sessions, TrustedUrls trusted,
    OAuthUrls urls, SsoProvisioning provisioning)
{
    public const string BindingCookie = "openwork-den.sso_state";
    public static readonly TimeSpan StateLifetime = TimeSpan.FromMinutes(10);

    public sealed record Start(string CallbackUrl, string? ErrorCallbackUrl, string? NewUserCallbackUrl, string? LoginHint, string? TestIntentId);

    public async Task<string> StartAsync(HttpContext ctx, SsoConnection c, Start start, CancellationToken ct)
    {
        var settings = SsoService.Settings(c) ?? throw new InvalidOperationException("Not an OIDC connection.");
        var state = Token(32);
        var verifier = Token(32);
        var nonce = Token(24);
        var binding = Token(32);
        var now = DateTime.UtcNow;
        db.Add(new SsoAuthState
        {
            Id = Ids.Sha256Hex(state), ProviderId = c.ProviderId, ConfigRevision = c.ConfigRevision, BrowserBindingHash = Ids.Sha256Hex(binding), NonceHash = Ids.Sha256Hex(nonce),
            CodeVerifierProtected = secrets.Protect(verifier), CallbackUrl = start.CallbackUrl, ErrorCallbackUrl = start.ErrorCallbackUrl, NewUserCallbackUrl = start.NewUserCallbackUrl,
            TestIntentId = start.TestIntentId, CreatedAt = now, ExpiresAt = now.Add(StateLifetime),
        });
        await db.SaveChangesAsync(ct);
        // Old attempts are useless: keep the table small.
        await db.Set<SsoAuthState>().Where(s => s.ExpiresAt < now.AddHours(-1)).ExecuteDeleteAsync(ct);

        ctx.Response.Cookies.Append(BindingCookie, binding, new CookieOptions { HttpOnly = true, SameSite = SameSiteMode.Lax, Secure = ctx.Request.IsHttps, Path = "/", MaxAge = StateLifetime });

        var challenge = Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(verifier))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var query = new List<KeyValuePair<string, string>>
        {
            new("response_type", "code"), new("client_id", settings.ClientId), new("redirect_uri", sso.RedirectUrl(c.ProviderId)), new("scope", string.Join(' ', settings.Scopes)),
            new("state", state), new("nonce", nonce), new("code_challenge", challenge), new("code_challenge_method", "S256"),
        };
        if (!string.IsNullOrWhiteSpace(start.LoginHint)) query.Add(new("login_hint", start.LoginHint));
        var separator = settings.AuthorizationEndpoint.Contains('?') ? "&" : "?";
        return settings.AuthorizationEndpoint + separator + string.Join('&', query.Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}"));
    }

    /// <summary>What the browser gets back when the identity provider sends the person to us.</summary>
    public async Task<IResult> CallbackAsync(HttpContext ctx, string providerId, CancellationToken ct)
    {
        var query = ctx.Request.Query;
        var c = await db.Set<SsoConnection>().FirstOrDefaultAsync(o => o.ProviderId == providerId, ct);
        if (c is null || c.Kind != "oidc") return LocalError("state_mismatch");

        var stateValue = query["state"].ToString();
        var stateId = Ids.Sha256Hex(stateValue);
        var now = DateTime.UtcNow;
        var state = stateValue.Length == 0 ? null : await db.Set<SsoAuthState>().FirstOrDefaultAsync(s => s.Id == stateId, ct);

        // A disabled connection signs nobody in, except for an administrator's current test that was started from this very state.
        var liveTest = state?.TestIntentId is { } intent && SsoService.IsLiveTest(c, intent);
        if (!SsoService.Ready(c) && !liveTest) return Results.Json(new { error = "sso_not_enabled", message = "This disabled SSO provider cannot authenticate without a current administrator test." }, statusCode: 403);

        if (state is null || state.ProviderId != c.ProviderId || state.ExpiresAt <= now || state.ConsumedAt is not null) return LocalError("state_mismatch");
        // The state must come back in the browser that began the sign-in, or an attacker could hand a victim a code of their own (login CSRF).
        var binding = ctx.Request.Cookies[BindingCookie];
        if (string.IsNullOrEmpty(binding) || !SsoService.FixedEquals(Ids.Sha256Hex(binding), state.BrowserBindingHash)) return LocalError("state_mismatch");
        // Single use, even when the rest fails.
        var claimed = await db.Set<SsoAuthState>().Where(s => s.Id == stateId && s.ConsumedAt == null).ExecuteUpdateAsync(s => s.SetProperty(x => x.ConsumedAt, now), ct);
        if (claimed != 1) return LocalError("state_mismatch");
        ctx.Response.Cookies.Delete(BindingCookie, new CookieOptions { Path = "/" });

        async Task<IResult> Fail(string code, string? description)
        {
            if (state.TestIntentId is { } testIntent) await sso.FailTestAsync(testIntent, "authentication");
            return Redirect(AppendQuery(state.ErrorCallbackUrl ?? state.CallbackUrl, ("error", code), ("error_description", Clip(description))));
        }

        if (state.ConfigRevision != c.ConfigRevision) return await Fail("invalid_state", "sso_provider_changed_during_authentication");
        if (query.ContainsKey("error")) return await Fail(Clip(query["error"].ToString()) ?? "invalid_request", query["error_description"].ToString());
        // RFC 9207: when the provider says who answered, it must be the provider we asked.
        if (query.ContainsKey("iss") && query["iss"].ToString() != c.Issuer) return await Fail("invalid_state", "issuer_mismatch");
        var code = query["code"].ToString();
        if (code.Length == 0 || code.Length > 4096) return await Fail("invalid_request", "authorization_code_not_found");
        var settings = SsoService.Settings(c);
        if (settings is null || c.ClientSecretProtected is null) return await Fail("invalid_provider", "provider not found");

        string idToken, jwks;
        try
        {
            var client = http.CreateClient(IdpHttp.ClientName);
            using var tokenRequest = new HttpRequestMessage(HttpMethod.Post, settings.TokenEndpoint);
            var form = new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code", ["code"] = code, ["redirect_uri"] = sso.RedirectUrl(c.ProviderId), ["code_verifier"] = secrets.Unprotect(state.CodeVerifierProtected),
            };
            var secret = secrets.Unprotect(c.ClientSecretProtected);
            if (settings.TokenEndpointAuthentication == "client_secret_post") { form["client_id"] = settings.ClientId; form["client_secret"] = secret; }
            else tokenRequest.Headers.Authorization = new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Uri.EscapeDataString(settings.ClientId)}:{Uri.EscapeDataString(secret)}")));
            tokenRequest.Content = new FormUrlEncodedContent(form);
            tokenRequest.Headers.Accept.ParseAdd("application/json");
            using var tokenResponse = await client.SendAsync(tokenRequest, ct);
            if (!tokenResponse.IsSuccessStatusCode) return await Fail("invalid_provider", "token_response_error");
            using var tokenDoc = JsonDocument.Parse(await IdpHttp.ReadLimitedAsync(tokenResponse, ct));
            if (!tokenDoc.RootElement.TryGetProperty("id_token", out var idTokenElement) || idTokenElement.ValueKind != JsonValueKind.String) return await Fail("invalid_provider", "id_token_missing");
            idToken = idTokenElement.GetString()!;

            using var jwksResponse = await client.GetAsync(settings.JwksEndpoint, ct);
            if (!jwksResponse.IsSuccessStatusCode) return await Fail("invalid_provider", "jwks_unavailable");
            jwks = await IdpHttp.ReadLimitedAsync(jwksResponse, ct);
        }
        catch (Exception e) when (e is HttpRequestException or JsonException or InvalidDataException or TaskCanceledException or CryptographicException)
        {
            return await Fail("invalid_provider", "token_response_error");
        }

        JsonElement claims;
        try
        {
            claims = IdTokenValidator.Validate(idToken, jwks, new IdTokenValidator.Expected(c.Issuer, settings.ClientId, state.NonceHash, DateTimeOffset.UtcNow));
        }
        catch (OidcException e) { return await Fail(e.Code, e.Message); }

        string? Claim(string name) => claims.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String && v.GetString()!.Length > 0 ? v.GetString() : null;
        var email = Claim("email");
        if (email is null) return await Fail("invalid_provider", "missing_user_info");
        var identity = new SsoIdentity(Claim("sub")!, email, Claim("name"));

        var testing = state.TestIntentId is not null;
        var resolution = await provisioning.ResolveUserAsync(c, identity, mayCreate: !testing, ct);
        if (resolution.User is null) return await Fail(resolution.ErrorCode!, resolution.ErrorMessage);
        var user = resolution.User;

        if (testing)
        {
            // An administrator's test proves the provider works; it signs nobody in and replaces no session.
            var done = await sso.CompleteTestAsync(state.TestIntentId!, c.ProviderId, user.Id);
            return Redirect(done ? state.CallbackUrl : AppendQuery(state.ErrorCallbackUrl ?? state.CallbackUrl, ("error", "access_denied")));
        }

        if (await provisioning.ProvisionAsync(c, user, identity, Claim("name"), ct) is { } refusal) return await Fail("access_denied", refusal);

        var isNew = user.CreatedAt > now.AddMinutes(-1) && !await db.Sessions.AnyAsync(s => s.UserId == user.Id, ct);
        var (token, session) = await sessions.CreateAsync(user, c.OrganizationId, "sso", ctx);
        sessions.WriteCookie(ctx, token, session);
        return Redirect(isNew && state.NewUserCallbackUrl is { } nu ? nu : state.CallbackUrl);
    }

    private IResult Redirect(string url) => Results.Redirect(trusted.Absolute(url));

    private IResult LocalError(string code) => Results.Redirect($"{urls.Web}/connect/error?error={Uri.EscapeDataString(code)}");

    private static string? Clip(string? value) => string.IsNullOrWhiteSpace(value) ? null : (value.Length > 200 ? value[..200] : value);

    public static string AppendQuery(string url, params (string Key, string? Value)[] items)
    {
        var sb = new StringBuilder(url);
        var first = !url.Contains('?');
        foreach (var (key, value) in items)
        {
            if (value is null) continue;
            sb.Append(first ? '?' : '&').Append(Uri.EscapeDataString(key)).Append('=').Append(Uri.EscapeDataString(value));
            first = false;
        }
        return sb.ToString();
    }

    private static string Token(int bytes) => SsoService.Base64Url(RandomNumberGenerator.GetBytes(bytes));
}
