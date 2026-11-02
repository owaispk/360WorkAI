using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.Oidc;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Features.Oidc;

/// <summary>
/// OpenID Connect RP-Initiated Logout 1.0 at <c>/api/auth/oauth2/end-session</c>, with the reference's rules. A client that is allowed to log
/// people out presents the ID token it was issued (<c>id_token_hint</c>); if that token names the browser's current session, the session ends and
/// the browser may be sent to a registered <c>post_logout_redirect_uri</c>. Anything else (no hint, a hint for another session, a bad hint) needs
/// the person's own confirmation on a page this server serves, bound to the browser by a short-lived signed cookie. Only clients registered by a
/// signed-in person can be allowed to do this at all.
/// </summary>
public static class EndSessionEndpoints
{
    private const string ConfirmPath = "/api/auth/oauth2/end-session/confirm";
    private static readonly TimeSpan ConfirmLifetime = TimeSpan.FromMinutes(5);

    public static void Map(WebApplication app)
    {
        app.MapMethods("/api/auth/oauth2/end-session", ["GET", "POST"], EndSessionAsync);
        app.MapPost(ConfirmPath, ConfirmAsync);
    }

    private sealed record Context(DenDbContext Db, SessionService Sessions, SigningKeyStore Keys, OAuthUrls Urls, SignedQuery Signed, IOptions<AuthOptions> Options, ClientResolver Clients);

    private static async Task<IResult> EndSessionAsync(HttpContext http, DenDbContext db, SessionService sessions, SigningKeyStore keys, OAuthUrls urls, SignedQuery signed, IOptions<AuthOptions> options, ClientResolver clients)
    {
        var c = new Context(db, sessions, keys, urls, signed, options, clients);
        http.Response.Headers.CacheControl = "no-store";
        var request = new Dictionary<string, string>();
        foreach (var (k, v) in http.Request.Query) if (v.Count == 1 && v[0] is { } qv) request[k] = qv;
        if (http.Request.Method == "POST" && http.Request.HasFormContentType)
            foreach (var (k, v) in await http.Request.ReadFormAsync()) if (v.Count == 1 && v[0] is { } fv) request[k] = fv;

        var current = await CurrentSessionAsync(http, c);
        var hint = request.GetValueOrDefault("id_token_hint");

        if (hint is null)
        {
            Confirmation confirmation = new(null, null, null, false);
            if (request.GetValueOrDefault("client_id") is { Length: > 0 } clientId)
            {
                var (client, settings) = await LoadClientAsync(c, clientId);
                if (client is null) return Fail(http, 400, "invalid_client", "The logout client does not exist");
                if (settings is not { EnableEndSession: true }) return Fail(http, 401, "invalid_client", "The client is not allowed to initiate logout");
                confirmation = ConfirmationFor(client.Id, settings, request);
            }
            return ConfirmationRequired(http, c, current, confirmation);
        }

        // A hint names the client by its audience; a client_id parameter must agree.
        var hintedClientId = request.GetValueOrDefault("client_id") ?? AudienceOf(hint);
        var (hintClient, hintSettings) = hintedClientId is null ? (null, null) : await LoadClientAsync(c, hintedClientId);
        if (hintClient is null)
        {
            if (current is not null && IsBrowserNavigation(http)) return ConfirmationRequired(http, c, current, new(null, null, null, false));
            return Fail(http, 400, "invalid_client", "The logout client does not exist");
        }
        if (hintSettings is not { EnableEndSession: true }) return Fail(http, 401, "invalid_client", "The client is not allowed to initiate logout");

        var payload = await VerifyHintAsync(c, hint, hintClient.Id);
        if (payload is null)
        {
            if (current is not null && IsBrowserNavigation(http)) return ConfirmationRequired(http, c, current, ConfirmationFor(hintClient.Id, hintSettings, request));
            return Fail(http, 401, "invalid_token", "The id_token_hint is invalid");
        }

        var sessionId = payload;
        var matchesCurrent = current is not null && current.Id == sessionId;
        // A hint for some other session than this browser's is the person's call, not the client's.
        if (current is not null && !matchesCurrent) return ConfirmationRequired(http, c, current, ConfirmationFor(hintClient.Id, hintSettings, request));

        var redirect = RegisteredRedirect(hintSettings, request.GetValueOrDefault("post_logout_redirect_uri"), request.GetValueOrDefault("state"));
        await TerminateAsync(c, sessionId);
        if (matchesCurrent) sessions.ClearCookie(http);
        ClearConfirmationCookie(http, c);
        return Done(http, redirect);
    }

    private static async Task<IResult> ConfirmAsync(HttpContext http, DenDbContext db, SessionService sessions, SigningKeyStore keys, OAuthUrls urls, SignedQuery signed, IOptions<AuthOptions> options, ClientResolver clients)
    {
        var c = new Context(db, sessions, keys, urls, signed, options, clients);
        http.Response.Headers.CacheControl = "no-store";
        var form = http.Request.HasFormContentType ? await http.Request.ReadFormAsync() : null;
        if (form is null || form["action"] != "confirm") return Fail(http, 400, "invalid_request", "The logout confirmation is invalid or expired");

        var state = ReadConfirmation(http, c);
        var current = await CurrentSessionAsync(http, c);
        if (state is null) return Fail(http, 400, "invalid_request", "The logout confirmation is invalid or expired");

        string? redirect = null;
        var redirectInvalid = state.Value.RedirectInvalid;
        if (!redirectInvalid && state.Value.ClientId is { } clientId && state.Value.PostLogoutRedirectUri is { } uri)
        {
            var (client, settings) = await LoadClientAsync(c, clientId);
            if (client is null || settings is not { EnableEndSession: true }) redirectInvalid = true;
            else { redirect = RegisteredRedirect(settings, uri, state.Value.State); redirectInvalid = redirect is null; }
        }

        if (current is null)
        {
            ClearConfirmationCookie(http, c);
            if (redirect is not null) return Results.Redirect(redirect);
            return IsBrowserNavigation(http) ? Page(200, "Logged out", SuccessBody(redirectInvalid)) : Fail(http, 400, "invalid_request", "No active session is available for logout");
        }
        // The confirmation was issued for one session; it must not end another.
        if (state.Value.SessionId is { } expected && expected != current.Id) return Fail(http, 400, "invalid_request", "The logout confirmation is invalid or expired");

        await TerminateAsync(c, current.Id);
        c.Sessions.ClearCookie(http);
        ClearConfirmationCookie(http, c);
        if (redirect is not null) return Results.Redirect(redirect);
        return IsBrowserNavigation(http) ? Page(200, "Logged out", SuccessBody(redirectInvalid)) : Results.Text("null", "application/json");
    }

    // ============================== helpers ==============================

    private static async Task<Session?> CurrentSessionAsync(HttpContext http, Context c)
    {
        // The browser's own cookie only: a bearer token is not "this browser".
        var token = c.Sessions.ReadCookieToken(http.Request);
        if (token is null) return null;
        var hash = Ids.Sha256Hex(token);
        var now = DateTime.UtcNow;
        return await c.Db.Sessions.AsNoTracking().FirstOrDefaultAsync(s => s.TokenHash == hash && s.ExpiresAt > now);
    }

    private static async Task<(OAuthClient? Client, OidcClientSettings? Settings)> LoadClientAsync(Context c, string clientId)
    {
        var client = await c.Clients.ResolveAsync(clientId);
        if (client is null) return (null, null);
        return (client, await c.Db.Set<OidcClientSettings>().AsNoTracking().FirstOrDefaultAsync(s => s.ClientId == client.Id));
    }

    /// <summary>Deletes the session and revokes the refresh tokens that were issued to clients during it (the MCP grants stay).</summary>
    private static async Task TerminateAsync(Context c, string sessionId)
    {
        var codeHashes = await c.Db.Set<OidcGrant>().Where(g => g.SessionId == sessionId).Select(g => g.Id).ToListAsync();
        if (codeHashes.Count > 0)
            await c.Db.RefreshTokens.Where(t => t.CodeHash != null && codeHashes.Contains(t.CodeHash) && t.RevokedAt == null).ExecuteUpdateAsync(s => s.SetProperty(t => t.RevokedAt, DateTime.UtcNow));
        await c.Db.Sessions.Where(s => s.Id == sessionId).ExecuteDeleteAsync();
    }

    private static string? AudienceOf(string jwt)
    {
        var parts = jwt.Split('.');
        if (parts.Length != 3) return null;
        try
        {
            using var doc = JsonDocument.Parse(SigningKeyStore.FromBase64Url(parts[1]));
            if (!doc.RootElement.TryGetProperty("aud", out var aud)) return null;
            if (aud.ValueKind == JsonValueKind.String) return aud.GetString();
            return aud.ValueKind == JsonValueKind.Array && aud.GetArrayLength() == 1 && aud[0].ValueKind == JsonValueKind.String ? aud[0].GetString() : null;
        }
        catch (Exception e) when (e is JsonException or FormatException) { return null; }
    }

    /// <summary>The hint's session id when it is a genuine ID token of ours for this client (an expired one is fine, OIDC RP-Initiated Logout 2).</summary>
    private static async Task<string?> VerifyHintAsync(Context c, string hint, string clientId)
    {
        if (Jwt.Verify(hint, await c.Keys.KeysAsync()) is not { } p) return null;
        string? Str(string name) => p.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        if (Str("iss") != c.Urls.Issuer || Str("aud") != clientId || Str("sub") is not { Length: > 0 } || Str("sid") is not { Length: > 0 } sid) return null;
        return sid;
    }

    private static string? RegisteredRedirect(OidcClientSettings settings, string? requested, string? state)
    {
        if (string.IsNullOrEmpty(requested)) return null;
        var registered = settings.PostLogoutRedirectUrisJson is null ? [] : JsonSerializer.Deserialize<List<string>>(settings.PostLogoutRedirectUrisJson) ?? [];
        if (!registered.Contains(requested, StringComparer.Ordinal)) return null;   // exact match only: never a prefix, never a pattern
        return string.IsNullOrEmpty(state) ? requested : QueryHelpers.AddQueryString(requested, "state", state);
    }

    private readonly record struct Confirmation(string? ClientId, string? PostLogoutRedirectUri, string? State, bool RedirectInvalid);

    private static Confirmation ConfirmationFor(string clientId, OidcClientSettings settings, Dictionary<string, string> request)
    {
        var uri = request.GetValueOrDefault("post_logout_redirect_uri");
        if (string.IsNullOrEmpty(uri)) return new(null, null, null, false);
        return RegisteredRedirect(settings, uri, null) is null ? new(null, null, null, true) : new(clientId, uri, request.GetValueOrDefault("state"), false);
    }

    // ---------- confirmation page and its cookie ----------

    private static IResult ConfirmationRequired(HttpContext http, Context c, Session? current, Confirmation confirmation)
    {
        if (current is null)
        {
            if (!IsBrowserNavigation(http)) return Fail(http, 400, "invalid_request", "No active session is available for logout");
            SetConfirmationCookie(http, c, null, confirmation);
            return Page(200, "Confirm logout", ConfirmBody(), RedirectOrigin(confirmation));
        }
        if (!IsBrowserNavigation(http)) return Fail(http, 400, "invalid_request", "User confirmation is required to complete logout");
        SetConfirmationCookie(http, c, current.Id, confirmation);
        return Page(200, "Confirm logout", ConfirmBody(), RedirectOrigin(confirmation));
    }

    private static string CookieName(Context c) => $"{c.Options.Value.CookieName}.oauth_logout_confirmation";

    private static void SetConfirmationCookie(HttpContext http, Context c, string? sessionId, Confirmation confirmation)
    {
        var pairs = new List<KeyValuePair<string, string>> { new("purpose", "end_session") };
        if (sessionId is not null) pairs.Add(new("sid", sessionId));
        if (confirmation.ClientId is not null) pairs.Add(new("client_id", confirmation.ClientId));
        if (confirmation.PostLogoutRedirectUri is not null) pairs.Add(new("uri", confirmation.PostLogoutRedirectUri));
        if (confirmation.State is not null) pairs.Add(new("state", confirmation.State));
        if (confirmation.RedirectInvalid) pairs.Add(new("redirect_invalid", "1"));
        http.Response.Cookies.Append(CookieName(c), c.Signed.Sign(pairs, ConfirmLifetime), new CookieOptions
        {
            HttpOnly = true, SameSite = SameSiteMode.Lax, Secure = http.Request.IsHttps, Path = ConfirmPath, MaxAge = ConfirmLifetime,
        });
    }

    private static (string? SessionId, string? ClientId, string? PostLogoutRedirectUri, string? State, bool RedirectInvalid)? ReadConfirmation(HttpContext http, Context c)
    {
        if (!http.Request.Cookies.TryGetValue(CookieName(c), out var raw)) return null;
        var p = c.Signed.Verify(raw);
        if (p is null || p.GetValueOrDefault("purpose") != "end_session") return null;
        return (p.GetValueOrDefault("sid"), p.GetValueOrDefault("client_id"), p.GetValueOrDefault("uri"), p.GetValueOrDefault("state"), p.ContainsKey("redirect_invalid"));
    }

    private static void ClearConfirmationCookie(HttpContext http, Context c) =>
        http.Response.Cookies.Append(CookieName(c), "", new CookieOptions { HttpOnly = true, SameSite = SameSiteMode.Lax, Secure = http.Request.IsHttps, Path = ConfirmPath, MaxAge = TimeSpan.Zero, Expires = DateTimeOffset.UnixEpoch });

    private static bool IsBrowserNavigation(HttpContext http)
    {
        var headers = http.Request.Headers;
        var mode = headers["Sec-Fetch-Mode"].ToString();
        if (mode is "cors" or "same-origin" or "no-cors") return false;
        var accept = headers.Accept.ToString();
        return mode == "navigate" || accept.Contains("text/html", StringComparison.OrdinalIgnoreCase) || accept.Contains("application/xhtml+xml", StringComparison.OrdinalIgnoreCase);
    }

    private static IResult Done(HttpContext http, string? redirect)
    {
        if (redirect is not null) return Results.Redirect(redirect);
        return IsBrowserNavigation(http) ? Page(200, "Logged out", SuccessBody(false)) : Results.Text("null", "application/json");
    }

    private static IResult Fail(HttpContext http, int status, string error, string description) =>
        IsBrowserNavigation(http) ? Page(status, "Logout error", $"<main><h1>Logout error</h1><p data-oidc-logout-state=\"error\">{WebUtility.HtmlEncode(description)}</p></main>")
            : Results.Json(new { error, error_description = description }, statusCode: status);

    private static string ConfirmBody() =>
        $"<main><h1>Confirm logout</h1><p>Do you want to log out of this account?</p><form method=\"post\" data-oidc-logout-confirmation action=\"{ConfirmPath}\"><button type=\"submit\" name=\"action\" value=\"confirm\">Confirm logout</button></form></main>";

    private static string SuccessBody(bool redirectInvalid) =>
        $"<main><p data-oidc-logout-state=\"logged-out\">Logged out.{(redirectInvalid ? " The requested post-logout redirect was not registered." : "")}</p></main>";

    /// <summary>Browsers apply a page's form-action to the redirect that follows the form, so the registered address the person goes on to must be allowed (it was checked against the client's list).</summary>
    private static string? RedirectOrigin(Confirmation confirmation) =>
        confirmation.PostLogoutRedirectUri is { } uri && Uri.TryCreate(uri, UriKind.Absolute, out var parsed) && parsed.GetLeftPart(UriPartial.Authority) is var origin
            && System.Text.RegularExpressions.Regex.IsMatch(origin, @"^https?://[A-Za-z0-9.\-\[\]:]+$") ? origin : null;   // plain host and port only: nothing that could add a CSP directive

    private static IResult Page(int status, string title, string body, string? formActionOrigin = null) =>
        new PageResult(formActionOrigin, Results.Content($"<!doctype html><html><head><meta charset=\"utf-8\"><title>{WebUtility.HtmlEncode(title)}</title></head><body>{body}</body></html>", "text/html; charset=utf-8", Encoding.UTF8, status));

    /// <summary>The page, with the security headers the reference sends (no framing, no scripts, forms only to this origin).</summary>
    private sealed class PageResult(string? formActionOrigin, IResult inner) : IResult
    {
        public Task ExecuteAsync(HttpContext httpContext)
        {
            httpContext.Response.Headers["Content-Security-Policy"] = $"default-src 'none'; form-action 'self'{(formActionOrigin is null ? "" : " " + formActionOrigin)}; base-uri 'none'; frame-ancestors 'none'";
            httpContext.Response.Headers["X-Content-Type-Options"] = "nosniff";
            httpContext.Response.Headers.CacheControl = "no-store";
            httpContext.Response.Headers.Pragma = "no-cache";
            return inner.ExecuteAsync(httpContext);
        }
    }
}
