using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.Social;
using WorkAI360.Api.Domain.Sso;
using WorkAI360.Api.Endpoints;
using WorkAI360.Api.Features.OrgAdmin;
using WorkAI360.Api.Features.Sso;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Features.Social;

/// <summary>Who the provider says the person is. The email is always one the provider vouches for as verified.</summary>
public sealed record SocialIdentity(string AccountId, string Email, string? Name, string? Picture);

/// <summary>
/// Sign-in with Google or GitHub (authorization code with PKCE). Every attempt has a state value that works once, for one provider, in the
/// browser that started it (a cookie binds them), so an attacker cannot hand a victim a code of their own. Google's ID token must carry the
/// attempt's nonce and pass the same validation SSO uses. GitHub's identity is read from its API, and only the primary, verified email counts.
/// A person is recognised by the provider's stable account id; an existing account is joined only through an email the provider has verified;
/// and a workspace that requires SSO cannot be entered this way.
/// </summary>
public sealed class SocialFlow(
    DenDbContext db, SocialProviders providers, SecretProtector secrets, IHttpClientFactory http, SessionService sessions, TrustedUrls trusted,
    OAuthUrls urls, SsoRouting sso, IAuditLog audit)
{
    public const string BindingCookie = "openwork-den.social_state";
    public const string SsoManaged = "This account is managed by an organization. Use SSO to sign in.";
    public static readonly TimeSpan StateLifetime = TimeSpan.FromMinutes(10);
    public const string HttpClientName = "social-idp";

    public sealed record Start(string CallbackUrl, string? ErrorCallbackUrl, string? NewUserCallbackUrl, bool RequestSignUp);

    public string RedirectUrl(string provider) => $"{urls.Web}/api/auth/callback/{provider}";

    public async Task<string> StartAsync(HttpContext ctx, SocialProvider p, Start start, CancellationToken ct)
    {
        var state = Token(32);
        var verifier = Token(32);
        var nonce = p.IsGoogle ? Token(24) : null;
        var binding = Token(32);
        var now = DateTime.UtcNow;
        db.Add(new SocialAuthState
        {
            Id = Ids.Sha256Hex(state), Provider = p.Name, BrowserBindingHash = Ids.Sha256Hex(binding), NonceHash = nonce is null ? null : Ids.Sha256Hex(nonce),
            CodeVerifierProtected = secrets.Protect(verifier), CallbackUrl = start.CallbackUrl, ErrorCallbackUrl = start.ErrorCallbackUrl, NewUserCallbackUrl = start.NewUserCallbackUrl,
            RequestSignUp = start.RequestSignUp, CreatedAt = now, ExpiresAt = now.Add(StateLifetime),
        });
        await db.SaveChangesAsync(ct);
        await db.Set<SocialAuthState>().Where(s => s.ExpiresAt < now.AddHours(-1)).ExecuteDeleteAsync(ct);   // old attempts are useless

        ctx.Response.Cookies.Append(BindingCookie, binding, new CookieOptions { HttpOnly = true, SameSite = SameSiteMode.Lax, Secure = ctx.Request.IsHttps, Path = "/", MaxAge = StateLifetime });

        var challenge = SsoService.Base64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        var query = new List<KeyValuePair<string, string>>
        {
            new("response_type", "code"), new("client_id", p.ClientId), new("redirect_uri", RedirectUrl(p.Name)), new("scope", p.Scope),
            new("state", state), new("code_challenge", challenge), new("code_challenge_method", "S256"),
        };
        if (nonce is not null) query.Add(new("nonce", nonce));
        var separator = p.AuthorizationEndpoint.Contains('?') ? "&" : "?";
        return p.AuthorizationEndpoint + separator + string.Join('&', query.Select(q => $"{Uri.EscapeDataString(q.Key)}={Uri.EscapeDataString(q.Value)}"));
    }

    /// <summary>What the browser gets back when the provider sends the person to us.</summary>
    public async Task<IResult> CallbackAsync(HttpContext ctx, string providerName, CancellationToken ct)
    {
        var query = ctx.Request.Query;
        var p = providers.Find(providerName);
        if (p is null) return LocalError("oauth_provider_not_found");

        var stateValue = query["state"].ToString();
        if (stateValue.Length == 0) return LocalError("state_not_found");
        var stateId = Ids.Sha256Hex(stateValue);
        var now = DateTime.UtcNow;
        var state = await db.Set<SocialAuthState>().FirstOrDefaultAsync(s => s.Id == stateId, ct);
        if (state is null || state.Provider != p.Name || state.ExpiresAt <= now || state.ConsumedAt is not null) return LocalError("state_mismatch");
        // The state must come back in the browser that began the sign-in, or an attacker could hand a victim a code of their own (login CSRF).
        // Checked before the state is spent, so someone who has seen a state value cannot burn it.
        var binding = ctx.Request.Cookies[BindingCookie];
        if (string.IsNullOrEmpty(binding) || !SsoService.FixedEquals(Ids.Sha256Hex(binding), state.BrowserBindingHash)) return LocalError("state_mismatch");
        // Single use, even when everything after this fails.
        var claimed = await db.Set<SocialAuthState>().Where(s => s.Id == stateId && s.ConsumedAt == null).ExecuteUpdateAsync(s => s.SetProperty(x => x.ConsumedAt, now), ct);
        if (claimed != 1) return LocalError("state_mismatch");
        ctx.Response.Cookies.Delete(BindingCookie, new CookieOptions { Path = "/" });

        IResult Fail(string code, string? description) =>
            Results.Redirect(OidcFlow.AppendQuery(state.ErrorCallbackUrl is { } e ? trusted.Absolute(e) : $"{urls.Web}/connect/error", ("error", code), ("error_description", Clip(description))));

        if (query.ContainsKey("error")) return Fail(Clip(query["error"].ToString()) ?? "access_denied", query["error_description"].ToString());
        // RFC 9207: when the provider says who answered, it must be the provider we asked.
        if (p.IsGoogle && query.ContainsKey("iss") && query["iss"].ToString() is var iss && iss != p.Issuer && iss != "accounts.google.com") return Fail("invalid_state", "issuer_mismatch");
        var code = query["code"].ToString();
        if (code.Length == 0 || code.Length > 4096) return Fail("no_code", "authorization_code_not_found");

        SocialIdentity identity;
        try
        {
            var client = http.CreateClient(HttpClientName);
            var verifier = secrets.Unprotect(state.CodeVerifierProtected);
            var (found, failure) = p.IsGoogle ? await GoogleIdentityAsync(client, p, code, verifier, state.NonceHash!, ct) : await GitHubIdentityAsync(client, p, code, verifier, ct);
            if (found is null) return Fail(failure!.Value.Code, failure.Value.Description);
            identity = found;
        }
        catch (Exception e) when (e is HttpRequestException or JsonException or InvalidDataException or TaskCanceledException or CryptographicException or FormatException)
        {
            return Fail("unable_to_get_user_info", "provider_unreachable_or_invalid");
        }

        var email = identity.Email.Trim().ToLowerInvariant();
        // A workspace that requires single sign-on closes every other way in: an address on its verified domain, or a person already in it.
        if (await sso.ForEmailDomainAsync(email) is not null || await sso.ForExistingUserAsync(email) is not null) return Fail("sso_required", SsoManaged);

        // While first-administrator setup is open there are no accounts yet, so this sign-in would make the first one: it waits for setup.
        if (await ctx.RequestServices.GetRequiredService<WorkAI360.Api.Features.PlatformAdmin.InitialAdminSetup>().BlocksOrdinarySignUpAsync()) return Fail("setup_required", WorkAI360.Api.Features.PlatformAdmin.InitialAdminSetup.SetupRequired);

        var (user, isNew) = await ResolveUserAsync(p, identity with { Email = email }, ct);
        // The link may lead to a person whose email is no longer the one that was checked above.
        if (user.Email != email && await sso.ForExistingUserAsync(user.Email) is not null) return Fail("sso_required", SsoManaged);

        var active = await db.Members.Where(m => m.UserId == user.Id).OrderBy(m => m.CreatedAt).Select(m => m.OrganizationId).FirstOrDefaultAsync(ct);
        var (token, session) = await sessions.CreateAsync(user, active, $"social:{p.Name}", ctx);
        sessions.WriteCookie(ctx, token, session);
        await audit.RecordForUserAsync(user.Id, new AuditEntry(AuditActions.SessionCreated, [new("session", session.Id)], "security", After: new() { ["method"] = $"social:{p.Name}" }));
        return Results.Redirect(trusted.Absolute(isNew && state.NewUserCallbackUrl is { } nu ? nu : state.CallbackUrl));
    }

    // ============================== identities ==============================

    private async Task<(SocialIdentity? Identity, (string Code, string Description)? Failure)> GoogleIdentityAsync(HttpClient client, SocialProvider p, string code, string verifier, string nonceHash, CancellationToken ct)
    {
        using var tokenRequest = new HttpRequestMessage(HttpMethod.Post, p.TokenEndpoint)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code", ["code"] = code, ["redirect_uri"] = RedirectUrl(p.Name), ["code_verifier"] = verifier, ["client_id"] = p.ClientId, ["client_secret"] = p.ClientSecret,
            }),
        };
        tokenRequest.Headers.Accept.ParseAdd("application/json");
        using var tokenResponse = await client.SendAsync(tokenRequest, ct);
        if (!tokenResponse.IsSuccessStatusCode) return (null, ("invalid_code", "token_response_error"));
        using var tokenDoc = JsonDocument.Parse(await IdpHttp.ReadLimitedAsync(tokenResponse, ct));
        if (!tokenDoc.RootElement.TryGetProperty("id_token", out var idTokenElement) || idTokenElement.ValueKind != JsonValueKind.String) return (null, ("invalid_code", "id_token_missing"));
        var idToken = idTokenElement.GetString()!;

        using var jwksResponse = await client.GetAsync(p.JwksUri, ct);
        if (!jwksResponse.IsSuccessStatusCode) return (null, ("unable_to_get_user_info", "jwks_unavailable"));
        var jwks = await IdpHttp.ReadLimitedAsync(jwksResponse, ct);

        // Google signs as "https://accounts.google.com" and sometimes "accounts.google.com": both are accepted, nothing else.
        var issuer = p.Issuer!;
        if (p.Issuer == SocialProviders.GoogleIssuer && PayloadString(idToken, "iss") == "accounts.google.com") issuer = "accounts.google.com";
        JsonElement claims;
        try { claims = IdTokenValidator.Validate(idToken, jwks, new IdTokenValidator.Expected(issuer, p.ClientId, nonceHash, DateTimeOffset.UtcNow)); }
        catch (OidcException e) { return (null, ("unable_to_get_user_info", e.Message)); }

        string? Claim(string name) => claims.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String && v.GetString()!.Length > 0 ? v.GetString() : null;
        var email = Claim("email");
        if (email is null) return (null, ("email_not_found", "missing_email"));
        // The provider must vouch for the address: an unverified one never signs anyone in or joins any account.
        var verified = claims.TryGetProperty("email_verified", out var ev) && (ev.ValueKind == JsonValueKind.True || (ev.ValueKind == JsonValueKind.String && ev.GetString() == "true"));
        if (!verified) return (null, ("email_not_verified", "the provider has not verified this email"));
        return (new SocialIdentity(Claim("sub")!, email, Claim("name"), Claim("picture")), null);
    }

    private async Task<(SocialIdentity? Identity, (string Code, string Description)? Failure)> GitHubIdentityAsync(HttpClient client, SocialProvider p, string code, string verifier, CancellationToken ct)
    {
        using var tokenRequest = new HttpRequestMessage(HttpMethod.Post, p.TokenEndpoint)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["code"] = code, ["redirect_uri"] = RedirectUrl(p.Name), ["code_verifier"] = verifier, ["client_id"] = p.ClientId, ["client_secret"] = p.ClientSecret,
            }),
        };
        tokenRequest.Headers.Accept.ParseAdd("application/json");
        using var tokenResponse = await client.SendAsync(tokenRequest, ct);
        if (!tokenResponse.IsSuccessStatusCode) return (null, ("invalid_code", "token_response_error"));
        using var tokenDoc = JsonDocument.Parse(await IdpHttp.ReadLimitedAsync(tokenResponse, ct));
        // GitHub answers 200 with an "error" field when the code is bad.
        if (!tokenDoc.RootElement.TryGetProperty("access_token", out var accessToken) || accessToken.ValueKind != JsonValueKind.String || accessToken.GetString()!.Length == 0) return (null, ("invalid_code", "token_response_error"));
        var bearer = accessToken.GetString()!;

        async Task<JsonDocument?> GetAsync(string path)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, p.ApiBase + path);
            request.Headers.Authorization = new("Bearer", bearer);
            request.Headers.Accept.ParseAdd("application/vnd.github+json");
            request.Headers.UserAgent.ParseAdd("360workai");
            using var response = await client.SendAsync(request, ct);
            return response.IsSuccessStatusCode ? JsonDocument.Parse(await IdpHttp.ReadLimitedAsync(response, ct)) : null;
        }

        using var user = await GetAsync("/user");
        if (user is null || user.RootElement.ValueKind != JsonValueKind.Object || !user.RootElement.TryGetProperty("id", out var id) || id.ValueKind is not (JsonValueKind.Number or JsonValueKind.String)) return (null, ("unable_to_get_user_info", "user_unavailable"));
        using var emails = await GetAsync("/user/emails");
        if (emails is null || emails.RootElement.ValueKind != JsonValueKind.Array) return (null, ("email_not_found", "emails_unavailable"));

        // Only the primary, verified address counts. The profile's own "email" field is a public, unverified display value, never used.
        string? primary = null; var primaryUnverified = false;
        foreach (var entry in emails.RootElement.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.Object || !entry.TryGetProperty("primary", out var isPrimary) || isPrimary.ValueKind != JsonValueKind.True) continue;
            var address = entry.TryGetProperty("email", out var a) && a.ValueKind == JsonValueKind.String ? a.GetString() : null;
            if (string.IsNullOrWhiteSpace(address)) continue;
            if (entry.TryGetProperty("verified", out var v) && v.ValueKind == JsonValueKind.True) primary = address; else primaryUnverified = true;
            break;
        }
        if (primary is null) return (null, primaryUnverified ? ("email_not_verified", "the primary email is not verified") : ("email_not_found", "no primary email"));

        string? Str(string name) => user.RootElement.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String && v.GetString()!.Length > 0 ? v.GetString() : null;
        return (new SocialIdentity(id.ValueKind == JsonValueKind.Number ? id.GetRawText() : id.GetString()!, primary, Str("name") ?? Str("login"), Str("avatar_url")), null);
    }

    // ============================== accounts ==============================

    /// <summary>
    /// The person behind a verified provider identity. A known provider account signs in to the person it is linked to (never by email, so an
    /// address that changed at the provider cannot take over an account). Otherwise the verified email finds the existing person, or makes a
    /// new one. If that existing account never proved its email, whoever registered it first does not get to keep it: its password and every
    /// other way in are removed, as with SSO.
    /// </summary>
    public async Task<(User User, bool IsNew)> ResolveUserAsync(SocialProvider p, SocialIdentity identity, CancellationToken ct)
    {
        var link = await db.Set<ExternalAccount>().FirstOrDefaultAsync(a => a.ProviderId == p.Name && a.AccountId == identity.AccountId, ct);
        if (link is not null)
        {
            var linked = await db.Users.FirstOrDefaultAsync(u => u.Id == link.UserId, ct);
            if (linked is not null) return (linked, false);
            db.Remove(link);
            await db.SaveChangesAsync(ct);
        }

        var now = DateTime.UtcNow;
        var user = await db.Users.FirstOrDefaultAsync(u => u.Email == identity.Email, ct);
        var isNew = user is null;
        if (user is not null)
        {
            if (!user.EmailVerified)
            {
                user.PasswordHash = SsoProvisioning.UnusablePassword;
                user.EmailVerified = true;
                user.UpdatedAt = now;
                await db.Set<ExternalAccount>().Where(a => a.UserId == user.Id && !a.ProviderId.StartsWith("openwork-scim-")).ExecuteDeleteAsync(ct);
                await db.Sessions.Where(s => s.UserId == user.Id).ExecuteDeleteAsync(ct);
            }
        }
        else
        {
            user = new User
            {
                Id = Ids.New("usr"), Email = identity.Email, Name = string.IsNullOrWhiteSpace(identity.Name) ? identity.Email.Split('@')[0] : identity.Name.Trim(),
                EmailVerified = true, PasswordHash = SsoProvisioning.UnusablePassword, CreatedAt = now, UpdatedAt = now,
                Image = identity.Picture is { } pic && Uri.TryCreate(pic, UriKind.Absolute, out var u) && u.Scheme == Uri.UriSchemeHttps ? pic : null,
            };
            db.Users.Add(user);
        }
        db.Add(new ExternalAccount { Id = Ids.New("acc"), UserId = user.Id, ProviderId = p.Name, AccountId = identity.AccountId, CreatedAt = now });
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateException)
        {
            // A parallel sign-in created the same person or link first: take what exists.
            db.ChangeTracker.Clear();
            var again = await db.Set<ExternalAccount>().FirstOrDefaultAsync(a => a.ProviderId == p.Name && a.AccountId == identity.AccountId, ct);
            var existing = again is null ? await db.Users.FirstOrDefaultAsync(u => u.Email == identity.Email, ct) : await db.Users.FirstOrDefaultAsync(u => u.Id == again.UserId, ct);
            if (existing is null) throw;
            if (again is null)
            {
                db.Add(new ExternalAccount { Id = Ids.New("acc"), UserId = existing.Id, ProviderId = p.Name, AccountId = identity.AccountId, CreatedAt = now });
                try { await db.SaveChangesAsync(ct); } catch (DbUpdateException) { db.ChangeTracker.Clear(); }
            }
            return (existing, false);
        }
        return (user, isNew);
    }

    // ============================== helpers ==============================

    private IResult LocalError(string code) => Results.Redirect($"{urls.Web}/connect/error?error={Uri.EscapeDataString(code)}");

    private static string? Clip(string? value) => string.IsNullOrWhiteSpace(value) ? null : (value.Length > 200 ? value[..200] : value);

    private static string? PayloadString(string jwt, string name)
    {
        var parts = jwt.Split('.');
        if (parts.Length != 3) return null;
        try
        {
            using var doc = JsonDocument.Parse(SigningKeyStore.FromBase64Url(parts[1]));
            return doc.RootElement.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
        }
        catch (Exception e) when (e is JsonException or FormatException) { return null; }
    }

    private static string Token(int bytes) => SsoService.Base64Url(RandomNumberGenerator.GetBytes(bytes));
}
