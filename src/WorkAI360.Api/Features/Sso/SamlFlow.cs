using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Saml;
using WorkAI360.Api.Domain.Sso;
using WorkAI360.Api.Endpoints;
using WorkAI360.Api.Features.Replay;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Features.Sso;

/// <summary>
/// SAML 2.0 web sign-in. <b>Start</b> (SP-initiated): an AuthnRequest with a fresh id is remembered (hashed) together with a RelayState value and a browser
/// binding cookie, and the person is sent to the identity provider (redirect binding, or a self-submitting POST form). <b>ACS</b>: the identity provider
/// posts the response; <see cref="SamlValidator"/> checks the signature and every claim, the response must answer a request this service really sent
/// (<c>InResponseTo</c>, used once), and the assertion id goes into the replay cache. The identity is parked on the request row and the browser is sent (303,
/// a same-site GET) to <b>continue</b>, where the binding cookie proves it is the browser that started the sign-in; only then is anybody signed in. Nothing
/// is decided from a cross-site POST alone, so a response the attacker obtained for their own login cannot be handed to a victim (login CSRF).
/// IdP-initiated responses (no <c>InResponseTo</c>) are accepted only when <c>Sso:SamlAllowIdpInitiated</c> is on (the reference's default); they cannot be browser bound.
/// </summary>
public sealed class SamlFlow(
    DenDbContext db, SsoService sso, SessionService sessions, TrustedUrls trusted, OAuthUrls urls, SsoProvisioning provisioning, ReplayGuard replay,
    IOptions<SsoOptions> options, SamlServiceProvider sp, SamlLogoutFlow logout)
{
    public const string BindingCookie = "openwork-den.saml_state";
    public const string ReplayKind = "saml-assertion";
    public static readonly TimeSpan RequestLifetime = TimeSpan.FromMinutes(10);
    public static readonly AuthLimitPolicy AcsLimit = new("saml-acs", TimeSpan.FromMinutes(5), 30, 200);
    private const string NotEnabled = "This disabled SSO provider cannot authenticate without a current administrator test.";

    private TimeSpan Skew => TimeSpan.FromSeconds(options.Value.SamlClockSkewSeconds ?? 300);
    private bool AllowIdpInitiated => options.Value.SamlAllowIdpInitiated ?? true;

    // ---------------------------------------------------------------- start

    public async Task<string> StartAsync(HttpContext ctx, SsoConnection c, OidcFlow.Start start, CancellationToken ct)
    {
        var settings = SsoService.SamlSettingsOf(c) ?? throw new InvalidOperationException("Not a SAML connection.");
        var requestId = SamlProtocol.NewRequestId();
        var relay = Token(32);
        var binding = Token(32);
        var now = DateTime.UtcNow;
        var xml = SamlProtocol.AuthnRequest(requestId, sso.SpEntityId(settings), settings.EntryPoint, sso.AcsUrl(c.ProviderId), now);
        var post = settings.Binding == "post";
        using var signingKey = settings.SignAuthnRequests ? await sp.KeyAsync(c.ProviderId, ct) : null;
        if (post && signingKey is not null) xml = SamlProtocol.SignedAuthnRequest(xml, signingKey);
        db.Add(new SamlAuthRequest
        {
            Id = Ids.Sha256Hex(requestId), RelayStateHash = Ids.Sha256Hex(relay), ProviderId = c.ProviderId, ConfigRevision = c.ConfigRevision,
            BrowserBindingHash = Ids.Sha256Hex(binding), CallbackUrl = start.CallbackUrl, ErrorCallbackUrl = start.ErrorCallbackUrl, NewUserCallbackUrl = start.NewUserCallbackUrl,
            TestIntentId = start.TestIntentId, RequestXml = post ? xml : null, CreatedAt = now, ExpiresAt = now.Add(RequestLifetime),
        });
        await db.SaveChangesAsync(ct);
        await db.Set<SamlAuthRequest>().Where(r => r.ExpiresAt < now.AddHours(-1)).ExecuteDeleteAsync(ct);
        // Lax: the cookie travels with the same-site navigation at the end of the sign-in (it is not needed on the cross-site POST).
        ctx.Response.Cookies.Append(BindingCookie, binding, new CookieOptions { HttpOnly = true, SameSite = SameSiteMode.Lax, Secure = ctx.Request.IsHttps, Path = "/", MaxAge = RequestLifetime });
        if (post) return $"{urls.Web}/api/auth/sso/saml2/sp/login/{Uri.EscapeDataString(c.ProviderId)}?relay={Uri.EscapeDataString(relay)}";
        return signingKey is null ? SamlProtocol.RedirectUrl(settings.EntryPoint, xml, relay) : SamlProtocol.SignedRedirectUrl(settings.EntryPoint, xml, relay, signingKey);
    }

    /// <summary>The page for the POST binding: it submits the stored AuthnRequest to the identity provider. Only the browser that started the sign-in gets it.</summary>
    public async Task<IResult> LoginFormAsync(HttpContext ctx, string providerId, string? relay, CancellationToken ct)
    {
        var c = await db.Set<SsoConnection>().FirstOrDefaultAsync(o => o.ProviderId == providerId, ct);
        var settings = c is null ? null : SsoService.SamlSettingsOf(c);
        var row = string.IsNullOrEmpty(relay) ? null : await db.Set<SamlAuthRequest>().FirstOrDefaultAsync(r => r.RelayStateHash == Ids.Sha256Hex(relay), ct);
        if (c is null || settings is null || row is null || row.ProviderId != providerId || row.RequestXml is null || row.ExpiresAt <= DateTime.UtcNow || row.AnsweredAt is not null
            || !BoundTo(ctx, row))
            return LocalError("state_mismatch", null);
        var (html, hash) = SamlProtocol.PostForm(settings.EntryPoint, row.RequestXml, relay!);
        var origin = new Uri(settings.EntryPoint).GetLeftPart(UriPartial.Authority);
        ctx.Response.Headers.CacheControl = "no-store";
        ctx.Response.Headers["Content-Security-Policy"] = $"default-src 'none'; script-src 'sha256-{hash}'; form-action {origin}; frame-ancestors 'none'; base-uri 'none'";
        return Results.Content(html, "text/html; charset=utf-8");
    }

    // ---------------------------------------------------------------- ACS

    /// <summary>The identity provider's POST. Always ends in a redirect for the browser (a JSON refusal only for a connection that is not on).</summary>
    public async Task<IResult> AcsAsync(HttpContext ctx, string providerId, string? samlResponse, string? relayState, CancellationToken ct)
    {
        var c = await db.Set<SsoConnection>().FirstOrDefaultAsync(o => o.ProviderId == providerId, ct);
        var settings = c is null ? null : SsoService.SamlSettingsOf(c);
        if (c is null || settings is null) return Results.Json(new { message = "No SAML provider found" }, statusCode: 404);
        if (string.IsNullOrWhiteSpace(samlResponse)) return Results.Json(new { message = "SAMLResponse is required for POST requests" }, statusCode: 400);

        var now = DateTime.UtcNow;
        SamlAuthRequest? request = null;
        if (!string.IsNullOrEmpty(relayState))
        {
            var relayHash = Ids.Sha256Hex(relayState);
            request = await db.Set<SamlAuthRequest>().FirstOrDefaultAsync(r => r.RelayStateHash == relayHash, ct);
        }
        // A disabled connection signs nobody in, except for an administrator's current test that was started from this very request.
        var liveTest = request?.TestIntentId is { } intent && SsoService.IsLiveTest(c, intent);
        if (!SsoService.Ready(c) && !liveTest) return Results.Json(new { error = "sso_not_enabled", message = NotEnabled }, statusCode: 403);

        async Task<IResult> Fail(string code, string? description, SamlAuthRequest? row = null)
        {
            row ??= request;
            if (row?.TestIntentId is { } testIntent) await sso.FailTestAsync(testIntent, "authentication");
            return ErrorRedirect(row, code, description, c);
        }

        if (!string.IsNullOrEmpty(relayState) && request is null) return await Fail("invalid_state", "invalid_or_expired_relay_state");
        if (request is not null && (request.ProviderId != c.ProviderId || request.ExpiresAt <= now || request.AnsweredAt is not null))
            return await Fail("invalid_state", request.AnsweredAt is not null ? "request_already_answered" : "invalid_or_expired_relay_state");
        if (request is not null && request.ConfigRevision != c.ConfigRevision) return await Fail("invalid_state", "sso_provider_changed_during_authentication");

        SamlAssertion assertion;
        try
        {
            using var decryptionKey = await sp.ExistingDecryptionKeyAsync(c.ProviderId, ct);
            var expectations = new SamlExpectations(settings.IdpEntityId, sso.SpEntityId(settings), [sso.AcsUrl(c.ProviderId)], SamlCertificates.Load(settings.Certificates), DateTimeOffset.UtcNow, Skew, decryptionKey);
            assertion = SamlValidator.Validate(samlResponse, expectations);
        }
        catch (SamlException e) { return await Fail("invalid_saml_response", e.Message); }
        catch (CryptographicException) { return await Fail("invalid_saml_response", "The identity provider's certificate could not be used."); }

        // Which request does it answer?
        if (assertion.InResponseTo is { } answered)
        {
            var byId = await db.Set<SamlAuthRequest>().FirstOrDefaultAsync(r => r.Id == Ids.Sha256Hex(answered), ct);
            if (byId is null || byId.ProviderId != c.ProviderId || byId.ExpiresAt <= now) return await Fail("invalid_saml_response", "Unknown or expired request ID", request);
            if (request is not null && request.Id != byId.Id) return await Fail("invalid_state", "relay_state_does_not_match_request");
            if (byId.AnsweredAt is not null) return await Fail("invalid_saml_response", "The request was already answered", byId);
            if (byId.ConfigRevision != c.ConfigRevision) return await Fail("invalid_state", "sso_provider_changed_during_authentication", byId);
            request = byId;
        }
        else if (request is not null) return await Fail("invalid_saml_response", "The response does not answer the request (InResponseTo is missing)");
        else if (!AllowIdpInitiated) return await Fail("unsolicited_response", "IdP-initiated SSO not allowed");

        // Used once, whoever carries it and however often it is posted.
        if (!await replay.ReserveAsync(ReplayKind, $"{c.ProviderId}\n{assertion.Issuer}\n{assertion.AssertionId}", assertion.ReplayExpiresAt, ct))
            return await Fail("replay_detected", "SAML assertion has already been used");

        var identity = ExtractIdentity(assertion);
        if (identity is null) return await Fail("invalid_saml_response", "Unable to extract user ID or email from SAML response");
        var parked = new SamlParkedIdentity(identity.Subject, identity.Email, identity.Name, assertion.NameId, assertion.NameIdFormat, assertion.SessionIndex);

        if (request is null)
        {
            // IdP-initiated: nothing was started here, so there is no browser to bind; the signed assertion is all there is.
            return await FinishAsync(ctx, c, parked, null, trusted.Absolute("/dashboard"), null, null, ct);
        }

        var claimed = await db.Set<SamlAuthRequest>().Where(r => r.Id == request.Id && r.AnsweredAt == null && r.ExpiresAt > now)
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.AnsweredAt, now).SetProperty(r => r.IdentityJson, JsonSerializer.Serialize(parked)), ct);
        if (claimed != 1) return await Fail("invalid_state", "request_already_answered", request);
        var handle = assertion.InResponseTo!;
        ctx.Response.StatusCode = StatusCodes.Status303SeeOther;
        ctx.Response.Headers.Location = $"{urls.Web}/api/auth/sso/saml2/sp/continue/{Uri.EscapeDataString(c.ProviderId)}?id={Uri.EscapeDataString(handle)}";
        return Results.Empty;
    }

    // ---------------------------------------------------------------- continue

    /// <summary>The same-site return that finishes a sign-in the ACS accepted: the binding cookie must be the one set when it started.</summary>
    public async Task<IResult> ContinueAsync(HttpContext ctx, string providerId, string? id, CancellationToken ct)
    {
        var c = await db.Set<SsoConnection>().FirstOrDefaultAsync(o => o.ProviderId == providerId, ct);
        var row = string.IsNullOrEmpty(id) ? null : await db.Set<SamlAuthRequest>().FirstOrDefaultAsync(r => r.Id == Ids.Sha256Hex(id), ct);
        var now = DateTime.UtcNow;
        if (c is null || c.Kind != "saml" || row is null || row.ProviderId != c.ProviderId || row.AnsweredAt is null || row.ConsumedAt is not null || row.ExpiresAt <= now || row.IdentityJson is null
            || !BoundTo(ctx, row))
            return LocalError("state_mismatch", null);
        var claimed = await db.Set<SamlAuthRequest>().Where(r => r.Id == row.Id && r.ConsumedAt == null).ExecuteUpdateAsync(s => s.SetProperty(r => r.ConsumedAt, now), ct);
        if (claimed != 1) return LocalError("state_mismatch", null);
        ctx.Response.Cookies.Delete(BindingCookie, new CookieOptions { Path = "/" });

        IResult Fail(string code, string? description) => ErrorRedirect(row, code, description, c);
        var liveTest = row.TestIntentId is { } intent && SsoService.IsLiveTest(c, intent);
        if (!SsoService.Ready(c) && !liveTest) return Results.Json(new { error = "sso_not_enabled", message = NotEnabled }, statusCode: 403);
        if (row.ConfigRevision != c.ConfigRevision)
        {
            if (row.TestIntentId is { } stale) await sso.FailTestAsync(stale, "authentication");
            return Fail("invalid_state", "sso_provider_changed_during_authentication");
        }
        var parked = JsonSerializer.Deserialize<SamlParkedIdentity>(row.IdentityJson)!;
        return await FinishAsync(ctx, c, parked, row.TestIntentId, row.CallbackUrl, row.ErrorCallbackUrl, row.NewUserCallbackUrl, ct);
    }

    // ---------------------------------------------------------------- shared

    /// <summary>Who the assertion is, for the workspace's rules: a stable subject (the NameID, or the address for transient ids), an email and a name.</summary>
    public static SsoIdentity? ExtractIdentity(SamlAssertion assertion)
    {
        string? First(params string[] names) => names.Select(n => assertion.Attributes.TryGetValue(n, out var v) ? v.FirstOrDefault() : null).FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));
        var email = First("email", "mail", "emailAddress", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress", "urn:oid:0.9.2342.19200300.100.1.3", "urn:mace:dir:attribute-def:mail")
            ?? (assertion.NameId.Contains('@') ? assertion.NameId : null);
        if (email is null || !email.Contains('@')) return null;
        email = email.Trim().ToLowerInvariant();
        var given = First("givenName", "firstName", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname", "urn:oid:2.5.4.42");
        var family = First("surname", "sn", "lastName", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname", "urn:oid:2.5.4.4");
        var name = string.Join(' ', new[] { given, family }.Where(v => !string.IsNullOrWhiteSpace(v)))
            is { Length: > 0 } joined ? joined
            : First("displayName", "name", "http://schemas.microsoft.com/identity/claims/displayname", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", "urn:oid:2.16.840.1.113730.3.1.241");
        // A transient NameID changes at every sign-in, so it cannot name a person: the (domain-checked) address does.
        var subject = assertion.NameIdFormat == SamlValidator.TransientNameId ? "email:" + email : assertion.NameId;
        return new SsoIdentity(subject, email, name);
    }

    private async Task<IResult> FinishAsync(HttpContext ctx, SsoConnection c, SamlParkedIdentity parked, string? testIntentId, string callbackUrl, string? errorCallbackUrl, string? newUserCallbackUrl, CancellationToken ct)
    {
        var identity = parked.Identity;
        IResult Fail(string code, string? description)
        {
            var url = OidcFlow.AppendQuery(errorCallbackUrl ?? callbackUrl, ("error", code), ("error_description", description));
            return Results.Redirect(trusted.Absolute(url));
        }
        async Task<IResult> Refuse(string code, string? description)
        {
            if (testIntentId is not null) await sso.FailTestAsync(testIntentId, "authentication");
            return Fail(code, description);
        }

        var testing = testIntentId is not null;
        var resolution = await provisioning.ResolveUserAsync(c, identity, readOnly: testing, ct);
        if (resolution.User is null) return await Refuse(resolution.ErrorCode!, resolution.ErrorMessage);
        var user = resolution.User;
        if (testing)
        {
            // An administrator's test proves the provider works; it signs nobody in and replaces no session.
            var done = await sso.CompleteTestAsync(testIntentId!, c.ProviderId, user.Id);
            return Results.Redirect(trusted.Absolute(done ? callbackUrl : OidcFlow.AppendQuery(errorCallbackUrl ?? callbackUrl, ("error", "access_denied"))));
        }
        if (await provisioning.ProvisionAsync(c, user, identity, identity.Name, ct) is { } refusal) return await Refuse("access_denied", refusal);

        var isNew = user.CreatedAt > DateTime.UtcNow.AddMinutes(-1) && !await db.Sessions.AnyAsync(s => s.UserId == user.Id, ct);
        var (token, session) = await sessions.CreateAsync(user, c.OrganizationId, "sso", ctx);
        sessions.WriteCookie(ctx, token, session);
        // So that Single Logout can end exactly this sign-in later (rows from before this field existed carry no NameID).
        if (!string.IsNullOrEmpty(parked.NameId)) await logout.LinkAsync(session.Id, c.ProviderId, parked, ct);
        return Results.Redirect(trusted.Absolute(isNew && newUserCallbackUrl is { } nu ? nu : callbackUrl));
    }

    /// <summary>Where a failed sign-in lands: the error address the sign-in named, else (nothing was started here) the workspace's own sign-in page, which shows the reason.</summary>
    private IResult ErrorRedirect(SamlAuthRequest? row, string code, string? description, SsoConnection? connection = null)
    {
        if (row is null)
            return connection is null ? LocalError(code, description)
                : Results.Redirect(OidcFlow.AppendQuery(urls.Web + connection.SignInPath, ("error", code), ("error_description", Clip(description))));
        var url = OidcFlow.AppendQuery(row.ErrorCallbackUrl ?? row.CallbackUrl, ("error", code), ("error_description", Clip(description)));
        return Results.Redirect(trusted.Absolute(url));
    }

    private IResult LocalError(string code, string? description) =>
        Results.Redirect(OidcFlow.AppendQuery($"{urls.Web}/connect/error", ("error", code), ("error_description", Clip(description))));

    private static bool BoundTo(HttpContext ctx, SamlAuthRequest row)
    {
        var binding = ctx.Request.Cookies[BindingCookie];
        return !string.IsNullOrEmpty(binding) && SsoService.FixedEquals(Ids.Sha256Hex(binding), row.BrowserBindingHash);
    }

    private static string? Clip(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Length > 200 ? value[..200] : value;

    private static string Token(int bytes) => SsoService.Base64Url(RandomNumberGenerator.GetBytes(bytes));
}
