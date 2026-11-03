using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Saml;
using WorkAI360.Api.Domain.Sso;
using WorkAI360.Api.Features.Replay;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Features.Sso;

/// <summary>A SAML sign-in's identity, parked on the request row between the ACS and the same-site continue step, with what Single Logout needs.</summary>
public sealed record SamlParkedIdentity(string Subject, string Email, string? Name, string NameId, string? NameIdFormat, string? SessionIndex)
{
    public SsoIdentity Identity => new(Subject, Email, Name);
}

/// <summary>
/// SAML Single Logout (SAML profiles 4.4), redirect binding out and redirect or POST binding in.
/// <list type="bullet">
/// <item><b>SP-initiated</b> (<c>GET …/sp/logout/{providerId}</c>): ends the person's session here at once, then, when the connection has the identity
/// provider's logout URL and the session came from this connection, sends a signed LogoutRequest naming the NameID and SessionIndex of that sign-in. Only
/// a LogoutResponse to a request this service sent (hashed id, ten minutes, answered once) is accepted back.</item>
/// <item><b>IdP-initiated</b> (<c>…/sp/slo/{providerId}</c>, GET or POST): the LogoutRequest must be signed with the identity provider's certificate (query
/// signature or enveloped XML signature), name this connection's identity provider as issuer, be addressed here, not have run out, and is used once.
/// Every session that sign-ins with that NameID (and, when given, those session indexes) opened through this connection ends; the answer is a signed
/// LogoutResponse.</item>
/// </list>
/// </summary>
public sealed class SamlLogoutFlow(DenDbContext db, SsoService sso, SamlServiceProvider sp, SessionService sessions, OAuthUrls urls, ReplayGuard replay, IOptions<SsoOptions> options)
{
    public const string ReplayKind = "saml-logout";
    public static readonly TimeSpan RequestLifetime = TimeSpan.FromMinutes(10);
    private TimeSpan Skew => TimeSpan.FromSeconds(options.Value.SamlClockSkewSeconds ?? 300);

    private static IResult Refuse(string message) => Results.Json(new { error = "invalid_logout", message }, statusCode: 400);

    /// <summary>Records which SAML sign-in a new session came from.</summary>
    public async Task LinkAsync(string sessionId, string providerId, SamlParkedIdentity parked, CancellationToken ct)
    {
        db.Add(new SamlSessionLink
        {
            SessionId = sessionId, ProviderId = providerId, NameId = parked.NameId, NameIdFormat = parked.NameIdFormat, SessionIndex = parked.SessionIndex, CreatedAt = DateTime.UtcNow,
        });
        await db.SaveChangesAsync(ct);
    }

    // ---------------------------------------------------------------- SP-initiated

    public async Task<IResult> StartAsync(HttpContext ctx, string providerId, CancellationToken ct)
    {
        var current = await sessions.ResolveAsync(ctx);
        var link = current is null ? null : await db.Set<SamlSessionLink>().AsNoTracking().FirstOrDefaultAsync(l => l.SessionId == current.Session.Id && l.ProviderId == providerId, ct);

        // Signed out here first, whatever the identity provider does next.
        if (sessions.ReadCookieToken(ctx.Request) is { } token) await sessions.RevokeAsync(token);
        sessions.ClearCookie(ctx);
        if (current is not null) await db.Set<SamlSessionLink>().Where(l => l.SessionId == current.Session.Id).ExecuteDeleteAsync(ct);

        var c = await db.Set<SsoConnection>().AsNoTracking().FirstOrDefaultAsync(o => o.ProviderId == providerId, ct);
        var settings = c is null ? null : SsoService.SamlSettingsOf(c);
        if (settings?.SloUrl is null || link is null) return Results.Redirect(urls.Web + "/");

        var id = SamlProtocol.NewRequestId();
        var now = DateTime.UtcNow;
        db.Add(new SamlLogoutRequest { Id = Ids.Sha256Hex(id), ProviderId = providerId, CreatedAt = now, ExpiresAt = now.Add(RequestLifetime) });
        await db.SaveChangesAsync(ct);
        await db.Set<SamlLogoutRequest>().Where(r => r.ExpiresAt < now.AddHours(-1)).ExecuteDeleteAsync(ct);

        var xml = SamlLogout.Request(id, sso.SpEntityId(settings), settings.SloUrl, link.NameId, link.NameIdFormat, link.SessionIndex, now);
        return Results.Redirect(await SignedRedirectAsync(providerId, settings.SloUrl, "SAMLRequest", xml, null, ct));
    }

    // ---------------------------------------------------------------- from the identity provider

    public async Task<IResult> ReceiveAsync(HttpContext ctx, string providerId, CancellationToken ct)
    {
        var c = await db.Set<SsoConnection>().AsNoTracking().FirstOrDefaultAsync(o => o.ProviderId == providerId, ct);
        var settings = c is null ? null : SsoService.SamlSettingsOf(c);
        if (c is null || settings is null) return Results.Json(new { message = "No SAML provider found" }, statusCode: 404);

        var redirect = HttpMethods.IsGet(ctx.Request.Method);
        string? request, response, relay;
        if (redirect)
        {
            request = ctx.Request.Query["SAMLRequest"].FirstOrDefault();
            response = ctx.Request.Query["SAMLResponse"].FirstOrDefault();
            relay = ctx.Request.Query["RelayState"].FirstOrDefault();
        }
        else
        {
            if (!ctx.Request.HasFormContentType) return Refuse("A logout message must be posted as a form.");
            var form = await ctx.Request.ReadFormAsync(ct);
            request = form["SAMLRequest"].FirstOrDefault();
            response = form["SAMLResponse"].FirstOrDefault();
            relay = form["RelayState"].FirstOrDefault();
        }
        var parameter = request is not null ? "SAMLRequest" : response is not null ? "SAMLResponse" : null;
        var encoded = request ?? response;
        if (parameter is null || string.IsNullOrWhiteSpace(encoded)) return Refuse("SAMLRequest or SAMLResponse is required.");
        if (encoded.Length > SamlValidator.MaxEncodedLength) return Refuse("The logout message is too large.");

        XmlDocument doc;
        var certificates = SamlCertificates.Load(settings.Certificates);
        try
        {
            var xml = redirect ? SamlProtocol.InflateRequest(encoded) : SamlValidator.Decode(encoded);
            doc = SamlValidator.Parse(xml);
            // A logout message changes who is signed in: it must be signed by the identity provider, in whichever binding it came.
            if (redirect)
            {
                if (!SamlSigning.VerifyRedirect(ctx.Request.QueryString.Value ?? "", parameter, certificates)) return Refuse("The logout message is not signed by the identity provider.");
            }
            else SamlValidator.VerifyRootSignature(doc, certificates);
        }
        catch (SamlException e) { return Refuse(e.Message); }
        catch (Exception e) when (e is FormatException or InvalidDataException or IOException) { return Refuse("The logout message could not be read."); }

        var root = doc.DocumentElement!;
        var issuer = Child(root, SamlValidator.AssertionNs, "Issuer")?.InnerText.Trim();
        if (issuer != settings.IdpEntityId) return Refuse("The logout message was issued by a different identity provider than the one configured.");
        if (root.GetAttribute("Destination") is { Length: > 0 } destination && !SameUrl(destination, sso.SloUrl(providerId)))
            return Refuse("The logout message is addressed to a different service provider.");

        if (parameter == "SAMLRequest")
        {
            if (root.LocalName != "LogoutRequest" || root.NamespaceURI != SamlValidator.ProtocolNs) return Refuse("The message is not a LogoutRequest.");
            return await LogoutRequestAsync(c, settings, root, relay, ct);
        }
        if (root.LocalName != "LogoutResponse" || root.NamespaceURI != SamlValidator.ProtocolNs) return Refuse("The message is not a LogoutResponse.");
        return await LogoutResponseAsync(c, root, ct);
    }

    private async Task<IResult> LogoutRequestAsync(SsoConnection c, SamlSettings settings, XmlElement root, string? relay, CancellationToken ct)
    {
        var id = root.GetAttribute("ID");
        if (id.Length is 0 or > 256) return Refuse("The LogoutRequest has no ID.");
        var now = DateTimeOffset.UtcNow;
        if (root.GetAttribute("NotOnOrAfter") is { Length: > 0 } end
            && (!DateTimeOffset.TryParse(end, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var until) || now >= until + Skew))
            return Refuse("The LogoutRequest has expired.");
        var nameId = Child(root, SamlValidator.AssertionNs, "NameID")?.InnerText.Trim();
        if (string.IsNullOrEmpty(nameId)) return Refuse("The LogoutRequest names nobody (no NameID).");
        if (!await replay.ReserveAsync(ReplayKind, $"{c.ProviderId}\nrequest\n{id}", now.UtcDateTime.AddHours(1), ct)) return Refuse("The LogoutRequest was already used.");

        var indexes = root.ChildNodes.OfType<XmlElement>().Where(e => e.LocalName == "SessionIndex" && e.NamespaceURI == SamlValidator.ProtocolNs).Select(e => e.InnerText.Trim()).ToList();
        var links = db.Set<SamlSessionLink>().Where(l => l.ProviderId == c.ProviderId && l.NameId == nameId);
        if (indexes.Count > 0) links = links.Where(l => l.SessionIndex != null && indexes.Contains(l.SessionIndex));
        var sessionIds = await links.Select(l => l.SessionId).ToListAsync(ct);
        await db.Sessions.Where(s => sessionIds.Contains(s.Id)).ExecuteDeleteAsync(ct);
        await db.Set<SamlSessionLink>().Where(l => sessionIds.Contains(l.SessionId)).ExecuteDeleteAsync(ct);

        if (settings.SloUrl is null) return Results.Text("Signed out.", "text/plain");
        var answer = SamlLogout.Response(SamlProtocol.NewRequestId(), id, sso.SpEntityId(settings), settings.SloUrl, SamlLogout.StatusSuccess, DateTime.UtcNow);
        return Results.Redirect(await SignedRedirectAsync(c.ProviderId, settings.SloUrl, "SAMLResponse", answer, relay, ct));
    }

    private async Task<IResult> LogoutResponseAsync(SsoConnection c, XmlElement root, CancellationToken ct)
    {
        var inResponseTo = root.GetAttribute("InResponseTo");
        if (inResponseTo.Length == 0) return Refuse("The LogoutResponse does not answer a request.");
        var now = DateTime.UtcNow;
        var hash = Ids.Sha256Hex(inResponseTo);
        var claimed = await db.Set<SamlLogoutRequest>().Where(r => r.Id == hash && r.ProviderId == c.ProviderId && r.AnsweredAt == null && r.ExpiresAt > now)
            .ExecuteUpdateAsync(s => s.SetProperty(r => r.AnsweredAt, now), ct);
        if (claimed != 1) return Refuse("The LogoutResponse answers no logout request this service sent (or it was already answered).");
        var status = Child(Child(root, SamlValidator.ProtocolNs, "Status"), SamlValidator.ProtocolNs, "StatusCode")?.GetAttribute("Value");
        // Signed out here already; the identity provider only reports whether it ended its own session too.
        return Results.Redirect(status == SamlLogout.StatusSuccess ? urls.Web + "/" : urls.Web + "/?error=identity_provider_logout_failed");
    }

    private async Task<string> SignedRedirectAsync(string providerId, string destination, string parameter, string xml, string? relay, CancellationToken ct)
    {
        using var cert = await sp.KeyAsync(providerId, ct);
        using var key = cert.GetRSAPrivateKey()!;
        var separator = destination.Contains('?') ? "&" : "?";
        return destination + separator + SamlSigning.RedirectQuery(parameter, SamlLogout.Deflate(xml), relay, key);
    }

    private static bool SameUrl(string a, string b) =>
        Uri.TryCreate(a.Trim(), UriKind.Absolute, out var x) && Uri.TryCreate(b, UriKind.Absolute, out var y) && x.AbsoluteUri == y.AbsoluteUri;

    private static XmlElement? Child(XmlNode? parent, string ns, string local) =>
        parent?.ChildNodes.OfType<XmlElement>().FirstOrDefault(e => e.NamespaceURI == ns && e.LocalName == local);
}
