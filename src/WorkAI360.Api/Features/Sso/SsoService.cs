using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.Sso;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Features.Sso;

public sealed record OidcSettings(
    string ClientId, string[] Scopes, string AuthorizationEndpoint, string TokenEndpoint, string JwksEndpoint, string? UserInfoEndpoint, string TokenEndpointAuthentication);

public sealed record OidcRegistration(
    string Issuer, string Domain, string ClientId, string ClientSecret, string[]? Scopes, bool SkipDiscovery,
    string? AuthorizationEndpoint, string? TokenEndpoint, string? JwksEndpoint, string? UserInfoEndpoint, string? TokenEndpointAuthentication);

public sealed record Outcome(bool Ok, string Message = "")
{
    public static Outcome Success { get; } = new(true);
    public static Outcome Fail(string message) => new(false, message);
}

/// <summary>Everything about a workspace's SSO connection that is not the sign-in itself: saving it, proving the domain, testing, enabling.</summary>
public sealed class SsoService(
    DenDbContext db, SecretProtector secrets, IDnsTxtResolver dns, IOptions<SsoOptions> sso, IOptions<AuthOptions> auth, IHostEnvironment env, IHttpClientFactory http, OAuthUrls urls)
{
    public const string TokenPrefix = "better-auth-token";
    public static readonly TimeSpan TestLifetime = TimeSpan.FromMinutes(5);
    public static readonly TimeSpan DomainTokenLifetime = TimeSpan.FromDays(7);
    public const string TestIntentQueryKey = "openworkSsoTest";

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public bool AllowPrivateNetworks => sso.Value.AllowPrivateNetworks ?? env.IsDevelopment();
    private bool DevLoopbackVerified => sso.Value.DevLoopbackIssuerIsVerified ?? env.IsDevelopment();

    public static string ProviderIdFor(string organizationId) => $"openwork-sso-{organizationId}";
    public static string SignInPathFor(string slug) => $"/sso/{Uri.EscapeDataString(slug)}";
    public static string VerificationHost(string providerId) => $"_{TokenPrefix}-{providerId}";

    public Task<SsoConnection?> ForOrganizationAsync(string organizationId) => db.Set<SsoConnection>().FirstOrDefaultAsync(c => c.OrganizationId == organizationId);

    public static OidcSettings? Settings(SsoConnection c) => c.OidcConfigJson is null ? null : JsonSerializer.Deserialize<OidcSettings>(c.OidcConfigJson, Json);

    public static bool Ready(SsoConnection c) => c.Status == "enabled" && c.DomainVerified;

    /// <summary>The domains a connection claims (comma separated, lower case).</summary>
    public static string[] Domains(string value) => value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(d => d.ToLowerInvariant()).Distinct().ToArray();

    /// <summary>An email domain equals a claimed domain or is a subdomain of one.</summary>
    public static bool EmailDomainMatches(string emailDomain, string configured) =>
        Domains(configured).Any(d => emailDomain.Equals(d, StringComparison.OrdinalIgnoreCase) || emailDomain.EndsWith("." + d, StringComparison.OrdinalIgnoreCase));

    public static string? EmailDomain(string? email)
    {
        var at = email?.LastIndexOf('@') ?? -1;
        return at > 0 && at < email!.Length - 1 ? email[(at + 1)..].Trim().ToLowerInvariant() : null;
    }

    private string Revision(string kind, string issuer, string domain, string? oidcJson, string? secret, string? samlJson) =>
        Convert.ToHexStringLower(HMACSHA256.HashData(SecretKeys.Derive(auth.Value.Secret, "sso config revision"),
            Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new { kind, issuer, domain, oidcJson, secret, samlJson }))));

    // ---- Saving the configuration ----

    /// <summary>Saves (or replaces) the OIDC connection. Everything is reset: disabled, untested, domain unverified (unless it is a development loopback).</summary>
    public async Task<(SsoConnection? Connection, string? Error)> RegisterOidcAsync(Organization org, OidcRegistration input, CancellationToken ct)
    {
        var (settings, error) = await ResolveEndpointsAsync(input, ct);
        if (settings is null) return (null, error);
        var oidcJson = JsonSerializer.Serialize(settings, Json);
        var providerId = ProviderIdFor(org.Id);
        var verified = DevLoopbackVerified && Uri.TryCreate(input.Issuer, UriKind.Absolute, out var issuerUri) && OutboundPolicy.IsLoopbackHost(issuerUri.Host);
        var now = DateTime.UtcNow;
        var revision = Revision("oidc", input.Issuer, input.Domain, oidcJson, input.ClientSecret, null);

        var existing = await db.Set<SsoConnection>().FirstOrDefaultAsync(c => c.OrganizationId == org.Id, ct);
        if (existing is null)
        {
            existing = new SsoConnection
            {
                Id = Ids.New("ssc"), OrganizationId = org.Id, ProviderId = providerId, Kind = "oidc", Issuer = input.Issuer, Domain = input.Domain,
                Status = "disabled", SignInPath = SignInPathFor(org.Slug), ConfigRevision = revision, TestStatus = "untested", CreatedAt = now, UpdatedAt = now,
            };
            db.Add(existing);
        }
        existing.Kind = "oidc";
        existing.Issuer = input.Issuer;
        existing.Domain = input.Domain;
        existing.Status = "disabled";
        existing.SignInPath = SignInPathFor(org.Slug);
        existing.ConfigRevision = revision;
        existing.TestStatus = "untested";
        existing.LastTestedAt = null;
        existing.LastTestedRevision = null;
        existing.LastError = null;
        existing.DomainVerified = verified;
        existing.DomainVerificationToken = null;
        existing.DomainVerificationExpiresAt = null;
        existing.OidcConfigJson = oidcJson;
        existing.ClientSecretProtected = secrets.Protect(input.ClientSecret);
        existing.SamlConfigJson = null;
        ClearTest(existing);
        existing.UpdatedAt = now;
        await db.SaveChangesAsync(ct);
        // Earlier sign-ins in flight belong to the old configuration.
        await db.Set<SsoAuthState>().Where(s => s.ProviderId == providerId).ExecuteDeleteAsync(ct);
        return (existing, null);
    }

    private async Task<(OidcSettings?, string? Error)> ResolveEndpointsAsync(OidcRegistration input, CancellationToken ct)
    {
        var allowPrivate = AllowPrivateNetworks;
        var scopes = input.Scopes is { Length: > 0 } ? input.Scopes : ["openid", "email", "profile"];
        var authMethod = input.TokenEndpointAuthentication ?? "client_secret_basic";
        if (!OutboundPolicy.IsAcceptableUrl(input.Issuer, allowPrivate)) return (null, "The issuer must be a public https URL.");

        string? authz = input.AuthorizationEndpoint, token = input.TokenEndpoint, jwks = input.JwksEndpoint, userinfo = input.UserInfoEndpoint;
        if (input.SkipDiscovery)
        {
            if (authz is null || token is null || jwks is null) return (null, "Manual OIDC configuration requires authorization, token, and JWKS endpoints.");
        }
        else
        {
            try
            {
                var client = http.CreateClient(IdpHttp.ClientName);
                using var request = new HttpRequestMessage(HttpMethod.Get, input.Issuer.TrimEnd('/') + "/.well-known/openid-configuration");
                request.Headers.Accept.ParseAdd("application/json");
                using var response = await client.SendAsync(request, ct);
                if (!response.IsSuccessStatusCode) return (null, $"OIDC discovery failed with {(int)response.StatusCode}. Enter manual OIDC endpoints or enable skip discovery.");
                using var doc = JsonDocument.Parse(await IdpHttp.ReadLimitedAsync(response, ct));
                string? Get(string name) => doc.RootElement.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
                if (Get("issuer") is not { } discoveredIssuer || Get("authorization_endpoint") is not { } a || Get("token_endpoint") is not { } t || Get("jwks_uri") is not { } j)
                    return (null, "OIDC discovery document is missing required endpoints.");
                if (discoveredIssuer.TrimEnd('/') != input.Issuer.TrimEnd('/')) return (null, "OIDC discovery issuer does not match the configured issuer.");
                authz = a; token = t; jwks = j; userinfo = Get("userinfo_endpoint");
            }
            catch (Exception e) when (e is HttpRequestException or JsonException or InvalidDataException or TaskCanceledException or InvalidOperationException)
            {
                return (null, "OIDC discovery failed. Enter manual OIDC endpoints or enable skip discovery.");
            }
        }
        foreach (var (label, value) in new[] { ("authorization", authz), ("token", token), ("JWKS", jwks), ("userinfo", userinfo) })
            if (value is not null && !OutboundPolicy.IsAcceptableUrl(value, allowPrivate)) return (null, $"The {label} endpoint must be a public https URL.");
        return (new OidcSettings(input.ClientId, scopes, authz!, token!, jwks!, userinfo, authMethod), null);
    }

    // ---- Domain verification ----

    public async Task<string> RequestDomainTokenAsync(SsoConnection c, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        if (c.DomainVerificationToken is { } existing && c.DomainVerificationExpiresAt > now) return existing;
        c.DomainVerificationToken = Base64Url(RandomNumberGenerator.GetBytes(18));
        c.DomainVerificationExpiresAt = now.Add(DomainTokenLifetime);
        c.UpdatedAt = now;
        await db.SaveChangesAsync(ct);
        return c.DomainVerificationToken;
    }

    /// <summary>Checks the DNS record. Every claimed domain must carry it; a domain already verified by another workspace cannot be claimed twice.</summary>
    public async Task<(int Status, string Message)?> VerifyDomainAsync(SsoConnection c, CancellationToken ct)
    {
        if (c.DomainVerified) return (409, "Domain has already been verified");
        if (c.DomainVerificationToken is null || c.DomainVerificationExpiresAt <= DateTime.UtcNow) return (404, "No pending domain verification exists");
        var domains = Domains(c.Domain);
        if (domains.Length == 0 || domains.Any(d => !d.Contains('.') || d.Length > 190)) return (400, "Invalid domain");
        var host = VerificationHost(c.ProviderId);
        if (host.Length > 63) return (400, $"Verification identifier exceeds the DNS label limit of 63 characters");
        var expected = $"{host}={c.DomainVerificationToken}";
        foreach (var domain in domains)
        {
            IReadOnlyList<string> records;
            try { records = await dns.ResolveTxtAsync($"{host}.{domain}", ct); }
            catch (Exception e) when (e is InvalidOperationException or InvalidDataException or OperationCanceledException) { records = []; }
            if (!records.Any(r => FixedEquals(r.Trim(), expected) || FixedEquals(r.Trim(), c.DomainVerificationToken)))
                return (502, $"Unable to verify domain ownership for {domain}. Try again later");
        }
        // Another workspace that already proved one of these domains keeps it.
        var others = await db.Set<SsoConnection>().Where(o => o.DomainVerified && o.OrganizationId != c.OrganizationId).Select(o => o.Domain).ToListAsync(ct);
        if (others.Any(o => Domains(o).Intersect(domains).Any())) return (409, "Another workspace has already verified this domain.");

        var claimed = await db.Set<SsoConnection>().Where(o => o.Id == c.Id && o.Domain == c.Domain && o.ConfigRevision == c.ConfigRevision)
            .ExecuteUpdateAsync(s => s.SetProperty(o => o.DomainVerified, true).SetProperty(o => o.DomainVerificationToken, (string?)null).SetProperty(o => o.UpdatedAt, DateTime.UtcNow), ct);
        return claimed == 0 ? (409, "SSO provider changed while domain verification was in progress. Reload the provider and try again") : null;
    }

    // ---- Testing, enabling, disabling ----

    public static void ClearTest(SsoConnection c)
    {
        c.ActiveTestIntentId = null;
        c.ActiveTestUserId = null;
        c.ActiveTestProviderId = null;
        c.ActiveTestConfigRevision = null;
        c.ActiveTestExpiresAt = null;
        c.ActiveTestStartedAt = null;
    }

    public const string ExpiredMessage = "The SSO authentication test expired. Start a new test and complete it within five minutes.";
    public static readonly Dictionary<string, string> FailureMessages = new()
    {
        ["authentication"] = "SSO authentication did not complete successfully. Check the provider configuration and try again.",
        ["cancelled"] = "The SSO authentication window was closed before the test completed. Start a new test and try again.",
        ["expired"] = ExpiredMessage,
        ["identity_mismatch"] = "SSO authenticated a different account. Sign in at the identity provider with the same administrator account and try again.",
        ["start_failed"] = "The SSO authentication test could not be started. Check the provider configuration and try again.",
    };

    public static (string TestStatus, string? LastError, DateTime? ExpiresAt) Presentation(SsoConnection c, DateTime now)
    {
        if (c.TestStatus == "testing" && (c.ActiveTestExpiresAt is null || c.ActiveTestExpiresAt <= now)) return ("failed", ExpiredMessage, null);
        var status = c.TestStatus is "succeeded" or "failed" or "testing" ? c.TestStatus : "untested";
        return (status, c.LastError, c.ActiveTestExpiresAt);
    }

    private static bool ActiveTestMatches(SsoConnection c, string intentId, string? userId, bool requireStarted, DateTime now) =>
        c.Status == "disabled" && c.TestStatus == "testing" && c.ActiveTestIntentId == intentId
        && (userId is null || c.ActiveTestUserId == userId) && c.ActiveTestProviderId == c.ProviderId && c.ActiveTestConfigRevision == c.ConfigRevision
        && c.ActiveTestExpiresAt > now && (!requireStarted || c.ActiveTestStartedAt is not null);

    public async Task<(string? IntentId, DateTime ExpiresAt, string? Error)> CreateTestAsync(SsoConnection c, string userId, CancellationToken ct)
    {
        if (!c.DomainVerified) return (null, default, "Verify the SSO domain before testing this configuration.");
        if (c.Status == "enabled") return (null, default, "Disable SSO before testing a replacement configuration.");
        var intent = Guid.NewGuid().ToString();
        var expires = DateTime.UtcNow.Add(TestLifetime);
        c.TestStatus = "testing";
        c.LastError = null;
        c.ActiveTestIntentId = intent;
        c.ActiveTestUserId = userId;
        c.ActiveTestProviderId = c.ProviderId;
        c.ActiveTestConfigRevision = c.ConfigRevision;
        c.ActiveTestExpiresAt = expires;
        c.ActiveTestStartedAt = null;
        c.UpdatedAt = DateTime.UtcNow;
        await db.SaveChangesAsync(ct);
        return (intent, expires, null);
    }

    /// <summary>Marks the test as started, once, for the administrator who created it.</summary>
    public async Task<(SsoConnection? Connection, string? Error)> BeginTestAsync(string organizationId, string intentId, string userId, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        var c = await ForOrganizationAsync(organizationId);
        if (c is null) return (null, "SSO configuration was not found.");
        if (c.ActiveTestIntentId == intentId && c.ActiveTestExpiresAt <= now)
        {
            await FailTestAsync(intentId, "expired");
            return (null, ExpiredMessage);
        }
        if (!ActiveTestMatches(c, intentId, userId, false, now) || c.ActiveTestStartedAt is not null) return (null, "This SSO authentication test is no longer available. Start a new test.");
        var updated = await db.Set<SsoConnection>().Where(o => o.Id == c.Id && o.ActiveTestIntentId == intentId && o.ActiveTestUserId == userId
                && o.ActiveTestConfigRevision == c.ConfigRevision && o.ActiveTestExpiresAt > now && o.ActiveTestStartedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(o => o.ActiveTestStartedAt, now), ct);
        if (updated != 1) return (null, "This SSO authentication test has already been used. Start a new test.");
        c.ActiveTestStartedAt = now;
        return (c, null);
    }

    public async Task<bool> FailTestAsync(string intentId, string reason)
    {
        var message = FailureMessages[reason];
        return await db.Set<SsoConnection>().Where(c => c.ActiveTestIntentId == intentId && c.TestStatus == "testing")
            .ExecuteUpdateAsync(s => s.SetProperty(c => c.TestStatus, "failed").SetProperty(c => c.LastError, message)
                .SetProperty(c => c.ActiveTestIntentId, (string?)null).SetProperty(c => c.ActiveTestUserId, (string?)null).SetProperty(c => c.ActiveTestProviderId, (string?)null)
                .SetProperty(c => c.ActiveTestConfigRevision, (string?)null).SetProperty(c => c.ActiveTestExpiresAt, (DateTime?)null).SetProperty(c => c.ActiveTestStartedAt, (DateTime?)null)) == 1;
    }

    /// <summary>Is this a started, current test? (A disabled connection signs nobody in except for such a test.)</summary>
    public static bool IsLiveTest(SsoConnection c, string intentId) => ActiveTestMatches(c, intentId, null, true, DateTime.UtcNow);

    public async Task<bool> CompleteTestAsync(string intentId, string providerId, string? authenticatedUserId)
    {
        var c = await db.Set<SsoConnection>().AsNoTracking().FirstOrDefaultAsync(o => o.ActiveTestIntentId == intentId);
        if (c is null || !ActiveTestMatches(c, intentId, null, true, DateTime.UtcNow)) return false;
        if (authenticatedUserId is null || authenticatedUserId != c.ActiveTestUserId || providerId != c.ProviderId)
        {
            await FailTestAsync(intentId, "identity_mismatch");
            return false;
        }
        var now = DateTime.UtcNow;
        return await db.Set<SsoConnection>().Where(o => o.Id == c.Id && o.Status == "disabled" && o.TestStatus == "testing" && o.ActiveTestIntentId == intentId
                && o.ActiveTestProviderId == providerId && o.ActiveTestConfigRevision == c.ConfigRevision && o.ActiveTestStartedAt != null)
            .ExecuteUpdateAsync(s => s.SetProperty(o => o.TestStatus, "succeeded").SetProperty(o => o.LastTestedAt, now).SetProperty(o => o.LastTestedRevision, c.ConfigRevision)
                .SetProperty(o => o.LastError, (string?)null).SetProperty(o => o.ActiveTestIntentId, (string?)null).SetProperty(o => o.ActiveTestUserId, (string?)null)
                .SetProperty(o => o.ActiveTestProviderId, (string?)null).SetProperty(o => o.ActiveTestConfigRevision, (string?)null)
                .SetProperty(o => o.ActiveTestExpiresAt, (DateTime?)null).SetProperty(o => o.ActiveTestStartedAt, (DateTime?)null)) == 1;
    }

    public async Task<Outcome> CancelTestAsync(SsoConnection? c, string intentId, string userId)
    {
        if (c?.ActiveTestIntentId == intentId && c.ActiveTestUserId == userId) await FailTestAsync(intentId, "cancelled");
        return Outcome.Success;
    }

    public async Task<Outcome> EnableAsync(string organizationId, CancellationToken ct)
    {
        var c = await ForOrganizationAsync(organizationId);
        if (c is null) return Outcome.Fail("SSO configuration was not found.");
        if (!c.DomainVerified) return Outcome.Fail("Verify the SSO domain before enabling SSO.");
        if (c.TestStatus != "succeeded" || c.LastTestedRevision is null || c.LastTestedRevision != c.ConfigRevision)
            return Outcome.Fail("Test the current SSO configuration successfully before enabling SSO.");
        var revision = c.LastTestedRevision;
        var updated = await db.Set<SsoConnection>().Where(o => o.Id == c.Id && o.ConfigRevision == revision && o.LastTestedRevision == revision && o.TestStatus == "succeeded" && o.DomainVerified)
            .ExecuteUpdateAsync(s => s.SetProperty(o => o.Status, "enabled").SetProperty(o => o.LastError, (string?)null).SetProperty(o => o.UpdatedAt, DateTime.UtcNow), ct);
        return updated == 1 ? Outcome.Success : Outcome.Fail("The SSO configuration changed before it could be enabled. Test it again.");
    }

    public async Task<bool> DisableAsync(string organizationId, CancellationToken ct) =>
        await db.Set<SsoConnection>().Where(c => c.OrganizationId == organizationId)
            .ExecuteUpdateAsync(s => s.SetProperty(c => c.Status, "disabled").SetProperty(c => c.UpdatedAt, DateTime.UtcNow), ct) > 0;

    /// <summary>Deletes the connection; what SSO created is cleaned up like the reference does (links removed, SSO-only identities deactivated).</summary>
    public async Task DeleteAsync(SsoConnection c, CancellationToken ct)
    {
        await db.Set<ExternalIdentity>().Where(i => i.OrganizationId == c.OrganizationId && i.SsoProviderId == c.ProviderId && i.ScimProviderId != null)
            .ExecuteUpdateAsync(s => s.SetProperty(i => i.Source, "scim").SetProperty(i => i.SsoProviderId, (string?)null).SetProperty(i => i.RemoteId, (string?)null), ct);
        await db.Set<ExternalIdentity>().Where(i => i.OrganizationId == c.OrganizationId && i.SsoProviderId == c.ProviderId && i.ScimProviderId == null)
            .ExecuteUpdateAsync(s => s.SetProperty(i => i.Active, false).SetProperty(i => i.SsoProviderId, (string?)null).SetProperty(i => i.RemoteId, (string?)null), ct);
        await db.Set<ExternalAccount>().Where(a => a.ProviderId == c.ProviderId).ExecuteDeleteAsync(ct);
        await db.Set<SsoAuthState>().Where(s => s.ProviderId == c.ProviderId).ExecuteDeleteAsync(ct);
        await db.Set<SsoConnection>().Where(o => o.Id == c.Id).ExecuteDeleteAsync(ct);
    }

    // ---- Presentation ----

    public object Payload(SsoConnection c)
    {
        var (testStatus, lastError, testExpires) = Presentation(c, DateTime.UtcNow);
        var oidc = Settings(c);
        var providerId = c.ProviderId;
        return new
        {
            id = c.Id,
            providerId,
            kind = c.Kind,
            issuer = c.Issuer,
            domain = c.Domain,
            status = c.DomainVerified && c.Status == "enabled" ? "enabled" : "disabled",
            testStatus,
            testExpiresAt = testExpires is { } e ? Responses.IsoUtc(e) : null,
            signInPath = c.SignInPath,
            signInUrl = urls.Web + c.SignInPath,
            redirectUrl = RedirectUrl(providerId),
            acsUrl = (string?)null,
            metadataUrl = (string?)null,
            domainVerified = c.DomainVerified,
            domainVerificationHost = VerificationHost(providerId),
            domainVerificationDnsName = $"{VerificationHost(providerId)}.{c.Domain}",
            oidc = oidc is null ? null : new
            {
                clientId = (string?)oidc.ClientId,
                scopes = oidc.Scopes,
                skipDiscovery = true,
                authorizationEndpoint = (string?)oidc.AuthorizationEndpoint,
                tokenEndpoint = (string?)oidc.TokenEndpoint,
                jwksEndpoint = (string?)oidc.JwksEndpoint,
                userInfoEndpoint = oidc.UserInfoEndpoint,
                tokenEndpointAuthentication = (string?)oidc.TokenEndpointAuthentication,
            },
            saml = (object?)null,
            lastTestedAt = c.LastTestedAt is { } t ? Responses.IsoUtc(t) : null,
            lastError,
            createdAt = Responses.IsoUtc(c.CreatedAt),
            updatedAt = Responses.IsoUtc(c.UpdatedAt),
        };
    }

    public string RedirectUrl(string providerId) => $"{urls.Api}/api/auth/sso/callback/{Uri.EscapeDataString(providerId)}";

    public static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static bool FixedEquals(string a, string b) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));
}
