using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.OAuthExtras;
using WorkAI360.Api.Endpoints;
using WorkAI360.Api.Features.Replay;
using WorkAI360.Api.Features.Sso;

namespace WorkAI360.Api.OAuth;

/// <summary>An OAuth error that should be answered as given (status, <c>error</c>, <c>error_description</c>).</summary>
public sealed class OAuthProblem(int status, string error, string description) : Exception(description)
{
    public int Status { get; } = status;
    public string Error { get; } = error;
    public IResult ToResult() => Results.Json(new { error = Error, error_description = Message }, statusCode: Status);
}

/// <summary>The keys of a client that authenticates with <c>private_key_jwt</c>: validation of a JWK Set and fetching one from the client's <c>jwks_uri</c>.</summary>
public sealed class ClientJwksStore(IHttpClientFactory http, IOptions<OAuthClientMetadataOptions> options)
{
    public const string HttpClientName = "oauth-client-jwks";
    public const int MaxKeys = 20;
    private const int MaxBytes = 64 * 1024;
    private static readonly TimeSpan Fresh = TimeSpan.FromMinutes(5);
    private static readonly ConcurrentDictionary<string, (JsonElement Set, DateTime FetchedAt)> Cache = new();

    /// <summary>A JWK Set the reference would accept: an object with a non-empty <c>keys</c> array of public RSA or EC keys. Returns the reason when it is not.</summary>
    public static string? Validate(JsonElement set)
    {
        if (set.ValueKind != JsonValueKind.Object || !set.TryGetProperty("keys", out var keys) || keys.ValueKind != JsonValueKind.Array || keys.GetArrayLength() == 0)
            return "jwks must be an RFC 7517 JWK Set object with a non-empty keys array";
        if (keys.GetArrayLength() > MaxKeys) return $"jwks may hold at most {MaxKeys} keys";
        foreach (var key in keys.EnumerateArray()) if (Jose.ValidatePublicKey(key) is { } reason) return reason;
        return null;
    }

    /// <summary>The reference's registration rules for a <c>jwks_uri</c> (https, no credentials or fragment, not a private address) plus, as it does, a trusted origin.</summary>
    public string? CheckUri(string uri, TrustedUrls trusted, bool forFetch = false)
    {
        if (!Uri.TryCreate(uri, UriKind.Absolute, out var parsed)) return "jwks_uri must be a valid URL";
        var allowPrivate = options.Value.AllowPrivateUrls;
        if (parsed.Scheme != Uri.UriSchemeHttps && !(allowPrivate && parsed.Scheme == Uri.UriSchemeHttp)) return "jwks_uri must use HTTPS";
        if (!string.IsNullOrEmpty(parsed.UserInfo)) return "jwks_uri must not contain credentials";
        if (uri.Contains('#')) return "jwks_uri must not include a fragment component";
        if (!allowPrivate && (OutboundPolicy.IsLoopbackHost(parsed.Host) || parsed.Host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase)
            || (IPAddress.TryParse(parsed.Host.Trim('[', ']'), out var literal) && !ClientMetadataPolicy.IsPublic(literal))))
            return "jwks_uri must not point to a private or reserved address";
        if (!trusted.IsTrusted(uri)) return forFetch ? "client jwks_uri is not trusted" : "jwks_uri must belong to a trusted origin";
        return null;
    }

    /// <summary>The client's keys. A fetched set is cached for five minutes (and reused up to ten when the client's server fails).</summary>
    public async Task<JsonElement?> KeysAsync(OAuthClientExtras extras, TrustedUrls trusted, bool forceRefresh, CancellationToken ct)
    {
        if (extras.JwksJson is { } inline) return JsonDocument.Parse(inline).RootElement.Clone();
        if (extras.JwksUri is not { } uri || CheckUri(uri, trusted, forFetch: true) is not null) return null;
        var now = DateTime.UtcNow;
        if (!forceRefresh && Cache.TryGetValue(uri, out var cached) && now - cached.FetchedAt < Fresh) return cached.Set;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.Accept.ParseAdd("application/json");
            using var response = await http.CreateClient(HttpClientName).SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            var media = response.Content.Headers.ContentType?.MediaType ?? "";
            if (response.StatusCode != HttpStatusCode.OK || !(media == "application/json" || media.EndsWith("+json", StringComparison.OrdinalIgnoreCase))) throw new InvalidDataException("not a JSON JWKS response");
            await using var stream = await response.Content.ReadAsStreamAsync(ct);
            var buffer = new byte[MaxBytes + 1];
            var read = 0;
            int n;
            while (read < buffer.Length && (n = await stream.ReadAsync(buffer.AsMemory(read), ct)) > 0) read += n;
            if (read > MaxBytes) throw new InvalidDataException("JWKS response exceeds 64 KiB");
            var set = JsonDocument.Parse(Encoding.UTF8.GetString(buffer, 0, read)).RootElement.Clone();
            if (Validate(set) is not null) throw new InvalidDataException("invalid JWKS");
            Cache[uri] = (set, now);
            return set;
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or OperationCanceledException or InvalidDataException or JsonException or IOException)
        {
            return Cache.TryGetValue(uri, out var stale) && now - stale.FetchedAt < Fresh * 2 ? stale.Set : null;
        }
    }
}

/// <summary>
/// <c>private_key_jwt</c> client authentication (RFC 7523, OpenID Connect Core 9), checked like the reference: the assertion type must be
/// <c>urn:ietf:params:oauth:client-assertion-type:jwt-bearer</c>; the algorithm one of RS/PS/ES 256-512; <c>iss</c> and <c>sub</c> both the client's id; the client
/// registered for <c>private_key_jwt</c>; the signature verifies under one of the client's keys (a <c>kid</c> in the header selects one); <c>aud</c> is the endpoint
/// or the issuer; <c>exp</c> is present, not past and at most 300 seconds ahead; <c>iat</c> not older than 300 seconds; <c>jti</c> is present and works once.
/// </summary>
public sealed class ClientAssertionVerifier(DenDbContext db, ClientResolver clients, ClientJwksStore jwks, ReplayGuard replay, OAuthUrls urls, TrustedUrls trusted)
{
    public const string AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    public const int MaxLifetimeSeconds = 300;

    /// <summary>The ids a client may name as audience for an assertion sent to this endpoint: the endpoint itself (either origin) or the issuer.</summary>
    public IReadOnlyList<string> Audiences(string endpointPath) => [$"{urls.Issuer}/{endpointPath}", $"{urls.Api}/api/auth/{endpointPath}", urls.Issuer];

    /// <summary>The client id an assertion names (<c>sub</c>, else <c>iss</c>), without trusting the assertion: only to pick a rate-limit bucket.</summary>
    public static string? PeekClientId(string? assertion) => Jose.Parse(assertion) is { } jwt ? jwt.PayloadString("sub") ?? jwt.PayloadString("iss") : null;

    public async Task<OAuthClient> AuthenticateAsync(string? assertion, string? assertionType, string? clientIdHint, string endpointPath, CancellationToken ct)
    {
        static OAuthProblem Invalid(string description, int status = 400) => new(status, "invalid_client", description);
        if (assertionType != AssertionType) throw Invalid("unsupported client_assertion_type");
        if (string.IsNullOrEmpty(assertion)) throw new OAuthProblem(400, "invalid_client", "client_assertion and client_assertion_type must both be provided");
        var jwt = Jose.Parse(assertion) ?? throw Invalid("malformed client assertion: invalid JWT header");
        var alg = jwt.HeaderString("alg");
        if (alg is null || !Jose.AssertionAlgorithms.Contains(alg)) throw Invalid($"unsupported assertion signing algorithm: {alg}");
        var clientId = jwt.PayloadString("sub") ?? jwt.PayloadString("iss") ?? throw Invalid("client assertion must contain sub or iss claim identifying the client");
        if (!string.IsNullOrEmpty(clientIdHint) && clientIdHint != clientId) throw Invalid("client_id in body does not match assertion sub/iss");

        var client = await clients.ResolveAsync(clientId, ct) ?? throw Invalid("unknown client");
        if (client.AuthMethod != "private_key_jwt") throw Invalid("client is not registered for private_key_jwt authentication");
        var extras = await db.Set<OAuthClientExtras>().AsNoTracking().FirstOrDefaultAsync(e => e.ClientId == clientId, ct);
        if (extras is null || (extras.JwksJson is null && extras.JwksUri is null)) throw Invalid("client has no JWKS configured");

        var set = await jwks.KeysAsync(extras, trusted, forceRefresh: false, ct) ?? throw Invalid("failed to fetch client JWKS");
        var verified = Verify(jwt, set, alg);
        if (!verified && extras.JwksUri is not null && await jwks.KeysAsync(extras, trusted, forceRefresh: true, ct) is { } refreshed) verified = Verify(jwt, refreshed, alg);
        if (!verified) throw Invalid("client assertion signature verification failed", 401);

        // Claims: the same single answer as a bad signature, as the reference's JWT library gives for issuer, subject and audience.
        var audiences = Audiences(endpointPath);
        var aud = jwt.Payload.TryGetProperty("aud", out var a) ? a : default;
        var named = aud.ValueKind == JsonValueKind.String ? [aud.GetString()!] : aud.ValueKind == JsonValueKind.Array ? aud.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).ToList() : [];
        if (jwt.PayloadString("iss") != clientId || jwt.PayloadString("sub") != clientId || !named.Any(n => audiences.Contains(n)))
            throw Invalid("client assertion signature verification failed", 401);

        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (jwt.PayloadNumber("nbf") is { } nbf && nbf > now + 5) throw Invalid("client assertion is not yet valid");
        if (jwt.PayloadNumber("exp") is not { } exp) throw Invalid("client assertion must include exp claim");
        if (exp <= now) throw Invalid("client assertion has expired");
        if (exp - now > MaxLifetimeSeconds) throw Invalid($"client assertion exp is too far in the future (max {MaxLifetimeSeconds}s)");
        if (jwt.PayloadNumber("iat") is { } iat && now - iat > MaxLifetimeSeconds) throw Invalid($"client assertion iat is too far in the past (max {MaxLifetimeSeconds}s)");
        if (jwt.PayloadString("jti") is not { Length: > 0 } jti || jti.Length > 512) throw Invalid("client assertion must include jti claim");
        if (!await replay.ReserveAsync("client-assertion", $"{clientId}\n{jti}", DateTimeOffset.FromUnixTimeSeconds(exp).UtcDateTime, ct)) throw Invalid("client assertion jti has already been used");
        return client;
    }

    private static bool Verify(ParsedJwt jwt, JsonElement set, string alg)
    {
        if (!set.TryGetProperty("keys", out var keys) || keys.ValueKind != JsonValueKind.Array) return false;
        var kid = jwt.HeaderString("kid");
        foreach (var key in keys.EnumerateArray())
        {
            if (kid is not null && Jose.Str(key, "kid") != kid) continue;
            if (!Jose.AlgorithmsFor(key).Contains(alg)) continue;
            if (Jose.Verify(jwt, key, Jose.AssertionAlgorithms)) return true;
        }
        return false;
    }
}
