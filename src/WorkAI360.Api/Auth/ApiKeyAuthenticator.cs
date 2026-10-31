using System.Collections.Concurrent;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.OrgAdmin;

namespace WorkAI360.Api.Auth;

/// <summary>A valid, unexpired, enabled organization API key and the person it acts as.</summary>
public sealed record ApiKeyPrincipal(ApiKey Key, User User);

/// <summary>Per-key request limit (fixed window, in memory, per instance). The reference gives each key 600 requests per minute.</summary>
public sealed class ApiKeyLimiter
{
    private readonly ConcurrentDictionary<string, (int Count, DateTime Start)> _windows = new();

    /// <summary>Counts one request. Returns how long to wait when the key is over its limit, otherwise null.</summary>
    public TimeSpan? Hit(ApiKey key)
    {
        if (!key.RateLimitEnabled || key.RateLimitMax <= 0) return null;
        var window = TimeSpan.FromMilliseconds(Math.Max(1, key.RateLimitTimeWindow));
        var now = DateTime.UtcNow;
        var state = _windows.AddOrUpdate(key.Id, _ => (1, now), (_, s) => now - s.Start >= window ? (1, now) : (s.Count + 1, s.Start));
        if (_windows.Count > 5000) foreach (var (id, s) in _windows) if (now - s.Start > TimeSpan.FromHours(1)) _windows.TryRemove(id, out _);
        return state.Count > key.RateLimitMax ? state.Start + window - now : null;
    }
}

/// <summary>
/// Authenticates a request that carries an organization API key. The key goes in the <c>x-api-key</c> header (as in the reference); a
/// <c>den_</c>-prefixed bearer token is accepted too, since that prefix cannot be mistaken for a session token. Keys are looked up by their
/// SHA-256, never stored in plain text. A key stops working when it expires, is disabled (member lost access) or is deleted.
/// </summary>
public sealed class ApiKeyAuthenticator(DenDbContext db, ApiKeyLimiter limiter)
{
    public const string Header = "x-api-key";
    public const string Prefix = "den_";
    private static readonly object CacheKey = new();

    public static string? Read(HttpRequest request)
    {
        var header = request.Headers[Header].ToString().Trim();
        if (header.Length > 0) return header;
        var bearer = SessionService.ReadBearer(request);
        return bearer is not null && bearer.StartsWith(Prefix, StringComparison.Ordinal) ? bearer : null;
    }

    /// <summary>The principal for the presented key, or null when none is presented or it is not valid. <paramref name="retryAfter"/> is set when a valid key is over its limit.</summary>
    public async Task<(ApiKeyPrincipal? Principal, TimeSpan? RetryAfter)> ResolveAsync(HttpContext ctx)
    {
        if (ctx.Items.TryGetValue(CacheKey, out var cached)) return ((ApiKeyPrincipal?, TimeSpan?))cached!;
        var result = await LookupAsync(ctx);
        ctx.Items[CacheKey] = result;
        return result;
    }

    private async Task<(ApiKeyPrincipal?, TimeSpan?)> LookupAsync(HttpContext ctx)
    {
        var secret = Read(ctx.Request);
        if (secret is null || secret.Length > 256) return (null, null);
        var hash = Ids.Sha256Hex(secret);
        var now = DateTime.UtcNow;
        var key = await db.Set<ApiKey>().AsNoTracking().FirstOrDefaultAsync(k => k.KeyHash == hash);
        if (key is null || !key.Enabled || key.ExpiresAt <= now) return (null, null);
        var user = await db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == key.UserId);
        if (user is null) return (null, null);
        if (limiter.Hit(key) is { } wait) return (null, wait);
        await db.Set<ApiKey>().Where(k => k.Id == key.Id).ExecuteUpdateAsync(s => s.SetProperty(k => k.LastRequestAt, now).SetProperty(k => k.UpdatedAt, now));
        return (new ApiKeyPrincipal(key, user), null);
    }
}
