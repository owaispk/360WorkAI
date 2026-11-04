using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using StackExchange.Redis;

namespace WorkAI360.Api.Auth;

public sealed class CacheOptions
{
    public const string Section = "Cache";

    public RedisOptions Redis { get; set; } = new();

    public sealed class RedisOptions
    {
        /// <summary>
        /// A StackExchange.Redis connection string (e.g. <c>redis:6379,password=...,ssl=true</c>). Set it when more than one instance serves the API, so
        /// rate limits, sign-in lockouts and the approved-origin cache are shared. Unset (the default): everything stays in this process's memory.
        /// </summary>
        public string? ConnectionString { get; set; }

        /// <summary>Prefix of every key, so one Redis can serve several deployments.</summary>
        public string KeyPrefix { get; set; } = "workai360:";
    }
}

/// <summary>
/// State the API's instances must agree on: fixed-window counters (rate limits, lockouts) and short-lived values (caches). One implementation keeps
/// it in memory (one instance), the other in Redis (any number). Every operation is atomic on its own.
/// </summary>
public interface ISharedStore
{
    /// <summary>True when the state is shared between instances.</summary>
    bool IsShared { get; }

    /// <summary>Counts one hit in the window that the first hit opened. Returns the count after this hit and the time left in the window.</summary>
    (long Count, TimeSpan Remaining) Increment(string key, TimeSpan window);

    /// <summary>Counts one hit only when the window holds fewer than <paramref name="max"/>; otherwise returns how long until it reopens.</summary>
    TimeSpan? TryConsume(string key, int max, TimeSpan window);

    /// <summary>The window's count and time left, or null when no window is open.</summary>
    (long Count, TimeSpan Remaining)? Peek(string key);

    void Delete(string key);

    string? Get(string key);

    void Set(string key, string value, TimeSpan ttl);
}

/// <summary>Single-instance store: a dictionary with expiry, swept now and then.</summary>
public sealed class MemoryStore : ISharedStore
{
    private readonly ConcurrentDictionary<string, (long Count, string? Value, DateTime Expires)> _items = new();
    private readonly Lock _gate = new();
    private int _sweep;

    public bool IsShared => false;

    public (long Count, TimeSpan Remaining) Increment(string key, TimeSpan window)
    {
        var now = DateTime.UtcNow;
        Sweep(now);
        var item = _items.AddOrUpdate(key, _ => (1, null, now + window), (_, s) => s.Expires <= now ? (1, null, now + window) : (s.Count + 1, s.Value, s.Expires));
        return (item.Count, item.Expires - now);
    }

    public TimeSpan? TryConsume(string key, int max, TimeSpan window)
    {
        var now = DateTime.UtcNow;
        Sweep(now);
        lock (_gate)
        {
            if (_items.TryGetValue(key, out var s) && s.Expires > now)
            {
                if (s.Count >= max) return s.Expires - now;
                _items[key] = (s.Count + 1, s.Value, s.Expires);
                return null;
            }
            _items[key] = (1, null, now + window);
            return null;
        }
    }

    public (long Count, TimeSpan Remaining)? Peek(string key)
    {
        var now = DateTime.UtcNow;
        return _items.TryGetValue(key, out var s) && s.Expires > now ? (s.Count, s.Expires - now) : null;
    }

    public void Delete(string key) => _items.TryRemove(key, out _);

    public string? Get(string key) => _items.TryGetValue(key, out var s) && s.Expires > DateTime.UtcNow ? s.Value : null;

    public void Set(string key, string value, TimeSpan ttl) => _items[key] = (0, value, DateTime.UtcNow + ttl);

    private void Sweep(DateTime now)
    {
        if (Interlocked.Increment(ref _sweep) % 1000 != 0) return;
        foreach (var (key, item) in _items) if (item.Expires <= now) _items.TryRemove(key, out _);
    }
}

/// <summary>
/// Redis store. Counters are one Lua script each (count and expiry set together, so a window can never lose its expiry). Keys are the configured prefix
/// plus a SHA-256 of the logical key, so addresses, emails and client ids never appear in Redis in clear. If Redis cannot be reached, counters answer
/// "not limited" and reads answer "not cached" (logged at most once a minute): an outage of the cache never locks people out, and callers fall back to
/// the database.
/// </summary>
public sealed class RedisStore(IConnectionMultiplexer redis, string prefix, ILogger<RedisStore> logger) : ISharedStore
{
    // KEYS[1]: counter; ARGV[1]: window in ms. Returns {count, ms left}.
    private const string IncrementScript = """
        local n = redis.call('INCR', KEYS[1])
        if n == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
        local ttl = redis.call('PTTL', KEYS[1])
        if ttl < 0 then redis.call('PEXPIRE', KEYS[1], ARGV[1]); ttl = tonumber(ARGV[1]) end
        return {n, ttl}
        """;

    // KEYS[1]: counter; ARGV[1]: max; ARGV[2]: window in ms. Returns ms to wait, or -1 when the hit was counted.
    private const string TryConsumeScript = """
        local n = tonumber(redis.call('GET', KEYS[1]) or '0')
        if n >= tonumber(ARGV[1]) then
          local ttl = redis.call('PTTL', KEYS[1])
          if ttl > 0 then return ttl end
        end
        n = redis.call('INCR', KEYS[1])
        if n == 1 or redis.call('PTTL', KEYS[1]) < 0 then redis.call('PEXPIRE', KEYS[1], ARGV[2]) end
        return -1
        """;

    private long _lastLogged;

    public bool IsShared => true;

    private RedisKey Key(string key) => prefix + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key)))[..40];

    private IDatabase Db => redis.GetDatabase();

    public (long Count, TimeSpan Remaining) Increment(string key, TimeSpan window)
    {
        try
        {
            var result = (RedisResult[])Db.ScriptEvaluate(IncrementScript, [Key(key)], [(long)window.TotalMilliseconds])!;
            return ((long)result[0], TimeSpan.FromMilliseconds((long)result[1]));
        }
        catch (Exception e) when (e is RedisException or TimeoutException) { Failed(e); return (0, TimeSpan.Zero); }
    }

    public TimeSpan? TryConsume(string key, int max, TimeSpan window)
    {
        try
        {
            var wait = (long)Db.ScriptEvaluate(TryConsumeScript, [Key(key)], [max, (long)window.TotalMilliseconds]);
            return wait < 0 ? null : TimeSpan.FromMilliseconds(wait);
        }
        catch (Exception e) when (e is RedisException or TimeoutException) { Failed(e); return null; }
    }

    public (long Count, TimeSpan Remaining)? Peek(string key)
    {
        try
        {
            var k = Key(key);
            var value = Db.StringGet(k);
            if (value.IsNullOrEmpty) return null;
            var ttl = Db.KeyTimeToLive(k);
            return ttl is { } left && left > TimeSpan.Zero ? ((long)value, left) : null;
        }
        catch (Exception e) when (e is RedisException or TimeoutException) { Failed(e); return null; }
    }

    public void Delete(string key)
    {
        try { Db.KeyDelete(Key(key)); }
        catch (Exception e) when (e is RedisException or TimeoutException) { Failed(e); }
    }

    public string? Get(string key)
    {
        try { var v = Db.StringGet(Key(key)); return v.IsNull ? null : v.ToString(); }
        catch (Exception e) when (e is RedisException or TimeoutException) { Failed(e); return null; }
    }

    public void Set(string key, string value, TimeSpan ttl)
    {
        try { Db.StringSet(Key(key), value, ttl); }
        catch (Exception e) when (e is RedisException or TimeoutException) { Failed(e); }
    }

    private void Failed(Exception e)
    {
        var now = Environment.TickCount64;
        if (now - Interlocked.Read(ref _lastLogged) < 60_000) return;
        Interlocked.Exchange(ref _lastLogged, now);
        logger.LogWarning("shared store (Redis) unreachable; limits fail open and caches miss until it is back ({Error})", e.GetType().Name);
    }
}
