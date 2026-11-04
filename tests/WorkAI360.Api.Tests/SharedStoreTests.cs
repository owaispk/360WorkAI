using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using StackExchange.Redis;
using WorkAI360.Api.Auth;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>The store contract, run against each implementation.</summary>
public abstract class SharedStoreContract
{
    protected abstract ISharedStore Store { get; }

    private static string K(string name) => $"test:{name}:{Guid.NewGuid():N}";

    [Fact]
    public void Increment_counts_within_one_window_and_starts_over_after_it()
    {
        var key = K("inc");
        Assert.Equal(1, Store.Increment(key, TimeSpan.FromMilliseconds(400)).Count);
        var (count, remaining) = Store.Increment(key, TimeSpan.FromMilliseconds(400));
        Assert.Equal(2, count);
        Assert.InRange(remaining, TimeSpan.FromMilliseconds(1), TimeSpan.FromMilliseconds(400));
        Thread.Sleep(500);
        Assert.Equal(1, Store.Increment(key, TimeSpan.FromMilliseconds(400)).Count);
    }

    [Fact]
    public void TryConsume_counts_up_to_the_limit_then_answers_the_wait_without_counting()
    {
        var key = K("consume");
        for (var i = 0; i < 3; i++) Assert.Null(Store.TryConsume(key, 3, TimeSpan.FromMinutes(1)));
        var wait = Store.TryConsume(key, 3, TimeSpan.FromMinutes(1));
        Assert.NotNull(wait);
        Assert.InRange(wait!.Value, TimeSpan.FromSeconds(1), TimeSpan.FromMinutes(1));
        Assert.Equal(3, Store.Peek(key)!.Value.Count);
    }

    [Fact]
    public void Concurrent_consumers_never_go_over_the_limit()
    {
        var key = K("race");
        var admitted = 0;
        Parallel.For(0, 200, new ParallelOptions { MaxDegreeOfParallelism = 16 }, _ => { if (Store.TryConsume(key, 50, TimeSpan.FromMinutes(1)) is null) Interlocked.Increment(ref admitted); });
        Assert.Equal(50, admitted);
    }

    [Fact]
    public void Peek_delete_and_values()
    {
        var key = K("peek");
        Assert.Null(Store.Peek(key));
        Store.Increment(key, TimeSpan.FromMinutes(1));
        Assert.Equal(1, Store.Peek(key)!.Value.Count);
        Store.Delete(key);
        Assert.Null(Store.Peek(key));

        var value = K("value");
        Assert.Null(Store.Get(value));
        Store.Set(value, "1", TimeSpan.FromMilliseconds(300));
        Assert.Equal("1", Store.Get(value));
        Thread.Sleep(400);
        Assert.Null(Store.Get(value));
    }
}

public sealed class MemoryStoreTests : SharedStoreContract
{
    protected override ISharedStore Store { get; } = new MemoryStore();
}

/// <summary>A test that needs a real Redis: skipped unless WORKAI_TEST_REDIS is set (e.g. <c>localhost:6379</c>).</summary>
public sealed class RedisFactAttribute : FactAttribute
{
    public RedisFactAttribute() { if (RedisStoreTests.Connection is null) Skip = "WORKAI_TEST_REDIS is not set"; }
}

/// <summary>The contract against a real Redis. Without WORKAI_TEST_REDIS the shared contract runs against memory again (see Store).</summary>
public sealed class RedisStoreTests : SharedStoreContract, IDisposable
{
    public static readonly string? Connection = Environment.GetEnvironmentVariable("WORKAI_TEST_REDIS");
    private readonly ConnectionMultiplexer? _redis = Connection is null ? null : ConnectionMultiplexer.Connect(Connection);

    // Without a Redis the inherited contract tests run against memory, so they still pass; the Redis-only tests below are [RedisFact].
    private ISharedStore? _store;
    protected override ISharedStore Store => _store ??= _redis is null ? new MemoryStore() : new RedisStore(_redis, "workai360-test:", NullLogger<RedisStore>.Instance);

    [RedisFact]
    public void Keys_are_hashed_so_no_address_or_email_is_stored_in_clear()
    {
        var store = Store;
        store.Increment("login-failures:secret.person@example.com", TimeSpan.FromMinutes(1));
        var server = _redis!.GetServer(_redis.GetEndPoints()[0]);
        var keys = server.Keys(pattern: "workai360-test:*").Select(k => k.ToString()).ToList();
        Assert.NotEmpty(keys);
        Assert.DoesNotContain(keys, k => k.Contains("example.com", StringComparison.Ordinal) || k.Contains("secret", StringComparison.Ordinal));
    }

    [RedisFact]
    public void An_unreachable_redis_fails_open_and_misses()
    {
        var config = ConfigurationOptions.Parse("127.0.0.1:1");
        config.AbortOnConnectFail = false;
        config.ConnectTimeout = 200;
        config.SyncTimeout = 200;
        using var dead = ConnectionMultiplexer.Connect(config);
        var store = new RedisStore(dead, "x:", NullLogger<RedisStore>.Instance);
        Assert.Null(store.TryConsume("k", 1, TimeSpan.FromMinutes(1)));
        Assert.Null(store.TryConsume("k", 1, TimeSpan.FromMinutes(1)));
        Assert.Null(store.Peek("k"));
        Assert.Null(store.Get("k"));
    }

    public void Dispose() => _redis?.Dispose();
}

/// <summary>Two API instances (separate processes' worth of state) sharing one Redis.</summary>
public class SharedRedisInstance : ApiFactory
{
    public static readonly string Prefix = $"workai360-shared-{Guid.NewGuid():N}:";
    protected override IEnumerable<KeyValuePair<string, string>> Settings =>
        RedisStoreTests.Connection is null ? [] : [new("Cache:Redis:ConnectionString", RedisStoreTests.Connection), new("Cache:Redis:KeyPrefix", Prefix)];
}

public sealed class SharedRedisInstanceA : SharedRedisInstance;
public sealed class SharedRedisInstanceB : SharedRedisInstance;

public sealed class SharedLimitTests(SharedRedisInstanceA a, SharedRedisInstanceB b) : IClassFixture<SharedRedisInstanceA>, IClassFixture<SharedRedisInstanceB>
{
    [RedisFact]
    public async Task A_sign_in_lockout_counted_on_two_instances_holds_on_both()
    {
        Assert.True(a.Services.GetRequiredService<ISharedStore>().IsShared);
        var email = NewEmail("locked");
        async Task<HttpStatusCode> Try(ApiFactory instance) =>
            (await instance.Plain().PostAsJsonAsync("/api/auth/sign-in/email", new { email, password = "Wrong!Passw0rd#1" })).StatusCode;
        // Five failures, split between the instances (the lockout is 5 in 15 minutes).
        foreach (var instance in new ApiFactory[] { a, b, a, b, a }) Assert.Equal(HttpStatusCode.Unauthorized, await Try(instance));
        Assert.Equal(HttpStatusCode.TooManyRequests, await Try(b));
        Assert.Equal(HttpStatusCode.TooManyRequests, await Try(a));
    }
}
