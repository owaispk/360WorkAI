using System.Collections.Concurrent;
using Microsoft.Extensions.Options;

namespace WorkAI360.Api.Auth;

public sealed record AuthLimitPolicy(string Name, TimeSpan Window, int EmailMax, int IpMax);

/// <summary>
/// Fixed-window limits on the email endpoints: tight per address (what an attacker targets) and generous per source address
/// (so a whole office can sign up together). Numbers match the reference. In memory, per instance.
/// </summary>
public sealed class RateLimiter(IOptions<AuthOptions> options, IHostEnvironment environment)
{
    public static readonly AuthLimitPolicy SignUp = new("sign-up", TimeSpan.FromHours(1), 5, 60);
    public static readonly AuthLimitPolicy SignIn = new("sign-in", TimeSpan.FromMinutes(5), 10, 100);
    public static readonly AuthLimitPolicy SendOtp = new("send-otp", TimeSpan.FromHours(1), 5, 60);
    public static readonly AuthLimitPolicy VerifyOtp = new("verify-otp", TimeSpan.FromMinutes(5), 10, 100);
    public static readonly AuthLimitPolicy ResetRequest = new("reset-request", TimeSpan.FromHours(1), 5, 30);

    private readonly ConcurrentDictionary<string, (int Count, DateTime Start)> _buckets = new();
    private int _sweep;

    public bool Enabled => options.Value.RateLimitsEnabled ?? !environment.IsDevelopment();

    /// <summary>Counts one request. Returns how long to wait when a limit is exceeded, otherwise null.</summary>
    public TimeSpan? Hit(AuthLimitPolicy policy, string? email, string? ip)
    {
        if (!Enabled) return null;
        var now = DateTime.UtcNow;
        if (Interlocked.Increment(ref _sweep) % 500 == 0) Sweep(now);

        TimeSpan? worst = null;
        if (!string.IsNullOrEmpty(email)) worst = Max(worst, Count($"{policy.Name}:email:{email}", policy.EmailMax, policy.Window, now));
        worst = Max(worst, Count($"{policy.Name}:ip:{ip ?? "unknown"}", policy.IpMax, policy.Window, now));
        return worst;
    }

    /// <summary>
    /// A fixed window on any key. Returns how long to wait when the window is already full; otherwise (when <paramref name="consume"/>) counts
    /// one use and returns null. With <paramref name="consume"/> false it only reads, so a refused caller does not spend shared budgets.
    /// </summary>
    public TimeSpan? Window(string key, int max, TimeSpan window, bool consume)
    {
        if (!Enabled) return null;
        var now = DateTime.UtcNow;
        if (Interlocked.Increment(ref _sweep) % 500 == 0) Sweep(now);
        var lockObject = _buckets;
        lock (lockObject)
        {
            _buckets.TryGetValue(key, out var state);
            if (state.Start == default || now - state.Start >= window) state = (0, now);
            if (state.Count >= max) { _buckets[key] = state; return state.Start + window - now; }
            _buckets[key] = consume ? (state.Count + 1, state.Start) : state;
            return null;
        }
    }

    private TimeSpan? Count(string key, int max, TimeSpan window, DateTime now)
    {
        var state = _buckets.AddOrUpdate(key, _ => (1, now), (_, s) => now - s.Start >= window ? (1, now) : (s.Count + 1, s.Start));
        return state.Count > max ? state.Start + window - now : null;
    }

    private static TimeSpan? Max(TimeSpan? a, TimeSpan? b) => a is null ? b : b is null ? a : a > b ? a : b;

    private void Sweep(DateTime now)
    {
        foreach (var (key, state) in _buckets)
            if (now - state.Start > TimeSpan.FromHours(2)) _buckets.TryRemove(key, out _);
    }
}
