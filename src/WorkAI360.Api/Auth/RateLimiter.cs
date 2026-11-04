using Microsoft.Extensions.Options;

namespace WorkAI360.Api.Auth;

public sealed record AuthLimitPolicy(string Name, TimeSpan Window, int EmailMax, int IpMax);

/// <summary>
/// Fixed-window limits on the email endpoints: tight per address (what an attacker targets) and generous per source address
/// (so a whole office can sign up together). Numbers match the reference. Counters live in the <see cref="ISharedStore"/>: this
/// instance's memory by default, Redis when <c>Cache:Redis:ConnectionString</c> is set (then every instance shares them).
/// </summary>
public sealed class RateLimiter(IOptions<AuthOptions> options, IHostEnvironment environment, ISharedStore store)
{
    public static readonly AuthLimitPolicy SignUp = new("sign-up", TimeSpan.FromHours(1), 5, 60);
    public static readonly AuthLimitPolicy SignIn = new("sign-in", TimeSpan.FromMinutes(5), 10, 100);
    public static readonly AuthLimitPolicy SendOtp = new("send-otp", TimeSpan.FromHours(1), 5, 60);
    public static readonly AuthLimitPolicy VerifyOtp = new("verify-otp", TimeSpan.FromMinutes(5), 10, 100);
    public static readonly AuthLimitPolicy ResetRequest = new("reset-request", TimeSpan.FromHours(1), 5, 30);

    public bool Enabled => options.Value.RateLimitsEnabled ?? !environment.IsDevelopment();

    /// <summary>Counts one request. Returns how long to wait when a limit is exceeded, otherwise null.</summary>
    public TimeSpan? Hit(AuthLimitPolicy policy, string? email, string? ip)
    {
        if (!Enabled) return null;
        TimeSpan? worst = null;
        if (!string.IsNullOrEmpty(email)) worst = Max(worst, Count($"rl:{policy.Name}:email:{email}", policy.EmailMax, policy.Window));
        worst = Max(worst, Count($"rl:{policy.Name}:ip:{ip ?? "unknown"}", policy.IpMax, policy.Window));
        return worst;
    }

    /// <summary>
    /// A fixed window on any key. Returns how long to wait when the window is already full; otherwise (when <paramref name="consume"/>) counts
    /// one use and returns null. With <paramref name="consume"/> false it only reads, so a refused caller does not spend shared budgets.
    /// </summary>
    public TimeSpan? Window(string key, int max, TimeSpan window, bool consume)
    {
        if (!Enabled) return null;
        if (consume) return store.TryConsume("rl:" + key, max, window);
        return store.Peek("rl:" + key) is { } open && open.Count >= max ? open.Remaining : null;
    }

    private TimeSpan? Count(string key, int max, TimeSpan window)
    {
        var (count, remaining) = store.Increment(key, window);
        return count > max ? remaining : null;
    }

    private static TimeSpan? Max(TimeSpan? a, TimeSpan? b) => a is null ? b : b is null ? a : a > b ? a : b;
}
