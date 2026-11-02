using System.Collections.Concurrent;

namespace WorkAI360.Api.Auth;

/// <summary>
/// Locks email/password sign-in after repeated failures (in memory; per instance).
/// <list type="bullet">
/// <item>Five failures from one address for one account lock that address out of that account for 15 minutes. Someone who only knows a victim's email
/// therefore cannot lock the victim out: the victim signs in from another address.</item>
/// <item>A higher ceiling per account (fifty failures in 15 minutes, from any addresses) stops a guessing attack spread over many addresses. Past it the
/// account is locked for everyone until the window ends or the password is reset, so it is a backstop, not the usual limit.</item>
/// </list>
/// Entries expire with their window and are swept as new failures arrive, so unknown addresses cannot grow the table without end.
/// </summary>
public sealed class LoginThrottle
{
    public const int MaxFailuresPerAddress = 5;
    public const int MaxFailuresPerAccount = 50;
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(15);
    private const char Separator = '\0';

    private readonly ConcurrentDictionary<string, (int Failures, DateTime FirstAt)> _state = new();
    private int _sweep;

    private static string AddressKey(string email, string? ip) => $"{email}{Separator}{ip ?? "unknown"}";
    private static string AccountKey(string email) => email;

    public TimeSpan? LockedFor(string email, string? ip)
    {
        var address = Remaining(AddressKey(email, ip), MaxFailuresPerAddress);
        var account = Remaining(AccountKey(email), MaxFailuresPerAccount);
        return address is null ? account : account is null ? address : address > account ? address : account;
    }

    private TimeSpan? Remaining(string key, int max)
    {
        if (!_state.TryGetValue(key, out var s)) return null;
        var remaining = s.FirstAt + Window - DateTime.UtcNow;
        if (remaining <= TimeSpan.Zero) { _state.TryRemove(key, out _); return null; }
        return s.Failures >= max ? remaining : null;
    }

    public void RecordFailure(string email, string? ip)
    {
        if (Interlocked.Increment(ref _sweep) % 200 == 0) Sweep();
        Count(AddressKey(email, ip));
        Count(AccountKey(email));
    }

    private void Count(string key) =>
        _state.AddOrUpdate(key, _ => (1, DateTime.UtcNow), (_, s) => s.FirstAt + Window < DateTime.UtcNow ? (1, DateTime.UtcNow) : (s.Failures + 1, s.FirstAt));

    /// <summary>A successful sign-in clears that address's count for the account (the account-wide count keeps running).</summary>
    public void Succeeded(string email, string? ip) => _state.TryRemove(AddressKey(email, ip), out _);

    /// <summary>Lifts every lock on the account, whichever address earned it (a password reset).</summary>
    public void Reset(string email)
    {
        _state.TryRemove(AccountKey(email), out _);
        var prefix = email + Separator;
        foreach (var key in _state.Keys)
            if (key.StartsWith(prefix, StringComparison.Ordinal)) _state.TryRemove(key, out _);
    }

    public int Tracked => _state.Count;

    private void Sweep()
    {
        var now = DateTime.UtcNow;
        foreach (var (key, s) in _state)
            if (s.FirstAt + Window <= now) _state.TryRemove(key, out _);
    }
}
