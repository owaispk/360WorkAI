using System.Collections.Concurrent;

namespace WorkAI360.Api.Auth;

/// <summary>Locks email/password sign-in for an address after repeated failures (in memory; per instance).</summary>
public sealed class LoginThrottle
{
    private const int MaxFailures = 5;
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(15);
    private readonly ConcurrentDictionary<string, (int Failures, DateTime FirstAt)> _state = new();

    public TimeSpan? LockedFor(string email)
    {
        if (!_state.TryGetValue(email, out var s)) return null;
        var remaining = s.FirstAt + Window - DateTime.UtcNow;
        if (remaining <= TimeSpan.Zero) { _state.TryRemove(email, out _); return null; }
        return s.Failures >= MaxFailures ? remaining : null;
    }

    public void RecordFailure(string email) =>
        _state.AddOrUpdate(email, _ => (1, DateTime.UtcNow), (_, s) => s.FirstAt + Window < DateTime.UtcNow ? (1, DateTime.UtcNow) : (s.Failures + 1, s.FirstAt));

    public void Reset(string email) => _state.TryRemove(email, out _);
}
