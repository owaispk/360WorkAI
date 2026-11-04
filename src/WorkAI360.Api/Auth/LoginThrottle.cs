namespace WorkAI360.Api.Auth;

/// <summary>
/// Locks email/password sign-in for an address after repeated failures: 5 in 15 minutes. Kept in the <see cref="ISharedStore"/> (Redis when configured,
/// so a lockout holds on every instance).
/// </summary>
public sealed class LoginThrottle(ISharedStore store)
{
    private const int MaxFailures = 5;
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(15);

    private static string Key(string email) => "login-failures:" + email;

    public TimeSpan? LockedFor(string email) => store.Peek(Key(email)) is { } open && open.Count >= MaxFailures ? open.Remaining : null;

    public void RecordFailure(string email) => store.Increment(Key(email), Window);

    public void Reset(string email) => store.Delete(Key(email));
}
