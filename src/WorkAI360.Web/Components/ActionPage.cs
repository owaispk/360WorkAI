using Microsoft.AspNetCore.Components;
using WorkAI360.Web.Services;

namespace WorkAI360.Web.Components;

/// <summary>
/// The shared behavior of pages that change workspace settings: one place for running a change, showing its outcome, and asking for the
/// password again when the server says the sign-in is too old (then trying the change once more).
/// </summary>
public abstract class ActionPage : ComponentBase
{
    [Inject] protected DenClient Den { get; set; } = null!;
    [Inject] protected NavigationManager Nav { get; set; } = null!;

    protected bool Busy { get; set; }
    protected string? Error { get; set; }
    protected string? Notice { get; set; }
    protected bool NeedsReauth { get; set; }
    protected string ReauthPassword { get; set; } = "";
    protected string MyEmail { get; set; } = "";

    private Func<Task>? _retry;

    /// <summary>Called after a change succeeded, to show the new state.</summary>
    protected virtual Task ReloadAsync() => Task.CompletedTask;

    /// <summary>Runs a change. On success shows <paramref name="success"/> and reloads; on a stale sign-in asks for the password and retries.</summary>
    protected async Task RunAsync(Func<Task<DenResponse>> action, string success, Func<DenResponse, string?>? explain = null)
    {
        Error = Notice = null;
        Busy = true;
        var result = await action();
        Busy = false;
        if (result.String("error") == "reauth")
        {
            NeedsReauth = true;
            _retry = () => RunAsync(action, success, explain);
            return;
        }
        if (result.Ok)
        {
            Notice = success;
            await ReloadAsync();
        }
        else Error = explain?.Invoke(result) ?? result.Message("That did not work. Try again.");
    }

    /// <summary>Asks for the password again for a change that needs a recent sign-in, then runs <paramref name="again"/>.</summary>
    protected void AskToConfirm(Func<Task> again)
    {
        NeedsReauth = true;
        _retry = again;
    }

    protected async Task ConfirmItsYouAsync()
    {
        Busy = true;
        Error = null;
        var signIn = await Den.RequestAsync("/api/auth/sign-in/email", "POST", new { email = MyEmail, password = ReauthPassword });
        Busy = false;
        ReauthPassword = "";
        if (!signIn.Ok) { Error = "That password is not right."; return; }
        NeedsReauth = false;
        var retry = _retry;
        _retry = null;
        if (retry is not null) await retry();
    }

    protected void CancelReauth()
    {
        NeedsReauth = false;
        _retry = null;
        ReauthPassword = "";
    }
}
