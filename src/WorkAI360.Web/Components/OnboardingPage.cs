using System.Text.Json;
using Microsoft.AspNetCore.Components;
using Microsoft.JSInterop;

namespace WorkAI360.Web.Components;

/// <summary>
/// The shared start of the pages between sign-up and a working workspace: find out who is signed in (sending everyone else to the sign-in form and
/// back to where they were going), and read the workspace they are in.
/// </summary>
public abstract class OnboardingPage : ActionPage
{
    [Inject] protected IJSRuntime Js { get; set; } = null!;

    protected async Task<IJSObjectReference> Module() => await Js.InvokeAsync<IJSObjectReference>("import", "./js/onboarding.js");

    protected string MyName { get; set; } = "";
    protected string MyUserId { get; set; } = "";
    protected string OrgName { get; set; } = "";
    protected HashSet<string> Permissions { get; set; } = [];
    protected bool Ready { get; set; }

    /// <summary>The paths a sign-in may return to: nothing else is ever followed (no open redirect).</summary>
    public static readonly string[] ReturnPaths = ["/install", "/setup", "/claim", "/workspace-claim", "/dashboard/onboarding", "/dashboard/onboarding/tools", "/dashboard/onboarding/people", "/reauth/desktop"];

    /// <summary>The address to go to after signing in, or null when it is not one of <see cref="ReturnPaths"/> (same site, no other host, no tricks).</summary>
    public static string? SafeReturnTo(string? value)
    {
        var candidate = value?.Trim() ?? "";
        if (!candidate.StartsWith('/') || candidate.StartsWith("//") || candidate.Contains('\\') || candidate.Contains('\n') || candidate.Contains('\r')) return null;
        var path = candidate.Split('?', '#')[0];
        return ReturnPaths.Contains(path, StringComparer.Ordinal) ? candidate : null;
    }

    /// <summary>Signs the person in (or sends them to the form and back). Returns false when they were sent away.</summary>
    protected async Task<bool> RequireSignInAsync(string returnTo)
    {
        var me = await Den.RequestAsync("/api/browser/v1/me");
        if (!me.Ok)
        {
            Nav.NavigateTo("/?returnTo=" + Uri.EscapeDataString(returnTo));
            return false;
        }
        MyEmail = me.String("user", "email") ?? "";
        MyName = me.String("user", "name") ?? "";
        MyUserId = me.String("user", "id") ?? "";
        return true;
    }

    /// <summary>Reads the active workspace (name and what this person may do). False when there is none, after sending them to create one.</summary>
    protected async Task<bool> LoadWorkspaceAsync()
    {
        var org = await Den.RequestAsync("/api/browser/v1/org");
        if (!org.Ok) { Nav.NavigateTo("/organization"); return false; }
        OrgName = org.String("organization", "name") ?? "";
        if (org.Json is { ValueKind: JsonValueKind.Object } root && root.TryGetProperty("currentMember", out var member) && member.TryGetProperty("permissions", out var list))
            Permissions = list.EnumerateArray().Select(p => p.GetString() ?? "").ToHashSet();
        return true;
    }

    protected static bool IsEmail(string value)
    {
        var at = value.IndexOf('@');
        return at > 0 && at == value.LastIndexOf('@') && value.IndexOf('.', at) > at + 1 && !value.EndsWith('.') && !value.Contains(' ');
    }
}
