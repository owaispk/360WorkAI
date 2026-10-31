using System.Text.Json;
using WorkAI360.Web.Services;

namespace WorkAI360.Web.Components;

public sealed record PersonRef(string Id, string Name, string Email);
public sealed record TeamRef(string Id, string Name);

/// <summary>What the connection pages share: who is signed in, their permissions, the people and teams a connection can be shared with, and how a connection reads.</summary>
public abstract class ConnectionsPageBase : ActionPage
{
    protected bool Loading { get; set; } = true;
    protected string OrgName { get; set; } = "";
    protected HashSet<string> Permissions { get; set; } = [];
    protected List<PersonRef> People { get; set; } = [];
    protected List<TeamRef> Teams { get; set; } = [];

    protected bool Can(string permission) => Permissions.Contains(permission);

    /// <summary>Loads the signed-in person and their workspace. False when there is no session or no workspace (the person was sent elsewhere).</summary>
    protected async Task<bool> LoadOrgAsync()
    {
        var me = await Den.RequestAsync("/api/browser/v1/me");
        if (!me.Ok) { Nav.NavigateTo("/"); return false; }
        MyEmail = me.String("user", "email") ?? "";
        var org = await Den.RequestAsync("/api/browser/v1/org");
        if (org.Status is 404 or 403) { Nav.NavigateTo("/organization"); return false; }
        if (org.Json is not { ValueKind: JsonValueKind.Object } root) return false;
        OrgName = org.String("organization", "name") ?? "";
        Permissions = root.GetProperty("currentMember").GetProperty("permissions").EnumerateArray().Select(p => p.GetString() ?? "").ToHashSet();
        People = root.GetProperty("members").EnumerateArray().Where(m => m.GetProperty("userId").ValueKind != JsonValueKind.Null)
            .Select(m => new PersonRef(m.GetProperty("id").GetString() ?? "", m.GetProperty("user").GetProperty("name").GetString() ?? "", m.GetProperty("user").GetProperty("email").GetString() ?? "")).ToList();
        Teams = root.GetProperty("teams").EnumerateArray().Select(t => new TeamRef(t.GetProperty("id").GetString() ?? "", t.GetProperty("name").GetString() ?? "")).ToList();
        return true;
    }

    protected static string Str(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
    protected static bool Flag(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.True;

    protected static string AuthLabel(string authType, string mode) => (authType, mode) switch
    {
        ("none", _) => "No sign-in",
        ("apikey", "per_member") => "Each person's own key",
        ("apikey", _) => "One shared key",
        ("oauth", "per_member") => "Each person signs in",
        _ => "One shared sign-in",
    };

    /// <summary>The plain-words status of a connection for the person looking: connected for them, or what is missing.</summary>
    protected static (string Label, string Kind) Status(JsonElement c)
    {
        if (Flag(c, "needsReconnect")) return ("Sign in again", "warn");
        if (Flag(c, "connectedForMe")) return c.TryGetProperty("readiness", out var r) && r.ValueKind == JsonValueKind.Object && Str(r, "status") == "could_not_verify" ? ("Could not verify", "warn") : ("Connected", "ok");
        if (Str(c, "credentialMode") == "per_member") return ("Not signed in", "idle");
        return ("Not connected", "idle");
    }

    protected static string Failure(DenResponse r, string fallback) => r.Message(fallback);
}
