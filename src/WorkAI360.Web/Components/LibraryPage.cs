using System.Text.Json;
using WorkAI360.Web.Services;

namespace WorkAI360.Web.Components;

public sealed record LibraryPerson(string Id, string Name, string Email);

public sealed record LibraryTeam(string Id, string Name);

/// <summary>What the library pages share: who I am, what I may do, the workspace's people and teams, and a short way to call the API.</summary>
public abstract class LibraryPage : ActionPage
{
    protected bool Loading { get; set; } = true;
    protected string OrgName { get; set; } = "";
    protected string MyMemberId { get; set; } = "";
    protected HashSet<string> Permissions { get; set; } = [];
    protected List<LibraryPerson> People { get; set; } = [];
    protected List<LibraryTeam> Teams { get; set; } = [];

    protected bool Can(string permission) => Permissions.Contains(permission);

    protected Task<DenResponse> Api(string path, string method = "GET", object? body = null) => Den.RequestAsync("/api/browser/v1" + path, method, body);

    protected string PersonName(string? memberId) => People.FirstOrDefault(p => p.Id == memberId)?.Name ?? "Someone";

    /// <summary>Signs the page in (or sends the person to sign in) and reads the workspace. False means the person was sent elsewhere.</summary>
    protected async Task<bool> LoadOrgAsync()
    {
        var me = await Den.RequestAsync("/api/browser/v1/me");
        if (!me.Ok) { Nav.NavigateTo("/"); return false; }
        MyEmail = me.String("user", "email") ?? "";
        var org = await Api("/org");
        if (org.Status is 404 or 403) { Nav.NavigateTo("/organization"); return false; }
        if (org.Json is not { ValueKind: JsonValueKind.Object } root) return false;
        OrgName = org.String("organization", "name") ?? "";
        MyMemberId = org.String("currentMember", "id") ?? "";
        Permissions = root.GetProperty("currentMember").GetProperty("permissions").EnumerateArray().Select(p => p.GetString() ?? "").ToHashSet();
        People = root.GetProperty("members").EnumerateArray().Where(m => m.GetProperty("userId").ValueKind != JsonValueKind.Null)
            .Select(m => new LibraryPerson(m.GetProperty("id").GetString() ?? "", m.GetProperty("user").GetProperty("name").GetString() ?? "", m.GetProperty("user").GetProperty("email").GetString() ?? "")).ToList();
        Teams = root.GetProperty("teams").EnumerateArray().Select(t => new LibraryTeam(t.GetProperty("id").GetString() ?? "", t.GetProperty("name").GetString() ?? "")).ToList();
        return true;
    }

    protected static string? Str(JsonElement e, string name) => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    protected static int Int(JsonElement e, string name) => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt32() : 0;

    /// <summary>The wording for how a plugin reached someone: "made by you", "shared with you by Ann", and so on.</summary>
    protected string EdgeLabel(JsonElement edge) => Str(edge, "kind") switch
    {
        "mine" => "You made it",
        "person" => edge.TryGetProperty("sharedBy", out var by) && by.ValueKind == JsonValueKind.Object ? $"Shared with you by {Str(by, "name")}" : "Shared with you",
        "team" => $"Through the {Str(edge.GetProperty("team"), "name")} team",
        "org_wide" => "Shared with everyone",
        "catalog" => $"In the {Str(edge.GetProperty("marketplace"), "name")} marketplace",
        _ => "Shared",
    };
}
