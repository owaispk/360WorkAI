using System.Text.Json;

namespace WorkAI360.Web.Components;

/// <summary>
/// The shared start of the platform admin pages (/admin): ask the API whether the signed-in person is a platform admin. Not signed in goes to the
/// sign-in page; anyone else gets a plain "no access" message and the page never asks for admin data.
/// </summary>
public abstract class AdminPage : ActionPage
{
    protected bool Loading { get; set; } = true;
    protected bool Denied { get; set; }

    /// <summary>True when the person may use the admin pages; otherwise the page state is already set (denied, or redirected).</summary>
    protected async Task<bool> EnterAsync()
    {
        var probe = await Den.RequestAsync("/api/browser/v1/admin/overview?limit=1");
        if (probe.Status == 401) { Nav.NavigateTo("/"); return false; }
        if (probe.Status == 403) { Denied = true; Loading = false; StateHasChanged(); return false; }
        return true;
    }

    protected static string Short(string? iso) =>
        DateTime.TryParse(iso, null, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out var at) ? at.ToString("d MMM yyyy") : "";

    protected static string Text(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
    protected static int Number(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt32() : 0;
    protected static bool Flag(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.True;
}
