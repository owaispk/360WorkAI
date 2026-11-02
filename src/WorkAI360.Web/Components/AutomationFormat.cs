using System.Text.Json;

namespace WorkAI360.Web.Components;

/// <summary>Plain-words labels for Automations, shared by the pages (the reference's one-line schedule label and a person's run status).</summary>
public static class AutomationFormat
{
    private static readonly string[] Days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

    private static string Clock(int hour, int minute = 0) => $"{hour:00}:{minute:00}";

    /// <summary>For example <c>Daily · 09:00 · Europe/Paris</c> or <c>Every 3 hours · 09:00–18:00 · UTC</c>.</summary>
    public static string Schedule(JsonElement s)
    {
        string Text(string name) => s.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString()! : "";
        int Int(string name) => s.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt32() : 0;
        var zone = Text("timezone");
        string WeekDays() => string.Join(", ", s.GetProperty("daysOfWeek").EnumerateArray().Select(d => Days[d.GetInt32()]));
        switch (Text("kind"))
        {
            case "once":
                return $"Once · {DateTimeOffset.FromUnixTimeMilliseconds(s.GetProperty("at").GetInt64()).UtcDateTime:yyyy-MM-dd HH:mm} UTC · {zone}";
            case "daily": return $"Daily · {Clock(Int("hour"), Int("minute"))} · {zone}";
            case "weekly": return $"Weekly · {WeekDays()} · {Clock(Int("hour"), Int("minute"))} · {zone}";
            case "calendar":
                var minutes = Math.Abs(Int("offsetMinutes"));
                var moment = Text("edge") == "end"
                    ? Int("offsetMinutes") == 0 ? "After each meeting" : Int("offsetMinutes") > 0 ? $"After each meeting (+{minutes} min)" : $"{minutes} min before each meeting ends"
                    : Int("offsetMinutes") == 0 ? "As each meeting starts" : Int("offsetMinutes") < 0 ? $"{minutes} min before each meeting" : $"{minutes} min into each meeting";
                return $"{moment} · {zone}";
            default:
                var every = Int("everyHours");
                var parts = new List<string> { every == 1 ? "Every hour" : $"Every {every} hours" };
                if (Int("startHour") != 0 || Int("endHour") != 24) parts.Add($"{Clock(Int("startHour"))}–{Clock(Int("endHour"))}");
                if (s.GetProperty("daysOfWeek").GetArrayLength() < 7) parts.Add(WeekDays());
                parts.Add(zone);
                return string.Join(" · ", parts);
        }
    }

    public static string When(long? ms) => ms is { } v ? DateTimeOffset.FromUnixTimeMilliseconds(v).UtcDateTime.ToString("yyyy-MM-dd HH:mm") + " UTC" : "—";

    /// <summary>What a person reads for a run's status.</summary>
    public static string Status(string status) => status switch
    {
        "queued" => "Waiting for your desktop", "claimed" => "Starting", "running" => "Running", "succeeded" => "Done", "failed" => "Failed", "cancelled" => "Cancelled",
        "skipped" => "Skipped", _ => status,
    };

    public static string State(string state) => state switch
    {
        "active" => "On", "inactive" => "Paused", "needs_attention" => "Needs attention", "archived" => "Archived", _ => state,
    };
}
