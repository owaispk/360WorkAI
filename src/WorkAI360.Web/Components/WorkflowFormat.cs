using System.Text.Json;

namespace WorkAI360.Web.Components;

/// <summary>The wording and small renderers the Workflow pages share.</summary>
public static class WorkflowFormat
{
    /// <summary>A result's Markdown table (the shape the server renders for flat objects and lists of them) as headers and rows; null when the text is not such a table.</summary>
    public static (List<string> Headers, List<List<string>> Rows)? Table(string? markdown)
    {
        if (string.IsNullOrEmpty(markdown) || !markdown.StartsWith('|')) return null;
        var lines = markdown.Split('\n');
        if (lines.Length < 2 || !lines[1].StartsWith("| ---", StringComparison.Ordinal)) return null;
        return (Cells(lines[0]), lines.Skip(2).Select(Cells).ToList());
    }

    private static List<string> Cells(string line)
    {
        var cells = new List<string>();
        var current = new System.Text.StringBuilder();
        var body = line.Trim();
        if (body.StartsWith('|')) body = body[1..];
        if (body.EndsWith('|') && !body.EndsWith("\\|")) body = body[..^1];
        for (var i = 0; i < body.Length; i++)
        {
            var c = body[i];
            if (c == '\\' && i + 1 < body.Length)
            {
                var next = body[++i];
                current.Append(next switch { 'n' => '\n', _ => next });
            }
            else if (c == '|') { cells.Add(Decode(current.ToString().Trim())); current.Clear(); }
            else current.Append(c);
        }
        cells.Add(Decode(current.ToString().Trim()));
        return cells;
    }

    private static string Decode(string s) => s.Replace("&lt;", "<").Replace("&gt;", ">").Replace("&amp;", "&");

    /// <summary>The JSON inside a fenced block, or the text with the server's HTML escaping undone.</summary>
    public static string Plain(string? markdown)
    {
        if (string.IsNullOrEmpty(markdown)) return "";
        if (markdown.StartsWith("```json\n", StringComparison.Ordinal) && markdown.EndsWith("\n```", StringComparison.Ordinal)) return markdown["```json\n".Length..^"\n```".Length];
        return Decode(markdown);
    }

    public static string Pretty(string json)
    {
        try { return JsonSerializer.Serialize(JsonDocument.Parse(json).RootElement, new JsonSerializerOptions { WriteIndented = true }); }
        catch (JsonException) { return json; }
    }

    public static string Fresh(string? state) => state switch
    {
        "fresh" => "Up to date",
        "stale" => "Out of date",
        "needs_attention" => "Needs attention",
        "never_run" => "Never run",
        _ => "Unknown",
    };

    public static string Ready(string? state) => state switch
    {
        "ready" => "Ready to run",
        "needs_signin" => "Needs your sign-in to a connection",
        "needs_admin_setup" => "Needs an administrator to set up a connection",
        _ => state ?? "",
    };

    public static string When(string? iso) => DateTime.TryParse(iso, null, System.Globalization.DateTimeStyles.RoundtripKind, out var d) ? d.ToUniversalTime().ToString("yyyy-MM-dd HH:mm 'UTC'") : "";

    public static string Duration(int ms) => ms < 1000 ? $"{ms} ms" : $"{ms / 1000.0:0.#} s";
}

/// <summary>The Workflow buttons on the dashboard.</summary>
public sealed class WorkspaceDashboardLinks : IDashboardLinkSource
{
    public IEnumerable<DashboardLink> Links => [new("Workflow runs", "/dashboard/workflow-runs", "workflow-runs-link", 44)];
}
