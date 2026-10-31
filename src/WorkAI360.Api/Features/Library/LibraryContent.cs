using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace WorkAI360.Api.Features.Library;

public sealed record ParsedSkill(string Name, string Description, string Body, bool HasFrontmatter);

/// <summary>Reads SKILL.md the way the reference does (YAML-style frontmatter between --- lines, then Markdown).</summary>
public static partial class SkillMarkdown
{
    [GeneratedRegex(@"^---\n([\s\S]*?)\n---\n?")]
    private static partial Regex FrontmatterPattern();

    [GeneratedRegex(@"^([A-Za-z0-9_-]+)\s*:\s*(.*)$")]
    private static partial Regex KeyLine();

    [GeneratedRegex(@"^([>|])[-+0-9]*$")]
    private static partial Regex BlockScalar();

    public static string Normalize(string content) => content.TrimStart('﻿').Replace("\r\n", "\n");

    private static string Value(string? raw)
    {
        var v = (raw ?? "").Trim();
        if (v.Length == 0) return "";
        if (v.Length >= 2 && v.StartsWith('"') && v.EndsWith('"'))
        {
            try { return JsonSerializer.Deserialize<string>(v)?.Trim() ?? v; }
            catch (JsonException) { return v[1..^1].Trim(); }
        }
        if (v.Length >= 2 && v.StartsWith('\'') && v.EndsWith('\'')) return v[1..^1];
        return v;
    }

    private static string Fold(List<string> lines, bool literal)
    {
        var normalized = lines.Select(l => l.TrimEnd(' ', '\t')).ToList();
        if (literal) return string.Join("\n", normalized).Trim();
        var folded = new List<string>();
        var paragraph = new List<string>();
        void Flush() { if (paragraph.Count > 0) { folded.Add(string.Join(" ", paragraph)); paragraph.Clear(); } }
        foreach (var line in normalized)
        {
            if (line.Trim().Length == 0)
            {
                Flush();
                if (folded.Count == 0 || folded[^1] != "") folded.Add("");
                continue;
            }
            paragraph.Add(line.Trim());
        }
        Flush();
        return string.Join("\n", folded).Trim();
    }

    private static Dictionary<string, string> Header(string header)
    {
        var data = new Dictionary<string, string>();
        var lines = header.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            var line = lines[i];
            if (line.Trim().Length == 0) continue;
            var m = KeyLine().Match(line);
            if (!m.Success) continue;
            var key = m.Groups[1].Value.Trim().ToLowerInvariant();
            var raw = m.Groups[2].Value.TrimEnd();
            var block = BlockScalar().Match(raw);
            if (block.Success)
            {
                var blockLines = new List<string>();
                int? indent = null;
                var next = i + 1;
                for (; next < lines.Length; next++)
                {
                    var l = lines[next];
                    if (l.Trim().Length == 0) { blockLines.Add(""); continue; }
                    var ind = l.Length - l.TrimStart().Length;
                    if (indent is null) { if (ind == 0) break; indent = ind; }
                    if (ind < indent) break;
                    blockLines.Add(l[indent.Value..]);
                }
                data[key] = Fold(blockLines, block.Groups[1].Value == "|");
                i = next - 1;
                continue;
            }
            data[key] = Value(raw);
        }
        return data;
    }

    public static ParsedSkill Parse(string content)
    {
        var text = Normalize(content);
        var m = FrontmatterPattern().Match(text);
        if (!m.Success) return new ParsedSkill("", "", text, false);
        var data = Header(m.Groups[1].Value);
        return new ParsedSkill(Value(data.GetValueOrDefault("name")), Value(data.GetValueOrDefault("description")), text[m.Length..], true);
    }

    /// <summary>The standard SKILL.md an agent reads: normalized name and description, then the source body.</summary>
    public static string Standard(string name, string description, string source)
    {
        var body = Regex.Replace(source, @"^---\r?\n[\s\S]*?\r?\n---\r?\n?", "").TrimStart();
        return $"---\nname: {name}\ndescription: {JsonSerializer.Serialize(description)}\n---\n\n{body}";
    }
}

/// <summary>What listings and search show for a config object, worked out from its text.</summary>
public sealed record Projection(string Title, string? Description, string? SearchText);

public static partial class Projections
{
    public const int TitleMaxChars = 255;
    public const int TextMaxBytes = 60_000;
    public const int InputMaxBytes = 1_048_576;

    [GeneratedRegex("^[a-z0-9]+(?:-[a-z0-9]+)*$")]
    private static partial Regex SkillName();

    public static string ClampBytes(string value, int max)
    {
        if (Encoding.UTF8.GetByteCount(value) <= max) return value;
        var bytes = 0;
        var sb = new StringBuilder();
        foreach (var rune in value.EnumerateRunes())
        {
            var n = rune.Utf8SequenceLength;
            if (bytes + n > max) break;
            bytes += n;
            sb.Append(rune.ToString());
        }
        return sb.ToString();
    }

    public static string ClampChars(string value, int max)
    {
        if (value.Length <= max) return value;
        var sb = new StringBuilder();
        var count = 0;
        foreach (var rune in value.EnumerateRunes())
        {
            if (count == max) break;
            count++;
            sb.Append(rune.ToString());
        }
        return sb.ToString();
    }

    public static string? Trimmed(string? v) { var t = v?.Trim(); return string.IsNullOrEmpty(t) ? null : t; }

    private static string FirstLine(string v) => v.Split('\n').Select(l => l.Trim()).FirstOrDefault(l => l.Length > 0) ?? "";

    private static string Strip(string v) =>
        Regex.Replace(Regex.Replace(Regex.Replace(Regex.Replace(v, @"^#{1,6}\s+", ""), @"^[-*+]\s+", ""), @"^title\s*:\s*", "", RegexOptions.IgnoreCase), @"^description\s*:\s*", "", RegexOptions.IgnoreCase).Trim();

    /// <summary>Skills must be a complete SKILL.md; everything else takes its title and description from metadata, payload or first lines.</summary>
    public static Projection Derive(string objectType, string? rawSourceText, JsonElement payload, JsonElement metadata)
    {
        var raw = Trimmed(rawSourceText);
        if (objectType == "skill") return Skill(raw);

        string? Prop(JsonElement obj, string key) => obj.ValueKind == JsonValueKind.Object && obj.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String && Trimmed(v.GetString()) is not null ? v.GetString() : null;
        var titleCandidate = Prop(metadata, "title") ?? Prop(metadata, "name") ?? Prop(payload, "title") ?? Prop(payload, "name") ?? (raw is null ? null : Trimmed(Strip(FirstLine(raw))));
        var description = Trimmed(Prop(metadata, "description") ?? Prop(payload, "description")
            ?? (raw is null ? null : raw.Split('\n').Select(l => Strip(l.Trim())).Where(l => l.Length > 0).Skip(1).FirstOrDefault()));
        var title = ClampChars(Trimmed(titleCandidate) ?? $"{char.ToUpperInvariant(objectType[0])}{objectType[1..]} {DateTime.UtcNow:yyyy-MM-ddTHH:mm:ss.fffZ}", TitleMaxChars);
        var search = string.Join("\n", new[] { title, description, raw }.Where(s => !string.IsNullOrEmpty(s)));
        return new Projection(title, description is null ? null : ClampBytes(description, TextMaxBytes), search.Length == 0 ? null : ClampBytes(search, TextMaxBytes));
    }

    private static Projection Skill(string? raw)
    {
        if (raw is null) throw new LibraryFailure(400, "invalid_skill_source", "Skill components require rawSourceText containing the complete SKILL.md.");
        var parsed = SkillMarkdown.Parse(raw);
        if (!parsed.HasFrontmatter) throw new LibraryFailure(400, "invalid_skill_frontmatter", "SKILL.md must start with YAML frontmatter delimited by --- lines.");
        var name = parsed.Name.Trim();
        if (name.Length == 0) throw new LibraryFailure(400, "invalid_skill_name", "SKILL.md frontmatter requires a non-empty name.");
        if (name.Length > 64 || !SkillName().IsMatch(name))
            throw new LibraryFailure(400, "invalid_skill_name", "SKILL.md frontmatter name must be 1-64 characters, contain only lowercase letters, numbers, and hyphens, and cannot start, end, or use consecutive hyphens.");
        var description = parsed.Description.Trim();
        if (description.Length == 0) throw new LibraryFailure(400, "invalid_skill_description", "SKILL.md frontmatter requires a non-empty description.");
        if (description.Length > 1024) throw new LibraryFailure(400, "invalid_skill_description", "SKILL.md frontmatter description must be 1024 characters or fewer.");
        var body = parsed.Body.Trim();
        if (body.Length == 0) throw new LibraryFailure(400, "invalid_skill_body", "SKILL.md requires a non-empty Markdown instruction body after the frontmatter.");
        return new Projection(name, description, ClampBytes(string.Join("\n", name, description, body), TextMaxBytes));
    }
}
