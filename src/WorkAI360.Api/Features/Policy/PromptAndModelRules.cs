namespace WorkAI360.Api.Features.Policy;

public sealed record PromptAssignment(bool Everyone, IReadOnlyList<string> TeamIds, IReadOnlyList<string> MemberIds);

/// <summary>A prompt as the resolver sees it.</summary>
public sealed record ResolvablePrompt(string Id, string Content, DateTime CreatedAt, PromptAssignment Assignment);

/// <summary>One prompt a person's desktop appends: where it came from ("organization", "team" or "member") and, for a team's, the team's name.</summary>
public sealed record MemberPrompt(string Id, string Source, string? TeamName, string Content);

/// <summary>System prompts: which apply to a person and in what order. Pure, ported from <c>packages/types/src/den/prompts.ts</c>.</summary>
public static class PromptRules
{
    public const int MaxLength = 20_000;

    /// <summary>
    /// Everyone's prompts first, then each of the person's teams' by team name, then prompts assigned to the person. A prompt that applies more
    /// than once is added once, at its first place; an empty one is never added.
    /// </summary>
    public static List<MemberPrompt> ResolveForMember(IEnumerable<ResolvablePrompt> prompts, string memberId, IEnumerable<(string Id, string Name)> teams)
    {
        var byAge = prompts.OrderBy(p => p.CreatedAt).ThenBy(p => p.Id, StringComparer.Ordinal).ToList();
        var orderedTeams = teams.OrderBy(t => t.Name, StringComparer.OrdinalIgnoreCase).ThenBy(t => t.Name, StringComparer.Ordinal).ThenBy(t => t.Id, StringComparer.Ordinal).ToList();
        var seen = new HashSet<string>();
        var resolved = new List<MemberPrompt>();
        void Add(ResolvablePrompt p, string source, string? teamName)
        {
            if (p.Content.Trim().Length == 0 || !seen.Add(p.Id)) return;
            resolved.Add(new MemberPrompt(p.Id, source, teamName, p.Content));
        }
        foreach (var p in byAge) if (p.Assignment.Everyone) Add(p, "organization", null);
        foreach (var team in orderedTeams)
            foreach (var p in byAge) if (p.Assignment.TeamIds.Contains(team.Id)) Add(p, "team", team.Name);
        foreach (var p in byAge) if (p.Assignment.MemberIds.Contains(memberId)) Add(p, "member", null);
        return resolved;
    }

    /// <summary>The text desktops append to OpenWork's instructions, or "" when no prompt applies.</summary>
    public static string Compose(IEnumerable<MemberPrompt> prompts) =>
        string.Join("\n\n", prompts.Select(p => p.Content.Trim()).Where(c => c.Length > 0));
}

public sealed record ModelChoice(string ProviderId, string ModelId);

public sealed record ResolvedDefaultModel(ModelChoice Model, string FromKind, string? TeamName, bool TeamConflict);

/// <summary>
/// The model new desktop chats start with. Pure, ported from <c>packages/types/src/den/default-model.ts</c>. For one person: the teams that
/// override the model, by team name; when they all choose the same model it applies; when two choose differently the organization default
/// applies instead (a conflict never picks one team over another); with no override the organization default; with none the desktop decides.
/// </summary>
public static class DefaultModelRules
{
    public const string EveryoneScope = "everyone";

    public static bool Same(ModelChoice? left, ModelChoice? right) =>
        left is null || right is null ? left is null && right is null : left.ProviderId == right.ProviderId && left.ModelId == right.ModelId;

    public static ResolvedDefaultModel? Resolve(ModelChoice? everyone, IEnumerable<(string Name, ModelChoice? Model)> teams)
    {
        var overriding = teams.Where(t => t.Model is not null).OrderBy(t => t.Name, StringComparer.OrdinalIgnoreCase).ThenBy(t => t.Name, StringComparer.Ordinal).ToList();
        var first = overriding.FirstOrDefault();
        var conflict = overriding.Any(t => !Same(t.Model, first.Model));
        if (first.Model is not null && !conflict) return new ResolvedDefaultModel(first.Model, "team", first.Name, false);
        return everyone is not null ? new ResolvedDefaultModel(everyone, "organization", null, conflict) : null;
    }

    /// <summary>For each team, how many of its members are also on a team that overrides the model differently (they start on the organization default).</summary>
    public static Dictionary<string, int> CountConflicts(IReadOnlyList<(string TeamId, ModelChoice? Model)> teams, IReadOnlyList<(string TeamId, string MemberId)> memberships)
    {
        var modelByTeam = teams.ToDictionary(t => t.TeamId, t => t.Model);
        var overrides = new Dictionary<string, List<ModelChoice>>();
        foreach (var m in memberships)
        {
            if (!modelByTeam.TryGetValue(m.TeamId, out var model) || model is null) continue;
            if (!overrides.TryGetValue(m.MemberId, out var list)) overrides[m.MemberId] = list = [];
            list.Add(model);
        }
        var conflicted = overrides.Where(o => o.Value.Any(x => !Same(x, o.Value[0]))).Select(o => o.Key).ToHashSet();
        var counts = teams.ToDictionary(t => t.TeamId, _ => 0);
        foreach (var m in memberships)
            if (conflicted.Contains(m.MemberId) && counts.ContainsKey(m.TeamId)) counts[m.TeamId]++;
        return counts;
    }
}
