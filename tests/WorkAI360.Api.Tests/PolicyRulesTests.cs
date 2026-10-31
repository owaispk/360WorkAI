using System.Text.Json;
using WorkAI360.Api.Features.Policy;

namespace WorkAI360.Api.Tests;

/// <summary>The resolution rules as pure functions: who gets which policy, prompt, model and agent permission when several apply.</summary>
public sealed class PolicyRulesTests
{
    // ---------------------------------------------------------------- agent permissions

    private static AgentSetting Set(string? decision = null, string[]? allow = null, string[]? block = null) => new(decision, allow ?? [], block ?? []);

    private static AgentPolicySettings Policy(string source, params (string Key, AgentSetting Setting)[] settings) =>
        new(source, settings.ToDictionary(s => s.Key, s => s.Setting));

    private static string Show(IEnumerable<AgentRule> rules) => string.Join(" | ", rules.Select(r => $"{r.Action} {r.Resource} {r.Effect} {r.Source}"));

    [Fact]
    public void With_no_policies_nothing_is_restricted()
    {
        Assert.Empty(AgentPermissionRules.ResolveRules(null, []));
        Assert.Empty(AgentPermissionRules.ResolveRules(Policy("Everyone"), [Policy("A")]));
    }

    [Fact]
    public void A_person_in_no_team_gets_everyones_settings()
    {
        var everyone = Policy("Everyone", ("commands", Set("ask", ["git *"], ["rm *"])));
        Assert.Equal("shell * ask Everyone | shell git * allow Everyone | shell rm * deny Everyone", Show(AgentPermissionRules.ResolveRules(everyone, [])));
    }

    [Fact]
    public void A_teams_decision_replaces_everyones_for_its_members_and_its_patterns_add_to_everyones()
    {
        var everyone = Policy("Everyone", ("commands", Set("deny", ["ls"])));
        var team = Policy("Ops", ("commands", Set("allow", ["make"])));
        // Ops allows commands, so nothing restricts them: the allowed patterns are not needed.
        Assert.Equal("", Show(AgentPermissionRules.ResolveRules(everyone, [team])));
        var strict = Policy("Ops", ("commands", Set("ask", ["make"])));
        Assert.Equal("shell * ask Ops | shell ls allow Everyone | shell make allow Ops", Show(AgentPermissionRules.ResolveRules(everyone, [strict])));
    }

    [Fact]
    public void The_strictest_decision_of_several_teams_wins_and_a_team_without_settings_keeps_everyones()
    {
        var everyone = Policy("Everyone", ("commands", Set("ask")));
        var deny = Policy("Audit", ("commands", Set("deny")));
        var silent = Policy("Zeta");
        Assert.Equal("shell * deny Audit", Show(AgentPermissionRules.ResolveRules(everyone, [deny, silent])));
        // The team that says nothing inherits "ask", so the result is not softened by a team that allows (Beta allows, but is not alone).
        var allows = Policy("Beta", ("commands", Set("allow")));
        Assert.Equal("shell * deny Audit", Show(AgentPermissionRules.ResolveRules(everyone, [allows, deny])));
        Assert.Equal("shell * ask Everyone", Show(AgentPermissionRules.ResolveRules(everyone, [silent])));
    }

    [Fact]
    public void An_allowed_pattern_survives_only_when_every_restricting_team_allows_it()
    {
        var a = Policy("A", ("commands", Set("deny", ["git *", "ls"])));
        var b = Policy("B", ("commands", Set("ask", ["git *"])));
        Assert.Equal("shell * deny A | shell git * allow A", Show(AgentPermissionRules.ResolveRules(null, [a, b])));
        // A team that does not restrict the permission does not need to allow anything.
        var c = Policy("C", ("commands", Set("allow")));
        Assert.Equal("shell * deny A | shell git * allow A | shell ls allow A", Show(AgentPermissionRules.ResolveRules(null, [a, c])));
    }

    [Fact]
    public void Blocked_patterns_add_up_everyones_first_without_repeats_and_always_come_last_for_their_permission()
    {
        var everyone = Policy("Everyone", ("commands", Set("ask", ["git *"], ["rm *"])));
        var team = Policy("Ops", ("commands", Set(null, null, ["rm *", "sudo *"])));
        Assert.Equal("shell * ask Everyone | shell git * allow Everyone | shell rm * deny Everyone | shell sudo * deny Ops", Show(AgentPermissionRules.ResolveRules(everyone, [team])));
    }

    [Fact]
    public void Blocking_file_edits_adds_a_final_rule_blocking_every_command_even_when_commands_allow_patterns()
    {
        var everyone = Policy("Everyone", ("fileEdits", Set("deny")), ("commands", Set("ask", ["ls"])));
        var rules = AgentPermissionRules.ResolveRules(everyone, []);
        Assert.Equal(new AgentRule("shell", "*", "deny", "Everyone"), rules[^1]);
        Assert.Equal("deny", AgentPermissionRules.Decide(rules, "shell", ["ls"]).Effect);
        // Asking about edits does not.
        Assert.DoesNotContain(AgentPermissionRules.ResolveRules(Policy("Everyone", ("fileEdits", Set("ask"))), []), r => r.Action == "shell");
    }

    [Fact]
    public void A_switch_never_reads_looser_than_it_was_saved()
    {
        var toggle = AgentPermissionRules.Definition("webSearch")!;
        Assert.Equal("deny", AgentPermissionRules.NormalizeSetting(toggle, "ask", null, null)!.Decision);
        Assert.Equal("deny", AgentPermissionRules.NormalizeSetting(toggle, null, null, ["example.com"])!.Decision);   // a block list on a switch can only mean block everything
        Assert.Null(AgentPermissionRules.NormalizeSetting(toggle, null, ["x"], null));
        var commands = AgentPermissionRules.Definition("commands")!;
        Assert.Null(AgentPermissionRules.NormalizeSetting(commands, "bogus", [" "], null));
    }

    [Theory]
    [InlineData("website", " Docs.Example.COM ", "docs.example.com")]
    [InlineData("website", "*.example.com", "*.example.com")]
    [InlineData("website", "https://example.com/docs/*", "https://example.com/docs")]
    [InlineData("website", "example.com.", "example.com")]
    [InlineData("website", "example.com:08080", "example.com:8080")]
    [InlineData("website", "*", "*")]
    [InlineData("website", "ftp://example.com", null)]
    [InlineData("website", "exa mple.com", null)]
    [InlineData("website", "example.com/a*b", null)]
    [InlineData("website", "user@example.com", null)]
    [InlineData("website", "example.com:99999", null)]
    [InlineData("website", "ex*ample.com", null)]
    [InlineData("command", " npm test * ", "npm test *")]
    [InlineData("command", "a\nb", null)]
    [InlineData("command", "", null)]
    public void Patterns_are_checked_and_stored_in_one_form(string kind, string input, string? expected) => Assert.Equal(expected, AgentPermissionRules.NormalizePattern(kind, input));

    [Theory]
    [InlineData("git status", "git *", true)]
    [InlineData("git", "git *", true)]          // "git *" also matches the bare command
    [InlineData("gitx", "git *", false)]
    [InlineData("rm -rf /", "rm *", true)]
    [InlineData("Git status", "git *", false)]   // case-sensitive
    [InlineData("ab", "a?", true)]
    [InlineData("abc", "a?", false)]
    [InlineData("a\\b", "a/b", true)]
    public void Wildcards_match_as_OpenCode_does(string value, string pattern, bool expected) => Assert.Equal(expected, AgentPermissionRules.WildcardMatch(value, pattern));

    [Theory]
    [InlineData("https://docs.example.com/a", "docs.example.com", true)]
    [InlineData("https://docs.example.com/a", "example.com", false)]
    [InlineData("https://docs.example.com/a", "*.example.com", true)]
    [InlineData("https://example.com/a", "*.example.com", false)]
    [InlineData("http://example.com/", "https://example.com", false)]
    [InlineData("https://example.com:8443/", "example.com", true)]
    [InlineData("https://example.com:8443/", "example.com:443", false)]
    [InlineData("https://example.com/", "example.com:443", true)]
    [InlineData("https://example.com/private/x", "example.com/private", true)]
    [InlineData("https://example.com/privatex", "example.com/private", false)]
    [InlineData("https://example.com/priv%61te/x", "example.com/private", true)]       // encoded letters
    [InlineData("https://example.com/private%2Fsecret", "example.com/private", true)]  // encoded separator
    [InlineData("https://example.com/a/%2E%2E/private", "example.com/private", true)]  // dot segments
    [InlineData("https://example.com//private", "example.com/private", true)]          // repeated slashes
    [InlineData("ftp://example.com/", "example.com", false)]
    [InlineData("https://anything.test/", "*", true)]
    public void Websites_match_by_host_port_scheme_and_canonical_path(string url, string pattern, bool expected) => Assert.Equal(expected, AgentPermissionRules.WebsitePatternMatches(url, pattern));

    [Fact]
    public void The_last_matching_rule_decides_and_several_resources_take_the_strictest()
    {
        var rules = new[]
        {
            new AgentRule("shell", "*", "deny", "Everyone"), new AgentRule("shell", "git *", "allow", "Everyone"), new AgentRule("shell", "git push *", "deny", "Everyone"),
        };
        Assert.Equal("allow", AgentPermissionRules.Decide(rules, "shell", ["git status"]).Effect);
        Assert.Equal("deny", AgentPermissionRules.Decide(rules, "shell", ["git push origin"]).Effect);
        Assert.Equal("deny", AgentPermissionRules.Decide(rules, "shell", ["git status", "git push origin"]).Effect);
        Assert.Equal("allow", AgentPermissionRules.Decide(rules, "websearch", ["x"]).Effect);   // no rule: allowed
        Assert.Equal("allow", AgentPermissionRules.Decide(null, "shell", []).Effect);
    }

    // ---------------------------------------------------------------- desktop policies

    private static DesktopPolicyDocument Doc(string json) => DesktopPolicyRules.Read(json);

    private static Dictionary<string, bool> Effective(string? defaultJson, params string[] assigned) =>
        DesktopPolicyRules.CalculateEffective(1 + assigned.Length, defaultJson is null ? null : Doc(defaultJson), assigned.Select(Doc).ToList());

    [Fact]
    public void With_no_policies_at_all_everything_is_on()
    {
        Assert.All(DesktopPolicyRules.CalculateEffective(0, null, []).Values, v => Assert.True(v));
    }

    [Fact]
    public void Grants_add_up_across_the_default_and_the_assigned_policies()
    {
        var offKeys = """{"allowZenModel":false,"allowAlphaUpdates":false}""";
        var e = Effective(offKeys, """{"allowZenModel":true}""", """{"allowControlSettings":false}""");
        Assert.True(e["allowZenModel"]);          // an assigned policy turns it on
        Assert.False(e["allowAlphaUpdates"]);     // nobody turns it on
        Assert.True(e["allowControlSettings"]);   // false in an assigned policy grants nothing, and the default fills it with the catalog's true
        // Without an enabled default the catalog defaults apply: every setting is on.
        Assert.All(Effective(null).Values, v => Assert.True(v));
    }

    [Fact]
    public void An_access_limit_switches_a_setting_off_whatever_the_grants_say()
    {
        var e = Effective("""{}""", """{"allowZenModel":true}""", """{"access":{"mode":"custom","capabilities":{"allowZenModel":false}}}""");
        Assert.False(e["allowZenModel"]);
        Assert.True(e["allowCustomProviders"]);   // capabilities it does not name default to on, so it limits nothing else
    }

    [Fact]
    public void The_locked_mode_switches_off_every_restrictable_setting_but_not_display_preferences()
    {
        var e = Effective("""{}""", """{"access":{"mode":"locked","capabilities":{}}}""");
        Assert.All(DesktopPolicyRules.Definitions, d => Assert.Equal(d.RestrictedValue is null, e[d.Id]));
        // A locked default policy limits everyone, even people with other policies.
        var all = Effective("""{"access":{"mode":"locked","capabilities":{}}}""", """{"allowZenModel":true}""");
        Assert.False(all["allowZenModel"]);
        Assert.True(all["showWelcomePage"]);
    }

    [Fact]
    public void A_malformed_access_is_ignored()
    {
        Assert.Null(Doc("""{"access":{"mode":"weird","capabilities":{}}}""").Access);
        Assert.Null(Doc("""{"access":{"mode":"custom"}}""").Access);
        Assert.Null(Doc("""{"access":{"mode":"custom","capabilities":{"allowZenModel":"no"}}}""").Access);
        Assert.Null(Doc("not json").Access);
    }

    [Fact]
    public void Execution_limits_intersect_across_policies()
    {
        var one = Doc("""{"execution":{"commands":"allow","blockedCommands":["a","b"],"browserOrigins":["https://a.com","https://b.com"]}}""");
        var two = Doc("""{"execution":{"commands":"deny","blockedCommands":["b","c"],"browserOrigins":["https://b.com","https://c.com"],"blockBrowserUploads":true}}""");
        var none = Doc("""{}""");
        var r = DesktopPolicyRules.ResolveExecution([none, one, two]);
        Assert.Equal("deny", r.Commands);
        Assert.Equal(["a", "b", "c"], r.BlockedCommands);
        Assert.True(r.BlockBrowserUploads);
        Assert.Equal(["https://b.com"], r.BrowserOrigins);
        var alone = DesktopPolicyRules.ResolveExecution([none, one]);
        Assert.Equal("allow", alone.Commands);
        Assert.Equal(["https://a.com", "https://b.com"], alone.BrowserOrigins);
        // No policy lists origins: no limit at all (not "no sites").
        Assert.Null(DesktopPolicyRules.ResolveExecution([none]).BrowserOrigins);
        // An empty list is a limit: nothing is allowed, and it empties any other list.
        var empty = Doc("""{"execution":{"browserOrigins":[]}}""");
        Assert.Empty(DesktopPolicyRules.ResolveExecution([one, empty]).BrowserOrigins!);
    }

    private static AssignedPolicy Prompts(string id, int priority, int minute, params string[] prompts) =>
        new(id, priority, new DateTime(2026, 1, 1, 0, minute, 0, DateTimeKind.Utc), new DesktopPolicyDocument(new Dictionary<string, bool>(), null, null, new OnboardingPrompts(prompts, null)));

    [Fact]
    public void Onboarding_suggestions_go_to_the_highest_priority_then_the_older_then_the_smaller_id_and_default_is_the_fallback()
    {
        var fallback = Doc("""{"onboardingPrompts":["d1","d2"]}""");
        Assert.Equal(["p2a", "p2b"], DesktopPolicyRules.SelectOnboarding(fallback, [Prompts("a", 1, 5, "p1a", "p1b"), Prompts("b", 2, 9, "p2a", "p2b")])!.Prompts);
        Assert.Equal(["old1", "old2"], DesktopPolicyRules.SelectOnboarding(fallback, [Prompts("b", 1, 9, "new1", "new2"), Prompts("a", 1, 3, "old1", "old2")])!.Prompts);
        Assert.Equal(["x1", "x2"], DesktopPolicyRules.SelectOnboarding(null, [Prompts("b", 1, 3, "y1", "y2"), Prompts("a", 1, 3, "x1", "x2")])!.Prompts);
        Assert.Equal(["d1", "d2"], DesktopPolicyRules.SelectOnboarding(fallback, [])!.Prompts);
        // A policy without suggestions (or with invalid ones) does not take part, however high its priority.
        var plain = new AssignedPolicy("z", 99, DateTime.UtcNow, Doc("""{"onboardingPrompts":["only one"]}"""));
        Assert.Equal(["d1", "d2"], DesktopPolicyRules.SelectOnboarding(fallback, [plain])!.Prompts);
        // The same policy reached twice (through a team and a role) counts once.
        Assert.Equal(["a1", "a2"], DesktopPolicyRules.SelectOnboarding(null, [Prompts("a", 1, 1, "a1", "a2"), Prompts("a", 1, 1, "a1", "a2")])!.Prompts);
        Assert.Null(DesktopPolicyRules.SelectOnboarding(null, []));
    }

    [Fact]
    public void Onboarding_descriptions_count_only_when_they_match_the_prompts_and_one_is_not_empty()
    {
        Assert.Equal(["x", "y"], Doc("""{"onboardingPrompts":["a","b"],"onboardingPromptDescriptions":["x","y"]}""").Onboarding!.Descriptions);
        Assert.Null(Doc("""{"onboardingPrompts":["a","b","c"],"onboardingPromptDescriptions":["x","y"]}""").Onboarding!.Descriptions);
        Assert.Null(Doc("""{"onboardingPrompts":["a","b"],"onboardingPromptDescriptions":["",""]}""").Onboarding!.Descriptions);
    }

    [Theory]
    [InlineData("member", false, "member")]
    [InlineData("admin", false, "admin,member")]
    [InlineData("owner", false, "owner,admin,member")]
    [InlineData("member", true, "admin,member")]            // an Admin team makes a member match admin
    [InlineData("member,admin", false, "admin,member")]
    [InlineData("custom", false, "member")]
    [InlineData("", false, "member")]
    public void A_person_matches_the_roles_their_role_and_Admin_teams_imply(string role, bool adminViaTeam, string expected) =>
        Assert.Equal(expected, string.Join(",", DesktopPolicyRules.MatchingAssignmentRoles(role, adminViaTeam)));

    private static DesktopPolicyDocument Merge(string write, string? existing, bool isDefault = false, bool replace = false) =>
        DesktopPolicyWrites.Merge(DesktopPolicyWrites.Parse(JsonDocument.Parse(write).RootElement), existing, isDefault, replace);

    [Fact]
    public void Writing_a_policy_replaces_its_settings_and_keeps_access_and_execution_the_write_leaves_out()
    {
        var existing = """{"allowZenModel":false,"access":{"mode":"locked","capabilities":{}},"execution":{"commands":"deny","blockedCommands":[]},"onboardingPrompts":["a","b"]}""";
        var merged = Merge("""{"allowControlSettings":false}""", existing);
        Assert.Equal(new Dictionary<string, bool> { ["allowControlSettings"] = false }, merged.Values);
        Assert.Equal("locked", merged.Access!.Mode);
        Assert.Equal("deny", merged.Execution!.Commands);
        Assert.Equal(["a", "b"], merged.Onboarding!.Prompts);
        // A declarative replace drops prompts but still keeps access and execution (as the reference does).
        var replaced = Merge("""{}""", existing, replace: true);
        Assert.Null(replaced.Onboarding);
        Assert.NotNull(replaced.Access);
        // A null clears them; new ones replace them.
        Assert.Null(Merge("""{"onboardingPrompts":null}""", existing).Onboarding);
        Assert.Equal(["c", "d"], Merge("""{"onboardingPrompts":["c","d"]}""", existing).Onboarding!.Prompts);
        // The default policy fills what the write does not name.
        Assert.True(Merge("""{"allowZenModel":false}""", null, isDefault: true).Values["allowCustomProviders"]);
    }

    // ---------------------------------------------------------------- prompts

    private static ResolvablePrompt Prompt(string id, int minute, string content, bool everyone = false, string[]? teams = null, string[]? members = null) =>
        new(id, content, new DateTime(2026, 1, 1, 0, minute, 0, DateTimeKind.Utc), new PromptAssignment(everyone, teams ?? [], members ?? []));

    [Fact]
    public void Prompts_apply_everyone_first_then_the_persons_teams_by_name_then_the_person()
    {
        var teams = new[] { ("t-zed", "Zed"), ("t-alpha", "alpha"), ("t-other", "Other") };
        var prompts = new[]
        {
            Prompt("p1", 1, "zed prompt", teams: ["t-zed"]), Prompt("p2", 2, "everyone prompt", everyone: true), Prompt("p3", 3, "alpha prompt", teams: ["t-alpha"]),
            Prompt("p4", 4, "mine", members: ["m1"]), Prompt("p5", 5, "someone else's", members: ["m2"]), Prompt("p6", 6, "not my team", teams: ["t-nobody"]),
        };
        var r = PromptRules.ResolveForMember(prompts, "m1", teams);
        Assert.Equal(["everyone prompt", "alpha prompt", "zed prompt", "mine"], r.Select(p => p.Content));
        Assert.Equal(["organization", "team", "team", "member"], r.Select(p => p.Source));
        Assert.Equal([null, "alpha", "Zed", null], r.Select(p => p.TeamName));
    }

    [Fact]
    public void A_prompt_that_applies_twice_counts_once_and_an_empty_one_never()
    {
        var teams = new[] { ("t1", "A"), ("t2", "B") };
        var shared = Prompt("p1", 1, "shared", everyone: true, teams: ["t1", "t2"], members: ["m1"]);
        var empty = Prompt("p2", 2, "  ", everyone: true);
        var r = PromptRules.ResolveForMember([shared, empty], "m1", teams);
        Assert.Single(r);
        Assert.Equal("organization", r[0].Source);
        Assert.Equal("a\n\nb", PromptRules.Compose([new MemberPrompt("1", "organization", null, " a "), new MemberPrompt("2", "team", "B", "b")]));
        Assert.Equal("", PromptRules.Compose([]));
    }

    [Fact]
    public void Two_prompts_for_the_same_team_come_oldest_first()
    {
        var r = PromptRules.ResolveForMember([Prompt("b", 5, "newer", teams: ["t"]), Prompt("a", 1, "older", teams: ["t"])], "m", [("t", "T")]);
        Assert.Equal(["older", "newer"], r.Select(p => p.Content));
    }

    // ---------------------------------------------------------------- default model

    private static ModelChoice M(string model, string provider = "p") => new(provider, model);

    [Fact]
    public void The_default_model_is_the_teams_override_unless_two_teams_disagree()
    {
        var org = M("org");
        Assert.Null(DefaultModelRules.Resolve(null, [("A", null)]));
        var none = DefaultModelRules.Resolve(org, [("A", null), ("B", null)])!;
        Assert.Equal(("organization", false), (none.FromKind, none.TeamConflict));
        var one = DefaultModelRules.Resolve(org, [("B", M("b")), ("A", null)])!;
        Assert.Equal((M("b"), "team", "B"), (one.Model, one.FromKind, one.TeamName));
        var agree = DefaultModelRules.Resolve(org, [("B", M("x")), ("A", M("x"))])!;
        Assert.Equal("A", agree.TeamName);   // by team name
        var conflict = DefaultModelRules.Resolve(org, [("B", M("x")), ("A", M("y"))])!;
        Assert.Equal((M("org"), "organization", true), (conflict.Model, conflict.FromKind, conflict.TeamConflict));
        Assert.Null(DefaultModelRules.Resolve(null, [("B", M("x")), ("A", M("y"))]));   // a conflict never picks a team
        // Same model id at another provider is a different model.
        Assert.True(DefaultModelRules.Resolve(org, [("B", M("x", "p1")), ("A", M("x", "p2"))])!.TeamConflict);
    }

    [Fact]
    public void Conflicting_members_are_counted_on_each_of_their_teams()
    {
        var teams = new (string, ModelChoice?)[] { ("t1", M("x")), ("t2", M("y")), ("t3", null), ("t4", M("x")) };
        var memberships = new[] { ("t1", "m1"), ("t2", "m1"), ("t1", "m2"), ("t4", "m2"), ("t3", "m1"), ("t2", "m3") };
        var counts = DefaultModelRules.CountConflicts(teams, memberships);
        Assert.Equal(1, counts["t1"]);   // m1 is on t1 and t2 with different models; m2 agrees with itself
        Assert.Equal(1, counts["t2"]);
        Assert.Equal(1, counts["t3"]);   // a team without an override still lists the member who starts on the organization default
        Assert.Equal(0, counts["t4"]);
    }
}
