using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.OrgAdmin;
using WorkAI360.Api.Domain.PlatformAdmin;
using WorkAI360.Api.Features.PlatformAdmin;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>The platform admin reports: feature usage, security, services and sandbox organizations.</summary>
public sealed class PlatformAdminReportTests(PlatformAdminFactory factory) : IClassFixture<PlatformAdminFactory>
{
    private async Task<string> AdminTokenAsync()
    {
        var http = factory.Plain();
        var signIn = await http.PostAsJsonAsync("/api/auth/sign-in/email", new { email = PlatformAdminFactory.BootstrapEmail, password = Password });
        if (!signIn.IsSuccessStatusCode)
        {
            var signUp = await http.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "Boot Admin", email = PlatformAdminFactory.BootstrapEmail, password = Password });
            signUp.EnsureSuccessStatusCode();
            return (await ReadJsonAsync(signUp)).GetProperty("token").GetString()!;
        }
        return (await ReadJsonAsync(signIn)).GetProperty("token").GetString()!;
    }

    private async Task<(HttpStatusCode Status, JsonElement Body, HttpResponseMessage Response)> AdminAsync(string url, HttpMethod? method = null)
    {
        var r = await factory.Plain().SendAsync(Bearer(method ?? HttpMethod.Get, url, await AdminTokenAsync()));
        var text = await r.Content.ReadAsStringAsync();
        return (r.StatusCode, string.IsNullOrEmpty(text) ? default : JsonDocument.Parse(text).RootElement.Clone(), r);
    }

    private static string Msg(JsonElement body) => body.GetProperty("message").GetString()!;

    private async Task ReportAsync(Workspace w, params string[] features)
    {
        var r = await w.Http.SendAsync(w.As(w.Owner, HttpMethod.Post, "/v1/org/feature-usage", new { features }));
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
    }

    // ---------------------------------------------------------------- access

    [Fact]
    public async Task The_reports_are_for_platform_admins_only()
    {
        var w = await Workspace.CreateAsync(factory);
        string[] urls =
        [
            "/v1/admin/feature-usage", "/v1/admin/feature-usage/libraryDetailBreadcrumbs", $"/v1/admin/organizations/{w.OrgId}/feature-usage",
            "/v1/admin/security", "/v1/admin/services", "/v1/admin/sandbox-orgs",
        ];
        foreach (var url in urls)
        {
            Assert.Equal(HttpStatusCode.Unauthorized, (await factory.Plain().GetAsync(url)).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await factory.Plain().SendAsync(Bearer(HttpMethod.Get, url, w.Owner.Token))).StatusCode);
        }
        Assert.Equal(HttpStatusCode.Unauthorized, (await factory.Plain().PostAsync("/v1/admin/services/check", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await factory.Plain().SendAsync(Bearer(HttpMethod.Post, "/v1/admin/services/check", w.Owner.Token))).StatusCode);
    }

    // ---------------------------------------------------------------- feature usage

    [Fact]
    public async Task A_report_is_recorded_for_features_that_are_on_and_unknown_or_off_ones_are_ignored()
    {
        var w = await Workspace.CreateAsync(factory);
        // mermaidZoom is locked off by the operator; libraryDetailBreadcrumbs is on by default.
        await ReportAsync(w, "libraryDetailBreadcrumbs", "mermaidZoom", "noSuchFeature");
        var usage = (await AdminAsync($"/v1/admin/organizations/{w.OrgId}/feature-usage")).Body;
        Assert.Equal(1, usage.GetProperty("activeMembers").GetInt32());
        var features = usage.GetProperty("features").EnumerateArray().ToDictionary(f => f.GetProperty("key").GetString()!);
        var breadcrumbs = features["libraryDetailBreadcrumbs"];
        Assert.Equal(1, breadcrumbs.GetProperty("usedLast7Days").GetInt32());
        Assert.Equal(1, breadcrumbs.GetProperty("usedLast30Days").GetInt32());
        Assert.Equal(1, breadcrumbs.GetProperty("enabledMembers").GetInt32());
        var member = breadcrumbs.GetProperty("members")[0];
        Assert.Equal(w.Owner.MemberId, member.GetProperty("memberId").GetString());
        Assert.Equal(w.Owner.Email, member.GetProperty("email").GetString());
        Assert.Equal(1, member.GetProperty("daysUsed").GetInt32());
        Assert.True(member.GetProperty("enabled").GetBoolean());
        Assert.Equal(0, features["mermaidZoom"].GetProperty("members").GetArrayLength());
        Assert.Equal(0, features["mermaidZoom"].GetProperty("enabledMembers").GetInt32());
        Assert.False(features.ContainsKey("noSuchFeature"));
        // Cloud-only features are not part of this deployment.
        Assert.False(features.ContainsKey("autoRouter"));
    }

    [Fact]
    public async Task Reporting_again_on_the_same_day_moves_the_last_use_and_not_the_day_count()
    {
        var w = await Workspace.CreateAsync(factory);
        await ReportAsync(w, "libraryDetailBreadcrumbs");
        await ReportAsync(w, "libraryDetailBreadcrumbs", "libraryDetailBreadcrumbs");
        var row = factory.WithDb(db => db.Set<FeatureUsageDay>().Where(u => u.MemberId == w.Owner.MemberId).ToList());
        Assert.Single(row);
        Assert.True(row[0].LastUsedAt >= row[0].FirstUsedAt);
        var concurrent = await Task.WhenAll(Enumerable.Range(0, 5).Select(_ => w.Http.SendAsync(w.As(w.Owner, HttpMethod.Post, "/v1/org/feature-usage", new { features = new[] { "mermaidZoom", "libraryDetailBreadcrumbs" } }))));
        Assert.All(concurrent, r => Assert.Equal(HttpStatusCode.OK, r.StatusCode));
        Assert.Single(factory.WithDb(db => db.Set<FeatureUsageDay>().Where(u => u.MemberId == w.Owner.MemberId && u.FeatureKey == "libraryDetailBreadcrumbs").ToList()));
    }

    [Fact]
    public async Task The_report_route_keeps_validating_its_body_and_stays_ok()
    {
        var w = await Workspace.CreateAsync(factory);
        var bad = await w.Http.SendAsync(w.As(w.Owner, HttpMethod.Post, "/v1/org/feature-usage", new { features = "x" }));
        Assert.Equal(HttpStatusCode.BadRequest, bad.StatusCode);
        var empty = await w.Http.SendAsync(w.As(w.Owner, HttpMethod.Post, "/v1/org/feature-usage", new { features = Array.Empty<string>() }));
        Assert.Equal(HttpStatusCode.OK, empty.StatusCode);
        Assert.Empty(factory.WithDb(db => db.Set<FeatureUsageDay>().Where(u => u.MemberId == w.Owner.MemberId).ToList()));
    }

    [Fact]
    public async Task The_all_features_report_counts_organizations_and_members_and_checks_the_range()
    {
        var w = await Workspace.CreateAsync(factory);
        await ReportAsync(w, "libraryDetailBreadcrumbs");
        var r = await AdminAsync("/v1/admin/feature-usage");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal("7d", r.Body.GetProperty("range").GetString());
        Assert.True(r.Body.GetProperty("organizations").GetInt32() >= 1);
        var features = r.Body.GetProperty("features").EnumerateArray().ToDictionary(f => f.GetProperty("key").GetString()!);
        var breadcrumbs = features["libraryDetailBreadcrumbs"];
        Assert.True(breadcrumbs.GetProperty("membersUsing").GetInt32() >= 1);
        Assert.NotEqual(JsonValueKind.Null, breadcrumbs.GetProperty("lastUsedAt").ValueKind);
        Assert.Equal("in_use", breadcrumbs.GetProperty("health").GetProperty("status").GetString());
        Assert.Equal(JsonValueKind.Null, breadcrumbs.GetProperty("outcomes").ValueKind);
        Assert.Equal("not_used", features["nativeDictation"].GetProperty("health").GetProperty("status").GetString());
        Assert.Equal(7, features["automationIntervalSchedules"].GetProperty("outcomes").GetProperty("days").GetArrayLength());
        Assert.Equal("run", features["automationIntervalSchedules"].GetProperty("outcomes").GetProperty("unit").GetString());
        Assert.Equal("meeting", features["automationCalendarTriggers"].GetProperty("outcomes").GetProperty("unit").GetString());
        var thirty = (await AdminAsync("/v1/admin/feature-usage?range=30d")).Body;
        Assert.Equal("30d", thirty.GetProperty("range").GetString());
        Assert.Equal(30, thirty.GetProperty("features").EnumerateArray().First(f => f.GetProperty("key").GetString() == "automationIntervalSchedules").GetProperty("outcomes").GetProperty("days").GetArrayLength());
        var invalid = await AdminAsync("/v1/admin/feature-usage?range=90d");
        Assert.Equal(HttpStatusCode.BadRequest, invalid.Status);
        Assert.Equal("range", invalid.Body.GetProperty("details")[0].GetProperty("path")[0].GetString());
    }

    [Fact]
    public async Task Organizations_with_a_feature_on_follow_the_rollout_and_the_overrides()
    {
        var w = await Workspace.CreateAsync(factory);
        var admin = await AdminTokenAsync();
        var total = (await AdminAsync("/v1/admin/feature-usage")).Body.GetProperty("organizations").GetInt32();
        async Task<int> On(string key) => (await AdminAsync("/v1/admin/feature-usage")).Body.GetProperty("features").EnumerateArray().First(f => f.GetProperty("key").GetString() == key).GetProperty("organizationsOn").GetInt32();
        Assert.Equal(total, await On("libraryDetailBreadcrumbs"));
        var off = await factory.Plain().SendAsync(Bearer(HttpMethod.Put, $"/v1/admin/organizations/{w.OrgId}/capabilities", admin, new { capabilities = new { libraryDetailBreadcrumbs = false } }));
        Assert.Equal(HttpStatusCode.OK, off.StatusCode);
        Assert.Equal(total - 1, await On("libraryDetailBreadcrumbs"));
        Assert.Equal(0, await On("mermaidZoom"));   // locked off
    }

    [Fact]
    public async Task One_feature_lists_its_organizations_and_refuses_what_is_not_there()
    {
        var w = await Workspace.CreateAsync(factory, "Usage Space");
        await ReportAsync(w, "libraryDetailBreadcrumbs");
        var r = await AdminAsync("/v1/admin/feature-usage/libraryDetailBreadcrumbs?range=30d");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        var feature = r.Body.GetProperty("feature");
        Assert.Equal("libraryDetailBreadcrumbs", feature.GetProperty("key").GetString());
        Assert.Equal(0, feature.GetProperty("reasons").GetArrayLength());
        var row = feature.GetProperty("byOrganization").EnumerateArray().First(o => o.GetProperty("organizationId").GetString() == w.OrgId);
        Assert.Equal("Usage Space", row.GetProperty("name").GetString());
        Assert.True(row.GetProperty("enabled").GetBoolean());
        Assert.Equal(1, row.GetProperty("membersUsing").GetInt32());
        Assert.Equal(JsonValueKind.Null, row.GetProperty("outcomes").ValueKind);

        var unknown = await AdminAsync("/v1/admin/feature-usage/nope");
        Assert.Equal(HttpStatusCode.BadRequest, unknown.Status);
        Assert.Equal("Unknown feature.", Msg(unknown.Body));
        var cloud = await AdminAsync("/v1/admin/feature-usage/autoRouter");
        Assert.Equal(HttpStatusCode.NotFound, cloud.Status);
        Assert.Equal("The feature is not part of this deployment.", Msg(cloud.Body));
        // An Automation feature carries outcome counts, zero when nothing ran.
        var automation = (await AdminAsync("/v1/admin/feature-usage/automationIntervalSchedules")).Body.GetProperty("feature");
        Assert.Equal(0, automation.GetProperty("outcomes").GetProperty("runs").GetInt32());
        Assert.All(automation.GetProperty("byOrganization").EnumerateArray(), o => Assert.Equal(0, o.GetProperty("outcomes").GetProperty("runs").GetInt32()));
    }

    [Fact]
    public async Task The_workspace_report_checks_its_id()
    {
        Assert.Equal("Invalid organization id.", Msg((await AdminAsync("/v1/admin/organizations/nope/feature-usage")).Body));
        var missing = await AdminAsync("/v1/admin/organizations/org_01jzzzzzzzzzzzzzzzzzzzzzzz/feature-usage");
        Assert.Equal(HttpStatusCode.NotFound, missing.Status);
        Assert.Equal("Organization not found.", Msg(missing.Body));
    }

    [Fact]
    public async Task Failed_automation_runs_make_a_feature_failing_and_name_the_reasons()
    {
        var w = await Workspace.CreateAsync(factory, "Runs Space");
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        factory.WithDb(db =>
        {
            var automationId = Ids.New("aut");
            var revisionId = Ids.New("rev");
            db.Add(new WorkAI360.Api.Domain.Automations.Automation { Id = automationId, OrganizationId = w.OrgId, OwnerMemberId = w.Owner.MemberId, Name = "x", State = "active", CurrentRevisionId = revisionId, CreatedAt = now, UpdatedAt = now });
            db.Add(new WorkAI360.Api.Domain.Automations.AutomationRevision
            {
                Id = revisionId, AutomationId = automationId, Version = 1, Instructions = "i", ScheduleKind = "interval", ScheduleJson = "{}", ProviderId = "p", ModelId = "m", ActionJson = "{}",
                ExecutionTarget = "cloud", MaximumRuntimeMs = 1000, Digest = "d", CreatedAt = now,
            });
            foreach (var (status, code) in new[] { ("succeeded", (string?)null), ("failed", "model_unavailable"), ("failed", "model_unavailable"), ("skipped", "previous_run_active"), ("queued", null) })
                db.Add(new WorkAI360.Api.Domain.Automations.AutomationRun
                {
                    Id = Ids.New("run"), AutomationId = automationId, RevisionId = revisionId, Trigger = "scheduled", IdempotencyKey = Guid.NewGuid().ToString(), Status = status, ExecutionTarget = "cloud",
                    ThreadId = "t", ProviderId = "p", ModelId = "m", ErrorJson = code is null ? null : JsonSerializer.Serialize(new { code }), UsageJson = "{}", CreatedAt = now, UpdatedAt = now,
                });
            db.SaveChanges();
            return 0;
        });
        var feature = (await AdminAsync("/v1/admin/feature-usage/automationIntervalSchedules")).Body.GetProperty("feature");
        var org = feature.GetProperty("byOrganization").EnumerateArray().First(o => o.GetProperty("organizationId").GetString() == w.OrgId).GetProperty("outcomes");
        Assert.Equal(5, org.GetProperty("runs").GetInt32());
        Assert.Equal(1, org.GetProperty("succeeded").GetInt32());
        Assert.Equal(2, org.GetProperty("failed").GetInt32());
        Assert.Equal(1, org.GetProperty("skipped").GetInt32());
        Assert.Equal("failing", feature.GetProperty("health").GetProperty("status").GetString());
        var reasons = feature.GetProperty("reasons").EnumerateArray().Select(r => (r.GetProperty("reason").GetString(), r.GetProperty("outcome").GetString(), r.GetProperty("count").GetInt32())).ToList();
        Assert.Contains(("model_unavailable", "failed", 2), reasons);
        Assert.Contains(("previous_run_active", "skipped", 1), reasons);
        // The other Automation feature is not mixed in.
        var calendar = (await AdminAsync("/v1/admin/feature-usage/automationCalendarTriggers")).Body.GetProperty("feature");
        Assert.DoesNotContain(calendar.GetProperty("byOrganization").EnumerateArray(), o => o.GetProperty("organizationId").GetString() == w.OrgId && o.GetProperty("outcomes").GetProperty("runs").GetInt32() > 0);
    }

    [Fact]
    public void Health_is_one_plain_state_by_the_references_rules()
    {
        static FeatureOutcomeTotals T(int runs, int ok, int failed, int skipped, int? limited = null) => new(runs, ok, failed, skipped, null, limited, null);
        Assert.Equal(("not_used", null), FeatureHealth.Of(0, null));
        Assert.Equal(("in_use", null), FeatureHealth.Of(3, null));
        Assert.Equal(("not_used", null), FeatureHealth.Of(0, T(0, 0, 0, 0)));
        Assert.Equal(("in_use", null), FeatureHealth.Of(2, T(0, 0, 0, 0)));
        Assert.Equal(("healthy", null), FeatureHealth.Of(1, T(10, 10, 0, 0)));
        Assert.Equal(("failing", 2), FeatureHealth.Of(1, T(10, 8, 2, 0)));        // 2 of 10 is a fifth
        Assert.Equal(("healthy", null), FeatureHealth.Of(1, T(11, 10, 1, 0)));    // 1 of 11 is not
        Assert.Equal(("limited", 4), FeatureHealth.Of(1, T(10, 10, 0, 0, 4)));
        Assert.Equal(("failing", 5), FeatureHealth.Of(1, T(10, 5, 5, 0, 4)));      // failures outrank limits
        Assert.Equal(("mostly_skipped", null), FeatureHealth.Of(1, T(10, 3, 0, 7)));
        Assert.Equal(("limited", 1), FeatureHealth.Of(0, T(0, 0, 0, 0, 1)));
    }

    // ---------------------------------------------------------------- security

    private async Task<Dictionary<string, JsonElement>> FindingsAsync(string query = "")
    {
        var r = await AdminAsync("/v1/admin/security" + query);
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal("no-store", r.Response.Headers.CacheControl?.ToString());
        return r.Body.GetProperty("findings").EnumerateArray().ToDictionary(f => f.GetProperty("id").GetString()!);
    }

    [Fact]
    public async Task The_security_report_has_the_references_shape_and_every_finding_states_its_rule()
    {
        var r = await AdminAsync("/v1/admin/security");
        Assert.Equal(7, r.Body.GetProperty("range").GetProperty("days").GetInt32());
        var findings = r.Body.GetProperty("findings").EnumerateArray().ToList();
        Assert.Equal(14, findings.Count);
        string[] expected = ["signup-networks", "unverified-signups", "disposable-signups", "unverified-domains", "network-spread", "organization-creation", "admin-grants", "api-keys", "client-registrations", "invitations", "spend-spikes", "automation-clients", "round-the-clock", "instant-allowance"];
        Assert.Equal(expected.OrderBy(x => x), findings.Select(f => f.GetProperty("id").GetString()!).OrderBy(x => x));
        foreach (var f in findings)
        {
            Assert.Equal(["category", "entities", "entityCount", "id", "review", "rule", "severity", "summary", "title", "unit", "value", "why"], f.EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal).ToArray());
            Assert.NotEmpty(f.GetProperty("rule").GetString()!);
            Assert.Contains(f.GetProperty("severity").GetString(), new[] { "high", "medium", "low", "clear" });
            Assert.Contains(f.GetProperty("category").GetString(), new[] { "access", "accounts", "automation", "credentials", "usage" });
        }
        // Worst first.
        var ranks = findings.Select(f => f.GetProperty("severity").GetString() switch { "high" => 3, "medium" => 2, "low" => 1, _ => 0 }).ToList();
        Assert.Equal(ranks.OrderByDescending(x => x), ranks);
    }

    [Theory]
    [InlineData("0", "Too small: expected number to be >=1")]
    [InlineData("31", "Too big: expected number to be <=30")]
    [InlineData("1.5", "Invalid input: expected int, received number")]
    [InlineData("abc", "Invalid input: expected number, received NaN")]
    public async Task The_range_is_checked(string days, string message)
    {
        var r = await AdminAsync($"/v1/admin/security?days={days}");
        Assert.Equal(HttpStatusCode.BadRequest, r.Status);
        Assert.Equal("invalid_request", r.Body.GetProperty("error").GetString());
        Assert.Equal(message, r.Body.GetProperty("details")[0].GetProperty("message").GetString());
        Assert.Equal("days", r.Body.GetProperty("details")[0].GetProperty("path")[0].GetString());
    }

    [Fact]
    public async Task The_range_is_in_days_and_reaches_back_that_far()
    {
        var r = await AdminAsync("/v1/admin/security?days=30");
        Assert.Equal(30, r.Body.GetProperty("range").GetProperty("days").GetInt32());
        var from = DateTime.Parse(r.Body.GetProperty("range").GetProperty("from").GetString()!).ToUniversalTime();
        var to = DateTime.Parse(r.Body.GetProperty("range").GetProperty("to").GetString()!).ToUniversalTime();
        Assert.InRange((to - from).TotalDays, 29.99, 30.01);
    }

    private static string Rand() => Guid.NewGuid().ToString("N")[..10];

    [Fact]
    public async Task Throwaway_inboxes_and_unverified_company_domains_are_flagged()
    {
        var http = factory.Plain();
        var domain = $"corp-{Rand()}.test";
        for (var i = 0; i < 5; i++)
        {
            await http.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "Throwaway", email = $"a{i}.{Rand()}@mailinator.com", password = Password });
            await http.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "Unverified", email = $"u{i}.{Rand()}@{domain}", password = Password });
        }
        var findings = await FindingsAsync();
        var disposable = findings["disposable-signups"];
        Assert.True(disposable.GetProperty("value").GetInt32() >= 5);
        Assert.NotEqual("clear", disposable.GetProperty("severity").GetString());
        var entity = disposable.GetProperty("entities").EnumerateArray().First(e => e.GetProperty("id").GetString() == "mailinator.com");
        Assert.True(entity.GetProperty("value").GetInt32() >= 5);
        Assert.Equal(JsonValueKind.Null, entity.GetProperty("target").ValueKind);
        var domains = findings["unverified-domains"];
        var corp = domains.GetProperty("entities").EnumerateArray().First(e => e.GetProperty("id").GetString() == domain);
        Assert.Equal("medium", corp.GetProperty("severity").GetString());
        Assert.Equal("5 of 5 new accounts unverified", corp.GetProperty("detail").GetString());
        // Personal and throwaway domains are covered elsewhere, not repeated here.
        Assert.DoesNotContain(domains.GetProperty("entities").EnumerateArray(), e => e.GetProperty("id").GetString() == "mailinator.com");
    }

    [Fact]
    public async Task A_new_platform_admin_is_listed_for_review()
    {
        await AdminTokenAsync();
        var finding = (await FindingsAsync())["admin-grants"];
        Assert.Equal("medium", finding.GetProperty("severity").GetString());
        Assert.Contains(finding.GetProperty("entities").EnumerateArray(), e => e.GetProperty("label").GetString() == PlatformAdminFactory.BootstrapEmail && e.GetProperty("detail").GetString()!.Contains("Seeded bootstrap admin"));
    }

    [Fact]
    public async Task Bursts_of_api_keys_invitations_and_workspaces_are_flagged_with_a_target()
    {
        var w = await Workspace.CreateAsync(factory);
        var now = DateTime.UtcNow;
        factory.WithDb(db =>
        {
            for (var i = 0; i < 5; i++)
                db.Add(new ApiKey { Id = Ids.New("apk"), OrganizationId = w.OrgId, MemberId = w.Owner.MemberId, UserId = w.Owner.UserId, Name = $"k{i}", Prefix = "den_", Start = "abc", KeyHash = Rand() + i, ExpiresAt = now.AddDays(30), CreatedAt = now, UpdatedAt = now });
            for (var i = 0; i < 25; i++)
                db.Add(new Invitation { Id = Ids.New("inv"), OrganizationId = w.OrgId, Email = $"i{i}.{Rand()}@elsewhere.test", Role = "member", Status = "pending", InviteToken = Rand() + Rand(), InvitedByUserId = w.Owner.UserId, PlaceholderMemberId = Ids.New("om"), CreatedAt = now, ExpiresAt = now.AddDays(7) });
            db.SaveChanges();
            return 0;
        });
        var findings = await FindingsAsync();
        var keys = findings["api-keys"].GetProperty("entities").EnumerateArray().First(e => e.GetProperty("id").GetString() == w.Owner.UserId);
        Assert.Equal("medium", keys.GetProperty("severity").GetString());
        Assert.Equal("Created 5 API keys", keys.GetProperty("detail").GetString());
        Assert.Equal("user", keys.GetProperty("target").GetProperty("type").GetString());
        Assert.Equal(w.Owner.UserId, keys.GetProperty("target").GetProperty("userId").GetString());
        Assert.Contains("keys enabled", findings["api-keys"].GetProperty("summary").GetString());
        var invitations = findings["invitations"].GetProperty("entities").EnumerateArray().First(e => e.GetProperty("id").GetString() == w.Owner.UserId);
        Assert.Equal("25 invitations from 1 organization", invitations.GetProperty("detail").GetString());
        Assert.Equal(w.Owner.Email, invitations.GetProperty("label").GetString());
    }

    [Fact]
    public async Task Sign_ins_from_scripts_and_many_networks_are_flagged()
    {
        var w = await Workspace.CreateAsync(factory);
        var now = DateTime.UtcNow;
        factory.WithDb(db =>
        {
            for (var i = 0; i < 8; i++)
                db.Sessions.Add(new Session { Id = Ids.New("ses"), TokenHash = Rand() + Rand() + i, UserId = w.Owner.UserId, Method = "password", IpAddress = $"203.0.{i}.9", UserAgent = i == 0 ? "Mozilla/5.0 HeadlessChrome/120" : "Mozilla/5.0", CreatedAt = now, UpdatedAt = now, ExpiresAt = now.AddDays(1) });
            db.SaveChanges();
            return 0;
        });
        var findings = await FindingsAsync();
        var spread = findings["network-spread"].GetProperty("entities").EnumerateArray().First(e => e.GetProperty("id").GetString() == w.Owner.UserId);
        Assert.Equal("low", spread.GetProperty("severity").GetString());
        Assert.Equal(8, spread.GetProperty("value").GetInt32());
        var script = findings["automation-clients"].GetProperty("entities").EnumerateArray().First(e => e.GetProperty("id").GetString() == w.Owner.UserId);
        Assert.Contains("Headless Chrome", script.GetProperty("detail").GetString());
        Assert.Contains("on a new account", script.GetProperty("detail").GetString());
        Assert.Equal("medium", script.GetProperty("severity").GetString());
    }

    [Fact]
    public async Task The_findings_that_need_model_usage_are_clear_because_this_build_has_none()
    {
        var findings = await FindingsAsync();
        foreach (var id in new[] { "spend-spikes", "round-the-clock", "instant-allowance" })
        {
            Assert.Equal("clear", findings[id].GetProperty("severity").GetString());
            Assert.Equal(0, findings[id].GetProperty("entityCount").GetInt32());
        }
        Assert.Contains("$25.00", findings["spend-spikes"].GetProperty("rule").GetString());
    }

    [Theory]
    [InlineData("203.0.113.77", "203.0.113.0/24")]
    [InlineData("::ffff:198.51.100.5", "198.51.100.0/24")]
    [InlineData("2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64")]
    [InlineData("2001:db8::1", "2001:db8:0:0::/64")]
    [InlineData("not an address", null)]
    [InlineData("", null)]
    [InlineData(null, null)]
    public void A_network_is_a_coarse_prefix_never_a_full_address(string? ip, string? expected) => Assert.Equal(expected, AdminSecurityEndpoints.NetworkOf(ip));

    [Theory]
    [InlineData("a@Example.COM", "example.com")]
    [InlineData("nobody", null)]
    [InlineData("a@localhost", null)]
    [InlineData("a@x y.test", null)]
    public void The_domain_of_an_email(string email, string? expected) => Assert.Equal(expected, AdminSecurityEndpoints.EmailDomain(email));

    // ---------------------------------------------------------------- services and sandboxes

    [Fact]
    public async Task Service_readiness_uses_the_references_fixed_shape_and_checks_the_database()
    {
        var r = await AdminAsync("/v1/admin/services");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal("no-store", r.Response.Headers.CacheControl?.ToString());
        Assert.Equal(2, r.Body.GetProperty("version").GetInt32());
        Assert.False(r.Body.GetProperty("checking").GetBoolean());
        Assert.Equal(["version", "startedAt", "startupMs"], r.Body.GetProperty("server").EnumerateObject().Select(p => p.Name).ToArray());
        var services = r.Body.GetProperty("services").EnumerateArray().ToList();
        Assert.Equal(["database", "gateway", "headlessRunner", "workbot", "email"], services.Select(s => s.GetProperty("id").GetString()!).ToArray());
        Assert.All(services, s => Assert.Equal(["id", "required", "configured", "state", "reason", "missingSettings", "dependencies", "notes", "durationMs", "checkedAt", "lastSuccessAt", "stale"], s.EnumerateObject().Select(p => p.Name).ToArray()));
        var database = services[0];
        Assert.Equal("ready", database.GetProperty("state").GetString());
        Assert.Equal("database_verified", database.GetProperty("reason").GetString());
        Assert.True(database.GetProperty("required").GetBoolean());
        Assert.False(database.GetProperty("stale").GetBoolean());
        foreach (var absent in services.Skip(1).Take(3))
        {
            Assert.Equal("not_configured", absent.GetProperty("state").GetString());
            Assert.False(absent.GetProperty("configured").GetBoolean());
        }
        Assert.Equal("not_configured", services[4].GetProperty("state").GetString());   // the development mail provider keeps messages in memory
    }

    [Fact]
    public async Task A_check_is_accepted_and_a_recent_one_is_answered_again_without_running()
    {
        var first = await AdminAsync("/v1/admin/services/check", HttpMethod.Post);
        Assert.Equal(HttpStatusCode.Accepted, first.Status);
        var second = await AdminAsync("/v1/admin/services/check", HttpMethod.Post);
        Assert.Equal(HttpStatusCode.Accepted, second.Status);
        Assert.Equal(first.Body.GetProperty("checkedAt").GetString(), second.Body.GetProperty("checkedAt").GetString());
        Assert.Equal("ready", second.Body.GetProperty("services")[0].GetProperty("state").GetString());
    }

    [Fact]
    public async Task Sandbox_organizations_are_off_on_a_self_hosted_deployment()
    {
        var r = await AdminAsync("/v1/admin/sandbox-orgs");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal("no-store", r.Response.Headers.CacheControl?.ToString());
        Assert.False(r.Body.GetProperty("enabled").GetBoolean());
        Assert.Equal(0, r.Body.GetProperty("sandboxes").GetArrayLength());
    }
}
