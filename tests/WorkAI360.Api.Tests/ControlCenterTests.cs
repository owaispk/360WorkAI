using Microsoft.EntityFrameworkCore;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.Library;
using WorkAI360.Api.Domain.PlatformAdmin;
using WorkAI360.Api.Features.PlatformAdmin;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>A fresh deployment with one platform admin, so Control Center and request-log numbers are exact.</summary>
public class ControlCenterFactory : ApiFactory
{
    public const string AdminEmail = "cc.admin@example.com";
    protected override IEnumerable<KeyValuePair<string, string>> Settings => [new("PlatformAdmin:BootstrapEmails", AdminEmail)];
}

public sealed class ControlCenterAccessFactory : ControlCenterFactory;
public sealed class RequestLogFactory : ControlCenterFactory;

file static class Admin
{
    public static async Task<string> TokenAsync(ApiFactory factory)
    {
        var http = factory.Plain();
        var r = await http.PostAsJsonAsync("/api/auth/sign-in/email", new { email = ControlCenterFactory.AdminEmail, password = Password });
        if (!r.IsSuccessStatusCode) r = await http.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "CC Admin", email = ControlCenterFactory.AdminEmail, password = Password });
        return (await ReadJsonAsync(r)).GetProperty("token").GetString()!;
    }

    public static async Task<(HttpStatusCode Status, JsonElement Body, HttpResponseMessage Raw)> CallAsync(ApiFactory factory, string? token, HttpMethod method, string url)
    {
        var request = token is null ? new HttpRequestMessage(method, url) : Bearer(method, url, token);
        var r = await factory.Plain().SendAsync(request);
        var text = await r.Content.ReadAsStringAsync();
        return (r.StatusCode, string.IsNullOrEmpty(text) ? default : JsonDocument.Parse(text).RootElement.Clone(), r);
    }
}

public sealed class ControlCenterMathTests
{
    private static UserActivity U(string signup, params string[] days) => new(signup, days.ToHashSet());

    [Fact]
    public void Weeks_start_on_monday_and_every_active_person_is_exactly_one_kind()
    {
        Assert.Equal("2026-11-02", ControlCenterMath.WeekStart("2026-11-03")); // Tuesday
        Assert.Equal("2026-11-02", ControlCenterMath.WeekStart("2026-11-08")); // Sunday
        Assert.Equal(["2026-10-19", "2026-10-26", "2026-11-02"], ControlCenterMath.WeekStarts("2026-11-03", 3));
        var weeks = ControlCenterMath.ClassifyWeeks(
        [
            U("2026-10-27", "2026-10-28", "2026-11-03"), // new in w1, still active in w2
            U("2026-09-01", "2026-10-20", "2026-11-04"), // back after a skipped week in w2; lost in w1? (active the week before w1)
            U("2026-09-01", "2026-10-28"),               // returned in w1, lost in w2
        ], ["2026-10-26", "2026-11-02"]);
        Assert.Equal(new LifecycleWeek("2026-10-26", 1, 0, 1, 1, 2.0), weeks[0]);
        Assert.Equal(new LifecycleWeek("2026-11-02", 0, 1, 1, 1, 1.0), weeks[1]);
    }

    [Fact]
    public void Funnel_reactivation_cohorts_and_reuse_follow_the_reference_rules()
    {
        var funnel = ControlCenterMath.Funnel([U("2026-10-01", "2026-10-02", "2026-10-05", "2026-10-09"), U("2026-10-01", "2026-10-02"), U("2026-10-01"), U("2026-11-01", "2026-11-01")], "2026-10-01", "2026-10-15");
        Assert.Equal(new ActivationFunnel(3, 2, 2, 1), funnel);

        Assert.True(ControlCenterMath.IsReactivated(U("2026-09-01", "2026-10-28"), "2026-10-26"));
        Assert.False(ControlCenterMath.IsReactivated(U("2026-09-01", "2026-10-20", "2026-10-28"), "2026-10-26")); // active during the quiet stretch
        Assert.False(ControlCenterMath.IsReactivated(U("2026-10-20", "2026-10-28"), "2026-10-26"));              // account too new

        var cohorts = ControlCenterMath.RetentionCohorts(
            [("a", "2026-10-19", ControlCenterMath.DayTime("2026-10-19")), ("b", "2026-10-19", ControlCenterMath.DayTime("2026-10-20"))],
            [("a", ControlCenterMath.DayTime("2026-10-20")), ("a", ControlCenterMath.DayTime("2026-10-27")), ("b", ControlCenterMath.DayTime("2026-10-21")), ("x", ControlCenterMath.DayTime("2026-10-21"))]);
        var cohort = Assert.Single(cohorts);
        Assert.Equal(2, cohort.Signups);
        Assert.Equal(2, cohort.Retained[0]);
        Assert.Equal(1, cohort.Retained[1]);

        var reuse = ControlCenterMath.ReuseRate([new("m1", "m1", 1), new("m2", "m1", 3), new("m3", null, 5)]);
        Assert.Equal((9L, 3L), (reuse.Total, reuse.ByOthers));
        Assert.Equal(3 / 9.0, reuse.Rate);
        Assert.Null(ControlCenterMath.ReuseRate([]).Rate);

        Assert.False(ControlCenterMath.IsSharedSkill("m1", [(false, null, "m1")]));
        Assert.True(ControlCenterMath.IsSharedSkill("m1", [(false, null, "m2")]));
        Assert.True(ControlCenterMath.IsSharedSkill("m1", [(false, "t1", null)]));
        Assert.True(ControlCenterMath.IsSharedSkill("m1", [(true, null, null)]));
        Assert.Equal(5, ControlCenterMath.WeekdaysBetween("2026-10-26", "2026-11-02"));
    }

    [Fact]
    public void Request_log_action_names_come_from_the_route_template_never_the_path()
    {
        Assert.Equal("auth.sign_in.email", RequestLog.ActionName("/api/auth/sign-in/email"));
        Assert.Equal("v1.admin.users", RequestLog.ActionName("/v1/admin/users/{userId}"));
        Assert.Equal("v1.org.web_origins", RequestLog.ActionName("v1/org/web-origins/{id}"));
        Assert.Equal("unmatched", RequestLog.ActionName(null));
        Assert.Equal("root", RequestLog.ActionName("/{**rest}"));
        Assert.True(RequestLog.ShouldRecord("/v1/me", 401));
        Assert.True(RequestLog.ShouldRecord("/v1/org", 429));
        Assert.False(RequestLog.ShouldRecord("/v1/org", 403));       // a workspace refusal has a trusted tenant
        Assert.True(RequestLog.ShouldRecord("/api/auth/sign-up/email", 400));
        Assert.True(RequestLog.ShouldRecord("/oauth2/token", 500));
        Assert.False(RequestLog.ShouldRecord("/api/auth/sign-in/email", 200));
    }
}

public sealed class ControlCenterTests(ControlCenterFactory factory) : IClassFixture<ControlCenterFactory>
{
    private static JsonElement Data(JsonElement body, string section) => body.GetProperty("sections").GetProperty(section).GetProperty("data");

    [Fact]
    public async Task Sections_are_computed_from_this_database_with_exact_counts()
    {
        var token = await Admin.TokenAsync(factory); // the admin signs up today: a work address, a session today
        var now = DateTime.UtcNow;
        string Day(int offset) => now.AddDays(offset).ToString("yyyy-MM-dd");
        factory.WithDb(db =>
        {
            User Person(string name, string email, DateTime created) { var u = new User { Id = Ids.New("usr"), Email = email, Name = name, PasswordHash = "!", CreatedAt = created, UpdatedAt = created }; db.Users.Add(u); return u; }
            void SignIn(User u, DateTime at, string? org) => db.Sessions.Add(new Session { Id = Ids.New("ses"), TokenHash = Guid.NewGuid().ToString("N"), UserId = u.Id, ActiveOrganizationId = org, Method = "email", CreatedAt = at, UpdatedAt = at, ExpiresAt = at.AddDays(7) });
            var org = new Organization { Id = Ids.New("org"), Name = "Busy Team", Slug = "busy-team", CreatedAt = now.AddDays(-5) };
            var solo = new Organization { Id = Ids.New("org"), Name = "Solo", Slug = "solo", CreatedAt = now.AddDays(-10) };
            db.Organizations.AddRange(org, solo);
            var alice = Person("Alice", "alice.cc@gmail.com", now.AddDays(-3));      // personal address
            var bob = Person("Bob", "bob.cc@company.example", now.AddDays(-40));       // old account
            var carol = Person("Carol", "carol.cc@company.example", now.AddDays(-10));
            SignIn(alice, now.AddDays(-3), org.Id);
            SignIn(alice, now, org.Id);
            SignIn(carol, now.AddDays(-10), solo.Id);
            var aliceMember = new Member { Id = Ids.New("om"), OrganizationId = org.Id, UserId = alice.Id, Role = "owner", CreatedAt = now.AddDays(-5), JoinedAt = now.AddDays(-5) };
            var invite = new Invitation { Id = Ids.New("inv"), OrganizationId = org.Id, Email = bob.Email, Role = "member", Status = InvitationStatus.Accepted, InviteToken = "t1", InvitedByUserId = alice.Id, PlaceholderMemberId = Ids.New("om"), CreatedAt = now.AddDays(-5), ExpiresAt = now.AddDays(2), AcceptedAt = now.AddDays(-4), AcceptedByUserId = bob.Id };
            var bobMember = new Member { Id = Ids.New("om"), OrganizationId = org.Id, UserId = bob.Id, Role = "member", CreatedAt = now.AddDays(-4), JoinedAt = now.AddDays(-4), InviteId = invite.Id };
            db.Members.AddRange(aliceMember, bobMember, new Member { Id = Ids.New("om"), OrganizationId = solo.Id, UserId = carol.Id, Role = "owner", CreatedAt = now.AddDays(-10), JoinedAt = now.AddDays(-10) });
            // The sign-in-less setup member of an agent-provisioned workspace is not a person: Solo stays a one-person workspace.
            var agent = Person("Setup agent", $"agent+cc@{WorkAI360.Api.Features.Onboarding.BootstrapService.AgentEmailDomain}", now.AddDays(-60));
            db.Members.Add(new Member { Id = Ids.New("om"), OrganizationId = solo.Id, UserId = agent.Id, Role = "owner", CreatedAt = now.AddDays(-10), JoinedAt = now.AddDays(-10) });
            db.Invitations.AddRange(invite,
                new Invitation { Id = Ids.New("inv"), OrganizationId = org.Id, Email = "pending.cc@company.example", Role = "member", Status = InvitationStatus.Pending, InviteToken = "t2", InvitedByUserId = alice.Id, PlaceholderMemberId = Ids.New("om"), CreatedAt = now.AddDays(-1), ExpiresAt = now.AddDays(6) },
                new Invitation { Id = Ids.New("inv"), OrganizationId = org.Id, Email = "gone.cc@company.example", Role = "member", Status = InvitationStatus.Canceled, InviteToken = "t3", InvitedByUserId = alice.Id, PlaceholderMemberId = Ids.New("om"), CreatedAt = now.AddDays(-2), ExpiresAt = now.AddDays(5) });
            db.Set<FeatureUsageDay>().Add(new FeatureUsageDay { MemberId = bobMember.Id, FeatureKey = "browserUse", Day = Day(-2), OrganizationId = org.Id, FirstUsedAt = now.AddDays(-2), LastUsedAt = now.AddDays(-2) });
            var skill = new ConfigObject { Id = Ids.New("cob"), OrganizationId = org.Id, ObjectType = "skill", SourceMode = "cloud", Title = "Shared skill", Status = "active", CreatedByMemberId = aliceMember.Id, CreatedAt = now.AddDays(-3), UpdatedAt = now.AddDays(-3) };
            db.Set<ConfigObject>().Add(skill);
            db.Set<LibraryGrant>().Add(new LibraryGrant { Id = Ids.New("lgr"), OrganizationId = org.Id, ResourceKind = GrantKinds.ConfigObject, ResourceId = skill.Id, SubjectKey = "org", OrgWide = true, Role = "viewer", CreatedByMemberId = aliceMember.Id, CreatedAt = now.AddDays(-3) });
            void Used(Member m, int offset) => db.Set<LibraryUsageEvent>().Add(new LibraryUsageEvent { Id = Ids.New("cue"), OrganizationId = org.Id, MemberId = m.Id, PluginId = "plg_x", ConfigObjectId = skill.Id, Source = "mcp", CreatedAt = now.AddDays(offset) });
            Used(bobMember, -2); Used(bobMember, -2); Used(aliceMember, -1);
            return db.SaveChanges();
        });

        var outcomes = await factory.Services.GetRequiredService<ControlCenterRefresher>().RefreshAsync(ControlCenterMetrics.Sections, force: true);
        Assert.All(ControlCenterMetrics.Sections, s => Assert.Equal("refreshed", outcomes[s]));

        var (status, body, raw) = await Admin.CallAsync(factory, token, HttpMethod.Get, "/v1/admin/control-center");
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal("no-store", raw.Headers.CacheControl?.ToString());
        Assert.Equal("7d", body.GetProperty("range").GetString());
        foreach (var section in ControlCenterMetrics.Sections)
        {
            var s = body.GetProperty("sections").GetProperty(section);
            Assert.False(s.GetProperty("stale").GetBoolean());
            Assert.Equal(JsonValueKind.Null, s.GetProperty("error").ValueKind);
            Assert.Equal(JsonValueKind.Object, s.GetProperty("data").ValueKind);
        }
        Assert.Equal(300_000, body.GetProperty("refresh").GetProperty("fastIntervalMs").GetInt64());

        var pulse = Data(body, "pulse");
        var people = pulse.GetProperty("taskUsers");
        Assert.Equal(2, people.GetProperty("daily").GetInt32());          // admin, Alice
        Assert.Equal(3, people.GetProperty("weekly").GetInt32());         // + Bob (feature use)
        Assert.Equal(4, people.GetProperty("monthly").GetInt32());        // + Carol
        Assert.Equal(1, people.GetProperty("previousWeekly").GetInt32()); // Carol
        Assert.Equal(0, pulse.GetProperty("tasks").GetProperty("weekly").GetInt32());
        Assert.Equal(1, pulse.GetProperty("teamOrganizations").GetProperty("active").GetInt32());
        var signups = pulse.GetProperty("signups");
        Assert.Equal(2, signups.GetProperty("weekly").GetInt32());        // admin, Alice
        Assert.Equal(1, signups.GetProperty("previousWeekly").GetInt32()); // Carol
        Assert.Equal(1, signups.GetProperty("workEmail").GetInt32());     // Alice uses a personal address
        Assert.Equal(7, pulse.GetProperty("daily").GetArrayLength());

        var invitations = Data(body, "invitations");
        Assert.Equal(1, invitations.GetProperty("joinedThroughInvite").GetInt32());
        Assert.Equal(1, invitations.GetProperty("joinedRanTask").GetInt32());
        Assert.Equal(1, invitations.GetProperty("joinedRanTaskWithin7Days").GetInt32());
        var sent = invitations.GetProperty("invitations");
        Assert.Equal((3, 1, 1, 1, 0), (sent.GetProperty("sent").GetInt32(), sent.GetProperty("accepted").GetInt32(), sent.GetProperty("pending").GetInt32(), sent.GetProperty("canceled").GetInt32(), sent.GetProperty("expired").GetInt32()));
        Assert.Equal(24, sent.GetProperty("medianHoursToAccept").GetDouble(), 3);
        Assert.Equal(1, invitations.GetProperty("pendingNow").GetInt32());
        Assert.Equal(JsonValueKind.Null, invitations.GetProperty("outreach").ValueKind);

        var sharing = Data(body, "sharing");
        Assert.Equal(3, sharing.GetProperty("weekly").EnumerateArray().Sum(w => w.GetProperty("skillUses").GetInt32()));
        var skills = sharing.GetProperty("skills");
        Assert.Equal((1, 1, 3, 2), (skills.GetProperty("teamSkills").GetInt32(), skills.GetProperty("sharedTeamSkills").GetInt32(), skills.GetProperty("teamUses").GetInt32(), skills.GetProperty("teammateUses").GetInt32()));
        Assert.Equal(2 / 3.0, skills.GetProperty("teammateReuseRate").GetDouble(), 6);
        Assert.Equal(1, skills.GetProperty("creators").GetInt32());

        var revenue = Data(body, "revenue");
        Assert.Equal(0, revenue.GetProperty("activePaidSeats").GetInt32());
        Assert.Empty(revenue.GetProperty("atRisk").EnumerateArray());

        var account = Assert.Single(Data(body, "accounts").GetProperty("rows").EnumerateArray());
        Assert.Equal("Busy Team", account.GetProperty("name").GetString());
        Assert.Equal((2, 2), (account.GetProperty("members").GetInt32(), account.GetProperty("active7d").GetInt32()));
        Assert.Equal("free", account.GetProperty("plan").GetString());
        Assert.False(account.GetProperty("paying").GetBoolean());

        var lifecycle = Data(body, "lifecycle");
        Assert.Equal(0, lifecycle.GetProperty("reactivation").GetProperty("inactivePool").GetInt32()); // Bob is the only old account, and he is active
        Assert.Equal(JsonValueKind.Array, lifecycle.GetProperty("cohorts").ValueKind);

        // Ranges: 30d has a longer daily chart, and revenue/accounts are range-independent.
        var month = await Admin.CallAsync(factory, token, HttpMethod.Get, "/v1/admin/control-center?range=30d");
        // As in the reference, the chart never starts before usage tracking did.
        var chartStart = ControlCenterMath.Later(ControlCenterMetrics.TrackingStarted, ControlCenterMath.AddDays(Day(0), -29));
        Assert.Equal((int)(ControlCenterMath.DayTime(Day(0)) - ControlCenterMath.DayTime(chartStart)).TotalDays + 1, Data(month.Body, "pulse").GetProperty("daily").GetArrayLength());
        Assert.Equal(HttpStatusCode.BadRequest, (await Admin.CallAsync(factory, token, HttpMethod.Get, "/v1/admin/control-center?range=1y")).Status);
    }

    [Fact]
    public async Task A_failed_refresh_keeps_the_last_good_data_and_says_why_and_leases_stop_double_work()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var store = scope.ServiceProvider.GetRequiredService<ControlCenterStore>();
        var now = DateTime.UtcNow;
        await store.SaveSuccessAsync("revenue", new Dictionary<string, System.Text.Json.Nodes.JsonNode?> { ["all"] = System.Text.Json.Nodes.JsonNode.Parse("{\"activePaidSeats\":7}") }, 5, now.AddMinutes(-1));
        await store.SaveFailureAsync("revenue", ["all"], "database went away", 9, now);
        var read = await AdminControlCenterEndpoints.ReadAsync(store, "7d", now, new ControlCenterOptions());
        var json = JsonSerializer.SerializeToElement(read, new JsonSerializerOptions(JsonSerializerDefaults.Web)).GetProperty("sections").GetProperty("revenue");
        Assert.Equal("database went away", json.GetProperty("error").GetString());
        Assert.Equal(7, json.GetProperty("data").GetProperty("activePaidSeats").GetInt32());

        Assert.True(await store.ClaimAsync("lease-test", "one", now.AddMinutes(15), now, force: false));
        Assert.False(await store.ClaimAsync("lease-test", "two", now.AddMinutes(15), now, force: false));
        Assert.False(await store.ClaimAsync("lease-test", "two", now.AddMinutes(15), now, force: true)); // a running refresh is never taken
        await store.ReleaseAsync("lease-test", "one", now.AddMinutes(10));
        Assert.False(await store.ClaimAsync("lease-test", "two", now.AddMinutes(15), now, force: false)); // cooling down
        Assert.True(await store.ClaimAsync("lease-test", "two", now.AddMinutes(15), now, force: true));   // a manual refresh may skip the cool-down
    }
}

public sealed class ControlCenterAccessTests(ControlCenterAccessFactory factory) : IClassFixture<ControlCenterAccessFactory>
{
    [Fact]
    public async Task Manual_refresh_is_once_a_minute_and_every_route_is_for_platform_admins_only()
    {
        var token = await Admin.TokenAsync(factory);
        var first = await Admin.CallAsync(factory, token, HttpMethod.Post, "/v1/admin/control-center/refresh");
        Assert.Equal(HttpStatusCode.Accepted, first.Status);
        Assert.True(first.Body.GetProperty("scheduled").GetBoolean());
        var second = await Admin.CallAsync(factory, token, HttpMethod.Post, "/v1/admin/control-center/refresh");
        Assert.Equal((HttpStatusCode)429, second.Status);
        Assert.Equal("refresh_rate_limited", second.Body.GetProperty("error").GetString());
        var retry = second.Body.GetProperty("retryAfterSeconds").GetInt32();
        Assert.InRange(retry, 1, 60);
        Assert.Equal(retry.ToString(), second.Raw.Headers.RetryAfter?.ToString());
        Assert.NotEqual(JsonValueKind.Null, (await Admin.CallAsync(factory, token, HttpMethod.Get, "/v1/admin/control-center")).Body.GetProperty("refresh").GetProperty("lastRequestedAt").ValueKind);

        var (_, other, _) = await factory.SignUpAsync(factory.Plain(), "Not Admin");
        foreach (var (method, url) in new[] { (HttpMethod.Get, "/v1/admin/control-center"), (HttpMethod.Post, "/v1/admin/control-center/refresh"), (HttpMethod.Get, "/v1/admin/security/requests") })
        {
            Assert.Equal(HttpStatusCode.Forbidden, (await Admin.CallAsync(factory, other, method, url)).Status);
            Assert.Equal(HttpStatusCode.Unauthorized, (await Admin.CallAsync(factory, null, method, url)).Status);
        }
    }
}

public sealed class RequestLogTests(RequestLogFactory factory) : IClassFixture<RequestLogFactory>
{
    [Fact]
    public async Task Refused_sign_ins_and_stale_credentials_are_counted_by_route_without_any_address_token_or_id()
    {
        var token = await Admin.TokenAsync(factory);
        var http = factory.Plain();
        // Start from an empty log (getting the admin's token may itself have logged a refused sign-in).
        var log = factory.Services.GetRequiredService<RequestLog>();
        await log.FlushAsync();
        factory.WithDb(db => db.Set<PlatformRequestEvent>().ToList().Count + db.Database.ExecuteSqlRaw("DELETE FROM PlatformRequestEvent"));
        const string probeEmail = "victim.cc@example.com";
        for (var i = 0; i < 3; i++)
            Assert.Equal(HttpStatusCode.Unauthorized, (await http.PostAsJsonAsync("/api/auth/sign-in/email", new { email = probeEmail, password = "wrong-" + i })).StatusCode);
        const string staleToken = "stale-token-value-123456";
        Assert.Equal(HttpStatusCode.Unauthorized, (await http.SendAsync(Bearer(HttpMethod.Get, "/v1/me", staleToken))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await http.DeleteAsync("/v1/admin/users/usr_secretid123")).StatusCode);
        // A workspace refusal (trusted tenant) and a successful call are not logged.
        Assert.Equal(HttpStatusCode.OK, (await http.SendAsync(Bearer(HttpMethod.Get, "/v1/me", token))).StatusCode);

        await log.FlushAsync();
        var stored = factory.WithDb(db => db.Set<PlatformRequestEvent>().ToList());
        Assert.Equal(3, stored.Count(e => e.Action == "auth.sign_in.email" && e.Outcome == "denied" && e.Status == 401));
        Assert.Contains(stored, e => e.Action == "v1.me");
        Assert.Contains(stored, e => e.Action == "v1.admin.users");
        Assert.DoesNotContain(stored, e => e.Action.Contains("secretid") || e.Action.Contains("stale") || e.Action.Contains("victim") || e.Action.Contains('@'));

        var (status, body, raw) = await Admin.CallAsync(factory, token, HttpMethod.Get, "/v1/admin/security/requests");
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Equal("no-store", raw.Headers.CacheControl?.ToString());
        Assert.Equal(24, body.GetProperty("hourly").GetArrayLength());
        Assert.Equal(24, body.GetProperty("range").GetProperty("hours").GetInt32());
        Assert.Equal(3, body.GetProperty("hourly").EnumerateArray().Sum(h => h.GetProperty("failedSignIns").GetInt32()));
        Assert.Equal(5, body.GetProperty("hourly").EnumerateArray().Sum(h => h.GetProperty("refused").GetInt32()));
        var signIn = body.GetProperty("endpoints").EnumerateArray().First(e => e.GetProperty("action").GetString() == "auth.sign_in.email");
        Assert.Equal(3, signIn.GetProperty("refused").GetInt32());
        var findings = body.GetProperty("findings").EnumerateArray().ToList();
        Assert.Equal(["denied-spikes", "failed-sign-ins", "rate-limited"], findings.Select(f => f.GetProperty("id").GetString()!).Order().ToArray());
        Assert.Equal(3, findings.Single(f => f.GetProperty("id").GetString() == "failed-sign-ins").GetProperty("value").GetInt32());
        var text = body.GetRawText();
        Assert.DoesNotContain(probeEmail, text);
        Assert.DoesNotContain(staleToken, text);
        Assert.DoesNotContain("127.0.0.1", text);
    }
}
