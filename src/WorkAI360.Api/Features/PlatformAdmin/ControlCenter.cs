using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.Library;
using WorkAI360.Api.Domain.PlatformAdmin;
using static WorkAI360.Api.Features.PlatformAdmin.ControlCenterMath;

namespace WorkAI360.Api.Features.PlatformAdmin;

public sealed class ControlCenterOptions
{
    public const string Section = "PlatformAdmin:Metrics";
    /// <summary>The background refresh (the reference's ADMIN_METRICS_REFRESH_ENABLED). Off: sections stay as last computed, a manual refresh still works.</summary>
    public bool RefreshEnabled { get; set; } = true;
    public int FastIntervalSeconds { get; set; } = 300;
    public int HeavyIntervalSeconds { get; set; } = 1800;
    public int FirstRefreshDelaySeconds { get; set; } = 15;

    public TimeSpan Fast => TimeSpan.FromSeconds(Math.Max(60, FastIntervalSeconds));
    public TimeSpan Heavy => TimeSpan.FromSeconds(Math.Max(300, HeavyIntervalSeconds));
}

/// <summary>
/// The Control Center's sections computed from this database (the reference's <c>admin-metrics/metrics.ts</c>). "Active" is this build's activity rule
/// (a sign-in, or a feature use a client reported), because there is no task telemetry here; task counts are therefore 0, as they are in the reference
/// while its task query is switched off. Never selects emails, tokens or credentials; invitations are read only as counts and durations.
/// </summary>
public sealed class ControlCenterMetrics(DenDbContext db, OrganizationPlans plans)
{
    public static readonly string[] Ranges = ["7d", "30d", "90d"];
    public static readonly string[] Sections = ["pulse", "lifecycle", "invitations", "sharing", "revenue", "accounts"];
    public static readonly IReadOnlyDictionary<string, int> RangeDays = new Dictionary<string, int> { ["7d"] = 7, ["30d"] = 30, ["90d"] = 90 };
    private static readonly IReadOnlyDictionary<string, int> RangeWeeks = new Dictionary<string, int> { ["7d"] = 4, ["30d"] = 5, ["90d"] = 13 };

    // The reference's tracking dates, kept so both builds compare the same windows.
    public const string TrackingStarted = "2026-10-09";
    public const string TrendStart = "2026-10-13";
    public const string CapabilityTrackingStarted = "2026-10-26";

    public static string Tier(string section) => section == "pulse" ? "fast" : "heavy";
    public static IReadOnlyList<string> RangesOf(string section) => section is "revenue" or "accounts" ? ["all"] : Ranges;

    private static string RangeStartDay(string today, string range) => AddDays(today, 1 - RangeDays[range]);

    public Task<Dictionary<string, JsonNode?>> ComputeAsync(string section, DateTime now) => section switch
    {
        "pulse" => PulseAsync(now),
        "lifecycle" => LifecycleAsync(now),
        "invitations" => InvitationsAsync(now),
        "sharing" => SharingAsync(now),
        "revenue" => Task.FromResult(Revenue()),
        "accounts" => AccountsAsync(now),
        _ => throw new ArgumentOutOfRangeException(nameof(section)),
    };

    private static JsonNode? Node(object value) => JsonSerializer.SerializeToNode(value, new JsonSerializerOptions(JsonSerializerDefaults.Web));

    private static Dictionary<string, JsonNode?> PerRange(Func<string, object> build) => Ranges.ToDictionary(r => r, r => Node(build(r)));

    // ---------------------------------------------------------------- shared reads

    /// <summary>People in workspaces (not the sign-in-less setup member of an agent-provisioned workspace).</summary>
    private IQueryable<Member> HumanMembers() =>
        from m in db.Members.AsNoTracking()
        join u in db.Users.AsNoTracking() on m.UserId equals u.Id
        where !u.Email.EndsWith("@" + Onboarding.BootstrapService.AgentEmailDomain)
        select m;

    private IQueryable<User> HumanUsers() => db.Users.AsNoTracking().Where(u => !u.Email.EndsWith("@" + Onboarding.BootstrapService.AgentEmailDomain));

    /// <summary>Workspaces with at least two people.</summary>
    private async Task<Dictionary<string, int>> TeamOrganizationsAsync() =>
        (await HumanMembers().GroupBy(m => m.OrganizationId).Select(g => new { g.Key, People = g.Count() }).Where(g => g.People >= 2).ToListAsync())
            .ToDictionary(g => g.Key, g => g.People, StringComparer.Ordinal);

    /// <summary>Who was active on which UTC day since <paramref name="fromDay"/>: a session created, or a reported feature use.</summary>
    private async Task<List<(string UserId, string Day, string? OrganizationId)>> ActivityAsync(string fromDay, DateTime now)
    {
        var from = DayTime(fromDay);
        var sessions = await db.Sessions.AsNoTracking().Where(s => s.CreatedAt >= from && s.CreatedAt <= now)
            .Select(s => new { s.UserId, s.CreatedAt, s.ActiveOrganizationId }).ToListAsync();
        var toDay = DayKey(now);
        var uses = await (from f in db.Set<FeatureUsageDay>().AsNoTracking()
                          join m in db.Members.AsNoTracking() on f.MemberId equals m.Id
                          where string.Compare(f.Day, fromDay) >= 0 && string.Compare(f.Day, toDay) <= 0
                          select new { m.UserId, f.Day, f.OrganizationId }).Distinct().ToListAsync();
        return sessions.Select(s => (s.UserId, DayKey(s.CreatedAt), s.ActiveOrganizationId))
            .Concat(uses.Select(u => (u.UserId, u.Day, (string?)u.OrganizationId))).ToList();
    }

    /// <summary>People active per workspace in [from, to): a feature use in it, or a sign-in into it.</summary>
    private static Dictionary<string, int> ActivePeopleByOrganization(IEnumerable<(string UserId, string Day, string? OrganizationId)> activity, string from, string to) =>
        activity.Where(a => a.OrganizationId is not null && string.CompareOrdinal(a.Day, from) >= 0 && string.CompareOrdinal(a.Day, to) < 0)
            .GroupBy(a => a.OrganizationId!).ToDictionary(g => g.Key, g => g.Select(a => a.UserId).Distinct().Count(), StringComparer.Ordinal);

    private static bool IsWorkEmail(string email)
    {
        var at = email.LastIndexOf('@');
        return at >= 0 && !AdminSecurityEndpoints.PersonalDomains.Contains(email[(at + 1)..].Trim().ToLowerInvariant());
    }

    // ---------------------------------------------------------------- A. Pulse

    private async Task<Dictionary<string, JsonNode?>> PulseAsync(DateTime now)
    {
        var today = DayKey(now);
        var from = Later(TrackingStarted, AddDays(today, -89));
        // The 30-day window may reach back before the daily chart starts.
        var monthStart = AddDays(today, -29);
        var activity = await ActivityAsync(string.CompareOrdinal(monthStart, from) < 0 ? monthStart : from, now);
        // Windows (rolling, like the reference): today = last 24 hours of days, weekly = last 7 days, monthly = last 30 days.
        int Active(string fromDay, string toDayExclusive) => activity.Where(x => string.CompareOrdinal(x.Day, fromDay) >= 0 && string.CompareOrdinal(x.Day, toDayExclusive) < 0).Select(x => x.UserId).Distinct().Count();
        var tomorrow = AddDays(today, 1);
        var daily = Active(today, tomorrow);
        var weekly = Active(AddDays(today, -6), tomorrow);
        var monthly = Active(AddDays(today, -29), tomorrow);
        var previousWeekly = Active(AddDays(today, -13), AddDays(today, -6));

        var teams = await TeamOrganizationsAsync();
        int ActiveTeams(string fromDay, string toDay) => ActivePeopleByOrganization(activity, fromDay, toDay).Count(p => teams.ContainsKey(p.Key) && p.Value >= 2);

        var fromTime = DayTime(from);
        var users = await HumanUsers().Where(u => u.CreatedAt >= fromTime && u.CreatedAt <= now).Select(u => new { u.Email, u.CreatedAt }).ToListAsync();
        var signupsByDay = users.GroupBy(u => DayKey(u.CreatedAt)).ToDictionary(g => g.Key, g => (All: g.Count(), Work: g.Count(u => IsWorkEmail(u.Email))));
        var weekAgo = now.AddDays(-7);
        var recent = await HumanUsers().Where(u => u.CreatedAt >= now.AddDays(-14) && u.CreatedAt <= now).Select(u => new { u.Email, u.CreatedAt }).ToListAsync();
        var current = recent.Where(u => u.CreatedAt >= weekAgo).ToList();
        var work = current.Count(u => IsWorkEmail(u.Email));

        var activeByDay = activity.GroupBy(x => x.Day).ToDictionary(g => g.Key, g => g.Select(x => x.UserId).Distinct().Count());
        var days = new List<object>();
        for (var day = from; string.CompareOrdinal(day, today) <= 0; day = AddDays(day, 1))
        {
            signupsByDay.TryGetValue(day, out var s);
            days.Add(new Dictionary<string, object> { ["date"] = day, ["taskUsers"] = activeByDay.GetValueOrDefault(day), ["started"] = 0, ["completed"] = 0, ["failed"] = 0, ["signups"] = s.All, ["workEmailSignups"] = s.Work });
        }

        var kpis = new
        {
            taskUsers = new { daily, weekly, monthly, previousWeekly, dailyOverMonthly = Ratio(daily, monthly) },
            tasks = new { weekly = 0, previousWeekly = 0, perWeekday = 0.0, perActiveUser = Ratio(0, weekly) },
            failures = new { started = 0, completed = 0, failed = 0, abandoned = 0, failureRate = (double?)null, abandonedRate = (double?)null, previousFailureRate = (double?)null },
            teamOrganizations = new { active = ActiveTeams(AddDays(today, -6), tomorrow), previous = ActiveTeams(AddDays(today, -13), AddDays(today, -6)) },
            signups = new { weekly = current.Count, previousWeekly = recent.Count - current.Count, workEmail = work, workEmailShare = Ratio(work, current.Count) },
        };
        return PerRange(range =>
        {
            var start = RangeStartDay(today, range);
            return new { kpis.taskUsers, kpis.tasks, kpis.failures, kpis.teamOrganizations, kpis.signups, daily = days.Where(d => string.CompareOrdinal((string)((Dictionary<string, object>)d)["date"], start) >= 0).ToList() };
        });
    }

    // ---------------------------------------------------------------- B–D. Growth, lifecycle, activation, retention, reactivation

    private async Task<List<UserActivity>> UserActivityAsync(DateTime now, string from)
    {
        var fromTime = DayTime(from);
        var signups = await HumanUsers().Where(u => u.CreatedAt >= fromTime && u.CreatedAt <= now).Select(u => new { u.Id, u.CreatedAt }).ToListAsync();
        var activity = await ActivityAsync(from, now);
        var users = signups.ToDictionary(s => s.Id, s => (Signup: DayKey(s.CreatedAt), Days: new HashSet<string>(StringComparer.Ordinal)), StringComparer.Ordinal);
        // Activity counts for people who signed up in the window (the reference reads activity joined to sign-ups the same way).
        var activeIds = activity.Select(a => a.UserId).Distinct().Where(id => !users.ContainsKey(id)).ToList();
        if (activeIds.Count > 0)
        {
            var older = await HumanUsers().Where(u => activeIds.Contains(u.Id)).Select(u => new { u.Id, u.CreatedAt }).ToListAsync();
            foreach (var o in older) users[o.Id] = (DayKey(o.CreatedAt), new HashSet<string>(StringComparer.Ordinal));
        }
        foreach (var a in activity) if (users.TryGetValue(a.UserId, out var u)) u.Days.Add(a.Day);
        return users.Values.Select(u => new UserActivity(u.Signup, u.Days)).ToList();
    }

    private async Task<Dictionary<string, JsonNode?>> LifecycleAsync(DateTime now)
    {
        var today = DayKey(now);
        var currentWeek = WeekStart(today);
        var lastComplete = AddDays(currentWeek, -7);
        var firstTrendWeek = WeekStart(TrendStart);
        var recentWeeks = WeekStarts(lastComplete, RangeWeeks["90d"]);
        var lifecycleWeeks = recentWeeks.Where(w => string.CompareOrdinal(w, AddDays(firstTrendWeek, 7)) >= 0).ToList();
        var from = Later(TrackingStarted, AddDays(today, -126));
        var inactiveCutoff = now.AddDays(-30);
        var people = await UserActivityAsync(now, from);

        var orgFrom = DayTime(recentWeeks[0]);
        var orgTo = DayTime(currentWeek);
        var organizations = await db.Organizations.AsNoTracking().Where(o => o.CreatedAt >= orgFrom && o.CreatedAt < orgTo).Select(o => new { o.Id, o.CreatedAt }).ToListAsync();
        var orgIds = organizations.Select(o => o.Id).ToList();
        var sizes = (await HumanMembers().Where(m => orgIds.Contains(m.OrganizationId)).GroupBy(m => m.OrganizationId).Select(g => new { g.Key, People = g.Count() }).ToListAsync())
            .ToDictionary(g => g.Key, g => g.People, StringComparer.Ordinal);
        var organizationWeeks = recentWeeks.ToDictionary(w => w, _ => new int[2], StringComparer.Ordinal);
        foreach (var o in organizations)
            if (organizationWeeks.TryGetValue(WeekStart(DayKey(o.CreatedAt)), out var bucket)) bucket[sizes.GetValueOrDefault(o.Id) >= 2 ? 1 : 0]++;
        var oldAccounts = await HumanUsers().CountAsync(u => u.CreatedAt < inactiveCutoff);

        var weekRows = ClassifyWeeks(people, lifecycleWeeks);
        var cutoffDay = DayKey(inactiveCutoff);
        var recentlyActiveOld = people.Count(u => DayTime(u.SignupDay) < inactiveCutoff && ActiveBetween(u, cutoffDay, AddDays(today, 1)));
        var previousWeek = AddDays(lastComplete, -7);
        var returnedPrevious = people.Where(u => WeekStart(u.SignupDay) != previousWeek && ActiveBetween(u, previousWeek, lastComplete) && !ActiveBetween(u, AddDays(previousWeek, -7), previousWeek)).ToList();
        var lastWeekRow = ClassifyWeeks(people, [lastComplete])[0];
        var stayed = returnedPrevious.Count(u => ActiveBetween(u, lastComplete, currentWeek));
        var reactivation = new
        {
            week = lastComplete,
            reactivated = people.Count(u => IsReactivated(u, lastComplete)),
            returned = lastWeekRow.Returned,
            lost = lastWeekRow.Lost,
            inactivePool = Math.Max(0, oldAccounts - recentlyActiveOld),
            returnersStayed = new { week = previousWeek, returned = returnedPrevious.Count, stayed, rate = Ratio(stayed, returnedPrevious.Count) },
        };

        var cohortPeople = people.Select((u, i) => (User: u, Id: i.ToString(System.Globalization.CultureInfo.InvariantCulture)))
            .Where(p => string.CompareOrdinal(p.User.SignupDay, firstTrendWeek) >= 0 && string.CompareOrdinal(p.User.SignupDay, currentWeek) < 0).ToList();
        var cohortRows = RetentionCohorts(
            cohortPeople.Select(p => (p.Id, WeekStart(p.User.SignupDay), DayTime(p.User.SignupDay))),
            cohortPeople.SelectMany(p => p.User.Days.Select(d => (p.Id, DayTime(d)))));
        var cohorts = cohortRows.Select(c =>
        {
            // An offset is shown only once the cohort's last signup day has had that whole week.
            var complete = (int)Math.Floor((DayTime(today) - DayTime(AddDays(c.Cohort, 6))).TotalDays / 7) - 1;
            var retention = new List<object>();
            for (var offset = 0; offset <= Math.Min(complete, 13); offset++)
            {
                var retained = c.Retained.GetValueOrDefault(offset);
                retention.Add(new { offset, users = retained, rate = Ratio(retained, c.Signups) });
            }
            return new { week = c.Cohort, signups = c.Signups, retention };
        }).ToList();

        var funnelTo = AddDays(today, -14);
        return PerRange(range =>
        {
            var weeks = WeekStarts(lastComplete, RangeWeeks[range]).ToHashSet(StringComparer.Ordinal);
            var funnelFrom = Later(TrackingStarted, AddDays(funnelTo, 1 - RangeDays[range]));
            var funnel = Funnel(people, funnelFrom, funnelTo);
            return new
            {
                weeks = weekRows.Where(w => weeks.Contains(w.Week)).Select(w => new { week = w.Week, @new = w.New, stillActive = w.StillActive, returned = w.Returned, lost = w.Lost, gainsVsLosses = w.GainsVsLosses }),
                organizations = organizationWeeks.Where(p => weeks.Contains(p.Key)).OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => new { week = p.Key, personal = p.Value[0], team = p.Value[1] }),
                activation = new { from = funnelFrom, to = funnelTo, signedUp = funnel.SignedUp, ranTaskWithin3Days = funnel.Within3Days, backAfterDay1 = funnel.BackAfterDay1, activeInWeek1 = funnel.ActiveInWeek1 },
                cohorts = cohorts.Where(c => weeks.Contains(c.week)),
                reactivation,
            };
        });
    }

    // ---------------------------------------------------------------- D. Invitations

    private async Task<Dictionary<string, JsonNode?>> InvitationsAsync(DateTime now)
    {
        var from = now.AddDays(-90);
        var joined = await HumanMembers().Where(m => m.InviteId != null && m.JoinedAt >= from).Select(m => new { m.Id, m.UserId, m.JoinedAt }).ToListAsync();
        var joinedIds = joined.Select(j => j.Id).ToList();
        // "Started working": a feature use reported in the workspace on or after the day they joined (a sign-in alone does not count here).
        var uses = await db.Set<FeatureUsageDay>().AsNoTracking().Where(f => joinedIds.Contains(f.MemberId)).Select(f => new { f.MemberId, f.FirstUsedAt }).ToListAsync();
        var firstUse = uses.GroupBy(u => u.MemberId).ToDictionary(g => g.Key, g => g.Min(u => u.FirstUsedAt), StringComparer.Ordinal);
        var invitations = await db.Invitations.AsNoTracking().Where(i => i.CreatedAt >= from).Select(i => new { i.CreatedAt, i.Status, i.ExpiresAt, i.AcceptedAt }).ToListAsync();
        var pendingNow = await db.Invitations.AsNoTracking().CountAsync(i => i.Status == InvitationStatus.Pending && i.ExpiresAt >= now);
        return PerRange(range =>
        {
            var since = now.AddDays(-RangeDays[range]);
            var members = joined.Where(j => j.JoinedAt >= since).ToList();
            var ran = members.Where(m => firstUse.TryGetValue(m.Id, out var at) && at >= m.JoinedAt!.Value.Date).ToList();
            var inRange = invitations.Where(i => i.CreatedAt >= since).ToList();
            var hours = inRange.Where(i => i.Status == InvitationStatus.Accepted && i.AcceptedAt is not null).Select(i => (i.AcceptedAt!.Value - i.CreatedAt).TotalHours).Where(h => h >= 0);
            return new
            {
                joinedThroughInvite = members.Count,
                joinedRanTask = ran.Count,
                joinedRanTaskWithin7Days = ran.Count(m => firstUse[m.Id] - m.JoinedAt!.Value <= TimeSpan.FromDays(7)),
                peopleWithAcceptedInvite = members.Select(m => m.UserId).Distinct().Count(),
                invitations = new
                {
                    sent = inRange.Count,
                    accepted = inRange.Count(i => i.Status == InvitationStatus.Accepted),
                    expired = inRange.Count(i => i.Status == InvitationStatus.Pending && i.ExpiresAt < now),
                    pending = inRange.Count(i => i.Status == InvitationStatus.Pending && i.ExpiresAt >= now),
                    canceled = inRange.Count(i => i.Status != InvitationStatus.Pending && i.Status != InvitationStatus.Accepted),
                    medianHoursToAccept = Median(hours),
                },
                pendingNow,
                // No outreach is recorded in this build (the reference's account follow-ups and team nudges).
                outreach = (object?)null,
            };
        });
    }

    // ---------------------------------------------------------------- E–F. Skills and MCP sharing

    private async Task<Dictionary<string, JsonNode?>> SharingAsync(DateTime now)
    {
        var today = DayKey(now);
        var from = Later(CapabilityTrackingStarted, AddDays(today, -89));
        var fromTime = DayTime(from);
        var teams = await TeamOrganizationsAsync();
        var uses = await (from e in db.Set<LibraryUsageEvent>().AsNoTracking()
                          join co in db.Set<ConfigObject>().AsNoTracking() on e.ConfigObjectId equals co.Id into objects
                          from co in objects.DefaultIfEmpty()
                          where e.CreatedAt >= fromTime && e.CreatedAt <= now
                          select new { e.CreatedAt, e.OrganizationId, e.MemberId, Creator = co == null ? null : co.CreatedByMemberId }).ToListAsync();
        var useRows = uses.Select(u => (Day: DayKey(u.CreatedAt), u.OrganizationId, u.MemberId, u.Creator)).ToList();
        var skills = await db.Set<ConfigObject>().AsNoTracking().Where(o => o.ObjectType == "skill" && o.Status == "active" && o.DeletedAt == null)
            .Select(o => new { o.Id, o.OrganizationId, o.CreatedByMemberId, o.CreatedAt }).ToListAsync();
        var skillIds = skills.Select(s => s.Id).ToList();
        var grants = (await db.Set<LibraryGrant>().AsNoTracking().Where(g => g.ResourceKind == GrantKinds.ConfigObject && g.RemovedAt == null && skillIds.Contains(g.ResourceId))
            .Select(g => new { g.ResourceId, g.OrgWide, g.TeamId, g.MemberId }).ToListAsync())
            .GroupBy(g => g.ResourceId).ToDictionary(g => g.Key, g => g.Select(x => (x.OrgWide, x.TeamId, x.MemberId)).ToList(), StringComparer.Ordinal);
        var teamSkills = skills.Where(s => teams.ContainsKey(s.OrganizationId)).ToList();
        var sharedTeamSkills = teamSkills.Count(s => IsSharedSkill(s.CreatedByMemberId, grants.GetValueOrDefault(s.Id) ?? []));
        var marketplaces = await db.Set<Marketplace>().AsNoTracking().Where(m => m.Status == "active" && m.CreatedAt >= now.AddDays(-90)).Select(m => m.CreatedAt).ToListAsync();

        return PerRange(range =>
        {
            var start = Later(from, RangeStartDay(today, range));
            var inRange = useRows.Where(r => string.CompareOrdinal(r.Day, start) >= 0).ToList();
            var weeks = WeekStarts(today, RangeWeeks[range]).Where(w => string.CompareOrdinal(w, WeekStart(from)) >= 0).ToList();
            var weekly = weeks.Select(week =>
            {
                var rows = inRange.Where(r => WeekStart(r.Day) == week).ToList();
                return new { week, skillUsers = rows.Select(r => r.MemberId).Distinct().Count(), skillUses = rows.Count, mcpUsers = 0, mcpCalls = 0 };
            }).ToList();
            var reuse = ReuseRate(inRange.Where(r => teams.ContainsKey(r.OrganizationId)).Select(r => new CapabilityUse(r.MemberId, r.Creator, 1)));
            var rangeStart = now.AddDays(-RangeDays[range]).AddDays(-1);
            var startDay = RangeStartDay(today, range);
            return new
            {
                weekly,
                skills = new
                {
                    creators = skills.Where(s => string.CompareOrdinal(DayKey(s.CreatedAt), startDay) >= 0).Select(s => s.CreatedByMemberId).Distinct().Count(),
                    teamSkills = teamSkills.Count,
                    sharedTeamSkills,
                    sharingRate = Ratio(sharedTeamSkills, teamSkills.Count),
                    teamUses = reuse.Total,
                    teammateUses = reuse.ByOthers,
                    teammateReuseRate = reuse.Rate,
                },
                // MCP tool calls are not logged per call in this build, so these stay 0.
                mcp = new { teamCalls = 0, sharedConnectionCalls = 0, sharedReuseRate = (double?)null },
                connectors = Array.Empty<object>(),
                // The reference reports 0 plugins too (its query is switched off).
                catalog = new { plugins = 0, marketplaces = marketplaces.Count(c => c >= rangeStart) },
            };
        });
    }

    // ---------------------------------------------------------------- G. Revenue (no billing in this build)

    private static Dictionary<string, JsonNode?> Revenue() => new()
    {
        ["all"] = Node(new { activePaidSeats = 0, activePlans = 0, pastDue = 0, monthly = Array.Empty<object>(), atRisk = Array.Empty<object>() }),
    };

    // ---------------------------------------------------------------- H. Accounts to watch

    private async Task<Dictionary<string, JsonNode?>> AccountsAsync(DateTime now)
    {
        var today = DayKey(now);
        var teams = await TeamOrganizationsAsync();
        var activity = await ActivityAsync(AddDays(today, -6), now);
        var active = ActivePeopleByOrganization(activity, AddDays(today, -6), AddDays(today, 1));
        var top = teams.Select(t => (Org: t.Key, Members: t.Value, Active: active.GetValueOrDefault(t.Key)))
            .OrderByDescending(t => t.Active).ThenByDescending(t => t.Members).ThenBy(t => t.Org, StringComparer.Ordinal).Take(25).ToList();
        var ids = top.Select(t => t.Org).ToList();
        var names = await db.Organizations.AsNoTracking().Where(o => ids.Contains(o.Id)).ToDictionaryAsync(o => o.Id, o => o.Name);
        var planStates = await plans.GetManyAsync(ids);
        var rows = top.Where(t => names.ContainsKey(t.Org)).Select(t => new
        {
            organizationId = t.Org, name = names[t.Org], members = t.Members, active7d = t.Active, tasks7d = 0,
            plan = planStates.TryGetValue(t.Org, out var p) ? p.Tier : "free", paying = false, seats = (int?)null, seatUsage = (double?)null,
        }).ToList();
        return new() { ["all"] = Node(new { rows }) };
    }
}

/// <summary>Snapshot rows and refresh leases (the reference's <c>dbSnapshotStore</c>), portable to SQLite and MySQL: every claim is one conditional update.</summary>
public sealed class ControlCenterStore(DenDbContext db)
{
    public const string ManualRefreshKey = "manual_refresh";
    /// <summary>A refresh holding its lease longer than this is presumed dead and can be taken over.</summary>
    public static readonly TimeSpan LeaseTime = TimeSpan.FromMinutes(15);

    private async Task EnsureLeaseRowAsync(string key)
    {
        if (await db.Set<AdminMetricRefreshLease>().AnyAsync(l => l.MetricKey == key)) return;
        db.Set<AdminMetricRefreshLease>().Add(new AdminMetricRefreshLease { MetricKey = key });
        try { await db.SaveChangesAsync(); }
        catch (DbUpdateException) { /* another instance added it */ }
        db.ChangeTracker.Clear();
    }

    /// <summary>Takes the metric's lease. <paramref name="force"/> also takes one that is only cooling down after a refresh, never a running one.</summary>
    public async Task<bool> ClaimAsync(string key, string owner, DateTime until, DateTime now, bool force)
    {
        await EnsureLeaseRowAsync(key);
        var claimed = await db.Set<AdminMetricRefreshLease>()
            .Where(l => l.MetricKey == key && (l.LeaseUntil == null || l.LeaseUntil < now || (force && l.Owner == null)))
            .ExecuteUpdateAsync(s => s.SetProperty(l => l.Owner, owner).SetProperty(l => l.LeaseUntil, until));
        return claimed == 1;
    }

    public Task ReleaseAsync(string key, string owner, DateTime nextDue) =>
        db.Set<AdminMetricRefreshLease>().Where(l => l.MetricKey == key && l.Owner == owner)
            .ExecuteUpdateAsync(s => s.SetProperty(l => l.Owner, (string?)null).SetProperty(l => l.LeaseUntil, nextDue));

    public async Task SaveSuccessAsync(string key, IReadOnlyDictionary<string, JsonNode?> payloads, int durationMs, DateTime now)
    {
        foreach (var (range, payload) in payloads)
        {
            var row = await db.Set<AdminMetricSnapshot>().FirstOrDefaultAsync(s => s.MetricKey == key && s.RangeKey == range);
            if (row is null) db.Set<AdminMetricSnapshot>().Add(row = new AdminMetricSnapshot { MetricKey = key, RangeKey = range });
            row.PayloadJson = payload?.ToJsonString(); row.ComputedAt = now; row.DurationMs = durationMs; row.Error = null; row.AttemptedAt = now;
        }
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();
    }

    /// <summary>Records the error on the metric's rows without touching their last good payload.</summary>
    public async Task SaveFailureAsync(string key, IEnumerable<string> ranges, string error, int durationMs, DateTime now)
    {
        foreach (var range in ranges)
        {
            var row = await db.Set<AdminMetricSnapshot>().FirstOrDefaultAsync(s => s.MetricKey == key && s.RangeKey == range);
            if (row is null) db.Set<AdminMetricSnapshot>().Add(row = new AdminMetricSnapshot { MetricKey = key, RangeKey = range });
            row.Error = error.Length > 500 ? error[..500] : error; row.DurationMs = durationMs; row.AttemptedAt = now;
        }
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();
    }

    public Task<List<AdminMetricSnapshot>> ReadAsync(IEnumerable<string> ranges)
    {
        var keys = ranges.ToList();
        return db.Set<AdminMetricSnapshot>().AsNoTracking().Where(s => keys.Contains(s.RangeKey)).ToListAsync();
    }

    /// <summary>Records a manual refresh unless one was requested less than <paramref name="minInterval"/> ago (one conditional update, so admins never both win).</summary>
    public async Task<(bool Accepted, TimeSpan RetryAfter)> RequestRefreshAsync(DateTime now, TimeSpan minInterval)
    {
        await EnsureLeaseRowAsync(ManualRefreshKey);
        var cutoff = now - minInterval;
        var updated = await db.Set<AdminMetricRefreshLease>()
            .Where(l => l.MetricKey == ManualRefreshKey && (l.RequestedAt == null || l.RequestedAt <= cutoff))
            .ExecuteUpdateAsync(s => s.SetProperty(l => l.RequestedAt, now));
        if (updated == 1) return (true, TimeSpan.Zero);
        var last = await LastRequestedAtAsync() ?? now;
        var wait = last + minInterval - now;
        return (false, wait < TimeSpan.FromSeconds(1) ? TimeSpan.FromSeconds(1) : wait);
    }

    public Task<DateTime?> LastRequestedAtAsync() =>
        db.Set<AdminMetricRefreshLease>().AsNoTracking().Where(l => l.MetricKey == ManualRefreshKey).Select(l => l.RequestedAt).FirstOrDefaultAsync();
}

/// <summary>
/// Recomputes the sections on their tier's interval (fast: pulse; heavy: the rest) and on a manual refresh. One queue per process, so two metric
/// computations never run side by side here; leases coordinate instances.
/// </summary>
public sealed class ControlCenterRefresher(IServiceScopeFactory scopes, IOptions<ControlCenterOptions> options, ILogger<ControlCenterRefresher> logger) : BackgroundService
{
    private readonly SemaphoreSlim _queue = new(1, 1);
    private readonly string _owner = $"{Environment.MachineName[..Math.Min(40, Environment.MachineName.Length)]}:{Environment.ProcessId}:{Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(4)).ToLowerInvariant()}";

    /// <summary>Refreshes the given sections now (waiting for any refresh already running). Returns each section's outcome.</summary>
    public async Task<Dictionary<string, string>> RefreshAsync(IEnumerable<string> sections, bool force, CancellationToken ct = default)
    {
        var outcomes = new Dictionary<string, string>(StringComparer.Ordinal);
        await _queue.WaitAsync(ct);
        try
        {
            foreach (var section in sections)
            {
                await using var scope = scopes.CreateAsyncScope();
                var store = scope.ServiceProvider.GetRequiredService<ControlCenterStore>();
                var metrics = scope.ServiceProvider.GetRequiredService<ControlCenterMetrics>();
                var now = DateTime.UtcNow;
                if (!await store.ClaimAsync(section, _owner, now + ControlCenterStore.LeaseTime, now, force)) { outcomes[section] = "skipped"; continue; }
                var started = System.Diagnostics.Stopwatch.StartNew();
                var outcome = "failed";
                try
                {
                    var payloads = await metrics.ComputeAsync(section, now);
                    await store.SaveSuccessAsync(section, payloads, (int)started.ElapsedMilliseconds, now);
                    outcome = "refreshed";
                }
                catch (Exception e) when (e is not OperationCanceledException)
                {
                    // The first line only: never a query or a value.
                    var message = (e.InnerException ?? e).Message.Split('\n')[0];
                    await store.SaveFailureAsync(section, ControlCenterMetrics.RangesOf(section), string.IsNullOrWhiteSpace(message) ? "Refresh failed" : message, (int)started.ElapsedMilliseconds, now);
                    logger.LogWarning(e, "Control Center section {Section} failed to refresh", section);
                }
                finally
                {
                    var interval = ControlCenterMetrics.Tier(section) == "fast" ? options.Value.Fast : options.Value.Heavy;
                    await store.ReleaseAsync(section, _owner, DateTime.UtcNow + (outcome == "refreshed" ? interval * 0.9 : TimeSpan.Zero));
                }
                outcomes[section] = outcome;
            }
        }
        finally { _queue.Release(); }
        return outcomes;
    }

    /// <summary>Starts a forced refresh of every section without waiting for it.</summary>
    public void ScheduleAll() => _ = Task.Run(async () =>
    {
        try { await RefreshAsync(ControlCenterMetrics.Sections, force: true); }
        catch (Exception e) { logger.LogError(e, "Control Center manual refresh crashed"); }
    });

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Value.RefreshEnabled) return;
        var fast = ControlCenterMetrics.Sections.Where(s => ControlCenterMetrics.Tier(s) == "fast").ToList();
        var heavy = ControlCenterMetrics.Sections.Where(s => ControlCenterMetrics.Tier(s) == "heavy").ToList();
        try { await Task.Delay(TimeSpan.FromSeconds(Math.Max(0, options.Value.FirstRefreshDelaySeconds)), stoppingToken); }
        catch (OperationCanceledException) { return; }
        var nextFast = DateTime.UtcNow;
        var nextHeavy = DateTime.UtcNow;
        while (!stoppingToken.IsCancellationRequested)
        {
            var due = new List<string>();
            if (DateTime.UtcNow >= nextFast) { due.AddRange(fast); nextFast = DateTime.UtcNow + options.Value.Fast; }
            if (DateTime.UtcNow >= nextHeavy) { due.AddRange(heavy); nextHeavy = DateTime.UtcNow + options.Value.Heavy; }
            if (due.Count > 0)
            {
                try { await RefreshAsync(due, force: false, stoppingToken); }
                catch (OperationCanceledException) { break; }
                catch (Exception e) { logger.LogError(e, "Control Center refresh crashed"); }
            }
            var wait = (nextFast < nextHeavy ? nextFast : nextHeavy) - DateTime.UtcNow;
            try { await Task.Delay(wait > TimeSpan.Zero ? wait : TimeSpan.FromSeconds(1), stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }
}

public static class AdminControlCenterEndpoints
{
    private static readonly TimeSpan ManualRefreshInterval = TimeSpan.FromMinutes(1);

    public static void MapAdminControlCenterEndpoints(this WebApplication app)
    {
        app.MapGet("/v1/admin/control-center", async (HttpContext ctx, PlatformAdminGuard guard, ControlCenterStore store, IOptions<ControlCenterOptions> options) =>
        {
            var (_, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            var range = ctx.Request.Query["range"].ToString();
            if (range.Length == 0) range = "7d";
            if (!ControlCenterMetrics.Ranges.Contains(range))
                return AdminSupport.Invalid("range: Invalid option: expected one of \"7d\"|\"30d\"|\"90d\"");
            ctx.Response.Headers.CacheControl = "no-store";
            return Results.Json(await ReadAsync(store, range, DateTime.UtcNow, options.Value));
        });

        app.MapPost("/v1/admin/control-center/refresh", async (HttpContext ctx, PlatformAdminGuard guard, ControlCenterStore store, ControlCenterRefresher refresher) =>
        {
            var (_, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            ctx.Response.Headers.CacheControl = "no-store";
            var now = DateTime.UtcNow;
            var (accepted, retryAfter) = await store.RequestRefreshAsync(now, ManualRefreshInterval);
            if (!accepted)
            {
                var seconds = (int)Math.Ceiling(retryAfter.TotalSeconds);
                ctx.Response.Headers.RetryAfter = seconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
                return Results.Json(new { error = "refresh_rate_limited", message = "The Control Center was refreshed less than a minute ago.", retryAfterSeconds = seconds }, statusCode: 429);
            }
            refresher.ScheduleAll();
            return Results.Json(new { scheduled = true, requestedAt = AdminSupport.Iso(now) }, statusCode: 202);
        });
    }

    public static async Task<object> ReadAsync(ControlCenterStore store, string range, DateTime now, ControlCenterOptions options)
    {
        var rows = await store.ReadAsync([range, "all"]);
        var lastRequested = await store.LastRequestedAtAsync();
        var sections = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach (var key in ControlCenterMetrics.Sections)
        {
            var rangeKey = ControlCenterMetrics.RangesOf(key).Contains(range) ? range : "all";
            var row = rows.FirstOrDefault(r => r.MetricKey == key && r.RangeKey == rangeKey);
            JsonNode? data = null;
            if (row?.PayloadJson is { } json) { try { data = JsonNode.Parse(json); } catch (JsonException) { data = null; } }
            var computedAt = data is null ? null : row!.ComputedAt;
            var interval = ControlCenterMetrics.Tier(key) == "fast" ? options.Fast : options.Heavy;
            sections[key] = new
            {
                computedAt = computedAt is { } c ? AdminSupport.Iso(c) : null,
                stale = computedAt is null || now - computedAt.Value > interval * 2,
                error = row?.Error,
                durationMs = row?.DurationMs,
                data,
            };
        }
        return new
        {
            range,
            generatedAt = AdminSupport.Iso(now),
            sections,
            refresh = new { fastIntervalMs = (long)options.Fast.TotalMilliseconds, heavyIntervalMs = (long)options.Heavy.TotalMilliseconds, lastRequestedAt = lastRequested is { } l ? AdminSupport.Iso(l) : null },
        };
    }
}
