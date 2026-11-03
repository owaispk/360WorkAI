using System.Text.Json;
using WorkAI360.Api.Features.Automations;
using WorkAI360.Api.Features.Library;

namespace WorkAI360.Api.Tests;

/// <summary>The schedule function and the other pure automation rules: no database, no clock.</summary>
public sealed class AutomationScheduleTests
{
    private static long Ms(string utc) => DateTimeOffset.Parse(utc, System.Globalization.CultureInfo.InvariantCulture).ToUnixTimeMilliseconds();
    private static string Utc(long ms) => DateTimeOffset.FromUnixTimeMilliseconds(ms).UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss'Z'");

    private static AutomationSchedule Daily(string tz, int hour, int minute = 0) => new("daily", tz, Hour: hour, Minute: minute);
    private static AutomationSchedule Weekly(string tz, int[] days, int hour, int minute = 0) => new("weekly", tz, Hour: hour, Minute: minute, DaysOfWeek: days);
    private static AutomationSchedule Interval(string tz, int every, int start = 0, int end = 24, int[]? days = null) =>
        new("interval", tz, EveryHours: every, StartHour: start, EndHour: end, DaysOfWeek: days ?? [0, 1, 2, 3, 4, 5, 6]);

    [Fact]
    public void Daily_runs_at_the_next_wall_clock_time_in_the_zone()
    {
        Assert.Equal("2026-03-04T09:00:00Z", Utc(ScheduleMath.Next(Daily("UTC", 9), Ms("2026-03-04T08:59:59Z"))!.Value));
        Assert.Equal("2026-03-05T09:00:00Z", Utc(ScheduleMath.Next(Daily("UTC", 9), Ms("2026-03-04T09:00:01Z"))!.Value));
        // Strictly after: the moment itself is already past.
        Assert.Equal("2026-03-05T09:00:00Z", Utc(ScheduleMath.Next(Daily("UTC", 9), Ms("2026-03-04T09:00:00Z"))!.Value));
        // 09:00 in Kolkata (UTC+5:30) is 03:30 UTC; in Los Angeles in winter (UTC-8) it is 17:00 UTC.
        Assert.Equal("2026-01-10T03:30:00Z", Utc(ScheduleMath.Next(Daily("Asia/Kolkata", 9), Ms("2026-01-10T00:00:00Z"))!.Value));
        Assert.Equal("2026-01-10T17:00:00Z", Utc(ScheduleMath.Next(Daily("America/Los_Angeles", 9), Ms("2026-01-10T00:00:00Z"))!.Value));
    }

    [Fact]
    public void The_local_date_counts_not_the_utc_date()
    {
        // 23:30 in Auckland (UTC+13 in January) on the 11th is still the 10th in UTC.
        Assert.Equal("2026-01-10T10:30:00Z", Utc(ScheduleMath.Next(Daily("Pacific/Auckland", 23, 30), Ms("2026-01-10T10:00:00Z"))!.Value));
    }

    [Fact]
    public void Weekly_runs_only_on_its_days_and_skips_the_rest()
    {
        // 2026-03-04 is a Wednesday. Monday and Friday: the next is Friday the 6th.
        var schedule = Weekly("UTC", [1, 5], 7, 30);
        Assert.Equal("2026-03-06T07:30:00Z", Utc(ScheduleMath.Next(schedule, Ms("2026-03-04T12:00:00Z"))!.Value));
        Assert.Equal("2026-03-09T07:30:00Z", Utc(ScheduleMath.Next(schedule, Ms("2026-03-06T07:30:00Z"))!.Value));
        Assert.Equal(["2026-03-06T07:30:00Z", "2026-03-09T07:30:00Z", "2026-03-13T07:30:00Z"], ScheduleMath.Occurrences(schedule, Ms("2026-03-04T12:00:00Z"), 3).Select(Utc));
    }

    [Fact]
    public void Once_runs_a_single_time_and_never_again()
    {
        var at = Ms("2026-06-01T12:00:00Z");
        var schedule = new AutomationSchedule("once", "UTC", At: at);
        Assert.Equal(at, ScheduleMath.Next(schedule, at - 1));
        Assert.Null(ScheduleMath.Next(schedule, at));
        Assert.Null(ScheduleMath.Next(schedule, at + 1));
    }

    [Fact]
    public void Calendar_triggers_have_no_clock_times()
    {
        var schedule = new AutomationSchedule("calendar", "UTC", Edge: "start", OffsetMinutes: -5);
        Assert.Null(ScheduleMath.Next(schedule, 0));
        Assert.Empty(ScheduleMath.InRange(schedule, 0, 10_000_000_000));
    }

    [Fact]
    public void Interval_counts_from_the_start_hour_and_stops_before_the_end_hour()
    {
        // Every 3 hours from 9 to 18 is 9:00, 12:00 and 15:00 (18:00 is the end, not a run).
        var schedule = Interval("UTC", 3, 9, 18);
        Assert.Equal(["2026-03-04T09:00:00Z", "2026-03-04T12:00:00Z", "2026-03-04T15:00:00Z", "2026-03-05T09:00:00Z"],
            ScheduleMath.Occurrences(schedule, Ms("2026-03-04T00:00:00Z"), 4).Select(Utc));
        Assert.Equal("2026-03-05T09:00:00Z", Utc(ScheduleMath.Next(schedule, Ms("2026-03-04T15:00:00Z"))!.Value));
    }

    [Fact]
    public void Interval_respects_its_days_and_runs_hourly_all_day_by_default()
    {
        // Wednesday 2026-03-04; only Thursday (4).
        Assert.Equal("2026-03-05T00:00:00Z", Utc(ScheduleMath.Next(Interval("UTC", 6, days: [4]), Ms("2026-03-04T12:00:00Z"))!.Value));
        Assert.Equal(["2026-03-04T13:00:00Z", "2026-03-04T14:00:00Z"], ScheduleMath.Occurrences(Interval("UTC", 1), Ms("2026-03-04T12:30:00Z"), 2).Select(Utc));
    }

    [Fact]
    public void Clocks_going_forward_move_a_missing_time_to_the_first_valid_minute_after_the_gap()
    {
        // New York, 2024-03-10: 02:00 jumps to 03:00 (EST -5 becomes EDT -4), so 02:30 does not exist and runs at 03:00 EDT = 07:00 UTC.
        Assert.Equal("2024-03-10T07:00:00Z", Utc(ScheduleMath.Next(Daily("America/New_York", 2, 30), Ms("2024-03-10T00:00:00Z"))!.Value));
        // The day before it is at its normal time (02:30 EST = 07:30 UTC), and the day after too (02:30 EDT = 06:30 UTC).
        Assert.Equal("2024-03-09T07:30:00Z", Utc(ScheduleMath.Next(Daily("America/New_York", 2, 30), Ms("2024-03-09T00:00:00Z"))!.Value));
        Assert.Equal("2024-03-11T06:30:00Z", Utc(ScheduleMath.Next(Daily("America/New_York", 2, 30), Ms("2024-03-10T08:00:00Z"))!.Value));
    }

    [Fact]
    public void Clocks_going_back_run_a_repeated_time_once_at_its_first_instant()
    {
        // New York, 2024-11-03: 02:00 EDT falls back to 01:00 EST, so 01:30 happens twice; the first is 01:30 EDT = 05:30 UTC.
        var next = ScheduleMath.Next(Daily("America/New_York", 1, 30), Ms("2024-11-03T00:00:00Z"));
        Assert.Equal("2024-11-03T05:30:00Z", Utc(next!.Value));
        // It does not run a second time that night: the next is the following day (01:30 EST = 06:30 UTC).
        Assert.Equal("2024-11-04T06:30:00Z", Utc(ScheduleMath.Next(Daily("America/New_York", 1, 30), next.Value)!.Value));
    }

    [Fact]
    public void Two_wall_times_pushed_onto_one_instant_by_a_gap_count_once()
    {
        // Hourly in New York on 2024-03-10: 02:00 does not exist and moves to 03:00, which is also 03:00; one run, not two.
        var runs = ScheduleMath.InRange(Interval("America/New_York", 1), Ms("2024-03-10T06:00:00Z"), Ms("2024-03-10T09:00:00Z")).Select(Utc).ToList();
        Assert.Equal(["2024-03-10T06:00:00Z", "2024-03-10T07:00:00Z", "2024-03-10T08:00:00Z"], runs);
        Assert.Equal(runs.Count, runs.Distinct().Count());
    }

    [Fact]
    public void A_range_lists_every_occurrence_in_it_and_is_half_open()
    {
        var from = Ms("2026-03-01T09:00:00Z");
        var to = Ms("2026-03-04T09:00:00Z");
        Assert.Equal(["2026-03-01T09:00:00Z", "2026-03-02T09:00:00Z", "2026-03-03T09:00:00Z"], ScheduleMath.InRange(Daily("UTC", 9), from, to).Select(Utc));
        Assert.Equal(2, ScheduleMath.InRange(Daily("UTC", 9), from, to, limit: 2).Count);
        Assert.Empty(ScheduleMath.InRange(Daily("UTC", 9), to, from));
    }

    [Fact]
    public void An_occurrence_search_never_returns_more_than_five()
    {
        Assert.Equal(5, ScheduleMath.Occurrences(Daily("UTC", 9), 0, 50).Count);
        Assert.Empty(ScheduleMath.Occurrences(Daily("UTC", 9), 0, 0));
    }

    // ---------------------------------------------------------------- reading a schedule

    private static AutomationSchedule Parse(string json) => AutomationSchedule.Parse(JsonDocument.Parse(json).RootElement, ["schedule"]);

    private static string Message(string json)
    {
        try { Parse(json); return "valid"; }
        catch (Invalid invalid) { var i = invalid.Issues[0]; return string.Join('.', i.Path) + ": " + i.Message; }
    }

    [Theory]
    [InlineData("""{"kind":"daily","timezone":"UTC","hour":24,"minute":0}""", "schedule.hour: Too big: expected number to be <=23")]
    [InlineData("""{"kind":"daily","timezone":"UTC","hour":9,"minute":60}""", "schedule.minute: Too big: expected number to be <=59")]
    [InlineData("""{"kind":"daily","timezone":"UTC","hour":-1,"minute":0}""", "schedule.hour: Too small: expected number to be >=0")]
    [InlineData("""{"kind":"daily","timezone":"UTC","hour":9.5,"minute":0}""", "schedule.hour: Invalid input: expected int, received number")]
    [InlineData("""{"kind":"daily","timezone":"UTC","hour":"9","minute":0}""", "schedule.hour: Invalid input: expected number, received string")]
    [InlineData("""{"kind":"daily","timezone":"Nope/Zone","hour":9,"minute":0}""", "schedule.timezone: Expected a valid IANA timezone")]
    [InlineData("""{"kind":"daily","timezone":" ","hour":9,"minute":0}""", "schedule.timezone: Too small: expected string to have >=1 characters")]
    [InlineData("""{"kind":"daily","hour":9,"minute":0}""", "schedule.timezone: Invalid input: expected string, received undefined")]
    [InlineData("""{"kind":"hourly","timezone":"UTC"}""", "schedule.kind: Invalid input")]
    [InlineData("""{"kind":"weekly","timezone":"UTC","hour":9,"minute":0,"daysOfWeek":[]}""", "schedule.daysOfWeek: Too small: expected array to have >=1 items")]
    [InlineData("""{"kind":"weekly","timezone":"UTC","hour":9,"minute":0,"daysOfWeek":[7]}""", "schedule.daysOfWeek.0: Too big: expected number to be <=6")]
    [InlineData("""{"kind":"weekly","timezone":"UTC","hour":9,"minute":0}""", "schedule.daysOfWeek: Invalid input: expected array, received undefined")]
    [InlineData("""{"kind":"interval","timezone":"UTC","everyHours":0}""", "schedule.everyHours: Too small: expected number to be >=1")]
    [InlineData("""{"kind":"interval","timezone":"UTC","everyHours":25}""", "schedule.everyHours: Too big: expected number to be <=24")]
    [InlineData("""{"kind":"interval","timezone":"UTC","everyHours":3,"startHour":10,"endHour":10}""", "schedule.endHour: endHour must be after startHour")]
    [InlineData("""{"kind":"calendar","timezone":"UTC","edge":"middle","offsetMinutes":0}""", "schedule.edge: Invalid option: expected one of \"start\"|\"end\"")]
    [InlineData("""{"kind":"calendar","timezone":"UTC","edge":"start","offsetMinutes":121}""", "schedule.offsetMinutes: Too big: expected number to be <=120")]
    [InlineData("""{"kind":"calendar","timezone":"UTC","edge":"start","offsetMinutes":0,"rule":{"nope":1}}""", "schedule.rule: Unrecognized key: \"nope\"")]
    [InlineData("""{"kind":"once","timezone":"UTC","at":-5}""", "schedule.at: Too small: expected number to be >=0")]
    [InlineData("""[]""", "schedule: Invalid input: expected object, received array")]
    public void A_schedule_is_validated_with_the_reference_messages(string json, string expected) => Assert.Equal(expected, Message(json));

    [Fact]
    public void Parsing_fills_every_default_and_normalizes()
    {
        var weekly = Parse("""{"kind":"weekly","timezone":"UTC","hour":7,"minute":30,"daysOfWeek":[3,1,3]}""");
        Assert.Equal([1, 3], weekly.DaysOfWeek);
        var interval = Parse("""{"kind":"interval","timezone":"UTC","everyHours":3}""");
        Assert.Equal(0, interval.StartHour);
        Assert.Equal(24, interval.EndHour);
        Assert.Equal(7, interval.DaysOfWeek!.Count);
        var calendar = Parse("""{"kind":"calendar","timezone":"UTC","edge":"end","offsetMinutes":5}""");
        Assert.False(calendar.WithExternalAttendees);
        // What is stored reads back to the same schedule.
        foreach (var s in new[] { weekly, interval, calendar }) Assert.True(s.SameAs(AutomationSchedule.FromJson(s.ToJson())));
    }

    [Fact]
    public void Two_schedules_are_the_same_when_they_say_the_same_thing()
    {
        Assert.True(Daily("UTC", 9).SameAs(Daily("UTC", 9)));
        Assert.False(Daily("UTC", 9).SameAs(Daily("UTC", 10)));
        Assert.False(Daily("UTC", 9).SameAs(Daily("Europe/Paris", 9)));
    }

    // ---------------------------------------------------------------- queue rules

    [Fact]
    public void A_claim_window_never_reaches_the_next_occurrence_nor_drops_below_a_minute()
    {
        const long now = 1_000_000;
        // A scheduled run: the full window when the next occurrence is far away, otherwise cut short at it.
        Assert.Equal(now + 900_000, RunQueue.ClaimDeadline("scheduled", now, 900_000, null));
        Assert.Equal(now + 900_000, RunQueue.ClaimDeadline("scheduled", now, 900_000, now + 3_600_000));
        Assert.Equal(now + 300_000, RunQueue.ClaimDeadline("scheduled", now, 900_000, now + 300_000));
        // But never less than a minute (a due minute-by-minute schedule still gets one).
        Assert.Equal(now + 60_000, RunQueue.ClaimDeadline("scheduled", now, 900_000, now + 10_000));
        // A manual run just gets its window.
        Assert.Equal(now + 180_000, RunQueue.ClaimDeadline("manual", now, 180_000, now + 10_000));
    }

    [Fact]
    public void An_occurrence_has_one_key_and_a_manual_one_needs_a_nonce()
    {
        Assert.Equal(RunQueue.IdempotencyKey("atm_1", 1234, null), RunQueue.IdempotencyKey("atm_1", 1234, null));
        Assert.NotEqual(RunQueue.IdempotencyKey("atm_1", 1234, null), RunQueue.IdempotencyKey("atm_1", 1235, null));
        Assert.NotEqual(RunQueue.IdempotencyKey("atm_1", 1234, null), RunQueue.IdempotencyKey("atm_2", 1234, null));
        Assert.NotEqual(RunQueue.IdempotencyKey("atm_1", null, "a"), RunQueue.IdempotencyKey("atm_1", null, "b"));
        Assert.Throws<ArgumentException>(() => RunQueue.IdempotencyKey("atm_1", null, null));
    }

    [Fact]
    public void A_missed_run_says_why_in_words_a_person_can_act_on()
    {
        const long now = 10_000_000;
        Assert.Equal("Missed — the desktop was busy with another Automation run.", RunQueue.MissedMessage(true, now, now));
        Assert.Equal("Missed — the connected desktop did not pick this up in time.", RunQueue.MissedMessage(false, now - 60_000, now));
        Assert.Equal("Missed — no desktop was connected.", RunQueue.MissedMessage(false, null, now));
        // Presence lasts ten minutes.
        Assert.True(AutomationService.Connected(now - 600_000, now));
        Assert.False(AutomationService.Connected(now - 600_001, now));
    }

    [Fact]
    public void The_retired_free_model_is_only_refused_for_clients_that_handle_model_attention()
    {
        var zen = new ModelChoice("opencode", "big-pickle", null, false);
        var gone = new Failed("model_access_lost", "gone");
        Assert.False(AutomationService.ShouldApply(zen, gone, modelAttentionCapable: false));
        Assert.True(AutomationService.ShouldApply(zen, gone, modelAttentionCapable: true));
        Assert.True(AutomationService.ShouldApply(new ModelChoice("anthropic", "claude", null, false), gone, modelAttentionCapable: false));
        Assert.True(AutomationService.ShouldApply(zen, new Failed("provider_unavailable", "x"), modelAttentionCapable: false));
    }

    // ---------------------------------------------------------------- telemetry rules

    [Fact]
    public void A_dimension_value_is_a_stable_slug_with_a_hash()
    {
        var value = TelemetryRules.DeriveDimensionValue("project", "Alpha Project");
        Assert.Matches("^alpha-project-[0-9a-f]{10}$", value);
        Assert.Equal(value, TelemetryRules.DeriveDimensionValue("project", "  alpha PROJECT "));
        Assert.NotEqual(value, TelemetryRules.DeriveDimensionValue("model", "Alpha Project"));
        Assert.Matches("^cafe-[0-9a-f]{10}$", TelemetryRules.DeriveDimensionValue("project", "Café"));
        Assert.Matches("^dimension-[0-9a-f]{10}$", TelemetryRules.DeriveDimensionValue("project", "!!!"));
        Assert.True(TelemetryRules.DeriveDimensionValue("project", new string('x', 500)).Length <= 128);
    }

    [Fact]
    public void Events_fall_into_weekly_and_daily_buckets_and_a_skewed_clock_counts_in_the_last()
    {
        const long start = 1_000_000_000;
        Assert.Equal(0, TelemetryRules.Bucket(start, start, TelemetryRules.WeekMs, 12));
        Assert.Equal(0, TelemetryRules.Bucket(start + TelemetryRules.WeekMs - 1, start, TelemetryRules.WeekMs, 12));
        Assert.Equal(1, TelemetryRules.Bucket(start + TelemetryRules.WeekMs, start, TelemetryRules.WeekMs, 12));
        Assert.Equal(11, TelemetryRules.Bucket(start + 12 * TelemetryRules.WeekMs, start, TelemetryRules.WeekMs, 12));
        Assert.Equal(11, TelemetryRules.Bucket(start + 50 * TelemetryRules.WeekMs, start, TelemetryRules.WeekMs, 12));
        // The daily trend starts at a UTC midnight 29 days before today's.
        var now = Ms("2026-03-15T13:45:00Z");
        Assert.Equal("2026-02-14T00:00:00Z", Utc(TelemetryRules.DailyTrendStart(now)));
    }

    [Fact]
    public void Window_metrics_count_distinct_people_and_sessions_and_average_task_time()
    {
        TelemetryRow Row(string type, string member, string? session, int? duration = null) => new(type, 0, member, session, "app", duration);
        var m = TelemetryRules.Metrics([Row("task.completed", "a", "s1", 1000), Row("task.completed", "a", "s1", 2001), Row("task.failed", "b", "s2"), Row("user.active", "c", null)]);
        Assert.Equal(3, m.ActiveMembers);
        Assert.Equal(2, m.Sessions);
        Assert.Equal(2, m.TasksCompleted);
        Assert.Equal(1, m.TasksFailed);
        Assert.Equal(1501, m.AvgTaskDurationMs);   // 1500.5 rounds up
        Assert.Null(TelemetryRules.Metrics([Row("task.failed", "a", "s")]).AvgTaskDurationMs);
    }
}
