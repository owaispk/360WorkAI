using System.Globalization;

namespace WorkAI360.Api.Features.PlatformAdmin;

/// <summary>One person's activity: the UTC day they signed up and the UTC days they were active.</summary>
public sealed record UserActivity(string SignupDay, IReadOnlySet<string> Days);

public sealed record LifecycleWeek(string Week, int New, int StillActive, int Returned, int Lost, double? GainsVsLosses);

public sealed record ActivationFunnel(int SignedUp, int Within3Days, int BackAfterDay1, int ActiveInWeek1);

public sealed record RetentionCohort(string Cohort, int Signups, SortedDictionary<int, int> Retained);

/// <summary>A skill use: who used it and who made it (null when unknown).</summary>
public sealed record CapabilityUse(string MemberId, string? CreatorId, long Uses);

/// <summary>
/// The Control Center's pure metric rules (the reference's <c>admin-metrics/definitions.ts</c>), on plain values so they are unit-tested without a
/// database. Days are UTC dates (yyyy-MM-dd); weeks start on Monday and are named by that Monday.
/// </summary>
public static class ControlCenterMath
{
    public static string DayKey(DateTime at) => DateTime.SpecifyKind(at, DateTimeKind.Utc).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

    public static DateTime DayTime(string day) => DateTime.SpecifyKind(DateTime.ParseExact(day, "yyyy-MM-dd", CultureInfo.InvariantCulture), DateTimeKind.Utc);

    public static string AddDays(string day, int days) => DayKey(DayTime(day).AddDays(days));

    public static string WeekStart(string day)
    {
        var offset = ((int)DayTime(day).DayOfWeek + 6) % 7;
        return AddDays(day, -offset);
    }

    /// <summary><paramref name="count"/> consecutive week starts ending with the week that contains <paramref name="lastDay"/>.</summary>
    public static List<string> WeekStarts(string lastDay, int count)
    {
        var last = WeekStart(lastDay);
        return Enumerable.Range(0, count).Select(i => AddDays(last, (i - count + 1) * 7)).ToList();
    }

    public static string Later(string a, string b) => string.CompareOrdinal(a, b) > 0 ? a : b;

    public static double? Ratio(double numerator, double denominator) => denominator > 0 ? numerator / denominator : null;

    public static double? Median(IEnumerable<double> values)
    {
        var sorted = values.OrderBy(v => v).ToArray();
        if (sorted.Length == 0) return null;
        var middle = sorted.Length / 2;
        return sorted.Length % 2 == 1 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
    }

    public static bool ActiveBetween(UserActivity user, string from, string to) =>
        user.Days.Any(d => string.CompareOrdinal(d, from) >= 0 && string.CompareOrdinal(d, to) < 0);

    /// <summary>
    /// Weekly growth accounting. Everyone active in a week is exactly one of: new (signed up that week), still active (also active the week before) or
    /// back after a skipped week. Lost people were active the week before and not this week.
    /// </summary>
    public static List<LifecycleWeek> ClassifyWeeks(IEnumerable<UserActivity> users, IReadOnlyList<string> weeks)
    {
        var counts = weeks.Select(_ => new int[4]).ToList();
        foreach (var user in users)
        {
            var activeWeeks = user.Days.Select(WeekStart).ToHashSet(StringComparer.Ordinal);
            var signupWeek = WeekStart(user.SignupDay);
            for (var i = 0; i < weeks.Count; i++)
            {
                var current = activeWeeks.Contains(weeks[i]);
                var previous = activeWeeks.Contains(AddDays(weeks[i], -7));
                if (current)
                {
                    if (signupWeek == weeks[i]) counts[i][0]++;
                    else if (previous) counts[i][1]++;
                    else counts[i][2]++;
                }
                else if (previous) counts[i][3]++;
            }
        }
        return weeks.Select((w, i) => new LifecycleWeek(w, counts[i][0], counts[i][1], counts[i][2], counts[i][3], Ratio(counts[i][0] + counts[i][2], counts[i][3]))).ToList();
    }

    public const int ReactivationQuietDays = 14;

    /// <summary>Reactivated in a week: active that week, no activity in the 14 days before it, and an account at least 14 days old when the week started.</summary>
    public static bool IsReactivated(UserActivity user, string week)
    {
        var end = AddDays(week, 7);
        var quietFrom = AddDays(week, -ReactivationQuietDays);
        if (string.CompareOrdinal(user.SignupDay, quietFrom) > 0) return false;
        var activeInWeek = false;
        foreach (var day in user.Days)
        {
            if (string.CompareOrdinal(day, quietFrom) >= 0 && string.CompareOrdinal(day, week) < 0) return false;
            if (string.CompareOrdinal(day, week) >= 0 && string.CompareOrdinal(day, end) < 0) activeInWeek = true;
        }
        return activeInWeek;
    }

    /// <summary>
    /// Activation of people who signed up in [from, to]: active within 3 days of signing up, then back on a later day in their first week, then active
    /// again in days 7 to 13. Each step is a subset of the one before.
    /// </summary>
    public static ActivationFunnel Funnel(IEnumerable<UserActivity> users, string from, string to)
    {
        int signedUp = 0, within3 = 0, back = 0, week1 = 0;
        foreach (var user in users)
        {
            if (string.CompareOrdinal(user.SignupDay, from) < 0 || string.CompareOrdinal(user.SignupDay, to) > 0) continue;
            signedUp++;
            var signup = user.SignupDay;
            if (!ActiveBetween(user, signup, AddDays(signup, 3))) continue;
            within3++;
            if (!ActiveBetween(user, AddDays(signup, 1), AddDays(signup, 7))) continue;
            back++;
            if (ActiveBetween(user, AddDays(signup, 7), AddDays(signup, 14))) week1++;
        }
        return new(signedUp, within3, back, week1);
    }

    /// <summary>Weekly signup cohorts: for each cohort, how many people were active N whole weeks after signing up (week 0 is the first 7 days).</summary>
    public static List<RetentionCohort> RetentionCohorts(IEnumerable<(string UserId, string Cohort, DateTime SignupTime)> signups, IEnumerable<(string UserId, DateTime DayTime)> activity)
    {
        var byUser = new Dictionary<string, (string Cohort, DateTime SignupTime)>(StringComparer.Ordinal);
        var cohorts = new SortedDictionary<string, (int Size, Dictionary<int, HashSet<string>> Retained)>(StringComparer.Ordinal);
        foreach (var s in signups)
        {
            byUser[s.UserId] = (s.Cohort, s.SignupTime);
            var c = cohorts.TryGetValue(s.Cohort, out var existing) ? existing : (0, new Dictionary<int, HashSet<string>>());
            cohorts[s.Cohort] = (c.Item1 + 1, c.Item2);
        }
        foreach (var row in activity)
        {
            if (!byUser.TryGetValue(row.UserId, out var signup)) continue;
            var offset = (int)Math.Floor((row.DayTime - signup.SignupTime).TotalDays / 7);
            if (offset < 0) continue;
            var retained = cohorts[signup.Cohort].Retained;
            if (!retained.TryGetValue(offset, out var set)) retained[offset] = set = new HashSet<string>(StringComparer.Ordinal);
            set.Add(row.UserId);
        }
        return cohorts.Select(c => new RetentionCohort(c.Key, c.Value.Size, new SortedDictionary<int, int>(c.Value.Retained.ToDictionary(r => r.Key, r => r.Value.Count)))).ToList();
    }

    /// <summary>Share of uses made by someone other than the skill's creator.</summary>
    public static (long Total, long ByOthers, double? Rate) ReuseRate(IEnumerable<CapabilityUse> uses)
    {
        long total = 0, byOthers = 0;
        foreach (var use in uses)
        {
            total += use.Uses;
            if (use.CreatorId is not null && use.CreatorId != use.MemberId) byOthers += use.Uses;
        }
        return (total, byOthers, Ratio(byOthers, total));
    }

    /// <summary>Shared means granted to the whole workspace, a team, or another person.</summary>
    public static bool IsSharedSkill(string creatorId, IEnumerable<(bool OrgWide, string? TeamId, string? MemberId)> grants) =>
        grants.Any(g => g.OrgWide || g.TeamId is not null || (g.MemberId is not null && g.MemberId != creatorId));

    /// <summary>Monday to Friday days in [from, to).</summary>
    public static int WeekdaysBetween(string from, string to)
    {
        var count = 0;
        for (var day = from; string.CompareOrdinal(day, to) < 0; day = AddDays(day, 1))
            if (DayTime(day).DayOfWeek is not (DayOfWeek.Saturday or DayOfWeek.Sunday)) count++;
        return count;
    }
}
