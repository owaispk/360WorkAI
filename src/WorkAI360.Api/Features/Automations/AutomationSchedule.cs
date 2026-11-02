using System.Text.Json;
using WorkAI360.Api.Features.Library;

namespace WorkAI360.Api.Features.Automations;

/// <summary>
/// An Automation's schedule, as the reference models it: a one-off moment, every day, certain weekdays, every few hours inside a daily window, or a
/// moment around each meeting (a calendar trigger, which has no clock times). Times of day are wall-clock times in the schedule's own IANA zone.
/// </summary>
public sealed record AutomationSchedule(
    string Kind, string Timezone,
    long At = 0, int Hour = 0, int Minute = 0, IReadOnlyList<int>? DaysOfWeek = null,
    int EveryHours = 0, int StartHour = 0, int EndHour = 24,
    string Edge = "", int OffsetMinutes = 0, bool WithExternalAttendees = false, string? TitleIncludes = null)
{
    public static readonly string[] Kinds = ["once", "daily", "weekly", "interval", "calendar"];
    /// <summary>The kinds released desktops can read; they parse a schedule strictly and cannot cope with any other.</summary>
    public static readonly string[] LegacyKinds = ["once", "daily", "weekly"];

    /// <summary>The wire shape: only the fields of this kind, with every default filled in.</summary>
    public Dictionary<string, object?> ToWire()
    {
        var wire = new Dictionary<string, object?> { ["kind"] = Kind, ["timezone"] = Timezone };
        switch (Kind)
        {
            case "once": wire["at"] = At; break;
            case "daily": wire["hour"] = Hour; wire["minute"] = Minute; break;
            case "weekly": wire["daysOfWeek"] = DaysOfWeek; wire["hour"] = Hour; wire["minute"] = Minute; break;
            case "interval": wire["everyHours"] = EveryHours; wire["daysOfWeek"] = DaysOfWeek; wire["startHour"] = StartHour; wire["endHour"] = EndHour; break;
            case "calendar":
                wire["edge"] = Edge; wire["offsetMinutes"] = OffsetMinutes;
                var rule = new Dictionary<string, object?> { ["withExternalAttendees"] = WithExternalAttendees };
                if (TitleIncludes is not null) rule["titleIncludes"] = TitleIncludes;
                wire["rule"] = rule;
                break;
        }
        return wire;
    }

    public string ToJson() => JsonSerializer.Serialize(ToWire());

    /// <summary>Reads a stored schedule (already validated when it was written).</summary>
    public static AutomationSchedule FromJson(string json) => Parse(JsonDocument.Parse(json).RootElement, []);

    /// <summary>Validates a request's schedule with the reference's rules and messages. Throws <see cref="Invalid"/> with the path under <paramref name="path"/>.</summary>
    public static AutomationSchedule Parse(JsonElement e, string[] path)
    {
        if (e.ValueKind != JsonValueKind.Object) throw new Invalid(Join(path), $"Invalid input: expected object, received {Reader.Kind(e)}");
        var kind = e.TryGetProperty("kind", out var k) && k.ValueKind == JsonValueKind.String ? k.GetString() : null;
        if (kind is null || !Kinds.Contains(kind)) throw new Invalid([(Append(path, "kind"), "invalid_union", "Invalid input")]);
        var tz = Reader.Str(e, "timezone", path, 1, 120);
        if (!ValidZone(tz)) throw new Invalid([(Append(path, "timezone"), "custom", "Expected a valid IANA timezone")]);
        switch (kind)
        {
            case "once":
                return new AutomationSchedule(kind, tz, At: Reader.Int(e, "at", path, 0, long.MaxValue));
            case "daily":
                return new AutomationSchedule(kind, tz, Hour: (int)Reader.Int(e, "hour", path, 0, 23), Minute: (int)Reader.Int(e, "minute", path, 0, 59));
            case "weekly":
                return new AutomationSchedule(kind, tz, Hour: (int)Reader.Int(e, "hour", path, 0, 23), Minute: (int)Reader.Int(e, "minute", path, 0, 59), DaysOfWeek: Days(e, path, required: true));
            case "interval":
                {
                    var every = (int)Reader.Int(e, "everyHours", path, 1, 24);
                    var days = Days(e, path, required: false);
                    var start = Reader.HasValue(e, "startHour") ? (int)Reader.Int(e, "startHour", path, 0, 23) : 0;
                    var end = Reader.HasValue(e, "endHour") ? (int)Reader.Int(e, "endHour", path, 1, 24) : 24;
                    if (end <= start) throw new Invalid([(Append(path, "endHour"), "custom", "endHour must be after startHour")]);
                    return new AutomationSchedule(kind, tz, EveryHours: every, DaysOfWeek: days, StartHour: start, EndHour: end);
                }
            default:
                {
                    var edge = Reader.Str(e, "edge", path, 1, 16, trim: false);
                    if (edge is not ("start" or "end")) throw new Invalid([(Append(path, "edge"), "invalid_value", "Invalid option: expected one of \"start\"|\"end\"")]);
                    var offset = (int)Reader.Int(e, "offsetMinutes", path, -CalendarOffsetMaxMinutes, CalendarOffsetMaxMinutes);
                    var external = false;
                    string? title = null;
                    if (e.TryGetProperty("rule", out var rule))
                    {
                        var rp = Append(path, "rule");
                        if (rule.ValueKind != JsonValueKind.Object) throw new Invalid(Join(rp), $"Invalid input: expected object, received {Reader.Kind(rule)}");
                        var extra = rule.EnumerateObject().Select(p => p.Name).Where(n => n is not ("withExternalAttendees" or "titleIncludes")).ToList();
                        if (extra.Count > 0) throw new Invalid([(rp, "unrecognized_keys", extra.Count == 1 ? $"Unrecognized key: \"{extra[0]}\"" : $"Unrecognized keys: {string.Join(", ", extra.Select(n => $"\"{n}\""))}")]);
                        if (rule.TryGetProperty("withExternalAttendees", out var w))
                        {
                            if (w.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) throw new Invalid(Join(Append(rp, "withExternalAttendees")), $"Invalid input: expected boolean, received {Reader.Kind(w)}");
                            external = w.GetBoolean();
                        }
                        if (rule.TryGetProperty("titleIncludes", out _)) title = Reader.Str(rule, "titleIncludes", rp, 1, 120);
                    }
                    return new AutomationSchedule(kind, tz, Edge: edge, OffsetMinutes: offset, WithExternalAttendees: external, TitleIncludes: title);
                }
        }
    }

    public const int CalendarOffsetMaxMinutes = 120;

    private static IReadOnlyList<int> Days(JsonElement e, string[] path, bool required)
    {
        if (!e.TryGetProperty("daysOfWeek", out var d) || d.ValueKind == JsonValueKind.Undefined)
        {
            if (required) throw new Invalid(Join(Append(path, "daysOfWeek")), "Invalid input: expected array, received undefined");
            return [0, 1, 2, 3, 4, 5, 6];
        }
        if (d.ValueKind != JsonValueKind.Array) throw new Invalid(Join(Append(path, "daysOfWeek")), $"Invalid input: expected array, received {Reader.Kind(d)}");
        var items = new List<int>();
        var index = 0;
        foreach (var item in d.EnumerateArray())
        {
            var ip = Append(Append(path, "daysOfWeek"), index.ToString());
            if (item.ValueKind != JsonValueKind.Number) throw new Invalid(Join(ip), $"Invalid input: expected number, received {Reader.Kind(item)}");
            if (!item.TryGetInt64(out var n)) throw new Invalid(Join(ip), "Invalid input: expected int, received number");
            if (n < 0) throw new Invalid([(ip, "too_small", "Too small: expected number to be >=0")]);
            if (n > 6) throw new Invalid([(ip, "too_big", "Too big: expected number to be <=6")]);
            items.Add((int)n);
            index++;
        }
        if (items.Count < 1) throw new Invalid([(Append(path, "daysOfWeek"), "too_small", "Too small: expected array to have >=1 items")]);
        if (items.Count > 7) throw new Invalid([(Append(path, "daysOfWeek"), "too_big", "Too big: expected array to have <=7 items")]);
        return items.Distinct().Order().ToList();
    }

    private static string Join(string[] path) => string.Join('.', path);
    private static string[] Append(string[] path, string name) => [.. path, name];

    /// <summary>Whether the zone is a real IANA zone this machine knows.</summary>
    public static bool ValidZone(string id)
    {
        try { TimeZoneInfo.FindSystemTimeZoneById(id); return true; }
        catch (Exception e) when (e is TimeZoneNotFoundException or InvalidTimeZoneException) { return false; }
    }

    /// <summary>Whether two schedules say the same thing (an editor sends the whole definition on every save).</summary>
    public bool SameAs(AutomationSchedule other) => ToJson() == other.ToJson();
}

/// <summary>Reading request fields with the reference's messages and paths.</summary>
public static class Reader
{
    public static string Kind(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.Null => "null", JsonValueKind.Number => "number", JsonValueKind.String => "string", JsonValueKind.Array => "array",
        JsonValueKind.Object => "object", JsonValueKind.Undefined => "undefined", _ => "boolean",
    };

    public static bool HasValue(JsonElement e, string name) => e.TryGetProperty(name, out var v) && v.ValueKind != JsonValueKind.Undefined;

    private static string P(string[] path, string name) => string.Join('.', [.. path, name]);

    public static string Str(JsonElement e, string name, string[] path, int min, int max, bool trim = true)
    {
        if (!e.TryGetProperty(name, out var v)) throw new Invalid(P(path, name), "Invalid input: expected string, received undefined");
        if (v.ValueKind != JsonValueKind.String) throw new Invalid(P(path, name), $"Invalid input: expected string, received {Kind(v)}");
        var s = v.GetString()!;
        if (trim) s = s.Trim();
        if (s.Length < min) throw new Invalid(P(path, name), $"Too small: expected string to have >={min} characters", "too_small");
        if (s.Length > max) throw new Invalid(P(path, name), $"Too big: expected string to have <={max} characters", "too_big");
        return s;
    }

    public static long Int(JsonElement e, string name, string[] path, long min, long max)
    {
        if (!e.TryGetProperty(name, out var v)) throw new Invalid(P(path, name), "Invalid input: expected number, received undefined");
        if (v.ValueKind != JsonValueKind.Number) throw new Invalid(P(path, name), $"Invalid input: expected number, received {Kind(v)}");
        long n;
        if (v.TryGetInt64(out var whole)) n = whole;
        else if (v.TryGetDouble(out var d) && d == Math.Floor(d) && Math.Abs(d) < 9e15) n = (long)d;
        else throw new Invalid(P(path, name), "Invalid input: expected int, received number");
        if (n < min) throw new Invalid(P(path, name), $"Too small: expected number to be >={min}", "too_small");
        if (n > max) throw new Invalid(P(path, name), $"Too big: expected number to be <={max}", "too_big");
        return n;
    }
}

/// <summary>
/// When a schedule next runs. Pure functions of the schedule and a time, with the reference's daylight-saving rules: a wall-clock time that happens
/// twice (clocks go back) runs at its first instant; one that does not exist (clocks go forward) runs at the first valid minute after the gap.
/// </summary>
public static class ScheduleMath
{
    private const long MinuteMs = 60_000;
    private const long DayMs = 24 * 60 * MinuteMs;
    private const long ProbeMs = 14 * 60 * MinuteMs;

    private static TimeZoneInfo Zone(string id) => TimeZoneInfo.FindSystemTimeZoneById(id);

    /// <summary>The zone's wall-clock reading of an instant, as milliseconds counted as if that reading were UTC.</summary>
    private static long LocalKey(long utcMs, TimeZoneInfo zone)
    {
        var minute = utcMs - ((utcMs % MinuteMs) + MinuteMs) % MinuteMs;
        var offset = zone.GetUtcOffset(DateTimeOffset.FromUnixTimeMilliseconds(minute));
        return minute + (long)offset.TotalMilliseconds;
    }

    private static DateOnly LocalDate(long utcMs, TimeZoneInfo zone) => DateOnly.FromDateTime(DateTime.UnixEpoch.AddMilliseconds(LocalKey(utcMs, zone)));

    /// <summary>One wall-clock occurrence on a local date: its instant, and whether a daylight-saving gap moved it. Null when it falls on another day.</summary>
    private static (long Instant, bool Shifted)? Resolve(DateOnly date, int hour, int minute, TimeZoneInfo zone)
    {
        var local = date.ToDateTime(new TimeOnly(hour, minute), DateTimeKind.Unspecified);
        var nominal = new DateTimeOffset(DateTime.SpecifyKind(local, DateTimeKind.Utc)).ToUnixTimeMilliseconds();
        if (!zone.IsInvalidTime(local))
        {
            var offset = zone.IsAmbiguousTime(local) ? zone.GetAmbiguousTimeOffsets(local).Max() : zone.GetUtcOffset(local);
            return (nominal - (long)offset.TotalMilliseconds, false);
        }
        // The time does not exist: find the first minute whose wall-clock reading is past it.
        long low = nominal - ProbeMs, high = nominal + ProbeMs;
        if (LocalKey(high, zone) <= nominal) return null;
        if (LocalKey(low, zone) > nominal) return null;
        while (high - low > MinuteMs)
        {
            var middle = low + (high - low) / 2 / MinuteMs * MinuteMs;
            if (middle <= low) middle = low + MinuteMs;
            if (LocalKey(middle, zone) > nominal) high = middle; else low = middle;
        }
        return LocalDate(high, zone) == date ? (high, true) : null;
    }

    private static IEnumerable<(int Hour, int Minute)> WallTimes(AutomationSchedule s)
    {
        if (s.Kind != "interval") { yield return (s.Hour, s.Minute); yield break; }
        for (var hour = s.StartHour; hour < s.EndHour; hour += s.EveryHours) yield return (hour, 0);
    }

    private static List<long> OccurrencesOnDay(AutomationSchedule s, DateOnly date, TimeZoneInfo zone)
    {
        var weekday = (int)date.DayOfWeek;
        if (s.Kind != "daily" && !(s.DaysOfWeek ?? []).Contains(weekday)) return [];
        var found = new List<long>();
        foreach (var (hour, minute) in WallTimes(s))
        {
            if (Resolve(date, hour, minute, zone) is not { } occurrence) continue;
            // Two wall times can land on one instant when a gap pushes one onto the next; it counts once.
            if (found.Count > 0 && occurrence.Instant <= found[^1]) continue;
            found.Add(occurrence.Instant);
        }
        return found;
    }

    /// <summary>The next <paramref name="count"/> (at most 5) occurrences strictly after <paramref name="after"/> (epoch milliseconds), earliest first.</summary>
    public static List<long> Occurrences(AutomationSchedule schedule, long after, int count = 5)
    {
        count = Math.Clamp(count, 0, 5);
        if (count == 0) return [];
        if (schedule.Kind == "once") return schedule.At > after ? [schedule.At] : [];
        if (schedule.Kind == "calendar") return [];
        var zone = Zone(schedule.Timezone);
        var start = LocalDate(after, zone);
        var result = new List<long>();
        for (var offset = 0; offset < 370 && result.Count < count; offset++)
        {
            foreach (var instant in OccurrencesOnDay(schedule, start.AddDays(offset), zone))
            {
                if (instant <= after) continue;
                if (result.Count >= count) break;
                result.Add(instant);
            }
        }
        return result;
    }

    /// <summary>The next occurrence strictly after <paramref name="after"/>, or null when there is none (a past one-off, or a calendar trigger).</summary>
    public static long? Next(AutomationSchedule schedule, long after) => Occurrences(schedule, after, 1) is [var first, ..] ? first : null;

    /// <summary>Every occurrence in [from, to), for calendar views. Ranges beyond 400 days are cut.</summary>
    public static List<long> InRange(AutomationSchedule schedule, long from, long to, int limit = 1000)
    {
        to = Math.Min(to, from + 400 * DayMs);
        if (to <= from || limit <= 0) return [];
        if (schedule.Kind == "once") return schedule.At >= from && schedule.At < to ? [schedule.At] : [];
        if (schedule.Kind == "calendar") return [];
        var zone = Zone(schedule.Timezone);
        var result = new List<long>();
        var last = LocalDate(to, zone).AddDays(1);
        for (var date = LocalDate(from, zone).AddDays(-1); date <= last; date = date.AddDays(1))
        {
            foreach (var instant in OccurrencesOnDay(schedule, date, zone))
            {
                if (instant < from || instant >= to) continue;
                if (result.Count >= limit) return result;
                result.Add(instant);
            }
        }
        return result;
    }
}
