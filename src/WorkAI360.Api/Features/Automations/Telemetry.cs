using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.Automations;
using WorkAI360.Api.Features.Library;
using WorkAI360.Api.Features.OrgAdmin;
using LibraryZod = WorkAI360.Api.Features.Library.Zod;

namespace WorkAI360.Api.Features.Automations;

public sealed record DimensionInput(string Type, string? Value, string Label, string? MetadataJson);

public sealed record IngestEvent(string Type, long Timestamp, string? Source, string? SessionId, int? DurationMs, bool? Success, IReadOnlyList<DimensionInput> Dimensions);

public sealed record DimensionFilter(string Type, string Value);

public sealed record WindowMetrics(int ActiveMembers, int Sessions, int TasksCompleted, int TasksFailed, int? AvgTaskDurationMs);

/// <summary>Pure rules for telemetry: which events count, how a dimension value is derived, how events fall into weekly and daily buckets.</summary>
public static class TelemetryRules
{
    public const int TrendWeeks = 12;
    public const int TrendDays = 30;
    public const long DayMs = 24 * 60 * 60 * 1000;
    public const long WeekMs = 7 * DayMs;

    /// <summary>The event types the desktop and workers may send.</summary>
    public static readonly string[] ClientTypes = ["user.active", "session.active", "session.started", "session.ended", "task.started", "task.completed", "task.failed"];

    /// <summary>Known to the server but written only by it (Workbot, connections, the activation checklist): a client batch carrying them has them dropped.</summary>
    public static readonly string[] ServerOnlyTypes =
    [
        "workbot.signed_in", "workbot.greeting_started", "workbot.greeting_completed", "workbot.greeting_failed", "workbot.message_sent", "workbot.turn_completed",
        "connection.connected", "activation.first_response", "activation.use_skill", "activation.own_provider", "activation.dismissed",
    ];

    public static readonly string[] Sources = ["app", "worker"];

    /// <summary>Unknown event types, and the server-only ones, are dropped; an unknown source is stored as none.</summary>
    public static bool Accepts(IngestEvent e) => ClientTypes.Contains(e.Type) && e.Source != "workbot";

    public static string NormalizeSource(string? source) => source is not null && Sources.Contains(source) ? source : "unknown";

    public static long DailyTrendStart(long now) => now - ((now % DayMs) + DayMs) % DayMs - (TrendDays - 1) * DayMs;

    /// <summary>The 0-based bucket of a time from <paramref name="start"/>; a time after the last bucket (a skewed clock) counts in the last.</summary>
    public static int Bucket(long timestamp, long start, long size, int count) => (int)Math.Min((timestamp - start) / size, count - 1);

    /// <summary>
    /// A stable value for a (type, label) pair: a slug of the label (lower-case ASCII, other runs become one hyphen, accents dropped) plus a 10-character
    /// content hash, at most 128 characters. Values already stored must keep matching values derived for future events, so the derivation is a contract.
    /// </summary>
    public static string DeriveDimensionValue(string type, string label)
    {
        var digest = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes($"{type}:{label.Trim().ToLowerInvariant()}")))[..10];
        var suffix = "-" + digest;
        var budget = 128 - suffix.Length;
        var slug = new StringBuilder();
        var pendingHyphen = false;
        foreach (var ch in label.Trim().ToLowerInvariant().Normalize(NormalizationForm.FormKD))
        {
            if (ch is >= 'a' and <= 'z' or >= '0' and <= '9')
            {
                if (pendingHyphen && slug.Length > 0) slug.Append('-');
                pendingHyphen = false;
                slug.Append(ch);
            }
            else if (ch is >= '̀' and <= 'ͯ') { /* a combining accent from folding: dropped */ }
            else pendingHyphen = true;
        }
        var text = slug.Length > 0 ? slug.ToString() : "dimension";
        return (text.Length > budget ? text[..budget] : text) + suffix;
    }

    public static WindowMetrics Metrics(IReadOnlyCollection<TelemetryRow> events)
    {
        var completed = events.Where(e => e.Type == "task.completed").ToList();
        var durations = completed.Where(e => e.DurationMs is not null).Select(e => (double)e.DurationMs!.Value).ToList();
        return new WindowMetrics(
            events.Select(e => e.MemberId).Distinct().Count(),
            events.Where(e => e.SessionId is not null).Select(e => e.SessionId).Distinct().Count(),
            completed.Count, events.Count(e => e.Type == "task.failed"),
            durations.Count == 0 ? null : (int)Math.Round(durations.Average(), MidpointRounding.AwayFromZero));
    }
}

public sealed record TelemetryRow(string Type, long Timestamp, string MemberId, string? SessionId, string? Source, int? DurationMs);

/// <summary>Accepting usage events from the desktop and workers, and the analytics computed from them (nothing leaves this database).</summary>
public sealed class TelemetryService(DenDbContext db)
{
    public async Task IngestAsync(string organizationId, string memberId, IReadOnlyList<IngestEvent> batch)
    {
        var accepted = batch.Where(TelemetryRules.Accepts).ToList();
        var now = AutomationService.Now();
        if (accepted.Count > 0)
        {
            foreach (var e in accepted)
                db.Set<TelemetryEvent>().Add(new TelemetryEvent
                {
                    Id = Ids.New("tev"), OrganizationId = organizationId, MemberId = memberId, EventType = e.Type, EventTimestamp = e.Timestamp,
                    Source = e.Source is not null && TelemetryRules.Sources.Contains(e.Source) ? e.Source : null, SessionId = e.SessionId, DurationMs = e.DurationMs, Success = e.Success, CreatedAt = now,
                });
            await db.SaveChangesAsync();
        }
        // The last sighting per (source, session, dimension type) in the batch wins.
        var pending = new Dictionary<(string, string, string), (string Session, string Source, DimensionInput Dimension, long SeenAt)>();
        foreach (var e in accepted)
        {
            if (e.SessionId is null || e.Dimensions.Count == 0) continue;
            var source = TelemetryRules.NormalizeSource(e.Source);
            foreach (var d in e.Dimensions) pending[(source, e.SessionId, d.Type)] = (e.SessionId, source, d, e.Timestamp);
        }
        foreach (var sighting in pending.Values) await UpsertDimensionAsync(organizationId, sighting.Session, sighting.Source, sighting.Dimension, sighting.SeenAt);
    }

    /// <summary>One row per (workspace, source, session, type): a repeat sighting refreshes label, metadata and last-seen, and only replaces the value when the client gave one.</summary>
    private async Task UpsertDimensionAsync(string organizationId, string sessionId, string source, DimensionInput d, long seenAt)
    {
        for (var attempt = 0; ; attempt++)
        {
            var explicitValue = d.Value;
            var updated = await db.Set<TelemetrySessionDimension>().Where(x => x.OrganizationId == organizationId && x.Source == source && x.SessionId == sessionId && x.DimensionType == d.Type)
                .ExecuteUpdateAsync(s => s.SetProperty(x => x.DimensionValue, x => explicitValue ?? x.DimensionValue).SetProperty(x => x.DimensionLabel, d.Label)
                    .SetProperty(x => x.MetadataJson, d.MetadataJson).SetProperty(x => x.UpdatedAt, seenAt).SetProperty(x => x.LastSeenAt, seenAt));
            if (updated > 0) return;
            db.Set<TelemetrySessionDimension>().Add(new TelemetrySessionDimension
            {
                Id = Ids.New("tsd"), OrganizationId = organizationId, SessionId = sessionId, Source = source, DimensionType = d.Type,
                DimensionValue = d.Value ?? TelemetryRules.DeriveDimensionValue(d.Type, d.Label), DimensionLabel = d.Label, MetadataJson = d.MetadataJson,
                CreatedAt = seenAt, UpdatedAt = seenAt, LastSeenAt = seenAt,
            });
            try { await db.SaveChangesAsync(); return; }
            catch (DbUpdateException) when (attempt == 0) { db.ChangeTracker.Clear(); }   // a batch from the same session got there first: update its row instead
        }
    }

    private async Task<List<TelemetryRow>> WindowAsync(string organizationId, long since, DimensionFilter? filter)
    {
        var rows = await db.Set<TelemetryEvent>().AsNoTracking().Where(e => e.OrganizationId == organizationId && e.EventTimestamp >= since)
            .Select(e => new TelemetryRow(e.EventType, e.EventTimestamp, e.MemberId, e.SessionId, e.Source, e.DurationMs)).ToListAsync();
        if (filter is null) return rows;
        var matching = (await db.Set<TelemetrySessionDimension>().AsNoTracking().Where(d => d.OrganizationId == organizationId && d.DimensionType == filter.Type && d.DimensionValue == filter.Value)
            .Select(d => new { d.SessionId, d.Source }).ToListAsync()).Select(d => (d.SessionId, d.Source)).ToHashSet();
        return rows.Where(r => r.SessionId is not null && matching.Contains((r.SessionId, r.Source ?? "unknown"))).ToList();
    }

    public async Task<int> MemberCountAsync(string organizationId) => await db.Members.CountAsync(m => m.OrganizationId == organizationId);

    public async Task<int> PendingInviteCountAsync(string organizationId) => await db.Invitations.CountAsync(i => i.OrganizationId == organizationId && i.Status == InvitationStatus.Pending);

    public async Task<object> AdoptionAsync(string organizationId, long now)
    {
        var trendStart = now - TelemetryRules.TrendWeeks * TelemetryRules.WeekMs;
        var events = await WindowAsync(organizationId, trendStart, null);
        var weekly = Enumerable.Range(0, TelemetryRules.TrendWeeks)
            .Select(i => events.Where(e => TelemetryRules.Bucket(e.Timestamp, trendStart, TelemetryRules.WeekMs, TelemetryRules.TrendWeeks) == i).Select(e => e.MemberId).Distinct().Count()).ToList();
        return new
        {
            members = await MemberCountAsync(organizationId), pendingInvites = await PendingInviteCountAsync(organizationId),
            activeMembers7d = TelemetryRules.Metrics(events.Where(e => e.Timestamp >= now - 7 * TelemetryRules.DayMs).ToList()).ActiveMembers,
            activeMembers30d = TelemetryRules.Metrics(events.Where(e => e.Timestamp >= now - 30 * TelemetryRules.DayMs).ToList()).ActiveMembers,
            weeklyTrend = weekly,
        };
    }

    public async Task<object> AnalyticsAsync(string organizationId, long now, DimensionFilter? filter, bool daily)
    {
        var trendStart = now - TelemetryRules.TrendWeeks * TelemetryRules.WeekMs;
        var dayStart = TelemetryRules.DailyTrendStart(now);
        var events = await WindowAsync(organizationId, Math.Min(trendStart, daily ? dayStart : trendStart), filter);
        var w7 = TelemetryRules.Metrics(events.Where(e => e.Timestamp >= now - 7 * TelemetryRules.DayMs).ToList());
        var w30Events = events.Where(e => e.Timestamp >= now - 30 * TelemetryRules.DayMs).ToList();
        var w30 = TelemetryRules.Metrics(w30Events);

        var weeks = Enumerable.Range(0, TelemetryRules.TrendWeeks).Select(i =>
        {
            var inWeek = events.Where(e => e.Timestamp >= trendStart && TelemetryRules.Bucket(e.Timestamp, trendStart, TelemetryRules.WeekMs, TelemetryRules.TrendWeeks) == i).ToList();
            var m = TelemetryRules.Metrics(inWeek);
            return new { weekStart = DateTimeOffset.FromUnixTimeMilliseconds(trendStart + i * TelemetryRules.WeekMs).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), activeMembers = m.ActiveMembers, sessions = m.Sessions, tasksCompleted = m.TasksCompleted, tasksFailed = m.TasksFailed };
        }).ToList();

        var days = daily ? Enumerable.Range(0, TelemetryRules.TrendDays).Select(i =>
        {
            var inDay = events.Where(e => e.Timestamp >= dayStart && TelemetryRules.Bucket(e.Timestamp, dayStart, TelemetryRules.DayMs, TelemetryRules.TrendDays) == i).ToList();
            var m = TelemetryRules.Metrics(inDay);
            return new { day = DateTimeOffset.FromUnixTimeMilliseconds(dayStart + i * TelemetryRules.DayMs).ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), activeMembers = m.ActiveMembers, sessions = m.Sessions, tasksCompleted = m.TasksCompleted, tasksFailed = m.TasksFailed };
        }).ToList() : null;

        var windowSessions = w30Events.Where(e => e.SessionId is not null).Select(e => (SessionId: e.SessionId!, Source: e.Source ?? "unknown")).Distinct().ToList();
        var dimensionRows = windowSessions.Count == 0 ? [] : await db.Set<TelemetrySessionDimension>().AsNoTracking()
            .Where(d => d.OrganizationId == organizationId && (d.DimensionType == "model" || d.DimensionType == "model_selection")).ToListAsync();
        var sessionSet = windowSessions.ToHashSet();
        var joined = dimensionRows.Where(d => sessionSet.Contains((d.SessionId, d.Source))).ToList();
        var usage = joined.Where(d => d.DimensionType == "model").GroupBy(d => d.DimensionValue)
            .Select(g => new { id = g.Key, label = g.Select(d => d.DimensionLabel).OrderByDescending(x => x, StringComparer.OrdinalIgnoreCase).First(), sessions = g.Select(d => d.SessionId).Distinct().Count() })
            .OrderByDescending(x => x.sessions).ThenBy(x => x.id, StringComparer.Ordinal).ToList();
        int Selection(string value) => joined.Where(d => d.DimensionType == "model_selection" && d.DimensionValue == value).Select(d => d.SessionId).Distinct().Count();

        var result = new Dictionary<string, object?>
        {
            ["members"] = await MemberCountAsync(organizationId), ["pendingInvites"] = await PendingInviteCountAsync(organizationId),
            ["activeMembers7d"] = w7.ActiveMembers, ["activeMembers30d"] = w30.ActiveMembers, ["sessions7d"] = w7.Sessions, ["sessions30d"] = w30.Sessions,
            ["tasksCompleted7d"] = w7.TasksCompleted, ["tasksFailed7d"] = w7.TasksFailed, ["tasksCompleted30d"] = w30.TasksCompleted, ["tasksFailed30d"] = w30.TasksFailed,
            ["avgTaskDurationMs30d"] = w30.AvgTaskDurationMs, ["weekly"] = weeks,
        };
        if (days is not null) result["daily"] = days;
        result["models"] = new { usage30d = usage, selection30d = new { @default = Selection("default"), manual = Selection("manual") } };
        return result;
    }

    public async Task<object> DimensionsAsync(string organizationId, string type)
    {
        var rows = await db.Set<TelemetrySessionDimension>().AsNoTracking().Where(d => d.OrganizationId == organizationId && d.DimensionType == type).ToListAsync();
        var items = rows.GroupBy(d => d.DimensionValue).Select(g => new
        {
            type, value = g.Key, label = g.Select(d => d.DimensionLabel).OrderByDescending(x => x, StringComparer.OrdinalIgnoreCase).First(), sessionCount = g.Select(d => d.SessionId).Distinct().Count(),
            lastSeenAt = Responses.IsoUtc(DateTimeOffset.FromUnixTimeMilliseconds(g.Max(d => d.LastSeenAt)).UtcDateTime),
        }).OrderByDescending(x => x.lastSeenAt, StringComparer.Ordinal).ThenBy(x => x.value, StringComparer.Ordinal).ToList();
        return new { items };
    }
}

public static class TelemetryEndpoints
{
    private static readonly Regex DimensionType = new("^[a-z][a-z0-9_.-]{0,63}$", RegexOptions.Compiled);
    private static readonly Regex DimensionValue = new("^[a-zA-Z0-9][a-zA-Z0-9_.:/-]{0,127}$", RegexOptions.Compiled);
    private static readonly Regex IsoZ = new(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$", RegexOptions.Compiled);

    private static string P(params object[] path) => string.Join('.', path);

    private static string TypeOf(string value, string path)
    {
        var type = value.Trim();
        if (type.Length < 1) throw new Invalid(path, "Too small: expected string to have >=1 characters", "too_small");
        if (type.Length > 64) throw new Invalid(path, "Too big: expected string to have <=64 characters", "too_big");
        type = type.ToLowerInvariant();
        if (!DimensionType.IsMatch(type)) throw new Invalid(path, "Dimension type must start with a lowercase letter and contain only lowercase letters, numbers, dots, underscores, or hyphens.", "custom");
        return type;
    }

    private static string ValueOf(string value, string path)
    {
        var v = value.Trim();
        if (v.Length < 1) throw new Invalid(path, "Too small: expected string to have >=1 characters", "too_small");
        if (v.Length > 128) throw new Invalid(path, "Too big: expected string to have <=128 characters", "too_big");
        if (!DimensionValue.IsMatch(v)) throw new Invalid(path, "Dimension value must contain only letters, numbers, dots, underscores, colons, slashes, or hyphens.", "custom");
        return v;
    }

    private static string StringAt(JsonElement e, string name, string path, bool required, int min, int max, bool trim, out bool present)
    {
        present = false;
        if (!e.TryGetProperty(name, out var v))
        {
            if (required) throw new Invalid(path, "Invalid input: expected string, received undefined");
            return "";
        }
        if (v.ValueKind != JsonValueKind.String) throw new Invalid(path, $"Invalid input: expected string, received {Reader.Kind(v)}");
        var s = trim ? v.GetString()!.Trim() : v.GetString()!;
        if (s.Length < min) throw new Invalid(path, $"Too small: expected string to have >={min} characters", "too_small");
        if (s.Length > max) throw new Invalid(path, $"Too big: expected string to have <={max} characters", "too_big");
        present = true;
        return s;
    }

    public static List<IngestEvent> ParseBatch(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object) throw new Invalid("", $"Invalid input: expected object, received {Reader.Kind(root)}");
        if (!root.TryGetProperty("events", out var events)) throw new Invalid("events", "Invalid input: expected array, received undefined");
        if (events.ValueKind != JsonValueKind.Array) throw new Invalid("events", $"Invalid input: expected array, received {Reader.Kind(events)}");
        if (events.GetArrayLength() < 1) throw new Invalid("events", "Too small: expected array to have >=1 items", "too_small");
        if (events.GetArrayLength() > 50) throw new Invalid("events", "Too big: expected array to have <=50 items", "too_big");
        var result = new List<IngestEvent>();
        var index = 0;
        foreach (var e in events.EnumerateArray())
        {
            var prefix = P("events", index++);
            if (e.ValueKind != JsonValueKind.Object) throw new Invalid(prefix, $"Invalid input: expected object, received {Reader.Kind(e)}");
            var type = StringAt(e, "type", P(prefix, "type"), true, 1, 64, trim: false, out _);
            var stamp = StringAt(e, "timestamp", P(prefix, "timestamp"), true, 0, int.MaxValue, trim: false, out _);
            if (!IsoZ.IsMatch(stamp) || !DateTimeOffset.TryParse(stamp, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var when))
                throw new Invalid(P(prefix, "timestamp"), "Invalid ISO datetime", "invalid_format");
            var source = StringAt(e, "source", P(prefix, "source"), false, 0, 32, trim: false, out var hasSource);
            var session = StringAt(e, "sessionId", P(prefix, "sessionId"), false, 0, 128, trim: false, out var hasSession);
            int? duration = null;
            if (e.TryGetProperty("durationMs", out var d))
            {
                if (d.ValueKind != JsonValueKind.Number) throw new Invalid(P(prefix, "durationMs"), $"Invalid input: expected number, received {Reader.Kind(d)}");
                if (!d.TryGetInt64(out var n)) throw new Invalid(P(prefix, "durationMs"), "Invalid input: expected int, received number");
                if (n < 0) throw new Invalid(P(prefix, "durationMs"), "Too small: expected number to be >=0", "too_small");
                if (n > 86_400_000) throw new Invalid(P(prefix, "durationMs"), "Too big: expected number to be <=86400000", "too_big");
                duration = (int)n;
            }
            bool? success = null;
            if (e.TryGetProperty("success", out var s))
            {
                if (s.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) throw new Invalid(P(prefix, "success"), $"Invalid input: expected boolean, received {Reader.Kind(s)}");
                success = s.GetBoolean();
            }
            var dimensions = new List<DimensionInput>();
            if (e.TryGetProperty("dimensions", out var dims))
            {
                if (dims.ValueKind != JsonValueKind.Array) throw new Invalid(P(prefix, "dimensions"), $"Invalid input: expected array, received {Reader.Kind(dims)}");
                if (dims.GetArrayLength() > 8) throw new Invalid(P(prefix, "dimensions"), "Too big: expected array to have <=8 items", "too_big");
                var di = 0;
                foreach (var dim in dims.EnumerateArray())
                {
                    var dp = P(prefix, "dimensions", di++);
                    if (dim.ValueKind != JsonValueKind.Object) throw new Invalid(dp, $"Invalid input: expected object, received {Reader.Kind(dim)}");
                    var dimType = TypeOf(StringAt(dim, "type", P(dp, "type"), true, 0, int.MaxValue, trim: false, out _), P(dp, "type"));
                    string? value = null;
                    if (dim.TryGetProperty("value", out _)) value = ValueOf(StringAt(dim, "value", P(dp, "value"), true, 0, int.MaxValue, trim: false, out _), P(dp, "value"));
                    var label = StringAt(dim, "label", P(dp, "label"), true, 1, 255, trim: true, out _);
                    string? metadata = null;
                    if (dim.TryGetProperty("metadata", out var m))
                    {
                        if (m.ValueKind != JsonValueKind.Object) throw new Invalid(P(dp, "metadata"), $"Invalid input: expected record, received {Reader.Kind(m)}");
                        metadata = m.GetRawText();
                        if (Encoding.UTF8.GetByteCount(metadata) > 4096) throw new Invalid(P(dp, "metadata"), "Dimension metadata is too large.", "custom");
                    }
                    dimensions.Add(new DimensionInput(dimType, value, label, metadata));
                }
            }
            result.Add(new IngestEvent(type, when.ToUnixTimeMilliseconds(), hasSource ? source : null, hasSession ? session : null, duration, success, dimensions));
        }
        return result;
    }

    public static void Map(WebApplication app)
    {
        app.MapPost("/v1/telemetry/ingest", async (HttpContext ctx, OrgAccess access, TelemetryService service) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            List<IngestEvent> batch;
            try { batch = ParseBatch(await LibraryZod.BodyAsync(ctx)); }
            catch (Invalid invalid) { return invalid.ToResult(); }
            // Telemetry must never break the app: a failure to store the batch drops it.
            try { await service.IngestAsync(context!.Organization.Id, context.Member.Id, batch); }
            catch (Exception e) when (e is DbUpdateException or InvalidOperationException) { }
            return Results.NoContent();
        });

        app.MapGet("/v1/telemetry/dimensions", async (HttpContext ctx, OrgAccess access, TelemetryService service) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "usage_analytics.view") is { } denied) return denied;
            try
            {
                var raw = ctx.Request.Query.ContainsKey("type") ? ctx.Request.Query["type"].ToString() : null;
                if (raw is null) throw new Invalid("type", "Invalid input: expected string, received undefined");
                return Results.Json(await service.DimensionsAsync(context!.Organization.Id, TypeOf(raw, "type")));
            }
            catch (Invalid invalid) { return invalid.ToResult(); }
        });

        app.MapGet("/v1/telemetry/adoption", async (HttpContext ctx, OrgAccess access, TelemetryService service) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "usage_analytics.view") is { } denied) return denied;
            return Results.Json(await service.AdoptionAsync(context!.Organization.Id, AutomationService.Now()));
        });

        app.MapGet("/v1/telemetry/analytics", async (HttpContext ctx, OrgAccess access, TelemetryService service, IConfiguration configuration) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "usage_analytics.view") is { } denied) return denied;
            DimensionFilter? filter = null;
            try
            {
                var type = ctx.Request.Query.ContainsKey("dimensionType") ? TypeOf(ctx.Request.Query["dimensionType"].ToString(), "dimensionType") : null;
                var value = ctx.Request.Query.ContainsKey("dimensionValue") ? ValueOf(ctx.Request.Query["dimensionValue"].ToString(), "dimensionValue") : null;
                if ((type is null) != (value is null)) throw new Invalid([([], "custom", "dimensionType and dimensionValue must be supplied together.")]);
                if (type is not null) filter = new DimensionFilter(type, value!);
            }
            catch (Invalid invalid) { return invalid.ToResult(); }
            return Results.Json(await service.AnalyticsAsync(context!.Organization.Id, AutomationService.Now(), filter, FeatureState.Resolve(configuration, "analyticsDailyTrends")));
        });
    }
}
