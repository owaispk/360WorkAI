using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Automations;
using WorkAI360.Api.Domain.PlatformAdmin;

namespace WorkAI360.Api.Features.PlatformAdmin;

/// <summary>Records that a member used features, once per member, feature and UTC day (the reference's <c>feature_usage</c>). Best effort: callers never fail on it.</summary>
public sealed class FeatureUsageStore(DenDbContext db)
{
    public static string Day(DateTime at) => at.ToString("yyyy-MM-dd");

    public async Task RecordAsync(string organizationId, string memberId, IEnumerable<string> keys)
    {
        var now = DateTime.UtcNow;
        var day = Day(now);
        foreach (var key in keys.Distinct())
        {
            try
            {
                var updated = await db.Set<FeatureUsageDay>().Where(u => u.MemberId == memberId && u.FeatureKey == key && u.Day == day)
                    .ExecuteUpdateAsync(s => s.SetProperty(u => u.LastUsedAt, now));
                if (updated > 0) continue;
                db.Set<FeatureUsageDay>().Add(new FeatureUsageDay { MemberId = memberId, FeatureKey = key, Day = day, OrganizationId = organizationId, FirstUsedAt = now, LastUsedAt = now });
                await db.SaveChangesAsync();
            }
            catch (DbUpdateException)
            {
                // A parallel report for the same day created the row first: that is all it needed.
                db.ChangeTracker.Clear();
            }
        }
    }
}

/// <summary>How a feature is doing, in one plain state: the reference's rules (failures outrank limits, limits outrank skips).</summary>
public sealed record FeatureOutcomeTotals(int Runs, int Succeeded, int Failed, int Skipped, int? Delivered, int? Limited, DateTime? LastRunAt)
{
    public static FeatureOutcomeTotals Empty { get; } = new(0, 0, 0, 0, null, null, null);
}

public static class FeatureHealth
{
    public static (string Status, int? Count) Of(int membersUsing, FeatureOutcomeTotals? outcomes)
    {
        if (outcomes is null) return membersUsing > 0 ? ("in_use", null) : ("not_used", null);
        if (outcomes.Runs == 0 && outcomes.Limited is not > 0) return membersUsing > 0 ? ("in_use", null) : ("not_used", null);
        var ran = outcomes.Succeeded + outcomes.Failed;
        if (outcomes.Failed > 0 && outcomes.Failed >= ran * 0.2) return ("failing", outcomes.Failed);
        if (outcomes.Limited is > 0) return ("limited", outcomes.Limited);
        if (outcomes.Skipped * 2 > ran + outcomes.Skipped) return ("mostly_skipped", null);
        return ("healthy", null);
    }
}

/// <summary>
/// /admin Features by feature and by workspace: who has a feature on, who uses it, what it did and how it is doing (the reference's
/// <c>/v1/admin/feature-usage</c>, <c>/v1/admin/feature-usage/{key}</c> and <c>/v1/admin/organizations/{id}/feature-usage</c>). Usage is what clients reported to
/// <c>POST /v1/org/feature-usage</c>; outcomes are read from this database's Automation runs. Counts only.
/// </summary>
public static class AdminFeatureUsageEndpoints
{
    private const int OrganizationRowsMax = 200;
    private static readonly Dictionary<string, (string Kind, string Unit)> OutcomeFeatures = new()
    {
        ["automationIntervalSchedules"] = ("interval", "run"),
        ["automationCalendarTriggers"] = ("calendar", "meeting"),
    };

    private sealed record Range(string Name, DateTime From, DateTime To, string[] Days);

    private static (Range? Range, IResult? Failure) ReadRange(HttpContext ctx)
    {
        var name = ctx.Request.Query.ContainsKey("range") ? ctx.Request.Query["range"].ToString() : "7d";
        if (name is not ("7d" or "30d"))
            return (null, Results.Json(new { error = "invalid_request", details = new[] { new { message = "Invalid option: expected one of \"7d\"|\"30d\"", path = new[] { "range" } } } }, statusCode: 400));
        var days = name == "7d" ? 7 : 30;
        var now = DateTime.UtcNow;
        var first = now.Date.AddDays(-(days - 1));
        return (new Range(name, first, now, [.. Enumerable.Range(0, days).Select(i => FeatureUsageStore.Day(first.AddDays(i)))]), null);
    }

    private static string? Iso(DateTime? value) => value is { } v ? Responses.IsoUtc(v) : null;

    private sealed record UsageRow(string FeatureKey, string OrganizationId, int Members, DateTime LastUsedAt);

    private static async Task<List<UsageRow>> UsageSinceAsync(DenDbContext db, DateTime from, string? featureKey)
    {
        var sinceDay = FeatureUsageStore.Day(from);
        var query = db.Set<FeatureUsageDay>().AsNoTracking().Where(u => string.Compare(u.Day, sinceDay) >= 0);
        if (featureKey is not null) query = query.Where(u => u.FeatureKey == featureKey);
        var rows = await (from u in query join m in db.Members on u.MemberId equals m.Id select new { u.FeatureKey, u.OrganizationId, u.MemberId, u.LastUsedAt }).ToListAsync();
        return [.. rows.GroupBy(r => (r.FeatureKey, r.OrganizationId)).Select(g => new UsageRow(g.Key.FeatureKey, g.Key.OrganizationId, g.Select(r => r.MemberId).Distinct().Count(), g.Max(r => r.LastUsedAt)))];
    }

    private static (int MembersUsing, DateTime? LastUsedAt) Adoption(IEnumerable<UsageRow> rows)
    {
        var list = rows.ToList();
        return (list.Sum(r => r.Members), list.Count == 0 ? null : list.Max(r => r.LastUsedAt));
    }

    /// <summary>Runs of Automations whose schedule is of this kind, by workspace, day, outcome and reason.</summary>
    private static async Task<(Dictionary<string, FeatureOutcomeTotals> ByOrganization, FeatureOutcomeTotals Total, List<(string Reason, string Outcome, int Count)> Reasons, List<(string Day, int Runs, int Failed)> Days)> OutcomesAsync(DenDbContext db, string kind, Range range)
    {
        var fromMs = new DateTimeOffset(DateTime.SpecifyKind(range.From, DateTimeKind.Utc)).ToUnixTimeMilliseconds();
        var toMs = new DateTimeOffset(DateTime.SpecifyKind(range.To, DateTimeKind.Utc)).ToUnixTimeMilliseconds();
        var rows = await (from r in db.Set<AutomationRun>().AsNoTracking()
                          join rev in db.Set<AutomationRevision>() on r.RevisionId equals rev.Id
                          join a in db.Set<Automation>() on r.AutomationId equals a.Id
                          where rev.ScheduleKind == kind && r.CreatedAt >= fromMs && r.CreatedAt < toMs
                          select new { a.OrganizationId, r.Status, r.ErrorJson, r.CreatedAt }).ToListAsync();
        static string Outcome(string status) => status switch { "succeeded" => "succeeded", "failed" => "failed", "cancelled" or "skipped" => "skipped", _ => "running" };
        static string? Code(string? json)
        {
            if (json is null) return null;
            try { using var d = JsonDocument.Parse(json); return d.RootElement.TryGetProperty("code", out var c) && c.ValueKind == JsonValueKind.String ? c.GetString() : null; }
            catch (JsonException) { return null; }
        }
        FeatureOutcomeTotals Totals(IEnumerable<(string Outcome, long At)> items)
        {
            var list = items.ToList();
            return new(list.Count, list.Count(i => i.Outcome == "succeeded"), list.Count(i => i.Outcome == "failed"), list.Count(i => i.Outcome == "skipped"), null, null,
                list.Count == 0 ? null : DateTimeOffset.FromUnixTimeMilliseconds(list.Max(i => i.At)).UtcDateTime);
        }
        var typed = rows.Select(r => (r.OrganizationId, Outcome: Outcome(r.Status), r.CreatedAt, Reason: r.Status == "cancelled" ? "cancelled" : r.Status == "failed" ? Code(r.ErrorJson) ?? "unknown" : r.Status == "skipped" ? Code(r.ErrorJson) ?? "previous_run_active" : null)).ToList();
        var byOrg = typed.GroupBy(r => r.OrganizationId).ToDictionary(g => g.Key, g => Totals(g.Select(r => (r.Outcome, r.CreatedAt))));
        var reasons = typed.Where(r => r.Reason is not null).GroupBy(r => (r.Reason!, r.Outcome)).Select(g => (g.Key.Item1, g.Key.Outcome, g.Count()))
            .OrderByDescending(r => r.Item3).ThenBy(r => r.Item1, StringComparer.Ordinal).ToList();
        var days = range.Days.Select(d => (d, typed.Count(r => FeatureUsageStore.Day(DateTimeOffset.FromUnixTimeMilliseconds(r.CreatedAt).UtcDateTime) == d), typed.Count(r => r.Outcome == "failed" && FeatureUsageStore.Day(DateTimeOffset.FromUnixTimeMilliseconds(r.CreatedAt).UtcDateTime) == d))).ToList();
        return (byOrg, Totals(typed.Select(r => (r.Outcome, r.CreatedAt))), reasons, days);
    }

    private static object TotalsJson(FeatureOutcomeTotals t) => new { runs = t.Runs, succeeded = t.Succeeded, failed = t.Failed, skipped = t.Skipped, delivered = t.Delivered, limited = t.Limited, lastRunAt = Iso(t.LastRunAt) };

    private static object OutcomesJson(string unit, FeatureOutcomeTotals t, List<(string Day, int Runs, int Failed)> days) => new
    {
        runs = t.Runs, succeeded = t.Succeeded, failed = t.Failed, skipped = t.Skipped, delivered = t.Delivered, limited = t.Limited, lastRunAt = Iso(t.LastRunAt),
        unit, days = days.Select(d => new { day = d.Day, runs = d.Runs, failed = d.Failed }), coverage = (object?)null,
    };

    /// <summary>The workspaces a feature is on for, without reading each one (the reference's <c>organizationsWithFeatureOn</c>).</summary>
    private static int OrganizationsOn(FeatureResolver resolver, FeatureInfo feature, IReadOnlyDictionary<string, FeatureResolver.Rollout> rollouts, int organizations, int overridesOn, int overridesOff)
    {
        var baseline = resolver.Resolve(feature, rollouts, new Dictionary<string, bool>());
        if (!baseline.OverrideApplies) return baseline.Enabled ? organizations : 0;
        return baseline.Enabled ? Math.Max(0, organizations - overridesOff) : overridesOn;
    }

    public static void MapAdminFeatureUsageEndpoints(this WebApplication app)
    {
        app.MapGet("/v1/admin/feature-usage", async (HttpContext ctx, PlatformAdminGuard guard, DenDbContext db, FeatureResolver resolver) =>
        {
            var (_, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            var (range, bad) = ReadRange(ctx);
            if (bad is not null) return bad;
            var organizations = await db.Organizations.CountAsync();
            var rollouts = await resolver.RolloutsAsync();
            var counts = (await db.Set<PlatformOrganizationFeature>().AsNoTracking().GroupBy(o => new { o.FeatureKey, o.Enabled }).Select(g => new { g.Key.FeatureKey, g.Key.Enabled, N = g.Count() }).ToListAsync())
                .ToLookup(c => c.FeatureKey);
            var usage = await UsageSinceAsync(db, range!.From, null);
            var features = new List<object>();
            foreach (var feature in FeatureCatalog.All.Where(f => f.Available))
            {
                var adoption = Adoption(usage.Where(u => u.FeatureKey == feature.Key));
                var on = counts[feature.Key].Where(c => c.Enabled).Sum(c => c.N);
                var off = counts[feature.Key].Where(c => !c.Enabled).Sum(c => c.N);
                object? outcomes = null;
                FeatureOutcomeTotals? totals = null;
                if (OutcomeFeatures.TryGetValue(feature.Key, out var reader))
                {
                    var read = await OutcomesAsync(db, reader.Kind, range);
                    totals = read.Total;
                    outcomes = OutcomesJson(reader.Unit, read.Total, read.Days);
                }
                var (status, count) = FeatureHealth.Of(adoption.MembersUsing, totals);
                features.Add(new
                {
                    key = feature.Key, organizationsOn = OrganizationsOn(resolver, feature, rollouts, organizations, on, off), membersUsing = adoption.MembersUsing, lastUsedAt = Iso(adoption.LastUsedAt),
                    health = new { status, count }, outcomes,
                });
            }
            return Results.Json(new { range = range.Name, from = Responses.IsoUtc(range.From), to = Responses.IsoUtc(range.To), organizations, features, generatedAt = Responses.IsoUtc(DateTime.UtcNow) });
        });

        app.MapGet("/v1/admin/feature-usage/{key}", async (string key, HttpContext ctx, PlatformAdminGuard guard, DenDbContext db, FeatureResolver resolver) =>
        {
            var (_, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            var (range, bad) = ReadRange(ctx);
            if (bad is not null) return bad;
            if (FeatureCatalog.Find(key) is not { } feature) return AdminSupport.Invalid("Unknown feature.");
            if (!feature.Available) return AdminSupport.NotFound("The feature is not part of this deployment.");
            var organizations = await db.Organizations.CountAsync();
            var rollouts = await resolver.RolloutsAsync();
            var overrides = await db.Set<PlatformOrganizationFeature>().AsNoTracking().Where(o => o.FeatureKey == key).ToDictionaryAsync(o => o.OrganizationId, o => o.Enabled);
            var usage = await UsageSinceAsync(db, range!.From, key);
            var adoption = Adoption(usage);
            FeatureOutcomeTotals? totals = null;
            Dictionary<string, FeatureOutcomeTotals>? byOrg = null;
            object? outcomes = null;
            var reasons = new List<(string Reason, string Outcome, int Count)>();
            if (OutcomeFeatures.TryGetValue(key, out var reader))
            {
                var read = await OutcomesAsync(db, reader.Kind, range);
                totals = read.Total; byOrg = read.ByOrganization; reasons = read.Reasons;
                outcomes = OutcomesJson(reader.Unit, read.Total, read.Days);
            }
            var ids = usage.Select(u => u.OrganizationId).Concat(byOrg is null ? [] : byOrg.Keys).Concat(overrides.Keys).Distinct().ToList();
            var names = await db.Organizations.AsNoTracking().Where(o => ids.Contains(o.Id)).ToDictionaryAsync(o => o.Id, o => o.Name);
            var rows = ids.Where(names.ContainsKey).Select(id =>
            {
                var used = Adoption(usage.Where(u => u.OrganizationId == id));
                var enabled = resolver.Resolve(feature, rollouts, overrides.TryGetValue(id, out var o) ? new Dictionary<string, bool> { [key] = o } : new Dictionary<string, bool>()).Enabled;
                var orgTotals = byOrg is null ? null : byOrg.GetValueOrDefault(id) ?? FeatureOutcomeTotals.Empty;
                return (Id: id, Name: names[id], Enabled: enabled, used.MembersUsing, used.LastUsedAt, Totals: orgTotals);
            })
                .OrderByDescending(r => r.Totals?.Runs ?? 0).ThenByDescending(r => r.MembersUsing).ThenBy(r => r.Name, StringComparer.CurrentCultureIgnoreCase).Take(OrganizationRowsMax).ToList();
            var (status, count) = FeatureHealth.Of(adoption.MembersUsing, totals);
            return Results.Json(new
            {
                range = range.Name, from = Responses.IsoUtc(range.From), to = Responses.IsoUtc(range.To), organizations,
                feature = new
                {
                    key, organizationsOn = OrganizationsOn(resolver, feature, rollouts, organizations, overrides.Count(o => o.Value), overrides.Count(o => !o.Value)),
                    membersUsing = adoption.MembersUsing, lastUsedAt = Iso(adoption.LastUsedAt), health = new { status, count }, outcomes,
                    reasons = reasons.Select(r => new { reason = r.Reason, outcome = r.Outcome, count = r.Count }),
                    byOrganization = rows.Select(r => new { organizationId = r.Id, name = r.Name, enabled = r.Enabled, membersUsing = r.MembersUsing, lastUsedAt = Iso(r.LastUsedAt), outcomes = r.Totals is null ? null : TotalsJson(r.Totals) }),
                },
                generatedAt = Responses.IsoUtc(DateTime.UtcNow),
            });
        });

        app.MapGet("/v1/admin/organizations/{organizationId}/feature-usage", async (string organizationId, HttpContext ctx, PlatformAdminGuard guard, DenDbContext db, FeatureResolver resolver) =>
        {
            var (_, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            if (!AdminSupport.IsTypeId("org", organizationId)) return AdminSupport.Invalid("Invalid organization id.");
            if (!await db.Organizations.AnyAsync(o => o.Id == organizationId)) return AdminSupport.NotFound("Organization not found.");

            var members = await (from m in db.Members.AsNoTracking() where m.OrganizationId == organizationId join u in db.Users on m.UserId equals u.Id select new { m.Id, u.Name, u.Email }).ToListAsync();
            var rollouts = await resolver.RolloutsAsync();
            var overrides = await resolver.OverridesAsync(organizationId);
            var usage = await db.Set<FeatureUsageDay>().AsNoTracking().Where(u => u.OrganizationId == organizationId).ToListAsync();
            var people = members.ToDictionary(m => m.Id);
            var now = DateTime.UtcNow;
            // The feature is on for everyone in a workspace alike (there are no per-member overrides in this build).
            var features = FeatureCatalog.All.Where(f => f.Available).Select(feature =>
            {
                var enabled = resolver.Resolve(feature, rollouts, overrides).Enabled;
                var used = usage.Where(u => u.FeatureKey == feature.Key && people.ContainsKey(u.MemberId)).GroupBy(u => u.MemberId)
                    .Select(g => new { MemberId = g.Key, First = g.Min(u => u.FirstUsedAt), Last = g.Max(u => u.LastUsedAt), Days = g.Count() }).OrderByDescending(u => u.Last).ToList();
                int Within(int days) => used.Count(u => now - u.Last <= TimeSpan.FromDays(days));
                return new
                {
                    key = feature.Key, enabledMembers = enabled ? members.Count : 0, usedLast7Days = Within(7), usedLast30Days = Within(30),
                    members = used.Select(u => new { memberId = u.MemberId, name = (string?)people[u.MemberId].Name, email = (string?)people[u.MemberId].Email, enabled, firstUsedAt = Responses.IsoUtc(u.First), lastUsedAt = Responses.IsoUtc(u.Last), daysUsed = u.Days }),
                };
            });
            return Results.Json(new { activeMembers = members.Count, features, generatedAt = Responses.IsoUtc(now) });
        });
    }
}
