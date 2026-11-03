using System.Globalization;
using System.Text;
using System.Threading.Channels;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.PlatformAdmin;

namespace WorkAI360.Api.Features.PlatformAdmin;

public sealed class RequestLogOptions
{
    public const string Section = "PlatformAdmin:RequestLog";
    public bool Enabled { get; set; } = true;
    /// <summary>How long refused and failed requests are kept (at least 1 day; the report reads the last 24 hours).</summary>
    public int RetentionDays { get; set; } = 7;
    /// <summary>Events held in memory between writes; more are dropped (and counted) rather than letting a flood grow memory.</summary>
    public int QueueCapacity { get; set; } = 10_000;
}

/// <summary>
/// The log behind <c>GET /v1/admin/security/requests</c> (the reference's platform audit events with an outcome other than succeeded). Middleware notes
/// every 401 and 429 response, and any 4xx/5xx from the sign-in, token and app-registration routes, as (time, route name, outcome, status) only: no
/// address, person, credential, query string or path value is kept. Events are queued in memory (bounded) and written in batches by a background
/// loop that also deletes events past their retention.
/// </summary>
public sealed class RequestLog(IServiceScopeFactory scopes, IOptions<RequestLogOptions> options, ILogger<RequestLog> logger) : BackgroundService
{
    private readonly Channel<PlatformRequestEvent> _queue = Channel.CreateBounded<PlatformRequestEvent>(
        new BoundedChannelOptions(Math.Max(100, options.Value.QueueCapacity)) { FullMode = BoundedChannelFullMode.DropWrite, SingleReader = true });
    private readonly SemaphoreSlim _flushLock = new(1, 1);
    private DateTime _lastCleanup = DateTime.MinValue;
    private long _dropped;

    public long Dropped => Interlocked.Read(ref _dropped);

    public void Record(string action, int status, DateTime at)
    {
        if (!options.Value.Enabled) return;
        var item = new PlatformRequestEvent { Id = Ids.New("pre"), OccurredAt = at, Action = action, Outcome = status is 401 or 403 or 429 ? "denied" : "failed", Status = status };
        if (!_queue.Writer.TryWrite(item)) Interlocked.Increment(ref _dropped);
    }

    /// <summary>Writes everything queued so far (the background loop calls this every couple of seconds; tests call it directly).</summary>
    public async Task FlushAsync(CancellationToken ct = default)
    {
        await _flushLock.WaitAsync(ct);
        try
        {
            var batch = new List<PlatformRequestEvent>();
            while (batch.Count < 1000 && _queue.Reader.TryRead(out var item)) batch.Add(item);
            if (batch.Count == 0 && DateTime.UtcNow - _lastCleanup < TimeSpan.FromHours(1)) return;
            await using var scope = scopes.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<DenDbContext>();
            if (batch.Count > 0)
            {
                db.Set<PlatformRequestEvent>().AddRange(batch);
                await db.SaveChangesAsync(ct);
            }
            if (DateTime.UtcNow - _lastCleanup >= TimeSpan.FromHours(1))
            {
                var cutoff = DateTime.UtcNow.AddDays(-Math.Max(1, options.Value.RetentionDays));
                await db.Set<PlatformRequestEvent>().Where(e => e.OccurredAt < cutoff).ExecuteDeleteAsync(ct);
                _lastCleanup = DateTime.UtcNow;
            }
        }
        finally { _flushLock.Release(); }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try { await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken); }
            catch (OperationCanceledException) { break; }
            try { await FlushAsync(stoppingToken); }
            catch (OperationCanceledException) { break; }
            catch (Exception e) { logger.LogWarning(e, "Writing the request log failed; the batch is dropped."); }
        }
    }

    /// <summary>Routes whose callers have no trusted workspace yet: their refusals and failures are worth watching (the reference's scope).</summary>
    public static bool IsUntrustedRoute(string path) =>
        path.StartsWith("/api/auth/", StringComparison.OrdinalIgnoreCase) || path.StartsWith("/v1/auth/", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("/oauth2/", StringComparison.OrdinalIgnoreCase) || path.Equals("/register", StringComparison.OrdinalIgnoreCase)
        || path.StartsWith("/token", StringComparison.OrdinalIgnoreCase);

    /// <summary>Whether a finished request belongs in the log.</summary>
    public static bool ShouldRecord(string path, int status) => status is 401 or 429 || (status >= 400 && IsUntrustedRoute(path));

    /// <summary>
    /// The route as a dotted name from its template, never from the request path, so no id, token or address can land in the log:
    /// <c>/api/auth/sign-in/email</c> is <c>auth.sign_in.email</c>, <c>/v1/admin/users/{id}</c> is <c>v1.admin.users</c>. A request that matched no
    /// route is <c>unmatched</c>.
    /// </summary>
    public static string ActionName(string? routeTemplate)
    {
        if (string.IsNullOrWhiteSpace(routeTemplate)) return "unmatched";
        var parts = routeTemplate.Split('/', StringSplitOptions.RemoveEmptyEntries)
            .Where(p => !p.Contains('{') && !p.Contains('*'))
            .Select(p => p.Replace('-', '_').ToLowerInvariant())
            .ToList();
        if (parts.Count >= 2 && parts[0] == "api" && parts[1] == "auth") parts.RemoveAt(0);
        var name = parts.Count == 0 ? "root" : string.Join('.', parts);
        var clean = new StringBuilder(name.Length);
        foreach (var c in name) clean.Append(char.IsAsciiLetterOrDigit(c) || c is '.' or '_' ? c : '_');
        return clean.Length > 128 ? clean.ToString(0, 128) : clean.ToString();
    }

    public static void UseRequestLog(WebApplication app)
    {
        app.Use(async (context, next) =>
        {
            var failed = false;
            try { await next(); }
            catch { failed = true; throw; }
            finally
            {
                var status = failed ? 500 : context.Response.StatusCode;
                var path = context.Request.Path.Value ?? "";
                if (ShouldRecord(path, status) || (failed && IsUntrustedRoute(path)))
                {
                    var template = (context.GetEndpoint() as RouteEndpoint)?.RoutePattern.RawText;
                    context.RequestServices.GetRequiredService<RequestLog>().Record(ActionName(template), status, DateTime.UtcNow);
                }
            }
        });
    }
}

/// <summary><c>GET /v1/admin/security/requests</c>: the last 24 hours of the request log, in the reference's shape.</summary>
public static class AdminSecurityRequestsEndpoints
{
    private const int Hours = 24;
    private const int EndpointLimit = 25;
    private static readonly (int HighPeak, double HighRatio, int MediumPeak, double MediumRatio, int? LowTotal) FailedSignIn = (100, 5, 30, 3, 200);
    private static readonly (int HighPeak, double HighRatio, int MediumPeak, double MediumRatio, int? LowTotal) RateLimited = (200, 5, 50, 3, null);
    private static readonly (int HighPeak, double HighRatio, int MediumPeak, double MediumRatio, int? LowTotal) DeniedSpike = (2_000, 10, 200, 4, null);

    public static void MapAdminSecurityRequestsEndpoints(this WebApplication app)
    {
        app.MapGet("/v1/admin/security/requests", async (HttpContext ctx, PlatformAdminGuard guard, DenDbContext db) =>
        {
            var (_, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            ctx.Response.Headers.CacheControl = "no-store";
            return Results.Json(await ReadAsync(db, DateTime.UtcNow));
        });
    }

    public static async Task<object> ReadAsync(DenDbContext db, DateTime now)
    {
        var currentHour = HourOf(now);
        var firstHour = currentHour - Hours + 1;
        var from = DateTime.UnixEpoch.AddHours(firstHour);
        var rows = await db.Set<PlatformRequestEvent>().AsNoTracking().Where(e => e.OccurredAt >= from)
            .Select(e => new { e.OccurredAt, e.Action, e.Outcome, e.Status }).ToListAsync();

        var hourly = Enumerable.Range(0, Hours).Select(i => new Bucket(AdminSupport.Iso(DateTime.UnixEpoch.AddHours(firstHour + i)))).ToList();
        var byAction = new Dictionary<string, (long Refused, long Limited, long Failed, long[] Series)>(StringComparer.Ordinal);
        var limitedByAction = new Dictionary<string, long[]>(StringComparer.Ordinal);
        var signIns = new long[Hours];
        foreach (var row in rows)
        {
            var index = (int)(HourOf(row.OccurredAt) - firstHour);
            if (index < 0 || index >= Hours) continue;
            var kind = row.Status == 429 ? "rateLimited" : row.Outcome == "denied" ? "refused" : "failed";
            var bucket = hourly[index];
            var entry = byAction.TryGetValue(row.Action, out var e) ? e : (0, 0, 0, new long[Hours]);
            switch (kind)
            {
                case "rateLimited": bucket.RateLimited++; entry.Limited++; break;
                case "refused": bucket.Refused++; entry.Refused++; break;
                default: bucket.Failed++; entry.Failed++; break;
            }
            entry.Series[index]++;
            byAction[row.Action] = entry;
            if (kind == "rateLimited")
            {
                if (!limitedByAction.TryGetValue(row.Action, out var series)) limitedByAction[row.Action] = series = new long[Hours];
                series[index]++;
            }
            if (row.Action.StartsWith("auth.sign_in.", StringComparison.Ordinal)) { bucket.FailedSignIns++; signIns[index]++; }
        }

        var endpoints = byAction
            .OrderByDescending(p => p.Value.Refused + p.Value.Limited + p.Value.Failed).ThenBy(p => p.Key, StringComparer.Ordinal)
            .Take(EndpointLimit)
            .Select(p =>
            {
                var spike = SpikeOf(p.Value.Series);
                return new { action = p.Key, refused = p.Value.Refused, rateLimited = p.Value.Limited, failed = p.Value.Failed, peakHour = spike.Peak, typicalHour = spike.Typical };
            }).ToList();

        var findings = new List<SecurityFinding>
        {
            FailedSignInFinding(signIns),
            RateLimitedFinding(limitedByAction),
            DeniedSpikeFinding(byAction.ToDictionary(p => p.Key, p => p.Value.Series)),
        }.OrderByDescending(f => AdminSecurityEndpoints.SeverityRank(f.Severity)).ToList();

        return new
        {
            generatedAt = AdminSupport.Iso(now),
            range = new { hours = Hours, from = AdminSupport.Iso(from), to = AdminSupport.Iso(now) },
            hourly = hourly.Select(b => new { hour = b.Hour, refused = b.Refused, rateLimited = b.RateLimited, failed = b.Failed, failedSignIns = b.FailedSignIns }),
            endpoints,
            findings = findings.Select(AdminSecurityEndpoints.FindingJson),
        };
    }

    private sealed class Bucket(string hour)
    {
        public string Hour { get; } = hour;
        public long Refused, RateLimited, Failed, FailedSignIns;
    }

    private static long HourOf(DateTime at) => (long)Math.Floor((DateTime.SpecifyKind(at, DateTimeKind.Utc) - DateTime.UnixEpoch).TotalHours);

    public static (long Peak, double Typical, double Ratio, long Total) SpikeOf(long[] series)
    {
        var peak = series.Length == 0 ? 0 : Math.Max(0, series.Max());
        var sorted = series.OrderBy(v => v).ToArray();
        double typical = sorted.Length == 0 ? 0 : sorted.Length % 2 == 1 ? sorted[sorted.Length / 2] : (sorted[sorted.Length / 2 - 1] + sorted[sorted.Length / 2]) / 2.0;
        return (peak, typical, peak / Math.Max(1, typical), series.Sum());
    }

    private static string Severity((long Peak, double Typical, double Ratio, long Total) spike, (int HighPeak, double HighRatio, int MediumPeak, double MediumRatio, int? LowTotal) tiers)
    {
        if (spike.Peak >= tiers.HighPeak && spike.Ratio >= tiers.HighRatio) return "high";
        if (spike.Peak >= tiers.MediumPeak && spike.Ratio >= tiers.MediumRatio) return "medium";
        return tiers.LowTotal is { } low && spike.Total >= low ? "low" : "clear";
    }

    private static string N(double value) => value.ToString("N0", CultureInfo.InvariantCulture);
    private static string Plural(long count, string one) => $"{N(count)} {(count == 1 ? one : one + "s")}";

    public static SecurityFinding FailedSignInFinding(long[] series)
    {
        var spike = SpikeOf(series);
        return new("failed-sign-ins", "access", Severity(spike, FailedSignIn), "Failed sign-ins",
            $"{Plural(spike.Total, "failed sign-in")} in 24 hours; the busiest hour had {N(spike.Peak)}, a typical hour {N(Math.Round(spike.Typical))}.",
            $"Medium when an hour reaches {FailedSignIn.MediumPeak}+ and {FailedSignIn.MediumRatio}× a typical hour, high at {FailedSignIn.HighPeak}+ and {FailedSignIn.HighRatio}×; {FailedSignIn.LowTotal}+ in a day is low.",
            "Bursts of wrong passwords are the signature of password guessing and of logins reused from other breaches.",
            "Check whether the burst lines up with sign-up or rate-limit spikes. Sign-in attempts store no address, so look in the edge logs for the source.",
            spike.Total, "count", [], 0);
    }

    public static SecurityFinding RateLimitedFinding(IReadOnlyDictionary<string, long[]> byAction)
    {
        var all = Enumerable.Range(0, Hours).Select(i => byAction.Values.Sum(s => i < s.Length ? s[i] : 0)).ToArray();
        var spike = SpikeOf(all);
        var severity = Severity(spike, RateLimited);
        var entities = byAction.Select(p => (Action: p.Key, Spike: SpikeOf(p.Value))).Where(p => p.Spike.Total > 0).OrderByDescending(p => p.Spike.Total)
            .Select(p => new SecurityEntity(p.Action, p.Action, $"Busiest hour {N(p.Spike.Peak)}", p.Spike.Total, severity, null)).ToList();
        return new("rate-limited", "access", severity, "Rate-limited requests",
            $"{Plural(spike.Total, "request")} hit a rate limit in 24 hours; the busiest hour had {N(spike.Peak)}.",
            $"Medium when an hour reaches {RateLimited.MediumPeak}+ and {RateLimited.MediumRatio}× a typical hour, high at {RateLimited.HighPeak}+ and {RateLimited.HighRatio}×.",
            "Limits stop guessing and scraping. A jump means someone is pushing hard on a sign-in or token endpoint.",
            "See which endpoints are limited. Token and sign-in endpoints matter most.",
            spike.Total, "count", entities.Take(AdminSecurityEndpoints.EntityLimit).ToList(), entities.Count);
    }

    public static SecurityFinding DeniedSpikeFinding(IReadOnlyDictionary<string, long[]> byAction)
    {
        var entities = byAction.Select(p => (Action: p.Key, Spike: SpikeOf(p.Value)))
            .Select(p => (p.Action, p.Spike, Severity: Severity(p.Spike, DeniedSpike)))
            .Where(p => p.Severity != "clear")
            .Select(p => new SecurityEntity(p.Action, p.Action, $"Busiest hour {N(p.Spike.Peak)}, typical {N(Math.Round(p.Spike.Typical))} ({N(Math.Round(p.Spike.Ratio))}×)", p.Spike.Peak, p.Severity, null))
            .ToList();
        return AdminSecurityEndpoints.Finding("denied-spikes", "access", "Refused request spikes",
            entities.Count > 0 ? $"{Plural(entities.Count, "endpoint")} refused far more requests than usual in one hour." : "Refused requests stayed at their usual hourly level.",
            $"Flags an endpoint whose busiest hour of refused or failed requests is {DeniedSpike.MediumPeak}+ and {DeniedSpike.MediumRatio}× its typical hour; {DeniedSpike.HighPeak}+ and {DeniedSpike.HighRatio}× is high. Steady pollers do not fire.",
            "A burst of refusals on one endpoint is what scanning, enumeration or a leaked-but-revoked credential looks like.",
            "Match the hour with deploys first; a release can briefly reject valid callers. Otherwise look in the edge logs for the source.",
            entities.Count, "count", entities);
    }
}
