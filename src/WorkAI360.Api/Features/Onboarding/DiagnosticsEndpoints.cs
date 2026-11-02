using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Onboarding;
using WorkAI360.Api.Features.Connections;
using WorkAI360.Api.Features.OrgAdmin;

namespace WorkAI360.Api.Features.Onboarding;

/// <summary>Settings > Diagnostics: what desktops report about starting up, and the network check an operator can configure. See docs/features/onboarding.md.</summary>
public static partial class DiagnosticsEndpoints
{
    private const int ReportsPerHour = 20;
    private static readonly string[] Steps = ["window", "engine", "signed_in", "org_tools"];
    private static readonly string[] Reasons = ["certificate", "dns", "offline", "timeout", "connection_refused", "server_error", "signed_out", "session_expired", "engine_failed", "org_unavailable", "unknown"];
    private static readonly string[] Platforms = ["darwin", "win32", "linux", "other"];
    private static readonly TimeSpan Window = TimeSpan.FromHours(24), MaxAge = TimeSpan.FromDays(7), MaxFuture = TimeSpan.FromMinutes(5), Retention = TimeSpan.FromDays(30);

    [GeneratedRegex("^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$")]
    private static partial Regex VersionPattern();

    [GeneratedRegex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")]
    private static partial Regex UuidPattern();

    public static void MapDiagnosticsEndpoints(this WebApplication app)
    {
        app.MapGet("/v1/org/diagnostics", async (HttpContext ctx, OrgAccess access, DenDbContext db) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            var strict = ctx.Request.Query["strict"].ToString();
            if (ctx.Request.Query.ContainsKey("strict") && strict is not ("0" or "1" or "true" or "false"))
                return Zod.Respond("strict", "Invalid option: expected one of \"0\"|\"1\"|\"true\"|\"false\"", "invalid_value");
            ctx.Response.Headers.CacheControl = "no-store";
            var body = await ReadAsync(db, context!);
            // Nothing here reaches error severity (no provider or installation checks exist), so a strict smoke test passes.
            return Results.Json(body);
        });

        // There are no live checks to start (providers, Slack, Google and installation services are not part of this build): the answer is the current picture.
        app.MapPost("/v1/org/diagnostics/check", async (HttpContext ctx, OrgAccess access, DenDbContext db) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            ctx.Response.Headers.CacheControl = "no-store";
            return Results.Json(await ReadAsync(db, context!), statusCode: 202);
        });

        app.MapPost("/v1/diagnostics/desktop-startup", async (HttpContext ctx, OrgAccess access, DenDbContext db, WindowLimiter limiter) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            var (root, invalid) = await Zod.ReadObjectAsync(ctx, "attemptId");
            if (invalid is not null) return invalid;
            var issues = new List<ZodIssue>();
            if (Zod.Unrecognized(root, "attemptId", "appVersion", "platform", "observedAt", "success", "steps", "failedStep", "reason") is { } extra) issues.Add(extra);
            string? attempt = null, version = null, platform = null;
            if (Zod.String(root, "attemptId", 0, 1000, true, out attempt) is { } a) issues.Add(a);
            else if (!UuidPattern().IsMatch(attempt!)) issues.Add(new ZodIssue("invalid_format", ["attemptId"], "Invalid UUID"));
            if (Zod.String(root, "appVersion", 1, 64, true, out version) is { } v) issues.Add(v);
            else if (!VersionPattern().IsMatch(version!)) issues.Add(new ZodIssue("invalid_format", ["appVersion"], "Invalid string: must match pattern /^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$/"));
            if (Zod.String(root, "platform", 0, 32, true, out platform) is { } p) issues.Add(p);
            else if (!Platforms.Contains(platform!)) issues.Add(new ZodIssue("invalid_value", ["platform"], "Invalid option: expected one of " + string.Join("|", Platforms.Select(x => $"\"{x}\""))));
            DateTime observed = default;
            if (Zod.String(root, "observedAt", 0, 64, true, out var at) is { } o) issues.Add(o);
            else if (!DateTimeOffset.TryParse(at, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal, out var parsed) || !at!.EndsWith('Z') && !at.Contains('+') && !(at.Length > 6 && at[^6] == '-')) issues.Add(new ZodIssue("invalid_format", ["observedAt"], "Invalid ISO datetime"));
            else observed = parsed.UtcDateTime;
            bool success = false;
            if (!root.TryGetProperty("success", out var s)) issues.Add(new ZodIssue("invalid_type", ["success"], "Invalid input: expected boolean, received undefined"));
            else if (s.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) issues.Add(new ZodIssue("invalid_type", ["success"], $"Invalid input: expected boolean, received {Zod.Kind(s)}"));
            else success = s.GetBoolean();

            var timings = new Dictionary<string, int?>();
            if (!root.TryGetProperty("steps", out var steps)) issues.Add(new ZodIssue("invalid_type", ["steps"], "Invalid input: expected object, received undefined"));
            else if (steps.ValueKind != JsonValueKind.Object) issues.Add(new ZodIssue("invalid_type", ["steps"], $"Invalid input: expected object, received {Zod.Kind(steps)}"));
            else
            {
                if (Zod.Unrecognized(steps, Steps) is { } stepExtra) issues.Add(stepExtra with { Path = ["steps"] });
                foreach (var step in Steps)
                {
                    if (!steps.TryGetProperty(step, out var t)) issues.Add(new ZodIssue("invalid_type", ["steps", step], "Invalid input: expected number, received undefined"));
                    else if (t.ValueKind == JsonValueKind.Null) timings[step] = null;
                    else if (t.ValueKind != JsonValueKind.Number || !t.TryGetInt32(out var ms)) issues.Add(new ZodIssue("invalid_type", ["steps", step], $"Invalid input: expected int, received {Zod.Kind(t)}"));
                    else if (ms < 0) issues.Add(new ZodIssue("too_small", ["steps", step], "Too small: expected number to be >=0"));
                    else if (ms > 3_600_000) issues.Add(new ZodIssue("too_big", ["steps", step], "Too big: expected number to be <=3600000"));
                    else timings[step] = ms;
                }
            }
            string? failedStep = null, reason = null;
            if (!NullableChoice(root, "failedStep", Steps, out failedStep, out var fs)) issues.Add(fs!);
            if (!NullableChoice(root, "reason", Reasons, out reason, out var rs)) issues.Add(rs!);
            if (issues.Count == 0)
            {
                if (success && (failedStep is not null || reason is not null)) issues.Add(new ZodIssue("custom", ["failedStep"], "A successful startup has no failed step or reason."));
                if (!success && (failedStep is null || reason is null)) issues.Add(new ZodIssue("custom", ["failedStep"], "A failed startup names its failed step and reason."));
            }
            if (issues.Count > 0) return Zod.Respond(issues);

            if (await limiter.HitAsync($"diagnostics:desktop-startup:{context!.Member.Id}", ReportsPerHour, TimeSpan.FromHours(1)) is { } wait)
            {
                ctx.Response.Headers.RetryAfter = wait.ToString();
                return Results.Json(new { error = "rate_limited" }, statusCode: 429);
            }

            var now = DateTime.UtcNow;
            // A launch that is too old or from the future is dropped quietly, so the app never retries it.
            if (observed < now - MaxAge || observed > now + MaxFuture) return Results.NoContent();
            var key = attempt!.ToLowerInvariant();
            if (!await db.Set<DesktopStartupReport>().AnyAsync(r => r.OrganizationId == context.Organization.Id && r.AttemptId == key))
            {
                db.Set<DesktopStartupReport>().Add(new DesktopStartupReport
                {
                    Id = Ids.New("dsr"), OrganizationId = context.Organization.Id, MemberId = context.Member.Id, AttemptId = key, AppVersion = version!, Platform = platform!, Success = success,
                    FailedStep = failedStep, FailureReason = reason, WindowMs = timings["window"], EngineMs = timings["engine"], SignedInMs = timings["signed_in"], OrgToolsMs = timings["org_tools"], ObservedAt = observed,
                });
                // A second request with the same launch id lost the race: the first report stands.
                try { await db.SaveChangesAsync(); } catch (DbUpdateException) { db.ChangeTracker.Clear(); }
                await db.Set<DesktopStartupReport>().Where(r => r.OrganizationId == context.Organization.Id && r.ObservedAt < now - Retention).ExecuteDeleteAsync();
            }
            return Results.NoContent();
        });

        MapEgress(app);
    }

    private static bool NullableChoice(JsonElement root, string name, string[] allowed, out string? value, out ZodIssue? issue)
    {
        value = null; issue = null;
        if (!root.TryGetProperty(name, out var e)) { issue = new ZodIssue("invalid_type", [name], "Invalid input: expected string, received undefined"); return false; }
        if (e.ValueKind == JsonValueKind.Null) return true;
        if (e.ValueKind != JsonValueKind.String || !allowed.Contains(e.GetString())) { issue = new ZodIssue("invalid_value", [name], "Invalid option: expected one of " + string.Join("|", allowed.Select(x => $"\"{x}\""))); return false; }
        value = e.GetString();
        return true;
    }

    // ---- the picture ---------------------------------------------------------------------------------------------------------------------

    private static async Task<object> ReadAsync(DenDbContext db, OrgContext context)
    {
        var has = context.Permissions;
        object desktop = new { access = "locked", permission = "desktop_policies.view" };
        object? attention = null;
        if (has.Has("desktop_policies.view"))
        {
            var (section, failure) = await DesktopAsync(db, context.Organization.Id);
            desktop = section;
            attention = failure;
        }
        return new
        {
            version = 1,
            generatedAt = Responses.IsoUtc(DateTime.UtcNow),
            deployment = "self_hosted",
            checking = false,
            attention = attention is null ? Array.Empty<object>() : [attention],
            desktop,
            providers = has.Has("llm_providers.view") ? (object)new { access = "granted", checkedAt = (string?)null, checking = false, items = Array.Empty<object>() } : new { access = "locked", permission = "llm_providers.view" },
            connectors = has.Has("connections.view") ? (object)new { access = "granted", checkedAt = (string?)null, items = Array.Empty<object>() } : new { access = "locked", permission = "connections.view" },
            installation = new { access = "locked", reason = "installation_admin_required" },
            network = has.Has("egress_diagnostics.view") ? (object)new { access = "granted", canRun = has.Has("egress_diagnostics.manage") } : new { access = "locked", permission = "egress_diagnostics.view" },
        };
    }

    private static async Task<(object Section, object? Attention)> DesktopAsync(DenDbContext db, string organizationId)
    {
        var now = DateTime.UtcNow;
        var since = now - Window;
        var rows = await db.Set<DesktopStartupReport>().AsNoTracking().Where(r => r.OrganizationId == organizationId && r.ObservedAt >= since && r.ObservedAt <= now + MaxFuture)
            .OrderByDescending(r => r.ObservedAt).Take(5000).ToListAsync();
        var ok = rows.Where(r => r.Success).ToList();
        var totals = ok.Where(r => r.OrgToolsMs is not null).Select(r => r.OrgToolsMs!.Value).ToList();
        // Steps are timed from process start and may overlap, so each duration is the step's time minus the previous reached step's.
        var perStep = Steps.ToDictionary(s => s, _ => new List<int>());
        foreach (var r in ok)
        {
            var stamps = new[] { r.WindowMs, r.EngineMs, r.SignedInMs, r.OrgToolsMs };
            var previous = 0;
            for (var i = 0; i < 4; i++)
            {
                if (stamps[i] is not { } t) continue;
                perStep[Steps[i]].Add(Math.Max(0, t - previous));
                previous = t;
            }
        }
        var failures = rows.Where(r => !r.Success && r.FailedStep is not null && r.FailureReason is not null).GroupBy(r => (Step: r.FailedStep!, Reason: r.FailureReason!))
            .Select(g => new { step = g.Key.Step, reason = g.Key.Reason, count = g.Count(), people = g.Select(x => x.MemberId).Distinct().Count(), last = g.Max(x => x.ObservedAt) })
            .OrderByDescending(f => f.count).ThenByDescending(f => f.last).Take(20).ToList();
        var section = new
        {
            access = "granted",
            windowHours = 24,
            startups = rows.Count,
            connected = ok.Count,
            failed = rows.Count - ok.Count,
            people = rows.Select(r => r.MemberId).Distinct().Count(),
            typicalMs = Percentile(totals, 0.5),
            slowestMs = Percentile(totals, 0.95),
            steps = Steps.Select(s => new { step = s, typicalMs = Percentile(perStep[s], 0.5) }),
            failures = failures.Select(f => new { f.step, f.reason, f.count, f.people, lastSeenAt = Responses.IsoUtc(f.last) }),
            versions = rows.GroupBy(r => r.AppVersion).Select(g => new { version = g.Key, startups = g.Count() }).OrderByDescending(x => x.startups).ThenBy(x => x.version, StringComparer.Ordinal).Take(10),
        };
        var failed = rows.Count - ok.Count;
        object? attention = failed > 0
            ? new { section = "desktop", targetId = failures.FirstOrDefault()?.step ?? "startup", severity = "warning", code = "desktop_startup_failures", subject = "Desktop app", count = (int?)failed, detail = failures.FirstOrDefault()?.reason }
            : null;
        return (section, attention);
    }

    /// <summary>Nearest-rank percentile, whole milliseconds; null for nothing.</summary>
    public static int? Percentile(IReadOnlyList<int> values, double fraction)
    {
        if (values.Count == 0) return null;
        var sorted = values.Order().ToList();
        var rank = Math.Min(sorted.Count, Math.Max(1, (int)Math.Ceiling(fraction * sorted.Count)));
        return sorted[rank - 1];
    }

    // ---- network check --------------------------------------------------------------------------------------------------------------------

    private static void MapEgress(WebApplication app)
    {
        app.MapGet("/v1/diagnostics/egress", async (HttpContext ctx, OrgAccess access, DenDbContext db, IOptions<OnboardingOptions> options) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "egress_diagnostics.view") is { } denied) return denied;
            var c = await ConfigurationAsync(db, context!.Organization.Id, options.Value);
            return Results.Json(new { available = c.Available, targetOrigin = c.TargetOrigin, missingConfiguration = c.Missing });
        });

        // The token is stored encrypted and never returned by any route.
        app.MapPut("/v1/diagnostics/egress/token", async (HttpContext ctx, OrgAccess access, DenDbContext db, SecretBox box) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "egress_diagnostics.manage") is { } denied) return denied;
            var (root, invalid) = await Zod.ReadObjectAsync(ctx, "bearerToken");
            if (invalid is not null) return invalid;
            if (Zod.String(root, "bearerToken", 24, 4096, true, out var token) is { } issue) return Zod.Respond([issue]);
            var orgId = context!.Organization.Id;
            var row = await db.Set<EgressDiagnosticCredential>().FirstOrDefaultAsync(c => c.OrganizationId == orgId);
            if (row is null) db.Set<EgressDiagnosticCredential>().Add(new EgressDiagnosticCredential { OrganizationId = orgId, TokenCipher = box.Encrypt(token!), UpdatedAt = DateTime.UtcNow });
            else { row.TokenCipher = box.Encrypt(token!); row.UpdatedAt = DateTime.UtcNow; }
            try { await db.SaveChangesAsync(); }
            catch (DbUpdateException)
            {
                // Two first saves at once: the other one created the row, so this one replaces its value.
                db.ChangeTracker.Clear();
                await db.Set<EgressDiagnosticCredential>().Where(c => c.OrganizationId == orgId).ExecuteUpdateAsync(u => u.SetProperty(c => c.TokenCipher, box.Encrypt(token!)).SetProperty(c => c.UpdatedAt, DateTime.UtcNow));
            }
            return Results.NoContent();
        });

        // The fixed probes (HTTP, redirect, OAuth-shaped, MCP) are not built: with no target this is the reference's 503, and with one it says so.
        app.MapPost("/v1/diagnostics/egress", async (HttpContext ctx, OrgAccess access, DenDbContext db, IOptions<OnboardingOptions> options) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (access.Require(context!, "egress_diagnostics.manage") is { } denied) return denied;
            var configuration = await ConfigurationAsync(db, context!.Organization.Id, options.Value);
            if (!configuration.Available) return Results.Json(new { error = "egress_diagnostics_not_configured", missingConfiguration = configuration.Missing }, statusCode: 503);
            return Results.Json(new { error = "not_implemented", message = "The network probes are not built in this deployment." }, statusCode: 501);
        });
    }

    private static async Task<EgressJson> ConfigurationAsync(DenDbContext db, string organizationId, OnboardingOptions options)
    {
        var missing = new List<string>();
        var hasOwn = await db.Set<EgressDiagnosticCredential>().AsNoTracking().AnyAsync(c => c.OrganizationId == organizationId);
        if (!hasOwn && options.DiagnosticsBearerToken.Length == 0) missing.Add("DEN_DIAGNOSTICS_BEARER_TOKEN");
        if (options.DiagnosticsOrigin.Length == 0) missing.Add("DEN_DIAGNOSTICS_ORIGIN");
        return new EgressJson(missing.Count == 0, options.DiagnosticsOrigin.Length == 0 ? null : options.DiagnosticsOrigin, [.. missing]);
    }

    private sealed record EgressJson(bool Available, string? TargetOrigin, string[] Missing);
}
