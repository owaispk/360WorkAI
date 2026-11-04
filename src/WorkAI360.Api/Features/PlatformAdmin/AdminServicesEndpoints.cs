using System.Diagnostics;
using System.Reflection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Email;

namespace WorkAI360.Api.Features.PlatformAdmin;

/// <summary>
/// Deployment service readiness for the operator (the reference's <c>GET /v1/admin/services</c> and <c>POST /v1/admin/services/check</c>), in the reference's
/// shape (version 2: fixed facts and codes, never addresses or credentials). Checks are local and read-only: a database query, and the mail settings (nothing is
/// sent). The gateway, the headless runner and Workbot are not part of this build and read as "not set up". A check made less than 30 seconds ago answers again
/// without running another.
/// </summary>
public static class AdminServicesEndpoints
{
    private static readonly DateTime Started = Process.GetCurrentProcess().StartTime.ToUniversalTime();
    private static readonly TimeSpan Coalesce = TimeSpan.FromSeconds(30);

    /// <summary>The last check, held per running API (one per test host), shared by the operator's page and the member projection.</summary>
    public sealed class Cache
    {
        internal readonly SemaphoreSlim Gate = new(1, 1);
        internal Snapshot? Last;
    }

    internal sealed record Status(string Id, bool Required, bool Configured, string State, string Reason, string[] MissingSettings, string[] Dependencies, string[] Notes, int? DurationMs, DateTime? CheckedAt, DateTime? LastSuccessAt);
    internal sealed record Snapshot(DateTime CheckedAt, List<Status> Services);

    private static async Task<Snapshot> CheckAsync(DenDbContext db, IOptions<EmailOptions> email, IHostEnvironment env, Snapshot? previous)
    {
        var now = DateTime.UtcNow;
        var watch = Stopwatch.StartNew();
        string state, reason;
        try { await db.Database.ExecuteSqlRawAsync("SELECT 1"); state = "ready"; reason = "database_verified"; }
        catch (Exception e) when (e is DbUpdateException or InvalidOperationException or Microsoft.Data.Sqlite.SqliteException or MySql.Data.MySqlClient.MySqlException or TimeoutException) { state = "unreachable"; reason = "request_failed"; }
        var database = new Status("database", true, true, state, reason, [], [], [], (int)watch.ElapsedMilliseconds, now, state == "ready" ? now : previous?.Services.First(s => s.Id == "database").LastSuccessAt);

        var provider = email.Value.Provider ?? "dev";
        var smtpHost = !string.IsNullOrWhiteSpace(email.Value.Smtp.Host);
        var resendKey = !string.IsNullOrWhiteSpace(email.Value.Resend.ApiKey);
        Status mail = provider switch
        {
            "smtp" => new("email", true, smtpHost, smtpHost ? "unknown" : "misconfigured", smtpHost ? "configuration_only" : "missing_configuration", smtpHost ? [] : ["EMAIL__SMTP__HOST"], [], ["email_smtp"], null, now, null),
            "resend" => new("email", true, resendKey, resendKey ? "unknown" : "misconfigured", resendKey ? "configuration_only" : "missing_configuration", resendKey ? [] : ["EMAIL__RESEND__APIKEY"], [], ["email_resend"], null, now, null),
            _ => new("email", true, false, env.IsDevelopment() ? "not_configured" : "misconfigured", env.IsDevelopment() ? "not_configured" : "invalid_configuration", [], [], [], null, now, null),
        };
        Status Absent(string id) => new(id, false, false, "not_configured", "not_configured", [], [], [], null, now, null);
        return new(now, [database, Absent("gateway"), Absent("headlessRunner"), Absent("workbot"), mail]);
    }

    private static object Json(Snapshot? snapshot, bool checking) => new
    {
        version = 2,
        checkedAt = snapshot is null ? null : Responses.IsoUtc(snapshot.CheckedAt),
        checking,
        server = new
        {
            version = typeof(AdminServicesEndpoints).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "0.0.0",
            startedAt = Responses.IsoUtc(Started), startupMs = (int?)null,
        },
        services = (snapshot?.Services ?? []).Select(s => new
        {
            id = s.Id, required = s.Required, configured = s.Configured, state = s.State, reason = s.Reason, missingSettings = s.MissingSettings, dependencies = s.Dependencies, notes = s.Notes,
            durationMs = s.DurationMs, checkedAt = s.CheckedAt is { } c ? Responses.IsoUtc(c) : null, lastSuccessAt = s.LastSuccessAt is { } l ? Responses.IsoUtc(l) : null,
            stale = Stale(s),
        }),
    };

    private static bool Stale(Status s) => s.CheckedAt is null || DateTime.UtcNow - s.CheckedAt > TimeSpan.FromMinutes(5);

    /// <summary>
    /// The member-safe projection of the cached snapshot (the reference's <c>OrganizationServiceReadiness</c>): no required flag, missing settings,
    /// notes, durations or server facts. Null when no check has run yet. Never starts a check.
    /// </summary>
    public static object? MemberProjection(Cache cache)
    {
        var snapshot = cache.Last;
        if (snapshot is null) return null;
        return new
        {
            version = 2,
            checkedAt = Responses.IsoUtc(snapshot.CheckedAt),
            checking = false,
            services = snapshot.Services.Select(s => new
            {
                id = s.Id, configured = s.Configured, state = s.State, reason = s.Reason, dependencies = s.Dependencies,
                checkedAt = s.CheckedAt is { } c ? Responses.IsoUtc(c) : null, lastSuccessAt = s.LastSuccessAt is { } l ? Responses.IsoUtc(l) : null,
                stale = Stale(s),
            }),
        };
    }

    public static void MapAdminServicesEndpoints(this WebApplication app)
    {
        // Any member may read the cached, member-safe facts (the reference's GET /v1/org/service-readiness). It never runs a check: until an
        // operator has opened the services page (or asked for a check) there is no snapshot, and the answer is 503 with no detail.
        app.MapGet("/v1/org/service-readiness", async (HttpContext ctx, OrgAccess access, Cache cache) =>
        {
            var (_, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            ctx.Response.Headers.CacheControl = "no-store";
            return MemberProjection(cache) is { } projection ? Results.Json(projection) : Results.Json(new { error = "service_readiness_unavailable" }, statusCode: 503);
        });

        app.MapGet("/v1/admin/services", async (HttpContext ctx, PlatformAdminGuard guard, DenDbContext db, IOptions<EmailOptions> email, IHostEnvironment env, Cache cache) =>
        {
            var (_, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            ctx.Response.Headers.CacheControl = "no-store";
            // Never waits on an outside service: the first read runs the (local) checks, later reads answer from the snapshot.
            if (cache.Last is null || DateTime.UtcNow - cache.Last.CheckedAt > TimeSpan.FromMinutes(5))
            {
                await cache.Gate.WaitAsync();
                try { cache.Last = await CheckAsync(db, email, env, cache.Last); } finally { cache.Gate.Release(); }
            }
            return Results.Json(Json(cache.Last, checking: false));
        });

        app.MapPost("/v1/admin/services/check", async (HttpContext ctx, PlatformAdminGuard guard, DenDbContext db, IOptions<EmailOptions> email, IHostEnvironment env, Cache cache) =>
        {
            var (_, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            ctx.Response.Headers.CacheControl = "no-store";
            await cache.Gate.WaitAsync();
            try
            {
                // Recent results with the same settings are answered again, so repeated clicks cost nothing.
                if (cache.Last is null || DateTime.UtcNow - cache.Last.CheckedAt > Coalesce) cache.Last = await CheckAsync(db, email, env, cache.Last);
            }
            finally { cache.Gate.Release(); }
            return Results.Json(Json(cache.Last, checking: false), statusCode: 202);
        });

        // Sandbox organizations are a cloud feature ("sandboxOrgs"): on a self-hosted deployment the reference answers that they are off.
        app.MapGet("/v1/admin/sandbox-orgs", async (HttpContext ctx, PlatformAdminGuard guard, FeatureResolver resolver) =>
        {
            var (_, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            ctx.Response.Headers.CacheControl = "no-store";
            var feature = FeatureCatalog.Find("sandboxOrgs")!;
            var enabled = resolver.Resolve(feature, await resolver.RolloutsAsync(), new Dictionary<string, bool>()).Enabled;
            return Results.Json(new { enabled, sandboxes = Array.Empty<object>() });
        });
    }
}
