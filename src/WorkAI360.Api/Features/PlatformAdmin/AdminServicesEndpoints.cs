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
    private static readonly SemaphoreSlim Gate = new(1, 1);
    private static Snapshot? _last;

    private sealed record Status(string Id, bool Required, bool Configured, string State, string Reason, string[] MissingSettings, string[] Dependencies, string[] Notes, int? DurationMs, DateTime? CheckedAt, DateTime? LastSuccessAt);
    private sealed record Snapshot(DateTime CheckedAt, List<Status> Services);

    private static async Task<Snapshot> CheckAsync(DenDbContext db, IOptions<EmailOptions> email, IHostEnvironment env)
    {
        var now = DateTime.UtcNow;
        var watch = Stopwatch.StartNew();
        string state, reason;
        try { await db.Database.ExecuteSqlRawAsync("SELECT 1"); state = "ready"; reason = "database_verified"; }
        catch (Exception e) when (e is DbUpdateException or InvalidOperationException or Microsoft.Data.Sqlite.SqliteException or MySql.Data.MySqlClient.MySqlException or TimeoutException) { state = "unreachable"; reason = "request_failed"; }
        var database = new Status("database", true, true, state, reason, [], [], [], (int)watch.ElapsedMilliseconds, now, state == "ready" ? now : _last?.Services.First(s => s.Id == "database").LastSuccessAt);

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
            stale = s.CheckedAt is null || DateTime.UtcNow - s.CheckedAt > TimeSpan.FromMinutes(5),
        }),
    };

    public static void MapAdminServicesEndpoints(this WebApplication app)
    {
        app.MapGet("/v1/admin/services", async (HttpContext ctx, PlatformAdminGuard guard, DenDbContext db, IOptions<EmailOptions> email, IHostEnvironment env) =>
        {
            var (_, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            ctx.Response.Headers.CacheControl = "no-store";
            // Never waits on an outside service: the first read runs the (local) checks, later reads answer from the snapshot.
            if (_last is null || DateTime.UtcNow - _last.CheckedAt > TimeSpan.FromMinutes(5))
            {
                await Gate.WaitAsync();
                try { _last = await CheckAsync(db, email, env); } finally { Gate.Release(); }
            }
            return Results.Json(Json(_last, checking: false));
        });

        app.MapPost("/v1/admin/services/check", async (HttpContext ctx, PlatformAdminGuard guard, DenDbContext db, IOptions<EmailOptions> email, IHostEnvironment env) =>
        {
            var (_, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            ctx.Response.Headers.CacheControl = "no-store";
            await Gate.WaitAsync();
            try
            {
                // Recent results with the same settings are answered again, so repeated clicks cost nothing.
                if (_last is null || DateTime.UtcNow - _last.CheckedAt > Coalesce) _last = await CheckAsync(db, email, env);
            }
            finally { Gate.Release(); }
            return Results.Json(Json(_last, checking: false), statusCode: 202);
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
