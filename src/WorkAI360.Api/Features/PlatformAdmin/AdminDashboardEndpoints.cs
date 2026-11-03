using System.Globalization;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.PlatformAdmin;

namespace WorkAI360.Api.Features.PlatformAdmin;

/// <summary>
/// The platform dashboard (the reference's <c>routes/admin/dashboard.ts</c>). <c>GET /v1/admin/dashboard</c> is 30 UTC days of AI gateway usage across
/// workspaces; this build has no gateway, so it answers the reference's shape with nothing recorded (what the reference answers on a deployment whose
/// gateway has served no requests). <c>GET /v1/admin/dashboard/active-users</c> counts real people from this database.
/// </summary>
public static class AdminDashboardEndpoints
{
    public static void MapAdminDashboardEndpoints(this WebApplication app)
    {
        app.MapGet("/v1/admin/dashboard", async (HttpContext ctx, PlatformAdminGuard guard) =>
        {
            var (_, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            ctx.Response.Headers.CacheControl = "no-store";
            var today = DateOnly.FromDateTime(DateTime.UtcNow);
            var from = today.AddDays(-29);
            static object Zero() => new { requests = 0, tokens = 0, costMicroUsd = 0, unreportedRequests = 0, unpricedRequests = 0 };
            return Results.Json(new
            {
                from = Day(from), to = Day(today), activeOrganizations = 0, totals = Zero(),
                daily = Enumerable.Range(0, 30).Select(i => new { date = Day(from.AddDays(i)), requests = 0, tokens = 0, costMicroUsd = 0, unreportedRequests = 0, unpricedRequests = 0 }),
                organizations = Array.Empty<object>(),
                generatedAt = AdminSupport.Iso(DateTime.UtcNow),
            });
        });

        app.MapGet("/v1/admin/dashboard/active-users", async (HttpContext ctx, PlatformAdminGuard guard, DenDbContext db) =>
        {
            var (_, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            ctx.Response.Headers.CacheControl = "no-store";
            var (todayCount, days7, days30) = await ActiveUsersAsync(db, DateTime.UtcNow);
            return Results.Json(new { today = todayCount, days7, days30, generatedAt = AdminSupport.Iso(DateTime.UtcNow) });
        });
    }

    /// <summary>
    /// Distinct people active today, in the last 7 and in the last 30 UTC calendar days, across every workspace. Activity is a sign-in (a session created)
    /// or a feature use a client reported (<c>POST /v1/org/feature-usage</c>), the closest this build has to the reference's telemetry events.
    /// </summary>
    public static async Task<(int Today, int Days7, int Days30)> ActiveUsersAsync(DenDbContext db, DateTime now)
    {
        var today = DateOnly.FromDateTime(now);
        var start = today.AddDays(-29).ToDateTime(TimeOnly.MinValue, DateTimeKind.Utc);
        var end = today.AddDays(1).ToDateTime(TimeOnly.MinValue, DateTimeKind.Utc);
        var signIns = await db.Sessions.AsNoTracking().Where(s => s.CreatedAt >= start && s.CreatedAt < end).Select(s => new { s.UserId, s.CreatedAt }).ToListAsync();
        var fromDay = Day(today.AddDays(-29));
        var toDay = Day(today);
        // Day is "yyyy-MM-dd", so string order is date order.
        var uses = await (from u in db.Set<FeatureUsageDay>().AsNoTracking()
                          join m in db.Members.AsNoTracking() on u.MemberId equals m.Id
                          where string.Compare(u.Day, fromDay) >= 0 && string.Compare(u.Day, toDay) <= 0
                          select new { m.UserId, u.Day }).Distinct().ToListAsync();
        var activity = signIns.Select(s => (s.UserId, Day: DateOnly.FromDateTime(s.CreatedAt)))
            .Concat(uses.Select(u => (u.UserId, Day: DateOnly.ParseExact(u.Day, "yyyy-MM-dd", CultureInfo.InvariantCulture))))
            .ToList();
        int Since(DateOnly first) => activity.Where(a => a.Day >= first).Select(a => a.UserId).Distinct().Count();
        return (Since(today), Since(today.AddDays(-6)), Since(today.AddDays(-29)));
    }

    private static string Day(DateOnly day) => day.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
}
