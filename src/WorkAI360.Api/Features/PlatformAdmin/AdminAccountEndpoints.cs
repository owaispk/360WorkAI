using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.OrgAdmin;
using WorkAI360.Api.Domain.PlatformAdmin;
using WorkAI360.Api.Domain.Sso;
using WorkAI360.Api.Features.OrgAdmin;

namespace WorkAI360.Api.Features.PlatformAdmin;

/// <summary>People on the deployment, as the operator sees them: the overview, the user list, deleting a user, the metrics, and who the platform admins are.</summary>
public static partial class AdminAccountEndpoints
{
    [GeneratedRegex(@"^(?!\.)(?!.*\.\.)([A-Za-z0-9_'+\-\.]*)[A-Za-z0-9_+-]@([A-Za-z0-9][A-Za-z0-9\-]*\.)+[A-Za-z]{2,}$")]
    private static partial Regex EmailPattern();

    private const string NoBillingNote = "No cached organization subscription covers this user.";

    public static void MapAdminAccountEndpoints(this WebApplication app)
    {
        app.MapGet("/v1/admin/overview", async (HttpContext ctx, PlatformAdminGuard guard, DenDbContext db) =>
        {
            var (admin, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            var (limit, offset, search) = AdminSupport.Page(ctx.Request.Query);
            var watch = Stopwatch.StartNew();
            var page = await UserPageAsync(db, limit, offset, search, includeBilling: false);
            var admins = await AdminListAsync(db);
            var organizationTotal = await db.Organizations.CountAsync();
            return Results.Json(new
            {
                viewer = new { id = admin!.User.Id, email = PlatformAdmins.Normalize(admin.User.Email), name = admin.User.Name },
                admins,
                organizations = Array.Empty<object>(),
                organizationPage = AdminSupport.PageInfo(limit, 0, "", organizationTotal, 0, 0),
                summary = Summary(page.Total, organizationTotal, admins.Count),
                users = page.Users,
                userPage = AdminSupport.PageInfo(limit, offset, search, page.Total, page.Users.Count, watch.ElapsedMilliseconds),
                generatedAt = AdminSupport.Iso(DateTime.UtcNow),
            });
        });

        app.MapGet("/v1/admin/users", async (HttpContext ctx, PlatformAdminGuard guard, DenDbContext db) =>
        {
            var (_, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            var (limit, offset, search) = AdminSupport.Page(ctx.Request.Query);
            var billing = ctx.Request.Query["includeBilling"].ToString().Trim().ToLowerInvariant() is "1" or "true" or "yes";
            var watch = Stopwatch.StartNew();
            var page = await UserPageAsync(db, limit, offset, search, billing);
            return Results.Json(new
            {
                users = page.Users,
                page = AdminSupport.PageInfo(limit, offset, search, page.Total, page.Users.Count, watch.ElapsedMilliseconds),
                billing = billing ? new { loaded = true, paidUsers = (int?)0, unpaidUsers = (int?)page.Users.Count, billingUnavailableUsers = (int?)0 } : new { loaded = false, paidUsers = (int?)null, unpaidUsers = (int?)null, billingUnavailableUsers = (int?)null },
                generatedAt = AdminSupport.Iso(DateTime.UtcNow),
            });
        });

        app.MapGet("/v1/admin/metrics", async (HttpContext ctx, PlatformAdminGuard guard, DenDbContext db) =>
        {
            var (_, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            return Results.Json(new { summary = await MetricsAsync(db), generatedAt = AdminSupport.Iso(DateTime.UtcNow) });
        });

        app.MapPost("/v1/admin/admins", async (HttpContext ctx, PlatformAdminGuard guard, DenDbContext db) =>
        {
            var (_, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            var body = await AdminBody.ReadAsync(ctx);
            if (AdminBody.NotObject(body) is { } notObject) return AdminSupport.Invalid(notObject);
            var root = body!.Value;
            var emailValue = AdminBody.Get(root, "email");
            if (emailValue is not { ValueKind: JsonValueKind.String } e) return AdminSupport.Invalid($"Invalid input: expected string, received {AdminBody.Kind(emailValue)}");
            var email = e.GetString()!.Trim();
            if (email.Length > 255) return AdminSupport.Invalid("Too big: expected string to have <=255 characters");
            if (!EmailPattern().IsMatch(email)) return AdminSupport.Invalid("Invalid email address");
            string? note = null;
            if (AdminBody.Get(root, "note") is { ValueKind: not JsonValueKind.Null } noteValue)
            {
                if (noteValue.ValueKind != JsonValueKind.String) return AdminSupport.Invalid($"Invalid input: expected string, received {AdminBody.Kind(noteValue)}");
                note = noteValue.GetString()!;
                if (note.Length > 255) return AdminSupport.Invalid("Too big: expected string to have <=255 characters");
            }
            email = email.ToLowerInvariant();
            var now = DateTime.UtcNow;
            var entry = new AdminAllowlistEntry { Id = Ids.New("aal"), Email = email, Note = note, CreatedAt = now, UpdatedAt = now };
            db.Set<AdminAllowlistEntry>().Add(entry);
            try { await db.SaveChangesAsync(); }
            catch (DbUpdateException)
            {
                db.Entry(entry).State = EntityState.Detached;
                if (await db.Set<AdminAllowlistEntry>().AnyAsync(a => a.Email == email))
                    return Results.Json(new { error = "conflict", message = $"An admin with email {email} already exists." }, statusCode: 409);
                throw;
            }
            return Results.Json(new { ok = true, admin = new { id = entry.Id, email, note, createdAt = AdminSupport.Iso(now) } });
        });

        app.MapDelete("/v1/admin/admins/{adminId}", async (string adminId, HttpContext ctx, PlatformAdminGuard guard, DenDbContext db) =>
        {
            var (admin, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            if (!AdminSupport.IsTypeId("aal", adminId)) return AdminSupport.Invalid("Invalid admin id.");
            var viewer = PlatformAdmins.Normalize(admin!.User.Email);
            await using var tx = await db.Database.BeginTransactionAsync();
            // Locks the whole list (the writer lock on SQLite, every row on MySQL), so two admins removing each other cannot both succeed and leave no admin.
            await db.Database.ExecuteSqlAsync($"UPDATE `AdminAllowlistEntry` SET `Email` = `Email`");
            var all = await db.Set<AdminAllowlistEntry>().ToListAsync();
            var target = all.FirstOrDefault(a => a.Id == adminId);
            if (target is null) return AdminSupport.NotFound("Admin not found.");
            if (PlatformAdmins.Normalize(target.Email) == viewer) return AdminSupport.Invalid("You cannot delete your own admin access.");
            if (all.Count == 1) return AdminSupport.Invalid("You cannot delete the final admin.");
            db.Set<AdminAllowlistEntry>().Remove(target);
            await db.SaveChangesAsync();
            await tx.CommitAsync();
            return Results.Json(new { ok = true });
        });

        app.MapDelete("/v1/admin/users/{userId}", async (string userId, HttpContext ctx, PlatformAdminGuard guard, DenDbContext db, IAuditLog audit) =>
        {
            var (admin, failure) = await guard.RequireAsync(ctx);
            if (failure is not null) return failure;
            if (!AdminSupport.IsTypeId("usr", userId)) return AdminSupport.Invalid("Invalid user id.");
            if (userId == admin!.User.Id) return AdminSupport.Invalid("You cannot delete your own admin user.");
            var target = await db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == userId);
            if (target is null) return AdminSupport.NotFound("User not found.");

            var members = await db.Members.AsNoTracking().Where(m => m.UserId == userId).ToListAsync();
            var sessions = await db.Sessions.AsNoTracking().Where(s => s.UserId == userId).ToListAsync();
            var memberIds = members.Select(m => m.Id).ToList();
            await using (var tx = await db.Database.BeginTransactionAsync())
            {
                await db.RefreshTokens.Where(t => t.UserId == userId).ExecuteDeleteAsync();
                await db.OAuthConsents.Where(c => c.UserId == userId).ExecuteDeleteAsync();
                await db.McpAccessTokens.Where(t => t.UserId == userId).ExecuteDeleteAsync();
                await db.AuthorizationCodes.Where(c => c.UserId == userId).ExecuteDeleteAsync();
                await db.DeviceCodes.Where(d => d.UserId == userId).ExecuteDeleteAsync();
                await db.HandoffGrants.Where(g => g.UserId == userId).ExecuteDeleteAsync();
                await db.PasswordResetTokens.Where(t => t.UserId == userId).ExecuteDeleteAsync();
                await db.Set<ApiKey>().Where(k => k.UserId == userId).ExecuteDeleteAsync();
                await db.Set<ExternalAccount>().Where(a => a.UserId == userId).ExecuteDeleteAsync();
                await db.Set<ScimSyncEvent>().Where(e => e.UserId == userId).ExecuteDeleteAsync();
                await db.Sessions.Where(s => s.UserId == userId).ExecuteDeleteAsync();
                await db.TeamMembers.Where(t => memberIds.Contains(t.MemberId)).ExecuteDeleteAsync();
                await db.Members.Where(m => m.UserId == userId).ExecuteDeleteAsync();
                await db.EmailOtps.Where(o => o.Email == target.Email).ExecuteDeleteAsync();
                var removed = await db.Users.Where(u => u.Id == userId).ExecuteDeleteAsync();
                if (removed == 0) return AdminSupport.NotFound("User not found.");
                await tx.CommitAsync();
            }

            // Each workspace the person belonged to records the removal (by this admin, origin platform_admin) and the sessions that ended.
            var actor = AuditActor.User(admin.User.Id);
            foreach (var member in members)
            {
                var entries = new List<AuditEntry>
                {
                    new(AuditActions.MemberRemoved, [new("member", member.Id), new("user", userId, "related"), new("organization", member.OrganizationId, "parent")],
                        Before: new() { ["role"] = member.Role, ["userId"] = userId }, ReasonCode: "user_deleted", Origin: "platform_admin"),
                };
                entries.AddRange(sessions.Where(s => s.ExpiresAt > DateTime.UtcNow).Select(s =>
                    new AuditEntry(AuditActions.SessionRevoked, [new("session", s.Id), new("member", member.Id, "related")], "security", ReasonCode: "admin_user_deleted", Origin: "platform_admin")));
                await audit.RecordAsync(member.OrganizationId, actor, entries.ToArray());
            }
            return Results.Json(new { ok = true, user = new { id = target.Id, email = target.Email } });
        });
    }

    private static async Task<List<object>> AdminListAsync(DenDbContext db) =>
        (await db.Set<AdminAllowlistEntry>().AsNoTracking().OrderBy(a => a.Email).ToListAsync())
        .Select(a => (object)new { id = a.Id, email = a.Email, note = a.Note, createdAt = AdminSupport.Iso(a.CreatedAt) }).ToList();

    private sealed record UserPage(int Total, List<object> Users);

    private static async Task<UserPage> UserPageAsync(DenDbContext db, int limit, int offset, string search, bool includeBilling)
    {
        var query = db.Users.AsNoTracking().AsQueryable();
        if (search.Length > 0)
        {
            var normalized = search.ToLowerInvariant();
            if (Regex.IsMatch(normalized, @"^[^@\s]+@[^@\s]+\.[^@\s]+$")) query = query.Where(u => u.Email == normalized);
            else
            {
                var pattern = AdminSupport.LikePattern(search);
                query = query.Where(u => EF.Functions.Like(u.Name.ToLower(), pattern, "|") || EF.Functions.Like(u.Email.ToLower(), pattern, "|") || EF.Functions.Like(u.Id.ToLower(), pattern, "|")
                    || (from m in db.Members join o in db.Organizations on m.OrganizationId equals o.Id
                        where m.UserId == u.Id && (EF.Functions.Like(o.Name.ToLower(), pattern, "|") || EF.Functions.Like(o.Id.ToLower(), pattern, "|") || EF.Functions.Like(m.Role.ToLower(), pattern, "|"))
                        select m.Id).Any());
            }
        }
        var total = await query.CountAsync();
        var rows = await query.OrderByDescending(u => u.CreatedAt).ThenByDescending(u => u.Id).Skip(offset).Take(limit).ToListAsync();
        var ids = rows.Select(u => u.Id).ToList();

        var since = DateTime.UtcNow.AddDays(-90);
        var sessions = (await db.Sessions.AsNoTracking().Where(s => ids.Contains(s.UserId)).Select(s => new { s.UserId, s.CreatedAt, s.UpdatedAt }).ToListAsync()).GroupBy(s => s.UserId).ToDictionary(g => g.Key);
        var memberships = (await (from m in db.Members.AsNoTracking() join o in db.Organizations.AsNoTracking() on m.OrganizationId equals o.Id where ids.Contains(m.UserId)
                                  select new { m.UserId, OrganizationId = o.Id, o.Name, m.Role, m.JoinedAt, m.CreatedAt }).ToListAsync()).GroupBy(m => m.UserId).ToDictionary(g => g.Key);
        var orgIds = memberships.Values.SelectMany(g => g).Select(m => m.OrganizationId).Distinct().ToList();
        var memberCounts = (await db.Members.AsNoTracking().Where(m => orgIds.Contains(m.OrganizationId)).GroupBy(m => m.OrganizationId).Select(g => new { Id = g.Key, Count = g.Count() }).ToListAsync()).ToDictionary(g => g.Id, g => g.Count);
        var external = (await db.Set<ExternalAccount>().AsNoTracking().Where(a => ids.Contains(a.UserId)).Select(a => a.UserId).Distinct().ToListAsync()).ToHashSet();
        var invites = (await db.Invitations.AsNoTracking().Where(i => ids.Contains(i.InvitedByUserId)).GroupBy(i => i.InvitedByUserId).Select(g => new { UserId = g.Key, Count = g.Count(), First = g.Min(i => i.CreatedAt) }).ToListAsync()).ToDictionary(g => g.UserId);

        var users = rows.Select(u =>
        {
            var userSessions = sessions.GetValueOrDefault(u.Id)?.ToList() ?? [];
            var lastSeen = userSessions.Count == 0 ? (DateTime?)null : userSessions.Max(s => s.UpdatedAt);
            var activeDays = userSessions.Where(s => s.CreatedAt >= since).Select(s => s.CreatedAt.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)).Distinct().Count();
            invites.TryGetValue(u.Id, out var invite);
            double? hours = invite is null ? null : Math.Max(0, Math.Round((invite.First - u.CreatedAt).TotalHours * 10) / 10);
            var providers = new List<string>();
            if (u.PasswordHash.Length > 0) providers.Add("email");
            if (external.Contains(u.Id)) providers.Add("sso");
            return (object)new Dictionary<string, object?>
            {
                ["id"] = u.Id, ["name"] = u.Name, ["email"] = u.Email, ["emailVerified"] = u.EmailVerified, ["createdAt"] = AdminSupport.Iso(u.CreatedAt), ["updatedAt"] = AdminSupport.Iso(u.UpdatedAt),
                ["lastSeenAt"] = lastSeen?.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture), ["sessionCount"] = userSessions.Count, ["activeDayCount"] = activeDays, ["isRecurring"] = activeDays >= 2,
                ["lastActiveAt"] = lastSeen is { } l ? AdminSupport.Iso(l) : null, ["invitesSent"] = invite?.Count ?? 0, ["firstInviteAt"] = invite is null ? null : AdminSupport.Iso(invite.First),
                ["hoursToFirstInvite"] = hours, ["authProviders"] = providers.Order(StringComparer.Ordinal).ToList(),
                ["workerCount"] = 0, ["cloudWorkerCount"] = 0, ["localWorkerCount"] = 0, ["latestWorkerCreatedAt"] = null,
                ["billing"] = includeBilling ? new { status = "unpaid", featureGateEnabled = false, subscriptionId = (string?)null, subscriptionStatus = (string?)null, currentPeriodEnd = (string?)null, source = "subscription", note = NoBillingNote } : null,
                ["organizations"] = (memberships.GetValueOrDefault(u.Id)?.OrderBy(m => m.Name, StringComparer.CurrentCulture).ToList() ?? []).Select(m =>
                    new { id = m.OrganizationId, name = m.Name, role = m.Role, memberCount = memberCounts.GetValueOrDefault(m.OrganizationId), joinedAt = AdminSupport.Iso(m.JoinedAt ?? m.CreatedAt) }).ToList(),
            };
        }).ToList();
        return new UserPage(total, users);
    }

    /// <summary>The summary before the heavy numbers are loaded (the overview): totals only.</summary>
    private static object Summary(int users, int organizations, int admins) => new
    {
        totalUsers = users, totalOrganizations = organizations, verifiedUsers = (int?)null, recentUsers7d = (int?)null, recentUsers30d = (int?)null, totalWorkers = (int?)null,
        cloudWorkers = (int?)null, localWorkers = (int?)null, usersWithWorkers = (int?)null, usersWithoutWorkers = (int?)null, paidUsers = (int?)null, unpaidUsers = (int?)null,
        billingUnavailableUsers = (int?)null, adminCount = admins, billingLoaded = false, activeUsers1d = (int?)null, activeUsers7d = (int?)null, activeUsers30d = (int?)null,
        realActiveUsers1d = (int?)null, realActiveUsers7d = (int?)null, realActiveUsers30d = (int?)null, recurringUsers = (int?)null, inviters = (int?)null,
        medianHoursToFirstInvite = (double?)null, activitySeries = Array.Empty<object>(),
    };

    /// <summary>
    /// Counts computed from this database. "Active" means a sign-in (a session created) on that UTC day; there is no product telemetry here, so the real-active
    /// figures are 0, and there are no workers or billing.
    /// </summary>
    private static async Task<object> MetricsAsync(DenDbContext db)
    {
        var now = DateTime.UtcNow;
        var today = DateOnly.FromDateTime(now);
        var users = await db.Users.AsNoTracking().Select(u => new { u.Id, u.EmailVerified, u.CreatedAt }).ToListAsync();
        var organizations = await db.Organizations.CountAsync();
        var admins = await db.Set<AdminAllowlistEntry>().CountAsync();
        var ninety = now.AddDays(-90);
        var sessions = await db.Sessions.AsNoTracking().Where(s => s.CreatedAt >= ninety).Select(s => new { s.UserId, s.CreatedAt }).ToListAsync();
        var daysByUser = sessions.GroupBy(s => s.UserId).ToDictionary(g => g.Key, g => g.Select(s => DateOnly.FromDateTime(s.CreatedAt)).ToHashSet());
        var signups = users.GroupBy(u => DateOnly.FromDateTime(u.CreatedAt)).ToDictionary(g => g.Key, g => g.Count());
        var series = Enumerable.Range(0, 30).Select(i => today.AddDays(i - 29)).Select(day => new
        {
            day = day.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
            activeUsers = daysByUser.Count(p => p.Value.Contains(day)), realActiveUsers = 0, signups = signups.GetValueOrDefault(day),
        }).ToList();
        int Active(int days) => daysByUser.Count(p => p.Value.Any(d => d >= today.AddDays(1 - days)));
        var firstInvite = await db.Invitations.AsNoTracking().GroupBy(i => i.InvitedByUserId).Select(g => new { UserId = g.Key, First = g.Min(i => i.CreatedAt) }).ToListAsync();
        var created = users.ToDictionary(u => u.Id, u => u.CreatedAt);
        var hours = firstInvite.Where(f => created.ContainsKey(f.UserId)).Select(f => Math.Max(0, Math.Round((f.First - created[f.UserId]).TotalHours * 10) / 10)).Order().ToList();
        double? median = hours.Count == 0 ? null : hours.Count % 2 == 0 ? (hours[hours.Count / 2 - 1] + hours[hours.Count / 2]) / 2 : hours[hours.Count / 2];
        return new
        {
            totalUsers = users.Count, totalOrganizations = organizations, verifiedUsers = users.Count(u => u.EmailVerified), recentUsers7d = users.Count(u => u.CreatedAt >= now.AddDays(-7)),
            recentUsers30d = users.Count(u => u.CreatedAt >= now.AddDays(-30)), totalWorkers = 0, cloudWorkers = 0, localWorkers = 0, usersWithWorkers = 0, usersWithoutWorkers = users.Count,
            paidUsers = (int?)null, unpaidUsers = (int?)null, billingUnavailableUsers = (int?)null, adminCount = admins, billingLoaded = false,
            activeUsers1d = Active(1), activeUsers7d = Active(7), activeUsers30d = Active(30), realActiveUsers1d = 0, realActiveUsers7d = 0, realActiveUsers30d = 0,
            recurringUsers = daysByUser.Count(p => p.Value.Count >= 2), inviters = firstInvite.Count(f => created.ContainsKey(f.UserId)), medianHoursToFirstInvite = median, activitySeries = series,
        };
    }
}
