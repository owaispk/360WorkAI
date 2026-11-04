using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.OAuthExtras;
using WorkAI360.Api.Domain.Onboarding;
using WorkAI360.Api.Domain.OrgAdmin;

namespace WorkAI360.Api.Features.OrgAdmin;

public sealed class HousekeepingOptions
{
    public const string Section = "Housekeeping";

    /// <summary>Run the job at all (default on).</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>Minutes between runs (default 60); the first run starts this long after startup too.</summary>
    public int IntervalMinutes { get; set; } = 60;

    /// <summary>
    /// How long an expired row is kept before it is deleted (default 24 hours), so a code or link used just after it expired still gets its "expired"
    /// answer rather than "not found".
    /// </summary>
    public int GraceHours { get; set; } = 24;
}

/// <summary>What one run deleted, per kind.</summary>
public sealed record HousekeepingResult(IReadOnlyDictionary<string, int> Deleted);

/// <summary>
/// Deletes rows that can no longer do anything: expired sessions, sign-in and OAuth codes, refresh and agent tokens, handoff grants, DPoP bindings,
/// claim codes and finished rate-limit windows, a grace period after they expired; and, when <c>OrgAdmin:Audit:RetentionDays</c> is set, audit history
/// older than that. Each kind is one set-based delete, so a run is cheap and two instances running it at once do no harm. Invitations are kept (an expired
/// invitation still shows as expired, as in the reference); tables that already clean up after themselves (SSO, social and SAML states, connection
/// OAuth transactions, replay reservations, the request log) are left to their own code.
/// </summary>
public sealed class Housekeeping(IServiceScopeFactory scopes, IOptions<HousekeepingOptions> options, IOptions<OrgAdminOptions> admin, ILogger<Housekeeping> logger) : BackgroundService
{
    /// <summary>The longest rate-limit window any counter uses (a day); a window older than twice that is finished.</summary>
    private static readonly TimeSpan CounterWindow = TimeSpan.FromDays(2);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Value.Enabled) return;
        var interval = TimeSpan.FromMinutes(Math.Max(1, options.Value.IntervalMinutes));
        using var timer = new PeriodicTimer(interval);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                var result = await RunOnceAsync(DateTime.UtcNow, stoppingToken);
                if (result.Deleted.Values.Sum() > 0) logger.LogInformation("housekeeping deleted {Counts}", string.Join(", ", result.Deleted.Where(p => p.Value > 0).Select(p => $"{p.Key}={p.Value}")));
            }
            catch (Exception e) when (e is DbUpdateException or InvalidOperationException or Microsoft.Data.Sqlite.SqliteException or MySql.Data.MySqlClient.MySqlException)
            {
                logger.LogWarning(e, "housekeeping run failed; it will try again next time");
            }
        }
    }

    public async Task<HousekeepingResult> RunOnceAsync(DateTime now, CancellationToken ct = default)
    {
        await using var scope = scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<DenDbContext>();
        var expired = now - TimeSpan.FromHours(Math.Max(0, options.Value.GraceHours));
        var deleted = new Dictionary<string, int>
        {
            ["sessions"] = await db.Sessions.Where(s => s.ExpiresAt < expired).ExecuteDeleteAsync(ct),
            ["handoffGrants"] = await db.Set<DesktopHandoffGrant>().Where(g => g.ExpiresAt < expired).ExecuteDeleteAsync(ct),
            ["deviceCodes"] = await db.Set<DeviceCode>().Where(d => d.ExpiresAt < expired).ExecuteDeleteAsync(ct),
            ["authorizationCodes"] = await db.Set<AuthorizationCode>().Where(c => c.ExpiresAt < expired).ExecuteDeleteAsync(ct),
            ["refreshTokens"] = await db.Set<RefreshToken>().Where(t => t.ExpiresAt < expired).ExecuteDeleteAsync(ct),
            ["mcpAccessTokens"] = await db.Set<McpAccessToken>().Where(t => t.ExpiresAt < expired).ExecuteDeleteAsync(ct),
            ["emailCodes"] = await db.Set<EmailOtp>().Where(o => o.ExpiresAt < expired).ExecuteDeleteAsync(ct),
            ["passwordResetTokens"] = await db.Set<PasswordResetToken>().Where(t => t.ExpiresAt < expired).ExecuteDeleteAsync(ct),
            ["dpopBindings"] = await db.Set<OAuthDpopBinding>().Where(b => b.ExpiresAt < expired).ExecuteDeleteAsync(ct),
            ["claimCodes"] = await db.Set<WorkspaceClaimCode>().Where(c => c.ExpiresAt < expired).ExecuteDeleteAsync(ct),
        };
        var counterCutoff = new DateTimeOffset(now - CounterWindow).ToUnixTimeMilliseconds();
        deleted["rateLimitWindows"] = await db.Set<OnboardingRateLimit>().Where(r => r.WindowStart < counterCutoff).ExecuteDeleteAsync(ct);

        if (admin.Value.Audit.RetentionDays is int days && days > 0)
        {
            var cutoff = now - TimeSpan.FromDays(days);
            // Whole operations go together, so a kept operation never loses some of its events. Resource rows first: they point at events.
            var old = db.Set<AuditOperation>().Where(o => o.FirstRecordedAt < cutoff).Select(o => o.Id);
            deleted["auditResources"] = await db.Set<AuditEventResource>().Where(r => old.Contains(r.OperationId)).ExecuteDeleteAsync(ct);
            deleted["auditEvents"] = await db.Set<AuditEvent>().Where(e => old.Contains(e.OperationId)).ExecuteDeleteAsync(ct);
            deleted["auditOperations"] = await db.Set<AuditOperation>().Where(o => o.FirstRecordedAt < cutoff).ExecuteDeleteAsync(ct);
        }
        return new HousekeepingResult(deleted);
    }
}
