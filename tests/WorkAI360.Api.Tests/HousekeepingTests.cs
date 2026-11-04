using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.Onboarding;
using WorkAI360.Api.Domain.OrgAdmin;
using WorkAI360.Api.Features.OrgAdmin;

namespace WorkAI360.Api.Tests;

/// <summary>Audit history kept for 30 days.</summary>
public sealed class HousekeepingRetentionFactory : ApiFactory
{
    protected override IEnumerable<KeyValuePair<string, string>> Settings => [new("OrgAdmin:Audit:RetentionDays", "30")];
}

public sealed class HousekeepingTests(HousekeepingRetentionFactory factory) : IClassFixture<HousekeepingRetentionFactory>
{
    private Task<HousekeepingResult> RunAsync(DateTime now) => factory.Services.GetRequiredService<Housekeeping>().RunOnceAsync(now);

    private static Session NewSession(string userId, DateTime expiresAt) =>
        new() { Id = Ids.New("ses"), TokenHash = Guid.NewGuid().ToString("N"), UserId = userId, Method = "email", CreatedAt = expiresAt.AddDays(-7), UpdatedAt = expiresAt.AddDays(-7), ExpiresAt = expiresAt };

    [Fact]
    public async Task Expired_rows_go_after_the_grace_period_and_live_ones_stay()
    {
        var w = await Workspace.CreateAsync(factory);
        var now = DateTime.UtcNow;
        var ids = factory.WithDb(db =>
        {
            var gone = NewSession(w.Owner.UserId, now.AddDays(-2));
            var justExpired = NewSession(w.Owner.UserId, now.AddHours(-1));
            db.Sessions.AddRange(gone, justExpired);
            var oldCode = new DeviceCode { Id = Ids.New("dvc"), DeviceCodeHash = Guid.NewGuid().ToString("N"), UserCode = "OLD-" + Guid.NewGuid().ToString("N")[..6], ClientId = "c", Status = DeviceStatus.Pending, ExpiresAt = now.AddDays(-3) };
            var liveCode = new DeviceCode { Id = Ids.New("dvc"), DeviceCodeHash = Guid.NewGuid().ToString("N"), UserCode = "NEW-" + Guid.NewGuid().ToString("N")[..6], ClientId = "c", Status = DeviceStatus.Pending, ExpiresAt = now.AddMinutes(10) };
            db.Set<DeviceCode>().AddRange(oldCode, liveCode);
            var oldWindow = new OnboardingRateLimit { Id = Ids.New("orl"), Key = "test:old:" + Guid.NewGuid(), Count = 3, WindowStart = new DateTimeOffset(now.AddDays(-3)).ToUnixTimeMilliseconds() };
            var liveWindow = new OnboardingRateLimit { Id = Ids.New("orl"), Key = "test:live:" + Guid.NewGuid(), Count = 3, WindowStart = new DateTimeOffset(now.AddMinutes(-5)).ToUnixTimeMilliseconds() };
            db.Set<OnboardingRateLimit>().AddRange(oldWindow, liveWindow);
            db.SaveChanges();
            return (gone.Id, justExpired.Id, oldCode.Id, liveCode.Id, oldWindow.Id, liveWindow.Id);
        });

        var result = await RunAsync(now);
        Assert.True(result.Deleted["sessions"] >= 1);
        factory.WithDb(db =>
        {
            Assert.False(db.Sessions.Any(s => s.Id == ids.Item1));
            Assert.True(db.Sessions.Any(s => s.Id == ids.Item2)); // inside the grace period
            Assert.False(db.Set<DeviceCode>().Any(d => d.Id == ids.Item3));
            Assert.True(db.Set<DeviceCode>().Any(d => d.Id == ids.Item4));
            Assert.False(db.Set<OnboardingRateLimit>().Any(r => r.Id == ids.Item5));
            Assert.True(db.Set<OnboardingRateLimit>().Any(r => r.Id == ids.Item6));
            return 0;
        });
        // The owner's own live session still works.
        Assert.Equal(HttpStatusCode.OK, (await w.Http.SendAsync(w.As(w.Owner, HttpMethod.Get, "/v1/org"))).StatusCode);
    }

    [Fact]
    public async Task Audit_history_older_than_the_retention_goes_as_whole_operations_and_newer_history_stays_in_every_workspace()
    {
        var a = await Workspace.CreateAsync(factory, "Alpha");
        var b = await Workspace.CreateAsync(factory, "Beta");
        foreach (var w in new[] { a, b })
            foreach (var name in new[] { "old", "recent" })
                Assert.True((await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/api-keys", new { name })).Status is HttpStatusCode.Created or HttpStatusCode.OK);
        var now = DateTime.UtcNow;
        // Backdate the "old" key's operation in Alpha to 40 days ago and the "recent" ones to 29 days ago (inside the 30-day window).
        var (oldOperation, keptA, keptB) = factory.WithDb(db =>
        {
            string Op(string org, int index) => db.Set<AuditEvent>().Where(e => e.OrganizationId == org && e.Action == AuditActions.ApiKeyCreated).OrderBy(e => e.RecordedAt).Select(e => e.OperationId).ToList()[index];
            var old = Op(a.OrgId, 0);
            var recentA = Op(a.OrgId, 1);
            var recentB = Op(b.OrgId, 1);
            var oldB = Op(b.OrgId, 0);
            void Age(string op, DateTime at, DateTime? eventsAt = null)
            {
                db.Set<AuditOperation>().Where(o => o.Id == op).ExecuteUpdate(u => u.SetProperty(o => o.FirstRecordedAt, at));
                db.Set<AuditEvent>().Where(e => e.OperationId == op).ExecuteUpdate(u => u.SetProperty(e => e.RecordedAt, eventsAt ?? at));
            }
            // The old operation started before the cutoff; its events are dated inside the window: the whole operation still goes.
            Age(old, now.AddDays(-40), now.AddDays(-29));
            Age(recentA, now.AddDays(-29));
            Age(recentB, now.AddDays(-29));
            Age(oldB, now.AddDays(-29));
            return (old, recentA, recentB);
        });

        var result = await RunAsync(now);
        Assert.True(result.Deleted["auditOperations"] >= 1);
        factory.WithDb(db =>
        {
            Assert.False(db.Set<AuditOperation>().Any(o => o.Id == oldOperation));
            Assert.False(db.Set<AuditEvent>().Any(e => e.OperationId == oldOperation));
            Assert.False(db.Set<AuditEventResource>().Any(r => r.OperationId == oldOperation));
            foreach (var kept in new[] { keptA, keptB })
            {
                Assert.True(db.Set<AuditOperation>().Any(o => o.Id == kept));
                Assert.True(db.Set<AuditEvent>().Any(e => e.OperationId == kept));
                Assert.True(db.Set<AuditEventResource>().Any(r => r.OperationId == kept));
            }
            Assert.Equal(2, db.Set<AuditEvent>().Count(e => e.OrganizationId == b.OrgId && e.Action == AuditActions.ApiKeyCreated));
            return 0;
        });
        // History that remains still reads back.
        var page = await a.CallAsync(a.Owner, HttpMethod.Get, "/v1/audit/operations");
        Assert.Equal(HttpStatusCode.OK, page.Status);
    }
}

/// <summary>No retention configured: audit history is never deleted, as in the reference.</summary>
public sealed class HousekeepingNoRetentionTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    [Fact]
    public async Task Without_a_retention_setting_no_audit_history_is_deleted()
    {
        var w = await Workspace.CreateAsync(factory);
        Assert.True((await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/api-keys", new { name = "ancient" })).Status is HttpStatusCode.Created or HttpStatusCode.OK);
        factory.WithDb(db => db.Set<AuditOperation>().Where(o => o.OrganizationId == w.OrgId).ExecuteUpdate(u => u.SetProperty(o => o.FirstRecordedAt, DateTime.UtcNow.AddYears(-5))));
        var result = await factory.Services.GetRequiredService<Housekeeping>().RunOnceAsync(DateTime.UtcNow);
        Assert.False(result.Deleted.ContainsKey("auditOperations"));
        Assert.True(factory.WithDb(db => db.Set<AuditOperation>().Any(o => o.OrganizationId == w.OrgId)));
    }
}
