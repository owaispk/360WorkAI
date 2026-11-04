using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Automations;
using WorkAI360.Api.Features.OrgAdmin;

namespace WorkAI360.Api.Features.Automations;

/// <summary>
/// Audit events for Automations (the reference's <c>automations/audit.ts</c> and its route events). One job operation per run: <c>automation_run.started</c> when
/// the scheduler starts an occurrence, and one <c>automation_run.completed</c> for its end, whoever ended it (the in-Den Workflow executor, a desktop runner,
/// the scheduler's recovery, a skip, an immediate cancel). Never instructions, prompts, results, summaries or usage: only ids, the outcome and a reason code.
/// </summary>
public sealed class AutomationAudit(DenDbContext db, IAuditLog audit)
{
    public static readonly AuditActor Executor = new("system", "den-api.automation-executor");
    public static readonly AuditActor Scheduler = new("system", "den-api.automation-scheduler");
    private static readonly string[] Terminal = ["succeeded", "failed", "cancelled", "skipped"];

    /// <summary>A person's change to their Automation (or a run of it), through the routes.</summary>
    public Task ChangedAsync(OrgContext context, string action, string automationId, string? runId = null)
    {
        var resources = new List<AuditResource>();
        if (runId is not null) resources.Add(new("automation_run", runId, "target"));
        resources.Add(new("automation", automationId, runId is null ? "target" : "parent"));
        return audit.RecordAsync(context, new AuditEntry(action, resources, Category: action.StartsWith("automation.run.", StringComparison.Ordinal) ? "execution" : "change"));
    }

    /// <summary>The scheduler started an occurrence.</summary>
    public async Task StartedAsync(string runId)
    {
        var run = await LoadAsync(runId);
        if (run is null) return;
        await audit.RecordAsync(run.Value.OrganizationId, Scheduler, new AuditEntry("automation_run.started", Resources(run.Value), "execution", Origin: "scheduler"));
    }

    /// <summary>Records the end of a run, if it has ended. <paramref name="actor"/> is who reported it (the executor when not given).</summary>
    public async Task CompletedAsync(string runId, AuditActor? actor = null)
    {
        var run = await LoadAsync(runId);
        if (run is null || !Terminal.Contains(run.Value.Status)) return;
        var (outcome, reason) = Outcome(run.Value.Status, run.Value.ErrorCode);
        await audit.RecordAsync(run.Value.OrganizationId, actor ?? Executor,
            new AuditEntry("automation_run.completed", Resources(run.Value), "execution", outcome, ReasonCode: reason, Origin: run.Value.Trigger == "scheduled" ? "scheduler" : "api"));
    }

    /// <summary>succeeded is succeeded; failed, cancelled and skipped are failed. The reason is the status, or the error code (never a message).</summary>
    public static (string Outcome, string Reason) Outcome(string status, string? errorCode)
    {
        var outcome = status == "succeeded" ? "succeeded" : Terminal.Contains(status) ? "failed" : "unknown";
        var code = string.IsNullOrWhiteSpace(errorCode) ? null : errorCode;
        var reason = code is null || code == status ? status : status == "failed" ? code : $"{status}.{code}";
        return (outcome, reason);
    }

    private static List<AuditResource> Resources(RunRow run) =>
        [new("automation_run", run.RunId, "target"), new("automation", run.AutomationId, "parent")];

    private readonly record struct RunRow(string RunId, string AutomationId, string OrganizationId, string Trigger, string Status, string? ErrorCode);

    private async Task<RunRow?> LoadAsync(string runId)
    {
        var row = await (from r in db.Set<AutomationRun>().AsNoTracking()
                         join a in db.Set<Automation>().AsNoTracking() on r.AutomationId equals a.Id
                         where r.Id == runId
                         select new { r.Id, r.AutomationId, a.OrganizationId, r.Trigger, r.Status, r.ErrorJson }).FirstOrDefaultAsync();
        if (row is null) return null;
        string? code = null;
        if (row.ErrorJson is { } json)
        {
            try { code = JsonDocument.Parse(json).RootElement.TryGetProperty("code", out var c) && c.ValueKind == JsonValueKind.String ? c.GetString() : null; }
            catch (JsonException) { code = null; }
        }
        return new RunRow(row.Id, row.AutomationId, row.OrganizationId, row.Trigger, row.Status, code);
    }

    /// <summary>The run's owner, as the actor of a desktop runner's report.</summary>
    public async Task<AuditActor?> OwnerActorAsync(string organizationId, string memberId)
    {
        var userId = await db.Members.AsNoTracking().Where(m => m.Id == memberId && m.OrganizationId == organizationId).Select(m => m.UserId).FirstOrDefaultAsync();
        return userId is null ? null : AuditActor.User(userId, memberId);
    }
}
