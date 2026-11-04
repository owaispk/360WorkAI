using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using WorkAI360.Api.Domain.Automations;
using WorkAI360.Api.Domain.OrgAdmin;
using WorkAI360.Api.Domain.Workspace;
using WorkAI360.Api.Features.Automations;

namespace WorkAI360.Api.Tests;

/// <summary>Workflows and Automations together: the scheduler off (ticks are driven by the test) and the headless runtime configured, so cloud Automations are allowed.</summary>
public sealed class WorkflowAutomationFactory : WorkspaceFactory
{
    protected override IEnumerable<KeyValuePair<string, string>> Extra =>
        [new("Automations:SchedulerEnabled", "false"), new("Policy:HeadlessRunnerConfigured", "true")];

    public async Task<List<string>> TickAsync(long? now = null)
    {
        using var scope = Services.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<AutomationTicker>().TickAsync(now);
    }
}

/// <summary>Automations whose action is a saved Workflow version: validated like the reference, run in Den on the cloud target, audited.</summary>
public sealed class WorkflowAutomationTests(WorkflowAutomationFactory factory) : IClassFixture<WorkflowAutomationFactory>
{
    private static readonly object Daily9 = new { kind = "daily", timezone = "UTC", hour = 9, minute = 0 };

    private static object Action(Seeded wf, string? versionId = null, object? input = null) => new
    {
        kind = "saved_script",
        script = new { pluginId = wf.PluginId, configObjectId = wf.Id, configObjectVersionId = versionId ?? wf.VersionId },
        input = input ?? new { n = 3 },
    };

    private static Task<(HttpStatusCode Status, JsonElement Body)> CreateAsync(Workspace w, Person p, object action, string name = "Nightly doubling") =>
        w.CallAsync(p, HttpMethod.Post, "/v1/cloud-automations", new { name, schedule = Daily9, action });

    private static async Task<string> CreatedAsync(Workspace w, Person p, object action)
    {
        var r = await CreateAsync(w, p, action);
        Assert.True(r.Status == HttpStatusCode.Created, $"{r.Status} {r.Body}");
        return r.Body.GetProperty("automation").GetProperty("id").GetString()!;
    }

    private static async Task<string> RunNowAsync(Workspace w, Person p, string id)
    {
        var r = await w.CallAsync(p, HttpMethod.Post, $"/v1/automations/{id}/run", new { });
        Assert.True(r.Status == HttpStatusCode.Accepted, $"{r.Status} {r.Body}");
        return r.Body.GetProperty("run").GetProperty("id").GetString()!;
    }

    private AutomationRun Run(string id) => factory.WithDb(db => db.Set<AutomationRun>().AsNoTracking().First(r => r.Id == id));

    private List<string> AuditActions(string orgId) => factory.WithDb(db => db.Set<AuditEvent>().AsNoTracking().Where(e => e.OrganizationId == orgId).Select(e => e.Action).ToList());

    [Fact]
    public async Task A_Workflow_Automation_runs_in_Den_records_a_receipt_for_the_run_and_is_audited()
    {
        var w = await Workspace.CreateAsync(factory);
        var wf = await w.WorkflowAsync(w.Owner);
        var id = await CreatedAsync(w, w.Owner, Action(wf));
        var runId = await RunNowAsync(w, w.Owner, id);
        Assert.Equal("queued", Run(runId).Status);

        await factory.TickAsync();
        var run = Run(runId);
        Assert.Equal("succeeded", run.Status);
        Assert.Equal(WorkflowActions.EngineKind, run.EngineKind);
        Assert.Equal(6, JsonDocument.Parse(run.ResultSummary!).RootElement.GetProperty("doubled").GetInt32());
        Assert.Null(run.ErrorJson);
        Assert.Null(run.LeaseExpiresAt);

        // The receipt names the Automation run and is readable under the Workflow's standing source, as a manual run.
        var receipt = factory.WithDb(db => db.Set<WorkflowRun>().AsNoTracking().Single(r => r.AutomationRunId == runId));
        Assert.Equal("succeeded", receipt.Status);
        Assert.Equal(wf.VersionId, receipt.ConfigObjectVersionId);
        var snapshots = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/workflows/{wf.Id}/snapshots");
        var item = snapshots.Body.GetProperty("items").EnumerateArray().Single(i => i.GetProperty("receiptId").GetString() == receipt.Id);
        Assert.Equal("manual", item.GetProperty("source").GetString());

        var actions = AuditActions(w.OrgId);
        Assert.Contains("automation.cloud.create", actions);
        Assert.Contains("automation.run.start", actions);
        Assert.Single(actions, a => a == "automation_run.completed");
        var completed = factory.WithDb(db => db.Set<AuditEvent>().AsNoTracking().Single(e => e.OrganizationId == w.OrgId && e.Action == "automation_run.completed").EnvelopeJson);
        Assert.Contains("\"succeeded\"", completed);
        Assert.DoesNotContain("doubled", completed); // never the result

        // A second tick finds nothing to do: the run is never executed twice.
        await factory.TickAsync();
        Assert.Equal(1, factory.WithDb(db => db.Set<WorkflowRun>().Count(r => r.AutomationRunId == runId)));
    }

    [Fact]
    public async Task Scheduled_occurrences_start_and_finish_in_one_tick_and_two_ticks_at_once_run_it_once()
    {
        var w = await Workspace.CreateAsync(factory);
        var wf = await w.WorkflowAsync(w.Owner);
        var id = await CreatedAsync(w, w.Owner, Action(wf));
        var due = factory.WithDb(db => db.Set<Automation>().AsNoTracking().First(a => a.Id == id).NextDueAt!.Value);
        await Task.WhenAll(factory.TickAsync(due + 1000), factory.TickAsync(due + 1000));
        var runs = factory.WithDb(db => db.Set<AutomationRun>().AsNoTracking().Where(r => r.AutomationId == id).ToList());
        var run = Assert.Single(runs);
        Assert.Equal("scheduled", run.Trigger);
        Assert.Equal("succeeded", run.Status);
        Assert.Equal(1, factory.WithDb(db => db.Set<WorkflowRun>().Count(r => r.AutomationRunId == run.Id)));
        Assert.Contains("automation_run.started", AuditActions(w.OrgId));
    }

    [Fact]
    public async Task A_run_another_instance_took_is_never_executed_again()
    {
        var w = await Workspace.CreateAsync(factory);
        var wf = await w.WorkflowAsync(w.Owner);
        var runId = await RunNowAsync(w, w.Owner, await CreatedAsync(w, w.Owner, Action(wf)));
        async Task<bool> RunOnce()
        {
            using var scope = factory.Services.CreateScope();
            return await scope.ServiceProvider.GetRequiredService<WorkflowActions>().RunOneAsync(runId, CancellationToken.None);
        }
        // Two instances that both listed the run as queued: the first takes it, the second finds nothing to take.
        Assert.True(await RunOnce());
        Assert.False(await RunOnce());
        Assert.Equal(1, factory.WithDb(db => db.Set<WorkflowRun>().Count(r => r.AutomationRunId == runId)));
        Assert.Equal(1, Run(runId).AttemptCount);
        Assert.Single(AuditActions(w.OrgId), a => a == "automation_run.completed");
    }

    [Fact]
    public async Task The_owner_needs_run_access_a_real_version_and_input_that_fits()
    {
        var w = await Workspace.CreateAsync(factory);
        var wf = await w.WorkflowAsync(w.Owner);
        var member = await w.AddAsync();

        var none = await CreateAsync(w, member, Action(wf));
        Assert.Equal(HttpStatusCode.Forbidden, none.Status);
        Assert.Equal("automation_saved_script_forbidden", none.Body.GetProperty("error").GetString());
        Assert.Equal("The Automation owner does not have access to this Workflow.", none.Body.GetProperty("message").GetString());
        // A viewer may read results but must not gain scheduled execution.
        await w.ShareWorkflowAsync(w.Owner, wf.Id, member, "viewer");
        Assert.Equal(HttpStatusCode.Forbidden, (await CreateAsync(w, member, Action(wf))).Status);
        Assert.Equal(0, factory.WithDb(db => db.Set<Automation>().Count(a => a.OwnerMemberId == member.MemberId)));
        await w.ShareWorkflowAsync(w.Owner, wf.Id, member, "editor");
        Assert.Equal(HttpStatusCode.Created, (await CreateAsync(w, member, Action(wf))).Status);

        var missing = await CreateAsync(w, w.Owner, Action(wf, versionId: "cov_00000000000000000000000000"));
        Assert.Equal(HttpStatusCode.BadRequest, missing.Status);
        Assert.Equal("automation_saved_script_version_not_found", missing.Body.GetProperty("error").GetString());
        var other = await Workspace.CreateAsync(factory, "Other");
        var foreign = await other.WorkflowAsync(other.Owner);
        // Another workspace's Workflow is simply not there (the owner holds sharing.manage_all, so only the version lookup, scoped to this workspace, decides).
        Assert.Equal("automation_saved_script_version_not_found", (await CreateAsync(w, w.Owner, Action(foreign))).Body.GetProperty("error").GetString());
        Assert.Equal("automation_saved_script_forbidden", (await CreateAsync(w, member, Action(foreign))).Body.GetProperty("error").GetString());

        var badInput = await CreateAsync(w, w.Owner, Action(wf, input: new { n = "three" }));
        Assert.Equal(HttpStatusCode.BadRequest, badInput.Status);
        Assert.Equal("automation_saved_script_input_invalid", badInput.Body.GetProperty("error").GetString());

        // A Workflow never runs on a desktop.
        var id = await CreatedAsync(w, w.Owner, Action(wf));
        var moved = await w.CallAsync(w.Owner, HttpMethod.Patch, $"/v1/automations/{id}", new { executionTarget = "desktop" });
        Assert.Equal(HttpStatusCode.BadRequest, moved.Status);
        Assert.Equal("automation_action_target_mismatch", moved.Body.GetProperty("error").GetString());
    }

    [Fact]
    public async Task A_failing_Workflow_or_access_lost_after_saving_fails_the_run_with_a_reason()
    {
        var w = await Workspace.CreateAsync(factory);
        var broken = await w.WorkflowAsync(w.Owner, "Broken", "throw new Error('boom')");
        var failing = await RunNowAsync(w, w.Owner, await CreatedAsync(w, w.Owner, Action(broken)));
        await factory.TickAsync();
        var run = Run(failing);
        Assert.Equal("failed", run.Status);
        Assert.Equal("execution_failed", JsonDocument.Parse(run.ErrorJson!).RootElement.GetProperty("code").GetString());
        Assert.Equal(1, factory.WithDb(db => db.Set<WorkflowRun>().Count(r => r.AutomationRunId == failing && r.Status == "failed")));

        // An editor whose grant is removed after saving: the run fails at run time instead of executing under access they lost.
        var wf = await w.WorkflowAsync(w.Owner, "Shared");
        var member = await w.AddAsync();
        await w.ShareWorkflowAsync(w.Owner, wf.Id, member, "editor");
        var automation = await CreatedAsync(w, member, Action(wf));
        var grants = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/config-objects/{wf.Id}/access");
        foreach (var g in grants.Body.GetProperty("items").EnumerateArray().Where(g => g.TryGetProperty("orgMembershipId", out var m) && m.GetString() == member.MemberId))
            Assert.True((await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/config-objects/{wf.Id}/access/{g.GetProperty("id").GetString()}")).Status is HttpStatusCode.OK or HttpStatusCode.NoContent);
        var lost = await RunNowAsync(w, member, automation);
        await factory.TickAsync();
        Assert.Equal("failed", Run(lost).Status);
        Assert.Contains("does not have access", Run(lost).ResultSummary);
        Assert.Equal(0, factory.WithDb(db => db.Set<WorkflowRun>().Count(r => r.AutomationRunId == lost)));
    }

    [Fact]
    public void Run_outcomes_map_to_the_reference_audit_outcomes_and_reason_codes()
    {
        Assert.Equal(("succeeded", "succeeded"), AutomationAudit.Outcome("succeeded", null));
        Assert.Equal(("failed", "execution_failed"), AutomationAudit.Outcome("failed", "execution_failed"));
        Assert.Equal(("failed", "failed"), AutomationAudit.Outcome("failed", null));
        Assert.Equal(("failed", "skipped.runner_unavailable"), AutomationAudit.Outcome("skipped", "runner_unavailable"));
        Assert.Equal(("failed", "cancelled"), AutomationAudit.Outcome("cancelled", "cancelled"));
        Assert.Equal(("unknown", "running"), AutomationAudit.Outcome("running", null));
    }
}
