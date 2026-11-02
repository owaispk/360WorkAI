using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Domain.Library;
using WorkAI360.Api.Domain.Workspace;
using WorkAI360.Api.Features.Workspace;

namespace WorkAI360.Api.Tests;

internal static class ViewSeed
{
    public static readonly string ObjectSchemaDigest = WorkflowArtifacts.Digest(new JsonObject { ["type"] = "object" });

    /// <summary>A view of a Workflow with one revision per entry in <paramref name="revisions"/> (oldest first), written straight to the database: the builder that normally makes them is not part of this build.</summary>
    public static (string ViewId, string[] RevisionIds) Add(ApiFactory f, Workspace w, Seeded wf, string title = "A view", string dataMode = "snapshot", string status = "active", int activeIndex = -1,
        (string Status, string? Digest, bool Retired)[]? revisions = null)
    {
        revisions ??= [("ready", null, false)];
        return f.WithDb(db =>
        {
            var viewId = Ids.New("arv");
            var ids = new List<string>();
            var start = DateTime.UtcNow.AddHours(-1);
            for (var i = 0; i < revisions.Length; i++)
            {
                var (rstatus, digest, retired) = revisions[i];
                var id = Ids.New("avr");
                ids.Add(id);
                db.Add(new ArtifactViewRevision
                {
                    Id = id, OrganizationId = w.OrgId, ArtifactViewId = viewId, CreatedByMemberId = w.Owner.MemberId, ReactSource = "export default () => null", CssSource = "",
                    CompiledHtml = rstatus == "ready" ? $"<html>revision {i}</html>" : null, BuildDiagnosticsJson = rstatus == "ready" ? "[]" : """[{"level":"error","message":"Unexpected token","line":1,"column":3}]""",
                    BuildStatus = rstatus, SourceDigest = "sha256:" + new string('a', 64), ResourceDigest = rstatus == "ready" ? "sha256:" + new string('b', 64) : null,
                    OutputSchemaDigest = digest ?? ObjectSchemaDigest, OutputSchemaJson = """{"type":"object"}""", CspJson = """{"connectDomains":[],"resourceDomains":[],"frameDomains":[],"baseUriDomains":[]}""",
                    CompilerName = "test", CompilerVersion = "1", ReactVersion = "19", CompiledHtmlBytes = rstatus == "ready" ? 20 : null, RetiredAt = retired ? DateTime.UtcNow : null,
                    CreatedAt = new DateTime(start.Ticks + i * TimeSpan.TicksPerSecond, DateTimeKind.Utc),
                });
            }
            db.Add(new ArtifactView
            {
                Id = viewId, OrganizationId = w.OrgId, ConfigObjectId = wf.Id, OwnerMemberId = w.Owner.MemberId, Title = title, Status = status, DataMode = dataMode,
                ActiveRevisionId = activeIndex >= 0 ? ids[activeIndex] : null, UseInWorkflow = false, CreatedAt = start, UpdatedAt = start,
            });
            db.SaveChanges();
            return (viewId, ids.ToArray());
        });
    }

    public static ArtifactView View(ApiFactory f, string id) => f.WithDb(db => db.Set<ArtifactView>().AsNoTracking().First(v => v.Id == id));
}

public sealed class ViewsDisabledTests : IClassFixture<WorkspaceFactory>
{
    private readonly WorkspaceFactory _factory;
    public ViewsDisabledTests(WorkspaceFactory factory) => _factory = factory;

    [Fact]
    public async Task With_views_off_nothing_is_served_even_for_rows_that_exist()
    {
        var w = await Workspace.CreateAsync(_factory, "Views off");
        var wf = await w.WorkflowAsync(w.Owner);
        var (view, revisions) = ViewSeed.Add(_factory, w, wf, activeIndex: 0);
        var apps = await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/apps");
        Assert.False(apps.Body.GetProperty("enabled").GetBoolean());
        Assert.Empty(apps.Body.GetProperty("items").EnumerateArray());
        Assert.Equal("artifact_view_not_found", (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/apps/{view}")).Err());
        Assert.Equal("artifact_view_not_found", (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/artifact-views/{view}/retire")).Err());
        Assert.Equal("artifact_view_not_found", (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/artifact-views/{view}/revisions/{revisions[0]}/activate")).Err());
        Assert.Empty((await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/workflows/{wf.Id}/views")).Body.GetProperty("items").EnumerateArray());
        var card = (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/workflows/{wf.Id}")).Body;
        Assert.Equal("default", card.GetProperty("workflow").S("viewState"));
        Assert.Equal(0, card.GetProperty("views").GetArrayLength());
    }
}

public sealed class ViewTests : IClassFixture<ViewsFactory>
{
    private readonly ViewsFactory _factory;
    public ViewTests(ViewsFactory factory) => _factory = factory;

    private static readonly object LiveOnly = new { language = "codemode-js", outputSchema = new { type = "object" }, requiredCapabilities = Array.Empty<object>() };

    private async Task<(Workspace W, Person Bob, Seeded Wf)> SetupAsync(string name, string code = "return { today: input.runtime.today }")
    {
        var w = await Workspace.CreateAsync(_factory, name);
        var bob = await w.AddAsync();
        var wf = await w.WorkflowAsync(w.Owner, "Viewed flow", code, LiveOnly);
        return (w, bob, wf);
    }

    [Fact]
    public async Task A_workflows_views_list_newest_first_with_their_revisions_and_build_status()
    {
        var (w, _, wf) = await SetupAsync("Views list");
        var (older, _) = ViewSeed.Add(_factory, w, wf, "Older view");
        await Task.Delay(1100);
        var (newer, revisions) = ViewSeed.Add(_factory, w, wf, "Newer view", activeIndex: 0, revisions: [("ready", null, false), ("failed", null, false)]);
        _factory.WithDb(db => db.Set<ArtifactView>().Where(v => v.Id == newer).ExecuteUpdate(s => s.SetProperty(v => v.UpdatedAt, DateTime.UtcNow)));
        var list = (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/workflows/{wf.Id}/views")).Body.GetProperty("items");
        Assert.Equal([newer, older], list.EnumerateArray().Select(v => v.S("id")).ToArray());
        var first = list[0];
        Assert.Equal("Newer view", first.S("title"));
        Assert.Equal(revisions[0], first.S("activeRevisionId"));
        Assert.Equal([revisions[1], revisions[0]], first.GetProperty("revisions").EnumerateArray().Select(r => r.S("id")).ToArray());
        var failed = first.GetProperty("revisions")[0];
        Assert.Equal("failed", failed.S("buildStatus"));
        Assert.Equal("Unexpected token", failed.GetProperty("diagnostics")[0].S("message"));
        Assert.StartsWith("ui://openwork/artifacts/", failed.S("resourceUri"));
        Assert.Equal(0, failed.GetProperty("csp").GetProperty("connectDomains").GetArrayLength());
        var card = (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/workflows/{wf.Id}")).Body;
        Assert.Equal("custom_active", card.GetProperty("workflow").S("viewState"));
        Assert.Equal("Newer view", card.GetProperty("workflow").S("activeViewTitle"));
        Assert.Equal(2, card.GetProperty("views").GetArrayLength());
    }

    [Fact]
    public async Task The_active_revision_stays_listed_even_when_it_is_older_than_the_newest_fifty()
    {
        var (w, _, wf) = await SetupAsync("Views pinned");
        var (view, ids) = ViewSeed.Add(_factory, w, wf, activeIndex: 0, revisions: Enumerable.Repeat(("ready", (string?)null, false), 53).ToArray());
        var revisions = (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/workflows/{wf.Id}/views")).Body.GetProperty("items")[0].GetProperty("revisions");
        Assert.Equal(51, revisions.GetArrayLength());
        Assert.Contains(ids[0], revisions.EnumerateArray().Select(r => r.S("id")));
        Assert.DoesNotContain(ids[1], revisions.EnumerateArray().Select(r => r.S("id")));
        Assert.Equal(view, (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/workflows/{wf.Id}/views")).Body.GetProperty("items")[0].S("id"));
    }

    [Fact]
    public async Task A_workflow_card_says_when_a_build_failed_or_every_view_was_retired()
    {
        var (w, _, wf) = await SetupAsync("Views state");
        var (view, _) = ViewSeed.Add(_factory, w, wf, revisions: [("failed", null, false)]);
        Assert.Equal("build_failed", (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/workflows/{wf.Id}")).Body.GetProperty("workflow").S("viewState"));
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/artifact-views/{view}/retire")).Status);
        Assert.Equal("retired", (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/workflows/{wf.Id}")).Body.GetProperty("workflow").S("viewState"));
        var library = (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/me/library")).Body.GetProperty("items").EnumerateArray().First(i => i.S("type") == "workflow");
        Assert.Equal("retired", library.S("viewState"));
    }

    [Fact]
    public async Task Activating_a_revision_makes_it_the_active_one_and_a_rollback_changes_no_bytes()
    {
        var (w, _, wf) = await SetupAsync("Views activate");
        var (view, ids) = ViewSeed.Add(_factory, w, wf, activeIndex: 1, revisions: [("ready", null, false), ("ready", null, false)]);
        var r = await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/artifact-views/{view}/revisions/{ids[0]}/activate");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal(ids[0], r.Body.S("activeRevisionId"));
        Assert.Equal("active", r.Body.S("status"));
        Assert.Equal(ids[0], ViewSeed.View(_factory, view).ActiveRevisionId);
        Assert.Equal("<html>revision 0</html>", _factory.WithDb(db => db.Set<ArtifactViewRevision>().AsNoTracking().First(x => x.Id == ids[0]).CompiledHtml));
    }

    [Fact]
    public async Task A_revision_that_failed_to_build_was_retired_or_fits_another_schema_cannot_be_activated()
    {
        var (w, _, wf) = await SetupAsync("Views refuse");
        var (view, ids) = ViewSeed.Add(_factory, w, wf, revisions: [("failed", null, false), ("ready", null, true), ("ready", "sha256:" + new string('c', 64), false)]);
        var failed = await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/artifact-views/{view}/revisions/{ids[0]}/activate");
        Assert.Equal(HttpStatusCode.BadRequest, failed.Status);
        Assert.Equal("artifact_view_revision_not_ready", failed.Message());
        Assert.Equal("artifact_view_revision_not_ready", (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/artifact-views/{view}/revisions/{ids[1]}/activate")).Message());
        Assert.Equal("artifact_view_schema_incompatible", (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/artifact-views/{view}/revisions/{ids[2]}/activate")).Message());
        Assert.Equal("artifact_view_revision_not_ready", (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/artifact-views/{view}/revisions/avr_01m6797hhce34acegcde4y57bd/activate")).Message());
        Assert.Null(ViewSeed.View(_factory, view).ActiveRevisionId);
    }

    [Fact]
    public async Task Only_a_manager_of_the_workflow_changes_its_views_and_others_cannot_tell_it_exists()
    {
        var (w, bob, wf) = await SetupAsync("Views managers");
        var other = await Workspace.CreateAsync(_factory, "Views managers other");
        var (view, ids) = ViewSeed.Add(_factory, w, wf, activeIndex: 0);
        await w.ShareAsync(w.Owner, wf.PluginId, bob);
        foreach (var url in new[] { $"/v1/artifact-views/{view}/revisions/{ids[0]}/activate", $"/v1/artifact-views/{view}/retire" })
        {
            var asViewer = await w.CallAsync(bob, HttpMethod.Post, url);
            Assert.Equal(HttpStatusCode.NotFound, asViewer.Status);
            Assert.Equal("workflow_not_found", asViewer.Err());
            Assert.Equal("artifact_view_not_found", asViewer.Message());
            var foreign = await other.CallAsync(other.Owner, HttpMethod.Post, url);
            Assert.Equal(HttpStatusCode.NotFound, foreign.Status);
        }
        var unshared = await w.AddAsync();
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(unshared, HttpMethod.Post, $"/v1/artifact-views/{view}/retire")).Status);
        Assert.Equal("active", ViewSeed.View(_factory, view).Status);
    }

    [Fact]
    public async Task Retiring_a_view_clears_it_from_every_dashboard_and_activating_a_revision_brings_it_back()
    {
        var (w, bob, wf) = await SetupAsync("Views retire");
        await w.ShareAsync(w.Owner, wf.PluginId, bob);
        var (view, ids) = ViewSeed.Add(_factory, w, wf, activeIndex: 0);
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/apps/{view}/dashboard", new { added = true })).Status);
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(bob, HttpMethod.Post, $"/v1/apps/{view}/dashboard", new { added = true })).Status);
        var retired = await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/artifact-views/{view}/retire");
        Assert.Equal("retired", retired.Body.S("status"));
        Assert.Equal(JsonValueKind.Null, retired.Body.GetProperty("activeRevisionId").ValueKind);
        Assert.False(retired.Body.GetProperty("useInWorkflow").GetBoolean());
        Assert.Equal(1, retired.Body.GetProperty("revisions").GetArrayLength());
        Assert.Equal(0, _factory.WithDb(db => db.Set<DashboardApp>().Count(d => d.ArtifactViewId == view)));
        Assert.Empty((await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/apps")).Body.GetProperty("items").EnumerateArray());
        var back = await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/artifact-views/{view}/revisions/{ids[0]}/activate");
        Assert.Equal("active", back.Body.S("status"));
        Assert.Single((await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/apps")).Body.GetProperty("items").EnumerateArray());
    }

    [Fact]
    public async Task Saved_apps_are_the_active_views_with_a_saved_revision_that_the_person_can_read_newest_first()
    {
        var (w, bob, wf) = await SetupAsync("Apps list");
        var hidden = await w.WorkflowAsync(w.Owner, "Hidden flow", "return 1", LiveOnly);
        var (visible, _) = ViewSeed.Add(_factory, w, wf, "Visible app", activeIndex: 0);
        ViewSeed.Add(_factory, w, wf, "Draft only app");
        ViewSeed.Add(_factory, w, wf, "Retired app", status: "retired", activeIndex: 0);
        ViewSeed.Add(_factory, w, hidden, "Hidden app", activeIndex: 0);
        await w.ShareAsync(w.Owner, wf.PluginId, bob);
        var mine = (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/apps")).Body;
        Assert.True(mine.GetProperty("enabled").GetBoolean());
        Assert.True(mine.GetProperty("sharingEnabled").GetBoolean());
        Assert.Equal(["Hidden app", "Visible app"], mine.GetProperty("items").EnumerateArray().Select(i => i.GetProperty("view").S("title")).Order().ToArray());
        var his = (await w.CallAsync(bob, HttpMethod.Get, "/v1/apps")).Body.GetProperty("items");
        Assert.Equal(1, his.GetArrayLength());
        Assert.Equal(visible, his[0].GetProperty("view").S("id"));
        Assert.Equal("Viewed flow", his[0].S("workflowTitle"));
        Assert.False(his[0].GetProperty("canManage").GetBoolean());
        Assert.False(his[0].GetProperty("onDashboard").GetBoolean());
        Assert.Equal("canManage,onDashboard,view,workflowTitle", string.Join(',', his[0].EnumerateObject().Select(p => p.Name).Order()));
    }

    [Fact]
    public async Task Putting_an_app_on_the_dashboard_is_idempotent_needs_an_active_saved_revision_and_removal_always_works()
    {
        var (w, bob, wf) = await SetupAsync("Apps dashboard");
        var (saved, _) = ViewSeed.Add(_factory, w, wf, activeIndex: 0);
        var (draft, _) = ViewSeed.Add(_factory, w, wf, "Draft");
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/apps/{saved}/dashboard", new { added = true })).Status);
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/apps/{saved}/dashboard", new { added = true })).Status);
        Assert.Equal(1, _factory.WithDb(db => db.Set<DashboardApp>().Count(d => d.ArtifactViewId == saved)));
        Assert.True((await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/apps")).Body.GetProperty("items")[0].GetProperty("onDashboard").GetBoolean());
        Assert.Equal(HttpStatusCode.NotFound, (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/apps/{draft}/dashboard", new { added = true })).Status);
        // Someone with no access cannot add it, but can always take it off their own dashboard.
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(bob, HttpMethod.Post, $"/v1/apps/{saved}/dashboard", new { added = true })).Status);
        _factory.WithDb(db => { db.Add(new DashboardApp { OrganizationId = w.OrgId, MemberId = bob.MemberId, ArtifactViewId = saved, CreatedAt = DateTime.UtcNow }); db.SaveChanges(); return 0; });
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(bob, HttpMethod.Post, $"/v1/apps/{saved}/dashboard", new { added = false })).Status);
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(bob, HttpMethod.Post, $"/v1/apps/{saved}/dashboard", new { added = false })).Status);
        Assert.Equal(0, _factory.WithDb(db => db.Set<DashboardApp>().Count(d => d.MemberId == bob.MemberId)));
        Assert.Equal(1, _factory.WithDb(db => db.Set<DashboardApp>().Count(d => d.MemberId == w.Owner.MemberId)));
    }

    [Fact]
    public async Task Saving_an_app_names_the_revision_it_expects_to_replace_and_one_of_two_saves_at_once_loses()
    {
        var (w, _, wf) = await SetupAsync("Apps save");
        var (view, ids) = ViewSeed.Add(_factory, w, wf, revisions: [("ready", null, false), ("ready", null, false)]);
        var stale = await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/apps/{view}/save", new { revisionId = ids[0], title = "Saved", useInWorkflow = true, expectedActiveRevisionId = ids[1] });
        Assert.Equal(HttpStatusCode.Conflict, stale.Status);
        Assert.Equal("app_changed_since_preview", stale.Err());
        Assert.Contains("saved elsewhere", stale.Message());
        var results = await Task.WhenAll(new[] { ids[0], ids[1] }.Select(rev => w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/apps/{view}/save", new { revisionId = rev, title = $"Saved {rev[^4..]}", useInWorkflow = true, expectedActiveRevisionId = (string?)null })));
        Assert.Equal(1, results.Count(r => r.Status == HttpStatusCode.OK));
        Assert.Equal(1, results.Count(r => r.Status == HttpStatusCode.Conflict));
        var row = ViewSeed.View(_factory, view);
        Assert.Equal(results.First(r => r.Status == HttpStatusCode.OK).Body.S("activeRevisionId"), row.ActiveRevisionId);
        Assert.True(row.UseInWorkflow);
        Assert.StartsWith("Saved ", row.Title);
        Assert.Equal(1, _factory.WithDb(db => db.Set<DashboardApp>().Count(d => d.ArtifactViewId == view && d.MemberId == w.Owner.MemberId)));
        var again = await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/apps/{view}/save", new { revisionId = ids[0], title = "Third", useInWorkflow = false, expectedActiveRevisionId = row.ActiveRevisionId });
        Assert.Equal(HttpStatusCode.OK, again.Status);
        Assert.Equal("Third", again.Body.S("title"));
    }

    [Fact]
    public async Task A_save_that_cannot_be_activated_says_so_in_words_for_the_person_using_the_app_and_leaves_no_dashboard_card()
    {
        var (w, _, wf) = await SetupAsync("Apps save refuse");
        var (view, ids) = ViewSeed.Add(_factory, w, wf, revisions: [("failed", null, false), ("ready", "sha256:" + new string('d', 64), false)]);
        var notReady = await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/apps/{view}/save", new { revisionId = ids[0], title = "x", useInWorkflow = true, expectedActiveRevisionId = (string?)null });
        Assert.Equal("This app is still being prepared. Wait for its preview before saving.", notReady.Message());
        var schema = await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/apps/{view}/save", new { revisionId = ids[1], title = "x", useInWorkflow = true, expectedActiveRevisionId = (string?)null });
        Assert.Equal("The workflow’s results have changed. Ask OpenWork to update this app before saving.", schema.Message());
        Assert.Equal(0, _factory.WithDb(db => db.Set<DashboardApp>().Count(d => d.ArtifactViewId == view)));
        var body = await w.RawAsync(w.Owner, HttpMethod.Post, $"/v1/apps/{view}/save", """{"title":" ","useInWorkflow":"yes"}""");
        Assert.Equal(HttpStatusCode.BadRequest, body.Status);
        Assert.Equal(["revisionId", "title", "useInWorkflow", "expectedActiveRevisionId"], body.Body.GetProperty("details").EnumerateArray().Select(d => d.GetProperty("path")[0].GetString()!).ToArray());
    }

    [Fact]
    public async Task Sharing_an_app_gives_the_teammate_viewer_access_to_the_workflow_never_less_than_they_had_and_never_copies_results()
    {
        var (w, bob, wf) = await SetupAsync("Apps share");
        var carol = await w.AddAsync();
        var (view, _) = ViewSeed.Add(_factory, w, wf, activeIndex: 0);
        await w.ShareWorkflowAsync(w.Owner, wf.Id, carol, "manager");
        var shared = await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/apps/{view}/share", new { email = bob.Email.ToUpperInvariant() });
        Assert.Equal(HttpStatusCode.OK, shared.Status);
        Assert.True(shared.Body.GetProperty("ok").GetBoolean());
        var his = (await w.CallAsync(bob, HttpMethod.Get, "/v1/apps")).Body.GetProperty("items");
        Assert.Equal(1, his.GetArrayLength());
        Assert.True(his[0].GetProperty("onDashboard").GetBoolean());
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(bob, HttpMethod.Get, $"/v1/workflows/{wf.Id}")).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(bob, HttpMethod.Post, $"/v1/workflows/test", WorkflowHelpers.Draft(wf))).Status);
        // Sharing again with someone who already manages it keeps the manager grant.
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/apps/{view}/share", new { email = carol.Email })).Status);
        var carolRole = (await w.CallAsync(carol, HttpMethod.Get, $"/v1/workflows/{wf.Id}")).Body.GetProperty("workflow").S("role");
        Assert.Equal("manager", carolRole);
        Assert.Equal(1, _factory.WithDb(db => db.Set<LibraryGrant>().Count(g => g.ResourceId == wf.Id && g.MemberId == carol.MemberId)));
    }

    [Fact]
    public async Task Sharing_needs_a_manager_a_real_teammate_and_an_app_with_a_saved_revision()
    {
        var (w, bob, wf) = await SetupAsync("Apps share refuse");
        var (saved, _) = ViewSeed.Add(_factory, w, wf, activeIndex: 0);
        var (draft, _) = ViewSeed.Add(_factory, w, wf, "Draft");
        await w.ShareAsync(w.Owner, wf.PluginId, bob);
        var byViewer = await w.CallAsync(bob, HttpMethod.Post, $"/v1/apps/{saved}/share", new { email = w.Owner.Email });
        Assert.Equal(HttpStatusCode.Forbidden, byViewer.Status);
        var nobody = await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/apps/{saved}/share", new { email = "nobody@example.com" });
        Assert.Equal(HttpStatusCode.NotFound, nobody.Status);
        Assert.Equal("teammate_not_found", nobody.Err());
        Assert.Equal("No teammate with that email belongs to this organization. Ask an admin to invite them first.", nobody.Message());
        var outsider = await Workspace.CreateAsync(_factory, "Outsider");
        Assert.Equal("teammate_not_found", (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/apps/{saved}/share", new { email = outsider.Owner.Email })).Err());
        Assert.Equal(HttpStatusCode.NotFound, (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/apps/{draft}/share", new { email = bob.Email })).Status);
        var bad = await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/apps/{saved}/share", new { email = "not an email" });
        Assert.Equal("email: Invalid email address", bad.Message());
    }

    [Fact]
    public async Task Opening_a_live_app_runs_the_current_workflow_as_the_person_and_hands_over_the_page_and_the_data()
    {
        var (w, bob, wf) = await SetupAsync("Apps live");
        var (view, _) = ViewSeed.Add(_factory, w, wf, dataMode: "live", activeIndex: 0);
        await w.ShareAsync(w.Owner, wf.PluginId, bob);
        var r = await w.CallAsync(bob, HttpMethod.Get, $"/v1/apps/{view}?timeZone=UTC");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal("<html>revision 0</html>", r.Body.S("html"));
        Assert.Equal(JsonValueKind.Null, r.Body.GetProperty("previewNotice").ValueKind);
        var payload = r.Body.GetProperty("payload");
        Assert.Equal("1", payload.S("schemaVersion"));
        Assert.Equal(DateTime.UtcNow.ToString("yyyy-MM-dd"), payload.GetProperty("data").S("today"));
        Assert.Equal("fresh", payload.GetProperty("artifact").GetProperty("freshness").S("state"));
        Assert.Equal("Viewed flow", payload.GetProperty("artifact").S("title"));
        var receipt = payload.GetProperty("artifact").S("receiptId");
        var row = _factory.WithDb(db => db.Set<WorkflowRun>().AsNoTracking().First(x => x.Id == receipt));
        Assert.Equal(bob.MemberId, row.MemberId);
        Assert.StartsWith("live:plugin:", row.Source);
        var asked = await w.CallAsync(bob, HttpMethod.Get, $"/v1/apps/{view}?receiptId={receipt}");
        Assert.Equal(HttpStatusCode.BadRequest, asked.Status);
        Assert.Equal("artifact_view_live_receipt_override_denied", asked.Message());
    }

    [Fact]
    public async Task Opening_an_app_that_cannot_show_yet_says_why_without_a_page()
    {
        var (w, _, wf) = await SetupAsync("Apps notices");
        var (failed, _) = ViewSeed.Add(_factory, w, wf, dataMode: "snapshot", activeIndex: 0, revisions: [("failed", null, false)]);
        var building = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/apps/{failed}");
        Assert.Equal(JsonValueKind.Null, building.Body.GetProperty("html").ValueKind);
        Assert.Equal("This app is still being prepared. Ask OpenWork to finish its preview.", building.Body.S("previewNotice"));
        var (snapshot, _) = ViewSeed.Add(_factory, w, wf, dataMode: "snapshot", activeIndex: 0);
        var none = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/apps/{snapshot}");
        Assert.Equal("Run the workflow to give this app a result to display.", none.Body.S("previewNotice"));
        await w.RunAsync(w.Owner, wf, wf.VersionId, mode: "live");
        var live = await w.RunAsync(w.Owner, wf, wf.VersionId, new { runtime = new { today = "2026-01-01" } });
        Assert.Equal(HttpStatusCode.OK, live.Status);
        var shown = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/apps/{snapshot}");
        Assert.Equal("<html>revision 0</html>", shown.Body.S("html"));
        Assert.NotNull(shown.Body.GetProperty("payload").GetProperty("data").S("today"));
        var (mismatch, _) = ViewSeed.Add(_factory, w, wf, dataMode: "snapshot", activeIndex: 0, revisions: [("ready", "sha256:" + new string('e', 64), false)]);
        var changed = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/apps/{mismatch}");
        Assert.Equal(JsonValueKind.Null, changed.Body.GetProperty("html").ValueKind);
        Assert.Contains("results have changed", changed.Body.S("previewNotice"));
    }

    [Fact]
    public async Task A_draft_revision_can_be_previewed_by_id_and_the_page_is_never_cached()
    {
        var (w, _, wf) = await SetupAsync("Apps preview");
        var (view, ids) = ViewSeed.Add(_factory, w, wf, dataMode: "live", activeIndex: 0, revisions: [("ready", null, false), ("ready", null, false)]);
        var request = w.As(w.Owner, HttpMethod.Get, $"/v1/apps/{view}?revisionId={ids[1]}");
        var response = await w.Http.SendAsync(request);
        Assert.Contains("no-store", response.Headers.CacheControl?.ToString());
        Assert.Contains("private", response.Headers.CacheControl?.ToString());
        var body = await ApiFactory.ReadJsonAsync(response);
        Assert.Equal("<html>revision 1</html>", body.S("html"));
        Assert.Equal(ids[1], body.GetProperty("revision").S("id"));
        var missing = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/apps/{view}?revisionId=avr_01m6797hhce34acegcde4y57bd");
        Assert.Equal(HttpStatusCode.NotFound, missing.Status);
        var badZone = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/apps/{view}?timeZone=Mars/Base");
        Assert.Equal("timeZone: Expected an IANA time zone", badZone.Message());
    }

    [Fact]
    public async Task An_app_of_another_workspace_or_one_the_person_cannot_read_is_not_there()
    {
        var (w, bob, wf) = await SetupAsync("Apps isolation");
        var other = await Workspace.CreateAsync(_factory, "Apps isolation other");
        var (view, _) = ViewSeed.Add(_factory, w, wf, activeIndex: 0);
        Assert.Equal(HttpStatusCode.NotFound, (await other.CallAsync(other.Owner, HttpMethod.Get, $"/v1/apps/{view}")).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(bob, HttpMethod.Get, $"/v1/apps/{view}")).Status);
        Assert.Empty((await other.CallAsync(other.Owner, HttpMethod.Get, "/v1/apps")).Body.GetProperty("items").EnumerateArray());
        var garbage = await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/apps/not-an-id");
        Assert.Equal(HttpStatusCode.BadRequest, garbage.Status);
    }
}

public sealed class LegacyViewTests : IClassFixture<LegacyViewsFactory>
{
    private readonly LegacyViewsFactory _factory;
    public LegacyViewTests(LegacyViewsFactory factory) => _factory = factory;

    [Fact]
    public async Task When_apps_are_their_own_servers_a_workflow_bound_view_still_opens_and_can_be_retired_but_not_activated_or_saved()
    {
        var w = await Workspace.CreateAsync(_factory, "Legacy views");
        var wf = await w.WorkflowAsync(w.Owner, "Legacy", "return { today: input.runtime.today }", new { language = "codemode-js", outputSchema = new { type = "object" }, requiredCapabilities = Array.Empty<object>() });
        var (view, ids) = ViewSeed.Add(_factory, w, wf, dataMode: "live", activeIndex: 0, revisions: [("ready", null, false), ("ready", null, false)]);
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/apps/{view}")).Status);
        var activate = await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/artifact-views/{view}/revisions/{ids[1]}/activate");
        Assert.Equal(HttpStatusCode.Conflict, activate.Status);
        Assert.Equal("legacy_view_read_only", activate.Err());
        Assert.Contains("older app that can no longer be edited", activate.Message());
        var save = await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/apps/{view}/save", new { revisionId = ids[1], title = "x", useInWorkflow = true, expectedActiveRevisionId = ids[0] });
        Assert.Equal("legacy_view_read_only", save.Err());
        Assert.Equal(ids[0], ViewSeed.View(_factory, view).ActiveRevisionId);
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/artifact-views/{view}/retire")).Status);
    }
}

public sealed class McpAppCatalogTests : IClassFixture<WorkspaceFactory>
{
    private readonly WorkspaceFactory _factory;
    public McpAppCatalogTests(WorkspaceFactory factory) => _factory = factory;

    private static object AppPayload(string title) => new
    {
        kind = "authored_mcp_app", schemaVersion = 1, pluginId = "plg_01m6797hhce34acegcde4y57bd", title, description = (string?)null, textFallback = "fallback",
        tools = Array.Empty<object>(), html = "<html>app</html>", htmlBytes = 15, resourceDigest = "sha256:" + new string('a', 64), sourceDigest = "sha256:" + new string('b', 64),
        csp = new { connectDomains = Array.Empty<string>(), resourceDomains = Array.Empty<string>(), frameDomains = Array.Empty<string>(), baseUriDomains = Array.Empty<string>() },
        compilerName = "openwork-react-mcp-app", compilerVersion = "1", reactVersion = "19",
    };

    private static async Task<(string PluginId, string AppId, string RevisionId)> AppAsync(Workspace w, string title, object? payload = null, string schemaVersion = "openwork.mcp-app/1")
    {
        var plugin = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/plugins", new { name = $"{title} plugin" });
        var pluginId = plugin.Body.GetProperty("item").S("id");
        var made = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/config-objects", new { type = "app", sourceMode = "cloud", pluginIds = new[] { pluginId },
            input = new { normalizedPayloadJson = payload ?? AppPayload(title), schemaVersion, metadata = new { name = title, description = $"{title} description" } } });
        Assert.Equal(HttpStatusCode.Created, made.Status);
        var item = made.Body.GetProperty("item");
        return (pluginId, item.S("id"), item.GetProperty("latestVersion").S("id"));
    }

    [Fact]
    public async Task The_catalog_lists_the_apps_whose_plugin_is_shared_with_the_person_in_the_tile_shape()
    {
        var w = await Workspace.CreateAsync(_factory, "Catalog");
        var bob = await w.AddAsync();
        var (pluginId, appId, revisionId) = await AppAsync(w, "Budget app");
        Assert.Empty((await w.CallAsync(bob, HttpMethod.Get, "/v1/mcp-apps")).Body.GetProperty("apps").EnumerateArray());
        await w.ShareAsync(w.Owner, pluginId, bob);
        var apps = (await w.CallAsync(bob, HttpMethod.Get, "/v1/mcp-apps")).Body.GetProperty("apps");
        Assert.Equal(1, apps.GetArrayLength());
        var app = apps[0];
        Assert.Equal("apps,".Length, "apps,".Length);
        Assert.Equal("connectionId,description,pluginId,pluginName,projectedToolName,requiredInputKeys,requiresApproval,requiresInput,resourceUri,serverName,title,toolName", string.Join(',', app.EnumerateObject().Select(p => p.Name).Order()));
        Assert.Equal(appId, app.S("connectionId"));
        Assert.Equal("open_app", app.S("toolName"));
        Assert.Equal($"ui://openwork/apps/{appId}/revisions/{revisionId}/index.html", app.S("resourceUri"));
        Assert.Equal("Budget app", app.S("title"));
        Assert.Equal("Budget app description", app.S("description"));
        Assert.Equal(pluginId, app.S("pluginId"));
        Assert.Equal("Budget app plugin", app.S("pluginName"));
        Assert.Matches("^openwork-app-host-connect-[0-9a-f]{12}$", app.S("serverName"));
        Assert.Equal($"{app.S("serverName")}_open_app", app.S("projectedToolName"));
        Assert.False(app.GetProperty("requiresInput").GetBoolean());
        Assert.False(app.GetProperty("requiresApproval").GetBoolean());
        Assert.Equal(0, app.GetProperty("requiredInputKeys").GetArrayLength());
    }

    [Fact]
    public async Task Apps_are_sorted_by_title_and_what_is_not_an_authored_app_or_not_active_is_left_out()
    {
        var w = await Workspace.CreateAsync(_factory, "Catalog filters");
        var (_, b, _) = await AppAsync(w, "Beta app");
        var (_, a, _) = await AppAsync(w, "Alpha app");
        await AppAsync(w, "Imported app", schemaVersion: "other/1");
        await AppAsync(w, "Broken app", payload: new { kind = "something", schemaVersion = 1 });
        var (archivedPlugin, _, _) = await AppAsync(w, "Archived app");
        await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/plugins/{archivedPlugin}/archive");
        var apps = (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/mcp-apps")).Body.GetProperty("apps");
        // The maker manages their own plugins, so their own apps are all reachable; only the well-formed, active ones are listed.
        Assert.Equal([a, b], apps.EnumerateArray().Select(x => x.S("connectionId")).ToArray());
    }

    [Fact]
    public async Task The_catalog_follows_the_newest_revision_of_an_app()
    {
        var w = await Workspace.CreateAsync(_factory, "Catalog revisions");
        var (_, appId, firstRevision) = await AppAsync(w, "Moving app");
        var second = Ids.New("cov");
        _factory.WithDb(db =>
        {
            db.Add(new ConfigObjectVersion
            {
                Id = second, OrganizationId = w.OrgId, ConfigObjectId = appId, SchemaVersion = "openwork.mcp-app/1", CreatedVia = "cloud", CreatedByMemberId = w.Owner.MemberId, CreatedAt = DateTime.UtcNow.AddMinutes(1),
                NormalizedPayloadJson = JsonSerializer.Serialize(AppPayload("Moving app")),
            });
            db.SaveChanges();
            return 0;
        });
        var apps = (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/mcp-apps")).Body.GetProperty("apps");
        Assert.Equal(second, apps[0].S("resourceUri").Split('/')[^2]);
        Assert.NotEqual(firstRevision, second);
        // A newest revision that is not a well-formed App hides the App until it is fixed.
        _factory.WithDb(db =>
        {
            db.Add(new ConfigObjectVersion { Id = Ids.New("cov"), OrganizationId = w.OrgId, ConfigObjectId = appId, SchemaVersion = "openwork.mcp-app/1", CreatedVia = "cloud", CreatedAt = DateTime.UtcNow.AddMinutes(2), NormalizedPayloadJson = "{}" });
            db.SaveChanges();
            return 0;
        });
        Assert.Empty((await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/mcp-apps")).Body.GetProperty("apps").EnumerateArray());
    }

    [Fact]
    public async Task The_catalog_needs_a_signed_in_member_of_the_workspace()
    {
        var w = await Workspace.CreateAsync(_factory, "Catalog auth");
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Http.GetAsync("/v1/mcp-apps")).StatusCode);
        var stranger = await Workspace.CreateAsync(_factory, "Catalog stranger");
        var request = w.As(stranger.Owner, HttpMethod.Get, "/v1/mcp-apps");
        Assert.Equal(HttpStatusCode.NotFound, (await w.Http.SendAsync(request)).StatusCode);
    }
}

public sealed class NoAppServersTests : IClassFixture<NoAppServersFactory>
{
    private readonly NoAppServersFactory _factory;
    public NoAppServersTests(NoAppServersFactory factory) => _factory = factory;

    [Fact]
    public async Task With_apps_as_servers_switched_off_the_catalog_is_empty()
    {
        var w = await Workspace.CreateAsync(_factory, "No app servers");
        var plugin = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/plugins", new { name = "App plugin" });
        var pluginId = plugin.Body.GetProperty("item").S("id");
        var payload = new { kind = "authored_mcp_app", schemaVersion = 1, title = "Hidden", html = "<html></html>" };
        await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/config-objects", new { type = "app", sourceMode = "cloud", pluginIds = new[] { pluginId }, input = new { normalizedPayloadJson = payload, schemaVersion = "openwork.mcp-app/1", metadata = new { name = "Hidden" } } });
        Assert.Empty((await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/mcp-apps")).Body.GetProperty("apps").EnumerateArray());
    }
}
