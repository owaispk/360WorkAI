using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>Declarative team keys: GET, PUT and DELETE /v1/teams/by-key/{externalKey}.</summary>
public sealed class DeclarativeTeamTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private static string Path(string key) => $"/v1/teams/by-key/{key}";

    [Fact]
    public async Task Put_creates_then_replaces_the_keyed_team_and_get_reads_it()
    {
        var w = await Workspace.CreateAsync(factory);
        var alice = await w.AddAsync();
        var bob = await w.AddAsync();

        var created = await w.CallAsync(w.Owner, HttpMethod.Put, Path("eng.platform"), new { name = "Platform", memberIds = new[] { alice.MemberId } });
        Assert.Equal(HttpStatusCode.Created, created.Status);
        var team = created.Body.GetProperty("team");
        var id = team.GetProperty("id").GetString()!;
        Assert.Equal("eng.platform", team.GetProperty("externalKey").GetString());
        Assert.Equal([alice.MemberId], team.GetProperty("memberIds").EnumerateArray().Select(m => m.GetString()!).ToArray());

        // Applying the same key again replaces name and people on the same team.
        var replaced = await w.CallAsync(w.Owner, HttpMethod.Put, Path("eng.platform"), new { name = "Platform Engineering", memberIds = new[] { bob.MemberId } });
        Assert.Equal(HttpStatusCode.OK, replaced.Status);
        Assert.Equal(id, replaced.Body.GetProperty("team").GetProperty("id").GetString());
        Assert.Equal([bob.MemberId], replaced.Body.GetProperty("team").GetProperty("memberIds").EnumerateArray().Select(m => m.GetString()!).ToArray());
        // memberIds omitted means "nobody" for a declarative write: assignments are replaced.
        var emptied = await w.CallAsync(w.Owner, HttpMethod.Put, Path("eng.platform"), new { name = "Platform Engineering" });
        Assert.Empty(emptied.Body.GetProperty("team").GetProperty("memberIds").EnumerateArray());

        var read = await w.CallAsync(w.Owner, HttpMethod.Get, Path("eng.platform"));
        Assert.Equal(HttpStatusCode.OK, read.Status);
        Assert.Equal("Platform Engineering", read.Body.GetProperty("team").GetProperty("name").GetString());
        Assert.Equal("eng.platform", read.Body.GetProperty("team").GetProperty("externalKey").GetString());
        Assert.Equal("eng.platform", (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/teams/{id}")).Body.GetProperty("team").GetProperty("externalKey").GetString());
        Assert.Equal(HttpStatusCode.NotFound, (await w.CallAsync(w.Owner, HttpMethod.Get, Path("nobody.here"))).Status);
    }

    [Fact]
    public async Task An_unkeyed_team_is_never_adopted_and_preconditions_and_bad_keys_are_refused()
    {
        var w = await Workspace.CreateAsync(factory);
        var manual = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/teams", new { name = "Design" });
        Assert.Equal(HttpStatusCode.Created, manual.Status);
        Assert.Equal(JsonValueKind.Null, manual.Body.GetProperty("team").GetProperty("externalKey").ValueKind);

        var clash = await w.CallAsync(w.Owner, HttpMethod.Put, Path("design"), new { name = "Design" });
        Assert.Equal(HttpStatusCode.Conflict, clash.Status);
        Assert.Equal("team_exists", clash.Body.GetProperty("error").GetString());
        Assert.Equal(0, factory.WithDb(db => db.Teams.Count(t => t.OrganizationId == w.OrgId && t.ExternalKey == "design")));

        var request = w.As(w.Owner, HttpMethod.Put, Path("design-2"), new { name = "Design Two" });
        request.Headers.TryAddWithoutValidation("If-Match", "\"1\"");
        var precondition = await w.SendAsync(request);
        Assert.Equal(HttpStatusCode.BadRequest, precondition.StatusCode);
        Assert.Contains("unsupported_precondition", await precondition.Content.ReadAsStringAsync());

        foreach (var bad in new[] { "Upper", "-leading", "has space", new string('a', 129) })
            Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Put, Path(Uri.EscapeDataString(bad)), new { name = "X" })).Status);
    }

    [Fact]
    public async Task Delete_is_idempotent_and_writes_need_the_team_permissions()
    {
        var w = await Workspace.CreateAsync(factory);
        var member = await w.AddAsync();
        Assert.Equal(HttpStatusCode.Created, (await w.CallAsync(w.Owner, HttpMethod.Put, Path("ops"), new { name = "Ops" })).Status);

        // A member holds no team permissions.
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(member, HttpMethod.Get, Path("ops"))).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(member, HttpMethod.Put, Path("ops"), new { name = "Hijacked" })).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await w.CallAsync(member, HttpMethod.Delete, Path("ops"))).Status);
        Assert.Equal("Ops", factory.WithDb(db => db.Teams.Single(t => t.OrganizationId == w.OrgId && t.ExternalKey == "ops").Name));

        var gone = await w.CallAsync(w.Owner, HttpMethod.Delete, Path("ops"));
        Assert.Equal(HttpStatusCode.OK, gone.Status);
        Assert.True(gone.Body.GetProperty("deleted").GetBoolean());
        var again = await w.CallAsync(w.Owner, HttpMethod.Delete, Path("ops"));
        Assert.True(again.Body.GetProperty("ok").GetBoolean());
        Assert.False(again.Body.GetProperty("deleted").GetBoolean());
    }

    [Fact]
    public async Task Keys_belong_to_a_workspace_and_concurrent_writes_make_one_team()
    {
        var w = await Workspace.CreateAsync(factory);
        var other = await Workspace.CreateAsync(factory, "Other");
        Assert.Equal(HttpStatusCode.Created, (await w.CallAsync(w.Owner, HttpMethod.Put, Path("shared.key"), new { name = "Mine" })).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await other.CallAsync(other.Owner, HttpMethod.Get, Path("shared.key"))).Status);
        Assert.Equal(HttpStatusCode.OK, (await other.CallAsync(other.Owner, HttpMethod.Delete, Path("shared.key"))).Status);
        Assert.Equal(1, factory.WithDb(db => db.Teams.Count(t => t.OrganizationId == w.OrgId && t.ExternalKey == "shared.key")));
        Assert.Equal(HttpStatusCode.Created, (await other.CallAsync(other.Owner, HttpMethod.Put, Path("shared.key"), new { name = "Theirs" })).Status);

        var results = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => w.CallAsync(w.Owner, HttpMethod.Put, Path("race"), new { name = "Racing" })));
        Assert.All(results, r => Assert.True(r.Status is HttpStatusCode.Created or HttpStatusCode.OK, $"{r.Status} {r.Body}"));
        Assert.Equal(1, factory.WithDb(db => db.Teams.Count(t => t.OrganizationId == w.OrgId && t.ExternalKey == "race")));
    }
}
