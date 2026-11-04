using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Domain.Connections;

namespace WorkAI360.Api.Tests;

/// <summary>POST /v1/mcp-connections/{id}/oauth/issuer-review: preview the issuers an MCP server advertises now, or confirm one.</summary>
public sealed class IssuerReviewTests : IClassFixture<ConnectionFactory>, IAsyncLifetime
{
    private readonly ConnectionFactory _factory;
    private FakeMcpServer _fake = null!;
    public IssuerReviewTests(ConnectionFactory factory) => _factory = factory;
    public async Task InitializeAsync() => _fake = await FakeMcpServer.StartAsync();
    public async Task DisposeAsync() => await _fake.DisposeAsync();

    private static string Path(string id) => $"/v1/mcp-connections/{id}/oauth/issuer-review";

    private async Task<string> OAuthConnectionAsync(Workspace w)
    {
        var r = await w.Post(w.Owner, new { name = "OAuth server", url = _fake.Url("oauth"), authType = "oauth", credentialMode = "per_member" });
        Assert.True(r.Status == HttpStatusCode.OK, $"{r.Status} {r.Body}");
        return r.Body.GetProperty("id").GetString()!;
    }

    private async Task<string> UpdatedAtAsync(Workspace w, string id) =>
        (await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/mcp-connections/{id}")).Body.GetProperty("updatedAt").GetString()!;

    /// <summary>The owner signs in to the provider, so the connection has an account, a registered client and a pinned issuer.</summary>
    private async Task SignInAsync(Workspace w, string id)
    {
        var start = await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/mcp-connections/{id}/connect/start");
        Assert.True(start.Status == HttpStatusCode.OK, $"{start.Status} {start.Body}");
        using var browser = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        var redirect = await browser.GetAsync(start.Body.GetProperty("authorizeUrl").GetString()!);
        var callback = await w.Http.GetAsync(new Uri(redirect.Headers.Location!.ToString()).PathAndQuery);
        Assert.Equal(HttpStatusCode.OK, callback.StatusCode);
    }

    [Fact]
    public async Task Preview_lists_the_advertised_issuers_without_changing_anything()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await OAuthConnectionAsync(w);
        var before = await UpdatedAtAsync(w, id);
        var r = await w.CallAsync(w.Owner, HttpMethod.Post, Path(id), new { action = "preview" });
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal(["currentIssuer", "advertisedIssuers", "reviewRequired"], r.Body.EnumerateObject().Select(p => p.Name).ToArray());
        Assert.Equal(JsonValueKind.Null, r.Body.GetProperty("currentIssuer").ValueKind);
        Assert.Equal([_fake.Origin], r.Body.GetProperty("advertisedIssuers").EnumerateArray().Select(e => e.GetString()!).ToArray());
        Assert.False(r.Body.GetProperty("reviewRequired").GetBoolean());
        Assert.Equal(before, await UpdatedAtAsync(w, id));

        await SignInAsync(w, id);
        Assert.Equal(_fake.Origin, (await w.CallAsync(w.Owner, HttpMethod.Post, Path(id), new { action = "preview" })).Body.GetProperty("currentIssuer").GetString());
    }

    [Fact]
    public async Task The_body_and_path_are_validated_with_the_references_wording()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await OAuthConnectionAsync(w);
        var missing = await w.CallAsync(w.Owner, HttpMethod.Post, Path(id), new { });
        Assert.Equal(HttpStatusCode.BadRequest, missing.Status);
        Assert.Equal("action: Invalid input", missing.Msg());
        Assert.Equal("invalid_union", missing.Body.GetProperty("details")[0].GetProperty("code").GetString());
        Assert.Equal("action: Invalid input", (await w.CallAsync(w.Owner, HttpMethod.Post, Path(id), new { action = "approve" })).Msg());

        var confirm = await w.CallAsync(w.Owner, HttpMethod.Post, Path(id), new { action = "confirm" });
        Assert.Equal(HttpStatusCode.BadRequest, confirm.Status);
        Assert.Equal("expectedUpdatedAt: Invalid input: expected string, received undefined (and 1 more)", confirm.Msg());
        var bad = await w.CallAsync(w.Owner, HttpMethod.Post, Path(id), new { action = "confirm", expectedUpdatedAt = "yesterday", authorizationServerIssuer = "not a url" });
        Assert.Equal(["expectedUpdatedAt", "authorizationServerIssuer"], bad.Body.GetProperty("details").EnumerateArray().Select(d => d.GetProperty("path")[0].GetString()!).ToArray());
        Assert.Equal("expectedUpdatedAt: Invalid ISO datetime (and 1 more)", bad.Msg());

        var malformed = await w.CallAsync(w.Owner, HttpMethod.Post, Path("emc_nope"), new { action = "preview" });
        Assert.Equal(HttpStatusCode.BadRequest, malformed.Status);
        Assert.StartsWith("connectionId: ", malformed.Msg());
    }

    [Fact]
    public async Task Only_those_who_manage_connections_may_review_and_other_workspaces_ids_are_404()
    {
        var w = await Workspace.CreateAsync(_factory);
        var member = await w.AddAsync();
        var admin = await w.AddAsync("admin");
        var id = await OAuthConnectionAsync(w);
        var denied = await w.CallAsync(member, HttpMethod.Post, Path(id), new { action = "preview" });
        Assert.Equal(HttpStatusCode.Forbidden, denied.Status);
        Assert.Equal("connections.manage", denied.Required());
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(admin, HttpMethod.Post, Path(id), new { action = "preview" })).Status);

        var other = await Workspace.CreateAsync(_factory, "Other Space");
        var foreign = await other.CallAsync(other.Owner, HttpMethod.Post, Path(id), new { action = "preview" });
        Assert.Equal(HttpStatusCode.NotFound, foreign.Status);
        Assert.Equal("connection_not_found", Workspace.Error(foreign.Body));
        var confirm = await other.CallAsync(other.Owner, HttpMethod.Post, Path(id), new { action = "confirm", expectedUpdatedAt = await UpdatedAtAsync(w, id), authorizationServerIssuer = _fake.Origin });
        Assert.Equal(HttpStatusCode.NotFound, confirm.Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Http.PostAsync(Path(id), null)).StatusCode);
    }

    [Fact]
    public async Task Confirming_needs_a_recent_sign_in_and_is_refused_to_API_keys_but_preview_is_not()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await OAuthConnectionAsync(w);
        var at = await UpdatedAtAsync(w, id);
        var (_, key) = await w.MakeKeyAsync();
        var byKey = await w.WithKeyAsync(key, HttpMethod.Post, Path(id), new { action = "confirm", expectedUpdatedAt = at, authorizationServerIssuer = _fake.Origin });
        Assert.Equal(HttpStatusCode.Forbidden, byKey.Status);
        Assert.Equal("Confirm an issuer from the dashboard; API keys can't do this.", byKey.Body.GetProperty("message").GetString());
        Assert.Equal(HttpStatusCode.OK, (await w.WithKeyAsync(key, HttpMethod.Post, Path(id), new { action = "preview" })).Status);

        _factory.WithDb(db => db.Sessions.Where(s => s.UserId == w.Owner.UserId).ExecuteUpdate(s => s.SetProperty(x => x.CreatedAt, DateTime.UtcNow.AddHours(-5))));
        var stale = await w.CallAsync(w.Owner, HttpMethod.Post, Path(id), new { action = "confirm", expectedUpdatedAt = at, authorizationServerIssuer = _fake.Origin });
        Assert.Equal(HttpStatusCode.Forbidden, stale.Status);
        Assert.Equal("reauth", Workspace.Error(stale.Body));
        Assert.Equal(HttpStatusCode.OK, (await w.CallAsync(w.Owner, HttpMethod.Post, Path(id), new { action = "preview" })).Status);
        Assert.Equal(at, await UpdatedAtAsync(w, id));
    }

    [Fact]
    public async Task Only_OAuth_connections_are_reviewed_and_a_failed_discovery_is_502()
    {
        var w = await Workspace.CreateAsync(_factory);
        var none = await w.NoneAsync(_fake);
        var notOAuth = await w.CallAsync(w.Owner, HttpMethod.Post, Path(none), new { action = "preview" });
        Assert.Equal(HttpStatusCode.BadRequest, notOAuth.Status);
        Assert.Equal("Issuer review is only available for OAuth MCP connections.", notOAuth.Msg());

        var id = await OAuthConnectionAsync(w);
        _factory.WithDb(db => db.Set<ExternalMcpConnection>().Where(c => c.Id == id).ExecuteUpdate(s => s.SetProperty(c => c.Url, _fake.Url("none"))));
        var failed = await w.CallAsync(w.Owner, HttpMethod.Post, Path(id), new { action = "preview" });
        Assert.Equal(HttpStatusCode.BadGateway, failed.Status);
        Assert.Equal("requirements_discovery_failed", Workspace.Error(failed.Body));
    }

    [Fact]
    public async Task Confirming_an_unadvertised_issuer_or_a_stale_version_is_a_conflict()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await OAuthConnectionAsync(w);
        var at = await UpdatedAtAsync(w, id);
        var foreign = await w.CallAsync(w.Owner, HttpMethod.Post, Path(id), new { action = "confirm", expectedUpdatedAt = at, authorizationServerIssuer = "https://elsewhere.example" });
        Assert.Equal(HttpStatusCode.Conflict, foreign.Status);
        Assert.Equal("connection_conflict", Workspace.Error(foreign.Body));
        Assert.Equal("The selected issuer is not currently advertised by this MCP resource. Refresh the review before confirming.", foreign.Msg());

        var stale = await w.CallAsync(w.Owner, HttpMethod.Post, Path(id), new { action = "confirm", expectedUpdatedAt = "2020-01-01T00:00:00.000Z", authorizationServerIssuer = _fake.Origin });
        Assert.Equal(HttpStatusCode.Conflict, stale.Status);
        Assert.Equal("This connection changed while the issuer was being reviewed. Reload and review the current provider metadata again.", stale.Msg());
        Assert.Equal(at, await UpdatedAtAsync(w, id));
    }

    [Fact]
    public async Task Confirming_the_same_issuer_keeps_sign_ins_and_a_new_one_drops_everything_bound_to_the_old()
    {
        var w = await Workspace.CreateAsync(_factory);
        var id = await OAuthConnectionAsync(w);
        await SignInAsync(w, id);

        var same = await w.CallAsync(w.Owner, HttpMethod.Post, Path(id), new { action = "confirm", expectedUpdatedAt = await UpdatedAtAsync(w, id), authorizationServerIssuer = _fake.Origin });
        Assert.Equal(HttpStatusCode.OK, same.Status);
        Assert.Equal(["currentIssuer", "advertisedIssuers", "reviewRequired", "issuerChanged", "reconnectionRequired", "updatedAt"], same.Body.EnumerateObject().Select(p => p.Name).ToArray());
        Assert.False(same.Body.GetProperty("issuerChanged").GetBoolean());
        Assert.False(same.Body.GetProperty("reconnectionRequired").GetBoolean());
        Assert.Equal(await UpdatedAtAsync(w, id), same.Body.GetProperty("updatedAt").GetString());
        Assert.Equal((1, 1), _factory.WithDb(db => (db.Set<ConnectedAccount>().Count(a => a.ConnectionId == id), db.Set<ConnectionOAuthClient>().Count(c => c.ConnectionId == id))));

        // The connection was pinned to an issuer the server no longer advertises: confirming the advertised one resets the sign-ins.
        _factory.WithDb(db =>
        {
            var c = db.Set<ExternalMcpConnection>().Single(x => x.Id == id);
            var config = JsonNode.Parse(c.OAuthConfigJson!)!.AsObject();
            config["authorizationServerIssuer"] = "https://old-issuer.example";
            c.OAuthConfigJson = config.ToJsonString();
            return db.SaveChanges();
        });
        var preview = await w.CallAsync(w.Owner, HttpMethod.Post, Path(id), new { action = "preview" });
        Assert.Equal("https://old-issuer.example", preview.Body.GetProperty("currentIssuer").GetString());
        var changed = await w.CallAsync(w.Owner, HttpMethod.Post, Path(id), new { action = "confirm", expectedUpdatedAt = await UpdatedAtAsync(w, id), authorizationServerIssuer = _fake.Origin });
        Assert.Equal(HttpStatusCode.OK, changed.Status);
        Assert.Equal(_fake.Origin, changed.Body.GetProperty("currentIssuer").GetString());
        Assert.True(changed.Body.GetProperty("issuerChanged").GetBoolean());
        Assert.True(changed.Body.GetProperty("reconnectionRequired").GetBoolean());
        var (accounts, clients, issuer) = _factory.WithDb(db => (db.Set<ConnectedAccount>().Count(a => a.ConnectionId == id), db.Set<ConnectionOAuthClient>().Count(c => c.ConnectionId == id),
            JsonNode.Parse(db.Set<ExternalMcpConnection>().AsNoTracking().Single(c => c.Id == id).OAuthConfigJson!)!["authorizationServerIssuer"]!.GetValue<string>()));
        Assert.Equal((0, 0, _fake.Origin), (accounts, clients, issuer));
        Assert.False((await w.CallAsync(w.Owner, HttpMethod.Get, $"/v1/mcp-connections/{id}")).Body.GetProperty("connectedForMe").GetBoolean());
    }
}
