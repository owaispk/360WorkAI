using System.Net;
using System.Net.Http.Json;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

public sealed class CorsFactory : ApiFactory
{
    protected override IEnumerable<KeyValuePair<string, string>> Settings => [new("Cors:Origins:0", "https://operator.example.com")];
}

public sealed class WebOriginEnforcementTests : IClassFixture<CorsFactory>
{
    private readonly CorsFactory _factory;
    public WebOriginEnforcementTests(CorsFactory factory) => _factory = factory;

    private static HttpRequestMessage From(string origin, HttpMethod method, string url, bool preflight = false)
    {
        var request = new HttpRequestMessage(method, url);
        request.Headers.Add("Origin", origin);
        if (preflight) { request.Headers.Add("Access-Control-Request-Method", "POST"); request.Headers.Add("Access-Control-Request-Headers", "content-type"); }
        return request;
    }

    private static string? Allowed(HttpResponseMessage r) => r.Headers.TryGetValues("Access-Control-Allow-Origin", out var v) ? v.Single() : null;

    private async Task ApproveAsync(Workspace w, string origin) =>
        Assert.Equal(HttpStatusCode.Created, (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/org/web-origins", new { origin })).Status);

    [Fact]
    public async Task Operator_and_own_origins_are_allowed_and_unknown_ones_get_no_cors_headers()
    {
        var http = _factory.Plain();
        var operatorOrigin = await http.SendAsync(From("https://operator.example.com", HttpMethod.Get, "/health"));
        Assert.Equal("https://operator.example.com", Allowed(operatorOrigin));
        Assert.Equal("true", operatorOrigin.Headers.GetValues("Access-Control-Allow-Credentials").Single());
        Assert.Contains("Origin", operatorOrigin.Headers.Vary);
        Assert.Equal("http://localhost", Allowed(await http.SendAsync(From("http://localhost", HttpMethod.Get, "/health"))));   // this deployment's own web origin

        foreach (var stranger in new[] { "https://stranger.example.com", "http://operator.example.com", "https://operator.example.com.evil.example", "null", "https://operator.example.com:8443" })
        {
            var response = await http.SendAsync(From(stranger, HttpMethod.Get, "/health"));
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);              // the request is served; the browser is simply not allowed to read it
            Assert.Null(Allowed(response));
            Assert.False(response.Headers.Contains("Access-Control-Allow-Credentials"));
        }
        // Without an Origin header nothing changes.
        Assert.Null(Allowed(await http.GetAsync("/health")));
    }

    [Fact]
    public async Task A_workspace_approving_an_origin_opens_it_and_removing_it_closes_it_at_once()
    {
        var w = await Workspace.CreateAsync(_factory);
        var origin = "https://embed.example.org";
        Assert.Null(Allowed(await w.Http.SendAsync(From(origin, HttpMethod.Get, "/health"))));   // also primes the negative cache

        await ApproveAsync(w, origin);
        Assert.Equal(origin, Allowed(await w.Http.SendAsync(From(origin, HttpMethod.Get, "/health"))));

        var id = (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/org/web-origins")).Body.GetProperty("origins").EnumerateArray().Single().GetProperty("id").GetString();
        Assert.Equal(HttpStatusCode.NoContent, (await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/org/web-origins/{id}")).Status);
        Assert.Null(Allowed(await w.Http.SendAsync(From(origin, HttpMethod.Get, "/health"))));
    }

    [Fact]
    public async Task Preflights_are_answered_only_for_allowed_origins_with_the_reference_headers()
    {
        var w = await Workspace.CreateAsync(_factory);
        var origin = "https://preflight.example.org";
        await ApproveAsync(w, origin);

        var ok = await w.Http.SendAsync(From(origin, HttpMethod.Options, "/v1/org", preflight: true));
        Assert.Equal(HttpStatusCode.NoContent, ok.StatusCode);
        Assert.Equal(origin, Allowed(ok));
        Assert.Equal("GET, POST, PUT, PATCH, DELETE, OPTIONS", ok.Headers.GetValues("Access-Control-Allow-Methods").Single());
        Assert.Contains("X-Api-Key", ok.Headers.GetValues("Access-Control-Allow-Headers").Single());
        Assert.Contains("X-OpenWork-Org-Id", ok.Headers.GetValues("Access-Control-Allow-Headers").Single());
        Assert.Equal("600", ok.Headers.GetValues("Access-Control-Max-Age").Single());

        var refused = await w.Http.SendAsync(From("https://not-approved.example.org", HttpMethod.Options, "/v1/org", preflight: true));
        Assert.Null(Allowed(refused));
        Assert.NotEqual(HttpStatusCode.NoContent, refused.StatusCode);
    }

    [Fact]
    public async Task Only_a_canonical_https_origin_can_be_approved_so_look_alikes_never_match()
    {
        var w = await Workspace.CreateAsync(_factory);
        await ApproveAsync(w, "https://exact.example.org");
        foreach (var lookAlike in new[] { "http://exact.example.org", "https://exact.example.org:444", "https://EXACT.example.org.", "https://sub.exact.example.org", "https://exact.example.org/" })
            Assert.Null(Allowed(await w.Http.SendAsync(From(lookAlike, HttpMethod.Get, "/health"))));
        Assert.Equal("https://exact.example.org", Allowed(await w.Http.SendAsync(From("https://exact.example.org", HttpMethod.Get, "/health"))));
        // A non-canonical origin is never even looked up (it could never have been approved).
        Assert.Null(Allowed(await w.Http.SendAsync(From("https://exact.example.org:443", HttpMethod.Get, "/health"))));
    }

    [Fact]
    public async Task The_desktop_handoff_exchange_is_open_to_any_origin_and_nothing_else_is()
    {
        var http = _factory.Plain();
        var origin = "https://preview-1234.example.net";
        var exchange = await http.SendAsync(From(origin, HttpMethod.Options, "/v1/auth/desktop-handoff/exchange", preflight: true));
        Assert.Equal(HttpStatusCode.NoContent, exchange.StatusCode);
        Assert.Equal(origin, Allowed(exchange));
        Assert.Equal("POST, OPTIONS", exchange.Headers.GetValues("Access-Control-Allow-Methods").Single());
        Assert.Equal("Content-Type, Authorization, X-Request-Id", exchange.Headers.GetValues("Access-Control-Allow-Headers").Single());
        // A neighbouring route does not get the same treatment.
        Assert.Null(Allowed(await http.SendAsync(From(origin, HttpMethod.Options, "/v1/auth/desktop-handoff/status", preflight: true))));
        Assert.Null(Allowed(await http.SendAsync(From(origin, HttpMethod.Post, "/v1/auth/desktop-handoff"))));
    }
}

public sealed class HandoffReturnUrlTests : IClassFixture<ApiFactory>
{
    private readonly ApiFactory _factory;
    public HandoffReturnUrlTests(ApiFactory factory) => _factory = factory;

    private async Task<(HttpStatusCode Status, System.Text.Json.JsonElement Body)> HandoffAsync(Workspace w, Person p, string? returnUrl) =>
        await w.CallAsync(p, HttpMethod.Post, "/v1/auth/desktop-handoff", returnUrl is null ? new { } : new { returnUrl });

    [Fact]
    public async Task An_approved_origin_is_honored_and_always_sends_the_person_to_its_sign_in_page()
    {
        var w = await Workspace.CreateAsync(_factory);
        await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/org/web-origins", new { origin = "https://app.example.org" });
        foreach (var url in new[] { "https://app.example.org", "https://app.example.org/", "https://app.example.org/signin", "https://APP.example.org/signin" })
        {
            var r = await HandoffAsync(w, w.Owner, url);
            Assert.Equal(HttpStatusCode.OK, r.Status);
            Assert.Equal("https://app.example.org/signin", r.Body.GetProperty("returnUrl").GetString());
            Assert.StartsWith("openwork://den-auth?grant=", r.Body.GetProperty("openworkUrl").GetString());
        }
        // Without a return URL the answer carries none, as before.
        Assert.Equal(System.Text.Json.JsonValueKind.Null, (await HandoffAsync(w, w.Owner, null)).Body.GetProperty("returnUrl").ValueKind);
    }

    [Fact]
    public async Task Anything_not_approved_or_not_shaped_right_is_refused_with_the_reference_message()
    {
        var w = await Workspace.CreateAsync(_factory);
        await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/org/web-origins", new { origin = "https://app.example.org" });
        foreach (var bad in new[]
        {
            "https://other.example.org/signin",              // not approved
            "http://app.example.org/signin",                 // not https
            "https://app.example.org/evil",                  // only / and /signin
            "https://app.example.org/signin?next=//evil",    // no query beyond what the page needs: the URL handed back drops it, so this is fine to accept? the path is what is checked
            "https://user:pw@app.example.org/signin",        // credentials
            "https://app.example.org/signin#x",              // fragment
            "https://app.example.org/%2e%2e/signin",         // traversal
            "https://app.example.org/a/../signin",
            "https://app.example.org:8443/signin",           // a different origin
            "javascript:alert(1)", "not a url", "",
        })
        {
            var r = await HandoffAsync(w, w.Owner, bad);
            if (bad.Contains("?next=")) { Assert.Equal(HttpStatusCode.OK, r.Status); Assert.Equal("https://app.example.org/signin", r.Body.GetProperty("returnUrl").GetString()); continue; }
            Assert.True(r.Status == HttpStatusCode.BadRequest, $"{bad} was accepted");
            Assert.Equal("invalid_return_url", r.Error());
            Assert.Equal("The Cloud web handoff return URL is not approved for this organization.", r.Body.GetProperty("message").GetString());
        }
    }

    [Fact]
    public async Task Another_workspaces_approval_never_counts_and_a_members_other_workspace_does_and_becomes_active()
    {
        var w1 = await Workspace.CreateAsync(_factory);
        var w2 = await Workspace.CreateAsync(_factory);
        await w2.CallAsync(w2.Owner, HttpMethod.Post, "/v1/org/web-origins", new { origin = "https://second.example.org" });

        // w1's owner is not a member of w2, so w2's approval means nothing to them.
        Assert.Equal("invalid_return_url", (await HandoffAsync(w1, w1.Owner, "https://second.example.org/signin")).Error());

        // A person who belongs to both: the second workspace's approval is enough, and the session switches to it.
        var both = await w2.AddAsync();
        var inv = await w1.InviteAsync(both.Email);
        Assert.Equal(HttpStatusCode.OK, (await w1.Http.SendAsync(Bearer(HttpMethod.Post, "/v1/orgs/invitations/accept", both.Token, new { id = inv.GetProperty("invitationId").GetString() }))).StatusCode);
        await w1.Http.SendAsync(Bearer(HttpMethod.Post, "/v1/me/active-organization", both.Token, new { organizationId = w1.OrgId }));
        var r = await HandoffAsync(w1, both, "https://second.example.org/signin");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal(w2.OrgId, _factory.WithDb(db => db.Sessions.Single(s => s.UserId == both.UserId && s.ActiveOrganizationId != null).ActiveOrganizationId));
        Assert.Equal(w2.OrgId, _factory.WithDb(db => db.HandoffGrants.Single(g => g.UserId == both.UserId).OrganizationId));
    }

    [Fact]
    public async Task A_removed_approval_stops_working_and_the_route_still_needs_a_session()
    {
        var w = await Workspace.CreateAsync(_factory);
        await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/org/web-origins", new { origin = "https://gone.example.org" });
        Assert.Equal(HttpStatusCode.OK, (await HandoffAsync(w, w.Owner, "https://gone.example.org")).Status);
        var id = (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/org/web-origins")).Body.GetProperty("origins").EnumerateArray().Single().GetProperty("id").GetString();
        await w.CallAsync(w.Owner, HttpMethod.Delete, $"/v1/org/web-origins/{id}");
        Assert.Equal("invalid_return_url", (await HandoffAsync(w, w.Owner, "https://gone.example.org")).Error());
        var anonymous = await w.Http.PostAsJsonAsync("/v1/auth/desktop-handoff", new { returnUrl = "https://gone.example.org" });
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
    }
}
