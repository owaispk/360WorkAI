using System.Net;
using System.Net.Http.Json;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

public sealed class OrgTests : IClassFixture<ApiFactory>
{
    private readonly ApiFactory _factory;
    public OrgTests(ApiFactory factory) => _factory = factory;

    private static async Task<string> CreateOrgAsync(HttpClient client, string token, string name = "Acme")
    {
        var response = await client.SendAsync(Bearer(HttpMethod.Post, "/v1/org", token, new { name }));
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return (await ReadJsonAsync(response)).GetProperty("organization").GetProperty("id").GetString()!;
    }

    [Fact]
    public async Task Creating_an_org_makes_the_creator_owner_and_activates_it()
    {
        var client = _factory.Plain();
        var (_, token, _) = await _factory.SignUpAsync(client);
        var orgId = await CreateOrgAsync(client, token);

        var orgs = await ReadJsonAsync(await client.SendAsync(Bearer(HttpMethod.Get, "/v1/me/orgs", token)));
        Assert.Equal(orgId, orgs.GetProperty("activeOrgId").GetString());
        var entry = orgs.GetProperty("orgs").EnumerateArray().Single();
        Assert.Equal("owner", entry.GetProperty("role").GetString());
        Assert.Matches(@"^org_", orgId);
    }

    [Fact]
    public async Task A_user_who_is_not_a_member_cannot_read_or_activate_the_org()
    {
        var client = _factory.Plain();
        var (_, ownerToken, _) = await _factory.SignUpAsync(client, "Owner");
        var (_, outsiderToken, _) = await _factory.SignUpAsync(client, "Outsider");
        var orgId = await CreateOrgAsync(client, ownerToken);

        var read = Bearer(HttpMethod.Get, "/v1/org", outsiderToken);
        read.Headers.Add("x-openwork-org-id", orgId);
        var notFound = await client.SendAsync(read);
        Assert.Equal(HttpStatusCode.NotFound, notFound.StatusCode);           // a workspace you are not in does not exist for you
        Assert.Equal("organization_not_found", (await ReadJsonAsync(notFound)).GetProperty("error").GetString());

        var activate = await client.SendAsync(Bearer(HttpMethod.Post, "/v1/me/active-organization", outsiderToken, new { organizationId = orgId }));
        Assert.Equal(HttpStatusCode.Forbidden, activate.StatusCode);
        var viaAuth = await client.SendAsync(Bearer(HttpMethod.Post, "/api/auth/organization/set-active", outsiderToken, new { organizationId = orgId }));
        Assert.Equal(HttpStatusCode.Forbidden, viaAuth.StatusCode);
    }

    [Fact]
    public async Task Org_names_are_validated_and_the_routes_require_a_session()
    {
        var client = _factory.Plain();
        var (_, token, _) = await _factory.SignUpAsync(client);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.SendAsync(Bearer(HttpMethod.Post, "/v1/org", token, new { name = "x" }))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/v1/me/orgs")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/v1/org", new { name = "Acme" })).StatusCode);
    }

    [Fact]
    public async Task Sign_in_restores_the_users_org_as_active()
    {
        var client = _factory.Plain();
        var (email, token, _) = await _factory.SignUpAsync(client);
        var orgId = await CreateOrgAsync(client, token);

        var signIn = await client.PostAsJsonAsync("/api/auth/sign-in/email", new { email, password = Password });
        var fresh = (await ReadJsonAsync(signIn)).GetProperty("token").GetString()!;
        var me = await ReadJsonAsync(await client.SendAsync(Bearer(HttpMethod.Get, "/v1/me", fresh)));
        Assert.Equal(orgId, me.GetProperty("session").GetProperty("activeOrganizationId").GetString());
    }

    [Fact]
    public async Task Login_options_tell_the_form_which_step_is_next()
    {
        var client = _factory.Plain();
        var (email, _, _) = await _factory.SignUpAsync(client);
        Assert.Equal("password", (await ReadJsonAsync(await client.GetAsync($"/v1/auth/login-options?email={Uri.EscapeDataString(email)}"))).GetProperty("nextStep").GetString());
        Assert.Equal("new_account", (await ReadJsonAsync(await client.GetAsync($"/v1/auth/login-options?email={Uri.EscapeDataString(NewEmail("fresh"))}"))).GetProperty("nextStep").GetString());
        Assert.Equal(HttpStatusCode.BadRequest, (await client.GetAsync("/v1/auth/login-options?email=nope")).StatusCode);
    }
}

public sealed class HandoffTests : IClassFixture<ApiFactory>
{
    private readonly ApiFactory _factory;
    public HandoffTests(ApiFactory factory) => _factory = factory;

    private async Task<string> GrantAsync(HttpClient client, string token)
    {
        var response = await client.SendAsync(Bearer(HttpMethod.Post, "/v1/auth/desktop-handoff", token, new { desktopScheme = "openwork" }));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await ReadJsonAsync(response);
        Assert.StartsWith("openwork://den-auth?grant=", json.GetProperty("openworkUrl").GetString());
        return json.GetProperty("grant").GetString()!;
    }

    [Fact]
    public async Task A_grant_is_exchanged_once_for_a_fresh_session_not_the_web_token()
    {
        var client = _factory.Plain();
        var (_, webToken, userId) = await _factory.SignUpAsync(client);
        var grant = await GrantAsync(client, webToken);

        Assert.Equal("pending", (await ReadJsonAsync(await client.PostAsJsonAsync("/v1/auth/desktop-handoff/status", new { grant }))).GetProperty("status").GetString());

        var exchange = await client.PostAsJsonAsync("/v1/auth/desktop-handoff/exchange", new { grant });
        Assert.Equal(HttpStatusCode.OK, exchange.StatusCode);
        var json = await ReadJsonAsync(exchange);
        var desktopToken = json.GetProperty("token").GetString()!;
        Assert.NotEqual(webToken, desktopToken);
        Assert.Equal(userId, json.GetProperty("user").GetProperty("id").GetString());
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(Bearer(HttpMethod.Get, "/v1/me", desktopToken))).StatusCode);

        Assert.Equal("consumed", (await ReadJsonAsync(await client.PostAsJsonAsync("/v1/auth/desktop-handoff/status", new { grant }))).GetProperty("status").GetString());
        var replay = await client.PostAsJsonAsync("/v1/auth/desktop-handoff/exchange", new { grant });
        Assert.Equal(HttpStatusCode.NotFound, replay.StatusCode);
        Assert.Equal("grant_not_found", (await ReadJsonAsync(replay)).GetProperty("error").GetString());
    }

    [Fact]
    public async Task Signing_out_the_web_session_does_not_kill_the_desktop_session()
    {
        var client = _factory.Plain();
        var (_, webToken, _) = await _factory.SignUpAsync(client);
        var grant = await GrantAsync(client, webToken);
        var desktopToken = (await ReadJsonAsync(await client.PostAsJsonAsync("/v1/auth/desktop-handoff/exchange", new { grant }))).GetProperty("token").GetString()!;

        await client.SendAsync(Bearer(HttpMethod.Post, "/api/auth/sign-out", webToken, new { }));
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Bearer(HttpMethod.Get, "/v1/me", webToken))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(Bearer(HttpMethod.Get, "/v1/me", desktopToken))).StatusCode);
    }

    [Fact]
    public async Task Concurrent_exchanges_of_one_grant_succeed_exactly_once()
    {
        var client = _factory.Plain();
        var (_, token, _) = await _factory.SignUpAsync(client);
        var grant = await GrantAsync(client, token);

        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => client.PostAsJsonAsync("/v1/auth/desktop-handoff/exchange", new { grant })));
        Assert.Equal(1, results.Count(r => r.StatusCode == HttpStatusCode.OK));
        Assert.Equal(7, results.Count(r => r.StatusCode == HttpStatusCode.NotFound));
    }

    [Fact]
    public async Task Handoff_requires_a_session_and_refuses_unapproved_return_urls_and_short_grants()
    {
        var client = _factory.Plain();
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/v1/auth/desktop-handoff", new { desktopScheme = "openwork" })).StatusCode);

        var (_, token, _) = await _factory.SignUpAsync(client);
        var withReturn = await client.SendAsync(Bearer(HttpMethod.Post, "/v1/auth/desktop-handoff", token, new { returnUrl = "https://evil.example/cb" }));
        Assert.Equal(HttpStatusCode.BadRequest, withReturn.StatusCode);
        var badScheme = await client.SendAsync(Bearer(HttpMethod.Post, "/v1/auth/desktop-handoff", token, new { desktopScheme = "javascript:alert(1)//" }));
        Assert.Equal(HttpStatusCode.BadRequest, badScheme.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/v1/auth/desktop-handoff/exchange", new { grant = "short" })).StatusCode);
    }
}

public sealed class DeviceTests : IClassFixture<ApiFactory>
{
    private const string Grant = "urn:ietf:params:oauth:grant-type:device_code";
    private readonly ApiFactory _factory;
    public DeviceTests(ApiFactory factory) => _factory = factory;

    private static async Task<(string DeviceCode, string UserCode)> StartAsync(HttpClient client, string clientId = "openwork-cli")
    {
        var response = await client.PostAsJsonAsync("/api/auth/device/code", new { client_id = clientId });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await ReadJsonAsync(response);
        Assert.Equal(900, json.GetProperty("expires_in").GetInt32());
        Assert.Equal(5, json.GetProperty("interval").GetInt32());
        Assert.EndsWith(json.GetProperty("user_code").GetString()!, json.GetProperty("verification_uri_complete").GetString());
        return (json.GetProperty("device_code").GetString()!, json.GetProperty("user_code").GetString()!);
    }

    private static Task<HttpResponseMessage> PollAsync(HttpClient client, string deviceCode, string clientId = "openwork-cli") =>
        client.PostAsJsonAsync("/api/auth/device/token", new { grant_type = Grant, device_code = deviceCode, client_id = clientId });

    private static async Task<string?> ErrorAsync(HttpResponseMessage response) =>
        (await ReadJsonAsync(response)).GetProperty("error").GetString();

    [Fact]
    public async Task Unknown_clients_are_refused()
    {
        var response = await _factory.Plain().PostAsJsonAsync("/api/auth/device/code", new { client_id = "nope" });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("invalid_client", await ErrorAsync(response));
    }

    [Fact]
    public async Task Approval_yields_an_access_token_exactly_once()
    {
        var client = _factory.Plain();
        var (_, approverToken, userId) = await _factory.SignUpAsync(client);
        var (deviceCode, userCode) = await StartAsync(client);

        Assert.Equal("authorization_pending", await ErrorAsync(await PollAsync(client, deviceCode)));

        var lookup = await client.SendAsync(Bearer(HttpMethod.Get, $"/v1/auth/device/{userCode[..4]}-{userCode[4..]}", approverToken));
        Assert.Equal("pending", (await ReadJsonAsync(lookup)).GetProperty("status").GetString());

        var decision = await client.SendAsync(Bearer(HttpMethod.Post, "/v1/auth/device/decision", approverToken, new { userCode, decision = "approve" }));
        Assert.Equal(HttpStatusCode.OK, decision.StatusCode);
        var again = await client.SendAsync(Bearer(HttpMethod.Post, "/v1/auth/device/decision", approverToken, new { userCode, decision = "deny" }));
        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);

        await Task.Delay(TimeSpan.FromSeconds(5.2)); // the poll interval
        var token = await PollAsync(client, deviceCode);
        Assert.Equal(HttpStatusCode.OK, token.StatusCode);
        var json = await ReadJsonAsync(token);
        Assert.Equal("Bearer", json.GetProperty("token_type").GetString());
        var access = json.GetProperty("access_token").GetString()!;
        var me = await ReadJsonAsync(await client.SendAsync(Bearer(HttpMethod.Get, "/v1/me", access)));
        Assert.Equal(userId, me.GetProperty("user").GetProperty("id").GetString());

        await Task.Delay(TimeSpan.FromSeconds(5.2));
        Assert.Equal("invalid_grant", await ErrorAsync(await PollAsync(client, deviceCode)));
    }

    [Fact]
    public async Task Denial_is_reported_to_the_device()
    {
        var client = _factory.Plain();
        var (_, approverToken, _) = await _factory.SignUpAsync(client);
        var (deviceCode, userCode) = await StartAsync(client, "openwork-opencode-plugin");
        await client.SendAsync(Bearer(HttpMethod.Post, "/v1/auth/device/decision", approverToken, new { userCode, decision = "deny" }));

        await Task.Delay(TimeSpan.FromSeconds(5.2));
        Assert.Equal("access_denied", await ErrorAsync(await PollAsync(client, deviceCode, "openwork-opencode-plugin")));
    }

    [Fact]
    public async Task Polling_faster_than_the_interval_is_told_to_slow_down()
    {
        var client = _factory.Plain();
        var (deviceCode, _) = await StartAsync(client);
        Assert.Equal("authorization_pending", await ErrorAsync(await PollAsync(client, deviceCode)));
        Assert.Equal("slow_down", await ErrorAsync(await PollAsync(client, deviceCode)));
    }

    [Fact]
    public async Task Only_a_signed_in_person_can_decide_and_a_device_code_cannot_be_used_by_another_client()
    {
        var client = _factory.Plain();
        var (deviceCode, userCode) = await StartAsync(client);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/v1/auth/device/decision", new { userCode, decision = "approve" })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync($"/v1/auth/device/{userCode}")).StatusCode);
        Assert.Equal("invalid_grant", await ErrorAsync(await PollAsync(client, deviceCode, "openwork-opencode-plugin")));
    }
}
