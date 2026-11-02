using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.Library;
using WorkAI360.Api.Domain.Onboarding;
using WorkAI360.Api.Email;
using WorkAI360.Api.Features.Connections;
using WorkAI360.Api.Features.Onboarding;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>Plenty of bootstrap attempts, and an installer folder for the download test.</summary>
public sealed class OnboardingFactory : ApiFactory
{
    public static readonly string Artifacts = Path.Combine(Path.GetTempPath(), $"workai-installers-{Guid.NewGuid():N}");
    protected override IEnumerable<KeyValuePair<string, string>> Settings =>
    [
        new("Onboarding:Bootstrap:LimitPerHour", "1000"),
        new("Onboarding:Desktop:ArtifactsDir", Artifacts),
        new("Onboarding:Desktop:LatestVersion", "1.2.3"),
        new("Onboarding:Desktop:MinAppVersion", "1.0.0"),
        new("Onboarding:Desktop:PublishedVersions:0", "1.2.3"),
        new("Onboarding:Desktop:PublishedVersions:1", "1.2.2"),
    ];
}

/// <summary>Three workspaces an hour per address.</summary>
public sealed class OnboardingLimitFactory : ApiFactory
{
    protected override IEnumerable<KeyValuePair<string, string>> Settings => [new("Onboarding:Bootstrap:LimitPerHour", "3")];
}

public sealed class FailingMail : IEmailSender
{
    public Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default) => throw new HttpRequestException("Resend refused the message (422).", null, HttpStatusCode.UnprocessableEntity);
}

/// <summary>The mail provider is down.</summary>
public sealed class OnboardingMailDownFactory : ApiFactory
{
    protected override void ConfigureWebHost(Microsoft.AspNetCore.Hosting.IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureTestServices(s => s.AddSingleton<IEmailSender, FailingMail>());
    }
}

public sealed class OnboardingTests : IClassFixture<OnboardingFactory>
{
    private readonly OnboardingFactory _factory;
    public OnboardingTests(OnboardingFactory factory) => _factory = factory;

    private HttpClient Anon() => _factory.Plain();

    private static async Task<(HttpStatusCode Status, JsonElement Body, HttpResponseMessage Raw)> SendAsync(HttpClient http, HttpRequestMessage request)
    {
        var r = await http.SendAsync(request);
        var text = await r.Content.ReadAsStringAsync();
        return (r.StatusCode, string.IsNullOrEmpty(text) ? default : JsonDocument.Parse(text).RootElement.Clone(), r);
    }

    private static Task<(HttpStatusCode Status, JsonElement Body, HttpResponseMessage Raw)> As(HttpClient http, string token, HttpMethod method, string url, object? body = null) => SendAsync(http, Bearer(method, url, token, body));

    private async Task<Person> NewPersonAsync(HttpClient http)
    {
        var (email, token, userId) = await _factory.SignUpAsync(http);
        return new Person(email, token, userId, "");
    }

    private static string Str(JsonElement e, params string[] path) { foreach (var p in path) e = e.GetProperty(p); return e.GetString()!; }

    // ---- profile ------------------------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task Profile_changes_only_my_own_name_and_never_returns_the_password_hash()
    {
        var http = Anon();
        var me = await NewPersonAsync(http);
        var other = await NewPersonAsync(http);
        var r = await As(http, me.Token, HttpMethod.Patch, "/v1/me/profile", new { firstName = "  Ann ", lastName = "  Bee   Cee " });
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal("Ann Bee Cee", Str(r.Body, "user", "name"));
        Assert.False(r.Body.GetProperty("user").TryGetProperty("passwordHash", out _));
        Assert.DoesNotContain("pbkdf2", r.Body.ToString());
        Assert.Equal("Ann Bee Cee", Str((await As(http, me.Token, HttpMethod.Get, "/v1/me")).Body, "user", "name"));
        Assert.NotEqual("Ann Bee Cee", Str((await As(http, other.Token, HttpMethod.Get, "/v1/me")).Body, "user", "name"));
    }

    [Theory]
    [InlineData("", " ", "Enter a first or last name.")]
    [InlineData("", "", "Enter a first or last name.")]
    public async Task Profile_needs_a_name(string first, string last, string message)
    {
        var http = Anon();
        var me = await NewPersonAsync(http);
        var r = await As(http, me.Token, HttpMethod.Patch, "/v1/me/profile", new { firstName = first, lastName = last });
        Assert.Equal(HttpStatusCode.BadRequest, r.Status);
        Assert.Equal(message, Str(r.Body, "message"));
    }

    [Fact]
    public async Task Profile_refuses_long_missing_and_anonymous()
    {
        var http = Anon();
        var me = await NewPersonAsync(http);
        var long_ = await As(http, me.Token, HttpMethod.Patch, "/v1/me/profile", new { firstName = new string('x', 121), lastName = "" });
        var missing = await As(http, me.Token, HttpMethod.Patch, "/v1/me/profile", new { firstName = "A" });
        var anon = await SendAsync(http, new HttpRequestMessage(HttpMethod.Patch, "/v1/me/profile") { Content = JsonContent.Create(new { firstName = "a", lastName = "" }) });
        Assert.Equal("firstName: Too big: expected string to have <=120 characters", Str(long_.Body, "message"));
        Assert.Equal("lastName: Invalid input: expected string, received undefined", Str(missing.Body, "message"));
        Assert.Equal(HttpStatusCode.Unauthorized, anon.Status);
    }

    // ---- the invitations a person has ------------------------------------------------------------------------------------------------------

    private IEnumerable<string> Listed(JsonElement body) => body.GetProperty("invitations").EnumerateArray().Select(i => Str(i, "id"));

    [Fact]
    public async Task My_invitations_need_a_verified_address_and_show_only_pending_unexpired_ones_for_that_address()
    {
        var w = await Workspace.CreateAsync(_factory, "Inviting Space");
        var (email, token, userId) = await _factory.SignUpAsync(w.Http);
        var mine = (await w.InviteAsync(email, "admin")).GetProperty("invitationId").GetString()!;
        var elsewhere = (await w.InviteAsync(ApiFactory.NewEmail("someone"))).GetProperty("invitationId").GetString()!;
        var expiring = (await (await Workspace.CreateAsync(_factory, "Second Space")).InviteAsync(email)).GetProperty("invitationId").GetString()!;
        var cancelled = (await (await Workspace.CreateAsync(_factory, "Third Space")).InviteAsync(email)).GetProperty("invitationId").GetString()!;
        _factory.WithDb(db =>
        {
            db.Invitations.Single(i => i.Id == expiring).ExpiresAt = DateTime.UtcNow.AddMinutes(-1);
            db.Invitations.Single(i => i.Id == cancelled).Status = InvitationStatus.Canceled;
            return db.SaveChanges();
        });

        // Not proven: an invitation id is the secret the emailed link carries, so nothing is listed.
        Assert.Empty(Listed((await As(w.Http, token, HttpMethod.Get, "/v1/me/invitations")).Body));

        _factory.WithDb(db => { db.Users.Single(u => u.Id == userId).EmailVerified = true; return db.SaveChanges(); });
        var list = await As(w.Http, token, HttpMethod.Get, "/v1/me/invitations");
        Assert.Equal([mine], Listed(list.Body));
        var row = list.Body.GetProperty("invitations")[0];
        Assert.Equal("Inviting Space", Str(row, "organization", "name"));
        Assert.Equal("admin", Str(row, "role"));
        Assert.DoesNotContain(elsewhere, list.Body.ToString());
        Assert.DoesNotContain("inviteToken", list.Body.ToString());

        // Joined: it is no longer waiting.
        var accepted = await As(w.Http, token, HttpMethod.Post, "/v1/orgs/invitations/accept", new { id = mine });
        Assert.Equal(HttpStatusCode.OK, accepted.Status);
        Assert.Empty(Listed((await As(w.Http, token, HttpMethod.Get, "/v1/me/invitations")).Body));
        Assert.Equal(HttpStatusCode.Unauthorized, (await SendAsync(w.Http, new HttpRequestMessage(HttpMethod.Get, "/v1/me/invitations"))).Status);
    }

    // ---- the download-link email -------------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task The_download_link_goes_only_to_the_signed_in_persons_own_address()
    {
        var http = Anon();
        var me = await NewPersonAsync(http);
        var victim = ApiFactory.NewEmail("victim");
        // Nothing in the request can name a recipient: a body, a query string or headers are all ignored.
        var req = Bearer(HttpMethod.Post, "/v1/me/send-download-link?to=" + victim, me.Token, new { email = victim, to = victim, recipient = victim });
        req.Headers.Add("x-forwarded-for", "9.9.9.9");
        var r = await SendAsync(http, req);
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal("""{"ok":true}""", r.Body.ToString());
        Assert.Single(_factory.Outbox.To(me.Email));
        Assert.Empty(_factory.Outbox.To(victim));
        var message = _factory.Outbox.To(me.Email)[0].Message;
        Assert.Equal("Your OpenWork download link", message.Subject);
        Assert.Contains("/install", message.Text);
        Assert.Equal(HttpStatusCode.Unauthorized, (await SendAsync(http, new HttpRequestMessage(HttpMethod.Post, "/v1/me/send-download-link"))).Status);
    }

    [Fact]
    public async Task The_download_link_email_is_limited_to_five_an_hour_per_person()
    {
        var http = Anon();
        var me = await NewPersonAsync(http);
        var other = await NewPersonAsync(http);
        for (var i = 0; i < 5; i++) Assert.Equal(HttpStatusCode.OK, (await As(http, me.Token, HttpMethod.Post, "/v1/me/send-download-link")).Status);
        var sixth = await As(http, me.Token, HttpMethod.Post, "/v1/me/send-download-link");
        Assert.Equal(HttpStatusCode.TooManyRequests, sixth.Status);
        Assert.Equal("rate_limited", Str(sixth.Body, "error"));
        Assert.InRange(int.Parse(sixth.Raw.Headers.GetValues("Retry-After").Single()), 1, 3600);
        Assert.Equal(5, _factory.Outbox.To(me.Email).Count);
        // The budget is the person's own.
        Assert.Equal(HttpStatusCode.OK, (await As(http, other.Token, HttpMethod.Post, "/v1/me/send-download-link")).Status);
    }

    [Fact]
    public async Task The_download_limit_holds_under_a_burst()
    {
        var http = Anon();
        var me = await NewPersonAsync(http);
        var results = await Task.WhenAll(Enumerable.Range(0, 12).Select(_ => As(http, me.Token, HttpMethod.Post, "/v1/me/send-download-link")));
        Assert.Equal(5, results.Count(r => r.Status == HttpStatusCode.OK));
        Assert.Equal(7, results.Count(r => r.Status == HttpStatusCode.TooManyRequests));
        Assert.Equal(5, _factory.Outbox.To(me.Email).Count);
    }

    // ---- install -------------------------------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task Install_config_names_the_callers_workspace_and_its_brand_and_version()
    {
        var w = await Workspace.CreateAsync(_factory, "Brand Space");
        var member = await w.AddAsync();
        var plain = await w.CallAsync(member, HttpMethod.Get, "/v1/me/install-config");
        Assert.Equal("Brand Space", Str(plain.Body, "clientName"));
        Assert.Equal("OpenWork", Str(plain.Body, "appName"));
        Assert.Equal("1.2.3", Str(plain.Body, "desktopVersion"));
        Assert.Equal("cloud", Str(plain.Body, "distribution"));
        Assert.True(plain.Body.GetProperty("requireSignin").GetBoolean());

        var patch = await w.CallAsync(w.Owner, HttpMethod.Patch, "/v1/org", new { brandAppName = "Acme Work", allowedDesktopVersions = new[] { "1.0.0", "1.1.0-beta.2", "1.1.0", "0.9.9" } });
        Assert.Equal(HttpStatusCode.OK, patch.Status);
        var branded = await w.CallAsync(member, HttpMethod.Get, "/v1/me/install-config");
        Assert.Equal("Acme Work", Str(branded.Body, "appName"));
        Assert.Equal("1.1.0", Str(branded.Body, "desktopVersion"));

        // Another workspace's name or brand is never reachable by asking for it.
        var elsewhere = await Workspace.CreateAsync(_factory, "Secret Space");
        var spoof = Bearer(HttpMethod.Get, "/v1/me/install-config", member.Token);
        spoof.Headers.Add("x-openwork-org-id", elsewhere.OrgId);
        Assert.Equal(HttpStatusCode.NotFound, (await w.Http.SendAsync(spoof)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await SendAsync(w.Http, new HttpRequestMessage(HttpMethod.Get, "/v1/me/install-config"))).Status);
    }

    [Fact]
    public async Task The_public_install_config_names_no_workspace()
    {
        var w = await Workspace.CreateAsync(_factory, "Hidden Name Space");
        await w.CallAsync(w.Owner, HttpMethod.Patch, "/v1/org", new { brandAppName = "Hidden Brand" });
        var r = await SendAsync(Anon(), new HttpRequestMessage(HttpMethod.Get, "/v1/install-config"));
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal("OpenWork Cloud", Str(r.Body, "clientName"));
        Assert.DoesNotContain("Hidden", r.Body.ToString());
        Assert.Equal(JsonValueKind.Null, r.Body.GetProperty("logoUrl").ValueKind);
    }

    [Fact]
    public async Task Installer_downloads_redirect_by_platform_serve_a_provisioned_file_and_refuse_odd_names()
    {
        var w = await Workspace.CreateAsync(_factory, "Download Space");
        var expected = new Dictionary<string, string>
        {
            ["mac-arm64"] = "openwork-cloud-mac-arm64-1.2.3.dmg", ["mac-x64"] = "openwork-cloud-mac-x64-1.2.3.dmg", ["win-x64"] = "openwork-cloud-win-x64-1.2.3.exe",
            ["linux-x64"] = "openwork-cloud-linux-x86_64-1.2.3.AppImage", ["linux-arm64"] = "openwork-cloud-linux-arm64-1.2.3.AppImage",
        };
        foreach (var (platform, file) in expected)
        {
            var r = await w.Http.SendAsync(w.As(w.Owner, HttpMethod.Get, $"/v1/me/install/{platform}"));
            Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
            Assert.EndsWith($"/v1.2.3/{file}", r.Headers.Location!.ToString());
        }
        // No traversal: the platform is one of five names, and the file name is built from constants.
        foreach (var bad in new[] { "..%2f..%2fetc%2fpasswd", "beos", "mac-arm64.dmg", "MAC-ARM64" })
            Assert.Equal(HttpStatusCode.BadRequest, (await w.Http.SendAsync(w.As(w.Owner, HttpMethod.Get, $"/v1/me/install/{bad}"))).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Http.SendAsync(new HttpRequestMessage(HttpMethod.Get, "/v1/me/install/mac-arm64"))).StatusCode);

        Directory.CreateDirectory(OnboardingFactory.Artifacts);
        File.WriteAllText(Path.Combine(OnboardingFactory.Artifacts, expected["win-x64"]), "installer bytes");
        var served = await w.Http.SendAsync(w.As(w.Owner, HttpMethod.Get, "/v1/me/install/win-x64"));
        Assert.Equal(HttpStatusCode.OK, served.StatusCode);
        Assert.Equal("installer bytes", await served.Content.ReadAsStringAsync());
        Assert.Contains("attachment", served.Content.Headers.ContentDisposition!.ToString());
    }

    [Fact]
    public async Task The_install_page_link_is_the_plain_page_and_only_for_the_callers_own_workspace()
    {
        var w = await Workspace.CreateAsync(_factory, "Link Space");
        var member = await w.AddAsync();
        var elsewhere = await Workspace.CreateAsync(_factory, "Other Space");
        var own = await w.CallAsync(member, HttpMethod.Post, $"/v1/orgs/{w.OrgId}/install-links", new { });
        Assert.Equal(HttpStatusCode.OK, own.Status);
        Assert.EndsWith("/install", Str(own.Body, "installPageUrl"));
        Assert.DoesNotContain('?', Str(own.Body, "installPageUrl"));
        // Another workspace reads as not found, whether or not it exists.
        Assert.Equal(HttpStatusCode.NotFound, (await w.CallAsync(member, HttpMethod.Post, $"/v1/orgs/{elsewhere.OrgId}/install-links", new { })).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await w.CallAsync(member, HttpMethod.Post, "/v1/orgs/org_01jzzzzzzzzzzzzzzzzzzzzzzz/install-links", new { })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(member, HttpMethod.Post, "/v1/orgs/xx/install-links", new { })).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Http.SendAsync(new HttpRequestMessage(HttpMethod.Post, $"/v1/orgs/{w.OrgId}/install-links"))).StatusCode);
    }

    [Fact]
    public async Task The_old_install_route_ignores_its_token_and_redirects_to_the_install_page()
    {
        var r = await Anon().GetAsync("/v1/install/mac-arm64?token=secret-token");
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.EndsWith("/install", r.Headers.Location!.ToString());
        Assert.DoesNotContain("secret-token", r.Headers.Location.ToString());
    }

    [Fact]
    public async Task App_version_reports_what_the_operator_configured()
    {
        var r = await Anon().GetAsync("/v1/app-version");
        var body = JsonDocument.Parse(await r.Content.ReadAsStringAsync()).RootElement;
        Assert.Equal("1.0.0", Str(body, "minAppVersion"));
        Assert.Equal("1.2.3", Str(body, "latestAppVersion"));
        Assert.Equal(["1.2.3", "1.2.2"], body.GetProperty("publishedDesktopVersions").EnumerateArray().Select(e => e.GetString()!));
        Assert.Contains("max-age=300", r.Headers.CacheControl!.ToString());
    }

    [Theory]
    [InlineData("1.2.3", "1.2.3", 0)]
    [InlineData("1.2.4", "1.2.3", 1)]
    [InlineData("1.10.0", "1.9.9", 1)]
    [InlineData("v2.0.0", "1.99.99", 1)]
    [InlineData("1.2.3-beta.1", "1.2.3", -1)]
    [InlineData("1.2.3-beta.2", "1.2.3-beta.10", -1)]
    [InlineData("1.2.3-alpha", "1.2.3-1", 1)]
    [InlineData("1.2.3+build", "1.2.3", 0)]
    public void Versions_compare_as_semantic_versions(string left, string right, int expected) => Assert.Equal(expected, InstallEndpoints.Compare(left, right));

    [Theory]
    [InlineData("1.2", "1.2.3")]
    [InlineData("latest", "1.2.3")]
    [InlineData("1.2.x", "1.2.3")]
    public void Things_that_are_not_versions_have_no_order(string left, string right) => Assert.Null(InstallEndpoints.Compare(left, right));

    // ---- my agent and the checklist (off) ---------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task My_agent_and_the_checklist_are_off_and_say_so_to_members_only()
    {
        var w = await Workspace.CreateAsync(_factory, "Agent Space");
        var member = await w.AddAsync();
        foreach (var (method, path, feature) in new[] { (HttpMethod.Get, "/v1/me/agent", "workbotProactive"), (HttpMethod.Put, "/v1/me/agent", "workbotProactive"), (HttpMethod.Get, "/v1/me/agent/checks", "workbotProactive"), (HttpMethod.Get, "/v1/me/activation", "activationChecklist"), (HttpMethod.Post, "/v1/me/activation/events", "activationChecklist") })
        {
            var r = await w.CallAsync(member, method, path, method == HttpMethod.Get ? null : new { });
            Assert.Equal(HttpStatusCode.NotFound, r.Status);
            Assert.Equal("feature_disabled", Str(r.Body, "error"));
            Assert.Equal(feature, Str(r.Body, "feature"));
            Assert.Equal(HttpStatusCode.Unauthorized, (await w.Http.SendAsync(new HttpRequestMessage(method, path))).StatusCode);
        }
        // Someone who belongs to no workspace gets the ordinary "no workspace" answer, not the feature's.
        var loner = await NewPersonAsync(w.Http);
        Assert.Equal(HttpStatusCode.NotFound, (await As(w.Http, loner.Token, HttpMethod.Get, "/v1/me/agent")).Status);
    }

    // ---- provision now, claim later -----------------------------------------------------------------------------------------------------------------

    private sealed record Provisioned(string OrgId, string BootstrapId, string Assertion, string OwnerToken, string? MemberToken, string SkillId, string AgentUserId);

    private async Task<Provisioned> ProvisionAsync(HttpClient http, object? extra = null, params string[] roles)
    {
        var body = new Dictionary<string, object?> { ["workspaceName"] = "Agent Built", ["claimRoles"] = roles.Length == 0 ? new[] { "owner", "member" } : roles, ["teammateEmails"] = new[] { "mate@example.com" } };
        var r = await SendAsync(http, new HttpRequestMessage(HttpMethod.Post, "/v1/bootstrap/workspace") { Content = JsonContent.Create(body) });
        Assert.True(r.Status == HttpStatusCode.OK, r.Body.ToString());
        var links = r.Body.GetProperty("claimLinks").EnumerateArray().ToList();
        string? Token(string role) => links.FirstOrDefault(l => Str(l, "role") == role).ValueKind == JsonValueKind.Object ? Str(links.First(l => Str(l, "role") == role), "token") : null;
        var orgId = Str(r.Body, "organization", "id");
        var bootstrapId = Str(r.Body, "setup", "id");
        var agent = _factory.WithDb(db => db.Set<WorkspaceBootstrap>().Single(b => b.Id == bootstrapId).AgentUserId);
        _ = extra;
        return new Provisioned(orgId, bootstrapId, Str(r.Body, "identity", "assertion"), Token("owner") ?? "", Token("member"), Str(r.Body, "skill", "id"), agent);
    }

    private static HttpRequestMessage Json(HttpMethod m, string url, object? body = null, string? bearer = null)
    {
        var req = bearer is null ? new HttpRequestMessage(m, url) : Bearer(m, url, bearer);
        if (body is not null) req.Content = JsonContent.Create(body);
        return req;
    }

    [Fact]
    public async Task A_provisional_workspace_is_invisible_and_its_agent_cannot_sign_in()
    {
        var http = Anon();
        var p = await ProvisionAsync(http);
        var stranger = await NewPersonAsync(http);
        var spoof = Bearer(HttpMethod.Get, "/v1/org", stranger.Token);
        spoof.Headers.Add("x-openwork-org-id", p.OrgId);
        Assert.Equal(HttpStatusCode.NotFound, (await http.SendAsync(spoof)).StatusCode);

        var agentEmail = _factory.WithDb(db => db.Users.Single(u => u.Id == p.AgentUserId).Email);
        Assert.EndsWith("@agents.openwork.invalid", agentEmail);
        foreach (var password in new[] { "!", "", ApiFactory.Password })
            Assert.NotEqual(HttpStatusCode.OK, (await http.PostAsJsonAsync("/api/auth/sign-in/email", new { email = agentEmail, password })).StatusCode);
    }

    [Fact]
    public async Task Claim_secrets_are_stored_hashed_and_the_assertion_is_not_stored_at_all()
    {
        var http = Anon();
        var p = await ProvisionAsync(http);
        var code = await SendAsync(http, Json(HttpMethod.Post, $"/v1/bootstrap/workspace/{p.BootstrapId}/claim", bearer: p.Assertion));
        var userCode = Str(code.Body, "user_code").Replace("-", "");
        _factory.WithDb(db =>
        {
            var claims = db.Set<WorkspaceClaim>().Where(c => c.BootstrapId == p.BootstrapId).ToList();
            Assert.All(claims, c => { Assert.Equal(64, c.TokenHash.Length); Assert.NotEqual(p.OwnerToken, c.TokenHash); });
            Assert.Contains(claims, c => c.TokenHash == WorkAI360.Api.Auth.Ids.Sha256Hex(p.OwnerToken));
            var stored = db.Set<WorkspaceClaimCode>().Single(c => c.BootstrapId == p.BootstrapId && c.State == "pending");
            Assert.DoesNotContain(userCode, stored.CodeHash);
            Assert.Equal(BootstrapService.HashCode(userCode), stored.CodeHash);
            var bootstrap = db.Set<WorkspaceBootstrap>().Single(b => b.Id == p.BootstrapId);
            Assert.DoesNotContain(p.Assertion, bootstrap.AssertionJti);
            return 0;
        });
    }

    [Fact]
    public async Task The_assertion_must_be_genuine_unexpired_unrevoked_and_for_this_workspace()
    {
        var http = Anon();
        var a = await ProvisionAsync(http);
        var b = await ProvisionAsync(http);
        var url = (string id) => $"/v1/bootstrap/workspace/{id}/claim";
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(http, Json(HttpMethod.Get, url(a.BootstrapId), bearer: a.Assertion))).Status);
        // Another workspace's assertion, none, and junk.
        Assert.Equal(HttpStatusCode.Unauthorized, (await SendAsync(http, Json(HttpMethod.Get, url(a.BootstrapId), bearer: b.Assertion))).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await SendAsync(http, Json(HttpMethod.Get, url(a.BootstrapId)))).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await SendAsync(http, Json(HttpMethod.Get, url(a.BootstrapId), bearer: "a.b.c"))).Status);
        // A changed payload keeps the old signature: it no longer matches.
        var parts = a.Assertion.Split('.');
        var payload = Encoding.UTF8.GetString(Convert.FromBase64String(parts[1].Replace('-', '+').Replace('_', '/').PadRight(parts[1].Length + (4 - parts[1].Length % 4) % 4, '=')));
        var forged = payload.Replace(a.BootstrapId, b.BootstrapId);
        var forgedToken = $"{parts[0]}.{Convert.ToBase64String(Encoding.UTF8.GetBytes(forged)).TrimEnd('=').Replace('+', '-').Replace('/', '_')}.{parts[2]}";
        Assert.Equal(HttpStatusCode.Unauthorized, (await SendAsync(http, Json(HttpMethod.Get, url(b.BootstrapId), bearer: forgedToken))).Status);
        // The header's algorithm cannot be changed to "none".
        var none = $"{Convert.ToBase64String(Encoding.UTF8.GetBytes("""{"alg":"none","typ":"openwork-preclaim+jwt"}""")).TrimEnd('=')}.{parts[1]}.";
        Assert.Equal(HttpStatusCode.Unauthorized, (await SendAsync(http, Json(HttpMethod.Get, url(a.BootstrapId), bearer: none))).Status);
        // A token signed for this deployment stops being recognized when the workspace expires: reading the state still answers, a new code does not.
        _factory.WithDb(db => { db.Set<WorkspaceBootstrap>().Single(x => x.Id == a.BootstrapId).ExpiresAt = DateTime.UtcNow.AddMinutes(-1); return db.SaveChanges(); });
        Assert.Equal(HttpStatusCode.Unauthorized, (await SendAsync(http, Json(HttpMethod.Post, url(a.BootstrapId), bearer: a.Assertion))).Status);
    }

    [Fact]
    public async Task A_code_claims_once_even_when_two_people_race_for_it()
    {
        var http = Anon();
        var p = await ProvisionAsync(http);
        var code = Str((await SendAsync(http, Json(HttpMethod.Post, $"/v1/bootstrap/workspace/{p.BootstrapId}/claim", bearer: p.Assertion))).Body, "user_code");
        var people = await Task.WhenAll(Enumerable.Range(0, 6).Select(_ => NewPersonAsync(http)));
        var results = await Task.WhenAll(people.Select(x => As(http, x.Token, HttpMethod.Post, "/v1/bootstrap/claim-codes/accept", new { userCode = code })));
        Assert.Equal(1, results.Count(r => r.Status == HttpStatusCode.OK));
        Assert.Equal(5, results.Count(r => r.Status == HttpStatusCode.NotFound));
        var winnerIndex = Array.FindIndex(results, r => r.Status == HttpStatusCode.OK);
        _factory.WithDb(db =>
        {
            var members = db.Members.Where(m => m.OrganizationId == p.OrgId).ToList();
            Assert.Single(members);
            Assert.Equal("owner", members[0].Role);
            Assert.Equal(people[winnerIndex].UserId, members[0].UserId);
            return 0;
        });
    }

    [Fact]
    public async Task Claiming_with_a_code_makes_the_person_the_only_owner_and_ends_the_agent()
    {
        var http = Anon();
        var p = await ProvisionAsync(http);
        var code = Str((await SendAsync(http, Json(HttpMethod.Post, $"/v1/bootstrap/workspace/{p.BootstrapId}/claim", bearer: p.Assertion))).Body, "user_code");
        var claimer = await NewPersonAsync(http);
        var seen = await As(http, claimer.Token, HttpMethod.Get, $"/v1/bootstrap/claim-codes/{code}");
        Assert.Equal("Agent Built", Str(seen.Body, "organization", "name"));

        var done = await As(http, claimer.Token, HttpMethod.Post, "/v1/bootstrap/claim-codes/accept", new { userCode = code.ToLowerInvariant().Replace("-", " ") });
        Assert.Equal(HttpStatusCode.OK, done.Status);
        Assert.Equal("owner", Str(done.Body, "organization", "role"));
        Assert.Equal(["mate@example.com"], done.Body.GetProperty("teammateEmails").EnumerateArray().Select(e => e.GetString()!));

        _factory.WithDb(db =>
        {
            Assert.False(db.Users.Any(u => u.Id == p.AgentUserId));
            Assert.Single(db.Members.Where(m => m.OrganizationId == p.OrgId));
            var memberId = db.Members.Single(m => m.OrganizationId == p.OrgId).Id;
            // What the agent made now belongs to the person.
            Assert.All(db.Set<Plugin>().Where(x => x.OrganizationId == p.OrgId), x => Assert.Equal(memberId, x.CreatedByMemberId));
            Assert.All(db.Set<ConfigObject>().Where(x => x.OrganizationId == p.OrgId), x => Assert.Equal(memberId, x.CreatedByMemberId));
            Assert.DoesNotContain(db.Set<LibraryGrant>().Where(g => g.OrganizationId == p.OrgId).ToList(), g => g.MemberId is not null && g.MemberId != memberId);
            var bootstrap = db.Set<WorkspaceBootstrap>().Single(b => b.Id == p.BootstrapId);
            Assert.Equal("claimed", bootstrap.Status);
            Assert.NotNull(bootstrap.CredentialsRevokedAt);
            Assert.All(db.Set<WorkspaceClaim>().Where(c => c.BootstrapId == p.BootstrapId), c => Assert.Equal("cancelled", c.Status));
            Assert.Equal("reconciled", db.Set<WorkspaceClaimCode>().Single(c => c.BootstrapId == p.BootstrapId).State);
            return 0;
        });
        var orgs = await As(http, claimer.Token, HttpMethod.Get, "/v1/me/orgs");
        Assert.Equal(p.OrgId, Str(orgs.Body, "activeOrgId"));
        // The agent's state: reconciled, and its credentials no longer make codes.
        var state = await SendAsync(http, Json(HttpMethod.Get, $"/v1/bootstrap/workspace/{p.BootstrapId}/claim", bearer: p.Assertion));
        Assert.Equal("reconciled", Str(state.Body, "state"));
        Assert.Equal(HttpStatusCode.Unauthorized, (await SendAsync(http, Json(HttpMethod.Post, $"/v1/bootstrap/workspace/{p.BootstrapId}/claim", bearer: p.Assertion))).Status);
        // The unused links are dead, and so is the code.
        var late = await NewPersonAsync(http);
        Assert.Equal(HttpStatusCode.NotFound, (await As(http, late.Token, HttpMethod.Post, "/v1/bootstrap/claims/accept", new { token = p.MemberToken })).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await As(http, late.Token, HttpMethod.Post, "/v1/bootstrap/claim-codes/accept", new { userCode = code })).Status);
    }

    [Fact]
    public async Task Claiming_with_a_link_gives_the_links_role_and_hands_teammates_to_owners_only()
    {
        var http = Anon();
        var p = await ProvisionAsync(http);
        var member = await NewPersonAsync(http);
        var viaMember = await As(http, member.Token, HttpMethod.Post, "/v1/bootstrap/claims/accept", new { token = p.MemberToken });
        Assert.Equal(HttpStatusCode.OK, viaMember.Status);
        Assert.Equal("member", Str(viaMember.Body, "organization", "role"));
        Assert.False(viaMember.Body.TryGetProperty("teammateEmails", out _));
        // The workspace has been taken: the owner link no longer works, and a second use of the first is refused.
        var next = await NewPersonAsync(http);
        Assert.Equal(HttpStatusCode.NotFound, (await As(http, next.Token, HttpMethod.Post, "/v1/bootstrap/claims/accept", new { token = p.OwnerToken })).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await As(http, member.Token, HttpMethod.Post, "/v1/bootstrap/claims/accept", new { token = p.MemberToken })).Status);

        var q = await ProvisionAsync(http, null, "owner");
        var owner = await NewPersonAsync(http);
        var viaOwner = await As(http, owner.Token, HttpMethod.Post, "/v1/bootstrap/claims/accept", new { token = q.OwnerToken });
        Assert.Equal("owner", Str(viaOwner.Body, "organization", "role"));
        Assert.Equal(["mate@example.com"], viaOwner.Body.GetProperty("teammateEmails").EnumerateArray().Select(e => e.GetString()!));
        var code = await SendAsync(http, Json(HttpMethod.Post, $"/v1/bootstrap/workspace/{q.BootstrapId}/claim", bearer: q.Assertion));
        Assert.Equal(HttpStatusCode.Unauthorized, code.Status);
    }

    [Fact]
    public async Task A_link_and_a_code_cannot_both_take_the_workspace()
    {
        var http = Anon();
        var p = await ProvisionAsync(http, null, "owner");
        var code = Str((await SendAsync(http, Json(HttpMethod.Post, $"/v1/bootstrap/workspace/{p.BootstrapId}/claim", bearer: p.Assertion))).Body, "user_code");
        var a = await NewPersonAsync(http);
        var b = await NewPersonAsync(http);
        var both = await Task.WhenAll(
            As(http, a.Token, HttpMethod.Post, "/v1/bootstrap/claims/accept", new { token = p.OwnerToken }),
            As(http, b.Token, HttpMethod.Post, "/v1/bootstrap/claim-codes/accept", new { userCode = code }));
        Assert.Equal(1, both.Count(r => r.Status == HttpStatusCode.OK));
        _factory.WithDb(db => { Assert.Single(db.Members.Where(m => m.OrganizationId == p.OrgId)); return 0; });
    }

    [Fact]
    public async Task Expired_links_and_codes_do_not_claim_and_new_provisioning_retires_the_old_agents()
    {
        var http = Anon();
        var p = await ProvisionAsync(http);
        var code = Str((await SendAsync(http, Json(HttpMethod.Post, $"/v1/bootstrap/workspace/{p.BootstrapId}/claim", bearer: p.Assertion))).Body, "user_code");
        var person = await NewPersonAsync(http);
        _factory.WithDb(db =>
        {
            db.Set<WorkspaceBootstrap>().Single(b => b.Id == p.BootstrapId).ExpiresAt = DateTime.UtcNow.AddMinutes(-1);
            db.Set<WorkspaceClaim>().Where(c => c.BootstrapId == p.BootstrapId).ToList().ForEach(c => c.ExpiresAt = DateTime.UtcNow.AddMinutes(-1));
            return db.SaveChanges();
        });
        Assert.Equal(HttpStatusCode.NotFound, (await As(http, person.Token, HttpMethod.Get, $"/v1/bootstrap/claim-codes/{code}")).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await As(http, person.Token, HttpMethod.Post, "/v1/bootstrap/claim-codes/accept", new { userCode = code })).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await As(http, person.Token, HttpMethod.Post, "/v1/bootstrap/claims/accept", new { token = p.OwnerToken })).Status);

        await ProvisionAsync(http);   // cleanup rides on the next provisioning
        _factory.WithDb(db =>
        {
            Assert.Equal("expired", db.Set<WorkspaceBootstrap>().Single(b => b.Id == p.BootstrapId).Status);
            Assert.False(db.Users.Any(u => u.Id == p.AgentUserId));
            Assert.False(db.Members.Any(m => m.OrganizationId == p.OrgId));
            return 0;
        });
    }

    [Fact]
    public async Task Claim_endpoints_check_the_input_and_the_session()
    {
        var http = Anon();
        var me = await NewPersonAsync(http);
        Assert.Equal(HttpStatusCode.Unauthorized, (await SendAsync(http, Json(HttpMethod.Post, "/v1/bootstrap/claims/accept", new { token = new string('x', 30) }))).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await SendAsync(http, Json(HttpMethod.Get, "/v1/bootstrap/claim-codes/ABCD2345"))).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await SendAsync(http, Json(HttpMethod.Post, "/v1/bootstrap/claim-codes/accept", new { userCode = "ABCD2345" }))).Status);
        Assert.Equal("token: Too small: expected string to have >=24 characters", Str((await As(http, me.Token, HttpMethod.Post, "/v1/bootstrap/claims/accept", new { token = "abc" })).Body, "message"));
        Assert.Equal("userCode: Too small: expected string to have >=4 characters", Str((await As(http, me.Token, HttpMethod.Get, "/v1/bootstrap/claim-codes/ab")).Body, "message"));
        Assert.Equal("mode: Invalid input: expected \"new_org\"", Str((await As(http, me.Token, HttpMethod.Post, "/v1/bootstrap/claim-codes/accept", new { userCode = "ABCD2345", mode = "x" })).Body, "message"));
        Assert.Equal(HttpStatusCode.NotFound, (await As(http, me.Token, HttpMethod.Post, "/v1/bootstrap/claims/accept", new { token = new string('x', 43) })).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await As(http, me.Token, HttpMethod.Get, "/v1/bootstrap/claim-codes/ZZZZZZZZ")).Status);
    }

    [Fact]
    public async Task Provisioning_validates_its_input_and_makes_the_starter_content()
    {
        var http = Anon();
        foreach (var (body, message) in new (object, string)[]
        {
            (new { workspaceName = "x" }, "workspaceName: Too small: expected string to have >=2 characters"),
            (new { workspaceName = "Fine", claimRoles = new[] { "root" } }, "claimRoles.0: Invalid option: expected one of \"owner\"|\"admin\"|\"member\""),
            (new { workspaceName = "Fine", claimRoles = Array.Empty<string>() }, "claimRoles: Too small: expected array to have >=1 items"),
            (new { workspaceName = "Fine", ownerEmail = "nope" }, "ownerEmail: Invalid email address"),
            (new { workspaceName = "Fine", teammateEmails = new[] { "a@example.com", "bad" } }, "teammateEmails.1: Invalid email address"),
            (new { workspaceName = "Fine", devicePublicKey = "short" }, "devicePublicKey: Too small: expected string to have >=16 characters"),
        })
        {
            var r = await SendAsync(http, Json(HttpMethod.Post, "/v1/bootstrap/workspace", body));
            Assert.Equal(HttpStatusCode.BadRequest, r.Status);
            Assert.Equal(message, Str(r.Body, "message"));
        }
        var p = await ProvisionAsync(http, null, "owner");
        _factory.WithDb(db =>
        {
            var plugin = db.Set<Plugin>().Single(x => x.OrganizationId == p.OrgId);
            Assert.Equal("First OpenWork Skill", plugin.Name);
            var skill = db.Set<ConfigObject>().Single(x => x.OrganizationId == p.OrgId);
            Assert.Equal(p.SkillId, skill.Id);
            Assert.Contains("OPENWORK_BOOTSTRAP_SKILL_TRIGGERED", db.Set<ConfigObjectVersion>().Single(v => v.ConfigObjectId == skill.Id).RawSourceText);
            Assert.Single(db.Set<Marketplace>().Where(x => x.OrganizationId == p.OrgId));
            Assert.Equal(1, db.Set<LibraryGrant>().Count(g => g.OrganizationId == p.OrgId && g.ResourceKind == GrantKinds.Plugin && g.OrgWide));
            return 0;
        });
    }

    // ---- desktop startup diagnostics ----------------------------------------------------------------------------------------------------------------

    private static object Report(Guid? id = null, bool success = true, DateTime? at = null, string version = "1.2.3") => new
    {
        attemptId = (id ?? Guid.NewGuid()).ToString(), appVersion = version, platform = "linux", observedAt = (at ?? DateTime.UtcNow).ToString("yyyy-MM-ddTHH:mm:ss.fffZ"), success,
        steps = new { window = 100, engine = 300, signed_in = 500, org_tools = success ? 900 : (int?)null },
        failedStep = success ? null : "org_tools", reason = success ? null : "timeout",
    };

    [Fact]
    public async Task Diagnostics_show_each_section_only_to_people_who_hold_its_permission()
    {
        var w = await Workspace.CreateAsync(_factory, "Diag Space");
        var member = await w.AddAsync();
        var r = await w.CallAsync(member, HttpMethod.Get, "/v1/org/diagnostics");
        Assert.Equal(HttpStatusCode.OK, r.Status);
        Assert.Equal("locked", Str(r.Body, "desktop", "access"));
        Assert.Equal("desktop_policies.view", Str(r.Body, "desktop", "permission"));
        Assert.Equal("locked", Str(r.Body, "network", "access"));
        Assert.Equal("locked", Str(r.Body, "providers", "access"));
        Assert.Equal("installation_admin_required", Str(r.Body, "installation", "reason"));
        var owner = await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/org/diagnostics");
        Assert.Equal("granted", Str(owner.Body, "desktop", "access"));
        Assert.True(owner.Body.GetProperty("network").GetProperty("canRun").GetBoolean());
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/org/diagnostics?strict=maybe")).Status);
        Assert.Equal(HttpStatusCode.Accepted, (await w.CallAsync(member, HttpMethod.Post, "/v1/org/diagnostics/check")).Status);
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Http.SendAsync(new HttpRequestMessage(HttpMethod.Get, "/v1/org/diagnostics"))).StatusCode);
    }

    [Fact]
    public async Task Startup_reports_count_once_per_launch_stay_in_their_workspace_and_carry_no_identity()
    {
        var w = await Workspace.CreateAsync(_factory, "Reports Space");
        var other = await Workspace.CreateAsync(_factory, "Other Reports");
        var member = await w.AddAsync();
        var launch = Guid.NewGuid();
        Assert.Equal(HttpStatusCode.NoContent, (await w.CallAsync(member, HttpMethod.Post, "/v1/diagnostics/desktop-startup", Report(launch))).Status);
        Assert.Equal(HttpStatusCode.NoContent, (await w.CallAsync(member, HttpMethod.Post, "/v1/diagnostics/desktop-startup", Report(launch, version: "9.9.9"))).Status);   // a resend never changes the first
        Assert.Equal(HttpStatusCode.NoContent, (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/diagnostics/desktop-startup", Report(success: false))).Status);
        Assert.Equal(HttpStatusCode.NoContent, (await w.CallAsync(member, HttpMethod.Post, "/v1/diagnostics/desktop-startup", Report(at: DateTime.UtcNow.AddDays(-9)))).Status);   // too old: ignored
        Assert.Equal(HttpStatusCode.NoContent, (await w.CallAsync(member, HttpMethod.Post, "/v1/diagnostics/desktop-startup", Report(at: DateTime.UtcNow.AddHours(1)))).Status);   // from the future: ignored

        var d = (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/org/diagnostics")).Body.GetProperty("desktop");
        Assert.Equal(2, d.GetProperty("startups").GetInt32());
        Assert.Equal(1, d.GetProperty("connected").GetInt32());
        Assert.Equal(1, d.GetProperty("failed").GetInt32());
        Assert.Equal(2, d.GetProperty("people").GetInt32());
        Assert.Equal("1.2.3", Str(d.GetProperty("versions")[0], "version"));
        Assert.DoesNotContain("9.9.9", d.ToString());
        // Another workspace sees none of it.
        var theirs = (await other.CallAsync(other.Owner, HttpMethod.Get, "/v1/org/diagnostics")).Body.GetProperty("desktop");
        Assert.Equal(0, theirs.GetProperty("startups").GetInt32());
        // A member's own report is attributed to their membership; nothing else about them is kept.
        _factory.WithDb(db =>
        {
            Assert.Equal(1, db.Set<DesktopStartupReport>().Count(r => r.OrganizationId == w.OrgId && r.MemberId == member.MemberId));
            return 0;
        });
    }

    [Fact]
    public async Task Startup_reports_are_validated_and_limited_per_member()
    {
        var w = await Workspace.CreateAsync(_factory, "Limit Space");
        var member = await w.AddAsync();
        var bad = await w.CallAsync(member, HttpMethod.Post, "/v1/diagnostics/desktop-startup", new { attemptId = "x" });
        Assert.Equal(HttpStatusCode.BadRequest, bad.Status);
        var extra = await w.CallAsync(member, HttpMethod.Post, "/v1/diagnostics/desktop-startup", new Dictionary<string, object?> { ["attemptId"] = Guid.NewGuid().ToString(), ["extra"] = 1 });
        Assert.Equal(HttpStatusCode.BadRequest, extra.Status);
        var refine = await w.CallAsync(member, HttpMethod.Post, "/v1/diagnostics/desktop-startup", new { attemptId = Guid.NewGuid().ToString(), appVersion = "1.0.0", platform = "linux", observedAt = DateTime.UtcNow.ToString("O"), success = false, steps = new { window = 1, engine = 1, signed_in = 1, org_tools = 1 }, failedStep = (string?)null, reason = (string?)null });
        Assert.Equal("failedStep: A failed startup names its failed step and reason.", Str(refine.Body, "message"));
        for (var i = 0; i < 20; i++) Assert.Equal(HttpStatusCode.NoContent, (await w.CallAsync(member, HttpMethod.Post, "/v1/diagnostics/desktop-startup", Report())).Status);
        var limited = await w.CallAsync(member, HttpMethod.Post, "/v1/diagnostics/desktop-startup", Report());
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.Status);
        // Someone else's budget is their own.
        Assert.Equal(HttpStatusCode.NoContent, (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/diagnostics/desktop-startup", Report())).Status);
    }

    [Fact]
    public void Percentiles_are_nearest_rank()
    {
        Assert.Null(DiagnosticsEndpoints.Percentile([], 0.5));
        Assert.Equal(900, DiagnosticsEndpoints.Percentile([900], 0.95));
        Assert.Equal(20, DiagnosticsEndpoints.Percentile([10, 20, 30, 40], 0.5));
        Assert.Equal(40, DiagnosticsEndpoints.Percentile([40, 10, 30, 20], 0.95));
    }

    // ---- the network check ----------------------------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task The_network_check_token_is_for_managers_stored_encrypted_and_never_returned()
    {
        var w = await Workspace.CreateAsync(_factory, "Egress Space");
        var member = await w.AddAsync();
        var token = "diag-" + new string('k', 40);
        var denied = await w.CallAsync(member, HttpMethod.Put, "/v1/diagnostics/egress/token", new { bearerToken = token });
        Assert.Equal(HttpStatusCode.Forbidden, denied.Status);
        Assert.Equal("egress_diagnostics.manage", denied.Required());
        Assert.Equal("egress_diagnostics.view", (await w.CallAsync(member, HttpMethod.Get, "/v1/diagnostics/egress")).Required());
        Assert.Equal("egress_diagnostics.manage", (await w.CallAsync(member, HttpMethod.Post, "/v1/diagnostics/egress")).Required());
        Assert.Equal(HttpStatusCode.BadRequest, (await w.CallAsync(w.Owner, HttpMethod.Put, "/v1/diagnostics/egress/token", new { bearerToken = "short" })).Status);

        var before = await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/diagnostics/egress");
        Assert.False(before.Body.GetProperty("available").GetBoolean());
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/diagnostics/egress")).Status);

        Assert.Equal(HttpStatusCode.NoContent, (await w.CallAsync(w.Owner, HttpMethod.Put, "/v1/diagnostics/egress/token", new { bearerToken = token })).Status);
        Assert.Equal(HttpStatusCode.NoContent, (await w.CallAsync(w.Owner, HttpMethod.Put, "/v1/diagnostics/egress/token", new { bearerToken = token + "2" })).Status);
        var stored = _factory.WithDb(db => db.Set<EgressDiagnosticCredential>().Single(c => c.OrganizationId == w.OrgId).TokenCipher);
        Assert.DoesNotContain("diag-", stored);
        Assert.Equal(token + "2", _factory.Services.GetRequiredService<SecretBox>().Decrypt(stored));
        var after = await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/diagnostics/egress");
        Assert.DoesNotContain("diag-", after.Body.ToString());
    }

    // ---- resources ------------------------------------------------------------------------------------------------------------------------------------

    private const string SkillText = "---\nname: shared-one\ndescription: Does a thing\n---\n\nBody.\n";

    [Fact]
    public async Task The_resource_snapshot_shows_only_marketplaces_shared_with_the_member_and_stays_in_the_workspace()
    {
        var w = await Workspace.CreateAsync(_factory, "Resources Space");
        var member = await w.AddAsync();
        var plugin = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/plugins", new { name = "Bundle", orgWide = true, components = new[] { new { type = "skill", input = new { rawSourceText = SkillText } } } });
        var pluginId = Str(plugin.Body, "item", "id");
        var shelf = Str((await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/marketplaces", new { name = "Shelf" })).Body, "item", "id");
        var hidden = Str((await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/marketplaces", new { name = "Hidden" })).Body, "item", "id");
        await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/marketplaces/{shelf}/plugins", new { pluginId });
        await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/marketplaces/{hidden}/plugins", new { pluginId });
        Assert.True((int)(await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/marketplaces/{shelf}/access", new { orgWide = true, role = "viewer" })).Status < 300);

        var snapshot = await w.CallAsync(member, HttpMethod.Get, "/v1/resources");
        var marketplaces = snapshot.Body.GetProperty("resources").GetProperty("marketplaces");
        Assert.True(marketplaces.TryGetProperty(shelf, out var m));
        Assert.False(marketplaces.TryGetProperty(hidden, out _));
        Assert.Equal(pluginId, Str(m.GetProperty("plugins")[0], "pluginId"));
        Assert.Equal(1, m.GetProperty("plugins")[0].GetProperty("configItems").GetArrayLength());
        Assert.Equal(member.MemberId, Str(snapshot.Body, "orgMemberId"));

        // The owner manages everything, so sees both shelves; a different workspace sees neither.
        var ownerView = (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/resources")).Body.GetProperty("resources").GetProperty("marketplaces");
        Assert.True(ownerView.TryGetProperty(hidden, out _));
        var other = await Workspace.CreateAsync(_factory, "Another Space");
        var theirs = (await other.CallAsync(other.Owner, HttpMethod.Get, "/v1/resources")).Body.GetProperty("resources").GetProperty("marketplaces");
        Assert.Empty(theirs.EnumerateObject());
        Assert.Equal(HttpStatusCode.Unauthorized, (await w.Http.SendAsync(new HttpRequestMessage(HttpMethod.Get, "/v1/resources"))).StatusCode);
    }

    [Fact]
    public async Task Marketplace_capabilities_are_grant_scoped_and_not_widened_by_being_an_administrator()
    {
        var w = await Workspace.CreateAsync(_factory, "Capabilities Space");
        var member = await w.AddAsync();
        var plugin = await w.CallAsync(w.Owner, HttpMethod.Post, "/v1/plugins", new { name = "Private Bundle", components = new[] { new { type = "skill", input = new { rawSourceText = SkillText } } } });
        var pluginId = Str(plugin.Body, "item", "id");
        // Only the owner holds it: the member lists nothing, the owner (who made it) lists it, with no marketplace.
        Assert.Empty((await w.CallAsync(member, HttpMethod.Get, "/v1/resources/marketplace-capabilities")).Body.GetProperty("items").EnumerateArray());
        var mine = (await w.CallAsync(w.Owner, HttpMethod.Get, "/v1/resources/marketplace-capabilities")).Body.GetProperty("items");
        Assert.Contains(mine.EnumerateArray(), i => Str(i, "pluginId") == pluginId && i.GetProperty("marketplaceId").ValueKind == JsonValueKind.Null && Str(i, "objectType") == "skill");
        // Shared with everyone through the plugin: the member lists it.
        Assert.True((int)(await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/plugins/{pluginId}/access", new { orgWide = true, role = "viewer" })).Status < 300);
        var objectId = Str(mine[0], "configObjectId");
        Assert.True((int)(await w.CallAsync(w.Owner, HttpMethod.Post, $"/v1/config-objects/{objectId}/access", new { orgWide = true, role = "viewer" })).Status < 300);
        Assert.Contains((await w.CallAsync(member, HttpMethod.Get, "/v1/resources/marketplace-capabilities")).Body.GetProperty("items").EnumerateArray(), i => Str(i, "pluginId") == pluginId);
    }
}

public sealed class OnboardingLimitTests : IClassFixture<OnboardingLimitFactory>
{
    private readonly OnboardingLimitFactory _factory;
    public OnboardingLimitTests(OnboardingLimitFactory factory) => _factory = factory;

    [Fact]
    public async Task Provisioning_is_limited_per_address_and_a_refused_request_does_not_use_an_attempt()
    {
        var http = _factory.Plain();
        for (var i = 0; i < 5; i++)
            Assert.Equal(HttpStatusCode.BadRequest, (await http.PostAsJsonAsync("/v1/bootstrap/workspace", new { workspaceName = "x" })).StatusCode);
        for (var i = 0; i < 3; i++)
            Assert.Equal(HttpStatusCode.OK, (await http.PostAsJsonAsync("/v1/bootstrap/workspace", new { workspaceName = "Allowed Space" })).StatusCode);
        var fourth = await http.PostAsJsonAsync("/v1/bootstrap/workspace", new { workspaceName = "Too Many" });
        Assert.Equal(HttpStatusCode.TooManyRequests, fourth.StatusCode);
        Assert.InRange(int.Parse(fourth.Headers.GetValues("Retry-After").Single()), 1, 3600);
        Assert.Equal("rate_limited", JsonDocument.Parse(await fourth.Content.ReadAsStringAsync()).RootElement.GetProperty("error").GetString());
        Assert.Equal(3, _factory.WithDb(db => db.Set<WorkspaceBootstrap>().Count()));
    }
}

public sealed class OnboardingMailTests : IClassFixture<OnboardingMailDownFactory>
{
    private readonly OnboardingMailDownFactory _factory;
    public OnboardingMailTests(OnboardingMailDownFactory factory) => _factory = factory;

    [Fact]
    public async Task A_mail_provider_that_refuses_is_a_502_with_a_reason_and_no_address_in_it()
    {
        var http = _factory.Plain();
        var (email, token, _) = await _factory.SignUpAsync(http);
        var r = await http.SendAsync(Bearer(HttpMethod.Post, "/v1/me/send-download-link", token));
        Assert.Equal(HttpStatusCode.BadGateway, r.StatusCode);
        var text = await r.Content.ReadAsStringAsync();
        var body = JsonDocument.Parse(text).RootElement;
        Assert.Equal("download_link_email_failed", body.GetProperty("error").GetString());
        Assert.Equal("resend_rejected", body.GetProperty("reason").GetString());
        Assert.DoesNotContain(email, text);
        Assert.DoesNotContain("422", text);
    }
}
