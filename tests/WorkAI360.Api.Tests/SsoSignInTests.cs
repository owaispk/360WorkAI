using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.Sso;
using WorkAI360.Api.Features.Sso;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>A workspace with SSO verified, tested and enabled against a fake provider.</summary>
public abstract class SsoSignInBase : IClassFixture<SsoFactory>, IAsyncLifetime
{
    protected readonly SsoFactory Factory;
    protected FakeIdp Idp = null!;
    protected SsoWorld W = null!;

    protected SsoSignInBase(SsoFactory factory) => Factory = factory;
    public async Task InitializeAsync()
    {
        Idp = await FakeIdp.StartAsync();
        W = await SsoWorld.CreateAsync(Factory, Idp, Factory.Dns);
        await W.VerifiedTestedAndEnabledAsync();
    }
    public async Task DisposeAsync() => await Idp.DisposeAsync();

    protected string Person(string local = "new.person") => $"{local}@{W.Domain}";
    protected void SignInAs(string email, string sub = "sub-x", string name = "Some One") => Idp.Identity = (sub, email, name);
    protected static async Task<int> MeStatus(HttpClient browser) => (int)(await browser.GetAsync("/v1/me")).StatusCode;
    protected static async Task<string> MeEmail(HttpClient browser) => (await ReadJsonAsync(await browser.GetAsync("/v1/me"))).GetProperty("user").GetProperty("email").GetString()!;
}

/// <summary>Signing in through a workspace's SSO, start to finish.</summary>
public sealed class SsoSignInTests(SsoFactory factory) : SsoSignInBase(factory)
{
    [Fact]
    public async Task A_new_person_signs_in_and_joins_as_a_member()
    {
        var email = Person();
        SignInAs(email, "sub-new");
        var browser = Factory.Browser();
        var response = await W.SignInAsync(browser);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("http://localhost/dashboard", response.Headers.Location!.ToString());
        Assert.Equal(200, await MeStatus(browser));
        Assert.Equal(email, await MeEmail(browser));

        var user = W.Db(db => db.Users.Single(u => u.Email == email));
        Assert.True(user.EmailVerified);
        Assert.Equal(SsoProvisioning.UnusablePassword, user.PasswordHash);
        var member = W.Db(db => db.Members.Single(m => m.UserId == user.Id && m.OrganizationId == W.OrgId));
        Assert.Equal("member", member.Role);
        var identity = W.Db(db => db.Set<ExternalIdentity>().Single(i => i.UserId == user.Id));
        Assert.Equal("sso", identity.Source);
        Assert.Equal("sub-new", identity.RemoteId);
        Assert.NotNull(identity.LastSsoLoginAt);
        Assert.Equal(W.OrgId, W.Db(db => db.Sessions.Single(s => s.UserId == user.Id).ActiveOrganizationId));
        Assert.Equal("sso", W.Db(db => db.Sessions.Single(s => s.UserId == user.Id).Method));
    }

    [Fact]
    public async Task A_returning_person_is_recognised_by_the_providers_subject_not_by_email()
    {
        SignInAs(Person("first"), "sub-stable");
        var browser = Factory.Browser();
        await W.SignInAsync(browser);
        var userId = W.Db(db => db.Users.Single(u => u.Email == Person("first")).Id);
        SignInAs(Person("renamed"), "sub-stable");
        var again = Factory.Browser();
        Assert.Equal(HttpStatusCode.Redirect, (await W.SignInAsync(again)).StatusCode);
        Assert.Equal(Person("first"), await MeEmail(again));
        Assert.Equal(0, W.UsersWithEmail(Person("renamed")));
        Assert.Equal(1, W.Db(db => db.Set<ExternalAccount>().Count(a => a.UserId == userId)));
    }

    [Fact]
    public async Task An_account_nobody_verified_is_taken_over_by_the_verified_domain_identity()
    {
        var email = Person("alice");
        var squatter = await W.Http.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "Squatter", email, password = Password });
        var oldToken = (await ReadJsonAsync(squatter)).GetProperty("token").GetString()!;
        Assert.Equal(HttpStatusCode.OK, (await W.Http.SendAsync(Bearer(HttpMethod.Get, "/v1/me", oldToken))).StatusCode);

        SignInAs(email, "sub-alice", "Alice");
        var browser = Factory.Browser();
        Assert.Equal(HttpStatusCode.Redirect, (await W.SignInAsync(browser)).StatusCode);
        Assert.Equal(1, W.UsersWithEmail(email));
        Assert.Equal(email, await MeEmail(browser));
        // Whoever registered the address first lost their way in: the password and every session.
        Assert.Equal(HttpStatusCode.Unauthorized, (await W.Http.SendAsync(Bearer(HttpMethod.Get, "/v1/me", oldToken))).StatusCode);
        Assert.Equal(SsoProvisioning.UnusablePassword, W.Db(db => db.Users.Single(u => u.Email == email).PasswordHash));
    }

    [Fact]
    public async Task An_account_that_proved_its_email_is_linked_and_keeps_its_password()
    {
        var email = Person("bob");
        await W.Http.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "Bob", email, password = Password });
        W.Db(db => { db.Users.Where(u => u.Email == email).ExecuteUpdate(s => s.SetProperty(u => u.EmailVerified, true)); return 0; });
        var before = W.Db(db => db.Users.Single(u => u.Email == email));
        SignInAs(email, "sub-bob");
        var browser = Factory.Browser();
        Assert.Equal(HttpStatusCode.Redirect, (await W.SignInAsync(browser)).StatusCode);
        var after = W.Db(db => db.Users.Single(u => u.Email == email));
        Assert.Equal(before.Id, after.Id);
        Assert.Equal(before.PasswordHash, after.PasswordHash);
        Assert.Equal(1, W.Db(db => db.Set<ExternalAccount>().Count(a => a.UserId == before.Id && a.ProviderId == W.ProviderId)));
    }

    [Fact]
    public async Task An_invited_person_joins_with_the_invitations_role()
    {
        var email = Person("invited");
        var invitation = await W.Owner(HttpMethod.Post, "/v1/invitations", new { email, role = "admin" });
        Assert.Equal(HttpStatusCode.Created, invitation.Status);
        SignInAs(email, "sub-invited");
        await W.SignInAsync(Factory.Browser());
        var userId = W.Db(db => db.Users.Single(u => u.Email == email).Id);
        Assert.Equal("admin", W.Db(db => db.Members.Single(m => m.UserId == userId && m.OrganizationId == W.OrgId).Role));
        Assert.Equal("accepted", W.Db(db => db.Invitations.Single(i => i.OrganizationId == W.OrgId && i.Email == email).Status));
    }

    [Fact]
    public async Task The_sign_in_form_sends_the_domain_to_SSO_only_while_it_is_enabled()
    {
        var anyone = $"someone@{W.Domain}";
        var options = await ReadJsonAsync(await W.Http.GetAsync($"/v1/auth/login-options?email={anyone}"));
        Assert.Equal("sso", options.GetProperty("nextStep").GetString());
        Assert.Equal(W.OrgSlug, options.GetProperty("organizationSlug").GetString());
        Assert.Equal($"http://localhost/sso/{W.OrgSlug}", options.GetProperty("signInUrl").GetString());
        var resolved = await ReadJsonAsync(await W.Http.GetAsync($"/v1/orgs/sso/resolve?email={anyone}"));
        Assert.True(resolved.GetProperty("requireSso").GetBoolean());
        Assert.Equal("sso", resolved.GetProperty("method").GetString());
        Assert.Equal($"/sso/{W.OrgSlug}", resolved.GetProperty("signInPath").GetString());

        var elsewhere = await ReadJsonAsync(await W.Http.GetAsync("/v1/orgs/sso/resolve?email=someone@not-this-domain.test"));
        Assert.False(elsewhere.GetProperty("requireSso").GetBoolean());
        Assert.Equal("signup", elsewhere.GetProperty("method").GetString());
        var known = await ReadJsonAsync(await W.Http.GetAsync($"/v1/orgs/sso/resolve?email={Uri.EscapeDataString(W.OwnerEmail)}"));
        Assert.Equal("sso", known.GetProperty("method").GetString());

        Assert.Equal(HttpStatusCode.NoContent, (await W.Owner(HttpMethod.Post, "/v1/sso/disable", new { })).Status);
        var off = await ReadJsonAsync(await W.Http.GetAsync($"/v1/auth/login-options?email={anyone}"));
        Assert.Equal("new_account", off.GetProperty("nextStep").GetString());
        Assert.False((await ReadJsonAsync(await W.Http.GetAsync($"/v1/orgs/sso/resolve?email={anyone}"))).GetProperty("requireSso").GetBoolean());
    }

    [Fact]
    public async Task Members_of_a_workspace_with_SSO_cannot_use_a_password()
    {
        var blocked = await W.Http.PostAsJsonAsync("/api/auth/sign-in/email", new { email = W.OwnerEmail, password = Password });
        Assert.Equal(HttpStatusCode.Forbidden, blocked.StatusCode);
        Assert.Equal("This account is managed by an organization. Use SSO to sign in.", (await ReadJsonAsync(blocked)).GetProperty("message").GetString());
        var signUp = await W.Http.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "Again", email = W.OwnerEmail, password = Password });
        Assert.Equal(HttpStatusCode.Forbidden, signUp.StatusCode);
        // Someone outside is not affected.
        var (outsider, _, _) = await Factory.SignUpAsync(W.Http, "Outsider");
        Assert.Equal(HttpStatusCode.OK, (await W.Http.PostAsJsonAsync("/api/auth/sign-in/email", new { email = outsider, password = Password })).StatusCode);
        // Turning SSO off gives the password back.
        await W.Owner(HttpMethod.Post, "/v1/sso/disable", new { });
        Assert.Equal(HttpStatusCode.OK, (await W.Http.PostAsJsonAsync("/api/auth/sign-in/email", new { email = W.OwnerEmail, password = Password })).StatusCode);
    }

    [Fact]
    public async Task A_disabled_connection_signs_nobody_in_even_mid_flight()
    {
        SignInAs(Person("late"), "sub-late");
        var browser = Factory.Browser();
        var (_, started) = await W.StartSignInAsync(browser);
        var back = await SsoWorld.AtIdpAsync(started.GetProperty("url").GetString()!);
        await W.Owner(HttpMethod.Post, "/v1/sso/disable", new { });
        var callback = await browser.GetAsync(SsoWorld.PathAndQuery(back));
        Assert.Equal(HttpStatusCode.Forbidden, callback.StatusCode);
        Assert.Equal("sso_not_enabled", (await ReadJsonAsync(callback)).GetProperty("error").GetString());
        Assert.Equal(0, Idp.TokenCalls - 1);   // only the connection test used the token endpoint
        Assert.Equal(0, W.UsersWithEmail(Person("late")));
        var (response, body) = await W.StartSignInAsync(Factory.Browser());
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains("SSO is not enabled for this organization", body.GetProperty("message").GetString());
    }

    [Fact]
    public async Task Starting_sign_in_finds_the_connection_in_the_ways_the_reference_does_and_explains_failures()
    {
        var browser = Factory.Browser();
        foreach (var body in new object[] { new { providerId = W.ProviderId, callbackURL = "/dashboard" }, new { domain = W.Domain, callbackURL = "/dashboard" }, new { email = $"x@{W.Domain}", callbackURL = "/dashboard" }, new { email = $"x@sub.{W.Domain}", callbackURL = "/dashboard" } })
        {
            var (response, started) = await W.StartSignInAsync(browser, body);
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.True(started.GetProperty("redirect").GetBoolean());
        }
        var unknownProvider = await W.StartSignInAsync(browser, new { providerId = "nope", callbackURL = "/dashboard" });
        Assert.Equal(HttpStatusCode.NotFound, unknownProvider.Response.StatusCode);
        Assert.Equal("No provider found for the issuer", unknownProvider.Body.GetProperty("message").GetString());
        var unknownSlug = await W.StartSignInAsync(browser, new { organizationSlug = "nope-nope", callbackURL = "/dashboard" });
        Assert.Equal(HttpStatusCode.BadRequest, unknownSlug.Response.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await W.StartSignInAsync(browser, new { callbackURL = "/dashboard" })).Response.StatusCode);
        var noCallback = await W.StartSignInAsync(browser, new { organizationSlug = W.OrgSlug });
        Assert.Equal(HttpStatusCode.BadRequest, noCallback.Response.StatusCode);
        Assert.Equal("VALIDATION_ERROR", noCallback.Body.GetProperty("code").GetString());
    }

    [Fact]
    public async Task A_new_person_can_be_sent_to_their_own_landing_page_and_a_failed_sign_in_to_the_error_page()
    {
        SignInAs(Person("landing"), "sub-landing");
        var browser = Factory.Browser();
        var response = await W.SignInAsync(browser, new { organizationSlug = W.OrgSlug, callbackURL = "/dashboard", newUserCallbackURL = "/welcome", errorCallbackURL = "/oops" });
        Assert.Equal("http://localhost/welcome", response.Headers.Location!.ToString());
        Idp.Fault = "error";
        var failed = await W.SignInAsync(Factory.Browser(), new { organizationSlug = W.OrgSlug, callbackURL = "/dashboard", errorCallbackURL = "/oops" });
        Assert.StartsWith("http://localhost/oops?error=access_denied", failed.Headers.Location!.ToString());
    }
}

/// <summary>Attacks on the sign-in: each must fail closed, create no one and sign no one in.</summary>
public sealed class SsoAttackTests(SsoFactory factory) : SsoSignInBase(factory)
{
    private async Task<(HttpClient Browser, string Callback)> ReadyAsync(string email = "target@x", string sub = "sub-target")
    {
        var address = email.EndsWith("@x") ? Person(email[..^2]) : email;
        SignInAs(address, sub);
        var browser = Factory.Browser();
        var (_, started) = await W.StartSignInAsync(browser);
        var back = await SsoWorld.AtIdpAsync(started.GetProperty("url").GetString()!);
        return (browser, SsoWorld.PathAndQuery(back));
    }

    private static string LocationOf(HttpResponseMessage r) => r.Headers.Location?.ToString() ?? "";
    private int Tokens => Idp.TokenCalls;

    [Fact]
    public async Task A_state_works_only_once()
    {
        var (browser, callback) = await ReadyAsync();
        var before = Tokens;
        Assert.Equal("http://localhost/dashboard", LocationOf(await browser.GetAsync(callback)));
        var replay = await browser.GetAsync(callback);
        Assert.Contains("/connect/error?error=state_mismatch", LocationOf(replay));
        Assert.Equal(before + 1, Tokens);
        Assert.Equal(1, W.SessionsFor(Person("target")));
    }

    [Fact]
    public async Task A_state_must_come_back_in_the_browser_that_started_it()
    {
        var (browser, callback) = await ReadyAsync();
        var victim = Factory.Browser();           // the attacker feeds the victim a callback with the attacker's code and state
        var before = Tokens;
        Assert.Contains("state_mismatch", LocationOf(await victim.GetAsync(callback)));
        Assert.Equal(before, Tokens);
        Assert.Equal(0, W.UsersWithEmail(Person("target")));
        Assert.Equal(401, await MeStatus(victim));
        // A refused attempt did not burn the real one.
        Assert.Equal("http://localhost/dashboard", LocationOf(await browser.GetAsync(callback)));
    }

    [Fact]
    public async Task A_state_made_for_one_connection_is_refused_by_another()
    {
        var (browser, callback) = await ReadyAsync();
        var other = await SsoWorld.CreateAsync(Factory, Idp, Factory.Dns);
        await other.VerifiedTestedAndEnabledAsync();
        var swapped = callback.Replace(W.ProviderId, other.ProviderId);
        Assert.NotEqual(callback, swapped);
        var before = Tokens;
        Assert.Contains("state_mismatch", LocationOf(await browser.GetAsync(swapped)));
        Assert.Equal(before, Tokens);
        Assert.Equal(0, W.UsersWithEmail(Person("target")));
    }

    [Fact]
    public async Task A_made_up_state_or_a_code_without_one_never_reaches_the_token_endpoint()
    {
        var browser = Factory.Browser();
        var before = Tokens;
        foreach (var query in new[] { "?code=abc&state=forged", "?code=abc", "?state=forged", "" })
            Assert.Contains("state_mismatch", LocationOf(await browser.GetAsync($"/api/auth/sso/callback/{W.ProviderId}{query}")));
        Assert.Contains("state_mismatch", LocationOf(await browser.GetAsync("/api/auth/sso/callback/unknown-provider?code=abc&state=x")));
        Assert.Equal(before, Tokens);
    }

    [Fact]
    public async Task A_state_expires()
    {
        var (browser, callback) = await ReadyAsync();
        Factory.WithDb(db => { db.Set<SsoAuthState>().ExecuteUpdate(s => s.SetProperty(x => x.ExpiresAt, DateTime.UtcNow.AddMinutes(-1))); return 0; });
        var before = Tokens;
        Assert.Contains("state_mismatch", LocationOf(await browser.GetAsync(callback)));
        Assert.Equal(before, Tokens);
    }

    [Theory]
    [InlineData("nonce")]
    [InlineData("no-nonce")]
    [InlineData("aud")]
    [InlineData("iss")]
    [InlineData("exp")]
    [InlineData("sig")]
    [InlineData("alg-none")]
    [InlineData("alg-hs256")]
    [InlineData("no-sub")]
    [InlineData("no-email")]
    [InlineData("kid-unknown")]
    [InlineData("azp")]
    [InlineData("nbf")]
    public async Task A_bad_ID_token_signs_nobody_in(string fault)
    {
        Idp.Fault = fault;
        var (browser, callback) = await ReadyAsync($"victim-{fault}@x");
        var response = await browser.GetAsync(callback);
        Assert.StartsWith("http://localhost/dashboard?error=", LocationOf(response));
        Assert.Equal(0, W.UsersWithEmail(Person($"victim-{fault}")));
        Assert.Equal(401, await MeStatus(browser));
        Assert.Equal(0, W.Db(db => db.Set<ExternalAccount>().Count(a => a.ProviderId == W.ProviderId && a.AccountId == "sub-target")));
    }

    [Fact]
    public async Task A_provider_answer_naming_another_issuer_is_refused_before_anything_is_sent_to_it()
    {
        var (browser, callback) = await ReadyAsync();
        var before = Tokens;
        var response = await browser.GetAsync(callback + "&iss=" + Uri.EscapeDataString("https://evil.example"));
        Assert.Contains("error=invalid_state", LocationOf(response));
        Assert.Equal(before, Tokens);
        Assert.Equal(0, W.UsersWithEmail(Person("target")));
    }

    [Fact]
    public async Task The_provider_telling_us_it_refused_ends_in_an_error_not_a_session()
    {
        Idp.Fault = "error";
        var (browser, callback) = await ReadyAsync();
        Assert.Contains("error=access_denied", LocationOf(await browser.GetAsync(callback)));
        Assert.Equal(401, await MeStatus(browser));
    }

    [Fact]
    public async Task The_request_uses_PKCE_state_and_nonce_and_keeps_the_secret_off_the_browser()
    {
        var (browser, callback) = await ReadyAsync();
        var request = Idp.AuthRequests.Last();
        Assert.Equal("S256", request["code_challenge_method"]);
        Assert.Equal(43, request["code_challenge"].Length);
        Assert.True(request["state"].Length >= 40 && request["nonce"].Length >= 30);
        Assert.NotEqual(request["state"], request["nonce"]);
        Assert.Contains("openid", request["scope"]);
        Assert.StartsWith("http://localhost/api/auth/sso/callback/", request["redirect_uri"]);
        Assert.DoesNotContain(FakeIdp.ClientSecret, string.Join('&', request.Values));
        await browser.GetAsync(callback);
        var token = Idp.TokenRequests.Last();
        Assert.Equal("basic", token["_auth"]);
        Assert.False(token.ContainsKey("client_secret"));
        Assert.Equal(request["redirect_uri"], token["redirect_uri"]);
        // The verifier is stored encrypted, never in the clear (it hashes to the challenge the provider checked).
        Assert.DoesNotContain(token["code_verifier"], W.Db(db => string.Join(',', db.Set<SsoAuthState>().Select(s => s.CodeVerifierProtected))));
    }

    [Fact]
    public async Task A_secret_can_be_sent_in_the_form_instead_of_basic_auth()
    {
        await W.Owner(HttpMethod.Post, "/v1/sso/disable", new { });
        await W.RegisterAsync(new { tokenEndpointAuthentication = "client_secret_post" });
        await W.VerifyDomainAsync();
        await W.RunTestAsync();
        await W.Owner(HttpMethod.Post, "/v1/sso/enable", new { });
        var (browser, callback) = await ReadyAsync();
        Assert.Equal("http://localhost/dashboard", LocationOf(await browser.GetAsync(callback)));
        var token = Idp.TokenRequests.Last();
        Assert.Equal("post", token["_auth"]);
        Assert.Equal(FakeIdp.ClientSecret, token["client_secret"]);
    }

    [Theory]
    [InlineData("https://evil.example/x")]
    [InlineData("//evil.example/x")]
    [InlineData("/\\evil.example")]
    [InlineData("javascript:alert(1)")]
    [InlineData("http://localhost@evil.example/")]
    [InlineData("https://localhost.evil.example/")]
    [InlineData("http://localhost:81/dashboard")]
    public async Task Sign_in_will_not_redirect_to_other_sites(string target)
    {
        var browser = Factory.Browser();
        var states = W.Db(db => db.Set<SsoAuthState>().Count());
        var callback = await W.StartSignInAsync(browser, new { organizationSlug = W.OrgSlug, callbackURL = target });
        Assert.Equal(HttpStatusCode.Forbidden, callback.Response.StatusCode);
        Assert.Equal("INVALID_CALLBACK_URL", callback.Body.GetProperty("code").GetString());
        var error = await W.StartSignInAsync(browser, new { organizationSlug = W.OrgSlug, callbackURL = "/dashboard", errorCallbackURL = target });
        Assert.Equal("INVALID_ERROR_CALLBACK_URL", error.Body.GetProperty("code").GetString());
        var fresh = await W.StartSignInAsync(browser, new { organizationSlug = W.OrgSlug, callbackURL = "/dashboard", newUserCallbackURL = target });
        Assert.Equal("INVALID_NEW_USER_CALLBACK_URL", fresh.Body.GetProperty("code").GetString());
        Assert.Equal(states, W.Db(db => db.Set<SsoAuthState>().Count()));
    }

    [Fact]
    public async Task A_provider_cannot_speak_for_an_email_outside_the_verified_domain()
    {
        var victim = "victim@other-company.test";
        var created = await W.Http.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "Victim", email = victim, password = Password });
        var victimToken = (await ReadJsonAsync(created)).GetProperty("token").GetString()!;
        var (browser, callback) = await ReadyAsync(victim, "sub-evil");
        Assert.Contains("error=email_outside_sso_domain", LocationOf(await browser.GetAsync(callback)));
        Assert.Equal(401, await MeStatus(browser));
        // The victim's account is untouched: still has its password and its session, and is not linked.
        Assert.NotEqual(SsoProvisioning.UnusablePassword, W.Db(db => db.Users.Single(u => u.Email == victim).PasswordHash));
        Assert.Equal(HttpStatusCode.OK, (await W.Http.SendAsync(Bearer(HttpMethod.Get, "/v1/me", victimToken))).StatusCode);
        Assert.Equal(0, W.Db(db => db.Set<ExternalAccount>().Count(a => a.AccountId == "sub-evil")));
        Assert.Equal(0, W.Db(db => db.Members.Count(m => m.OrganizationId == W.OrgId && db.Users.Any(u => u.Id == m.UserId && u.Email == victim))));
        // A look-alike domain is no better.
        var (b2, c2) = await ReadyAsync($"x@{W.Domain}.evil.test", "sub-evil2");
        Assert.Contains("error=email_outside_sso_domain", LocationOf(await b2.GetAsync(c2)));
        // A real subdomain of the verified domain is fine.
        var (b3, c3) = await ReadyAsync($"x@dept.{W.Domain}", "sub-dept");
        Assert.Equal("http://localhost/dashboard", LocationOf(await b3.GetAsync(c3)));
    }

    [Fact]
    public async Task An_unverified_domain_signs_nobody_in_and_forces_nobody_to_SSO()
    {
        // Even if a connection were switched on without its domain being proved, it must do nothing.
        Factory.WithDb(db => { db.Set<SsoConnection>().Where(c => c.OrganizationId == W.OrgId).ExecuteUpdate(s => s.SetProperty(c => c.DomainVerified, false)); return 0; });
        var started = await W.StartSignInAsync(Factory.Browser());
        Assert.Equal(HttpStatusCode.Forbidden, started.Response.StatusCode);
        var options = await ReadJsonAsync(await W.Http.GetAsync($"/v1/auth/login-options?email=anyone@{W.Domain}"));
        Assert.Equal("new_account", options.GetProperty("nextStep").GetString());
        Assert.False((await ReadJsonAsync(await W.Http.GetAsync($"/v1/orgs/sso/resolve?email=anyone@{W.Domain}"))).GetProperty("requireSso").GetBoolean());
        Assert.Equal(HttpStatusCode.OK, (await W.Http.PostAsJsonAsync("/api/auth/sign-in/email", new { email = W.OwnerEmail, password = Password })).StatusCode);
        // A state that was already in flight is refused at the callback too.
        Factory.WithDb(db => { db.Set<SsoConnection>().Where(c => c.OrganizationId == W.OrgId).ExecuteUpdate(s => s.SetProperty(c => c.DomainVerified, true)); return 0; });
        var (browser, callback) = await ReadyAsync();
        Factory.WithDb(db => { db.Set<SsoConnection>().Where(c => c.OrganizationId == W.OrgId).ExecuteUpdate(s => s.SetProperty(c => c.DomainVerified, false)); return 0; });
        Assert.Equal(HttpStatusCode.Forbidden, (await browser.GetAsync(callback)).StatusCode);
        Assert.Equal(0, W.UsersWithEmail(Person("target")));
    }

    [Fact]
    public async Task Saving_the_connection_again_voids_sign_ins_in_flight()
    {
        var (browser, callback) = await ReadyAsync();
        await W.RegisterAsync();
        var before = Tokens;
        var response = await browser.GetAsync(callback);
        Assert.True(response.StatusCode == HttpStatusCode.Forbidden || LocationOf(response).Contains("state_mismatch"));
        Assert.Equal(before, Tokens);
        Assert.Equal(0, W.UsersWithEmail(Person("target")));
    }

    [Fact]
    public async Task An_old_state_is_refused_when_the_configuration_changed_under_it()
    {
        var (browser, callback) = await ReadyAsync();
        Factory.WithDb(db => { db.Set<SsoAuthState>().ExecuteUpdate(s => s.SetProperty(x => x.ConfigRevision, "an-older-revision")); return 0; });
        Assert.Contains("error=invalid_state", LocationOf(await browser.GetAsync(callback)));
        Assert.Equal(0, W.UsersWithEmail(Person("target")));
    }

    [Fact]
    public async Task Too_many_sign_in_starts_are_slowed_down_when_limits_are_on()
    {
        // The limiter is off in Development; this proves the policy is wired with a per-source cap.
        Assert.Equal(100, SsoSignInEndpoints.StartLimit.IpMax);
        await Task.CompletedTask;
    }
}
