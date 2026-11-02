using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.Sso;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>
/// The emailed code's other uses (sign in, check, reset a password): the verification code's security rules apply to each (hashed, ten minutes,
/// five guesses even in parallel, one purpose per code, no account enumeration) plus an attack on each.
/// </summary>
public sealed class EmailCodeTests : IClassFixture<ApiFactory>
{
    private const string NewPassword = "N3w!Passw0rd#2027y";
    private readonly ApiFactory _factory;
    public EmailCodeTests(ApiFactory factory) => _factory = factory;

    private static Task<HttpResponseMessage> Post(HttpClient http, string path, object body) => http.PostAsJsonAsync(path, body);
    private static Task<HttpResponseMessage> Send(HttpClient http, string email, string type) => Post(http, "/api/auth/email-otp/send-verification-otp", new { email, type });
    private static Task<HttpResponseMessage> SignIn(HttpClient http, string email, string otp) => Post(http, "/api/auth/sign-in/email-otp", new { email, otp });
    private string CodeFor(string email) => Mail.LastCode(_factory.Outbox, email);
    private static string Wrong(string code) => code == "000000" ? "111111" : "000000";
    private static async Task<string?> CodeOf(HttpResponseMessage r) => (await ReadJsonAsync(r)).TryGetProperty("code", out var c) ? c.GetString() : null;

    private async Task<(string Email, string Token, string UserId)> PersonAsync() => await _factory.SignUpAsync(_factory.Plain());

    // ---------- sending ----------

    [Fact]
    public async Task Sending_a_sign_in_or_reset_code_answers_the_same_for_a_real_and_an_unknown_address()
    {
        var http = _factory.Plain();
        var (real, _, _) = await PersonAsync();
        foreach (var type in new[] { "sign-in", "forget-password" })
        {
            var a = await Send(http, real, type); var b = await Send(http, NewEmail("ghost"), type);
            Assert.Equal(HttpStatusCode.OK, a.StatusCode);
            Assert.Equal("{\"success\":true}", await a.Content.ReadAsStringAsync());
            Assert.Equal(await a.Content.ReadAsStringAsync(), await b.Content.ReadAsStringAsync());
        }
        // A code for a reset exists only for a real account; one for signing in exists for any address.
        var ghost = NewEmail("ghost2");
        await Send(http, ghost, "forget-password");
        Assert.Empty(_factory.Outbox.To(ghost));
        await Send(http, ghost, "sign-in");
        Assert.Single(_factory.Outbox.To(ghost));
    }

    [Fact]
    public async Task Change_email_codes_are_off_as_in_the_reference_and_the_routes_need_a_session()
    {
        var http = _factory.Plain();
        var response = await Send(http, NewEmail(), "change-email");
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("Invalid OTP type", (await ReadJsonAsync(response)).GetProperty("message").GetString());

        foreach (var path in new[] { "/api/auth/email-otp/request-email-change", "/api/auth/email-otp/change-email" })
        {
            Assert.Equal(HttpStatusCode.Unauthorized, (await Post(http, path, new { newEmail = NewEmail(), otp = "123456" })).StatusCode);
            var browser = _factory.Browser();
            await _factory.SignUpAsync(browser);
            var signedIn = await Post(browser, path, new { newEmail = NewEmail(), otp = "123456" });
            Assert.Equal(HttpStatusCode.BadRequest, signedIn.StatusCode);
            Assert.Equal("Change email with OTP is disabled", (await ReadJsonAsync(signedIn)).GetProperty("message").GetString());
        }
        var unknownType = await Send(http, NewEmail(), "nope");
        Assert.Equal("VALIDATION_ERROR", await CodeOf(unknownType));
    }

    [Fact]
    public async Task Codes_are_stored_only_as_keyed_hashes_and_each_purpose_has_its_own_row()
    {
        var http = _factory.Plain();
        var (email, _, _) = await PersonAsync();
        await Send(http, email, "sign-in");
        var code = CodeFor(email);
        await Send(http, email, "forget-password");
        var rows = _factory.WithDb(db => db.EmailOtps.AsNoTracking().Where(o => o.Email == email).ToList());
        Assert.Contains(rows, r => r.Type == "sign-in");
        Assert.Contains(rows, r => r.Type == "forget-password");
        Assert.All(rows, r => { Assert.DoesNotContain(code, r.CodeHash); Assert.Equal(64, r.CodeHash.Length); Assert.True(r.ExpiresAt - r.CreatedAt <= TimeSpan.FromMinutes(10)); });
        Assert.NotEqual(rows.Single(r => r.Type == "sign-in").CodeHash, rows.Single(r => r.Type == "forget-password").CodeHash);
    }

    // ---------- sign in with a code ----------

    [Fact]
    public async Task A_code_signs_the_person_in_verifies_the_account_and_works_once()
    {
        var browser = _factory.Browser();
        var (email, _, userId) = await _factory.SignUpAsync(browser);
        await Send(browser, email, "sign-in");
        var code = CodeFor(email);
        Assert.False(_factory.WithDb(db => db.Users.Single(u => u.Id == userId).EmailVerified));

        Assert.Equal(HttpStatusCode.BadRequest, (await SignIn(browser, email, Wrong(code))).StatusCode);
        var response = await SignIn(browser, email.ToUpperInvariant(), $" {code} ");   // address case and padding do not matter
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains(response.Headers.GetValues("Set-Cookie"), c => c.StartsWith("openwork-den.session_token="));
        var json = await ReadJsonAsync(response);
        Assert.True(json.GetProperty("user").GetProperty("emailVerified").GetBoolean());
        Assert.Equal(HttpStatusCode.OK, (await _factory.Plain().SendAsync(Bearer(HttpMethod.Get, "/v1/me", json.GetProperty("token").GetString()!))).StatusCode);
        Assert.True(_factory.WithDb(db => db.Users.Single(u => u.Id == userId).EmailVerified));
        Assert.Equal("email-otp", _factory.WithDb(db => db.Sessions.OrderByDescending(s => s.CreatedAt).First(s => s.UserId == userId).Method));

        Assert.Equal("INVALID_OTP", await CodeOf(await SignIn(browser, email, code)));   // spent
    }

    [Fact]
    public async Task An_address_with_no_account_gets_one_when_its_inbox_is_proven()
    {
        var http = _factory.Plain();
        var email = NewEmail("newcomer");
        await Send(http, email, "sign-in");
        var response = await SignIn(http, email, CodeFor(email));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var user = _factory.WithDb(db => db.Users.AsNoTracking().Single(u => u.Email == email));
        Assert.True(user.EmailVerified);
        Assert.False(Passwords.Verify("anything", user.PasswordHash));   // a code-only account has no password to guess
    }

    [Fact]
    public async Task Five_guesses_are_all_a_code_gets_even_when_they_arrive_together()
    {
        var http = _factory.Plain();
        var (email, _, _) = await PersonAsync();
        await Send(http, email, "sign-in");
        var code = CodeFor(email);
        var results = await Task.WhenAll(Enumerable.Range(0, 24).Select(_ => SignIn(http, email, Wrong(code))));
        var codes = await Task.WhenAll(results.Select(CodeOf));
        Assert.Contains("TOO_MANY_ATTEMPTS", codes);   // the code gave up after five guesses, however they were interleaved
        // The right code is of no use now: guessing used it up.
        Assert.Equal(HttpStatusCode.BadRequest, (await SignIn(http, email, code)).StatusCode);
        Assert.Equal(0, _factory.WithDb(db => db.EmailOtps.Count(o => o.Email == email && o.Type == "sign-in")));
    }

    [Fact]
    public async Task A_code_expires_after_ten_minutes()
    {
        var http = _factory.Plain();
        var (email, _, _) = await PersonAsync();
        await Send(http, email, "sign-in");
        var code = CodeFor(email);
        _factory.WithDb(db => db.EmailOtps.Where(o => o.Email == email).ExecuteUpdate(o => o.SetProperty(x => x.ExpiresAt, DateTime.UtcNow.AddSeconds(-1))));
        Assert.Equal("OTP_EXPIRED", await CodeOf(await SignIn(http, email, code)));
        Assert.Equal("INVALID_OTP", await CodeOf(await SignIn(http, email, code)));   // and it is gone
    }

    [Fact]
    public async Task A_code_is_for_one_purpose_and_one_address()
    {
        var http = _factory.Plain();
        var (email, _, _) = await PersonAsync();
        var (other, _, _) = await PersonAsync();

        await Send(http, email, "forget-password");
        var resetCode = CodeFor(email);
        Assert.Equal("INVALID_OTP", await CodeOf(await SignIn(http, email, resetCode)));   // a reset code cannot sign in

        await Send(http, email, "sign-in");
        var signInCode = CodeFor(email);
        Assert.Equal("INVALID_OTP", await CodeOf(await Post(http, "/api/auth/email-otp/reset-password", new { email, otp = signInCode, password = NewPassword })));   // and a sign-in code cannot reset
        Assert.Equal("INVALID_OTP", await CodeOf(await Post(http, "/api/auth/email-otp/check-verification-otp", new { email, type = "forget-password", otp = signInCode })));

        // Another address with the same digits (their own code) never accepts this one.
        await Send(http, other, "sign-in");
        Assert.Equal("INVALID_OTP", await CodeOf(await SignIn(http, other, signInCode == CodeFor(other) ? Wrong(signInCode) : signInCode)));
        // The verification code is a third purpose.
        var (unverified, _, _) = await PersonAsync();
        await Send(http, unverified, "email-verification");
        Assert.Equal("INVALID_OTP", await CodeOf(await SignIn(http, unverified, CodeFor(unverified))));
    }

    [Fact]
    public async Task A_wrong_code_reads_the_same_for_an_unknown_address_as_for_a_real_one()
    {
        var http = _factory.Plain();
        var (real, _, _) = await PersonAsync();
        await Send(http, real, "sign-in");
        var a = await SignIn(http, real, Wrong(CodeFor(real)));
        var b = await SignIn(http, NewEmail("nobody"), "000000");
        Assert.Equal(await a.Content.ReadAsStringAsync(), await b.Content.ReadAsStringAsync());
        Assert.Equal(a.StatusCode, b.StatusCode);
    }

    // ---------- check ----------

    [Fact]
    public async Task Checking_a_code_does_not_use_it_but_every_check_is_a_guess()
    {
        var http = _factory.Plain();
        var (email, _, _) = await PersonAsync();
        await Send(http, email, "sign-in");
        var code = CodeFor(email);
        async Task<HttpResponseMessage> Check(string otp) => await Post(http, "/api/auth/email-otp/check-verification-otp", new { email, type = "sign-in", otp });
        Assert.Equal(HttpStatusCode.OK, (await Check(code)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Check(code)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await SignIn(http, email, code)).StatusCode);   // still usable after checking

        // A check is no way around the five guesses.
        await Send(http, email, "sign-in");
        var fresh = CodeFor(email);
        for (var i = 0; i < 5; i++) await Check(Wrong(fresh));
        var sixth = await Check(fresh);
        Assert.Equal(HttpStatusCode.Forbidden, sixth.StatusCode);
        Assert.Equal("TOO_MANY_ATTEMPTS", await CodeOf(sixth));
    }

    // ---------- reset a password ----------

    [Fact]
    public async Task A_reset_code_sets_the_password_signs_every_device_out_and_works_once()
    {
        var http = _factory.Plain();
        var (email, oldToken, _) = await PersonAsync();
        await Send(http, email, "forget-password");
        var code = CodeFor(email);

        // A password that breaks the rules is refused without using the code up.
        Assert.Equal(HttpStatusCode.BadRequest, (await Post(http, "/api/auth/email-otp/reset-password", new { email, otp = code, password = "abc" })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await Post(http, "/api/auth/email-otp/reset-password", new { email, otp = Wrong(code), password = NewPassword })).StatusCode);

        var reset = await Post(http, "/api/auth/email-otp/reset-password", new { email, otp = code, password = NewPassword });
        Assert.Equal(HttpStatusCode.OK, reset.StatusCode);
        Assert.Equal("{\"success\":true}", await reset.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.Unauthorized, (await Post(http, "/api/auth/sign-in/email", new { email, password = Password })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Post(http, "/api/auth/sign-in/email", new { email, password = NewPassword })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await http.SendAsync(Bearer(HttpMethod.Get, "/v1/me", oldToken))).StatusCode);   // the old session is gone
        Assert.Equal("INVALID_OTP", await CodeOf(await Post(http, "/api/auth/email-otp/reset-password", new { email, otp = code, password = NewPassword })));
    }

    [Fact]
    public async Task A_reset_code_for_one_person_cannot_reset_another_persons_password()
    {
        var http = _factory.Plain();
        var (mine, _, _) = await PersonAsync();
        var (victim, _, _) = await PersonAsync();
        await Send(http, mine, "forget-password");
        var response = await Post(http, "/api/auth/email-otp/reset-password", new { email = victim, otp = CodeFor(mine), password = NewPassword });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await Post(http, "/api/auth/sign-in/email", new { email = victim, password = Password })).StatusCode);
    }

    // ---------- SSO ----------

    [Fact]
    public async Task A_code_cannot_get_around_a_workspace_that_requires_SSO()
    {
        var domain = $"codes-{Guid.NewGuid():N}"[..14] + ".example";
        var orgId = _factory.WithDb(db =>
        {
            var org = new Organization { Id = Ids.New("org"), Name = "Sso", Slug = "sso-" + Guid.NewGuid().ToString("N")[..8], CreatedAt = DateTime.UtcNow };
            db.Organizations.Add(org);
            db.Add(new SsoConnection { Id = Ids.New("sso"), OrganizationId = org.Id, ProviderId = $"openwork-sso-{org.Id}", Kind = "oidc", Issuer = "https://idp.example.test", Domain = domain, Status = "enabled", SignInPath = $"/sso/{org.Slug}", ConfigRevision = "r1", TestStatus = "succeeded", DomainVerified = true, CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow });
            db.SaveChanges();
            return org.Id;
        });
        var http = _factory.Plain();
        var (member, _, memberId) = await PersonAsync();
        _factory.WithDb(db => { db.Members.Add(new Member { Id = Ids.New("mem"), OrganizationId = orgId, UserId = memberId, Role = "member", CreatedAt = DateTime.UtcNow }); db.SaveChanges(); return 0; });

        await Send(http, member, "sign-in");
        var refused = await SignIn(http, member, CodeFor(member));
        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
        Assert.False(refused.Headers.Contains("Set-Cookie"));

        var onDomain = $"someone@{domain}";
        await Send(http, onDomain, "sign-in");
        Assert.Equal(HttpStatusCode.Forbidden, (await SignIn(http, onDomain, CodeFor(onDomain))).StatusCode);
        Assert.False(_factory.WithDb(db => db.Users.Any(u => u.Email == onDomain)));
    }

    // ---------- limits ----------

    private sealed class RateLimitedFactory : ApiFactory
    {
        protected override IEnumerable<KeyValuePair<string, string>> Settings => [new("Auth:RateLimitsEnabled", "true")];
    }

    [Fact]
    public async Task Sending_and_guessing_are_rate_limited_per_address()
    {
        await using var factory = new RateLimitedFactory();
        var http = factory.Plain();
        var email = NewEmail("limited");
        for (var i = 0; i < 5; i++) Assert.Equal(HttpStatusCode.OK, (await Send(http, email, "sign-in")).StatusCode);
        var sixth = await Send(http, email, "sign-in");
        Assert.Equal(HttpStatusCode.TooManyRequests, sixth.StatusCode);
        Assert.True(sixth.Headers.Contains("Retry-After"));

        var guesser = NewEmail("guesser");
        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < 12; i++) statuses.Add((await SignIn(http, guesser, "000000")).StatusCode);
        Assert.Equal(10, statuses.Count(s => s == HttpStatusCode.BadRequest));
        Assert.Equal(2, statuses.Count(s => s == HttpStatusCode.TooManyRequests));
    }
}
