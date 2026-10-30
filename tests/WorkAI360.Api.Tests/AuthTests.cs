using System.Net;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using WorkAI360.Api.Auth;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

public sealed class AuthTests : IClassFixture<ApiFactory>
{
    private readonly ApiFactory _factory;
    public AuthTests(ApiFactory factory) => _factory = factory;

    [Fact]
    public async Task SignUp_returns_token_user_and_signed_cookie()
    {
        var client = _factory.Plain();
        var response = await client.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "Ada", email = NewEmail("ada"), password = Password });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await ReadJsonAsync(response);
        Assert.Equal(32, json.GetProperty("token").GetString()!.Length);
        Assert.Matches(@"^usr_[0-9a-hjkmnp-tv-z]{26}$", json.GetProperty("user").GetProperty("id").GetString()!);
        var cookie = response.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith("openwork-den.session_token="));
        Assert.Contains("httponly", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=lax", cookie, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SignUp_rejects_duplicate_email_and_weak_passwords()
    {
        var client = _factory.Plain();
        var email = NewEmail();
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "A", email, password = Password })).StatusCode);

        var duplicate = await client.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "A", email = email.ToUpperInvariant(), password = Password });
        Assert.Equal((HttpStatusCode)422, duplicate.StatusCode);

        var weak = await client.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "A", email = NewEmail(), password = "abc12345" });
        Assert.Equal(HttpStatusCode.BadRequest, weak.StatusCode);
        Assert.Equal("password_missing_uppercase", (await ReadJsonAsync(weak)).GetProperty("error").GetString());

        var badEmail = await client.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "A", email = "not-an-email", password = Password });
        Assert.Equal(HttpStatusCode.BadRequest, badEmail.StatusCode);
    }

    [Fact]
    public async Task SignIn_wrong_password_is_401_and_correct_password_works_as_bearer()
    {
        var client = _factory.Plain();
        var (email, _, userId) = await _factory.SignUpAsync(client);

        var wrong = await client.PostAsJsonAsync("/api/auth/sign-in/email", new { email, password = "Wrong!Passw0rd#999" });
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        Assert.Equal("INVALID_EMAIL_OR_PASSWORD", (await ReadJsonAsync(wrong)).GetProperty("code").GetString());

        var ok = await client.PostAsJsonAsync("/api/auth/sign-in/email", new { email, password = Password });
        var token = (await ReadJsonAsync(ok)).GetProperty("token").GetString()!;

        var me = await client.SendAsync(Bearer(HttpMethod.Get, "/v1/me", token));
        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        Assert.Equal(userId, (await ReadJsonAsync(me)).GetProperty("user").GetProperty("id").GetString());
    }

    [Fact]
    public async Task Repeated_failures_lock_sign_in_with_retry_after()
    {
        var client = _factory.Plain();
        var (email, _, _) = await _factory.SignUpAsync(client);

        HttpResponseMessage? last = null;
        for (var i = 0; i < 6; i++) last = await client.PostAsJsonAsync("/api/auth/sign-in/email", new { email, password = "Wrong!Passw0rd#999" });

        Assert.Equal((HttpStatusCode)429, last!.StatusCode);
        Assert.True(last.Headers.Contains("Retry-After"));
        Assert.Equal("login_locked", (await ReadJsonAsync(last)).GetProperty("error").GetString());
        // Even the right password is refused while locked.
        var locked = await client.PostAsJsonAsync("/api/auth/sign-in/email", new { email, password = Password });
        Assert.Equal((HttpStatusCode)429, locked.StatusCode);
    }

    [Fact]
    public async Task Session_tokens_are_stored_hashed_never_in_plain_text()
    {
        var client = _factory.Plain();
        var (_, token, _) = await _factory.SignUpAsync(client);

        var hashes = _factory.WithDb(db => db.Sessions.Select(s => s.TokenHash).ToList());
        Assert.DoesNotContain(token, hashes);
        Assert.Contains(Ids.Sha256Hex(token), hashes);
    }

    [Fact]
    public async Task GetSession_is_null_without_credentials_and_returns_the_user_with_a_cookie()
    {
        var browser = _factory.Browser();
        var anonymous = await browser.GetAsync("/api/auth/get-session");
        Assert.Equal(HttpStatusCode.OK, anonymous.StatusCode);
        Assert.Equal("null", (await anonymous.Content.ReadAsStringAsync()).Trim());

        var (email, _, _) = await _factory.SignUpAsync(browser);
        var session = await ReadJsonAsync(await browser.GetAsync("/api/auth/get-session"));
        Assert.Equal(email, session.GetProperty("user").GetProperty("email").GetString());
    }

    [Fact]
    public async Task A_cookie_with_a_forged_signature_is_not_a_session()
    {
        var client = _factory.Plain();
        var (_, token, _) = await _factory.SignUpAsync(client);

        var forged = new HttpRequestMessage(HttpMethod.Get, "/v1/me");
        forged.Headers.Add("Cookie", $"openwork-den.session_token={token}.AAAAforgedsignatureAAAA");
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(forged)).StatusCode);

        var unsigned = new HttpRequestMessage(HttpMethod.Get, "/v1/me");
        unsigned.Headers.Add("Cookie", $"openwork-den.session_token={token}");
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(unsigned)).StatusCode);
    }

    [Fact]
    public async Task SignOut_revokes_the_bearer_and_the_cookie_session()
    {
        var browser = _factory.Browser();
        var (_, token, _) = await _factory.SignUpAsync(browser);

        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/v1/me")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await browser.PostAsJsonAsync("/api/auth/sign-out", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await browser.GetAsync("/v1/me")).StatusCode);
        // The cookie and the bearer were the same session, so the bearer is dead too.
        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.Plain().SendAsync(Bearer(HttpMethod.Get, "/v1/me", token))).StatusCode);
    }

    [Fact]
    public async Task Refused_mutations_are_403_and_unknown_auth_paths_are_404()
    {
        var client = _factory.Plain();
        foreach (var path in new[] { "/organization/update", "/organization/invite-member", "/api-key/create", "/sso/register", "/device/approve", "/scim/generate-token" })
        {
            var response = await client.PostAsJsonAsync("/api/auth" + path, new { });
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Equal("forbidden", (await ReadJsonAsync(response)).GetProperty("error").GetString());
        }
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/api/auth/definitely-not-a-route")).StatusCode);
    }

    [Fact]
    public async Task Password_reset_request_does_not_reveal_whether_the_account_exists()
    {
        var client = _factory.Plain();
        var (email, _, _) = await _factory.SignUpAsync(client);
        var known = await client.PostAsJsonAsync("/api/auth/request-password-reset", new { email, redirectTo = "http://localhost/reset" });
        var unknown = await client.PostAsJsonAsync("/api/auth/request-password-reset", new { email = NewEmail("nobody"), redirectTo = "http://localhost/reset" });
        Assert.Equal(known.StatusCode, unknown.StatusCode);
        Assert.Equal(await known.Content.ReadAsStringAsync(), await unknown.Content.ReadAsStringAsync());
    }

    [Fact]
    public void Ids_follow_the_typeid_format_and_sort_by_creation_time()
    {
        var ids = Enumerable.Range(0, 50).Select(_ => { Thread.Sleep(1); return Ids.New("org"); }).ToList();
        Assert.All(ids, id => Assert.Matches(new Regex(@"^org_[0-7][0-9a-hjkmnp-tv-z]{25}$"), id));
        Assert.Equal(ids.OrderBy(i => i, StringComparer.Ordinal).ToList(), ids);
    }

    [Theory]
    [InlineData("Short1!", "password_too_short")]
    [InlineData("abc12345", "password_missing_uppercase")]
    [InlineData("alllowercaseletters", "password_missing_uppercase")]
    [InlineData("UPPERCASE123!", "password_missing_lowercase")]
    [InlineData("Password1234", "password_missing_special_character")]
    [InlineData("Password!!!!", "password_missing_digit")]
    [InlineData("Str0ng!Passw0rd#2026x", null)]
    [InlineData("Correct-horse-battery-staple-9", null)]
    public void Password_policy_reports_the_first_rule_broken_with_the_reference_codes(string password, string? expectedError) =>
        Assert.Equal(expectedError, Passwords.Validate(password)?.Error);

    [Fact]
    public void Password_policy_has_a_maximum_but_a_roomier_one_than_the_reference()
    {
        Assert.Null(Passwords.Validate("Aa1!" + new string('x', 60)));
        Assert.Equal("password_too_long", Passwords.Validate("Aa1!" + new string('x', 125))?.Error);
    }

    [Fact]
    public void Password_hashes_verify_and_are_salted()
    {
        var a = Passwords.Hash("Str0ng!Passw0rd#2026x");
        var b = Passwords.Hash("Str0ng!Passw0rd#2026x");
        Assert.NotEqual(a, b);
        Assert.True(Passwords.Verify("Str0ng!Passw0rd#2026x", a));
        Assert.False(Passwords.Verify("wrong", a));
        Assert.False(Passwords.Verify("anything", "not-a-hash"));
    }
}
