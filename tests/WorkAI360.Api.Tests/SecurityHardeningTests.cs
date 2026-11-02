using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using WorkAI360.Api.Auth;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

public sealed class SecurityHardeningTests : IClassFixture<ApiFactory>
{
    private readonly ApiFactory _factory;
    public SecurityHardeningTests(ApiFactory factory) => _factory = factory;

    // ----- headers -----------------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task Responses_cannot_be_framed_or_sniffed()
    {
        var response = await _factory.Plain().GetAsync("/api/auth/get-session");
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Equal("frame-ancestors 'none'", response.Headers.GetValues("Content-Security-Policy").Single());
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        // Development never pins itself to HTTPS.
        Assert.False(response.Headers.Contains("Strict-Transport-Security"));
    }

    [Fact]
    public async Task Error_responses_carry_the_headers_too()
    {
        var response = await _factory.Plain().GetAsync("/api/auth/nothing-here");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
    }

    // ----- a key per purpose ---------------------------------------------------------------------------------------------------------

    private static string Cookie(string token, byte[] key) => $"{token}.{Convert.ToBase64String(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(token)))}";

    private async Task<string?> SessionUserAsync(string token, byte[] key)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, "/api/auth/get-session");
        request.Headers.Add("Cookie", "openwork-den.session_token=" + Uri.EscapeDataString(Cookie(token, key)));
        var body = await _factory.Plain().SendAsync(request);
        var text = await body.Content.ReadAsStringAsync();
        return text == "null" ? null : System.Text.Json.JsonDocument.Parse(text).RootElement.GetProperty("user").GetProperty("id").GetString();
    }

    [Fact]
    public async Task The_cookie_is_signed_with_its_own_key_not_the_raw_secret_or_another_purposes_key()
    {
        var (_, token, userId) = await _factory.SignUpAsync(_factory.Plain());

        Assert.Equal(userId, await SessionUserAsync(token, SecretKeys.Derive(Secret, "session cookie")));
        Assert.Null(await SessionUserAsync(token, Encoding.UTF8.GetBytes(Secret)));
        Assert.Null(await SessionUserAsync(token, SecretKeys.Derive(Secret, "audit cursor")));
        Assert.Null(await SessionUserAsync(token, SecretKeys.Derive(Secret, "brand asset url")));
    }

    [Fact]
    public void Keys_differ_by_purpose_and_by_secret()
    {
        Assert.NotEqual(SecretKeys.Derive(Secret, "a"), SecretKeys.Derive(Secret, "b"));
        Assert.NotEqual(SecretKeys.Derive(Secret, "a"), SecretKeys.Derive(Secret + "x", "a"));
        Assert.Equal(SecretKeys.Derive(Secret, "a"), SecretKeys.Derive(Secret, "a"));
        Assert.Equal(32, SecretKeys.Derive(Secret, "a").Length);
    }

    [Fact]
    public async Task Brand_links_signed_with_the_old_key_still_work_and_other_purposes_do_not()
    {
        var w = await Workspace.CreateAsync(_factory);
        var upload = await w.UploadAsync(w.Owner, ("logo", OrgAdminHelpers.Png(256, 64), "image/png"));
        Assert.Equal(HttpStatusCode.OK, upload.StatusCode);
        var logo = (await ReadJsonAsync(upload)).GetProperty("assets").GetProperty("logo");
        var url = new Uri(logo.GetProperty("url").GetString()!);
        var version = logo.GetProperty("version").GetString()!;
        var extension = logo.GetProperty("extension").GetString()!;

        static string Signature(byte[] key, string text) =>
            Convert.ToBase64String(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(text))).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var signed = string.Join('\0', w.OrgId, "logo", version, extension);

        // The link just issued uses the purpose key.
        Assert.Equal("?signature=" + Signature(SecretKeys.Derive(Secret, "brand asset url"), signed), url.Query);
        Assert.Equal(HttpStatusCode.OK, (await w.Http.GetAsync(url)).StatusCode);
        // A link stored before the change (signed with the secret itself) is still honoured.
        Assert.Equal(HttpStatusCode.OK, (await w.Http.GetAsync(url.AbsolutePath + "?signature=" + Signature(Encoding.UTF8.GetBytes(Secret), signed))).StatusCode);
        // A signature from another purpose's key is not.
        Assert.Equal(HttpStatusCode.NotFound, (await w.Http.GetAsync(url.AbsolutePath + "?signature=" + Signature(SecretKeys.Derive(Secret, "audit cursor"), signed))).StatusCode);
    }

    // ----- a damaged stored password hash --------------------------------------------------------------------------------------------

    [Theory]
    [InlineData("")]
    [InlineData("pbkdf2-sha256$210000$!!!notbase64$???")]
    [InlineData("pbkdf2-sha256$210000$AAAA$")]
    [InlineData("pbkdf2-sha256$0$AAAA$AAAA")]
    [InlineData("pbkdf2-sha256$-5$AAAA$AAAA")]
    [InlineData("pbkdf2-sha256$abc$AAAA$AAAA")]
    [InlineData("md5$1$AAAA$AAAA")]
    [InlineData("pbkdf2-sha256$210000$AAAA$AAAA$extra")]
    public void A_damaged_stored_hash_fails_verification_instead_of_throwing(string stored) =>
        Assert.False(Passwords.Verify(Password, stored));

    [Fact]
    public void A_good_hash_still_verifies()
    {
        var hash = Passwords.Hash(Password);
        Assert.True(Passwords.Verify(Password, hash));
        Assert.False(Passwords.Verify(Password + "x", hash));
    }

    [Fact]
    public async Task Signing_in_to_an_account_with_a_damaged_hash_is_a_normal_failure_not_a_server_error()
    {
        var client = _factory.Plain();
        var (email, _, userId) = await _factory.SignUpAsync(client);
        using (var scope = _factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<WorkAI360.Api.Data.DenDbContext>();
            await db.Users.Where(u => u.Id == userId).ExecuteUpdateAsync(s => s.SetProperty(u => u.PasswordHash, "pbkdf2-sha256$210000$!!!$???"));
        }
        var response = await client.PostAsJsonAsync("/api/auth/sign-in/email", new { email, password = Password });
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("INVALID_EMAIL_OR_PASSWORD", (await ReadJsonAsync(response)).GetProperty("code").GetString());
    }
}

public sealed class LoginThrottleTests
{
    private const string Email = "victim@example.com";

    [Fact]
    public void Failures_from_one_address_do_not_lock_the_account_for_other_addresses()
    {
        var throttle = new LoginThrottle();
        for (var i = 0; i < LoginThrottle.MaxFailuresPerAddress; i++) throttle.RecordFailure(Email, "203.0.113.9");

        Assert.NotNull(throttle.LockedFor(Email, "203.0.113.9"));
        Assert.Null(throttle.LockedFor(Email, "198.51.100.4"));
        Assert.Null(throttle.LockedFor("someone-else@example.com", "203.0.113.9"));
    }

    [Fact]
    public void Four_failures_do_not_lock()
    {
        var throttle = new LoginThrottle();
        for (var i = 0; i < LoginThrottle.MaxFailuresPerAddress - 1; i++) throttle.RecordFailure(Email, "203.0.113.9");
        Assert.Null(throttle.LockedFor(Email, "203.0.113.9"));
    }

    [Fact]
    public void Guessing_spread_over_many_addresses_hits_the_account_ceiling_and_locks_everyone()
    {
        var throttle = new LoginThrottle();
        // Never more than four from one address, so no address is locked, yet the account is under attack.
        for (var i = 0; i < LoginThrottle.MaxFailuresPerAccount; i++) throttle.RecordFailure(Email, $"192.0.2.{i % 250}.{i / 4}");

        Assert.NotNull(throttle.LockedFor(Email, "198.51.100.77"));
        Assert.Null(throttle.LockedFor("someone-else@example.com", "198.51.100.77"));
    }

    [Fact]
    public void A_password_reset_lifts_every_lock_on_the_account_but_not_on_others()
    {
        var throttle = new LoginThrottle();
        for (var i = 0; i < LoginThrottle.MaxFailuresPerAccount; i++) throttle.RecordFailure(Email, $"a{i}");
        for (var i = 0; i < LoginThrottle.MaxFailuresPerAddress; i++) throttle.RecordFailure("other@example.com", "203.0.113.9");
        Assert.NotNull(throttle.LockedFor(Email, "a1"));

        throttle.Reset(Email);

        Assert.Null(throttle.LockedFor(Email, "a1"));
        Assert.Null(throttle.LockedFor(Email, "new-address"));
        Assert.NotNull(throttle.LockedFor("other@example.com", "203.0.113.9"));
    }

    [Fact]
    public void A_successful_sign_in_clears_that_addresss_count_only()
    {
        var throttle = new LoginThrottle();
        for (var i = 0; i < LoginThrottle.MaxFailuresPerAddress - 1; i++) { throttle.RecordFailure(Email, "A"); throttle.RecordFailure(Email, "B"); }
        throttle.Succeeded(Email, "A");
        throttle.RecordFailure(Email, "A");
        throttle.RecordFailure(Email, "B");

        Assert.Null(throttle.LockedFor(Email, "A"));
        Assert.NotNull(throttle.LockedFor(Email, "B"));
    }

    [Fact]
    public void An_address_that_contains_the_separator_cannot_reach_another_accounts_entries()
    {
        var throttle = new LoginThrottle();
        // "a@x.com" + NUL + "1" must not be confusable with the account "a@x.com" and the address "1" (or with a longer email).
        for (var i = 0; i < LoginThrottle.MaxFailuresPerAddress; i++) throttle.RecordFailure("a@x.com", "1");
        Assert.Null(throttle.LockedFor("a@x.com", "2"));
        Assert.Null(throttle.LockedFor("a@x.com\01", "x"));
    }
}

public sealed class SignInLockoutTests : IClassFixture<SignInLockoutTests.LimitsOn>
{
    public sealed class LimitsOn : ApiFactory
    {
        protected override IEnumerable<KeyValuePair<string, string>> Settings => [new("Auth:RateLimitsEnabled", "true")];
    }

    private readonly LimitsOn _factory;
    public SignInLockoutTests(LimitsOn factory) => _factory = factory;

    // The test host gives every caller the same address, so what is checked here is that, with the rate limits on, the lockout still comes from the
    // fifth wrong password (not earlier), is a 429 and never a 500, and leaves other accounts alone. That different addresses do not affect each other
    // is covered by LoginThrottleTests, which can name addresses.
    [Fact]
    public async Task Five_wrong_passwords_lock_that_account_for_that_address_and_nothing_else()
    {
        var client = _factory.Plain();
        var (email, _, _) = await _factory.SignUpAsync(client);
        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < 7; i++) statuses.Add((await client.PostAsJsonAsync("/api/auth/sign-in/email", new { email, password = "Wrong!Passw0rd#999" })).StatusCode);

        Assert.All(statuses.Take(5), s => Assert.Equal(HttpStatusCode.Unauthorized, s));
        Assert.All(statuses.Skip(5), s => Assert.Equal((HttpStatusCode)429, s));

        var (other, _, _) = await _factory.SignUpAsync(client);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/auth/sign-in/email", new { email = other, password = Password })).StatusCode);
    }
}
