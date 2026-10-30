using System.Net;
using Microsoft.AspNetCore.Builder;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Email;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

public sealed class VerificationFactory : ApiFactory
{
    protected override IEnumerable<KeyValuePair<string, string>> Settings => [new("Auth:RequireEmailVerification", "true")];
}

public sealed class RateLimitedFactory : ApiFactory
{
    protected override IEnumerable<KeyValuePair<string, string>> Settings => [new("Auth:RateLimitsEnabled", "true")];
}

internal static class Mail
{
    public static string[] CodesFor(DevOutbox outbox, string email) =>
        outbox.To(email).Where(m => m.Message.Subject.StartsWith("Your OpenWork verification code")).Select(m => Regex.Match(m.Message.Subject, @"\d{6}$").Value).ToArray();

    public static string LastCode(DevOutbox outbox, string email) => CodesFor(outbox, email).Last();

    public static string LastResetToken(DevOutbox outbox, string email) =>
        Regex.Match(outbox.To(email).Last(m => m.Message.Subject.StartsWith("Reset your")).Message.Text, @"/api/auth/reset-password/([A-Za-z0-9]{32})").Groups[1].Value;
}

public sealed class VerificationTests : IClassFixture<VerificationFactory>
{
    private readonly VerificationFactory _factory;
    public VerificationTests(VerificationFactory factory) => _factory = factory;

    private async Task<(string Email, HttpClient Client)> NewUnverifiedAsync()
    {
        var client = _factory.Plain();
        var email = NewEmail("verify");
        var response = await client.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "Vera", email, password = Password });
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (email, client);
    }

    private static Task<HttpResponseMessage> VerifyAsync(HttpClient client, string email, string otp) =>
        client.PostAsJsonAsync("/api/auth/email-otp/verify-email", new { email, otp });

    private static async Task<string?> CodeOf(HttpResponseMessage response) => (await ReadJsonAsync(response)).GetProperty("code").GetString();

    [Fact]
    public async Task Sign_up_creates_an_unverified_account_without_a_session_and_mails_a_code()
    {
        var client = _factory.Plain();
        var email = NewEmail("verify");
        var response = await client.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "Vera", email, password = Password });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(response.Headers.Contains("Set-Cookie"));
        var json = await ReadJsonAsync(response);
        Assert.Equal(JsonValueKindNull, json.GetProperty("token").ValueKind.ToString());
        Assert.False(json.GetProperty("user").GetProperty("emailVerified").GetBoolean());

        var mails = _factory.Outbox.To(email);
        Assert.Single(mails);
        Assert.Matches(@"^Your OpenWork verification code is \d{6}$", mails[0].Message.Subject);
        Assert.Contains("10 minutes", mails[0].Message.Text);
        Assert.Contains("<html", mails[0].Message.Html);
    }

    private const string JsonValueKindNull = "Null";

    [Fact]
    public async Task Sign_in_is_refused_until_verified_but_only_after_the_password_is_right()
    {
        var (email, client) = await NewUnverifiedAsync();

        var wrong = await client.PostAsJsonAsync("/api/auth/sign-in/email", new { email, password = "Wrong!Passw0rd#999" });
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        Assert.Equal("INVALID_EMAIL_OR_PASSWORD", await CodeOf(wrong));

        var right = await client.PostAsJsonAsync("/api/auth/sign-in/email", new { email, password = Password });
        Assert.Equal(HttpStatusCode.Forbidden, right.StatusCode);
        Assert.False(right.Headers.Contains("Set-Cookie"));
        Assert.Equal("EMAIL_NOT_VERIFIED", await CodeOf(right));
        Assert.Equal("Email not verified", (await ReadJsonAsync(right)).GetProperty("message").GetString());
    }

    [Fact]
    public async Task The_right_code_verifies_once_and_then_sign_in_works()
    {
        var (email, client) = await NewUnverifiedAsync();
        var code = Mail.LastCode(_factory.Outbox, email);

        var verified = await VerifyAsync(client, email.ToUpperInvariant(), $" {code} ");   // address case and padding do not matter
        Assert.Equal(HttpStatusCode.OK, verified.StatusCode);
        Assert.False(verified.Headers.Contains("Set-Cookie")); // verifying proves the inbox; it does not sign anyone in
        var json = await ReadJsonAsync(verified);
        Assert.True(json.GetProperty("status").GetBoolean());
        Assert.Equal(System.Text.Json.JsonValueKind.Null, json.GetProperty("token").ValueKind);
        Assert.True(json.GetProperty("user").GetProperty("emailVerified").GetBoolean());

        var again = await VerifyAsync(client, email, code);
        Assert.Equal(HttpStatusCode.BadRequest, again.StatusCode);
        Assert.Equal("INVALID_OTP", await CodeOf(again));

        var signIn = await client.PostAsJsonAsync("/api/auth/sign-in/email", new { email, password = Password });
        Assert.Equal(HttpStatusCode.OK, signIn.StatusCode);
        Assert.Equal(32, (await ReadJsonAsync(signIn)).GetProperty("token").GetString()!.Length);
    }

    [Fact]
    public async Task Wrong_codes_are_refused_and_the_sixth_attempt_is_blocked_even_with_the_right_code()
    {
        var (email, client) = await NewUnverifiedAsync();
        var code = Mail.LastCode(_factory.Outbox, email);
        var wrong = code == "000000" ? "111111" : "000000";

        for (var i = 1; i <= 5; i++)
        {
            var response = await VerifyAsync(client, email, wrong);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Equal("INVALID_OTP", await CodeOf(response));
        }
        var blocked = await VerifyAsync(client, email, code);
        Assert.Equal(HttpStatusCode.Forbidden, blocked.StatusCode);
        Assert.Equal("TOO_MANY_ATTEMPTS", await CodeOf(blocked));

        // The code is gone; a fresh one is needed.
        Assert.Equal("INVALID_OTP", await CodeOf(await VerifyAsync(client, email, code)));
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/auth/email-otp/send-verification-otp", new { email, type = "email-verification" })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await VerifyAsync(client, email, Mail.LastCode(_factory.Outbox, email))).StatusCode);
    }

    [Fact]
    public async Task Parallel_guessing_cannot_get_more_than_five_attempts()
    {
        // Thirty concurrent guesses, the correct code last. If every guess were evaluated the correct one would always win.
        // With a budget of five it can only win when scheduling happens to put it among the first five, which is rare.
        var wins = 0;
        for (var trial = 0; trial < 12; trial++)
        {
            var (email, client) = await NewUnverifiedAsync();
            var correct = Mail.LastCode(_factory.Outbox, email);
            var guesses = Enumerable.Range(0, 1000).Select(n => n.ToString("D6")).Where(c => c != correct).Take(29).Append(correct).ToList();
            var results = await Task.WhenAll(guesses.Select(g => VerifyAsync(client, email, g)));
            if (results.Any(r => r.StatusCode == HttpStatusCode.OK)) wins++;
        }
        Assert.True(wins <= 3, $"the correct code won {wins} of 12 races; the five-attempt budget is not holding");
    }

    [Fact]
    public async Task An_expired_code_says_so_and_a_new_code_replaces_the_old_one()
    {
        var (email, client) = await NewUnverifiedAsync();
        var first = Mail.LastCode(_factory.Outbox, email);

        _factory.WithDb(db => db.Database.ExecuteSqlRaw("UPDATE EmailOtps SET ExpiresAt = {0} WHERE Email = {1}", DateTime.UtcNow.AddMinutes(-1), email));
        var expired = await VerifyAsync(client, email, first);
        Assert.Equal(HttpStatusCode.BadRequest, expired.StatusCode);
        Assert.Equal("OTP_EXPIRED", await CodeOf(expired));

        // Asking for another code invalidates the previous one, even if that was still valid.
        await client.PostAsJsonAsync("/api/auth/email-otp/send-verification-otp", new { email, type = "email-verification" });
        var second = Mail.LastCode(_factory.Outbox, email);
        await client.PostAsJsonAsync("/api/auth/email-otp/send-verification-otp", new { email, type = "email-verification" });
        var third = Mail.LastCode(_factory.Outbox, email);
        if (second != third) Assert.Equal("INVALID_OTP", await CodeOf(await VerifyAsync(client, email, second)));
        Assert.Equal(HttpStatusCode.OK, (await VerifyAsync(client, email, third)).StatusCode);
    }

    [Fact]
    public async Task Signing_in_while_unverified_sends_a_fresh_code_that_replaces_the_old_one()
    {
        var (email, client) = await NewUnverifiedAsync();
        var signUpCode = Mail.LastCode(_factory.Outbox, email);
        await client.PostAsJsonAsync("/api/auth/sign-in/email", new { email, password = Password });
        var signInCode = Mail.LastCode(_factory.Outbox, email);
        Assert.Equal(2, Mail.CodesFor(_factory.Outbox, email).Length);

        if (signUpCode != signInCode) Assert.Equal("INVALID_OTP", await CodeOf(await VerifyAsync(client, email, signUpCode)));
        Assert.Equal(HttpStatusCode.OK, (await VerifyAsync(client, email, signInCode)).StatusCode);
    }

    [Fact]
    public async Task Requesting_a_code_never_reveals_whether_an_account_exists_and_only_mails_unverified_ones()
    {
        var (email, client) = await NewUnverifiedAsync();
        var before = _factory.Outbox.To(email).Count;
        var unknown = NewEmail("ghost");

        var known = await client.PostAsJsonAsync("/api/auth/email-otp/send-verification-otp", new { email, type = "email-verification" });
        var ghost = await client.PostAsJsonAsync("/api/auth/email-otp/send-verification-otp", new { email = unknown, type = "email-verification" });
        Assert.Equal(await known.Content.ReadAsStringAsync(), await ghost.Content.ReadAsStringAsync());
        Assert.Equal("""{"success":true}""", await ghost.Content.ReadAsStringAsync());
        Assert.Equal(before + 1, _factory.Outbox.To(email).Count);
        Assert.Empty(_factory.Outbox.To(unknown));

        await VerifyAsync(client, email, Mail.LastCode(_factory.Outbox, email));
        var after = _factory.Outbox.To(email).Count;
        await client.PostAsJsonAsync("/api/auth/email-otp/send-verification-otp", new { email, type = "email-verification" });
        Assert.Equal(after, _factory.Outbox.To(email).Count); // already verified: nothing to send
    }

    [Fact]
    public async Task Bad_requests_get_the_reference_validation_messages()
    {
        var client = _factory.Plain();
        async Task<(HttpStatusCode, string?, string?)> Send(string path, object body)
        {
            var r = await client.PostAsJsonAsync(path, body);
            var j = await ReadJsonAsync(r);
            return (r.StatusCode, j.GetProperty("message").GetString(), j.GetProperty("code").GetString());
        }
        var badType = await Send("/api/auth/email-otp/send-verification-otp", new { email = "a@b.co", type = "nope" });
        Assert.Equal(HttpStatusCode.BadRequest, badType.Item1);
        Assert.Equal("[body.type] Invalid option: expected one of \"email-verification\"|\"sign-in\"|\"forget-password\"|\"change-email\"", badType.Item2);
        Assert.Equal("VALIDATION_ERROR", badType.Item3);
        Assert.Equal("INVALID_EMAIL", (await Send("/api/auth/email-otp/send-verification-otp", new { email = "nope", type = "email-verification" })).Item3);
        Assert.Equal("INVALID_EMAIL", (await Send("/api/auth/email-otp/verify-email", new { email = "nope", otp = "123456" })).Item3);
        Assert.Equal("[body.otp] Invalid input: expected string, received undefined", (await Send("/api/auth/email-otp/verify-email", new { email = "a@b.co" })).Item2);
        Assert.Equal("UNSUPPORTED_OTP_TYPE", (await Send("/api/auth/email-otp/send-verification-otp", new { email = "a@b.co", type = "sign-in" })).Item3);
        Assert.Equal("INVALID_OTP", (await Send("/api/auth/email-otp/verify-email", new { email = NewEmail("ghost"), otp = "123456" })).Item3);
    }

    [Fact]
    public async Task Codes_are_stored_only_as_keyed_hashes()
    {
        var (email, _) = await NewUnverifiedAsync();
        var code = Mail.LastCode(_factory.Outbox, email);
        var stored = _factory.WithDb(db => db.EmailOtps.Where(o => o.Email == email).Select(o => o.CodeHash).ToList());
        Assert.Single(stored);
        Assert.DoesNotContain(code, stored[0]);
        Assert.Equal(64, stored[0].Length);
    }

    [Fact]
    public async Task A_mail_outage_does_not_break_sign_up_or_reveal_anything()
    {
        await using var broken = new VerificationFactory().WithWebHostBuilder(b => b.ConfigureServices(s =>
        {
            s.RemoveAll<IEmailSender>();
            s.AddSingleton<IEmailSender, ThrowingSender>();
        }));
        var client = broken.CreateClient();
        var email = NewEmail("outage");
        var signUp = await client.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "O", email, password = Password });
        Assert.Equal(HttpStatusCode.OK, signUp.StatusCode);
        var send = await client.PostAsJsonAsync("/api/auth/email-otp/send-verification-otp", new { email, type = "email-verification" });
        Assert.Equal(HttpStatusCode.OK, send.StatusCode);
        var reset = await client.PostAsJsonAsync("/api/auth/request-password-reset", new { email });
        Assert.Equal(HttpStatusCode.OK, reset.StatusCode);
    }

    private sealed class ThrowingSender : IEmailSender
    {
        public Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default) => throw new IOException("smtp down");
    }
}

public sealed class PasswordResetTests : IClassFixture<ApiFactory>
{
    private readonly ApiFactory _factory;
    public PasswordResetTests(ApiFactory factory) => _factory = factory;

    private async Task<(string Email, HttpClient Client, string Token)> AccountAsync()
    {
        var client = _factory.Plain();
        var (email, token, _) = await _factory.SignUpAsync(client);
        return (email, client, token);
    }

    private static Task<HttpResponseMessage> Request(HttpClient c, string email, string? redirectTo = "http://localhost/reset-password") =>
        c.PostAsJsonAsync("/api/auth/request-password-reset", new { email, redirectTo });

    private static Task<HttpResponseMessage> Reset(HttpClient c, string token, string password = "N3w!Passw0rd#2026y") =>
        c.PostAsJsonAsync("/api/auth/reset-password", new { newPassword = password, token });

    [Fact]
    public async Task A_request_looks_the_same_for_known_and_unknown_addresses_and_only_mails_real_accounts()
    {
        var (email, client, _) = await AccountAsync();
        var ghost = NewEmail("ghost");
        var known = await Request(client, email);
        var unknown = await Request(client, ghost);

        Assert.Equal(HttpStatusCode.OK, known.StatusCode);
        Assert.Equal(await known.Content.ReadAsStringAsync(), await unknown.Content.ReadAsStringAsync());
        Assert.Equal("""{"status":true,"message":"If this email exists in our system, check your email for the reset link"}""", await unknown.Content.ReadAsStringAsync());
        Assert.Empty(_factory.Outbox.To(ghost));

        var mail = _factory.Outbox.To(email).Single().Message;
        Assert.Equal("Reset your OpenWork password", mail.Subject);
        Assert.Matches(@"http://localhost/api/auth/reset-password/[A-Za-z0-9]{32}\?callbackURL=http%3A%2F%2Flocalhost%2Freset-password", mail.Text);
        Assert.Contains("1 hour", mail.Text);
        Assert.Contains("<a href=\"http://localhost/api/auth/reset-password/", mail.Html);
    }

    [Fact]
    public async Task Redirect_targets_must_be_this_site()
    {
        var (email, client, _) = await AccountAsync();
        foreach (var bad in new[] { "https://evil.example/reset", "http://localhost@evil.example/", "//evil.example/x", "https://localhost.evil.example/", "javascript:alert(1)", "/\\evil.example", "http://localhost:81/reset" })
        {
            var response = await Request(client, email, bad);
            Assert.True(response.StatusCode == HttpStatusCode.Forbidden, $"{bad} was accepted");
            Assert.Equal("INVALID_REDIRECT_URL", (await ReadJsonAsync(response)).GetProperty("code").GetString());
        }
        Assert.Empty(_factory.Outbox.To(email));
        Assert.Equal(HttpStatusCode.OK, (await Request(client, email, "/reset-password")).StatusCode);   // a path on this site
        Assert.Equal(HttpStatusCode.OK, (await Request(client, email, null)).StatusCode);                  // none at all
        Assert.Equal(HttpStatusCode.BadRequest, (await Request(client, "not-an-email")).StatusCode);
    }

    [Fact]
    public async Task The_emailed_link_validates_the_token_and_redirects_without_changing_anything()
    {
        var (email, client, _) = await AccountAsync();
        await Request(client, email);
        var token = Mail.LastResetToken(_factory.Outbox, email);

        var link = $"/api/auth/reset-password/{token}?callbackURL={Uri.EscapeDataString("http://localhost/reset-password")}";
        for (var i = 0; i < 2; i++) // visiting the link does not use it up
        {
            var response = await client.GetAsync(link);
            Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
            Assert.Equal($"http://localhost/reset-password?token={token}", response.Headers.Location!.ToString());
        }
        var bogus = await client.GetAsync($"/api/auth/reset-password/not-a-real-token?callbackURL={Uri.EscapeDataString("http://localhost/reset-password")}");
        Assert.Equal("http://localhost/reset-password?error=INVALID_TOKEN", bogus.Headers.Location!.ToString());
        var foreign = await client.GetAsync($"/api/auth/reset-password/{token}?callbackURL={Uri.EscapeDataString("https://evil.example/x")}");
        Assert.Equal(HttpStatusCode.Forbidden, foreign.StatusCode);
        Assert.Equal("INVALID_CALLBACK_URL", (await ReadJsonAsync(foreign)).GetProperty("code").GetString());
        var noCallback = await client.GetAsync($"/api/auth/reset-password/{token}");
        Assert.Equal($"http://localhost/reset-password?token={token}", noCallback.Headers.Location!.ToString());
    }

    [Fact]
    public async Task Resetting_changes_the_password_signs_everything_out_and_works_only_once()
    {
        var (email, client, oldSession) = await AccountAsync();
        var otherDevice = (await ReadJsonAsync(await client.PostAsJsonAsync("/api/auth/sign-in/email", new { email, password = Password }))).GetProperty("token").GetString()!;
        await Request(client, email);
        var token = Mail.LastResetToken(_factory.Outbox, email);

        var done = await Reset(client, token);
        Assert.Equal(HttpStatusCode.OK, done.StatusCode);
        Assert.True((await ReadJsonAsync(done)).GetProperty("status").GetBoolean());

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/api/auth/sign-in/email", new { email, password = Password })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/auth/sign-in/email", new { email, password = "N3w!Passw0rd#2026y" })).StatusCode);
        foreach (var session in new[] { oldSession, otherDevice })
            Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(Bearer(HttpMethod.Get, "/v1/me", session))).StatusCode);

        var replay = await Reset(client, token, "An0ther!Passw0rd#9");
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);
        Assert.Equal("INVALID_TOKEN", (await ReadJsonAsync(replay)).GetProperty("code").GetString());
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/auth/sign-in/email", new { email, password = "N3w!Passw0rd#2026y" })).StatusCode);
    }

    [Fact]
    public async Task The_password_rules_apply_first_and_bad_or_expired_tokens_are_refused()
    {
        var (email, client, _) = await AccountAsync();
        var weakWithBogusToken = await Reset(client, "bogus", "abc12345");
        Assert.Equal(HttpStatusCode.BadRequest, weakWithBogusToken.StatusCode);
        Assert.Equal("password_missing_uppercase", (await ReadJsonAsync(weakWithBogusToken)).GetProperty("error").GetString());
        Assert.Equal("INVALID_TOKEN", (await ReadJsonAsync(await Reset(client, "bogus"))).GetProperty("code").GetString());
        Assert.Equal("INVALID_TOKEN", (await ReadJsonAsync(await client.PostAsJsonAsync("/api/auth/reset-password", new { newPassword = "N3w!Passw0rd#2026y" }))).GetProperty("code").GetString());

        await Request(client, email);
        var token = Mail.LastResetToken(_factory.Outbox, email);
        var weak = await Reset(client, token, "alllowercase1!");
        Assert.Equal(HttpStatusCode.BadRequest, weak.StatusCode);
        // A refused password does not use the link up.
        _factory.WithDb(db => db.Database.ExecuteSqlRaw("UPDATE PasswordResetTokens SET ExpiresAt = {0} WHERE Id = {1}", DateTime.UtcNow.AddMinutes(-1), Ids.Sha256Hex(token)));
        var expired = await Reset(client, token);
        Assert.Equal("INVALID_TOKEN", (await ReadJsonAsync(expired)).GetProperty("code").GetString());
        Assert.Equal("http://localhost/reset-password?error=INVALID_TOKEN", (await client.GetAsync($"/api/auth/reset-password/{token}?callbackURL={Uri.EscapeDataString("http://localhost/reset-password")}")).Headers.Location!.ToString());
    }

    [Fact]
    public async Task A_newer_link_replaces_the_older_one_and_tokens_are_stored_hashed()
    {
        var (email, client, _) = await AccountAsync();
        await Request(client, email);
        var first = Mail.LastResetToken(_factory.Outbox, email);
        await Request(client, email);
        var second = Mail.LastResetToken(_factory.Outbox, email);

        Assert.NotEqual(first, second);
        Assert.Equal("INVALID_TOKEN", (await ReadJsonAsync(await Reset(client, first))).GetProperty("code").GetString());
        Assert.DoesNotContain(second, _factory.WithDb(db => db.PasswordResetTokens.Select(t => t.Id).ToList()));
        Assert.Equal(HttpStatusCode.OK, (await Reset(client, second)).StatusCode);
    }

    [Fact]
    public async Task Concurrent_resets_with_one_link_succeed_exactly_once()
    {
        var (email, client, _) = await AccountAsync();
        await Request(client, email);
        var token = Mail.LastResetToken(_factory.Outbox, email);
        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(i => Reset(client, token, $"N3w!Passw0rd#{i}x")));
        Assert.Equal(1, results.Count(r => r.StatusCode == HttpStatusCode.OK));
        Assert.Equal(7, results.Count(r => r.StatusCode == HttpStatusCode.BadRequest));
    }

    [Fact]
    public async Task A_reset_lifts_a_sign_in_lockout()
    {
        var (email, client, _) = await AccountAsync();
        for (var i = 0; i < 6; i++) await client.PostAsJsonAsync("/api/auth/sign-in/email", new { email, password = "Wrong!Passw0rd#999" });
        Assert.Equal((HttpStatusCode)429, (await client.PostAsJsonAsync("/api/auth/sign-in/email", new { email, password = Password })).StatusCode);

        await Request(client, email);
        await Reset(client, Mail.LastResetToken(_factory.Outbox, email));
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/auth/sign-in/email", new { email, password = "N3w!Passw0rd#2026y" })).StatusCode);
    }
}

public sealed class RateLimitTests : IClassFixture<RateLimitedFactory>
{
    private readonly RateLimitedFactory _factory;
    public RateLimitTests(RateLimitedFactory factory) => _factory = factory;

    private static async Task AssertLimitedAfterAsync(int allowed, Func<Task<HttpResponseMessage>> call)
    {
        for (var i = 1; i <= allowed; i++) Assert.NotEqual((HttpStatusCode)429, (await call()).StatusCode);
        var limited = await call();
        Assert.Equal((HttpStatusCode)429, limited.StatusCode);
        Assert.True(int.Parse(limited.Headers.GetValues("Retry-After").Single()) > 0);
        Assert.Equal("rate_limited", (await ReadJsonAsync(limited)).GetProperty("error").GetString());
    }

    [Fact]
    public async Task Each_email_endpoint_limits_one_address_without_affecting_others()
    {
        var client = _factory.Plain();
        var a = NewEmail("rl-a"); var b = NewEmail("rl-b"); var c = NewEmail("rl-c"); var d = NewEmail("rl-d");

        await AssertLimitedAfterAsync(5, () => client.PostAsJsonAsync("/api/auth/email-otp/send-verification-otp", new { email = a, type = "email-verification" }));
        await AssertLimitedAfterAsync(5, () => client.PostAsJsonAsync("/api/auth/request-password-reset", new { email = b }));
        await AssertLimitedAfterAsync(10, () => client.PostAsJsonAsync("/api/auth/email-otp/verify-email", new { email = c, otp = "123456" }));
        await AssertLimitedAfterAsync(5, () => client.PostAsJsonAsync("/api/auth/sign-up/email", new { name = "X", email = d, password = Password }));

        // Another address is untouched, and so are the endpoints this one did not use.
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/auth/email-otp/send-verification-otp", new { email = NewEmail("fresh"), type = "email-verification" })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/auth/request-password-reset", new { email = a })).StatusCode);
    }

    [Fact]
    public async Task Sign_in_is_limited_per_address()
    {
        var client = _factory.Plain();
        var (email, _, _) = await _factory.SignUpAsync(client);
        await AssertLimitedAfterAsync(10, () => client.PostAsJsonAsync("/api/auth/sign-in/email", new { email, password = Password }));
    }
}

/// <summary>The in-memory test server gives callers no remote address; this stamps one on, as a real connection would have.</summary>
internal sealed class RemoteIpFilter(string ip) : Microsoft.AspNetCore.Hosting.IStartupFilter
{
    public Action<Microsoft.AspNetCore.Builder.IApplicationBuilder> Configure(Action<Microsoft.AspNetCore.Builder.IApplicationBuilder> next) => app =>
    {
        app.Use((context, nextMiddleware) => { context.Connection.RemoteIpAddress = IPAddress.Parse(ip); return nextMiddleware(context); });
        next(app);
    };
}

/// <summary>Calls arrive from 127.0.0.1, which is the default trusted proxy: this is the web host in front of the API.</summary>
public sealed class TrustedCallerFactory : ApiFactory
{
    protected override void ConfigureWebHost(Microsoft.AspNetCore.Hosting.IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureServices(s => s.AddTransient<Microsoft.AspNetCore.Hosting.IStartupFilter>(_ => new RemoteIpFilter("127.0.0.1")));
    }
}

/// <summary>Calls arrive from 127.0.0.1 but only 10.9.9.9 is a trusted proxy, so the caller is not one.</summary>
public sealed class UntrustedCallerFactory : ApiFactory
{
    protected override IEnumerable<KeyValuePair<string, string>> Settings => [new("Auth:TrustedProxies:0", "10.9.9.9")];

    protected override void ConfigureWebHost(Microsoft.AspNetCore.Hosting.IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureServices(s => s.AddTransient<Microsoft.AspNetCore.Hosting.IStartupFilter>(_ => new RemoteIpFilter("127.0.0.1")));
    }
}

public sealed class ForwardedHeaderTests : IClassFixture<UntrustedCallerFactory>, IClassFixture<TrustedCallerFactory>, IClassFixture<ApiFactory>
{
    private readonly UntrustedCallerFactory _untrusted;
    private readonly TrustedCallerFactory _trusted;
    private readonly ApiFactory _anonymous;
    public ForwardedHeaderTests(UntrustedCallerFactory untrusted, TrustedCallerFactory trusted, ApiFactory anonymous) { _untrusted = untrusted; _trusted = trusted; _anonymous = anonymous; }

    private static async Task<(string DenBaseUrl, string VerificationUri)> LinksAsync(ApiFactory factory, string host, bool withForwardedFor)
    {
        var client = factory.Plain();
        var (_, token, _) = await factory.SignUpAsync(client);
        void Spoof(HttpRequestMessage request)
        {
            request.Headers.Add("X-Forwarded-Host", host);
            request.Headers.Add("X-Forwarded-Proto", "https");
            if (withForwardedFor) request.Headers.Add("X-Forwarded-For", "203.0.113.7");
        }
        var handoff = Bearer(HttpMethod.Post, "/v1/auth/desktop-handoff", token, new { desktopScheme = "openwork" });
        Spoof(handoff);
        var open = (await ReadJsonAsync(await client.SendAsync(handoff))).GetProperty("openworkUrl").GetString()!;

        var device = new HttpRequestMessage(HttpMethod.Post, "/api/auth/device/code") { Content = JsonContent.Create(new { client_id = "openwork-cli" }) };
        Spoof(device);
        var verification = (await ReadJsonAsync(await client.SendAsync(device))).GetProperty("verification_uri").GetString()!;
        return (Uri.UnescapeDataString(open), verification);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)] // with X-Forwarded-For too: the framework middleware alone only checks the caller when that header is present
    public async Task Forwarding_headers_from_a_caller_that_is_not_a_trusted_proxy_cannot_choose_the_origin_in_links(bool withForwardedFor)
    {
        foreach (var factory in new ApiFactory[] { _untrusted, _anonymous })
        {
            var (open, verification) = await LinksAsync(factory, "evil.example", withForwardedFor);
            Assert.DoesNotContain("evil.example", open);
            Assert.EndsWith("denBaseUrl=http://localhost/api/den", open);
            Assert.Equal("http://localhost/device", verification);
        }
    }

    [Fact]
    public async Task The_configured_proxy_is_believed_so_the_web_hosts_origin_reaches_the_links()
    {
        var (open, verification) = await LinksAsync(_trusted, "app.example.com", withForwardedFor: true);
        Assert.EndsWith("denBaseUrl=https://app.example.com/api/den", open);
        Assert.Equal("https://app.example.com/device", verification);
    }
}

public sealed class SmtpTests
{
    [Fact]
    public async Task The_SMTP_sender_delivers_a_real_multipart_message()
    {
        using var server = new FakeSmtpServer();
        var options = Options.Create(new EmailOptions { Provider = "smtp", From = "OpenWork <no-reply@example.com>", Smtp = new() { Host = "127.0.0.1", Port = server.Port, Security = "none" } });
        var sender = new SmtpEmailSender(options, Microsoft.Extensions.Logging.Abstractions.NullLogger<SmtpEmailSender>.Instance);

        await sender.SendAsync(EmailTemplates.Verification("person@example.com", "482913"));
        var mail = await server.Received.Task.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Contains("MAIL FROM:<no-reply@example.com>", mail.Commands);
        Assert.Contains("RCPT TO:<person@example.com>", mail.Commands);
        Assert.Contains("Subject: Your OpenWork verification code is 482913", mail.Data);
        Assert.Contains("multipart/alternative", mail.Data);
        Assert.Contains("text/plain", mail.Data);
        Assert.Contains("text/html", mail.Data);
        Assert.Contains("482913", mail.Data);
    }

    [Fact]
    public async Task A_failing_SMTP_server_surfaces_an_error_to_the_caller()
    {
        var options = Options.Create(new EmailOptions { Smtp = new() { Host = "127.0.0.1", Port = 1, Security = "none" } });
        var sender = new SmtpEmailSender(options, Microsoft.Extensions.Logging.Abstractions.NullLogger<SmtpEmailSender>.Instance);
        await Assert.ThrowsAnyAsync<Exception>(() => sender.SendAsync(EmailTemplates.PasswordReset("p@example.com", "http://localhost/x")));
    }

    [Fact]
    public void Templates_escape_html_and_carry_the_reference_wording()
    {
        var reset = EmailTemplates.PasswordReset("p@example.com", "http://localhost/a?x=1&y=<script>");
        Assert.DoesNotContain("<script>", reset.Html);
        Assert.Contains("&lt;script&gt;", reset.Html);
        Assert.Equal("Reset your OpenWork password", reset.Subject);
        Assert.Contains("This link expires in 1 hour.", reset.Text);
        Assert.Equal("Your OpenWork verification code is 123456", EmailTemplates.Verification("p@example.com", "123456").Subject);
    }
}

/// <summary>A minimal SMTP server that records one message, enough to prove the sender speaks real SMTP.</summary>
internal sealed class FakeSmtpServer : IDisposable
{
    private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;
    public TaskCompletionSource<(string Commands, string Data)> Received { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public FakeSmtpServer()
    {
        _listener.Start();
        _ = Task.Run(RunAsync);
    }

    private async Task RunAsync()
    {
        try
        {
            using var client = await _listener.AcceptTcpClientAsync();
            using var stream = client.GetStream();
            using var reader = new StreamReader(stream, Encoding.ASCII);
            async Task Say(string line) { var b = Encoding.ASCII.GetBytes(line + "\r\n"); await stream.WriteAsync(b); }
            var commands = new StringBuilder();
            await Say("220 fake.smtp ready");
            while (await reader.ReadLineAsync() is { } line)
            {
                commands.AppendLine(line);
                var verb = line.Split(' ')[0].ToUpperInvariant();
                switch (verb)
                {
                    case "EHLO": await Say("250-fake.smtp"); await Say("250 8BITMIME"); break;
                    case "HELO" or "MAIL" or "RCPT" or "RSET" or "NOOP": await Say("250 OK"); break;
                    case "DATA":
                        await Say("354 End data with <CR><LF>.<CR><LF>");
                        var data = new StringBuilder();
                        while (await reader.ReadLineAsync() is { } d && d != ".") data.AppendLine(d.StartsWith("..") ? d[1..] : d);
                        await Say("250 queued");
                        Received.TrySetResult((commands.ToString(), data.ToString()));
                        break;
                    case "QUIT": await Say("221 bye"); return;
                    default: await Say("502 not implemented"); break;
                }
            }
        }
        catch (Exception e) { Received.TrySetException(e); }
    }

    public void Dispose() => _listener.Stop();
}
