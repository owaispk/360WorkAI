using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using WorkAI360.Api.Auth;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>A stand-in for the breach range service that records what it was asked.</summary>
public sealed class FakePwnedServer : IDisposable
{
    private readonly HttpListener _listener = new();
    public string Url { get; }
    public List<(string Path, string? Padding)> Requests { get; } = [];
    public Func<string, (int Status, string Body)> Answer { get; set; } = _ => (200, "");

    public FakePwnedServer()
    {
        var probe = new TcpListener(IPAddress.Loopback, 0); probe.Start(); var port = ((IPEndPoint)probe.LocalEndpoint).Port; probe.Stop();
        Url = $"http://127.0.0.1:{port}";
        _listener.Prefixes.Add(Url + "/"); _listener.Start();
        _ = Task.Run(async () =>
        {
            while (_listener.IsListening)
            {
                HttpListenerContext c;
                try { c = await _listener.GetContextAsync(); } catch { return; }
                lock (Requests) Requests.Add((c.Request.Url!.AbsolutePath, c.Request.Headers["Add-Padding"]));
                var (status, body) = Answer(c.Request.Url!.AbsolutePath);
                c.Response.StatusCode = status;
                var bytes = Encoding.UTF8.GetBytes(body);
                await c.Response.OutputStream.WriteAsync(bytes);
                c.Response.Close();
            }
        });
    }

    public void Dispose() => _listener.Close();
}

public sealed class ScreeningFactory : ApiFactory
{
    public FakePwnedServer Pwned { get; } = new();
    protected override IEnumerable<KeyValuePair<string, string>> Settings =>
        [new("Auth:PasswordBreachScreening", "true"), new("Auth:PwnedPasswordsUrl", Pwned.Url)];
    public override ValueTask DisposeAsync() { Pwned.Dispose(); return base.DisposeAsync(); }
}

public sealed class PasswordStrengthTests
{
    [Theory]
    [InlineData("Password1!")]
    [InlineData("Qwerty123!")]
    [InlineData("Welcome2026!")]
    [InlineData("Abcdefg1!")]
    [InlineData("Iloveyou123!")]
    public void Common_passwords_that_pass_the_basic_rules_are_still_too_weak(string password)
    {
        Assert.Null(Passwords.Validate(password));                  // the basic policy accepts it
        var weak = PasswordStrength.Check(password, []);
        Assert.NotNull(weak);
        Assert.False(string.IsNullOrWhiteSpace(weak!.Message));
        Assert.Equal(weak.Feedback.Warning ?? weak.Feedback.Suggestions.FirstOrDefault() ?? "Password is too weak.", weak.Message);   // the advice is the message
    }

    [Fact]
    public void A_name_based_password_is_weak_and_a_long_random_one_is_not()
    {
        Assert.NotNull(PasswordStrength.Check("JaneDoe1!", ["jane.doe@example.com", "Jane Doe"]));
        Assert.Null(PasswordStrength.Check("Str0ng!Passw0rd#2026x", ["jane.doe@example.com", "Jane Doe"]));
        Assert.Null(PasswordStrength.Check("vK9#mQ2$xL7&nR4@tZ8", []));
        Assert.Null(PasswordStrength.Check("correct-Horse-battery-Staple-7!", []));
    }
}

public sealed class PasswordScreeningFlowTests : IClassFixture<ScreeningFactory>
{
    private readonly ScreeningFactory _factory;
    public PasswordScreeningFlowTests(ScreeningFactory factory) => _factory = factory;

    private static string Sha1(string password) => Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password)));

    private Task<HttpResponseMessage> SignUp(string password, string? email = null, string name = "Test User") =>
        _factory.Plain().PostAsJsonAsync("/api/auth/sign-up/email", new { name, email = email ?? NewEmail(), password });

    [Fact]
    public async Task A_guessable_password_is_refused_with_advice_and_creates_nothing()
    {
        var email = NewEmail();
        var r = await SignUp("Password1!", email);
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        var body = await ReadJsonAsync(r);
        Assert.Equal("password_too_weak", body.GetProperty("error").GetString());
        Assert.False(string.IsNullOrWhiteSpace(body.GetProperty("message").GetString()));
        Assert.Equal(JsonValueKind.Array, body.GetProperty("feedback").GetProperty("suggestions").ValueKind);
        Assert.False(_factory.WithDb(db => db.Users.Any(u => u.Email == email)));
        // The strength check runs before the network: a weak password never reaches the breach service.
        Assert.DoesNotContain(_factory.Pwned.Requests, q => true);
    }

    [Fact]
    public async Task A_breached_password_is_refused_and_only_five_hash_characters_leave_the_server()
    {
        var password = "vK9#mQ2$xL7&nR4@tZ8";
        var hash = Sha1(password);
        _factory.Pwned.Answer = _ => (200, $"0000000000000000000000000000000000A:3\r\n{hash[5..]}:1203\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:9\r\n");
        _factory.Pwned.Requests.Clear();
        var email = NewEmail();
        var r = await SignUp(password, email);
        Assert.Equal(HttpStatusCode.BadRequest, r.StatusCode);
        var body = await ReadJsonAsync(r);
        Assert.Equal("password_compromised", body.GetProperty("error").GetString());
        Assert.Equal("This password appeared in a data breach. Choose a different one.", body.GetProperty("message").GetString());
        Assert.False(_factory.WithDb(db => db.Users.Any(u => u.Email == email)));

        var request = Assert.Single(_factory.Pwned.Requests);
        Assert.Equal($"/range/{hash[..5]}", request.Path);
        Assert.Equal("true", request.Padding);
        Assert.DoesNotContain(hash[5..], request.Path);
        Assert.DoesNotContain(password, request.Path);
    }

    [Fact]
    public async Task A_clean_password_signs_up_and_padding_lines_are_not_matches()
    {
        var password = "xQ4!mT9#vB2$kL6&pZ1@";
        var hash = Sha1(password);
        _factory.Pwned.Answer = _ => (200, $"{hash[5..]}:0\r\n0000000000000000000000000000000000A:12\r\n");   // a zero count is padding
        var r = await SignUp(password);
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
    }

    [Fact]
    public async Task When_the_breach_service_cannot_answer_sign_up_is_refused_not_waved_through()
    {
        foreach (var answer in new Func<string, (int, string)>[] { _ => (500, "oops"), _ => (429, "slow down"), _ => (404, "") })
        {
            _factory.Pwned.Answer = answer;
            var email = NewEmail();
            var r = await SignUp("nB7#kM3$qW9&zT5@rX2", email);
            Assert.Equal(HttpStatusCode.ServiceUnavailable, r.StatusCode);
            var body = await ReadJsonAsync(r);
            Assert.Equal("password_screening_unavailable", body.GetProperty("error").GetString());
            Assert.Equal("Something went wrong. Please try again in a moment.", body.GetProperty("message").GetString());
            Assert.False(_factory.WithDb(db => db.Users.Any(u => u.Email == email)));
        }
        // And an unreachable service too.
        await using var dead = new UnreachableFactory();
        var response = await dead.Plain().PostAsJsonAsync("/api/auth/sign-up/email", new { name = "T", email = NewEmail(), password = "nB7#kM3$qW9&zT5@rX2" });
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
    }

    [Fact]
    public async Task Reset_checks_the_new_password_for_policy_and_breaches_before_it_looks_at_the_token_but_not_for_strength()
    {
        _factory.Pwned.Answer = _ => (200, "");
        async Task<(HttpStatusCode, JsonElement)> Reset(string password) { var r = await _factory.Plain().PostAsJsonAsync("/api/auth/reset-password", new { newPassword = password, token = "bogus" }); return (r.StatusCode, await ReadJsonAsync(r)); }

        var short1 = await Reset("short");
        Assert.Equal("password_too_short", short1.Item2.GetProperty("error").GetString());
        // Guessable but policy-valid: not scored on reset (as in the reference), so it gets as far as the token.
        var guessable = await Reset("Password1!");
        Assert.Equal("INVALID_TOKEN", guessable.Item2.GetProperty("code").GetString());

        var password = "vK9#mQ2$xL7&nR4@tZ8";
        _factory.Pwned.Answer = _ => (200, $"{Sha1(password)[5..]}:77\r\n");
        var breached = await Reset(password);
        Assert.Equal(HttpStatusCode.BadRequest, breached.Item1);
        Assert.Equal("password_compromised", breached.Item2.GetProperty("error").GetString());
    }

    private sealed class UnreachableFactory : ApiFactory
    {
        protected override IEnumerable<KeyValuePair<string, string>> Settings => [new("Auth:PasswordBreachScreening", "true"), new("Auth:PwnedPasswordsUrl", "http://127.0.0.1:1")];
    }
}

public sealed class PasswordScreeningDefaultsTests : IClassFixture<ApiFactory>
{
    private readonly ApiFactory _factory;
    public PasswordScreeningDefaultsTests(ApiFactory factory) => _factory = factory;

    [Fact]
    public async Task In_development_breach_screening_is_off_by_default_so_a_local_run_works_offline_but_strength_still_applies()
    {
        var ok = await _factory.Plain().PostAsJsonAsync("/api/auth/sign-up/email", new { name = "T", email = NewEmail(), password = "Str0ng!Passw0rd#2026x" });
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        var weak = await _factory.Plain().PostAsJsonAsync("/api/auth/sign-up/email", new { name = "T", email = NewEmail(), password = "Password1!" });
        Assert.Equal(HttpStatusCode.BadRequest, weak.StatusCode);
        Assert.Equal("password_too_weak", (await ReadJsonAsync(weak)).GetProperty("error").GetString());
    }
}
