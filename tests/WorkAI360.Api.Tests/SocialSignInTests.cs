using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.Social;
using WorkAI360.Api.Domain.Sso;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>A fake Google (OpenID Connect, RS256 ID tokens) and a fake GitHub (OAuth 2 with /user and /user/emails) on one loopback server.</summary>
public sealed class FakeSocial : IAsyncDisposable
{
    private readonly WebApplication _app;
    private readonly RSA _key = RSA.Create(2048), _otherKey = RSA.Create(2048);
    private const string Kid = "g-test";
    public string Url { get; private set; } = "";

    public sealed record GoogleIdentity(string Sub, string Email, bool EmailVerified = true, string Name = "Gee Person", string Fault = "");
    public sealed record GitHubIdentity(long Id, string Login, string Name, string? ProfileEmail, (string Email, bool Primary, bool Verified)[] Emails, string Fault = "");
    public GoogleIdentity Google { get; set; } = new("g-1", "g@example.test");
    public GitHubIdentity GitHub { get; set; } = new(1, "octo", "Octo Person", "public@example.test", [("octo@example.test", true, true)]);
    public ConcurrentQueue<Dictionary<string, string>> AuthRequests { get; } = new();
    public ConcurrentQueue<Dictionary<string, string>> TokenRequests { get; } = new();
    private readonly ConcurrentDictionary<string, (string Provider, Dictionary<string, string> Query, GoogleIdentity G, GitHubIdentity H, bool Used)> _codes = new();
    private readonly ConcurrentDictionary<string, GitHubIdentity> _githubTokens = new();

    private FakeSocial(WebApplication app) => _app = app;

    public static FakeSocial Start()
    {
        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        var app = builder.Build();
        var fake = new FakeSocial(app);
        fake.Map(app);
        app.StartAsync().GetAwaiter().GetResult();
        fake.Url = app.Urls.First();
        return fake;
    }

    private static string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private string Jwt(Dictionary<string, object?> claims, string fault)
    {
        var head = B64(JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object> { ["alg"] = "RS256", ["typ"] = "JWT", ["kid"] = Kid }));
        var body = B64(JsonSerializer.SerializeToUtf8Bytes(claims));
        var key = fault == "sig" ? _otherKey : _key;
        return $"{head}.{body}.{B64(key.SignData(Encoding.ASCII.GetBytes($"{head}.{body}"), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))}";
    }

    public IEnumerable<KeyValuePair<string, string>> Settings() =>
    [
        new("SocialProviders:Google:ClientId", "g-client"), new("SocialProviders:Google:ClientSecret", "g-secret"),
        new("SocialProviders:Google:AuthorizationEndpoint", Url + "/google/authorize"), new("SocialProviders:Google:TokenEndpoint", Url + "/google/token"),
        new("SocialProviders:Google:JwksUri", Url + "/google/jwks"), new("SocialProviders:Google:Issuer", Url + "/google"),
        new("SocialProviders:GitHub:ClientId", "h-client"), new("SocialProviders:GitHub:ClientSecret", "h-secret"),
        new("SocialProviders:GitHub:AuthorizationEndpoint", Url + "/github/authorize"), new("SocialProviders:GitHub:TokenEndpoint", Url + "/github/token"),
        new("SocialProviders:GitHub:ApiBase", Url + "/github/api"),
    ];

    private void Map(WebApplication app)
    {
        app.MapGet("/google/jwks", () =>
        {
            var p = _key.ExportParameters(false);
            return Results.Json(new { keys = new[] { new { kty = "RSA", use = "sig", alg = "RS256", kid = Kid, n = B64(p.Modulus!), e = B64(p.Exponent!) } } });
        });
        foreach (var provider in new[] { "google", "github" })
        {
            var name = provider;
            app.MapGet($"/{name}/authorize", (HttpContext ctx) =>
            {
                var q = ctx.Request.Query.ToDictionary(k => k.Key, k => k.Value.ToString());
                AuthRequests.Enqueue(new Dictionary<string, string>(q) { ["_provider"] = name });
                var back = q["redirect_uri"];
                var fault = name == "google" ? Google.Fault : GitHub.Fault;
                if (fault == "error") return Results.Redirect($"{back}?error=access_denied&error_description=No&state={Uri.EscapeDataString(q["state"])}");
                var code = Convert.ToHexString(RandomNumberGenerator.GetBytes(12));
                _codes[code] = (name, q, Google, GitHub, false);
                return Results.Redirect($"{back}?code={code}&state={Uri.EscapeDataString(q["state"])}");
            });
            app.MapPost($"/{name}/token", async (HttpContext ctx) =>
            {
                var f = (await ctx.Request.ReadFormAsync()).ToDictionary(k => k.Key, k => k.Value.ToString());
                f["_provider"] = name;
                TokenRequests.Enqueue(f);
                if (f.GetValueOrDefault("client_id") != (name == "google" ? "g-client" : "h-client") || f.GetValueOrDefault("client_secret") != (name == "google" ? "g-secret" : "h-secret")) return Results.Json(new { error = "invalid_client" }, statusCode: 401);
                if (!_codes.TryGetValue(f.GetValueOrDefault("code") ?? "", out var rec) || rec.Used || rec.Provider != name) return Results.Json(new { error = "bad_verification_code" }, statusCode: name == "github" ? 200 : 400);
                _codes[f["code"]] = rec with { Used = true };
                var want = B64(SHA256.HashData(Encoding.ASCII.GetBytes(f.GetValueOrDefault("code_verifier") ?? "")));
                if (rec.Query.GetValueOrDefault("code_challenge_method") != "S256" || want != rec.Query.GetValueOrDefault("code_challenge")) return Results.Json(new { error = "invalid_grant" }, statusCode: 400);
                if (name == "github")
                {
                    var at = "gho_" + Guid.NewGuid().ToString("N")[..10];
                    _githubTokens[at] = rec.H;
                    return Results.Json(new { access_token = at, token_type = "bearer", scope = "read:user,user:email" });
                }
                var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds(); var g = rec.G;
                var claims = new Dictionary<string, object?>
                {
                    ["iss"] = g.Fault == "iss" ? "https://evil.example" : Url + "/google", ["aud"] = g.Fault == "aud" ? "someone-else" : "g-client", ["sub"] = g.Sub, ["iat"] = now,
                    ["exp"] = g.Fault == "exp" ? now - 3600 : now + 300, ["email"] = g.Email, ["email_verified"] = g.EmailVerified, ["name"] = g.Name,
                };
                if (g.Fault != "no-nonce") claims["nonce"] = g.Fault == "nonce" ? "not-the-nonce" : rec.Query.GetValueOrDefault("nonce");
                return Results.Json(new { access_token = "ya29.x", token_type = "Bearer", expires_in = 300, id_token = Jwt(claims, g.Fault) });
            });
        }
        app.MapGet("/github/api/user", (HttpContext ctx) =>
            _githubTokens.TryGetValue(ctx.Request.Headers.Authorization.ToString().Replace("Bearer ", ""), out var h) ? Results.Json(new { id = h.Id, login = h.Login, name = h.Name, email = h.ProfileEmail }) : Results.Json(new { message = "Bad credentials" }, statusCode: 401));
        app.MapGet("/github/api/user/emails", (HttpContext ctx) =>
            _githubTokens.TryGetValue(ctx.Request.Headers.Authorization.ToString().Replace("Bearer ", ""), out var h) ? Results.Json(h.Emails.Select(e => new { email = e.Email, primary = e.Primary, verified = e.Verified })) : Results.Json(new { message = "Bad credentials" }, statusCode: 401));
    }

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
        _key.Dispose(); _otherKey.Dispose();
    }
}

public class SocialFactory : ApiFactory
{
    public FakeSocial Fake { get; } = FakeSocial.Start();
    protected override IEnumerable<KeyValuePair<string, string>> Settings => Fake.Settings();
    public override async ValueTask DisposeAsync() { await base.DisposeAsync(); await Fake.DisposeAsync(); }
}

/// <summary>Sign-in with Google and GitHub: the happy paths and an attack on each rule (state, binding, PKCE, nonce, verified emails, linking, SSO, redirects).</summary>
public sealed class SocialSignInTests : IClassFixture<SocialFactory>
{
    private const string Back = "http://localhost/dashboard", ErrBack = "http://localhost/?social=1", NewBack = "http://localhost/organization";
    private readonly SocialFactory _factory;
    private FakeSocial Fake => _factory.Fake;
    public SocialSignInTests(SocialFactory factory) => _factory = factory;

    private static string Unique(string prefix = "p") => $"{prefix}-{Guid.NewGuid():N}"[..14];
    private static string Mail(string prefix = "social") => $"{prefix}.{Guid.NewGuid():N}@example.test";

    private sealed record Attempt(HttpResponseMessage Started, Uri AuthorizeUrl, string CallbackPathAndQuery, HttpResponseMessage Landed, string? Location);

    private async Task<Attempt> SignInAsync(HttpClient browser, string provider, bool newUserUrl = true)
    {
        var started = await browser.PostAsJsonAsync("/api/auth/sign-in/social", new { provider, callbackURL = Back, errorCallbackURL = ErrBack, newUserCallbackURL = newUserUrl ? NewBack : null });
        Assert.Equal(HttpStatusCode.OK, started.StatusCode);
        var url = new Uri((await ReadJsonAsync(started)).GetProperty("url").GetString()!);
        using var raw = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        var hop = await raw.GetAsync(url);
        var callback = hop.Headers.Location!;
        var pathAndQuery = callback.PathAndQuery;
        var landed = await browser.GetAsync(pathAndQuery);
        return new Attempt(started, url, pathAndQuery, landed, landed.Headers.Location?.ToString());
    }

    private static (string Error, string? Description, string Path) ErrorOf(string? location)
    {
        var uri = new Uri(new Uri("http://localhost"), location!);
        var q = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(uri.Query);
        return (q["error"].ToString(), q.TryGetValue("error_description", out var d) ? d.ToString() : null, uri.AbsolutePath);
    }

    private async Task<JsonElement?> MeAsync(HttpClient browser)
    {
        var r = await browser.GetAsync("/v1/me");
        return r.StatusCode == HttpStatusCode.OK ? await ReadJsonAsync(r) : null;
    }

    private static bool HasSession(HttpClient browser, HttpResponseMessage landed) => landed.Headers.TryGetValues("Set-Cookie", out var cookies) && cookies.Any(c => c.StartsWith("openwork-den.session_token=") && !c.StartsWith("openwork-den.session_token=;"));

    private User? UserByEmail(string email) => _factory.WithDb(db => db.Users.AsNoTracking().FirstOrDefault(u => u.Email == email.ToLowerInvariant()));

    // ---------- configuration ----------

    [Fact]
    public async Task A_provider_is_on_only_when_both_its_client_id_and_secret_are_set()
    {
        var providers = await ReadJsonAsync(await _factory.Plain().GetAsync("/api/auth/social-providers"));
        Assert.Equal(new[] { "google", "github" }, providers.GetProperty("providers").EnumerateArray().Select(p => p.GetString()!).ToArray());

        await using var half = new HalfConfiguredFactory();
        var http = half.Plain();
        Assert.Empty((await ReadJsonAsync(await http.GetAsync("/api/auth/social-providers"))).GetProperty("providers").EnumerateArray());
        var refused = await http.PostAsJsonAsync("/api/auth/sign-in/social", new { provider = "google", callbackURL = "http://localhost/" });
        Assert.Equal(HttpStatusCode.NotFound, refused.StatusCode);
        Assert.Equal("PROVIDER_NOT_FOUND", (await ReadJsonAsync(refused)).GetProperty("code").GetString());
    }

    private sealed class HalfConfiguredFactory : ApiFactory
    {
        protected override IEnumerable<KeyValuePair<string, string>> Settings => [new("SocialProviders:Google:ClientId", "only-an-id"), new("SocialProviders:GitHub:ClientSecret", "only-a-secret")];
    }

    // ---------- Google ----------

    [Fact]
    public async Task A_new_person_signs_up_through_Google_with_a_verified_account_and_a_session_like_any_other_sign_in()
    {
        var email = Mail(); var sub = Unique("g");
        Fake.Google = new(sub, email, Name: "Grace Hopper");
        var browser = _factory.Browser();
        var a = await SignInAsync(browser, "google");
        Assert.Equal(NewBack, a.Location);
        Assert.True(HasSession(browser, a.Landed));
        var me = await MeAsync(browser);
        Assert.Equal(email, me!.Value.GetProperty("user").GetProperty("email").GetString());
        Assert.Equal("Grace Hopper", me.Value.GetProperty("user").GetProperty("name").GetString());
        var user = UserByEmail(email)!;
        Assert.True(user.EmailVerified);
        Assert.False(WorkAI360.Api.Auth.Passwords.Verify("anything", user.PasswordHash));   // nothing to guess: it has no password
        Assert.Equal(sub, _factory.WithDb(db => db.Set<ExternalAccount>().Single(x => x.UserId == user.Id).AccountId));
        Assert.Equal("social:google", _factory.WithDb(db => db.Sessions.Single(s => s.UserId == user.Id).Method));

        // The same account again: the callback URL (not the new-user one), the same person.
        var again = await SignInAsync(_factory.Browser(), "google");
        Assert.Equal(Back, again.Location);
        Assert.Equal(1, _factory.WithDb(db => db.Users.Count(u => u.Email == email)));
    }

    [Fact]
    public async Task The_authorization_request_carries_PKCE_a_nonce_and_a_state_and_the_secret_and_verifier_travel_server_to_server()
    {
        Fake.Google = new(Unique("g"), Mail());
        var a = await SignInAsync(_factory.Browser(), "google");
        var q = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(a.AuthorizeUrl.Query);
        Assert.Equal("S256", q["code_challenge_method"]);
        Assert.True(q["code_challenge"].ToString().Length >= 43);
        Assert.True(q["nonce"].ToString().Length >= 24);
        Assert.True(q["state"].ToString().Length >= 32);
        Assert.Equal("http://localhost/api/auth/callback/google", q["redirect_uri"]);
        Assert.Equal("openid email profile", q["scope"]);
        var token = Fake.TokenRequests.Last(t => t["_provider"] == "google");
        Assert.Equal("g-secret", token["client_secret"]);
        Assert.Equal(q["code_challenge"], B64(SHA256.HashData(Encoding.ASCII.GetBytes(token["code_verifier"]))));
    }

    private static string B64(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    [Fact]
    public async Task Only_the_state_hash_and_an_encrypted_verifier_are_stored()
    {
        Fake.Google = new(Unique("g"), Mail());
        var browser = _factory.Browser();
        var started = await browser.PostAsJsonAsync("/api/auth/sign-in/social", new { provider = "google", callbackURL = Back });
        var url = new Uri((await ReadJsonAsync(started)).GetProperty("url").GetString()!);
        var state = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(url.Query)["state"].ToString();
        var row = _factory.WithDb(db => db.Set<SocialAuthState>().Single(s => s.Id == Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(state)))));
        Assert.DoesNotContain(state, JsonSerializer.Serialize(row));
        using var raw = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        await raw.GetAsync(url);
        var verifier = Fake.AuthRequests.Last().GetValueOrDefault("code_challenge");
        Assert.DoesNotContain(verifier!, row.CodeVerifierProtected);   // and it is not the challenge or any plain text either
        Assert.DoesNotMatch("^[A-Za-z0-9_-]{43}$", row.CodeVerifierProtected);
    }

    /// <summary>Starts an attempt and returns what a browser would hold: the callback address and the binding cookie, to replay by hand.</summary>
    private async Task<(string Callback, string Cookie)> StartedAsync(string provider = "google")
    {
        var started = await _factory.Plain().PostAsJsonAsync("/api/auth/sign-in/social", new { provider, callbackURL = Back });
        var cookie = started.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith("openwork-den.social_state=")).Split(';')[0];
        using var raw = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        var hop = await raw.GetAsync(new Uri((await ReadJsonAsync(started)).GetProperty("url").GetString()!));
        return (hop.Headers.Location!.PathAndQuery, cookie);
    }

    private static Task<HttpResponseMessage> WithCookieAsync(HttpClient http, string pathAndQuery, string cookie)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, pathAndQuery);
        request.Headers.Add("Cookie", cookie);
        return http.SendAsync(request);
    }

    [Fact]
    public async Task The_state_works_once_even_for_the_right_browser_and_even_when_two_callbacks_race()
    {
        Fake.Google = new(Unique("g"), Mail());
        var http = _factory.Plain();
        var (callback, cookie) = await StartedAsync();
        var first = await WithCookieAsync(http, callback, cookie);
        Assert.Equal(Back, first.Headers.Location!.ToString());
        // The same callback again with the very same cookie: the state was spent.
        var replay = await WithCookieAsync(http, callback, cookie);
        Assert.Equal("state_mismatch", ErrorOf(replay.Headers.Location!.ToString()).Error);

        // Two callbacks at the same moment: only one reaches the provider and only one can sign in.
        Fake.Google = new(Unique("g"), Mail());
        var (raceCallback, raceCookie) = await StartedAsync();
        var before = Fake.TokenRequests.Count;
        var results = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => WithCookieAsync(http, raceCallback, raceCookie)));
        Assert.Equal(1, results.Count(r => r.Headers.Location?.ToString() == Back));
        Assert.Equal(1, Fake.TokenRequests.Count - before);
    }

    [Fact]
    public async Task The_state_is_bound_to_the_browser_that_started_it_and_another_browser_cannot_spend_it()
    {
        Fake.Google = new(Unique("g"), Mail());
        var victim = _factory.Browser();
        var started = await victim.PostAsJsonAsync("/api/auth/sign-in/social", new { provider = "google", callbackURL = Back });
        var url = new Uri((await ReadJsonAsync(started)).GetProperty("url").GetString()!);
        using var raw = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        var callback = (await raw.GetAsync(url)).Headers.Location!.PathAndQuery;

        // The attacker's browser has no binding cookie: login CSRF with a code the attacker obtained is refused.
        var attacker = _factory.Browser();
        var refused = await attacker.GetAsync(callback);
        Assert.Equal("state_mismatch", ErrorOf(refused.Headers.Location!.ToString()).Error);
        Assert.False(HasSession(attacker, refused));
        // ...and a different browser with its own binding cookie for another attempt does not match either.
        var other = _factory.Browser();
        await other.PostAsJsonAsync("/api/auth/sign-in/social", new { provider = "google", callbackURL = Back });
        Assert.Equal("state_mismatch", ErrorOf((await other.GetAsync(callback)).Headers.Location!.ToString()).Error);
        // The real browser can still finish.
        var landed = await victim.GetAsync(callback);
        Assert.Equal(Back, landed.Headers.Location!.ToString());
        Assert.True(HasSession(victim, landed));
    }

    [Fact]
    public async Task A_forged_expired_or_cross_provider_state_signs_nobody_in()
    {
        var browser = _factory.Browser();
        Assert.Equal("state_mismatch", ErrorOf((await browser.GetAsync("/api/auth/callback/google?code=x&state=forged")).Headers.Location!.ToString()).Error);
        Assert.Equal("state_not_found", ErrorOf((await browser.GetAsync("/api/auth/callback/google?code=x")).Headers.Location!.ToString()).Error);
        Assert.Equal("oauth_provider_not_found", ErrorOf((await browser.GetAsync("/api/auth/callback/nope?code=x&state=y")).Headers.Location!.ToString()).Error);

        // A state made for Google, presented at GitHub's callback.
        Fake.Google = new(Unique("g"), Mail());
        var started = await browser.PostAsJsonAsync("/api/auth/sign-in/social", new { provider = "google", callbackURL = Back });
        var state = Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(new Uri((await ReadJsonAsync(started)).GetProperty("url").GetString()!).Query)["state"].ToString();
        Assert.Equal("state_mismatch", ErrorOf((await browser.GetAsync($"/api/auth/callback/github?code=x&state={state}")).Headers.Location!.ToString()).Error);

        // An attempt that took longer than ten minutes.
        var expired = _factory.Browser();
        var s2 = await expired.PostAsJsonAsync("/api/auth/sign-in/social", new { provider = "google", callbackURL = Back });
        var url = new Uri((await ReadJsonAsync(s2)).GetProperty("url").GetString()!);
        var callback = (await new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }).GetAsync(url)).Headers.Location!.PathAndQuery;
        _factory.WithDb(db => db.Set<SocialAuthState>().ExecuteUpdate(x => x.SetProperty(s => s.ExpiresAt, DateTime.UtcNow.AddMinutes(-1))));
        Assert.Equal("state_mismatch", ErrorOf((await expired.GetAsync(callback)).Headers.Location!.ToString()).Error);
    }

    [Theory]
    [InlineData("nonce")]
    [InlineData("no-nonce")]
    [InlineData("aud")]
    [InlineData("iss")]
    [InlineData("exp")]
    [InlineData("sig")]
    public async Task A_Google_ID_token_that_fails_validation_signs_nobody_in(string fault)
    {
        var email = Mail("bad");
        Fake.Google = new(Unique("g"), email, Fault: fault);
        var browser = _factory.Browser();
        var a = await SignInAsync(browser, "google");
        Fake.Google = new(Unique("g"), Mail());
        Assert.Equal("unable_to_get_user_info", ErrorOf(a.Location).Error);
        Assert.False(HasSession(browser, a.Landed));
        Assert.Null(UserByEmail(email));
    }

    [Fact]
    public async Task A_Google_email_the_provider_has_not_verified_never_signs_in_creates_or_joins_anyone()
    {
        var victim = Mail("victim");
        var (browserA, _, _) = (_factory.Browser(), 0, 0);
        var (_, token, victimId) = await _factory.SignUpAsync(browserA, "Victim");   // an existing account (even one with a verified email)
        _factory.WithDb(db => db.Users.Where(u => u.Id == victimId).ExecuteUpdate(u => u.SetProperty(x => x.EmailVerified, true)));
        var victimEmail = _factory.WithDb(db => db.Users.Single(u => u.Id == victimId).Email);
        Fake.Google = new(Unique("g"), victimEmail, EmailVerified: false);
        var attacker = _factory.Browser();
        var a = await SignInAsync(attacker, "google");
        Assert.Equal("email_not_verified", ErrorOf(a.Location).Error);
        Assert.False(HasSession(attacker, a.Landed));
        Assert.Equal(0, _factory.WithDb(db => db.Set<ExternalAccount>().Count(x => x.UserId == victimId)));
        Assert.NotNull(victim); Assert.NotNull(token);
        // And a brand-new address that is unverified creates nothing.
        var fresh = Mail("fresh");
        Fake.Google = new(Unique("g"), fresh, EmailVerified: false);
        await SignInAsync(_factory.Browser(), "google");
        Assert.Null(UserByEmail(fresh));
    }

    [Fact]
    public async Task A_verified_provider_email_joins_the_existing_verified_account_which_keeps_its_password()
    {
        var browser = _factory.Browser();
        var (email, _, userId) = await _factory.SignUpAsync(browser, "Existing Person");
        _factory.WithDb(db => db.Users.Where(u => u.Id == userId).ExecuteUpdate(u => u.SetProperty(x => x.EmailVerified, true)));
        Fake.Google = new(Unique("g"), email);
        var social = _factory.Browser();
        var a = await SignInAsync(social, "google");
        Assert.Equal(Back, a.Location);   // an existing person, not a new one
        Assert.Equal(userId, (await MeAsync(social))!.Value.GetProperty("user").GetProperty("id").GetString());
        var password = await _factory.Plain().PostAsJsonAsync("/api/auth/sign-in/email", new { email, password = Password });
        Assert.Equal(HttpStatusCode.OK, password.StatusCode);
    }

    [Fact]
    public async Task An_account_that_never_verified_its_email_is_taken_over_by_the_verified_identity_and_loses_its_password_and_sessions()
    {
        var browser = _factory.Browser();
        var (email, oldToken, userId) = await _factory.SignUpAsync(browser, "Pre-registered");   // email never verified
        Assert.False(_factory.WithDb(db => db.Users.Single(u => u.Id == userId).EmailVerified));
        Fake.Google = new(Unique("g"), email);
        var social = _factory.Browser();
        await SignInAsync(social, "google");
        Assert.True(_factory.WithDb(db => db.Users.Single(u => u.Id == userId).EmailVerified));
        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.Plain().PostAsJsonAsync("/api/auth/sign-in/email", new { email, password = Password })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await _factory.Plain().SendAsync(Bearer(HttpMethod.Get, "/v1/me", oldToken))).StatusCode);
    }

    [Fact]
    public async Task A_person_is_recognised_by_the_provider_account_not_by_a_changed_email_so_an_address_swap_hijacks_nothing()
    {
        var sub = Unique("g"); var first = Mail("first");
        Fake.Google = new(sub, first);
        var one = _factory.Browser();
        await SignInAsync(one, "google");
        var firstId = (await MeAsync(one))!.Value.GetProperty("user").GetProperty("id").GetString();

        // Someone else's account that already exists with a verified email.
        var otherBrowser = _factory.Browser();
        var (otherEmail, _, otherId) = await _factory.SignUpAsync(otherBrowser, "Someone Else");
        _factory.WithDb(db => db.Users.Where(u => u.Id == otherId).ExecuteUpdate(u => u.SetProperty(x => x.EmailVerified, true)));

        // The same Google account now reports the other person's address: it still signs in to ITS person.
        Fake.Google = new(sub, otherEmail);
        var two = _factory.Browser();
        await SignInAsync(two, "google");
        Assert.Equal(firstId, (await MeAsync(two))!.Value.GetProperty("user").GetProperty("id").GetString());
        Assert.NotEqual(otherId, firstId);
    }

    [Fact]
    public async Task The_provider_refusing_the_person_returns_to_the_error_URL_and_spends_the_state()
    {
        Fake.Google = new(Unique("g"), Mail(), Fault: "error");
        var browser = _factory.Browser();
        var a = await SignInAsync(browser, "google");
        Fake.Google = new(Unique("g"), Mail());
        var (error, description, path) = ErrorOf(a.Location);
        Assert.Equal("access_denied", error);
        Assert.Equal("No", description);
        Assert.Equal("/", path);
        Assert.False(HasSession(browser, a.Landed));
        Assert.Equal(1, _factory.WithDb(db => db.Set<SocialAuthState>().Count(s => s.ConsumedAt != null && s.ErrorCallbackUrl == ErrBack)) > 0 ? 1 : 0);
    }

    // ---------- GitHub ----------

    [Fact]
    public async Task GitHub_uses_the_primary_verified_email_and_ignores_the_public_profile_email()
    {
        var primary = Mail("octo");
        Fake.GitHub = new(Random.Shared.NextInt64(10_000, 900_000), "octo", "Octo Person", "public@example.test", [("secondary@example.test", false, true), (primary, true, true)]);
        var browser = _factory.Browser();
        var a = await SignInAsync(browser, "github");
        Assert.Equal(NewBack, a.Location);
        Assert.Equal(primary, (await MeAsync(browser))!.Value.GetProperty("user").GetProperty("email").GetString());
        Assert.Null(UserByEmail("public@example.test"));
        Assert.Equal("h-secret", Fake.TokenRequests.Last(t => t["_provider"] == "github")["client_secret"]);
    }

    [Theory]
    [InlineData("unverified-primary", "email_not_verified")]
    [InlineData("verified-secondary-only", "email_not_found")]
    [InlineData("no-emails", "email_not_found")]
    public async Task GitHub_never_signs_in_with_an_email_that_is_not_the_verified_primary(string shape, string expected)
    {
        var email = Mail("gh");
        var emails = shape switch
        {
            "unverified-primary" => new[] { (email, true, false), (Mail("v"), false, true) },
            "verified-secondary-only" => new[] { (email, false, true) },
            _ => Array.Empty<(string, bool, bool)>(),
        };
        Fake.GitHub = new(Random.Shared.NextInt64(10_000, 900_000), "octo", "Octo", email, emails);   // the profile claims the address too
        var browser = _factory.Browser();
        var a = await SignInAsync(browser, "github");
        Assert.Equal(expected, ErrorOf(a.Location).Error);
        Assert.False(HasSession(browser, a.Landed));
        Assert.Null(UserByEmail(email));
    }

    // ---------- SSO ----------

    private string OrgWithSso(string domain)
    {
        return _factory.WithDb(db =>
        {
            var org = new Organization { Id = Ids.New("org"), Name = "Sso Workspace", Slug = "sso-" + Guid.NewGuid().ToString("N")[..8], CreatedAt = DateTime.UtcNow };
            db.Organizations.Add(org);
            db.Add(new SsoConnection
            {
                Id = Ids.New("sso"), OrganizationId = org.Id, ProviderId = $"openwork-sso-{org.Id}", Kind = "oidc", Issuer = "https://idp.example.test", Domain = domain, Status = "enabled",
                SignInPath = $"/sso/{org.Slug}", ConfigRevision = "r1", TestStatus = "succeeded", DomainVerified = true, CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow,
            });
            db.SaveChanges();
            return org.Id;
        });
    }

    [Fact]
    public async Task Social_sign_in_cannot_get_around_a_workspace_that_requires_SSO()
    {
        var domain = $"corp-{Guid.NewGuid():N}"[..14] + ".example";
        var orgId = OrgWithSso(domain);

        // A person already in that workspace (their address is on another domain, so only their membership marks them).
        var browser = _factory.Browser();
        var (memberEmail, _, memberId) = await _factory.SignUpAsync(browser, "Member");
        _factory.WithDb(db => { db.Users.Where(u => u.Id == memberId).ExecuteUpdate(u => u.SetProperty(x => x.EmailVerified, true)); db.Members.Add(new Member { Id = Ids.New("mem"), OrganizationId = orgId, UserId = memberId, Role = "member", CreatedAt = DateTime.UtcNow }); db.SaveChanges(); return 0; });
        Fake.Google = new(Unique("g"), memberEmail);
        var attempt = await SignInAsync(_factory.Browser(), "google");
        Assert.Equal("sso_required", ErrorOf(attempt.Location).Error);

        // A new address on the domain the workspace claims.
        var onDomain = $"new.person@{domain}";
        Fake.Google = new(Unique("g"), onDomain);
        var claimed = await SignInAsync(_factory.Browser(), "google");
        Assert.Equal("sso_required", ErrorOf(claimed.Location).Error);
        Assert.Null(UserByEmail(onDomain));

        // The same through GitHub.
        Fake.GitHub = new(Random.Shared.NextInt64(10_000, 900_000), "octo", "Octo", null, [(onDomain, true, true)]);
        Assert.Equal("sso_required", ErrorOf((await SignInAsync(_factory.Browser(), "github")).Location).Error);

        // Someone unaffected still signs in.
        Fake.Google = new(Unique("g"), Mail("free"));
        Assert.Equal(NewBack, (await SignInAsync(_factory.Browser(), "google")).Location);
    }

    // ---------- redirects ----------

    [Theory]
    [InlineData("http://evil.example/")]
    [InlineData("//evil.example/x")]
    [InlineData("http://localhost@evil.example/")]
    [InlineData("javascript:alert(1)")]
    [InlineData("http://localhost.evil.example/")]
    public async Task The_return_addresses_may_only_be_this_site(string evil)
    {
        var http = _factory.Plain();
        foreach (var (field, code) in new[] { ("callbackURL", "INVALID_CALLBACK_URL"), ("errorCallbackURL", "INVALID_ERROR_CALLBACK_URL"), ("newUserCallbackURL", "INVALID_NEW_USER_CALLBACK_URL") })
        {
            var body = new Dictionary<string, string> { ["provider"] = "google", ["callbackURL"] = Back, [field] = evil };
            var response = await http.PostAsJsonAsync("/api/auth/sign-in/social", body);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Equal(code, (await ReadJsonAsync(response)).GetProperty("code").GetString());
        }
        Assert.Empty(_factory.WithDb(db => db.Set<SocialAuthState>().Where(s => s.CallbackUrl.Contains("evil")).ToList()));
    }

    [Fact]
    public async Task A_path_on_this_site_is_a_fine_return_address_and_the_default_is_the_home_page()
    {
        Fake.Google = new(Unique("g"), Mail());
        var browser = _factory.Browser();
        var started = await browser.PostAsJsonAsync("/api/auth/sign-in/social", new { provider = "google", callbackURL = "/dashboard?x=1" });
        Assert.Equal(HttpStatusCode.OK, started.StatusCode);
        using var raw = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        var callback = (await raw.GetAsync(new Uri((await ReadJsonAsync(started)).GetProperty("url").GetString()!))).Headers.Location!.PathAndQuery;
        Assert.Equal("http://localhost/dashboard?x=1", (await browser.GetAsync(callback)).Headers.Location!.ToString());
    }

    // ---------- limits and shape ----------

    [Fact]
    public async Task Starting_a_social_sign_in_is_rate_limited_per_address()
    {
        await using var factory = new LimitedSocialFactory();
        var http = factory.Plain();
        var last = HttpStatusCode.OK;
        for (var i = 0; i < 101 && last != HttpStatusCode.TooManyRequests; i++)
            last = (await http.PostAsJsonAsync("/api/auth/sign-in/social", new { provider = "google", callbackURL = "http://localhost/" })).StatusCode;
        Assert.Equal(HttpStatusCode.TooManyRequests, last);
    }

    private sealed class LimitedSocialFactory : SocialFactory
    {
        protected override IEnumerable<KeyValuePair<string, string>> Settings => base.Settings.Append(new("Auth:RateLimitsEnabled", "true"));
    }

    [Fact]
    public async Task The_start_answer_has_the_reference_shape_and_validation_errors()
    {
        var http = _factory.Plain();
        var ok = await ReadJsonAsync(await http.PostAsJsonAsync("/api/auth/sign-in/social", new { provider = "github", callbackURL = Back }));
        Assert.True(ok.GetProperty("redirect").GetBoolean());
        Assert.StartsWith(Fake.Url + "/github/authorize?", ok.GetProperty("url").GetString());
        var none = await http.PostAsJsonAsync("/api/auth/sign-in/social", new { });
        Assert.Equal(HttpStatusCode.BadRequest, none.StatusCode);
        Assert.Equal("[body.provider] Invalid input", (await ReadJsonAsync(none)).GetProperty("message").GetString());
        Assert.Equal(HttpStatusCode.NotFound, (await http.PostAsJsonAsync("/api/auth/sign-in/social", new { provider = "nope" })).StatusCode);
    }
}
