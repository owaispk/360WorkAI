using System.Net;
using System.Net.Http.Json;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>The limits on the OAuth token endpoint (the reference's numbers). Each test has its own server, so budgets never carry over.</summary>
public sealed class TokenRateLimitTests
{
    private static async Task<HttpResponseMessage> TokenAsync(HttpClient http, string? clientId, string grant = "authorization_code", string? refresh = null)
    {
        var form = new Dictionary<string, string> { ["grant_type"] = grant, ["code"] = "bogus", ["redirect_uri"] = "http://localhost/cb", ["code_verifier"] = new string('a', 50) };
        if (clientId is not null) form["client_id"] = clientId;
        if (refresh is not null) form["refresh_token"] = refresh;
        return await http.PostAsync("/api/auth/oauth2/token", new FormUrlEncodedContent(form));
    }

    [Fact]
    public async Task A_caller_that_keeps_failing_is_refused_after_fifteen_failures_with_a_wait_time()
    {
        await using var factory = new RateLimitedFactory();
        var http = factory.Plain();
        for (var i = 0; i < 15; i++) Assert.NotEqual(HttpStatusCode.TooManyRequests, (await TokenAsync(http, "client-a")).StatusCode);
        var refused = await TokenAsync(http, "client-a");
        Assert.Equal(HttpStatusCode.TooManyRequests, refused.StatusCode);
        var body = await ReadJsonAsync(refused);
        Assert.Equal("rate_limited", body.GetProperty("error").GetString());
        Assert.Equal("Too many OAuth token requests. Try again later.", body.GetProperty("error_description").GetString());
        Assert.True(int.Parse(refused.Headers.GetValues("Retry-After").Single()) is > 0 and <= 300);
        Assert.Equal("no-store", refused.Headers.CacheControl?.ToString());
    }

    [Fact]
    public async Task Another_client_from_the_same_address_is_not_locked_out_by_the_first()
    {
        await using var factory = new RateLimitedFactory();
        var http = factory.Plain();
        for (var i = 0; i < 16; i++) await TokenAsync(http, "client-a");
        Assert.Equal(HttpStatusCode.TooManyRequests, (await TokenAsync(http, "client-a")).StatusCode);
        Assert.NotEqual(HttpStatusCode.TooManyRequests, (await TokenAsync(http, "client-b")).StatusCode);
    }

    [Fact]
    public async Task One_address_cannot_dodge_the_limit_by_rotating_client_ids()
    {
        await using var factory = new RateLimitedFactory();
        var http = factory.Plain();
        // Every new client id has a fresh per-client budget; the address-wide failure ceiling (60) is what stops the rotation.
        var refusedAt = -1;
        for (var i = 0; i < 80 && refusedAt < 0; i++)
            if ((await TokenAsync(http, $"rotating-{i}")).StatusCode == HttpStatusCode.TooManyRequests) refusedAt = i;
        Assert.InRange(refusedAt, 60, 62);
    }

    [Fact]
    public async Task Callers_that_name_no_client_share_a_small_budget()
    {
        await using var factory = new RateLimitedFactory();
        var http = factory.Plain();
        for (var i = 0; i < 15; i++) Assert.NotEqual(HttpStatusCode.TooManyRequests, (await TokenAsync(http, null)).StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await TokenAsync(http, null)).StatusCode);
    }

    [Fact]
    public async Task A_dead_refresh_token_is_charged_to_that_token_only()
    {
        await using var factory = new RateLimitedFactory();
        var http = factory.Plain();
        async Task<string> RegisterAsync()
        {
            var r = await http.PostAsJsonAsync("/register", new { client_name = "Agent", redirect_uris = new[] { "http://127.0.0.1/cb" }, token_endpoint_auth_method = "none", grant_types = new[] { "authorization_code", "refresh_token" }, response_types = new[] { "code" } });
            return (await ReadJsonAsync(r)).GetProperty("client_id").GetString()!;
        }
        var clientA = await RegisterAsync(); var clientB = await RegisterAsync();
        // The same dead token over and over: its own budget fills after fifteen.
        var first = await TokenAsync(http, clientA, "refresh_token", "dead-token");
        Assert.Equal("invalid_grant", (await ReadJsonAsync(first)).GetProperty("error").GetString());
        for (var i = 1; i < 15; i++) Assert.NotEqual(HttpStatusCode.TooManyRequests, (await TokenAsync(http, clientA, "refresh_token", "dead-token")).StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await TokenAsync(http, clientA, "refresh_token", "dead-token")).StatusCode);
        // Many different dead tokens (a server renewing for many people) are not charged to the address, so the address-wide failure
        // ceiling is not hit; only the attempt ceiling of 60 a minute per client and address applies.
        var other = factory.Plain();
        var codes = new List<HttpStatusCode>();
        for (var i = 0; i < 70; i++) codes.Add((await TokenAsync(other, clientB, "refresh_token", $"dead-{i}")).StatusCode);
        var firstRefused = codes.FindIndex(c => c == HttpStatusCode.TooManyRequests);
        Assert.InRange(firstRefused, 59, 61);
        Assert.True(codes.Take(firstRefused).All(c => c == HttpStatusCode.BadRequest || c == HttpStatusCode.Unauthorized), "the dead tokens before the ceiling are ordinary failures");
    }

    [Fact]
    public async Task The_limits_are_off_in_development_by_default()
    {
        await using var factory = new ApiFactory();
        var http = factory.Plain();
        for (var i = 0; i < 100; i++) Assert.NotEqual(HttpStatusCode.TooManyRequests, (await TokenAsync(http, "client-a")).StatusCode);
    }
}
