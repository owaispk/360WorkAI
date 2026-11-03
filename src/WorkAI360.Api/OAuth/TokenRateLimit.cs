using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Endpoints;

namespace WorkAI360.Api.OAuth;

/// <summary>
/// Limits on <c>/oauth2/token</c>, with the reference's numbers: attempts per client and address (60 a minute; 20 for callers naming no client)
/// and per address (300), and failures (15 in five minutes per caller, 60 per address). No budget is keyed by the public client id alone, and
/// the keys never depend on whether a credential is valid, so a refusal reveals nothing about stored grants. A dead refresh token is charged
/// to that token only. Keys are keyed hashes, so stored keys cannot be matched against client ids, addresses or tokens. In memory.
/// </summary>
public sealed class TokenRateLimit(RateLimiter limiter, IOptions<AuthOptions> options)
{
    private const int AttemptMax = 60, AnonymousMax = 20, IpMax = 300, FailureMax = 15, SourceFailureMax = 60;
    private static readonly TimeSpan AttemptWindow = TimeSpan.FromMinutes(1), FailureWindow = TimeSpan.FromMinutes(5);

    public sealed record Budget(string Key, int Max, TimeSpan Window);

    /// <summary>What a refused caller is told, and the failure budgets to charge if this request fails.</summary>
    public sealed record Admission(IResult? Refused, Budget Subject, Budget Source, bool IsRefreshToken);

    /// <param name="bucket">Names the endpoint, so another endpoint (introspection) gets its own budgets with the same numbers; empty is the token endpoint.</param>
    public Admission Admit(HttpContext ctx, IReadOnlyDictionary<string, string> form, string? basicClientId, string bucket = "")
    {
        string Id(params string[] parts) => bucket.Length == 0 ? this.Id(parts) : this.Id([bucket, .. parts]);
        var address = AuthEndpoints.ClientIp(ctx);
        var clientId = basicClientId ?? (form.TryGetValue("client_id", out var c) && c.Length > 0 ? c : null);
        var refresh = form.GetValueOrDefault("grant_type") == "refresh_token" && form.TryGetValue("refresh_token", out var r) && r.Length > 0 ? r : null;

        var attempt = clientId is null
            ? new Budget(Id("anonymous", address), AnonymousMax, AttemptWindow)
            : new Budget(Id("client", clientId, address), AttemptMax, AttemptWindow);
        var ip = new Budget(Id("ip", address), IpMax, AttemptWindow);
        var subject = refresh is not null ? new Budget(Id("fail-refresh", refresh), FailureMax, FailureWindow)
            : clientId is not null ? new Budget(Id("fail-client", clientId, address), FailureMax, FailureWindow)
            : new Budget(Id("fail-anonymous", address), FailureMax, FailureWindow);
        var source = new Budget(Id("fail-ip", address), SourceFailureMax, FailureWindow);
        var admission = new Admission(null, subject, source, refresh is not null);

        // Failure budgets are only read first: a caller already refused for failing is turned away without spending the attempt
        // ceilings it shares with its neighbors.
        var wait = Longest(limiter.Window(subject.Key, subject.Max, subject.Window, consume: false), limiter.Window(source.Key, source.Max, source.Window, consume: false));
        if (wait is null) wait = Longest(limiter.Window(ip.Key, ip.Max, ip.Window, consume: true), limiter.Window(attempt.Key, attempt.Max, attempt.Window, consume: true));
        return wait is { } w ? admission with { Refused = Refused(ctx, w) } : admission;
    }

    /// <summary>Charges a failed request (400, 401 or 403). A refused refresh token is charged to that token only.</summary>
    public void RecordFailure(Admission admission, IResult result)
    {
        if (result is not IStatusCodeHttpResult { StatusCode: 400 or 401 or 403 }) return;
        if (limiter.Window(admission.Subject.Key, admission.Subject.Max, admission.Subject.Window, consume: true) is not null) return;
        if (admission.IsRefreshToken && ErrorCode(result) == "invalid_grant") return;
        limiter.Window(admission.Source.Key, admission.Source.Max, admission.Source.Window, consume: true);
    }

    private static string? ErrorCode(IResult result)
    {
        if (result is not IValueHttpResult { Value: { } value }) return null;
        using var doc = JsonDocument.Parse(JsonSerializer.Serialize(value));
        return doc.RootElement.TryGetProperty("error", out var e) ? e.GetString() : null;
    }

    private static IResult Refused(HttpContext ctx, TimeSpan wait)
    {
        ctx.Response.Headers.RetryAfter = ((int)Math.Ceiling(wait.TotalSeconds)).ToString();
        return Results.Json(new { error = "rate_limited", error_description = "Too many OAuth token requests. Try again later." }, statusCode: 429);
    }

    private static TimeSpan? Longest(TimeSpan? a, TimeSpan? b) => a is null ? b : b is null ? a : a > b ? a : b;

    private string Id(params string[] parts)
    {
        var key = SecretKeys.Derive(options.Value.Secret, "token rate limit");
        return Convert.ToBase64String(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(JsonSerializer.Serialize(parts)))).TrimEnd('=').Replace('+', '-').Replace('/', '_')[..32];
    }
}
