using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace WorkAI360.Api.Auth;

public sealed record PasswordFeedback(string? Warning, IReadOnlyList<string> Suggestions);

public sealed record WeakPassword(string Message, PasswordFeedback Feedback);

/// <summary>The strength estimate (zxcvbn, like the reference): a score under 3 of 4 is refused, with the estimator's own advice.</summary>
public static class PasswordStrength
{
    public const int MinScore = 3;

    /// <summary><paramref name="userInputs"/> (the person's email and name) are penalized when the password is built from them.</summary>
    public static WeakPassword? Check(string password, IEnumerable<string> userInputs)
    {
        var result = Zxcvbn.Core.EvaluatePassword(password, userInputs.Where(i => !string.IsNullOrWhiteSpace(i)).ToList());
        if (result.Score >= MinScore) return null;
        var warning = string.IsNullOrWhiteSpace(result.Feedback.Warning) ? null : result.Feedback.Warning.Trim();
        var suggestions = (result.Feedback.Suggestions ?? []).Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s.Trim()).ToList();
        return new WeakPassword(warning ?? suggestions.FirstOrDefault() ?? "Password is too weak.", new PasswordFeedback(warning, suggestions));
    }
}

public sealed class PasswordScreeningUnavailableException(string message, Exception? inner = null) : Exception(message, inner);

public interface IPwnedPasswords
{
    /// <summary>True when the password appears in a known breach. Throws <see cref="PasswordScreeningUnavailableException"/> when that cannot be told.</summary>
    Task<bool> IsCompromisedAsync(string password, CancellationToken cancellationToken = default);
}

/// <summary>k-anonymity range lookup: the service sees five hex characters of a SHA-1, never the password or the full hash.</summary>
public sealed class PwnedPasswords(HttpClient http, IOptions<AuthOptions> options) : IPwnedPasswords
{
    public async Task<bool> IsCompromisedAsync(string password, CancellationToken cancellationToken = default)
    {
        var hash = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(password)));
        var (prefix, suffix) = (hash[..5], hash[5..]);
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"{options.Value.PwnedPasswordsUrl.TrimEnd('/')}/range/{prefix}");
            request.Headers.Add("Add-Padding", "true");
            request.Headers.UserAgent.ParseAdd("OpenWork den-api password screening");
            using var response = await http.SendAsync(request, cancellationToken);
            if (!response.IsSuccessStatusCode) throw new PasswordScreeningUnavailableException($"The breach service answered {(int)response.StatusCode}.");
            foreach (var line in (await response.Content.ReadAsStringAsync(cancellationToken)).Split('\n'))
            {
                var parts = line.Trim().Split(':');
                // Padding lines (count 0) exist only to hide the real list's size; they are not matches.
                if (parts.Length >= 1 && string.Equals(parts[0], suffix, StringComparison.OrdinalIgnoreCase) && !(parts.Length == 2 && parts[1] == "0")) return true;
            }
            return false;
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or OperationCanceledException && !cancellationToken.IsCancellationRequested)
        {
            throw new PasswordScreeningUnavailableException("The breach service could not be reached.", e);
        }
    }
}

/// <summary>The checks applied to a new password after the basic policy, in the reference's order, answering with its exact bodies.</summary>
public sealed class PasswordScreening(IPwnedPasswords pwned, IOptions<AuthOptions> options, IHostEnvironment environment)
{
    public bool BreachScreeningEnabled => options.Value.PasswordBreachScreening ?? !environment.IsDevelopment();

    /// <summary>Null when the password is acceptable. <paramref name="strength"/> is for sign-up (the reference does not score reset passwords).</summary>
    public async Task<IResult?> CheckAsync(string password, IEnumerable<string> userInputs, bool strength, CancellationToken cancellationToken = default)
    {
        if (strength && PasswordStrength.Check(password, userInputs) is { } weak)
            return Results.Json(new { error = "password_too_weak", message = weak.Message, feedback = new { warning = weak.Feedback.Warning, suggestions = weak.Feedback.Suggestions } }, statusCode: 400);
        if (!BreachScreeningEnabled) return null;
        try
        {
            return await pwned.IsCompromisedAsync(password, cancellationToken)
                ? Results.Json(new { error = "password_compromised", message = "This password appeared in a data breach. Choose a different one." }, statusCode: 400)
                : null;
        }
        catch (PasswordScreeningUnavailableException)
        {
            return Results.Json(new { error = "password_screening_unavailable", message = "Something went wrong. Please try again in a moment." }, statusCode: 503);
        }
    }
}
