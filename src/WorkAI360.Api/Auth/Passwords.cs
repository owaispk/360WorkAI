using System.Security.Cryptography;

namespace WorkAI360.Api.Auth;

/// <summary>PBKDF2-SHA256 password hashing and the sign-up password policy.</summary>
public static class Passwords
{
    private const int Iterations = 210_000;
    private const int SaltBytes = 16;
    private const int HashBytes = 32;

    public static string Hash(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltBytes);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, HashBytes);
        return $"pbkdf2-sha256${Iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    public static bool Verify(string password, string stored)
    {
        var parts = stored.Split('$');
        if (parts.Length != 4 || parts[0] != "pbkdf2-sha256" || !int.TryParse(parts[1], out var iterations)) return false;
        var salt = Convert.FromBase64String(parts[2]);
        var expected = Convert.FromBase64String(parts[3]);
        var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    public const int MinLength = 8;
    public const int MaxLength = 128;
    private const string Specials = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

    public sealed record Violation(string Error, string Message);

    /// <summary>
    /// The first rule a proposed password breaks, or null. Codes, messages and order match the reference so existing clients can
    /// show them. One deliberate difference: the reference caps passwords at 32 characters; here the cap is 128, so passphrases work.
    /// Not built yet: the reference's strength score and breached-password screening.
    /// </summary>
    public static Violation? Validate(string password)
    {
        if (password.Length < MinLength) return new("password_too_short", $"Password must be at least {MinLength} characters.");
        if (password.Length > MaxLength) return new("password_too_long", $"Password must be at most {MaxLength} characters.");
        if (!password.Any(c => c is >= 'A' and <= 'Z')) return new("password_missing_uppercase", "Password must include at least one uppercase letter.");
        if (!password.Any(c => c is >= 'a' and <= 'z')) return new("password_missing_lowercase", "Password must include at least one lowercase letter.");
        if (!password.Any(c => Specials.Contains(c))) return new("password_missing_special_character", "Password must include at least one special character.");
        if (!password.Any(c => c is >= '0' and <= '9')) return new("password_missing_digit", "Password must include at least one digit.");
        return null;
    }
}
