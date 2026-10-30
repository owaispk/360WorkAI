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

    /// <summary>Returns the human-readable problems with a proposed password (empty when it is acceptable).</summary>
    public static IReadOnlyList<string> Validate(string password)
    {
        var problems = new List<string>();
        if (password.Length < 10) problems.Add("Use at least 10 characters.");
        if (password.Length > 128) problems.Add("Use at most 128 characters.");
        var classes = 0;
        if (password.Any(char.IsLower)) classes++;
        if (password.Any(char.IsUpper)) classes++;
        if (password.Any(char.IsDigit)) classes++;
        if (password.Any(c => !char.IsLetterOrDigit(c))) classes++;
        if (classes < 3) problems.Add("Mix at least three of: lowercase, uppercase, numbers and symbols.");
        return problems;
    }
}
