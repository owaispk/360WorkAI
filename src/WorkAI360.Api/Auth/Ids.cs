using System.Security.Cryptography;
using System.Text;

namespace WorkAI360.Api.Auth;

/// <summary>Prefixed, time-sortable ids in the TypeID format the reference API uses (usr_01m6…, org_01m6…).</summary>
public static class Ids
{
    private const string Base32 = "0123456789abcdefghjkmnpqrstvwxyz";
    private const string Alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    public static string New(string prefix)
    {
        Span<byte> bytes = stackalloc byte[16];
        Guid.CreateVersion7().TryWriteBytes(bytes, bigEndian: true, out _);
        // TypeID: 128 bits left-padded to 130, encoded as 26 base32 characters.
        var chars = new char[26];
        System.Numerics.BigInteger value = new(bytes, isUnsigned: true, isBigEndian: true);
        for (var i = 25; i >= 0; i--)
        {
            chars[i] = Base32[(int)(value & 31)];
            value >>= 5;
        }
        return $"{prefix}_{new string(chars)}";
    }

    public static string RandomAlnum(int length)
    {
        var sb = new StringBuilder(length);
        for (var i = 0; i < length; i++) sb.Append(Alnum[RandomNumberGenerator.GetInt32(Alnum.Length)]);
        return sb.ToString();
    }

    public static string RandomFrom(string alphabet, int length)
    {
        var sb = new StringBuilder(length);
        for (var i = 0; i < length; i++) sb.Append(alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)]);
        return sb.ToString();
    }

    public static string Sha256Hex(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}
