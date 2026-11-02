using System.Security.Cryptography;
using System.Text;

namespace WorkAI360.Api.Auth;

/// <summary>
/// One key per purpose, derived from <c>Auth:Secret</c> with HKDF. A signature made for one purpose (a session cookie, an audit cursor, a brand
/// image link) is therefore never valid for another, even where the signed text could be made to look alike.
/// </summary>
public static class SecretKeys
{
    public static byte[] Derive(string secret, string purpose) =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, Encoding.UTF8.GetBytes(secret), 32, salt: null, info: Encoding.UTF8.GetBytes("workai360 " + purpose));
}
