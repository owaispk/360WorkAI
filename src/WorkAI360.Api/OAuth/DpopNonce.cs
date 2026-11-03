using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;

namespace WorkAI360.Api.OAuth;

/// <summary>
/// Server-provided DPoP nonces (RFC 9449 sections 8 and 9). Off unless <c>OAuth:DpopNonceRequired</c> is true; the reference does not use nonces, so by default
/// nothing changes. When on, every DPoP proof at the token endpoint, the MCP endpoint and userinfo must carry a <c>nonce</c> this server issued recently;
/// otherwise the answer is <c>use_dpop_nonce</c> (400 at the token endpoint, a 401 <c>DPoP</c> challenge at a resource) with a fresh <c>DPoP-Nonce</c> header,
/// and the client retries. Nonces are stateless (a time slot and an HMAC under a key derived from <c>Auth:Secret</c>), so every instance accepts every
/// other's; one is valid for the slot it was made in and the next (two to four minutes).
/// </summary>
public sealed class DpopNonces(IOptions<AuthOptions> auth, IConfiguration configuration)
{
    public const string Header = "DPoP-Nonce";
    public const string UseNonce = "use_dpop_nonce";
    private const int SlotSeconds = 120;

    public bool Required => bool.TryParse(configuration["OAuth:DpopNonceRequired"], out var on) && on;

    private byte[] Key => HMACSHA256.HashData(Encoding.UTF8.GetBytes(auth.Value.Secret), "workai360:dpop-nonce:v1"u8);

    private static long Slot(DateTimeOffset at) => at.ToUnixTimeSeconds() / SlotSeconds;

    private string Make(long slot)
    {
        var slotBytes = BitConverter.GetBytes(slot);
        var mac = HMACSHA256.HashData(Key, slotBytes).AsSpan(0, 16).ToArray();
        return SigningKeyStore.Base64Url([.. slotBytes, .. mac]);
    }

    public string Issue() => Make(Slot(DateTimeOffset.UtcNow));

    public bool IsValid(string? nonce)
    {
        if (string.IsNullOrEmpty(nonce) || nonce.Length > 64) return false;
        var current = Slot(DateTimeOffset.UtcNow);
        foreach (var slot in new[] { current, current - 1 })
            if (CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(nonce), Encoding.ASCII.GetBytes(Make(slot)))) return true;
        return false;
    }

    /// <summary>Throws <c>use_dpop_nonce</c> when nonces are required and the proof's is missing or stale.</summary>
    public void Check(string? proofNonce, bool atResource)
    {
        if (!Required || IsValid(proofNonce)) return;
        throw new DpopException(atResource ? "Resource server requires nonce in DPoP proof" : "Authorization server requires nonce in DPoP proof", UseNonce);
    }
}

/// <summary>When nonces are on, every answer of the endpoints that read DPoP proofs carries a fresh <c>DPoP-Nonce</c> (RFC 9449 8.2 and 9), errors included.</summary>
public static class DpopNonceMiddleware
{
    private static readonly string[] Paths = ["/api/auth/oauth2/token", "/mcp/agent", "/api/auth/oauth2/userinfo", "/oauth2/userinfo", "/userinfo"];

    public static void UseDpopNonces(this WebApplication app) => app.Use(async (ctx, next) =>
    {
        var nonces = ctx.RequestServices.GetRequiredService<DpopNonces>();
        if (nonces.Required && Paths.Any(p => ctx.Request.Path.StartsWithSegments(p)))
        {
            ctx.Response.OnStarting(() =>
            {
                ctx.Response.Headers[DpopNonces.Header] = nonces.Issue();
                // Browsers may read it only when it is exposed (CORS).
                var exposed = ctx.Response.Headers.AccessControlExposeHeaders.ToString();
                if (exposed.Length > 0 && !exposed.Contains(DpopNonces.Header, StringComparison.OrdinalIgnoreCase))
                    ctx.Response.Headers.AccessControlExposeHeaders = exposed + ", " + DpopNonces.Header;
                return Task.CompletedTask;
            });
        }
        await next();
    });
}
