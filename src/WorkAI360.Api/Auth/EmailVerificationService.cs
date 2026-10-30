using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Email;

namespace WorkAI360.Api.Auth;

public enum OtpResult { Verified, Invalid, Expired, TooManyAttempts }

/// <summary>Creates, mails and checks the six-digit codes that prove someone controls an inbox.</summary>
public sealed class EmailVerificationService(DenDbContext db, IEmailSender sender, IOptions<AuthOptions> options, RateLimiter limiter, ILogger<EmailVerificationService> logger)
{
    public const string TypeEmailVerification = "email-verification";
    public const int CodeLength = 6;
    public const int MaxAttempts = 5;
    public static readonly TimeSpan CodeLifetime = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Mails a fresh code to an unverified account, replacing any earlier one (so only the newest code works).
    /// `force` skips the per-address send limit (used at sign-up, which has its own limit).
    /// </summary>
    public async Task SendCodeAsync(User user, bool force)
    {
        if (user.EmailVerified) return;
        if (!force && limiter.Hit(RateLimiter.SendOtp, user.Email, ip: null) is not null) return; // sign-in attempts must not become a way to flood an inbox

        var code = RandomNumberGenerator.GetInt32(0, (int)Math.Pow(10, CodeLength)).ToString().PadLeft(CodeLength, '0');
        var now = DateTime.UtcNow;
        await db.EmailOtps.Where(o => o.Email == user.Email && o.Type == TypeEmailVerification).ExecuteDeleteAsync();
        db.EmailOtps.Add(new EmailOtp { Id = Ids.New("otp"), Email = user.Email, Type = TypeEmailVerification, CodeHash = Hash(user.Email, code), CreatedAt = now, ExpiresAt = now + CodeLifetime });
        await db.SaveChangesAsync();

        try { await sender.SendAsync(EmailTemplates.Verification(user.Email, code)); }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            // The person can ask for another code; do not turn a mail outage into an error that reveals the account exists.
            logger.LogError(e, "Could not send a verification email");
        }
    }

    /// <summary>
    /// Checks a code. At most five guesses are ever possible per code, even under concurrency: the attempt is counted first,
    /// atomically, and the sixth is refused whatever it contains.
    /// </summary>
    public async Task<OtpResult> VerifyAsync(string email, string code)
    {
        var otp = await db.EmailOtps.AsNoTracking().Where(o => o.Email == email && o.Type == TypeEmailVerification).OrderByDescending(o => o.CreatedAt).FirstOrDefaultAsync();
        if (otp is null) return OtpResult.Invalid;
        if (otp.ExpiresAt <= DateTime.UtcNow)
        {
            await db.EmailOtps.Where(o => o.Id == otp.Id).ExecuteDeleteAsync();
            return OtpResult.Expired;
        }

        var counted = await db.EmailOtps.Where(o => o.Id == otp.Id && o.Attempts < MaxAttempts).ExecuteUpdateAsync(s => s.SetProperty(o => o.Attempts, o => o.Attempts + 1));
        if (counted == 0)
        {
            await db.EmailOtps.Where(o => o.Id == otp.Id).ExecuteDeleteAsync();
            return OtpResult.TooManyAttempts;
        }

        var matches = CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Hash(email, code)), Encoding.ASCII.GetBytes(otp.CodeHash));
        if (!matches) return OtpResult.Invalid;

        // One use: only the caller that deletes the row gets to verify.
        return await db.EmailOtps.Where(o => o.Id == otp.Id).ExecuteDeleteAsync() == 1 ? OtpResult.Verified : OtpResult.Invalid;
    }

    private string Hash(string email, string code)
    {
        var key = HKDF.DeriveKey(HashAlgorithmName.SHA256, Encoding.UTF8.GetBytes(options.Value.Secret), 32, salt: null, info: Encoding.UTF8.GetBytes("workai360 email otp"));
        return Convert.ToHexStringLower(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes($"{email}:{code}")));
    }
}
