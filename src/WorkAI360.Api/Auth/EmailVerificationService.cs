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

        await IssueAsync(user.Email, TypeEmailVerification);
    }

    /// <summary>
    /// Mails a fresh code of one type ("email-verification", "sign-in" or "forget-password") to an address, replacing any earlier code of that type.
    /// Codes are stored only as keyed hashes, last 10 minutes and allow five guesses; the type is part of the stored key, so a code for one
    /// purpose never works for another.
    /// </summary>
    public async Task IssueAsync(string email, string type)
    {
        var code = RandomNumberGenerator.GetInt32(0, (int)Math.Pow(10, CodeLength)).ToString().PadLeft(CodeLength, '0');
        var now = DateTime.UtcNow;
        await db.EmailOtps.Where(o => o.Email == email && o.Type == type).ExecuteDeleteAsync();
        db.EmailOtps.Add(new EmailOtp { Id = Ids.New("otp"), Email = email, Type = type, CodeHash = Hash(email, code, type), CreatedAt = now, ExpiresAt = now + CodeLifetime });
        await db.SaveChangesAsync();

        try { await sender.SendAsync(EmailTemplates.Verification(email, code)); }
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
    /// <param name="type">Which kind of code this must be (a code issued for another purpose never matches).</param>
    /// <param name="consume">False only for "check" calls: the guess still counts, but a right answer leaves the code usable.</param>
    public async Task<OtpResult> VerifyAsync(string email, string code, string type = TypeEmailVerification, bool consume = true)
    {
        var otp = await db.EmailOtps.AsNoTracking().Where(o => o.Email == email && o.Type == type).OrderByDescending(o => o.CreatedAt).FirstOrDefaultAsync();
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

        var matches = CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(Hash(email, code, type)), Encoding.ASCII.GetBytes(otp.CodeHash));
        if (!matches) return OtpResult.Invalid;
        if (!consume) return OtpResult.Verified;

        // One use: only the caller that deletes the row gets to verify.
        return await db.EmailOtps.Where(o => o.Id == otp.Id).ExecuteDeleteAsync() == 1 ? OtpResult.Verified : OtpResult.Invalid;
    }

    // The type is only mixed in for the new code types, so verification codes keep the hash they always had.
    private string Hash(string email, string code, string type = TypeEmailVerification)
    {
        var key = HKDF.DeriveKey(HashAlgorithmName.SHA256, Encoding.UTF8.GetBytes(options.Value.Secret), 32, salt: null, info: Encoding.UTF8.GetBytes("workai360 email otp"));
        return Convert.ToHexStringLower(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(type == TypeEmailVerification ? $"{email}:{code}" : $"{type}:{email}:{code}")));
    }
}
