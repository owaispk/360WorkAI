using System.Net;
using System.Text;
using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.Extensions.Options;
using MimeKit;

namespace WorkAI360.Api.Email;

public sealed record EmailMessage(string To, string Subject, string Text, string Html);

public interface IEmailSender
{
    Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default);
}

/// <summary>The messages this deployment sends. Wording and subjects follow the reference.</summary>
public static class EmailTemplates
{
    public static EmailMessage Verification(string to, string code) => new(
        to,
        $"Your OpenWork verification code is {code}",
        $"Verify your email\n\nEnter this code to finish signing in to OpenWork:\n\n    {code}\n\nThis code expires in 10 minutes. If you did not request it, you can ignore this email.\n",
        Layout("OpenWork", "Verify your email", "Enter this code to finish signing in to OpenWork.",
            $"<p style=\"font-size:32px;letter-spacing:8px;font-weight:700;margin:16px 0;background:#f6f4ef;border-radius:12px;padding:16px;text-align:center\">{WebUtility.HtmlEncode(code)}</p>",
            "This code expires in 10 minutes. If you did not request it, you can ignore this email."));

    public static EmailMessage PasswordReset(string to, string link) => new(
        to,
        "Reset your OpenWork password",
        $"Reset your password\n\nUse this secure link to choose a new password for your OpenWork account:\n\n{link}\n\nThis link expires in 1 hour. If you did not request a password reset, you can ignore this email.\n",
        Layout("OpenWork account", "Reset your password", "Use this secure link to choose a new password for your OpenWork account.",
            $"<p><a href=\"{WebUtility.HtmlEncode(link)}\" style=\"display:inline-block;background:#171412;color:#fff;text-decoration:none;border-radius:999px;padding:12px 24px;font-weight:600\">Reset password</a></p><p style=\"font-size:13px;color:#6b645c\">If the button does not work, paste this link into your browser:<br><span style=\"word-break:break-all\">{WebUtility.HtmlEncode(link)}</span></p>",
            "This link expires in 1 hour. If you did not request a password reset, you can ignore this email."));

    private static string Layout(string eyebrow, string heading, string intro, string body, string footer) => $"""
        <!doctype html><html><body style="margin:0;background:#f6f4ef;color:#171412;font-family:Arial,sans-serif">
        <div style="max-width:520px;margin:40px auto;background:#fffdf8;border:1px solid #e8dfd0;border-radius:20px;padding:32px">
        <p style="color:#8a5a28;font-size:13px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;margin:0 0 12px">{eyebrow}</p>
        <h1 style="font-size:28px;margin:0 0 16px">{heading}</h1>
        <p style="font-size:16px;line-height:24px;color:#4d4640">{intro}</p>
        {body}
        <p style="font-size:13px;color:#6b645c;margin-top:24px">{footer}</p>
        </div></body></html>
        """;
}

/// <summary>
/// Keeps sent messages in memory so development and tests can read them (the dev provider). Messages hold codes and links,
/// so this is only ever wired in Development, and the endpoint that lists them exists only there too.
/// </summary>
public sealed class DevOutbox : IEmailSender
{
    private readonly object _gate = new();
    private readonly List<(DateTime At, EmailMessage Message)> _messages = [];

    public Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
    {
        lock (_gate)
        {
            _messages.Add((DateTime.UtcNow, message));
            if (_messages.Count > 500) _messages.RemoveAt(0);
        }
        return Task.CompletedTask;
    }

    public IReadOnlyList<(DateTime At, EmailMessage Message)> To(string? address)
    {
        lock (_gate)
            return _messages.Where(m => address is null || string.Equals(m.Message.To, address, StringComparison.OrdinalIgnoreCase)).ToList();
    }

    public void Clear() { lock (_gate) _messages.Clear(); }
}

public sealed class SmtpEmailSender(IOptions<EmailOptions> options, ILogger<SmtpEmailSender> logger) : IEmailSender
{
    public async Task SendAsync(EmailMessage message, CancellationToken cancellationToken = default)
    {
        var o = options.Value;
        var mime = new MimeMessage();
        mime.From.Add(MailboxAddress.Parse(o.From));
        mime.To.Add(MailboxAddress.Parse(message.To));
        mime.Subject = message.Subject;
        mime.Body = new BodyBuilder { TextBody = message.Text, HtmlBody = message.Html }.ToMessageBody();

        using var client = new SmtpClient();
        client.Timeout = 15_000;
        var security = o.Smtp.Security.ToLowerInvariant() switch
        {
            "none" => SecureSocketOptions.None,
            "ssl" or "implicit" => SecureSocketOptions.SslOnConnect,
            "starttls" => SecureSocketOptions.StartTls,
            _ => SecureSocketOptions.Auto,
        };
        await client.ConnectAsync(o.Smtp.Host, o.Smtp.Port, security, cancellationToken);
        if (!string.IsNullOrEmpty(o.Smtp.User)) await client.AuthenticateAsync(o.Smtp.User, o.Smtp.Password ?? "", cancellationToken);
        await client.SendAsync(mime, cancellationToken);
        await client.DisconnectAsync(true, cancellationToken);
        logger.LogInformation("Sent an email to {Domain}", message.To[(message.To.IndexOf('@') + 1)..]);
    }
}
