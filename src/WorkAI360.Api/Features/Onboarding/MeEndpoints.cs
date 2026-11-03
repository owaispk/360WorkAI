using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Email;
using WorkAI360.Api.Features.OrgAdmin;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Features.Onboarding;

/// <summary>What the signed-in person can read and change about themselves: profile, invitations waiting for them, the download-link email, "my agent" and the checklist.</summary>
public static partial class MeEndpoints
{
    public const int DownloadLinkLimit = 5;
    public static readonly TimeSpan DownloadLinkWindow = TimeSpan.FromHours(1);

    [GeneratedRegex("\\s+")]
    private static partial Regex Whitespace();

    public static void MapMeEndpoints(this WebApplication app)
    {
        // The reference's schema: both names are required strings (trimmed, 120 at most) and at least one must say something.
        app.MapPatch("/v1/me/profile", async (HttpContext ctx, OrgAccess access, DenDbContext db) =>
        {
            var (current, failure) = await access.ResolveUserAsync(ctx);
            if (current is null) return failure!;
            var (root, invalid) = await Zod.ReadObjectAsync(ctx, "firstName");
            if (invalid is not null) return invalid;
            var issues = new List<ZodIssue>();
            if (Zod.String(root, "firstName", 0, 120, required: true, out var first) is { } a) issues.Add(a);
            if (Zod.String(root, "lastName", 0, 120, required: true, out var last) is { } b) issues.Add(b);
            if (issues.Count > 0) return Zod.Respond(issues);
            if (first!.Length == 0 && last!.Length == 0) return Zod.Respond([new ZodIssue("custom", [], "Enter a first or last name.")]);

            var name = string.Join(' ', new[] { Whitespace().Replace(first, " ").Trim(), Whitespace().Replace(last!, " ").Trim() }.Where(p => p.Length > 0));
            var now = DateTime.UtcNow;
            var user = await db.Users.FirstAsync(u => u.Id == current.User.Id);
            user.Name = name;
            user.UpdatedAt = now;
            await db.SaveChangesAsync();
            return Results.Json(new { user = Responses.UserJson(user) });
        });

        // Only a verified address proves the person owns the inbox an invitation went to; without it the list is empty, whatever the deployment's
        // verification setting, so listing cannot hand out an invitation id the emailed link would otherwise be needed for.
        app.MapGet("/v1/me/invitations", async (HttpContext ctx, SessionService sessions, DenDbContext db) =>
        {
            var auth = await sessions.ResolveAsync(ctx);
            if (auth is null) return Responses.Unauthorized();
            var email = auth.User.Email.Trim().ToLowerInvariant();
            if (email.Length == 0 || !auth.User.EmailVerified) return Results.Json(new { invitations = Array.Empty<object>() });

            var now = DateTime.UtcNow;
            var rows = await (from i in db.Invitations.AsNoTracking()
                              join o in db.Organizations.AsNoTracking() on i.OrganizationId equals o.Id
                              where i.Status == InvitationStatus.Pending && i.ExpiresAt > now && i.Email == email
                                    && !db.Members.Any(m => m.OrganizationId == i.OrganizationId && m.UserId == auth.User.Id)
                              orderby i.CreatedAt descending, i.Id
                              select new { i.Id, OrganizationId = o.Id, OrganizationName = o.Name, i.Role, i.ExpiresAt }).Take(20).ToListAsync();
            return Results.Json(new
            {
                invitations = rows.Select(r => new { id = r.Id, organization = new { id = r.OrganizationId, name = r.OrganizationName }, role = r.Role, expiresAt = Responses.IsoUtc(r.ExpiresAt) }),
            });
        });

        // Always to the signed-in person's own address (nothing in the request names a recipient), five an hour, counted whether or not the mail goes out.
        app.MapPost("/v1/me/send-download-link", async (HttpContext ctx, OrgAccess access, WindowLimiter limiter, IEmailSender mail, OAuthUrls urls, IOptions<OnboardingOptions> options, ILogger<OnboardingFeature> log) =>
        {
            var (current, failure) = await access.ResolveUserAsync(ctx);
            if (current is null) return failure!;
            var email = current.User.Email.Trim();
            if (email.Length == 0) return Results.Json(new { error = "user_email_required", message = "This account does not have an email address." }, statusCode: 400);

            if (await limiter.HitAsync($"me:send-download-link:{current.User.Id}", DownloadLinkLimit, DownloadLinkWindow) is { } wait)
            {
                ctx.Response.Headers.RetryAfter = wait.ToString();
                return Results.Json(new { error = "rate_limited", message = "Too many download link emails. Try again later." }, statusCode: 429);
            }

            var url = options.Value.DownloadUrl is { Length: > 0 } configured ? configured : urls.Web + "/install";
            try { await mail.SendAsync(DownloadLinkEmail.Create(email, url)); }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                log.LogWarning("The download link email could not be sent ({Type})", e.GetType().Name);
                var network = e is HttpRequestException { StatusCode: null } || e is TimeoutException || e is System.Net.Sockets.SocketException;
                var rejected = e is HttpRequestException { StatusCode: not null } || e.Message.Contains("refused", StringComparison.OrdinalIgnoreCase);
                var reason = network ? "resend_network" : rejected ? "resend_rejected" : "nodemailer_rejected";
                var message = network ? "Could not reach the download email provider. Try again later." : "The download email provider rejected the send.";
                return Results.Json(new { error = "download_link_email_failed", reason, message }, statusCode: 502);
            }
            return Results.Json(new { ok = true });
        });

        // "My agent" (Workbot proactive) and the "Get set up" checklist need the Workbot assistant, the AI gateway and provider facts, none of which exist in
        // this build. Their features are off, which is the reference's own answer for an organization that has them off.
        MapDisabled(app, "GET", "/v1/me/agent", "workbotProactive");
        MapDisabled(app, "PUT", "/v1/me/agent", "workbotProactive");
        MapDisabled(app, "GET", "/v1/me/agent/checks", "workbotProactive");
    }

    private static void MapDisabled(WebApplication app, string method, string path, string feature)
    {
        app.MapMethods(path, [method], async (HttpContext ctx, OrgAccess access) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            _ = context;
            return Results.Json(new { error = "feature_disabled", feature }, statusCode: 404);
        });
    }
}

/// <summary>The message sent by <c>POST /v1/me/send-download-link</c>.</summary>
public static class DownloadLinkEmail
{
    public static EmailMessage Create(string to, string url) => new(
        to,
        "Your OpenWork download link",
        $"Download OpenWork\n\nHere's your link to download the OpenWork desktop app.\n\n{url}\n\nSigning in inside the app syncs your team's shared skills.\n",
        $"""
        <!doctype html><html><body style="margin:0;background:#f6f4ef;color:#171412;font-family:Arial,sans-serif">
        <div style="max-width:560px;margin:40px auto;background:#fffdf8;border:1px solid #e8dfd0;border-radius:20px;padding:32px">
        <p style="color:#8a5a28;font-size:13px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;margin:0 0 12px">OpenWork desktop</p>
        <h1 style="font-size:28px;margin:0 0 16px">Download OpenWork</h1>
        <p style="font-size:16px;line-height:24px;color:#4d4640">Here's your link to download the OpenWork desktop app.</p>
        <p><a href="{System.Net.WebUtility.HtmlEncode(url)}" style="display:inline-block;background:#171412;color:#fff8eb;text-decoration:none;border-radius:999px;padding:13px 22px;font-weight:700">Download OpenWork</a></p>
        <p style="font-size:14px;color:#756c62">Signing in inside the app syncs your team's shared skills.</p>
        </div></body></html>
        """);
}
