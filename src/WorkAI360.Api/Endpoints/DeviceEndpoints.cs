using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;

namespace WorkAI360.Api.Endpoints;

public sealed record DeviceCodeBody(string? ClientId);
public sealed record DeviceTokenBody(string? GrantType, string? DeviceCode, string? ClientId);
public sealed record DeviceDecisionBody(string? UserCode, string? Decision, string? OrganizationId);

/// <summary>
/// RFC 8628 device authorization for `openwork-bootstrap login` and the OpenCode plugin. The client shows a code,
/// the person approves it on the web /device page, and the client receives a session token. No password reaches the client.
/// </summary>
public static class DeviceEndpoints
{
    public const string GrantType = "urn:ietf:params:oauth:grant-type:device_code";
    private const string UserCodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(5);

    private static string NormalizeUserCode(string code) => code.Replace("-", "").Trim().ToUpperInvariant();

    public static void MapDeviceEndpoints(this WebApplication app)
    {
        app.MapPost("/api/auth/device/code", async (HttpContext ctx, DenDbContext db, IOptions<AuthOptions> options) =>
        {
            var body = await ReadBodyAsync<DeviceCodeBody>(ctx);
            var clientId = body?.ClientId;
            if (clientId is null || !options.Value.DeviceClientIds.Contains(clientId))
                return OAuthError(400, "invalid_client", "Unknown client.");

            var deviceCode = Ids.RandomAlnum(40);
            var userCode = Ids.RandomFrom(UserCodeAlphabet, 8);
            var expiresAt = DateTime.UtcNow + Lifetime;
            db.DeviceCodes.Add(new DeviceCode
            {
                Id = Ids.New("dvc"),
                DeviceCodeHash = Ids.Sha256Hex(deviceCode),
                UserCode = userCode,
                ClientId = clientId,
                Status = DeviceStatus.Pending,
                ExpiresAt = expiresAt,
            });
            await db.SaveChangesAsync();

            var origin = HandoffEndpoints.PublicOrigin(ctx.Request, options.Value);
            return Results.Json(new
            {
                device_code = deviceCode,
                user_code = userCode,
                verification_uri = $"{origin}/device",
                verification_uri_complete = $"{origin}/device?user_code={userCode}",
                expires_in = (int)Lifetime.TotalSeconds,
                interval = (int)PollInterval.TotalSeconds,
            });
        });

        app.MapPost("/api/auth/device/token", async (HttpContext ctx, DenDbContext db, SessionService sessions, IOptions<AuthOptions> options) =>
        {
            var body = await ReadBodyAsync<DeviceTokenBody>(ctx);
            if (body?.GrantType != GrantType || string.IsNullOrEmpty(body.DeviceCode))
                return OAuthError(400, "invalid_request", "grant_type and device_code are required.");

            var hash = Ids.Sha256Hex(body.DeviceCode);
            var code = await db.DeviceCodes.FirstOrDefaultAsync(d => d.DeviceCodeHash == hash && d.ClientId == body.ClientId);
            if (code is null || code.Status == DeviceStatus.Consumed) return OAuthError(400, "invalid_grant", "Invalid device code.");

            var now = DateTime.UtcNow;
            if (code.ExpiresAt <= now) return OAuthError(400, "expired_token", "The device code has expired.");

            if (code.LastPolledAt is { } last && now - last < PollInterval && code.Status == DeviceStatus.Pending)
            {
                code.LastPolledAt = now;
                await db.SaveChangesAsync();
                return OAuthError(400, "slow_down", "Polling too fast.");
            }
            code.LastPolledAt = now;

            switch (code.Status)
            {
                case DeviceStatus.Denied:
                    await db.SaveChangesAsync();
                    return OAuthError(400, "access_denied", "The sign-in request was denied.");
                case DeviceStatus.Pending:
                    await db.SaveChangesAsync();
                    return OAuthError(400, "authorization_pending", "Waiting for approval.");
            }

            // Approved: consume the code exactly once and mint a session for the approver.
            var consumed = await db.DeviceCodes
                .Where(d => d.Id == code.Id && d.Status == DeviceStatus.Approved)
                .ExecuteUpdateAsync(s => s.SetProperty(d => d.Status, DeviceStatus.Consumed));
            if (consumed == 0) return OAuthError(400, "invalid_grant", "Invalid device code.");

            var user = await db.Users.FirstAsync(u => u.Id == code.UserId);
            var (token, session) = await sessions.CreateAsync(user, code.OrganizationId, "device", ctx);
            return Results.Json(new
            {
                access_token = token,
                token_type = "Bearer",
                expires_in = (int)(session.ExpiresAt - now).TotalSeconds,
                scope = "",
            });
        });

        app.MapGet("/v1/auth/device/{userCode}", async (string userCode, HttpContext ctx, SessionService sessions, DenDbContext db) =>
        {
            if (await sessions.ResolveAsync(ctx) is null) return Responses.Unauthorized();
            var normalized = NormalizeUserCode(userCode);
            var code = await db.DeviceCodes.AsNoTracking().FirstOrDefaultAsync(d => d.UserCode == normalized);
            if (code is null) return Responses.Error(404, "invalid_user_code", "This code is not valid. Check it against your terminal.");
            if (code.ExpiresAt <= DateTime.UtcNow) return Responses.Error(404, "expired_user_code", "This code has expired. Start sign-in again from your terminal.");
            return Results.Json(new { status = code.Status == DeviceStatus.Consumed ? DeviceStatus.Approved : code.Status, clientId = code.ClientId, expiresAt = Responses.IsoUtc(code.ExpiresAt) });
        });

        app.MapPost("/v1/auth/device/decision", async (DeviceDecisionBody? body, HttpContext ctx, SessionService sessions, DenDbContext db) =>
        {
            var current = await sessions.ResolveAsync(ctx);
            if (current is null) return Responses.Unauthorized();
            if (body is null || string.IsNullOrWhiteSpace(body.UserCode) || body.Decision is not ("approve" or "deny"))
                return Responses.Error(400, "invalid_request", "userCode and decision (approve or deny) are required.");

            var normalized = NormalizeUserCode(body.UserCode);
            var code = await db.DeviceCodes.FirstOrDefaultAsync(d => d.UserCode == normalized && d.ExpiresAt > DateTime.UtcNow);
            if (code is null) return Responses.Error(404, "invalid_user_code", "This code is unknown or has expired.");
            if (code.Status != DeviceStatus.Pending) return Responses.Error(409, "already_decided", "This code was already approved or denied.");

            string? organizationId = code.OrganizationId;
            if (body.Decision == "approve")
            {
                var requested = string.IsNullOrWhiteSpace(body.OrganizationId) ? current.Session.ActiveOrganizationId : body.OrganizationId;
                if (requested is not null)
                {
                    var isMember = await db.Members.AnyAsync(m => m.OrganizationId == requested && m.UserId == current.User.Id);
                    if (!isMember) return Responses.Error(403, "forbidden", "You are not a member of that organization.");
                }
                organizationId = requested;
            }

            code.Status = body.Decision == "approve" ? DeviceStatus.Approved : DeviceStatus.Denied;
            code.UserId = current.User.Id;
            code.OrganizationId = organizationId;
            await db.SaveChangesAsync();
            return Results.Json(new { status = code.Status });
        });
    }

    private static IResult OAuthError(int status, string error, string description) =>
        Results.Json(new { error, error_description = description }, statusCode: status);

    private static async Task<T?> ReadBodyAsync<T>(HttpContext ctx) where T : class
    {
        try
        {
            using var doc = await System.Text.Json.JsonDocument.ParseAsync(ctx.Request.Body);
            var root = doc.RootElement;
            // Device clients send snake_case (client_id, device_code, grant_type).
            string? Get(string name) => root.TryGetProperty(name, out var v) && v.ValueKind == System.Text.Json.JsonValueKind.String ? v.GetString() : null;
            object? result = typeof(T) == typeof(DeviceCodeBody)
                ? new DeviceCodeBody(Get("client_id"))
                : new DeviceTokenBody(Get("grant_type"), Get("device_code"), Get("client_id"));
            return (T?)result;
        }
        catch (System.Text.Json.JsonException)
        {
            return null;
        }
    }
}
