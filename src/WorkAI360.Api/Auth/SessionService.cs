using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;

namespace WorkAI360.Api.Auth;

/// <summary>The signed-in caller of the current request.</summary>
public sealed record AuthContext(User User, Session Session, string PresentedToken);

public sealed class SessionService(DenDbContext db, IOptions<AuthOptions> options)
{
    private readonly AuthOptions _options = options.Value;

    public async Task<(string Token, Session Session)> CreateAsync(User user, string? activeOrganizationId, string method, HttpContext ctx)
    {
        var token = Ids.RandomAlnum(32);
        var now = DateTime.UtcNow;
        var session = new Session
        {
            Id = Ids.New("ses"),
            TokenHash = Ids.Sha256Hex(token),
            UserId = user.Id,
            ActiveOrganizationId = activeOrganizationId,
            Method = method,
            IpAddress = ctx.Connection.RemoteIpAddress?.ToString(),
            UserAgent = ctx.Request.Headers.UserAgent.ToString() is { Length: > 0 } ua ? ua[..Math.Min(ua.Length, 256)] : null,
            CreatedAt = now,
            UpdatedAt = now,
            ExpiresAt = now.AddDays(_options.SessionDays),
        };
        db.Sessions.Add(session);
        await db.SaveChangesAsync();
        return (token, session);
    }

    /// <summary>Cookie first, then bearer: the same precedence the reference API uses.</summary>
    public async Task<AuthContext?> ResolveAsync(HttpContext ctx)
    {
        if (ctx.Items.TryGetValue(typeof(AuthContext), out var cached)) return cached as AuthContext;

        AuthContext? resolved = null;
        var cookieToken = ReadCookieToken(ctx.Request);
        if (cookieToken is not null) resolved = await LookupAsync(cookieToken);
        if (resolved is null && ReadBearer(ctx.Request) is { } bearer) resolved = await LookupAsync(bearer);

        ctx.Items[typeof(AuthContext)] = resolved;
        return resolved;
    }

    private async Task<AuthContext?> LookupAsync(string token)
    {
        var hash = Ids.Sha256Hex(token);
        var now = DateTime.UtcNow;
        var session = await db.Sessions.FirstOrDefaultAsync(s => s.TokenHash == hash && s.ExpiresAt > now);
        if (session is null) return null;
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == session.UserId);
        return user is null ? null : new AuthContext(user, session, token);
    }

    public async Task<bool> RevokeAsync(string token)
    {
        var hash = Ids.Sha256Hex(token);
        return await db.Sessions.Where(s => s.TokenHash == hash).ExecuteDeleteAsync() > 0;
    }

    public void WriteCookie(HttpContext ctx, string token, Session session)
    {
        var maxAge = session.ExpiresAt - DateTime.UtcNow;
        ctx.Response.Cookies.Append(_options.CookieName, $"{token}.{Sign(token)}", new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Lax,
            Secure = ctx.Request.IsHttps,
            Path = "/",
            MaxAge = maxAge,
        });
    }

    public void ClearCookie(HttpContext ctx) =>
        ctx.Response.Cookies.Append(_options.CookieName, "", new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Lax,
            Secure = ctx.Request.IsHttps,
            Path = "/",
            MaxAge = TimeSpan.Zero,
            Expires = DateTimeOffset.UnixEpoch,
        });

    public string? ReadCookieToken(HttpRequest request)
    {
        foreach (var name in new[] { _options.CookieName, "__Secure-" + _options.CookieName })
        {
            if (!request.Cookies.TryGetValue(name, out var raw) || string.IsNullOrEmpty(raw)) continue;
            var dot = raw.LastIndexOf('.');
            if (dot <= 0) continue;
            var token = raw[..dot];
            var signature = raw[(dot + 1)..];
            if (CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(Sign(token)), Encoding.UTF8.GetBytes(signature))) return token;
        }
        return null;
    }

    public static string? ReadBearer(HttpRequest request)
    {
        var header = request.Headers.Authorization.ToString().Trim();
        if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return null;
        var token = header["Bearer ".Length..].Trim();
        return token.Length == 0 ? null : token;
    }

    private string Sign(string token) =>
        Convert.ToBase64String(HMACSHA256.HashData(Encoding.UTF8.GetBytes(_options.Secret), Encoding.UTF8.GetBytes(token)));
}
