using System.Collections.Concurrent;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.OrgAdmin;
using WorkAI360.Api.Features.OrgAdmin;

namespace WorkAI360.Api.Features.WebOrigins;

public sealed class CorsOptions
{
    public const string Section = "Cors";

    /// <summary>Extra exact origins (besides this deployment's own) allowed to call the API from a browser.</summary>
    public string[] Origins { get; set; } = [];
}

/// <summary>
/// Whether an exact https origin was approved by any workspace (Org settings → approved web origins). Answers are cached per process for 30
/// seconds, both ways, so a busy API does not query for every request; changes are dropped from the cache at once on this instance and reach
/// other instances within the 30 seconds. A lookup that fails is a refusal: nobody gains access because the database hiccuped.
/// </summary>
public sealed class WebOriginApprovals(IServiceScopeFactory scopes, ILogger<WebOriginApprovals> logger)
{
    private static readonly TimeSpan Ttl = TimeSpan.FromSeconds(30);
    private const int MaxEntries = 2000;
    private readonly ConcurrentDictionary<string, (bool Approved, DateTime Expires)> _cache = new();
    private long _lastFailureLogged;

    public async Task<bool> IsApprovedByAnyWorkspaceAsync(string origin)
    {
        // Only a canonical exact https origin can ever be approved, so anything else is refused without a lookup.
        if (WebOriginEndpoints.Normalize(origin) != origin) return false;
        if (_cache.TryGetValue(origin, out var hit) && hit.Expires > DateTime.UtcNow) return hit.Approved;
        try
        {
            using var scope = scopes.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<DenDbContext>();
            var approved = await db.Set<OrganizationWebOrigin>().AsNoTracking().AnyAsync(o => o.Origin == origin);
            if (_cache.Count >= MaxEntries) _cache.Clear();
            _cache[origin] = (approved, DateTime.UtcNow + Ttl);
            return approved;
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            var now = Environment.TickCount64;
            if (now - Interlocked.Read(ref _lastFailureLogged) > 60_000) { Interlocked.Exchange(ref _lastFailureLogged, now); logger.LogWarning("approved web origin lookup failed; refusing CORS ({Error})", e.GetType().Name); }
            return false;
        }
    }

    /// <summary>Forgets one origin (or all) so a change takes effect on this instance immediately.</summary>
    public void Invalidate(string? origin = null)
    {
        if (origin is null) _cache.Clear(); else _cache.TryRemove(origin, out _);
    }
}

/// <summary>
/// CORS for browsers on other origins: the strict allowlist is this deployment's own origins, the operator's <c>Cors:Origins</c>, and the exact
/// origins workspaces approved. The desktop-handoff exchange is the one route open to any origin, because it is authenticated only by its
/// one-time, five-minute grant (it never reads cookies or sessions), and preview origins cannot be listed in advance.
/// </summary>
public sealed class WebOriginsFeature : IFeature
{
    private const string HandoffExchange = "/v1/auth/desktop-handoff/exchange";
    private const string StrictHeaders = "Content-Type, Authorization, X-Api-Key, X-Request-Id, X-OpenWork-Legacy-Org-Id, X-OpenWork-Org-Id, X-OpenWork-Audit-Correlation";
    private const string StrictExposed = "Content-Length, Content-Disposition, X-Audit-Next-Cursor, X-Audit-Snapshot-Sequence, X-Audit-Resource-Scope";

    public void AddServices(IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<CorsOptions>(configuration.GetSection(CorsOptions.Section));
        services.AddSingleton<WebOriginApprovals>();
    }

    public void MapEndpoints(WebApplication app)
    {
        var approvals = app.Services.GetRequiredService<WebOriginApprovals>();
        var configured = app.Services.GetRequiredService<IOptions<CorsOptions>>().Value.Origins.Select(Canonical).OfType<string>()
            .Concat(new[] { app.Configuration["Auth:WebUrl"], app.Configuration["Auth:ApiPublicUrl"] }.Select(Canonical).OfType<string>())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        app.Use(async (ctx, next) =>
        {
            var origin = ctx.Request.Headers.Origin.ToString();
            if (origin.Length == 0) { await next(); return; }

            var handoff = ctx.Request.Path.Equals(HandoffExchange, StringComparison.OrdinalIgnoreCase);
            var allowed = handoff || configured.Contains(origin) || await approvals.IsApprovedByAnyWorkspaceAsync(origin);
            if (!allowed) { await next(); return; }        // no CORS headers: the browser refuses to expose the response

            ctx.Response.Headers.Append("Vary", "Origin");
            ctx.Response.Headers["Access-Control-Allow-Origin"] = origin;
            ctx.Response.Headers["Access-Control-Allow-Credentials"] = "true";
            if (!handoff) ctx.Response.Headers["Access-Control-Expose-Headers"] = StrictExposed;
            if (HttpMethods.IsOptions(ctx.Request.Method) && ctx.Request.Headers.ContainsKey("Access-Control-Request-Method"))
            {
                ctx.Response.Headers["Access-Control-Allow-Methods"] = handoff ? "POST, OPTIONS" : "GET, POST, PUT, PATCH, DELETE, OPTIONS";
                ctx.Response.Headers["Access-Control-Allow-Headers"] = handoff ? "Content-Type, Authorization, X-Request-Id" : StrictHeaders;
                ctx.Response.Headers["Access-Control-Max-Age"] = "600";
                ctx.Response.StatusCode = StatusCodes.Status204NoContent;
                return;
            }
            await next();
        });
    }

    private static string? Canonical(string? value) =>
        value is not null && Uri.TryCreate(value, UriKind.Absolute, out var url) ? url.GetLeftPart(UriPartial.Authority).ToLowerInvariant() : null;
}

/// <summary>An approved web return URL for a desktop handoff, and the workspace that approved it.</summary>
public sealed record WebHandoffApproval(string ReturnUrl, string OrganizationId);

public static class WebHandoffReturnUrls
{
    /// <summary>
    /// Same rules as the reference: an https URL with no credentials, fragment or path tricks, whose path is "/" or "/signin"; it is approved when
    /// the active workspace approved that exact origin or, failing that, any workspace the person belongs to did (the handoff then lands them
    /// in that workspace). Null means not approved. The URL handed back is always the origin plus "/signin".
    /// </summary>
    public static async Task<WebHandoffApproval?> ResolveAsync(DenDbContext db, string returnUrl, string? activeOrganizationId, string userId)
    {
        if (returnUrl.Length > 2048 || !Uri.TryCreate(returnUrl, UriKind.Absolute, out var url)) return null;
        if (url.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(url.UserInfo) || !string.IsNullOrEmpty(url.Fragment) || returnUrl.Contains('#')) return null;
        var rawPath = returnUrl[(returnUrl.IndexOf("://", StringComparison.Ordinal) + 3)..];
        rawPath = rawPath.Contains('/') ? rawPath[rawPath.IndexOf('/')..] : "/";
        if (HasTraversal(rawPath) || url.AbsolutePath is not ("/" or "/signin")) return null;
        var origin = url.GetLeftPart(UriPartial.Authority).ToLowerInvariant();
        if (WebOriginEndpoints.Normalize(origin) != origin) return null;

        var signIn = $"{origin}/signin";
        if (activeOrganizationId is not null
            && await db.Set<OrganizationWebOrigin>().AsNoTracking().AnyAsync(o => o.OrganizationId == activeOrganizationId && o.Origin == origin)
            && await db.Members.AsNoTracking().AnyAsync(m => m.OrganizationId == activeOrganizationId && m.UserId == userId))
            return new WebHandoffApproval(signIn, activeOrganizationId);

        var approving = await (from o in db.Set<OrganizationWebOrigin>().AsNoTracking()
                               join m in db.Members.AsNoTracking() on o.OrganizationId equals m.OrganizationId
                               where o.Origin == origin && m.UserId == userId
                               orderby m.CreatedAt, m.Id
                               select o.OrganizationId).FirstOrDefaultAsync();
        return approving is null ? null : new WebHandoffApproval(signIn, approving);
    }

    private static bool HasTraversal(string rawPath)
    {
        var decoded = Uri.UnescapeDataString(rawPath).Replace('\\', '/');
        return decoded.Split('/').Any(s => s is "." or "..") || rawPath.Contains("%2e", StringComparison.OrdinalIgnoreCase) || rawPath.Contains("%2f", StringComparison.OrdinalIgnoreCase) || rawPath.Contains("%5c", StringComparison.OrdinalIgnoreCase);
    }
}
