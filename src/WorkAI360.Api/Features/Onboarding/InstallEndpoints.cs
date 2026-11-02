using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Endpoints;
using WorkAI360.Api.Features.OrgAdmin;
using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Features.Onboarding;

/// <summary>The install page's routes: what the app needs to know about this deployment, where each installer comes from, and which versions exist.</summary>
public static partial class InstallEndpoints
{
    public static readonly string[] Platforms = ["mac-arm64", "mac-x64", "win-x64", "linux-x64", "linux-arm64"];
    private static readonly TimeSpan Window = TimeSpan.FromHours(1);
    private const int ConfigLimit = 60, ArtifactLimit = 20;

    [GeneratedRegex("^org_[0-9a-hjkmnp-tv-z]{26}$")]
    private static partial Regex OrgIdPattern();

    public static void MapInstallEndpoints(this WebApplication app)
    {
        app.MapGet("/v1/app-version", (HttpContext ctx, IOptions<OnboardingOptions> options, OAuthUrls urls) =>
        {
            var d = options.Value.Desktop;
            ctx.Response.Headers.CacheControl = "public, max-age=300, stale-if-error=86400";
            var published = d.PublishedVersions.Length > 0 ? d.PublishedVersions : [d.LatestVersion];
            return Results.Json(new { minAppVersion = d.MinAppVersion, latestAppVersion = d.LatestVersion, publishedDesktopVersions = published, webUrl = urls.Web });
        });

        // The organization-scoped version: the signed-in member's active workspace names the branding and may pin the desktop version.
        app.MapGet("/v1/me/install-config", async (HttpContext ctx, OrgAccess access, DenDbContext db, OAuthUrls urls, IOptions<OnboardingOptions> options) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            var settings = await OrgSettings.GetAsync(db, context!.Organization.Id);
            var metadata = OrgSettings.Metadata(settings);
            return Results.Json(Config(context.Organization.Name, metadata, urls, ReleaseVersion(options.Value, metadata)));
        });

        // The public version names no workspace at all: only the server addresses and that signing in is required.
        app.MapGet("/v1/install-config", async (HttpContext ctx, WindowLimiter limiter, OAuthUrls urls, IOptions<OnboardingOptions> options) =>
        {
            if (await limiter.HitAsync($"install:config:{AuthEndpoints.ClientIp(ctx)}", ConfigLimit, Window) is { } wait)
                return Limited(ctx, wait, "Too many install configuration requests. Try again later.");
            return Results.Json(Config("OpenWork Cloud", new System.Text.Json.Nodes.JsonObject(), urls, options.Value.Desktop.LatestVersion, branded: false));
        });

        // Older install pages linked here with a token; it is ignored and the person lands on the normal install page.
        app.MapGet("/v1/install/{platform}", (OAuthUrls urls) => Results.Redirect(urls.Web + "/install", permanent: false));

        app.MapGet("/v1/me/install/{platform}", async (string platform, HttpContext ctx, OrgAccess access, DenDbContext db, WindowLimiter limiter, IOptions<OnboardingOptions> options) =>
        {
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            if (!Platforms.Contains(platform))
                return Results.Json(new { error = "invalid_request", details = new[] { new { code = "invalid_value", values = Platforms, path = new[] { "platform" }, message = "Invalid option: expected one of " + string.Join("|", Platforms.Select(p => $"\"{p}\"")) } } }, statusCode: 400);
            if (await limiter.HitAsync($"install:artifact:{AuthEndpoints.ClientIp(ctx)}", ArtifactLimit, Window) is { } wait)
                return Limited(ctx, wait, "Too many installer download attempts. Try again later.");

            var metadata = OrgSettings.Metadata(await OrgSettings.GetAsync(db, context!.Organization.Id));
            var version = ReleaseVersion(options.Value, metadata);
            var file = AssetName(platform, version);
            var dir = options.Value.Desktop.ArtifactsDir;
            if (dir.Length > 0)
            {
                // Only a plain file name inside the folder: the name is built from our own constants, never from the request.
                var path = Path.Combine(dir, file);
                if (File.Exists(path))
                {
                    ctx.Response.Headers.CacheControl = "private, max-age=300";
                    return Results.File(path, ContentType(platform), file);
                }
            }
            return Results.Redirect($"{options.Value.Desktop.ReleaseBase.TrimEnd('/')}/v{version}/{Uri.EscapeDataString(file)}", permanent: false);
        });

        // Install pages carry no token any more: the answer is the same normal page for anyone in the workspace, and nothing is created.
        app.MapPost("/v1/orgs/{organizationId}/install-links", async (string organizationId, HttpContext ctx, OrgAccess access, OAuthUrls urls) =>
        {
            if (!OrgIdPattern().IsMatch(organizationId))
                return Results.Json(new { error = "invalid_request", details = new[] { new { code = "custom", path = Array.Empty<string>(), message = "TypeID is structurally invalid" } } }, statusCode: 400);
            var (context, failure) = await access.ResolveAsync(ctx);
            if (failure is not null) return failure;
            // The workspace in the path must be the caller's own: another workspace's id reads as not found, whatever its state.
            if (context!.Organization.Id != organizationId) return Results.Json(new { error = "organization_not_found" }, statusCode: 404);
            return Results.Json(new { installPageUrl = urls.Web + "/install" });
        });
    }

    private static IResult Limited(HttpContext ctx, int wait, string message)
    {
        ctx.Response.Headers.RetryAfter = wait.ToString();
        return Results.Json(new { error = "rate_limited", message }, statusCode: 429);
    }

    private static object Config(string clientName, System.Text.Json.Nodes.JsonObject metadata, OAuthUrls urls, string version, bool branded = true) => new
    {
        appName = branded && metadata["brandAppName"]?.GetValue<string>() is { Length: > 0 } app ? app : "OpenWork",
        clientName,
        webUrl = urls.Web,
        apiUrl = urls.Api,
        requireSignin = true,
        logoUrl = branded ? metadata["brandLogoUrl"]?.GetValue<string>() : null,
        iconUrl = branded ? metadata["brandIconUrl"]?.GetValue<string>() : null,
        desktopVersion = version,
        distribution = "cloud",
    };

    /// <summary>The newest version a workspace allows (its approved list, when it has one), else the deployment's latest.</summary>
    public static string ReleaseVersion(OnboardingOptions options, System.Text.Json.Nodes.JsonObject metadata)
    {
        var allowed = (metadata["allowedDesktopVersions"] as System.Text.Json.Nodes.JsonArray)?.Select(n => n?.GetValue<string>()).Where(v => !string.IsNullOrWhiteSpace(v)).Select(v => v!.Trim().TrimStart('v', 'V')).ToList();
        if (allowed is null || allowed.Count == 0) return options.Desktop.LatestVersion;
        string? best = null;
        foreach (var version in allowed) if (best is null || Compare(version, best) is > 0) best = version;
        return best ?? options.Desktop.LatestVersion;
    }

    /// <summary>Semantic-version order (release numbers, then a version with a pre-release tag sorts before the plain one). Null when either is not a version.</summary>
    public static int? Compare(string left, string right)
    {
        if (!Parse(left, out var l, out var lp) || !Parse(right, out var r, out var rp)) return null;
        for (var i = 0; i < 3; i++) if (l[i] != r[i]) return l[i] < r[i] ? -1 : 1;
        if (lp.Length == 0 && rp.Length == 0) return 0;
        if (lp.Length == 0) return 1;
        if (rp.Length == 0) return -1;
        for (var i = 0; i < Math.Max(lp.Length, rp.Length); i++)
        {
            if (i >= lp.Length) return -1;
            if (i >= rp.Length) return 1;
            var ln = long.TryParse(lp[i], out var a); var rn = long.TryParse(rp[i], out var b);
            if (ln && rn) { if (a != b) return a < b ? -1 : 1; continue; }
            if (ln) return -1;
            if (rn) return 1;
            var c = string.CompareOrdinal(lp[i], rp[i]);
            if (c != 0) return c < 0 ? -1 : 1;
        }
        return 0;
    }

    private static bool Parse(string value, out long[] release, out string[] pre)
    {
        release = []; pre = [];
        var v = value.Trim().TrimStart('v', 'V').Split('+')[0];
        var dash = v.IndexOf('-');
        var core = dash < 0 ? v : v[..dash];
        pre = dash < 0 ? [] : v[(dash + 1)..].Split('.', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var parts = core.Split('.');
        if (parts.Length != 3) return false;
        var numbers = new long[3];
        for (var i = 0; i < 3; i++) if (!long.TryParse(parts[i], out numbers[i]) || numbers[i] < 0) return false;
        release = numbers;
        return true;
    }

    public static string AssetName(string platform, string version) => platform switch
    {
        "mac-arm64" or "mac-x64" => $"openwork-cloud-{platform}-{version}.dmg",
        "win-x64" => $"openwork-cloud-win-x64-{version}.exe",
        "linux-x64" => $"openwork-cloud-linux-x86_64-{version}.AppImage",
        _ => $"openwork-cloud-linux-arm64-{version}.AppImage",
    };

    private static string ContentType(string platform) => platform.StartsWith("mac-") ? "application/x-apple-diskimage" : platform == "win-x64" ? "application/vnd.microsoft.portable-executable" : "application/vnd.appimage";
}
