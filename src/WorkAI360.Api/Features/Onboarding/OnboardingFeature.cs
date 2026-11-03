using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Onboarding;
using WorkAI360.Api.Auth;

namespace WorkAI360.Api.Features.Onboarding;

/// <summary>
/// Everything between sign-up and a configured workspace: what the signed-in person sees about themselves (profile, invitations waiting for them,
/// the install configuration, the download-link email), the install page's routes, "provision now, claim later" workspaces made by an agent,
/// the diagnostics a desktop app reports, and the resource snapshot desktops poll. See docs/features/onboarding.md.
/// </summary>
public sealed class OnboardingFeature : IFeature
{
    public void AddServices(IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<OnboardingOptions>(configuration.GetSection(OnboardingOptions.Section));
        services.AddScoped<WindowLimiter>();
        services.AddScoped<BootstrapService>();
    }

    public void MapEndpoints(WebApplication app)
    {
        app.MapMeEndpoints();
        app.MapInstallEndpoints();
        app.MapBootstrapEndpoints();
        app.MapDiagnosticsEndpoints();
        app.MapResourceEndpoints();
        app.MapActivationEndpoints();
    }
}

public sealed class OnboardingOptions
{
    public const string Section = "Onboarding";

    public DesktopOptions Desktop { get; set; } = new();

    public BootstrapOptions Bootstrap { get; set; } = new();

    /// <summary>Where the "download OpenWork" link in the emailed message points. Empty: this deployment's install page.</summary>
    public string DownloadUrl { get; set; } = "";

    /// <summary>The synthetic diagnostics target (an origin that answers the fixed probes). Empty: the egress check reports "not configured".</summary>
    public string DiagnosticsOrigin { get; set; } = "";

    /// <summary>Environment-level diagnostics token, used when a workspace stored none of its own.</summary>
    public string DiagnosticsBearerToken { get; set; } = "";

    public sealed class BootstrapOptions
    {
        /// <summary>How long a provisional workspace and its claim links last.</summary>
        public int ExpiresHours { get; set; } = 72;

        /// <summary>Workspaces one address may provision per hour (the reference allows 5).</summary>
        public int LimitPerHour { get; set; } = 5;

        public int CodeMinutes { get; set; } = 15;
    }

    public sealed class DesktopOptions
    {
        /// <summary>The newest desktop version people should run. This rewrite does not read GitHub's releases; the operator names the versions.</summary>
        public string LatestVersion { get; set; } = "0.18.46";

        public string MinAppVersion { get; set; } = "0.17.0";

        /// <summary>Stable versions the install page and the app may offer, newest first. Empty: just <see cref="LatestVersion"/>.</summary>
        public string[] PublishedVersions { get; set; } = [];

        /// <summary>Release downloads redirect here: <c>{ReleaseBase}/v{version}/{file}</c>.</summary>
        public string ReleaseBase { get; set; } = "https://github.com/different-ai/openwork/releases/download";

        /// <summary>A folder holding installers named as in the release (for an air-gapped install). A file found here is served instead of redirecting.</summary>
        public string ArtifactsDir { get; set; } = "";
    }
}

/// <summary>
/// "At most N of this per window", kept in the database so every instance agrees. Every step is one conditional update, so two requests racing at
/// the limit cannot both get the last slot. Returns how many seconds to wait when the limit is reached, else null (and counts the use).
/// </summary>
public sealed class WindowLimiter(DenDbContext db)
{
    public async Task<int?> HitAsync(string key, int max, TimeSpan window)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var windowMs = (long)window.TotalMilliseconds;
        var set = db.Set<OnboardingRateLimit>();
        for (var attempt = 0; attempt < 4; attempt++)
        {
            // Inside the window and under the limit: count one.
            if (await set.Where(r => r.Key == key && r.WindowStart > now - windowMs && r.Count < max).ExecuteUpdateAsync(u => u.SetProperty(r => r.Count, r => r.Count + 1)) == 1) return null;
            // The window has passed: start a new one.
            if (await set.Where(r => r.Key == key && r.WindowStart <= now - windowMs).ExecuteUpdateAsync(u => u.SetProperty(r => r.Count, 1).SetProperty(r => r.WindowStart, now)) == 1) return null;
            var row = await set.AsNoTracking().FirstOrDefaultAsync(r => r.Key == key);
            if (row is not null) return Math.Max(1, (int)Math.Ceiling((windowMs - (now - row.WindowStart)) / 1000.0));
            try
            {
                set.Add(new OnboardingRateLimit { Id = Ids.New("rl"), Key = key, Count = 1, WindowStart = now });
                await db.SaveChangesAsync();
                return null;
            }
            catch (DbUpdateException) { db.ChangeTracker.Clear(); }
        }
        return null;
    }
}
