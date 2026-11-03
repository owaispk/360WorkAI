namespace WorkAI360.Api.Features.PlatformAdmin;

/// <summary>
/// Platform administration: what the operator of a deployment (not a workspace owner) can see and change. Who counts as one, users, workspaces
/// (plan fields, DPA, web access, per-workspace feature overrides), the feature registry with its rollout and kill switch, overview and metrics,
/// and the admin list itself. See docs/features/platform-admin.md.
/// </summary>
public sealed class PlatformAdminFeature : IFeature
{
    public void AddServices(IServiceCollection services, IConfiguration configuration)
    {
        // BootstrapEmails is a comma separated string in an environment variable and an array in a settings file; both are read.
        services.Configure<PlatformAdminOptions>(options =>
        {
            var section = configuration.GetSection($"{PlatformAdminOptions.Section}:BootstrapEmails");
            options.BootstrapEmails = [.. section.GetChildren().Select(c => c.Value).Where(v => !string.IsNullOrWhiteSpace(v)).Select(v => v!), .. section.Value is { Length: > 0 } single ? new[] { single } : []];
        });
        services.AddScoped<PlatformAdmins>();
        services.AddScoped<PlatformAdminGuard>();
        services.AddScoped<FeatureResolver>();
        services.AddScoped<FeatureChanges>();
        services.AddScoped<OrganizationPlans>();
        services.AddScoped<FeatureUsageStore>();
    }

    public void MapEndpoints(WebApplication app)
    {
        app.MapAdminAccountEndpoints();
        app.MapAdminOrganizationEndpoints();
        app.MapAdminFeatureEndpoints();
        app.MapAdminFeatureUsageEndpoints();
        app.MapAdminSecurityEndpoints();
        app.MapAdminServicesEndpoints();
    }
}
