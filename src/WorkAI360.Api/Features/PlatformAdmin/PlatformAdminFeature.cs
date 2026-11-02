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
        services.Configure<PlatformAdminOptions>(configuration.GetSection(PlatformAdminOptions.Section));
        services.AddScoped<PlatformAdmins>();
        services.AddScoped<PlatformAdminGuard>();
        services.AddScoped<FeatureResolver>();
        services.AddScoped<FeatureChanges>();
        services.AddScoped<OrganizationPlans>();
    }

    public void MapEndpoints(WebApplication app)
    {
        app.MapAdminAccountEndpoints();
        app.MapAdminOrganizationEndpoints();
        app.MapAdminFeatureEndpoints();
    }
}
