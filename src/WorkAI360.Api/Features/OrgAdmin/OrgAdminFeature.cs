using WorkAI360.Api.Auth;

namespace WorkAI360.Api.Features.OrgAdmin;

/// <summary>
/// Organization administration plumbing: API keys, the audit log, organization settings (name, allowed email domains, branding, approved web
/// origins), deleting a workspace, feature flags and a few small routes clients poll. See docs/features/org-admin.md.
/// </summary>
public sealed class OrgAdminFeature : IFeature
{
    public void AddServices(IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<OrgAdminOptions>(configuration.GetSection(OrgAdminOptions.Section));
        services.AddSingleton<ApiKeyLimiter>();
        services.AddScoped<ApiKeyAuthenticator>();
        services.AddScoped<AuditPolicies>();
        services.AddScoped<IAuditLog, AuditLog>();
        services.AddScoped<OrgEnvelope>();
    }

    public void MapEndpoints(WebApplication app)
    {
        app.MapApiKeyEndpoints();
        app.MapAuditEndpoints();
        app.MapOrgSettingsEndpoints();
        app.MapWebOriginEndpoints();
        app.MapBrandAssetEndpoints();
        AuditRoutes.UseAuditRequestCapture(app);
    }
}
