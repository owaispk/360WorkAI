namespace WorkAI360.Api.Features.Scim;

/// <summary>SCIM provisioning: the settings API and the SCIM 2.0 server identity providers talk to.</summary>
public sealed class ScimFeature : IFeature
{
    public void AddServices(IServiceCollection services, IConfiguration configuration) => services.AddScoped<ScimService>();

    public void MapEndpoints(WebApplication app)
    {
        ScimAdminEndpoints.Map(app);
        ScimProtocolEndpoints.Map(app);
    }
}
