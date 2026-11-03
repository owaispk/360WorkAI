using WorkAI360.Api.Auth;

namespace WorkAI360.Api.Features.Sso;

/// <summary>Single sign-on (OpenID Connect): the workspace's settings, domain proof, the test, and the sign-in itself.</summary>
public sealed class SsoFeature : IFeature
{
    public void AddServices(IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<SsoOptions>(configuration.GetSection(SsoOptions.Section));
        services.AddSingleton<SecretProtector>();
        services.AddSingleton<IDnsTxtResolver, SystemDnsTxtResolver>();
        services.AddHttpClient(IdpHttp.ClientName)
            .ConfigurePrimaryHttpMessageHandler(sp =>
            {
                var options = configuration.GetSection(SsoOptions.Section).Get<SsoOptions>() ?? new SsoOptions();
                var env = sp.GetRequiredService<IHostEnvironment>();
                return IdpHttp.CreateHandler(options.AllowPrivateNetworks ?? env.IsDevelopment());
            })
            .ConfigureHttpClient(c => c.Timeout = TimeSpan.FromSeconds(10));
        services.AddScoped<SsoService>();
        services.AddScoped<SsoProvisioning>();
        services.AddScoped<SsoRouting>();
        services.AddScoped<OidcFlow>();
        services.AddScoped<SamlFlow>();
    }

    public void MapEndpoints(WebApplication app)
    {
        SsoAdminEndpoints.Map(app);
        SsoSignInEndpoints.Map(app);
        SamlEndpoints.Map(app);
    }
}
