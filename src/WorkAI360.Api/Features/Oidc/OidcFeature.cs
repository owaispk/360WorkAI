namespace WorkAI360.Api.Features.Oidc;

/// <summary>
/// The OpenID Connect part of the OAuth provider: ID tokens (issued by <see cref="IdTokenIssuer"/> from the token endpoint), userinfo,
/// introspection and RP-initiated logout. Discovery lists them in <c>OAuthEndpoints.AuthorizationServerMetadata</c>.
/// </summary>
public sealed class OidcFeature : IFeature
{
    public void AddServices(IServiceCollection services, IConfiguration configuration) => services.AddScoped<IdTokenIssuer>();

    public void MapEndpoints(WebApplication app)
    {
        OidcEndpoints.Map(app);
        EndSessionEndpoints.Map(app);
    }
}
