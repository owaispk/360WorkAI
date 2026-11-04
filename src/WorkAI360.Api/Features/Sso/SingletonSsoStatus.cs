using WorkAI360.Api.OAuth;

namespace WorkAI360.Api.Features.Sso;

/// <summary>
/// The reference's <c>GET /v1/orgs/sso/singleton</c> (public). It serves the reference's single-organization mode, which this build does not
/// have: every deployment here is multi-workspace, so the answer is the reference's answer when that mode is off. <c>configured</c> is always
/// false, and the slug and sign-in path are the reference's defaults (its single-organization slug defaults to "default").
/// </summary>
public sealed class SingletonSsoStatusFeature : IFeature
{
    private const string DefaultSlug = "default";

    public void AddServices(IServiceCollection services, IConfiguration configuration) { }

    public void MapEndpoints(WebApplication app)
    {
        app.MapGet("/v1/orgs/sso/singleton", (OAuthUrls urls) =>
        {
            var signInPath = SsoService.SignInPathFor(DefaultSlug);
            return Results.Json(new { configured = false, organizationSlug = DefaultSlug, signInPath, signInUrl = urls.Web + signInPath });
        });
    }
}
