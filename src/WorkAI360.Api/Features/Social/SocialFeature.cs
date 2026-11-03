using WorkAI360.Api.Auth;
using WorkAI360.Api.Endpoints;
using WorkAI360.Api.Features.Sso;

namespace WorkAI360.Api.Features.Social;

/// <summary>
/// Sign-in with Google and GitHub: <c>POST /api/auth/sign-in/social</c> (answers <c>{url, redirect}</c>), the provider's return at
/// <c>GET /api/auth/callback/{provider}</c>, and <c>GET /api/auth/social-providers</c> (which providers are switched on, for the sign-in form).
/// A provider is on only when <c>SocialProviders:Google|GitHub:ClientId</c> and <c>ClientSecret</c> are both set.
/// </summary>
public sealed class SocialFeature : IFeature
{
    public static readonly AuthLimitPolicy StartLimit = new("social-start", TimeSpan.FromMinutes(5), 20, 100);
    public static readonly AuthLimitPolicy CallbackLimit = new("social-callback", TimeSpan.FromMinutes(5), 20, 200);

    public void AddServices(IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<SocialOptions>(configuration.GetSection(SocialOptions.Section));
        services.AddSingleton<SocialProviders>();
        services.AddHttpClient(SocialFlow.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(sp =>
            {
                var options = configuration.GetSection(SocialOptions.Section).Get<SocialOptions>() ?? new SocialOptions();
                var env = sp.GetRequiredService<IHostEnvironment>();
                return IdpHttp.CreateHandler(options.AllowPrivateNetworks ?? env.IsDevelopment());
            })
            .ConfigureHttpClient(c => c.Timeout = TimeSpan.FromSeconds(10));
        services.AddScoped<SocialFlow>();
    }

    private static IResult Message(int status, string message, string? code = null) =>
        code is null ? Results.Json(new { message }, statusCode: status) : Results.Json(new { message, code }, statusCode: status);

    public void MapEndpoints(WebApplication app)
    {
        app.MapGet("/api/auth/social-providers", (SocialProviders providers) => Results.Json(new { providers = providers.Enabled().Select(p => p.Name) }));

        app.MapPost("/api/auth/sign-in/social", async (HttpContext ctx, SocialProviders providers, SocialFlow flow, TrustedUrls trusted, RateLimiter limiter) =>
        {
            if (limiter.Hit(StartLimit, null, AuthEndpoints.ClientIp(ctx)) is { } wait) return AuthEndpoints.TooManyRequests(ctx, wait);
            var body = await BodyReader.ReadAsync(ctx.Request);
            string? Opt(string name) => body.String(name, false) is { Length: > 0 } s ? s.Trim() : null;
            var provider = body.String("provider", true);
            var callback = Opt("callbackURL"); var errorCallback = Opt("errorCallbackURL"); var newUserCallback = Opt("newUserCallbackURL");
            var requestSignUp = body.Bool("requestSignUp") ?? false;
            if (provider is null) return Message(400, "[body.provider] Invalid input", "VALIDATION_ERROR");
            if (body.Details.Count > 0) return Message(400, "Invalid request body.", "VALIDATION_ERROR");

            // Open-redirect guard first, as the reference does: only this site's own pages may be returned to.
            if (callback is not null && !trusted.IsTrusted(callback)) return Message(403, "Invalid callbackURL", "INVALID_CALLBACK_URL");
            if (errorCallback is not null && !trusted.IsTrusted(errorCallback)) return Message(403, "Invalid errorCallbackURL", "INVALID_ERROR_CALLBACK_URL");
            if (newUserCallback is not null && !trusted.IsTrusted(newUserCallback)) return Message(403, "Invalid newUserCallbackURL", "INVALID_NEW_USER_CALLBACK_URL");

            var p = providers.Find(provider);
            if (p is null) return Message(404, "Provider not found", "PROVIDER_NOT_FOUND");

            var url = await flow.StartAsync(ctx, p, new SocialFlow.Start(callback ?? "/", errorCallback, newUserCallback, requestSignUp), ctx.RequestAborted);
            return Results.Json(new { url, redirect = body.Bool("disableRedirect") != true });
        });

        app.MapGet("/api/auth/callback/{provider}", async (string provider, HttpContext ctx, SocialFlow flow, RateLimiter limiter) =>
        {
            if (limiter.Hit(CallbackLimit, null, AuthEndpoints.ClientIp(ctx)) is { } wait) return AuthEndpoints.TooManyRequests(ctx, wait);
            return await flow.CallbackAsync(ctx, provider, ctx.RequestAborted);
        });
    }
}
