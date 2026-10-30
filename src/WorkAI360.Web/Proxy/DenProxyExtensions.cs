using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Transforms;

namespace WorkAI360.Web.Proxy;

/// <summary>
/// The web host is the only thing the browser talks to. It forwards auth and API calls to the Den API on the same origin,
/// so session cookies never need a shared parent domain (the same reason the reference den-web proxies /api/auth).
/// </summary>
public static class DenProxyExtensions
{
    public const string ApiBaseUrlKey = "Den:ApiBaseUrl";
    private static readonly string[] AuthCookiePrefixes = ["openwork-den.", "__Secure-openwork-den.", "better-auth.", "__Secure-better-auth."];

    public static void AddDenReverseProxy(this IServiceCollection services, IConfiguration configuration)
    {
        var apiBase = ApiBase(configuration);

        static RouteConfig Route(string id, string path, string? setPath = null, string? pathPattern = null, params string[] methods) => new()
        {
            RouteId = id,
            ClusterId = "api",
            Match = new RouteMatch { Path = path, Methods = methods.Length == 0 ? null : methods },
            Transforms = setPath is not null
                ? [new Dictionary<string, string> { ["PathSet"] = setPath }]
                : pathPattern is not null ? [new Dictionary<string, string> { ["PathPattern"] = pathPattern }] : null,
        };

        RouteConfig[] routes =
        [
            // Aliases the web app calls under /api/auth that are not Better-Auth-style routes upstream.
            Route("login-options", "/api/auth/login-options", setPath: "/v1/auth/login-options", methods: "GET"),
            Route("sso-resolve", "/api/auth/sso-resolve", setPath: "/v1/orgs/sso/resolve", methods: "GET"),
            Route("desktop-handoff", "/api/auth/desktop-handoff", setPath: "/v1/auth/desktop-handoff", methods: "POST"),
            // Everything else under /api/auth goes to the API's auth routes unchanged.
            Route("auth", "/api/auth/{**rest}", pathPattern: "/api/auth/{**rest}"),
            // Cookie-authenticated JSON calls from the browser: /api/browser/v1/x -> API /v1/x.
            Route("browser-v1", "/api/browser/v1/{**rest}", pathPattern: "/v1/{**rest}"),
        ];

        ClusterConfig[] clusters =
        [
            new() { ClusterId = "api", Destinations = new Dictionary<string, DestinationConfig> { ["api"] = new() { Address = apiBase } } },
        ];

        services.AddReverseProxy()
            .LoadFromMemory(routes, clusters)
            .AddTransforms(context => context.AddRequestTransform(transform =>
            {
                // Only the session cookie crosses to the API; unrelated cookies on the web origin stay here.
                if (transform.HttpContext.Request.Cookies.Count == 0) return ValueTask.CompletedTask;
                var kept = transform.HttpContext.Request.Cookies
                    .Where(c => AuthCookiePrefixes.Any(p => c.Key.StartsWith(p, StringComparison.Ordinal)))
                    .Select(c => $"{c.Key}={Uri.EscapeDataString(c.Value)}");
                transform.ProxyRequest.Headers.Remove("Cookie");
                var joined = string.Join("; ", kept);
                if (joined.Length > 0) transform.ProxyRequest.Headers.TryAddWithoutValidation("Cookie", joined);
                return ValueTask.CompletedTask;
            }));
    }

    public static string ApiBase(IConfiguration configuration) =>
        (configuration[ApiBaseUrlKey] ?? "http://localhost:5080").TrimEnd('/') + "/";

    public static void MapDenLocalEndpoints(this WebApplication app)
    {
        app.MapGet("/api/health", () => Results.Json(new { ok = true, service = "den-web" }));

        app.MapGet("/api/ready", async (IConfiguration configuration) =>
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
            try
            {
                using var response = await http.GetAsync(new Uri(new Uri(ApiBase(configuration)), "health"));
                return response.IsSuccessStatusCode ? Results.Json(new { ok = true }) : Results.Json(new { ok = false, reason = "api_unhealthy" }, statusCode: 503);
            }
            catch (HttpRequestException)
            {
                return Results.Json(new { ok = false, reason = "api_unreachable" }, statusCode: 503);
            }
        });

        // What the browser needs to know about this deployment.
        app.MapGet("/api/runtime-config", (IConfiguration configuration, HttpRequest request) => Results.Json(new
        {
            denApiUrl = configuration["Den:ApiPublicUrl"] ?? ApiBase(configuration).TrimEnd('/'),
            orgMode = "multi_org",
            openworkWebUrl = $"{request.Scheme}://{request.Host}",
        }));

        // Clears the session cookie when /v1/me answers 401 (used by the web app's request helper).
        app.MapPost("/api/auth/clear-session-cookie", (HttpResponse response, HttpRequest request) =>
        {
            foreach (var name in new[] { "openwork-den.session_token", "__Secure-openwork-den.session_token" })
            {
                response.Cookies.Append(name, "", new CookieOptions { Path = "/", HttpOnly = true, SameSite = SameSiteMode.Lax, Secure = request.IsHttps, MaxAge = TimeSpan.Zero, Expires = DateTimeOffset.UnixEpoch });
            }
            return Results.Json(new { ok = true });
        });
    }
}
