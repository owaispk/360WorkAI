using Microsoft.Extensions.Options;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Endpoints;

namespace WorkAI360.Api.OAuth;

/// <summary>The issuer, endpoint and resource URLs. The issuer lives on the web origin; the MCP resource lives on the API origin.</summary>
public sealed class OAuthUrls(IOptions<AuthOptions> options, IHttpContextAccessor accessor)
{
    private readonly AuthOptions _options = options.Value;

    private HttpRequest Request => accessor.HttpContext?.Request ?? throw new InvalidOperationException("No active request.");

    public string Web => (_options.WebUrl is { Length: > 0 } w ? w : HandoffEndpoints.PublicOrigin(Request, _options)).TrimEnd('/');
    public string Api => (_options.ApiPublicUrl is { Length: > 0 } a ? a : $"{Request.Scheme}://{Request.Host}").TrimEnd('/');

    public string Issuer => $"{Web}/api/auth";
    public string AuthorizationEndpoint => $"{Issuer}/oauth2/authorize";
    public string TokenEndpoint => $"{Issuer}/oauth2/token";
    public string RegistrationEndpoint => $"{Issuer}/oauth2/register";
    public string RevocationEndpoint => $"{Issuer}/oauth2/revoke";
    public string JwksUri => $"{Issuer}/jwks";

    /// <summary>The audience of every access token.</summary>
    public string CanonicalResource => $"{Api}/mcp/agent";

    public string ProtectedResourceMetadata => $"{Api}/.well-known/oauth-protected-resource/mcp/agent";

    /// <summary>Maps any accepted spelling of the MCP resource to the canonical one, or null when it is not ours.</summary>
    public string? NormalizeResource(string? resource)
    {
        if (string.IsNullOrWhiteSpace(resource)) return null;
        var candidate = resource.Trim().TrimEnd('/');
        foreach (var host in HostAliases(Api))
        {
            if (candidate == $"{host}/mcp/agent" || candidate == $"{host}/mcp") return CanonicalResource;
        }
        return null;
    }

    /// <summary>localhost, 127.0.0.1 and [::1] name the same machine, so a client configured with either spelling is accepted.</summary>
    private static IEnumerable<string> HostAliases(string origin)
    {
        yield return origin;
        if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri) || !RedirectPolicy.IsLoopback(uri.Host)) yield break;
        foreach (var alias in new[] { "localhost", "127.0.0.1" })
        {
            if (!string.Equals(uri.Host, alias, StringComparison.OrdinalIgnoreCase)) yield return $"{uri.Scheme}://{alias}:{uri.Port}";
        }
    }
}
