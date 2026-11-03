using Microsoft.Extensions.Options;

namespace WorkAI360.Api.Features.Social;

/// <summary>
/// One provider's settings. A provider is on only when both its client id and its secret are set (the reference's rule). The endpoint
/// settings default to the real service and are overridden only to point tests and local runs at a fake provider.
/// </summary>
public sealed class SocialProviderOptions
{
    public string? ClientId { get; set; }
    public string? ClientSecret { get; set; }
    public string? AuthorizationEndpoint { get; set; }
    public string? TokenEndpoint { get; set; }
    /// <summary>Google: where its ID-token signing keys are published.</summary>
    public string? JwksUri { get; set; }
    /// <summary>Google: the issuer its ID tokens must carry.</summary>
    public string? Issuer { get; set; }
    /// <summary>GitHub: the API base (<c>/user</c> and <c>/user/emails</c> are read from here).</summary>
    public string? ApiBase { get; set; }
}

public sealed class SocialOptions
{
    public const string Section = "SocialProviders";
    public SocialProviderOptions Google { get; set; } = new();
    public SocialProviderOptions GitHub { get; set; } = new();
    /// <summary>Let the provider endpoints be on private or loopback addresses (local runs and tests only). Default: true in Development.</summary>
    public bool? AllowPrivateNetworks { get; set; }
}

/// <summary>A provider that is switched on, with every endpoint filled in.</summary>
public sealed record SocialProvider(string Name, string Label, string ClientId, string ClientSecret, string AuthorizationEndpoint, string TokenEndpoint, string Scope, string? JwksUri, string? Issuer, string? ApiBase)
{
    public bool IsGoogle => Name == "google";
}

public sealed class SocialProviders(IOptions<SocialOptions> options)
{
    public const string GoogleIssuer = "https://accounts.google.com";

    /// <summary>The providers that are on, in the order the sign-in form shows them.</summary>
    public IReadOnlyList<SocialProvider> Enabled()
    {
        var list = new List<SocialProvider>();
        var google = options.Value.Google;
        if (Set(google)) list.Add(new("google", "Google", google.ClientId!.Trim(), google.ClientSecret!.Trim(),
            Or(google.AuthorizationEndpoint, "https://accounts.google.com/o/oauth2/v2/auth"), Or(google.TokenEndpoint, "https://oauth2.googleapis.com/token"),
            "openid email profile", Or(google.JwksUri, "https://www.googleapis.com/oauth2/v3/certs"), Or(google.Issuer, GoogleIssuer), null));
        var github = options.Value.GitHub;
        if (Set(github)) list.Add(new("github", "GitHub", github.ClientId!.Trim(), github.ClientSecret!.Trim(),
            Or(github.AuthorizationEndpoint, "https://github.com/login/oauth/authorize"), Or(github.TokenEndpoint, "https://github.com/login/oauth/access_token"),
            "read:user user:email", null, null, Or(github.ApiBase, "https://api.github.com").TrimEnd('/')));
        return list;
    }

    public SocialProvider? Find(string? name) => Enabled().FirstOrDefault(p => p.Name == name);

    private static bool Set(SocialProviderOptions o) => !string.IsNullOrWhiteSpace(o.ClientId) && !string.IsNullOrWhiteSpace(o.ClientSecret);
    private static string Or(string? value, string fallback) => string.IsNullOrWhiteSpace(value) ? fallback : value.Trim();
}
