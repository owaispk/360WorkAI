using System.Text.Json;
using WorkAI360.Api.Domain;
using WorkAI360.Api.Domain.Sso;

namespace WorkAI360.Api.Features.Sso;

public sealed record SamlRegistration(string Issuer, string Domain, string EntryPoint, string Certificate, string? Audience, string? Binding);

/// <summary>The SAML half of a workspace's connection: saving it and the URLs the identity provider administrator needs.</summary>
public sealed partial class SsoService
{
    public const string DefaultSamlBinding = "redirect";

    public static SamlSettings? SamlSettingsOf(SsoConnection c) =>
        c.Kind == "saml" && c.SamlConfigJson is not null ? JsonSerializer.Deserialize<SamlSettings>(c.SamlConfigJson, Json) : null;

    /// <summary>Where the identity provider posts its response (the same address for every workspace, one path per connection), as the reference derives it.</summary>
    public string AcsUrl(string providerId) => $"{urls.Web}/api/auth/sso/saml2/sp/acs/{Uri.EscapeDataString(providerId)}";

    public string MetadataUrl(string providerId) => $"{urls.Web}/api/auth/sso/saml2/sp/metadata?providerId={Uri.EscapeDataString(providerId)}";

    /// <summary>The service provider's entity id: the audience given at registration, else this deployment's web address (as the reference does).</summary>
    public string SpEntityId(SamlSettings settings) => settings.Audience;

    /// <summary>Saves (or replaces) the workspace's SAML connection. Like OIDC: everything resets to disabled, untested and unproven.</summary>
    public async Task<(SsoConnection? Connection, string? Error)> RegisterSamlAsync(Organization org, SamlRegistration input, CancellationToken ct)
    {
        if (!Uri.TryCreate(input.EntryPoint, UriKind.Absolute, out var entry) || !string.IsNullOrEmpty(entry.UserInfo) || !string.IsNullOrEmpty(entry.Fragment)
            || !(entry.Scheme == Uri.UriSchemeHttps || (entry.Scheme == Uri.UriSchemeHttp && AllowPrivateNetworks)))
            return (null, AllowPrivateNetworks ? "The single sign-on URL must be an http or https URL." : "The single sign-on URL must be an https URL.");
        var certificates = SamlCertificates.Normalize(input.Certificate);
        if (certificates is null || certificates.Length == 0)
            return (null, "The signing certificate is not a valid X.509 certificate (paste the PEM text, or the base64 of the certificate).");
        var binding = input.Binding ?? DefaultSamlBinding;
        var settings = new SamlSettings(input.EntryPoint, input.Audience ?? urls.Web, input.Issuer, certificates, WantAssertionsSigned: true, binding);
        var samlJson = JsonSerializer.Serialize(settings, Json);
        var revision = Revision("saml", input.Issuer, input.Domain, null, null, samlJson);
        var connection = await SaveConnectionAsync(org, "saml", input.Issuer, input.Domain, null, null, samlJson, revision, ct);
        return (connection, null);
    }
}
