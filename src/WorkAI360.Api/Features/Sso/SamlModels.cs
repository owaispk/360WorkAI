using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace WorkAI360.Api.Features.Sso;

/// <summary>A SAML connection's public settings, stored as JSON in <c>SsoConnection.SamlConfigJson</c>. Holds no secret: the identity provider's certificates are public.</summary>
public sealed record SamlSettings(string EntryPoint, string Audience, string IdpEntityId, string[] Certificates, bool WantAssertionsSigned, string Binding);

/// <summary>What is wrong with a SAML response. <see cref="Code"/> is stable (tests and logs); the message is what a person reads.</summary>
public sealed class SamlException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

/// <summary>What the signed assertion says, after every check passed.</summary>
public sealed record SamlAssertion(
    string AssertionId, string Issuer, string NameId, string? NameIdFormat, string? InResponseTo, string? SessionIndex,
    IReadOnlyDictionary<string, string[]> Attributes, DateTime ReplayExpiresAt);

/// <summary>What the service provider expects of a response.</summary>
public sealed record SamlExpectations(
    string IdpEntityId, string SpEntityId, IReadOnlyCollection<string> AcsUrls, IReadOnlyList<X509Certificate2> Certificates,
    DateTimeOffset Now, TimeSpan ClockSkew);

/// <summary>Reading certificates the way administrators paste them: PEM (one or several), or the bare base64 of the DER.</summary>
public static class SamlCertificates
{
    public const int MaxCertificates = 5;
    private static readonly Regex Pem = new(@"-----BEGIN CERTIFICATE-----(?<body>[A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----", RegexOptions.Compiled);

    /// <summary>The certificates in the text as base64 DER, or null when any of them is not a usable RSA or ECDSA X.509 certificate.</summary>
    public static string[]? Normalize(string? text)
    {
        if (string.IsNullOrWhiteSpace(text) || text.Length > 64 * 1024) return null;
        var bodies = Pem.Matches(text).Select(m => Regex.Replace(m.Groups["body"].Value, @"\s+", "")).ToList();
        if (bodies.Count == 0) bodies.Add(Regex.Replace(text, @"\s+", ""));
        if (bodies.Count > MaxCertificates) return null;
        var result = new List<string>();
        foreach (var body in bodies)
        {
            try
            {
                var der = Convert.FromBase64String(body);
                using var cert = X509CertificateLoader.LoadCertificate(der);
                if (cert.GetRSAPublicKey() is null && cert.GetECDsaPublicKey() is null) return null;
                result.Add(Convert.ToBase64String(der));
            }
            catch (Exception e) when (e is FormatException or CryptographicException) { return null; }
        }
        return [.. result.Distinct()];
    }

    public static List<X509Certificate2> Load(IEnumerable<string> base64) => [.. base64.Select(b => X509CertificateLoader.LoadCertificate(Convert.FromBase64String(b)))];
}
