using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using Microsoft.EntityFrameworkCore;
using WorkAI360.Api.Auth;
using WorkAI360.Api.Data;
using WorkAI360.Api.Domain.Saml;
using WorkAI360.Api.Domain.Sso;

namespace WorkAI360.Api.Features.Sso;

/// <summary>
/// The service provider's own key for a connection (see <see cref="SamlSpKey"/>): made on first use, the private key kept encrypted. Used to sign
/// AuthnRequests and logout messages and to decrypt encrypted assertions; its certificate is published in the SP metadata for both uses.
/// </summary>
public sealed class SamlServiceProvider(DenDbContext db, SecretProtector protector)
{
    public async Task<X509Certificate2> KeyAsync(string providerId, CancellationToken ct = default)
    {
        var row = await db.Set<SamlSpKey>().AsNoTracking().FirstOrDefaultAsync(k => k.ProviderId == providerId, ct);
        if (row is null)
        {
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest($"CN=OpenWork SAML service provider {providerId[..Math.Min(providerId.Length, 40)]}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: true));
            using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));
            row = new SamlSpKey
            {
                ProviderId = providerId, CertificateDer = Convert.ToBase64String(cert.Export(X509ContentType.Cert)),
                ProtectedPrivateKey = protector.Protect(Convert.ToBase64String(rsa.ExportPkcs8PrivateKey())), CreatedAt = DateTime.UtcNow,
            };
            db.Add(row);
            try { await db.SaveChangesAsync(ct); }
            catch (DbUpdateException)
            {
                // Another request made it first: use theirs.
                db.ChangeTracker.Clear();
                row = await db.Set<SamlSpKey>().AsNoTracking().FirstAsync(k => k.ProviderId == providerId, ct);
            }
        }
        var key = RSA.Create();
        key.ImportPkcs8PrivateKey(Convert.FromBase64String(protector.Unprotect(row.ProtectedPrivateKey)), out _);
        using var publicOnly = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(row.CertificateDer));
        return publicOnly.CopyWithPrivateKey(key);
    }

    /// <summary>The private key for decrypting assertions, or null when this connection never published one (then nobody could have encrypted to it).</summary>
    public async Task<RSA?> ExistingDecryptionKeyAsync(string providerId, CancellationToken ct = default)
    {
        if (!await db.Set<SamlSpKey>().AnyAsync(k => k.ProviderId == providerId, ct)) return null;
        using var cert = await KeyAsync(providerId, ct);
        return cert.GetRSAPrivateKey();
    }

    /// <summary>The public certificate (base64 DER), made on first use.</summary>
    public async Task<string> CertificateAsync(string providerId, CancellationToken ct = default)
    {
        using var cert = await KeyAsync(providerId, ct);
        return Convert.ToBase64String(cert.Export(X509ContentType.Cert));
    }

    /// <summary>Removes the key with the connection (a new connection gets a new key).</summary>
    public Task DeleteAsync(string providerId, CancellationToken ct = default) =>
        db.Set<SamlSpKey>().Where(k => k.ProviderId == providerId).ExecuteDeleteAsync(ct);
}

/// <summary>Logout messages (SAML core 3.7) and the deflate encoding of the redirect binding.</summary>
public static class SamlLogout
{
    private static readonly XNamespace Samlp = SamlValidator.ProtocolNs, Saml = SamlValidator.AssertionNs;
    public const string StatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success";

    public static string Deflate(string xml)
    {
        using var buffer = new MemoryStream();
        using (var deflate = new DeflateStream(buffer, CompressionLevel.Optimal, leaveOpen: true)) deflate.Write(Encoding.UTF8.GetBytes(xml));
        return Convert.ToBase64String(buffer.ToArray());
    }

    public static string Request(string id, string issuer, string destination, string nameId, string? nameIdFormat, string? sessionIndex, DateTime now) =>
        new XElement(Samlp + "LogoutRequest",
            new XAttribute(XNamespace.Xmlns + "samlp", Samlp.NamespaceName), new XAttribute(XNamespace.Xmlns + "saml", Saml.NamespaceName),
            new XAttribute("ID", id), new XAttribute("Version", "2.0"), new XAttribute("IssueInstant", now.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")),
            new XAttribute("Destination", destination), new XAttribute("NotOnOrAfter", now.AddMinutes(10).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")),
            new XElement(Saml + "Issuer", issuer),
            nameIdFormat is null ? new XElement(Saml + "NameID", nameId) : new XElement(Saml + "NameID", new XAttribute("Format", nameIdFormat), nameId),
            sessionIndex is null ? null : new XElement(Samlp + "SessionIndex", sessionIndex)).ToString(SaveOptions.DisableFormatting);

    public static string Response(string id, string inResponseTo, string issuer, string destination, string status, DateTime now) =>
        new XElement(Samlp + "LogoutResponse",
            new XAttribute(XNamespace.Xmlns + "samlp", Samlp.NamespaceName), new XAttribute(XNamespace.Xmlns + "saml", Saml.NamespaceName),
            new XAttribute("ID", id), new XAttribute("Version", "2.0"), new XAttribute("IssueInstant", now.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")),
            new XAttribute("Destination", destination), new XAttribute("InResponseTo", inResponseTo),
            new XElement(Saml + "Issuer", issuer),
            new XElement(Samlp + "Status", new XElement(Samlp + "StatusCode", new XAttribute("Value", status)))).ToString(SaveOptions.DisableFormatting);
}

/// <summary>What an identity provider's metadata says, as far as a connection needs it.</summary>
public sealed record SamlIdpMetadata(string EntityId, string SsoUrl, string Binding, string Certificates, string? SloUrl);

/// <summary>
/// Reads identity provider metadata XML (an <c>EntityDescriptor</c>, or an <c>EntitiesDescriptor</c> holding exactly one IdP): entity id, the single
/// sign-on URL (redirect binding preferred, else POST), the signing certificates and the Single Logout URL (redirect binding). The text is parsed with
/// DTDs prohibited and a size cap; nothing is fetched.
/// </summary>
public static class SamlMetadataImport
{
    public const int MaxLength = 256 * 1024;
    private const string Md = "urn:oasis:names:tc:SAML:2.0:metadata";

    public static (SamlIdpMetadata? Metadata, string? Error) Read(string xml)
    {
        if (string.IsNullOrWhiteSpace(xml)) return (null, "The identity provider metadata is empty.");
        if (xml.Length > MaxLength) return (null, "The identity provider metadata is too large.");
        XmlDocument doc;
        try { doc = SamlValidator.Parse(xml); }
        catch (SamlException e) { return (null, e.Code == "saml_invalid_xml" && e.Message.Contains("DTD") ? "The identity provider metadata contains a DTD, which is not allowed." : "The identity provider metadata is not valid XML."); }

        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("md", Md);
        ns.AddNamespace("ds", SamlValidator.DsigNs);
        var idps = doc.SelectNodes("//md:EntityDescriptor[md:IDPSSODescriptor]", ns)!.Cast<XmlElement>().ToList();
        if (idps.Count != 1) return (null, idps.Count == 0 ? "The metadata describes no identity provider." : "The metadata describes several identity providers; paste the one to use.");
        var entity = idps[0];
        var entityId = entity.GetAttribute("entityID").Trim();
        if (entityId.Length == 0) return (null, "The identity provider metadata has no entityID.");
        var descriptor = (XmlElement)entity.SelectSingleNode("md:IDPSSODescriptor", ns)!;

        string? Service(string element, string binding) =>
            descriptor.SelectNodes($"md:{element}", ns)!.Cast<XmlElement>().FirstOrDefault(s => s.GetAttribute("Binding") == binding)?.GetAttribute("Location").Trim() is { Length: > 0 } location ? location : null;
        var redirect = Service("SingleSignOnService", SamlProtocol.RedirectBinding);
        var post = Service("SingleSignOnService", SamlProtocol.PostBinding);
        if (redirect is null && post is null) return (null, "The identity provider metadata has no SingleSignOnService for the redirect or POST binding.");

        var certificates = descriptor.SelectNodes("md:KeyDescriptor", ns)!.Cast<XmlElement>()
            .Where(k => k.GetAttribute("use") is "" or "signing")
            .SelectMany(k => k.SelectNodes(".//ds:X509Certificate", ns)!.Cast<XmlElement>())
            .Select(c => c.InnerText.Trim()).Where(c => c.Length > 0).Distinct().ToList();
        if (certificates.Count == 0) return (null, "The identity provider metadata has no signing certificate.");
        var pem = string.Join("\n", certificates.Select(c => $"-----BEGIN CERTIFICATE-----\n{c}\n-----END CERTIFICATE-----"));
        return (new SamlIdpMetadata(entityId, redirect ?? post!, redirect is not null ? "redirect" : "post", pem, Service("SingleLogoutService", SamlProtocol.RedirectBinding)), null);
    }
}
