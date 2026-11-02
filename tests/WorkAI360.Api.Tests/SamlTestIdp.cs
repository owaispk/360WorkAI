using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using WorkAI360.Api.Features.Sso;

namespace WorkAI360.Api.Tests;

/// <summary>What a test identity provider puts in a response. Every field can be broken on purpose.</summary>
public sealed record SamlOptions
{
    public string? Issuer { get; init; }
    public string? Audience { get; init; }
    public string? Destination { get; init; }
    public string? Recipient { get; init; }
    public string? InResponseTo { get; init; }
    public bool OmitInResponseTo { get; init; }
    public string? ResponseInResponseTo { get; init; }
    public string NameId { get; init; } = "person@example.test";
    public string? NameIdFormat { get; init; } = SamlProtocol.EmailNameId;
    public string? Email { get; init; } = "person@example.test";
    public string? DisplayName { get; init; } = "Person One";
    public string? AssertionId { get; init; }
    public int NotBeforeSeconds { get; init; } = -60;
    public int? NotOnOrAfterSeconds { get; init; } = 300;
    public int? ConfirmationNotOnOrAfterSeconds { get; init; } = 300;
    public bool OmitConditions { get; init; }
    public bool OmitAudience { get; init; }
    public bool OmitAuthnStatement { get; init; }
    public bool OmitRecipient { get; init; }
    public bool OmitBearer { get; init; }
    public string Status { get; init; } = SamlValidator.StatusSuccess;
    public bool SignAssertion { get; init; } = true;
    public bool SignResponse { get; init; }
    public bool Sha1 { get; init; }
    public bool UseOtherKey { get; init; }
    public bool UseRsaSha512 { get; init; }
    public bool Unsigned { get; init; }
}

/// <summary>An identity provider with a real RSA key and certificate: builds and signs SAML responses (with System.Security.Cryptography.Xml) the way a provider would.</summary>
public sealed class SamlTestIdp : IDisposable
{
    public string EntityId { get; } = "https://idp.example.test/metadata/" + Guid.NewGuid().ToString("N")[..8];
    public string SsoUrl { get; } = "https://idp.example.test/sso";
    public RSA Key { get; } = RSA.Create(2048);
    public RSA OtherKey { get; } = RSA.Create(2048);
    public X509Certificate2 Certificate { get; }
    public string CertificatePem => Certificate.ExportCertificatePem();

    public SamlTestIdp()
    {
        var request = new CertificateRequest("CN=test identity provider", Key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        Certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));
    }

    public void Dispose()
    {
        Key.Dispose();
        OtherKey.Dispose();
        Certificate.Dispose();
    }

    private static string Time(int seconds) => DateTime.UtcNow.AddSeconds(seconds).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'");

    /// <summary>The unsigned response XML (for tests that take it apart before signing).</summary>
    public string BuildXml(string acsUrl, string spEntityId, SamlOptions o)
    {
        var assertionId = o.AssertionId ?? "_a" + Guid.NewGuid().ToString("N");
        var responseId = "_r" + Guid.NewGuid().ToString("N");
        var issuer = o.Issuer ?? EntityId;
        var irt = o.OmitInResponseTo ? null : o.InResponseTo;
        string Attr(string name, string? value) => value is null ? "" : $"<saml:Attribute Name=\"{name}\"><saml:AttributeValue>{System.Security.SecurityElement.Escape(value)}</saml:AttributeValue></saml:Attribute>";
        var sb = new StringBuilder();
        sb.Append($"<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"{responseId}\" Version=\"2.0\" IssueInstant=\"{Time(0)}\" Destination=\"{o.Destination ?? acsUrl}\"");
        if ((o.ResponseInResponseTo ?? irt) is { } rirt) sb.Append($" InResponseTo=\"{rirt}\"");
        sb.Append($"><saml:Issuer>{issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"{o.Status}\"/></samlp:Status>");
        if (o.Status == SamlValidator.StatusSuccess)
        {
            sb.Append($"<saml:Assertion ID=\"{assertionId}\" Version=\"2.0\" IssueInstant=\"{Time(0)}\"><saml:Issuer>{issuer}</saml:Issuer><saml:Subject>");
            sb.Append($"<saml:NameID{(o.NameIdFormat is null ? "" : $" Format=\"{o.NameIdFormat}\"")}>{System.Security.SecurityElement.Escape(o.NameId)}</saml:NameID>");
            if (!o.OmitBearer)
            {
                sb.Append("<saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData");
                if (o.ConfirmationNotOnOrAfterSeconds is { } cs) sb.Append($" NotOnOrAfter=\"{Time(cs)}\"");
                if (!o.OmitRecipient) sb.Append($" Recipient=\"{o.Recipient ?? acsUrl}\"");
                if (irt is not null) sb.Append($" InResponseTo=\"{irt}\"");
                sb.Append("/></saml:SubjectConfirmation>");
            }
            sb.Append("</saml:Subject>");
            if (!o.OmitConditions)
            {
                sb.Append($"<saml:Conditions NotBefore=\"{Time(o.NotBeforeSeconds)}\"");
                if (o.NotOnOrAfterSeconds is { } ns) sb.Append($" NotOnOrAfter=\"{Time(ns)}\"");
                sb.Append(">");
                if (!o.OmitAudience) sb.Append($"<saml:AudienceRestriction><saml:Audience>{o.Audience ?? spEntityId}</saml:Audience></saml:AudienceRestriction>");
                sb.Append("</saml:Conditions>");
            }
            if (!o.OmitAuthnStatement)
                sb.Append($"<saml:AuthnStatement AuthnInstant=\"{Time(-5)}\" SessionIndex=\"_s1\"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>");
            sb.Append("<saml:AttributeStatement>").Append(Attr("email", o.Email)).Append(Attr("displayName", o.DisplayName)).Append("</saml:AttributeStatement></saml:Assertion>");
        }
        sb.Append("</samlp:Response>");
        return sb.ToString();
    }

    /// <summary>A signed response, base64 encoded as the browser posts it.</summary>
    public string Build(string acsUrl, string spEntityId, SamlOptions? options = null)
    {
        var o = options ?? new SamlOptions();
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(BuildXml(acsUrl, spEntityId, o));
        if (!o.Unsigned)
        {
            var assertion = doc.GetElementsByTagName("Assertion", SamlValidator.AssertionNs).Cast<XmlElement>().FirstOrDefault();
            if (assertion is not null && o.SignAssertion) Sign(assertion, o);
            if (o.SignResponse) Sign(doc.DocumentElement!, o);
        }
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(doc.OuterXml));
    }

    public static string Encode(string xml) => Convert.ToBase64String(Encoding.UTF8.GetBytes(xml));

    /// <summary>Signs an element in place (enveloped, exclusive canonicalization), placing the signature after the issuer as the profile asks.</summary>
    public XmlElement Sign(XmlElement element, SamlOptions? options = null, RSA? key = null)
    {
        var o = options ?? new SamlOptions();
        var sx = new SignedXml(element.OwnerDocument) { SigningKey = key ?? (o.UseOtherKey ? OtherKey : Key) };
        var reference = new Reference("#" + element.GetAttribute("ID")) { DigestMethod = o.Sha1 ? SignedXml.XmlDsigSHA1Url : SignedXml.XmlDsigSHA256Url };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        sx.AddReference(reference);
        sx.SignedInfo!.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        sx.SignedInfo.SignatureMethod = o.Sha1 ? SignedXml.XmlDsigRSASHA1Url : o.UseRsaSha512 ? "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512" : SignedXml.XmlDsigRSASHA256Url;
        sx.ComputeSignature();
        var signature = element.OwnerDocument.ImportNode(sx.GetXml(), true);
        var issuer = element.ChildNodes.OfType<XmlElement>().FirstOrDefault(e => e.LocalName == "Issuer");
        element.InsertAfter(signature, issuer);
        return (XmlElement)signature;
    }
}
