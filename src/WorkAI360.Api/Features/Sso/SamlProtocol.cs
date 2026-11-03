using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml.Linq;

namespace WorkAI360.Api.Features.Sso;

/// <summary>The messages this service provider sends and publishes: the AuthnRequest (redirect or POST binding) and its metadata.</summary>
public static class SamlProtocol
{
    public const string RedirectBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
    public const string PostBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
    public const string EmailNameId = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
    private static readonly XNamespace Samlp = SamlValidator.ProtocolNs, Saml = SamlValidator.AssertionNs, Md = "urn:oasis:names:tc:SAML:2.0:metadata";

    /// <summary>A request id: an XML NCName (so it starts with a letter) with 128 random bits.</summary>
    public static string NewRequestId() => "_" + Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));

    public static string AuthnRequest(string id, string spEntityId, string destination, string acsUrl, DateTime now) =>
        new XElement(Samlp + "AuthnRequest",
            new XAttribute(XNamespace.Xmlns + "samlp", Samlp.NamespaceName), new XAttribute(XNamespace.Xmlns + "saml", Saml.NamespaceName),
            new XAttribute("ID", id), new XAttribute("Version", "2.0"), new XAttribute("IssueInstant", now.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")),
            new XAttribute("Destination", destination), new XAttribute("ProtocolBinding", PostBinding), new XAttribute("AssertionConsumerServiceURL", acsUrl),
            new XElement(Saml + "Issuer", spEntityId),
            new XElement(Samlp + "NameIDPolicy", new XAttribute("Format", EmailNameId), new XAttribute("AllowCreate", "true"))).ToString(SaveOptions.DisableFormatting);

    /// <summary>HTTP-Redirect binding: the request is deflated, base64-encoded and sent as the <c>SAMLRequest</c> query parameter, with the RelayState.</summary>
    public static string RedirectUrl(string entryPoint, string requestXml, string relayState)
    {
        using var buffer = new MemoryStream();
        using (var deflate = new DeflateStream(buffer, CompressionLevel.Optimal, leaveOpen: true)) deflate.Write(Encoding.UTF8.GetBytes(requestXml));
        var separator = entryPoint.Contains('?') ? "&" : "?";
        return $"{entryPoint}{separator}SAMLRequest={Uri.EscapeDataString(Convert.ToBase64String(buffer.ToArray()))}&RelayState={Uri.EscapeDataString(relayState)}";
    }

    /// <summary>Inflates a redirect-binding <c>SAMLRequest</c> (for the fake provider in tests and the contract script's own checks).</summary>
    public static string InflateRequest(string samlRequest)
    {
        using var input = new MemoryStream(Convert.FromBase64String(samlRequest));
        using var deflate = new DeflateStream(input, CompressionMode.Decompress);
        using var reader = new StreamReader(deflate, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    /// <summary>HTTP-POST binding: a page that submits the request to the identity provider by itself (the script is allowed by its hash only).</summary>
    public static (string Html, string ScriptHash) PostForm(string entryPoint, string requestXml, string relayState)
    {
        const string script = "document.forms[0].submit();";
        var hash = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(script)));
        string E(string s) => WebUtility.HtmlEncode(s);
        var html = "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Signing in</title></head><body>"
            + $"<form method=\"post\" action=\"{E(entryPoint)}\">"
            + $"<input type=\"hidden\" name=\"SAMLRequest\" value=\"{E(Convert.ToBase64String(Encoding.UTF8.GetBytes(requestXml)))}\">"
            + $"<input type=\"hidden\" name=\"RelayState\" value=\"{E(relayState)}\">"
            + "<noscript><button type=\"submit\">Continue to sign in</button></noscript></form>"
            + $"<script>{script}</script></body></html>";
        return (html, hash);
    }

    /// <summary>
    /// The service provider metadata the identity provider administrator imports: entity id, ACS URL, signed assertions wanted, whether requests are signed,
    /// the service provider's certificate (for checking its signatures and for encrypting assertions to it) and its Single Logout endpoints.
    /// </summary>
    public static string Metadata(string spEntityId, string acsUrl, string? sloUrl = null, string? spCertificate = null, bool authnRequestsSigned = false)
    {
        XNamespace ds = SamlValidator.DsigNs;
        XElement? Key(string use) => spCertificate is null ? null
            : new XElement(Md + "KeyDescriptor", new XAttribute("use", use),
                new XElement(ds + "KeyInfo", new XAttribute(XNamespace.Xmlns + "ds", ds.NamespaceName), new XElement(ds + "X509Data", new XElement(ds + "X509Certificate", spCertificate))));
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            new XElement(Md + "EntityDescriptor", new XAttribute(XNamespace.Xmlns + "md", Md.NamespaceName), new XAttribute("entityID", spEntityId),
                new XElement(Md + "SPSSODescriptor",
                    new XAttribute("AuthnRequestsSigned", authnRequestsSigned ? "true" : "false"), new XAttribute("WantAssertionsSigned", "true"),
                    new XAttribute("protocolSupportEnumeration", SamlValidator.ProtocolNs),
                    Key("signing"), Key("encryption"),
                    sloUrl is null ? null : new XElement(Md + "SingleLogoutService", new XAttribute("Binding", RedirectBinding), new XAttribute("Location", sloUrl)),
                    sloUrl is null ? null : new XElement(Md + "SingleLogoutService", new XAttribute("Binding", PostBinding), new XAttribute("Location", sloUrl)),
                    new XElement(Md + "NameIDFormat", EmailNameId),
                    new XElement(Md + "AssertionConsumerService", new XAttribute("Binding", PostBinding), new XAttribute("Location", acsUrl), new XAttribute("index", "0"), new XAttribute("isDefault", "true"))))
            .ToString(SaveOptions.DisableFormatting);
    }

    /// <summary>The AuthnRequest with an enveloped signature (POST binding of a connection that signs its requests).</summary>
    public static string SignedAuthnRequest(string requestXml, X509Certificate2 key)
    {
        var doc = new System.Xml.XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(requestXml);
        SamlSigning.SignEnveloped(doc, doc.DocumentElement!, key);
        return doc.OuterXml;
    }

    /// <summary>The redirect-binding URL with a query signature (a connection that signs its requests).</summary>
    public static string SignedRedirectUrl(string entryPoint, string requestXml, string relayState, X509Certificate2 key)
    {
        using var rsa = key.GetRSAPrivateKey()!;
        var separator = entryPoint.Contains('?') ? "&" : "?";
        return entryPoint + separator + SamlSigning.RedirectQuery("SAMLRequest", SamlLogout.Deflate(requestXml), relayState, rsa);
    }
}
