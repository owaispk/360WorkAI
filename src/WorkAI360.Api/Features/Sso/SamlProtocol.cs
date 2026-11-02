using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
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

    /// <summary>The service provider metadata the identity provider administrator imports (entity id, ACS URL, signed assertions wanted).</summary>
    public static string Metadata(string spEntityId, string acsUrl) =>
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            new XElement(Md + "EntityDescriptor", new XAttribute(XNamespace.Xmlns + "md", Md.NamespaceName), new XAttribute("entityID", spEntityId),
                new XElement(Md + "SPSSODescriptor",
                    new XAttribute("AuthnRequestsSigned", "false"), new XAttribute("WantAssertionsSigned", "true"),
                    new XAttribute("protocolSupportEnumeration", SamlValidator.ProtocolNs),
                    new XElement(Md + "NameIDFormat", EmailNameId),
                    new XElement(Md + "AssertionConsumerService", new XAttribute("Binding", PostBinding), new XAttribute("Location", acsUrl), new XAttribute("index", "0"), new XAttribute("isDefault", "true"))))
            .ToString(SaveOptions.DisableFormatting);
}
