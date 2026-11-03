using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace WorkAI360.Api.Features.Sso;

/// <summary>
/// Checks a SAML Response the way a service provider must, and returns only what a signed assertion says.
/// <list type="bullet">
/// <item>The XML is parsed with DTDs prohibited and no resolver (no entity expansion, no outside reads), comments dropped, and a size limit.</item>
/// <item><b>Signature wrapping.</b> There must be exactly one Assertion in the whole document, a direct child of the Response. Signatures may sit only directly
/// under the Response or that Assertion. A signature must reference exactly its own parent by id, that id must be unique in the document, and
/// the reference lookup is pinned to that parent (the stock "find the first element with this id" is replaced), so what was verified is
/// the very element the claims are read from. Only enveloped-signature and (exclusive) canonicalization transforms are allowed. The Assertion
/// must be signed (the reference's <c>wantAssertionsSigned</c>); a signature on the Response must verify too.</item>
/// <item>Keys are the identity provider's pinned certificates, never what the message carries. SHA-1 and unknown algorithms are refused.</item>
/// <item>Then: status, issuer, destination, audience, bearer confirmation (recipient, expiry), conditions (NotBefore, NotOnOrAfter, with a clock skew),
/// an authentication statement, and consistency of <c>InResponseTo</c>.</item>
/// </list>
/// Matching the response to a request that was really sent, and the replay cache, belong to the caller (<see cref="SamlFlow"/>).
/// </summary>
public static class SamlValidator
{
    public const string ProtocolNs = "urn:oasis:names:tc:SAML:2.0:protocol";
    public const string AssertionNs = "urn:oasis:names:tc:SAML:2.0:assertion";
    public const string DsigNs = "http://www.w3.org/2000/09/xmldsig#";
    public const int MaxEncodedLength = 262_144;
    public const string StatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success";
    public const string BearerMethod = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
    public const string TransientNameId = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";

    private const string Enveloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
    private const string ExcC14n = "http://www.w3.org/2001/10/xml-exc-c14n#";
    private const string C14n = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

    private static readonly HashSet<string> Transforms = [Enveloped, ExcC14n, C14n];
    private static readonly HashSet<string> Canonicalizations = [ExcC14n, C14n];
    private static readonly HashSet<string> SignatureMethods =
    [
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
    ];
    private static readonly HashSet<string> DigestMethods = ["http://www.w3.org/2001/04/xmlenc#sha256", "http://www.w3.org/2001/04/xmldsig-more#sha384", "http://www.w3.org/2001/04/xmlenc#sha512"];
    private static readonly HashSet<string> Deprecated =
    [
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1", "http://www.w3.org/2000/09/xmldsig#dsa-sha1", "http://www.w3.org/2000/09/xmldsig#sha1",
        "http://www.w3.org/2001/04/xmldsig-more#rsa-md5", "http://www.w3.org/2001/04/xmldsig-more#md5", "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1",
    ];

    public static SamlAssertion Validate(string samlResponse, SamlExpectations expected)
    {
        var xml = Decode(samlResponse);
        var doc = Parse(xml);
        var response = doc.DocumentElement;
        if (response is null || response.LocalName != "Response" || response.NamespaceURI != ProtocolNs)
            throw new SamlException("saml_invalid_xml", "The SAML message is not a Response.");
        if (response.GetAttribute("Version") != "2.0") throw new SamlException("saml_invalid_xml", "The SAML Response is not version 2.0.");

        // The identity provider says whether it authenticated the person; a refusal has no assertion to look at.
        var statusCode = Child(Child(response, ProtocolNs, "Status"), ProtocolNs, "StatusCode")?.GetAttribute("Value");
        if (statusCode != StatusSuccess)
            throw new SamlException("saml_status_not_success", $"The identity provider did not authenticate the person ({ShortStatus(statusCode)}).");

        // An encrypted assertion: a signature on the Response covers the encrypted form, so it is checked first; then the assertion is decrypted
        // with this service provider's key and put in its place, and everything below applies to it exactly as to a plaintext one.
        var responseVerifiedEncrypted = false;
        var encrypted = doc.SelectNodes("//*")!.Cast<XmlElement>().Where(el => el.LocalName == "EncryptedAssertion").ToList();
        if (encrypted.Count > 0)
        {
            if (expected.DecryptionKey is null)
                throw new SamlException("saml_encrypted_assertion", "The assertion is encrypted, but this connection has no service provider key to decrypt it.");
            if (encrypted.Count > 1) throw new SamlException("saml_multiple_assertions", $"The SAML response contains {encrypted.Count} encrypted assertions, expected exactly 1.");
            var holder = encrypted[0];
            if (holder.NamespaceURI != AssertionNs || holder.ParentNode != response) throw new SamlException("saml_invalid_xml", "The encrypted assertion is not a direct child of the response.");
            var signaturesBefore = doc.GetElementsByTagName("Signature", DsigNs).Cast<XmlElement>().ToList();
            var onResponse = signaturesBefore.Where(s => s.ParentNode == response).ToList();
            if (onResponse.Count > 1 || signaturesBefore.Count != onResponse.Count)
                throw new SamlException("saml_signature_invalid", "The SAML message carries a signature in an unexpected place.");
            if (onResponse.Count == 1)
            {
                VerifySignature(doc, response, onResponse[0], expected.Certificates);
                responseVerifiedEncrypted = true;
            }
            var plain = SamlDecryptor.Decrypt(holder, expected.DecryptionKey);
            var fragment = Parse(plain).DocumentElement;
            if (fragment is null || fragment.LocalName != "Assertion" || fragment.NamespaceURI != AssertionNs)
                throw new SamlException("saml_decryption_failed", "The encrypted content is not a SAML assertion.");
            response.ReplaceChild(doc.ImportNode(fragment, deep: true), holder);
        }

        // Exactly one plaintext Assertion in the whole document, directly under the Response.
        var elements = doc.SelectNodes("//*")!.Cast<XmlElement>().ToList();
        if (elements.Any(el => el.LocalName is "EncryptedAssertion" or "EncryptedID" or "EncryptedAttribute"))
            throw new SamlException("saml_encrypted_assertion", "Encrypted identifiers and attributes are not supported. Configure the identity provider to encrypt the whole assertion.");
        var assertions = elements.Where(el => el.LocalName == "Assertion").ToList();
        if (assertions.Count == 0) throw new SamlException("saml_no_assertion", "The SAML response contains no assertion.");
        if (assertions.Count > 1) throw new SamlException("saml_multiple_assertions", $"The SAML response contains {assertions.Count} assertions, expected exactly 1.");
        var assertion = assertions[0];
        if (assertion.NamespaceURI != AssertionNs || assertion.ParentNode != response)
            throw new SamlException("saml_invalid_xml", "The assertion is not a direct child of the response.");
        if (assertion.GetAttribute("Version") != "2.0") throw new SamlException("saml_invalid_xml", "The SAML assertion is not version 2.0.");

        // Signatures: only the Response's and the Assertion's own, one each.
        var signatures = doc.GetElementsByTagName("Signature", DsigNs).Cast<XmlElement>().ToList();
        var responseSignatures = signatures.Where(s => s.ParentNode == response).ToList();
        var assertionSignatures = signatures.Where(s => s.ParentNode == assertion).ToList();
        if (responseSignatures.Count > 1 || assertionSignatures.Count > 1 || signatures.Count != responseSignatures.Count + assertionSignatures.Count)
            throw new SamlException("saml_signature_invalid", "The SAML message carries a signature in an unexpected place.");
        if (assertionSignatures.Count == 0) throw new SamlException("saml_assertion_signature_required", "The SAML assertion must be signed by the identity provider.");
        VerifySignature(doc, assertion, assertionSignatures[0], expected.Certificates);
        // (After decryption the response's signature no longer matches the document; it was checked on the encrypted form above.)
        if (responseSignatures.Count == 1 && !responseVerifiedEncrypted) VerifySignature(doc, response, responseSignatures[0], expected.Certificates);
        var responseSigned = responseSignatures.Count == 1;

        // ---- From here on only the verified assertion (and, as a courtesy check, the response's own attributes) are read. ----
        var now = expected.Now;
        var skew = expected.ClockSkew;
        var assertionId = assertion.GetAttribute("ID");
        var issuer = Child(assertion, AssertionNs, "Issuer")?.InnerText.Trim();
        if (issuer != expected.IdpEntityId) throw new SamlException("saml_issuer_mismatch", "The SAML assertion was issued by a different identity provider than the one configured.");
        if (Child(response, AssertionNs, "Issuer")?.InnerText.Trim() is { Length: > 0 } responseIssuer && responseIssuer != expected.IdpEntityId)
            throw new SamlException("saml_issuer_mismatch", "The SAML response was issued by a different identity provider than the one configured.");

        if (response.GetAttribute("Destination") is { Length: > 0 } destination && !MatchesAny(destination, expected.AcsUrls))
            throw new SamlException("saml_destination_mismatch", "The SAML response Destination does not match this service provider's assertion consumer URL.");

        if (Time(assertion.GetAttribute("IssueInstant")) is { } issued && issued > now + skew)
            throw new SamlException("saml_not_yet_valid", "The SAML assertion was issued in the future.");

        // Conditions.
        var conditions = Child(assertion, AssertionNs, "Conditions") ?? throw new SamlException("saml_timestamps_missing", "The SAML assertion has no Conditions (NotBefore / NotOnOrAfter are required).");
        foreach (var condition in conditions.ChildNodes.OfType<XmlElement>())
            if (condition.NamespaceURI != AssertionNs || condition.LocalName is not ("AudienceRestriction" or "OneTimeUse" or "ProxyRestriction"))
                throw new SamlException("saml_unsupported_condition", "The SAML assertion carries a condition this service provider does not understand.");
        var notBefore = TimeAttribute(conditions, "NotBefore");
        var conditionsEnd = TimeAttribute(conditions, "NotOnOrAfter");
        if (notBefore is null && conditionsEnd is null) throw new SamlException("saml_timestamps_missing", "The SAML assertion must carry a NotBefore and/or NotOnOrAfter condition.");
        if (notBefore is { } nb && now < nb - skew) throw new SamlException("saml_not_yet_valid", "The SAML assertion is not yet valid.");
        if (conditionsEnd is { } ce && now >= ce + skew) throw new SamlException("saml_expired", "The SAML assertion has expired.");

        // Audience: every restriction must name this service provider.
        var restrictions = Children(conditions, AssertionNs, "AudienceRestriction").ToList();
        if (restrictions.Count == 0 || restrictions.All(r => Children(r, AssertionNs, "Audience").All(a => a.InnerText.Trim().Length == 0)))
            throw new SamlException("saml_audience_missing", "The SAML assertion has no AudienceRestriction.");
        if (restrictions.Any(r => !Children(r, AssertionNs, "Audience").Any(a => a.InnerText.Trim() == expected.SpEntityId)))
            throw new SamlException("saml_audience_mismatch", "The SAML assertion audience does not match this service provider.");

        // Subject: a name, and a bearer confirmation that is addressed to our ACS URL and has not run out.
        var subject = Child(assertion, AssertionNs, "Subject") ?? throw new SamlException("saml_missing_subject", "The SAML assertion has no Subject.");
        var nameIdElement = Child(subject, AssertionNs, "NameID");
        var nameId = nameIdElement?.InnerText.Trim();
        if (string.IsNullOrEmpty(nameId) || nameId.Length > 512) throw new SamlException("saml_missing_subject", "The SAML assertion has no usable NameID.");
        var confirmations = Children(subject, AssertionNs, "SubjectConfirmation").Where(c => c.GetAttribute("Method") == BearerMethod).ToList();
        if (confirmations.Count == 0) throw new SamlException("saml_bearer_confirmation_missing", "The SAML assertion has no bearer subject confirmation.");
        XmlElement? good = null;
        SamlException? lastProblem = null;
        foreach (var confirmation in confirmations)
        {
            var data = Child(confirmation, AssertionNs, "SubjectConfirmationData");
            if (data is null) { lastProblem = new("saml_bearer_confirmation_missing", "The SAML bearer confirmation has no SubjectConfirmationData."); continue; }
            var recipient = data.GetAttribute("Recipient");
            if (recipient.Length == 0) { lastProblem = new("saml_recipient_missing", "The SAML assertion is missing a Recipient."); continue; }
            if (!MatchesAny(recipient, expected.AcsUrls)) { lastProblem = new("saml_recipient_mismatch", "The SAML assertion Recipient does not match this service provider's assertion consumer URL."); continue; }
            if (TimeAttribute(data, "NotOnOrAfter") is not { } dataEnd) { lastProblem = new("saml_timestamps_missing", "The SAML bearer confirmation has no NotOnOrAfter."); continue; }
            if (now >= dataEnd + skew) { lastProblem = new("saml_expired", "The SAML assertion has expired."); continue; }
            if (data.HasAttribute("NotBefore")) { lastProblem = new("saml_bearer_confirmation_missing", "A bearer confirmation must not carry NotBefore."); continue; }
            good = data;
            break;
        }
        if (good is null) throw lastProblem ?? new SamlException("saml_bearer_confirmation_missing", "The SAML assertion has no valid bearer confirmation.");
        var confirmationEnd = TimeAttribute(good, "NotOnOrAfter")!.Value;

        var statements = Children(assertion, AssertionNs, "AuthnStatement").ToList();
        if (statements.Count == 0) throw new SamlException("saml_missing_subject", "The SAML assertion has no AuthnStatement.");
        if (statements.Any(s => TimeAttribute(s, "SessionNotOnOrAfter") is { } end && now >= end + skew)) throw new SamlException("saml_expired", "The identity provider's session for this sign-in has ended.");
        var sessionIndex = statements[0].GetAttribute("SessionIndex");

        // InResponseTo: the assertion's (signed) value decides; the response's own is only trusted if the response is signed too.
        string? inResponseTo = good.GetAttribute("InResponseTo") is { Length: > 0 } fromAssertion ? fromAssertion : null;
        var fromResponse = response.GetAttribute("InResponseTo") is { Length: > 0 } r ? r : null;
        if (inResponseTo is null && fromResponse is not null)
        {
            if (!responseSigned) throw new SamlException("saml_in_response_to_mismatch", "InResponseTo is not covered by a signature.");
            inResponseTo = fromResponse;
        }
        else if (inResponseTo is not null && fromResponse is not null && inResponseTo != fromResponse)
            throw new SamlException("saml_in_response_to_mismatch", "The SAML response and its assertion answer different requests.");

        var attributes = new Dictionary<string, string[]>(StringComparer.Ordinal);
        foreach (var statement in Children(assertion, AssertionNs, "AttributeStatement"))
        {
            foreach (var attribute in Children(statement, AssertionNs, "Attribute"))
            {
                var values = Children(attribute, AssertionNs, "AttributeValue").Select(v => v.InnerText.Trim()).Where(v => v.Length > 0).ToArray();
                foreach (var key in new[] { attribute.GetAttribute("Name"), attribute.GetAttribute("FriendlyName") }.Where(k => k.Length > 0))
                    attributes[key] = attributes.TryGetValue(key, out var existing) ? [.. existing, .. values] : values;
            }
        }

        var replayUntil = new[] { conditionsEnd, confirmationEnd }.Where(t => t is not null).Max()!.Value + skew;
        return new SamlAssertion(assertionId, issuer, nameId, nameIdElement!.GetAttribute("Format") is { Length: > 0 } f ? f : null, inResponseTo,
            sessionIndex.Length > 0 ? sessionIndex : null, attributes, replayUntil.UtcDateTime);
    }

    // ---------------------------------------------------------------- parsing

    public static string Decode(string samlResponse)
    {
        var compact = new string(samlResponse.Where(c => !char.IsWhiteSpace(c)).ToArray());
        if (compact.Length == 0) throw new SamlException("saml_invalid_encoding", "The SAML response is empty.");
        if (compact.Length > MaxEncodedLength) throw new SamlException("saml_too_large", $"The SAML response exceeds the maximum allowed size ({MaxEncodedLength} bytes).");
        byte[] bytes;
        try { bytes = Convert.FromBase64String(compact); }
        catch (FormatException) { throw new SamlException("saml_invalid_encoding", "The SAML response is not valid base64."); }
        var text = new UTF8Encoding(false, throwOnInvalidBytes: false).GetString(bytes);
        if (!text.Contains('<')) throw new SamlException("saml_invalid_encoding", "The SAML response is not base64-encoded XML.");
        return text;
    }

    /// <summary>Loads XML with every outside reference and entity switched off. Comments are dropped so that text cannot be split by one.</summary>
    public static XmlDocument Parse(string xml)
    {
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersFromEntities = 0, MaxCharactersInDocument = 2_000_000,
            IgnoreComments = true, IgnoreProcessingInstructions = true,
        };
        var doc = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        try
        {
            using var reader = XmlReader.Create(new StringReader(xml), settings);
            doc.Load(reader);
        }
        catch (XmlException e)
        {
            throw new SamlException("saml_invalid_xml", e.Message.Contains("DTD", StringComparison.OrdinalIgnoreCase) ? "The SAML message contains a DTD, which is not allowed." : "The SAML message could not be parsed.");
        }
        return doc;
    }

    // ---------------------------------------------------------------- signatures

    /// <summary>A SignedXml whose id lookup can only ever answer with the one element we decided it signs (the wrapping defence).</summary>
    private sealed class PinnedSignedXml(XmlDocument document, XmlElement target, string id) : SignedXml(document)
    {
        public override XmlElement? GetIdElement(XmlDocument? doc, string idValue) => idValue == id ? target : null;
    }

    /// <summary>Nothing outside the document may be fetched while checking a signature.</summary>
    private sealed class NoResolver : XmlResolver
    {
        public override object? GetEntity(Uri absoluteUri, string? role, Type? ofObjectToReturn) => throw new XmlException("External references are not allowed.");
    }

    /// <summary>Checks the enveloped signature of a signed logout message (its root element) with every rule a response signature is held to.</summary>
    public static void VerifyRootSignature(XmlDocument doc, IReadOnlyList<X509Certificate2> certificates)
    {
        var root = doc.DocumentElement ?? throw new SamlException("saml_invalid_xml", "The SAML message is empty.");
        var signatures = doc.GetElementsByTagName("Signature", DsigNs).Cast<XmlElement>().ToList();
        if (signatures.Count != 1 || signatures[0].ParentNode != root) throw new SamlException("saml_signature_invalid", "The SAML message must carry exactly one signature, on itself.");
        VerifySignature(doc, root, signatures[0], certificates);
    }

    private static void VerifySignature(XmlDocument doc, XmlElement signed, XmlElement signature, IReadOnlyList<X509Certificate2> certificates)
    {
        var id = signed.GetAttribute("ID");
        if (id.Length == 0) throw new SamlException("saml_signature_invalid", "A signed element has no ID.");
        // The id must belong to exactly one element: otherwise "the element with this id" is a matter of opinion.
        var holders = doc.SelectNodes("//*")!.Cast<XmlElement>().Count(el => el.Attributes.Cast<XmlAttribute>().Any(a => a.LocalName.Equals("id", StringComparison.OrdinalIgnoreCase) && a.Value == id));
        if (holders != 1) throw new SamlException("saml_signature_invalid", "The signed element's ID is not unique in the document.");

        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", DsigNs);
        var signedInfos = signature.SelectNodes("ds:SignedInfo", ns)!;
        if (signedInfos.Count != 1) throw new SamlException("saml_signature_invalid", "The signature has no single SignedInfo.");
        var signedInfo = (XmlElement)signedInfos[0]!;
        var references = signedInfo.SelectNodes("ds:Reference", ns)!;
        if (references.Count != 1) throw new SamlException("saml_signature_invalid", "A signature must cover exactly one element.");
        var reference = (XmlElement)references[0]!;
        if (reference.GetAttribute("URI") != "#" + id) throw new SamlException("saml_signature_invalid", "The signature does not cover the element it sits in.");

        CheckAlgorithm((signedInfo.SelectSingleNode("ds:SignatureMethod", ns) as XmlElement)?.GetAttribute("Algorithm"), SignatureMethods);
        CheckAlgorithm((signedInfo.SelectSingleNode("ds:CanonicalizationMethod", ns) as XmlElement)?.GetAttribute("Algorithm"), Canonicalizations);
        CheckAlgorithm((reference.SelectSingleNode("ds:DigestMethod", ns) as XmlElement)?.GetAttribute("Algorithm"), DigestMethods);
        var transformUris = reference.SelectNodes("ds:Transforms/ds:Transform", ns)!.Cast<XmlElement>().Select(t => t.GetAttribute("Algorithm")).ToList();
        foreach (var uri in transformUris) CheckAlgorithm(uri, Transforms);
        if (!transformUris.Contains(Enveloped)) throw new SamlException("saml_signature_invalid", "The signature is not an enveloped signature.");

        var verified = false;
        foreach (var certificate in certificates)
        {
            try
            {
                var sx = new PinnedSignedXml(doc, signed, id) { Resolver = new NoResolver() };
                sx.LoadXml(signature);
                using AsymmetricAlgorithm? key = (AsymmetricAlgorithm?)certificate.GetRSAPublicKey() ?? certificate.GetECDsaPublicKey();
                if (key is not null && sx.CheckSignature(key)) { verified = true; break; }
            }
            catch (Exception e) when (e is CryptographicException or XmlException or ArgumentException or InvalidOperationException or NotSupportedException or FormatException) { }
        }
        if (!verified) throw new SamlException("saml_signature_invalid", "The SAML signature could not be verified with the identity provider's certificate.");
    }

    private static void CheckAlgorithm(string? uri, HashSet<string> allowed)
    {
        if (string.IsNullOrEmpty(uri)) throw new SamlException("saml_signature_invalid", "The signature is missing an algorithm.");
        if (Deprecated.Contains(uri)) throw new SamlException("saml_deprecated_algorithm", $"The SAML signature uses a deprecated algorithm ({uri}). Configure the identity provider to use SHA-256 or stronger.");
        if (!allowed.Contains(uri)) throw new SamlException("saml_unsupported_algorithm", $"The SAML signature uses an algorithm that is not allowed ({uri}).");
    }

    // ---------------------------------------------------------------- helpers

    private static XmlElement? Child(XmlNode? parent, string ns, string local) => parent?.ChildNodes.OfType<XmlElement>().FirstOrDefault(e => e.NamespaceURI == ns && e.LocalName == local);

    private static IEnumerable<XmlElement> Children(XmlNode parent, string ns, string local) => parent.ChildNodes.OfType<XmlElement>().Where(e => e.NamespaceURI == ns && e.LocalName == local);

    private static DateTimeOffset? Time(string value) =>
        value.Length > 0 && DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var t) ? t : null;

    private static DateTimeOffset? TimeAttribute(XmlElement element, string name)
    {
        if (!element.HasAttribute(name)) return null;
        return Time(element.GetAttribute(name)) ?? throw new SamlException("saml_invalid_xml", $"The SAML {name} timestamp could not be read.");
    }

    private static bool MatchesAny(string url, IEnumerable<string> expected)
    {
        var normalized = Normalize(url);
        return normalized is not null && expected.Any(e => Normalize(e) == normalized);
    }

    private static string? Normalize(string url) => Uri.TryCreate(url.Trim(), UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https" ? uri.AbsoluteUri : null;

    private static string ShortStatus(string? value) => value is null ? "no status" : value.StartsWith("urn:oasis:names:tc:SAML:2.0:status:", StringComparison.Ordinal) ? value["urn:oasis:names:tc:SAML:2.0:status:".Length..] : "unknown status";
}
