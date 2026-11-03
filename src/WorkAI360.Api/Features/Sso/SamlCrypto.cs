using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace WorkAI360.Api.Features.Sso;

/// <summary>
/// Signing and checking SAML messages outside the response: the HTTP-Redirect binding's query signature (SAML bindings 3.4.4.1) and enveloped XML
/// signatures on AuthnRequests and logout messages. Only SHA-256 or stronger RSA/ECDSA algorithms are used or accepted.
/// </summary>
public static class SamlSigning
{
    public const string RsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    private static readonly Dictionary<string, HashAlgorithmName> RedirectAlgorithms = new()
    {
        ["http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"] = HashAlgorithmName.SHA256,
        ["http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"] = HashAlgorithmName.SHA384,
        ["http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"] = HashAlgorithmName.SHA512,
        ["http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"] = HashAlgorithmName.SHA256,
        ["http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"] = HashAlgorithmName.SHA384,
        ["http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"] = HashAlgorithmName.SHA512,
    };

    /// <summary>
    /// The redirect-binding query for a message (<paramref name="parameter"/> is <c>SAMLRequest</c> or <c>SAMLResponse</c>, already deflated and base64-encoded),
    /// signed with RSA-SHA256 when a key is given: the signature covers <c>param=…&amp;RelayState=…&amp;SigAlg=…</c> exactly as it is sent.
    /// </summary>
    public static string RedirectQuery(string parameter, string encodedMessage, string? relayState, RSA? key)
    {
        var query = $"{parameter}={Uri.EscapeDataString(encodedMessage)}";
        if (!string.IsNullOrEmpty(relayState)) query += $"&RelayState={Uri.EscapeDataString(relayState)}";
        if (key is null) return query;
        query += $"&SigAlg={Uri.EscapeDataString(RsaSha256)}";
        var signature = key.SignData(Encoding.UTF8.GetBytes(query), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return query + $"&Signature={Uri.EscapeDataString(Convert.ToBase64String(signature))}";
    }

    /// <summary>
    /// Checks a redirect-binding signature against the identity provider's certificates, over the parameters exactly as they arrived (raw, still
    /// URL-encoded, in the order the binding fixes). False when there is no signature, the algorithm is weak or unknown, or nothing verifies.
    /// </summary>
    public static bool VerifyRedirect(string rawQuery, string parameter, IReadOnlyList<X509Certificate2> certificates)
    {
        var raw = rawQuery.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Split('=', 2)).Where(p => p.Length == 2).GroupBy(p => p[0]).ToDictionary(g => g.Key, g => g.Select(p => p[1]).ToList());
        // A repeated parameter would make "what was signed" ambiguous.
        if (raw.Values.Any(v => v.Count != 1)) return false;
        if (!raw.TryGetValue(parameter, out var message) || !raw.TryGetValue("SigAlg", out var sigAlg) || !raw.TryGetValue("Signature", out var signatureValue)) return false;
        var algorithm = Uri.UnescapeDataString(sigAlg[0]);
        if (!RedirectAlgorithms.TryGetValue(algorithm, out var hash)) return false;
        var signed = $"{parameter}={message[0]}";
        if (raw.TryGetValue("RelayState", out var relay)) signed += $"&RelayState={relay[0]}";
        signed += $"&SigAlg={sigAlg[0]}";
        byte[] signature;
        try { signature = Convert.FromBase64String(Uri.UnescapeDataString(signatureValue[0])); }
        catch (FormatException) { return false; }
        var data = Encoding.UTF8.GetBytes(signed);
        foreach (var certificate in certificates)
        {
            try
            {
                if (algorithm.Contains("#rsa-", StringComparison.Ordinal) && certificate.GetRSAPublicKey() is { } rsa)
                {
                    using (rsa) if (rsa.VerifyData(data, signature, hash, RSASignaturePadding.Pkcs1)) return true;
                }
                else if (algorithm.Contains("#ecdsa-", StringComparison.Ordinal) && certificate.GetECDsaPublicKey() is { } ec)
                {
                    using (ec) if (ec.VerifyData(data, signature, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) return true;
                }
            }
            catch (CryptographicException) { }
        }
        return false;
    }

    /// <summary>Adds an enveloped RSA-SHA256 signature (exclusive canonicalization) to <paramref name="element"/>, placed right after its Issuer.</summary>
    public static void SignEnveloped(XmlDocument doc, XmlElement element, X509Certificate2 certificate)
    {
        var id = element.GetAttribute("ID");
        var signed = new SignedXml(doc) { SigningKey = certificate.GetRSAPrivateKey() };
        signed.SignedInfo!.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
        signed.SignedInfo.SignatureMethod = RsaSha256;
        var reference = new Reference("#" + id) { DigestMethod = SignedXml.XmlDsigSHA256Url };
        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new XmlDsigExcC14NTransform());
        signed.AddReference(reference);
        var keyInfo = new KeyInfo();
        keyInfo.AddClause(new KeyInfoX509Data(certificate));
        signed.KeyInfo = keyInfo;
        signed.ComputeSignature();
        var signature = doc.ImportNode(signed.GetXml(), true);
        var issuer = element.ChildNodes.OfType<XmlElement>().FirstOrDefault(e => e.LocalName == "Issuer");
        if (issuer is not null) element.InsertAfter(signature, issuer); else element.PrependChild(signature);
    }
}

/// <summary>
/// Decrypts an <c>EncryptedAssertion</c> (XML Encryption 1.1) with the service provider's RSA key. Key transport must be RSA-OAEP (SHA-1 or SHA-256 digest;
/// RSA PKCS#1 v1.5 is refused, it allows padding-oracle attacks); content encryption AES-CBC or AES-GCM (128, 192 or 256 bits). The content key may sit in
/// the EncryptedData's KeyInfo or next to it in the EncryptedAssertion. Nothing is fetched (no RetrievalMethod resolution outside the element).
/// </summary>
public static class SamlDecryptor
{
    public const string XencNs = "http://www.w3.org/2001/04/xmlenc#";
    public const string Xenc11Ns = "http://www.w3.org/2009/xmlenc11#";
    private const string RsaOaepMgf1p = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
    private const string RsaOaep11 = "http://www.w3.org/2009/xmlenc11#rsa-oaep";
    private const string Rsa15 = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";

    private static readonly Dictionary<string, (int KeyBytes, bool Gcm)> ContentAlgorithms = new()
    {
        ["http://www.w3.org/2001/04/xmlenc#aes128-cbc"] = (16, false),
        ["http://www.w3.org/2001/04/xmlenc#aes192-cbc"] = (24, false),
        ["http://www.w3.org/2001/04/xmlenc#aes256-cbc"] = (32, false),
        ["http://www.w3.org/2009/xmlenc11#aes128-gcm"] = (16, true),
        ["http://www.w3.org/2009/xmlenc11#aes192-gcm"] = (24, true),
        ["http://www.w3.org/2009/xmlenc11#aes256-gcm"] = (32, true),
    };

    /// <summary>The plaintext the EncryptedData carried (the Assertion's XML).</summary>
    public static string Decrypt(XmlElement encryptedAssertion, RSA key)
    {
        static SamlException Bad(string message) => new("saml_decryption_failed", message);
        var encryptedData = Child(encryptedAssertion, XencNs, "EncryptedData") ?? throw Bad("The encrypted assertion has no EncryptedData.");
        var method = Child(encryptedData, XencNs, "EncryptionMethod")?.GetAttribute("Algorithm") ?? "";
        if (!ContentAlgorithms.TryGetValue(method, out var content)) throw Bad($"The assertion is encrypted with an algorithm that is not allowed ({method}).");

        var encryptedKey = Child(Child(encryptedData, SamlValidator.DsigNs, "KeyInfo"), XencNs, "EncryptedKey") ?? Child(encryptedAssertion, XencNs, "EncryptedKey")
            ?? throw Bad("The encrypted assertion carries no encrypted key.");
        var keyMethod = Child(encryptedKey, XencNs, "EncryptionMethod");
        var transport = keyMethod?.GetAttribute("Algorithm") ?? "";
        if (transport == Rsa15) throw Bad("RSA PKCS#1 v1.5 key transport is not allowed; configure the identity provider to use RSA-OAEP.");
        if (transport is not (RsaOaepMgf1p or RsaOaep11)) throw Bad($"The assertion key is encrypted with an algorithm that is not allowed ({transport}).");
        var digest = Child(keyMethod, SamlValidator.DsigNs, "DigestMethod")?.GetAttribute("Algorithm");
        var mgf = Child(keyMethod, Xenc11Ns, "MGF")?.GetAttribute("Algorithm");
        var padding = digest switch
        {
            null or "http://www.w3.org/2000/09/xmldsig#sha1" => RSAEncryptionPadding.OaepSHA1,
            "http://www.w3.org/2001/04/xmlenc#sha256" => RSAEncryptionPadding.OaepSHA256,
            _ => throw Bad("The key transport digest is not supported."),
        };
        // .NET pairs MGF1 with the OAEP digest; a different MGF hash cannot be honoured, so it is refused rather than misread.
        var expectedMgf = padding == RSAEncryptionPadding.OaepSHA1 ? "http://www.w3.org/2009/xmlenc11#mgf1sha1" : "http://www.w3.org/2009/xmlenc11#mgf1sha256";
        if (mgf is not null && mgf != expectedMgf) throw Bad("The key transport mask generation function is not supported.");

        byte[] contentKey, cipher;
        try
        {
            contentKey = key.Decrypt(CipherValue(encryptedKey) ?? throw Bad("The encrypted key has no CipherValue."), padding);
            cipher = CipherValue(encryptedData) ?? throw Bad("The encrypted assertion has no CipherValue.");
        }
        catch (CryptographicException) { throw Bad("The assertion could not be decrypted with this service provider's key."); }
        catch (FormatException) { throw Bad("The encrypted assertion is not valid base64."); }
        if (contentKey.Length != content.KeyBytes) throw Bad("The assertion key has the wrong length for its algorithm.");

        byte[] plain;
        try
        {
            if (content.Gcm)
            {
                if (cipher.Length < 12 + 16) throw Bad("The encrypted assertion is too short.");
                var nonce = cipher[..12];
                var tag = cipher[^16..];
                var body = cipher[12..^16];
                plain = new byte[body.Length];
                using var gcm = new AesGcm(contentKey, 16);
                gcm.Decrypt(nonce, body, tag, plain);
            }
            else
            {
                if (cipher.Length < 32 || cipher.Length % 16 != 0) throw Bad("The encrypted assertion is not a whole number of blocks.");
                using var aes = Aes.Create();
                aes.Key = contentKey;
                var raw = aes.DecryptCbc(cipher[16..], cipher[..16], PaddingMode.None);
                // XML Encryption padding: the last byte says how many bytes (1 to 16) to drop; the others are arbitrary.
                var pad = raw[^1];
                if (pad is 0 or > 16) throw Bad("The decrypted assertion has invalid padding.");
                plain = raw[..^pad];
            }
        }
        catch (CryptographicException) { throw Bad("The assertion could not be decrypted with this service provider's key."); }
        return new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(plain);
    }

    private static byte[]? CipherValue(XmlElement holder) =>
        Child(Child(holder, XencNs, "CipherData"), XencNs, "CipherValue") is { } value ? Convert.FromBase64String(value.InnerText.Trim()) : null;

    private static XmlElement? Child(XmlNode? parent, string ns, string local) =>
        parent?.ChildNodes.OfType<XmlElement>().FirstOrDefault(e => e.NamespaceURI == ns && e.LocalName == local);
}
