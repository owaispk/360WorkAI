using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Web;
using System.Xml;
using WorkAI360.Api.Domain.Saml;
using WorkAI360.Api.Domain.Sso;
using WorkAI360.Api.Features.Sso;
using static WorkAI360.Api.Tests.ApiFactory;

namespace WorkAI360.Api.Tests;

/// <summary>What the identity provider does with the service provider's published key: encrypting assertions to it, and signing logout messages.</summary>
public static class SamlExtrasKit
{
    public const string Aes256Cbc = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
    public const string Aes128Gcm = "http://www.w3.org/2009/xmlenc11#aes128-gcm";

    public static async Task<X509Certificate2> SpCertificateAsync(HttpClient http, string providerId)
    {
        var xml = await (await http.GetAsync($"/api/auth/sso/saml2/sp/metadata?providerId={providerId}")).Content.ReadAsStringAsync();
        var doc = new XmlDocument();
        doc.LoadXml(xml);
        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("ds", SamlValidator.DsigNs);
        return X509CertificateLoader.LoadCertificate(Convert.FromBase64String(doc.SelectSingleNode("//ds:X509Certificate", ns)!.InnerText));
    }

    /// <summary>Replaces the (signed) assertion of a base64 response with an EncryptedAssertion for <paramref name="spCert"/>.</summary>
    public static string Encrypt(string responseB64, X509Certificate2 spCert, string contentAlgorithm = Aes256Cbc, string transport = "oaep-sha1", Action<XmlDocument>? after = null, string? plaintext = null)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(Encoding.UTF8.GetString(Convert.FromBase64String(responseB64)));
        var assertion = (XmlElement)doc.GetElementsByTagName("Assertion", SamlValidator.AssertionNs)[0]!;
        var plain = Encoding.UTF8.GetBytes(plaintext ?? assertion.OuterXml);
        var gcm = contentAlgorithm.Contains("gcm");
        var key = RandomNumberGenerator.GetBytes(contentAlgorithm.Contains("128") ? 16 : 32);
        byte[] cipher;
        if (gcm)
        {
            var nonce = RandomNumberGenerator.GetBytes(12);
            var body = new byte[plain.Length];
            var tag = new byte[16];
            using var aes = new AesGcm(key, 16);
            aes.Encrypt(nonce, plain, body, tag);
            cipher = [.. nonce, .. body, .. tag];
        }
        else
        {
            using var aes = Aes.Create();
            aes.Key = key;
            var iv = RandomNumberGenerator.GetBytes(16);
            cipher = [.. iv, .. aes.EncryptCbc(plain, iv, PaddingMode.PKCS7)];
        }
        using var rsa = spCert.GetRSAPublicKey()!;
        var (padding, method) = transport switch
        {
            "rsa15" => (RSAEncryptionPadding.Pkcs1, "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-1_5\"/>"),
            "oaep-sha256" => (RSAEncryptionPadding.OaepSHA256, "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#rsa-oaep\"><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><xenc11:MGF Algorithm=\"http://www.w3.org/2009/xmlenc11#mgf1sha256\"/></xenc:EncryptionMethod>"),
            _ => (RSAEncryptionPadding.OaepSHA1, "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/></xenc:EncryptionMethod>"),
        };
        var encryptedKey = rsa.Encrypt(key, padding);
        var fragment = $"<saml:EncryptedAssertion xmlns:saml=\"{SamlValidator.AssertionNs}\"><xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" xmlns:xenc11=\"http://www.w3.org/2009/xmlenc11#\" xmlns:ds=\"{SamlValidator.DsigNs}\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\">"
            + $"<xenc:EncryptionMethod Algorithm=\"{contentAlgorithm}\"/><ds:KeyInfo><xenc:EncryptedKey>{method}<xenc:CipherData><xenc:CipherValue>{Convert.ToBase64String(encryptedKey)}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo>"
            + $"<xenc:CipherData><xenc:CipherValue>{Convert.ToBase64String(cipher)}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion>";
        var holder = new XmlDocument { PreserveWhitespace = true };
        holder.LoadXml(fragment);
        assertion.ParentNode!.ReplaceChild(doc.ImportNode(holder.DocumentElement!, true), assertion);
        after?.Invoke(doc);
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(doc.OuterXml));
    }

    /// <summary>A redirect-binding URL path+query to the SP's SLO endpoint, signed with the identity provider's key (or not).</summary>
    public static string RedirectTo(string path, string parameter, string xml, RSA? key, string? relay = null) =>
        path + "?" + SamlSigning.RedirectQuery(parameter, SamlLogout.Deflate(xml), relay, key);

    public static (string Parameter, string Xml, string Query) ReadRedirect(Uri location)
    {
        var query = HttpUtility.ParseQueryString(location.Query);
        var parameter = query["SAMLRequest"] is not null ? "SAMLRequest" : "SAMLResponse";
        return (parameter, SamlProtocol.InflateRequest(query[parameter]!), location.Query);
    }
}

/// <summary>A connection that signs its requests and knows the identity provider's logout URL: encrypted assertions, signed AuthnRequests, Single Logout.</summary>
public sealed class SamlExtrasTests(SsoFactory factory) : SamlBase, IClassFixture<SsoFactory>
{
    protected override SsoFactory Factory => factory;
    private const string IdpSlo = "https://idp.example.test/slo";
    private string SloPath => $"/api/auth/sso/saml2/sp/slo/{W.ProviderId}";

    public override async Task InitializeAsync()
    {
        await base.InitializeAsync();
        Assert.Equal(HttpStatusCode.Created, (await W.RegisterAsync(new { signAuthnRequests = true, singleLogoutUrl = IdpSlo })).Status);
        await W.VerifyDomainAsync(factory.Dns);
        await W.RunTestAsync(factory.Browser(), new SamlOptions { NameId = W.OwnerEmail, Email = W.OwnerEmail });
        Assert.Equal(HttpStatusCode.NoContent, (await W.Owner(HttpMethod.Post, "/v1/sso/enable", new { })).Status);
    }

    // ---------------------------------------------------------------- metadata and signed requests

    [Fact]
    public async Task Metadata_publishes_the_sp_key_for_signing_and_encryption_and_the_logout_endpoints()
    {
        var xml = await (await Factory.Plain().GetAsync($"/api/auth/sso/saml2/sp/metadata?providerId={W.ProviderId}")).Content.ReadAsStringAsync();
        Assert.Contains("AuthnRequestsSigned=\"true\"", xml);
        Assert.Contains("use=\"signing\"", xml);
        Assert.Contains("use=\"encryption\"", xml);
        Assert.Contains($"<md:SingleLogoutService Binding=\"{SamlProtocol.RedirectBinding}\" Location=\"http://localhost{SloPath}\"", xml);
        // One key per connection, made once, private part encrypted at rest.
        var row = W.Db(db => db.Set<SamlSpKey>().Single(k => k.ProviderId == W.ProviderId));
        Assert.DoesNotContain("PRIVATE", row.ProtectedPrivateKey);
        var again = await SamlExtrasKit.SpCertificateAsync(Factory.Plain(), W.ProviderId);
        Assert.Equal(row.CertificateDer, Convert.ToBase64String(again.Export(X509ContentType.Cert)));
    }

    [Fact]
    public async Task Redirect_binding_requests_carry_a_query_signature_made_with_the_sp_key()
    {
        var started = await W.StartAsync(Factory.Browser());
        var query = new Uri(started.Url).Query;
        Assert.Contains("SigAlg=", query);
        Assert.Contains("Signature=", query);
        using var cert = await SamlExtrasKit.SpCertificateAsync(Factory.Plain(), W.ProviderId);
        Assert.True(SamlSigning.VerifyRedirect(query, "SAMLRequest", [cert]));
        // Tampering with the request breaks it.
        Assert.False(SamlSigning.VerifyRedirect(query.Replace("RelayState=", "RelayState=x"), "SAMLRequest", [cert]));
        Assert.False(SamlSigning.VerifyRedirect(query, "SAMLRequest", [Idp.Certificate]));
    }

    [Fact]
    public async Task Post_binding_requests_carry_an_enveloped_signature()
    {
        Assert.Equal(HttpStatusCode.Created, (await W.RegisterAsync(new { binding = "post", signAuthnRequests = true })).Status);
        // Saving a connection again resets it (disabled, untested, domain unproven).
        await W.VerifyDomainAsync(factory.Dns);
        await W.RunTestAsync(Factory.Browser(), new SamlOptions { NameId = W.OwnerEmail, Email = W.OwnerEmail });
        Assert.Equal(HttpStatusCode.NoContent, (await W.Owner(HttpMethod.Post, "/v1/sso/enable", new { })).Status);
        var browser = Factory.Browser();
        var r = await browser.PostAsJsonAsync("/api/auth/sign-in/sso", new { organizationSlug = W.OrgId, callbackURL = "/dashboard" });
        var started = await W.ResolveAsync(browser, (await ReadJsonAsync(r)).GetProperty("url").GetString()!);
        var doc = SamlValidator.Parse(started.Xml);
        using var cert = await SamlExtrasKit.SpCertificateAsync(Factory.Plain(), W.ProviderId);
        SamlValidator.VerifyRootSignature(doc, [cert]);
        Assert.Throws<SamlException>(() => SamlValidator.VerifyRootSignature(SamlValidator.Parse(started.Xml.Replace("http://localhost/api/auth/sso", "http://evil.example/api/auth/sso")), [cert]));
    }

    // ---------------------------------------------------------------- encrypted assertions

    [Theory]
    [InlineData(SamlExtrasKit.Aes256Cbc, "oaep-sha1", false)]
    [InlineData(SamlExtrasKit.Aes128Gcm, "oaep-sha256", false)]
    [InlineData(SamlExtrasKit.Aes256Cbc, "oaep-sha1", true)]
    public async Task An_encrypted_signed_assertion_signs_the_person_in(string content, string transport, bool signResponseOverEncrypted)
    {
        using var cert = await SamlExtrasKit.SpCertificateAsync(Factory.Plain(), W.ProviderId);
        var browser = Factory.Browser();
        var started = await W.StartAsync(browser);
        var email = Person("encrypted");
        var encrypted = SamlExtrasKit.Encrypt(W.Response(started, For(email)), cert, content, transport,
            after: signResponseOverEncrypted ? doc => Idp.Sign(doc.DocumentElement!) : null);
        var acs = await W.PostAcsAsync(browser, encrypted, started.RelayState);
        Assert.Equal(HttpStatusCode.SeeOther, acs.StatusCode);
        await browser.GetAsync(SamlWorld.PathAndQuery(acs.Headers.Location!.ToString()));
        Assert.Equal(email, await MeEmail(browser));
    }

    [Fact]
    public async Task Encrypted_assertions_that_are_weak_unsigned_tampered_or_for_another_key_are_refused()
    {
        using var cert = await SamlExtrasKit.SpCertificateAsync(Factory.Plain(), W.ProviderId);
        using var otherRsa = RSA.Create(2048);
        using var other = new CertificateRequest("CN=other", otherRsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));

        async Task<string> Refusal(Func<SamlWorld.Started, string> build)
        {
            var browser = Factory.Browser();
            var started = await W.StartAsync(browser);
            var acs = await W.PostAcsAsync(browser, build(started), started.RelayState);
            Assert.Equal(HttpStatusCode.Redirect, acs.StatusCode);
            Assert.Equal(401, await MeStatus(browser));
            return SamlWorld.Query(acs, "error_description");
        }

        Assert.Contains("PKCS#1 v1.5", await Refusal(s => SamlExtrasKit.Encrypt(W.Response(s, For(Person("a"))), cert, transport: "rsa15")));
        Assert.Contains("could not be decrypted", await Refusal(s => SamlExtrasKit.Encrypt(W.Response(s, For(Person("b"))), other)));
        Assert.Contains("must be signed", await Refusal(s => SamlExtrasKit.Encrypt(W.Response(s, For(Person("c")) with { SignAssertion = false }), cert)));
        Assert.Contains("could not be decrypted", await Refusal(s => SamlExtrasKit.Encrypt(W.Response(s, For(Person("d"))), cert, SamlExtrasKit.Aes128Gcm,
            after: doc => { var v = doc.GetElementsByTagName("CipherValue", SamlDecryptor.XencNs)[1]!; var bytes = Convert.FromBase64String(v.InnerText); bytes[20] ^= 1; v.InnerText = Convert.ToBase64String(bytes); })));
        // A response signature must still verify over the encrypted form.
        Assert.Contains("could not be verified", await Refusal(s => SamlExtrasKit.Encrypt(W.Response(s, For(Person("e"))), cert,
            after: doc => { Idp.Sign(doc.DocumentElement!); doc.GetElementsByTagName("Issuer", SamlValidator.AssertionNs)[0]!.InnerText = Idp.EntityId + "x"; })));
        Assert.Equal(0, W.Db(db => db.Users.Count(u => u.Email.StartsWith("a@") || u.Email.StartsWith("b@") || u.Email.StartsWith("c@") || u.Email.StartsWith("d@") || u.Email.StartsWith("e@"))));
    }

    // ---------------------------------------------------------------- Single Logout

    private async Task<HttpClient> SignedInAsync(string email)
    {
        var browser = Factory.Browser();
        var (_, final) = await W.SignInAsync(browser, For(email, email));
        Assert.Equal(HttpStatusCode.Redirect, final!.StatusCode);
        Assert.Equal(200, await MeStatus(browser));
        return browser;
    }

    private string LogoutRequest(string nameId, string? sessionIndex = null, string? issuer = null, string? destination = null, int expiresInSeconds = 300) =>
        SamlLogout.Request("_lr" + Guid.NewGuid().ToString("N"), issuer ?? Idp.EntityId, destination ?? "http://localhost" + SloPath, nameId, SamlProtocol.EmailNameId, sessionIndex, DateTime.UtcNow)
            .Replace(" NotOnOrAfter=\"", " NotOnOrAfter=\"" + (expiresInSeconds < 0 ? DateTime.UtcNow.AddSeconds(expiresInSeconds).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'") + "\" Old=\"" : ""));

    [Fact]
    public async Task An_identity_provider_logout_request_ends_that_persons_sessions_and_is_answered_signed()
    {
        var email = Person("slo");
        var browser = await SignedInAsync(email);
        var bystander = await SignedInAsync(Person("bystander"));
        var request = LogoutRequest(email, "_s1");
        var r = await Factory.Plain().GetAsync(SamlExtrasKit.RedirectTo(SloPath, "SAMLRequest", request, Idp.Key, relay: "idp-relay"));
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.StartsWith(IdpSlo + "?", r.Headers.Location!.ToString());

        var (parameter, xml, query) = SamlExtrasKit.ReadRedirect(r.Headers.Location!);
        Assert.Equal("SAMLResponse", parameter);
        Assert.Contains($"InResponseTo=\"{SamlValidator.Parse(request).DocumentElement!.GetAttribute("ID")}\"", xml);
        Assert.Contains(SamlLogout.StatusSuccess, xml);
        Assert.Contains("RelayState=idp-relay", query);
        using var cert = await SamlExtrasKit.SpCertificateAsync(Factory.Plain(), W.ProviderId);
        Assert.True(SamlSigning.VerifyRedirect(query, "SAMLResponse", [cert]));

        Assert.Equal(401, await MeStatus(browser));
        Assert.Equal(200, await MeStatus(bystander));
        Assert.Equal(0, W.Db(db => db.Set<SamlSessionLink>().Count(l => l.NameId == email)));

        // The same request again is refused (used once).
        Assert.Equal(HttpStatusCode.BadRequest, (await Factory.Plain().GetAsync(SamlExtrasKit.RedirectTo(SloPath, "SAMLRequest", request, Idp.Key))).StatusCode);
    }

    [Fact]
    public async Task A_post_binding_logout_request_with_an_xml_signature_works_too()
    {
        var email = Person("slopost");
        var browser = await SignedInAsync(email);
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(LogoutRequest(email));
        Idp.Sign(doc.DocumentElement!);
        var r = await Factory.Plain().PostAsync(SloPath, new FormUrlEncodedContent(new Dictionary<string, string> { ["SAMLRequest"] = SamlTestIdp.Encode(doc.OuterXml) }));
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.Equal(401, await MeStatus(browser));
    }

    [Fact]
    public async Task Unsigned_forged_misaddressed_or_expired_logout_requests_end_nothing()
    {
        var email = Person("slosafe");
        var browser = await SignedInAsync(email);
        using var stranger = RSA.Create(2048);
        foreach (var url in new[]
        {
            SamlExtrasKit.RedirectTo(SloPath, "SAMLRequest", LogoutRequest(email), key: null),                                   // unsigned
            SamlExtrasKit.RedirectTo(SloPath, "SAMLRequest", LogoutRequest(email), stranger),                                    // someone else's key
            SamlExtrasKit.RedirectTo(SloPath, "SAMLRequest", LogoutRequest(email, issuer: "https://other-idp.example"), Idp.Key), // another issuer
            SamlExtrasKit.RedirectTo(SloPath, "SAMLRequest", LogoutRequest(email, destination: "https://elsewhere.example/slo"), Idp.Key),
            SamlExtrasKit.RedirectTo(SloPath, "SAMLRequest", LogoutRequest(email, expiresInSeconds: -3600), Idp.Key),
        })
            Assert.Equal(HttpStatusCode.BadRequest, (await Factory.Plain().GetAsync(url)).StatusCode);
        // An unsigned POST is refused as well.
        var post = await Factory.Plain().PostAsync(SloPath, new FormUrlEncodedContent(new Dictionary<string, string> { ["SAMLRequest"] = SamlTestIdp.Encode(LogoutRequest(email)) }));
        Assert.Equal(HttpStatusCode.BadRequest, post.StatusCode);
        Assert.Equal(200, await MeStatus(browser));
    }

    [Fact]
    public async Task A_persons_own_logout_ends_the_session_here_and_asks_the_identity_provider_with_a_signed_request()
    {
        var email = Person("splo");
        var browser = await SignedInAsync(email);
        var userId = W.Db(db => db.Users.Single(u => u.Email == email).Id);
        Assert.Equal(1, W.Db(db => db.Sessions.Count(s => s.UserId == userId)));
        var r = await browser.GetAsync($"/api/auth/sso/saml2/sp/logout/{W.ProviderId}");
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.Equal(401, await MeStatus(browser));
        // Ended on the server, not only forgotten by the browser (a copied cookie must not work either).
        Assert.Equal(0, W.Db(db => db.Sessions.Count(s => s.UserId == userId)));
        var (parameter, xml, query) = SamlExtrasKit.ReadRedirect(r.Headers.Location!);
        Assert.Equal("SAMLRequest", parameter);
        Assert.Contains($">{email}</saml:NameID>", xml);
        Assert.Contains("<samlp:SessionIndex>_s1</samlp:SessionIndex>", xml);
        using var cert = await SamlExtrasKit.SpCertificateAsync(Factory.Plain(), W.ProviderId);
        Assert.True(SamlSigning.VerifyRedirect(query, "SAMLRequest", [cert]));

        // The identity provider answers; only an answer to that request is taken, once.
        var requestId = SamlValidator.Parse(xml).DocumentElement!.GetAttribute("ID");
        var answer = SamlLogout.Response("_lp" + Guid.NewGuid().ToString("N"), requestId, Idp.EntityId, "http://localhost" + SloPath, SamlLogout.StatusSuccess, DateTime.UtcNow);
        var done = await browser.GetAsync(SamlExtrasKit.RedirectTo(SloPath, "SAMLResponse", answer, Idp.Key));
        Assert.Equal(HttpStatusCode.Redirect, done.StatusCode);
        Assert.Equal("http://localhost/", done.Headers.Location!.ToString());
        Assert.Equal(HttpStatusCode.BadRequest, (await browser.GetAsync(SamlExtrasKit.RedirectTo(SloPath, "SAMLResponse", answer, Idp.Key))).StatusCode);
        var unknown = SamlLogout.Response("_lp2", "_never_sent", Idp.EntityId, "http://localhost" + SloPath, SamlLogout.StatusSuccess, DateTime.UtcNow);
        Assert.Equal(HttpStatusCode.BadRequest, (await browser.GetAsync(SamlExtrasKit.RedirectTo(SloPath, "SAMLResponse", unknown, Idp.Key))).StatusCode);
    }

    [Fact]
    public async Task Logging_out_without_a_saml_session_just_signs_out_locally()
    {
        var r = await Factory.Browser().GetAsync($"/api/auth/sso/saml2/sp/logout/{W.ProviderId}");
        Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
        Assert.Equal("http://localhost/", r.Headers.Location!.ToString());
    }
}

/// <summary>The validator on its own: what an EncryptedAssertion must decrypt to.</summary>
public sealed class SamlDecryptionUnitTests
{
    [Fact]
    public void Encrypted_content_that_is_not_an_assertion_is_refused_and_a_missing_key_is_named()
    {
        using var idp = new SamlTestIdp();
        using var rsa = RSA.Create(2048);
        using var sp = new CertificateRequest("CN=sp", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        const string acs = "https://sp.example/acs", entity = "https://sp.example";
        var expectations = new SamlExpectations(idp.EntityId, entity, [acs], [idp.Certificate], DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5), rsa);

        var notAnAssertion = SamlExtrasKit.Encrypt(idp.Build(acs, entity), sp, plaintext: $"<saml:Issuer xmlns:saml=\"{SamlValidator.AssertionNs}\">x</saml:Issuer>");
        Assert.Equal("saml_decryption_failed", Assert.Throws<SamlException>(() => SamlValidator.Validate(notAnAssertion, expectations)).Code);

        var fine = SamlExtrasKit.Encrypt(idp.Build(acs, entity), sp);
        Assert.Equal("person@example.test", SamlValidator.Validate(fine, expectations).NameId);
        Assert.Equal("saml_encrypted_assertion", Assert.Throws<SamlException>(() => SamlValidator.Validate(fine, expectations with { DecryptionKey = null })).Code);
    }
}

/// <summary>The redirect binding's query signature on its own.</summary>
public sealed class SamlRedirectSignatureTests
{
    [Fact]
    public void Weak_algorithms_and_repeated_parameters_never_verify()
    {
        using var idp = new SamlTestIdp();
        var good = SamlSigning.RedirectQuery("SAMLRequest", SamlLogout.Deflate("<x/>"), "relay", idp.Key);
        Assert.True(SamlSigning.VerifyRedirect(good, "SAMLRequest", [idp.Certificate]));

        // SHA-1, correctly signed, is still refused.
        var sha1Base = $"SAMLRequest={Uri.EscapeDataString(SamlLogout.Deflate("<x/>"))}&RelayState=relay&SigAlg={Uri.EscapeDataString("http://www.w3.org/2000/09/xmldsig#rsa-sha1")}";
        var sha1 = sha1Base + "&Signature=" + Uri.EscapeDataString(Convert.ToBase64String(idp.Key.SignData(Encoding.UTF8.GetBytes(sha1Base), HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1)));
        Assert.False(SamlSigning.VerifyRedirect(sha1, "SAMLRequest", [idp.Certificate]));

        // A second SAMLRequest smuggled next to the signed one makes the query ambiguous.
        Assert.False(SamlSigning.VerifyRedirect(good + "&SAMLRequest=" + Uri.EscapeDataString(SamlLogout.Deflate("<y/>")), "SAMLRequest", [idp.Certificate]));
        // No signature at all.
        Assert.False(SamlSigning.VerifyRedirect(SamlSigning.RedirectQuery("SAMLRequest", SamlLogout.Deflate("<x/>"), null, null), "SAMLRequest", [idp.Certificate]));
    }
}

/// <summary>Registering a connection from pasted identity provider metadata.</summary>
public sealed class SamlMetadataImportTests(SsoFactory factory) : SamlBase, IClassFixture<SsoFactory>
{
    protected override SsoFactory Factory => factory;

    private string IdpMetadata(bool redirect = true, bool withSlo = true, string? extra = null) =>
        $"<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"{SamlValidator.DsigNs}\" entityID=\"{Idp.EntityId}\">{extra}"
        + "<md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">"
        + $"<md:KeyDescriptor use=\"signing\"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>{Convert.ToBase64String(Idp.Certificate.Export(X509ContentType.Cert))}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"
        + (withSlo ? $"<md:SingleLogoutService Binding=\"{SamlProtocol.RedirectBinding}\" Location=\"https://idp.example.test/slo\"/>" : "")
        + $"<md:SingleSignOnService Binding=\"{SamlProtocol.PostBinding}\" Location=\"https://idp.example.test/sso-post\"/>"
        + (redirect ? $"<md:SingleSignOnService Binding=\"{SamlProtocol.RedirectBinding}\" Location=\"{Idp.SsoUrl}\"/>" : "")
        + "</md:IDPSSODescriptor></md:EntityDescriptor>";

    [Fact]
    public async Task Metadata_fills_issuer_sign_on_url_certificate_and_logout_url()
    {
        var r = await W.Owner(HttpMethod.Post, "/v1/sso/saml", new { domain = W.Domain, idpMetadata = IdpMetadata() });
        Assert.Equal(HttpStatusCode.Created, r.Status);
        var settings = W.Db(db => SsoService.SamlSettingsOf(db.Set<SsoConnection>().Single(c => c.ProviderId == W.ProviderId)))!;
        Assert.Equal(Idp.EntityId, settings.IdpEntityId);
        Assert.Equal(Idp.SsoUrl, settings.EntryPoint);
        Assert.Equal("redirect", settings.Binding);
        Assert.Equal("https://idp.example.test/slo", settings.SloUrl);
        Assert.Equal(Convert.ToBase64String(Idp.Certificate.Export(X509ContentType.Cert)), Assert.Single(settings.Certificates));

        // POST binding when that is all the provider offers; explicit fields win over the metadata.
        r = await W.Owner(HttpMethod.Post, "/v1/sso/saml", new { domain = W.Domain, idpMetadata = IdpMetadata(redirect: false, withSlo: false), entryPoint = "https://idp.example.test/custom" });
        Assert.Equal(HttpStatusCode.Created, r.Status);
        settings = W.Db(db => SsoService.SamlSettingsOf(db.Set<SsoConnection>().Single(c => c.ProviderId == W.ProviderId)))!;
        Assert.Equal("post", settings.Binding);
        Assert.Equal("https://idp.example.test/custom", settings.EntryPoint);
        Assert.Null(settings.SloUrl);
    }

    [Fact]
    public async Task Bad_metadata_is_refused_with_a_reason()
    {
        async Task<string> Refused(string xml)
        {
            var (status, body) = await W.Owner(HttpMethod.Post, "/v1/sso/saml", new { domain = W.Domain, idpMetadata = xml });
            Assert.Equal(HttpStatusCode.BadRequest, status);
            return body.ToString();
        }
        Assert.Contains("DTD", await Refused("<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]>" + IdpMetadata()));
        Assert.Contains("no identity provider", await Refused("<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"x\"/>"));
        Assert.Contains("not valid XML", await Refused("<md:EntityDescriptor"));
        Assert.Contains("too large", await Refused(IdpMetadata(extra: new string(' ', SamlMetadataImport.MaxLength))));
        // Without metadata the three fields are still required.
        Assert.Equal(HttpStatusCode.BadRequest, (await W.Owner(HttpMethod.Post, "/v1/sso/saml", new { domain = W.Domain })).Status);
        Assert.Equal(0, W.Db(db => db.Set<SsoConnection>().Count(c => c.ProviderId == W.ProviderId)));
    }
}
