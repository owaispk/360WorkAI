using System.Security.Cryptography;
using System.Text;
using System.Xml;
using WorkAI360.Api.Features.Sso;

namespace WorkAI360.Api.Tests;

/// <summary>The SAML response checks in isolation: signatures (including signature wrapping), XML safety, and every claim.</summary>
public sealed class SamlValidatorTests : IDisposable
{
    private const string Acs = "https://den.example.test/api/auth/sso/saml2/sp/acs/openwork-sso-org_x";
    private const string Sp = "https://den.example.test";
    private const string Assertion = SamlValidator.AssertionNs;
    private readonly SamlTestIdp _idp = new();

    public void Dispose() => _idp.Dispose();

    private SamlExpectations Expect(SamlTestIdp? idp = null, TimeSpan? skew = null, params SamlTestIdp[] more) =>
        new((idp ?? _idp).EntityId, Sp, [Acs], [(idp ?? _idp).Certificate, .. more.Select(m => m.Certificate)], DateTimeOffset.UtcNow, skew ?? TimeSpan.FromMinutes(5));

    private SamlAssertion Ok(SamlOptions? o = null) => SamlValidator.Validate(_idp.Build(Acs, Sp, o), Expect());
    private SamlException Refused(string response, SamlExpectations? e = null) => Assert.Throws<SamlException>(() => SamlValidator.Validate(response, e ?? Expect()));
    private SamlException Refused(SamlOptions o) => Refused(_idp.Build(Acs, Sp, o));

    private XmlDocument Signed(SamlOptions? o = null)
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(Encoding.UTF8.GetString(Convert.FromBase64String(_idp.Build(Acs, Sp, o))));
        return doc;
    }

    private static XmlElement AssertionOf(XmlDocument doc) => doc.GetElementsByTagName("Assertion", Assertion).Cast<XmlElement>().First();
    private static string Encode(XmlDocument doc) => SamlTestIdp.Encode(doc.OuterXml);

    // ---------------------------------------------------------------- the good path

    [Fact]
    public void A_signed_assertion_is_accepted_and_read()
    {
        var a = Ok(new SamlOptions { InResponseTo = "_req1", Email = "a@example.test", NameId = "a@example.test" });
        Assert.Equal("a@example.test", a.NameId);
        Assert.Equal(SamlProtocol.EmailNameId, a.NameIdFormat);
        Assert.Equal("_req1", a.InResponseTo);
        Assert.Equal("_s1", a.SessionIndex);
        Assert.Equal(_idp.EntityId, a.Issuer);
        Assert.Equal(["a@example.test"], a.Attributes["email"]);
        Assert.True(a.ReplayExpiresAt > DateTime.UtcNow.AddMinutes(5));
    }

    [Fact]
    public void A_response_signed_as_well_as_the_assertion_is_accepted() => Ok(new SamlOptions { SignResponse = true });

    [Fact]
    public void Any_of_several_certificates_can_verify_so_a_key_rotation_works()
    {
        using var old = new SamlTestIdp();
        SamlValidator.Validate(_idp.Build(Acs, Sp), Expect(old, null, _idp) with { IdpEntityId = _idp.EntityId });
        SamlValidator.Validate(_idp.Build(Acs, Sp), Expect(_idp, null, old));
    }

    [Fact]
    public void Rsa_sha512_signatures_are_accepted() => Ok(new SamlOptions { UseRsaSha512 = true });

    // ---------------------------------------------------------------- signatures

    [Fact]
    public void An_unsigned_response_is_refused() => Assert.Equal("saml_assertion_signature_required", Refused(new SamlOptions { Unsigned = true }).Code);

    [Fact]
    public void A_response_signature_alone_does_not_stand_in_for_a_signed_assertion() =>
        Assert.Equal("saml_assertion_signature_required", Refused(new SamlOptions { SignAssertion = false, SignResponse = true }).Code);

    [Fact]
    public void A_signature_by_another_key_is_refused() => Assert.Equal("saml_signature_invalid", Refused(new SamlOptions { UseOtherKey = true }).Code);

    [Fact]
    public void Changing_anything_after_signing_breaks_the_signature()
    {
        var doc = Signed();
        var nameId = doc.GetElementsByTagName("NameID", Assertion).Cast<XmlElement>().First();
        nameId.InnerText = "admin@example.test";
        Assert.Equal("saml_signature_invalid", Refused(Encode(doc)).Code);
    }

    [Fact]
    public void Changing_the_audience_or_time_after_signing_breaks_the_signature()
    {
        var doc = Signed();
        var conditions = doc.GetElementsByTagName("Conditions", Assertion).Cast<XmlElement>().First();
        conditions.SetAttribute("NotOnOrAfter", DateTime.UtcNow.AddYears(5).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"));
        Assert.Equal("saml_signature_invalid", Refused(Encode(doc)).Code);
    }

    [Fact]
    public void A_certificate_that_is_not_the_providers_is_refused()
    {
        using var other = new SamlTestIdp();
        Assert.Equal("saml_signature_invalid", Refused(_idp.Build(Acs, Sp), new SamlExpectations(_idp.EntityId, Sp, [Acs], [other.Certificate], DateTimeOffset.UtcNow, TimeSpan.FromMinutes(5))).Code);
    }

    [Fact]
    public void A_key_carried_in_the_message_is_never_trusted()
    {
        // The attacker signs with their own key and ships their certificate inside the signature: only the configured certificate counts.
        using var attacker = new SamlTestIdp();
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(attacker.BuildXml(Acs, Sp, new SamlOptions { Issuer = _idp.EntityId }));
        var assertion = AssertionOf(doc);
        var sx = new System.Security.Cryptography.Xml.SignedXml(doc) { SigningKey = attacker.Key };
        var reference = new System.Security.Cryptography.Xml.Reference("#" + assertion.GetAttribute("ID"));
        reference.AddTransform(new System.Security.Cryptography.Xml.XmlDsigEnvelopedSignatureTransform());
        reference.AddTransform(new System.Security.Cryptography.Xml.XmlDsigExcC14NTransform());
        sx.AddReference(reference);
        sx.KeyInfo = new System.Security.Cryptography.Xml.KeyInfo();
        sx.KeyInfo.AddClause(new System.Security.Cryptography.Xml.KeyInfoX509Data(attacker.Certificate));
        sx.ComputeSignature();
        assertion.InsertAfter(doc.ImportNode(sx.GetXml(), true), assertion.ChildNodes.OfType<XmlElement>().First());
        Assert.Equal("saml_signature_invalid", Refused(Encode(doc)).Code);
    }

    [Fact]
    public void Sha1_signatures_are_refused_as_deprecated() => Assert.Equal("saml_deprecated_algorithm", Refused(new SamlOptions { Sha1 = true }).Code);

    [Fact]
    public void A_signature_method_outside_the_allow_list_is_refused()
    {
        var doc = Signed();
        var method = doc.GetElementsByTagName("SignatureMethod", SamlValidator.DsigNs).Cast<XmlElement>().First();
        method.SetAttribute("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256");
        Assert.Equal("saml_unsupported_algorithm", Refused(Encode(doc)).Code);
    }

    [Fact]
    public void An_hmac_signature_cannot_be_checked_against_the_public_key()
    {
        // The classic key-confusion attack signs with the public key as an HMAC secret.
        var doc = Signed(new SamlOptions { Unsigned = true });
        var assertion = AssertionOf(doc);
        var id = assertion.GetAttribute("ID");
        var signed = $"<ds:Signature xmlns:ds=\"{SamlValidator.DsigNs}\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#hmac-sha1\"/><ds:Reference URI=\"#{id}\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature>";
        var frag = doc.CreateDocumentFragment();
        frag.InnerXml = signed;
        assertion.InsertAfter(frag, assertion.ChildNodes.OfType<XmlElement>().First());
        Assert.Contains(Refused(Encode(doc)).Code, new[] { "saml_deprecated_algorithm", "saml_unsupported_algorithm" });
    }

    [Fact]
    public void A_transform_that_could_reach_outside_the_document_is_refused()
    {
        var doc = Signed();
        var transforms = doc.GetElementsByTagName("Transforms", SamlValidator.DsigNs).Cast<XmlElement>().First();
        var xslt = doc.CreateElement("ds", "Transform", SamlValidator.DsigNs);
        xslt.SetAttribute("Algorithm", "http://www.w3.org/TR/1999/REC-xslt-19991116");
        transforms.AppendChild(xslt);
        Assert.Equal("saml_unsupported_algorithm", Refused(Encode(doc)).Code);
    }

    [Fact]
    public void A_signature_must_cover_the_element_it_sits_in()
    {
        var doc = Signed(new SamlOptions { SignAssertion = false, SignResponse = true });
        // Move the response's signature into the assertion: it now claims to cover the assertion but references the response.
        var signature = doc.GetElementsByTagName("Signature", SamlValidator.DsigNs).Cast<XmlElement>().First();
        signature.ParentNode!.RemoveChild(signature);
        var assertion = AssertionOf(doc);
        assertion.InsertAfter(signature, assertion.ChildNodes.OfType<XmlElement>().First());
        Assert.Equal("saml_signature_invalid", Refused(Encode(doc)).Code);
    }

    [Fact]
    public void An_empty_reference_uri_is_refused()
    {
        var doc = Signed();
        doc.GetElementsByTagName("Reference", SamlValidator.DsigNs).Cast<XmlElement>().First().SetAttribute("URI", "");
        Assert.Equal("saml_signature_invalid", Refused(Encode(doc)).Code);
    }

    [Fact]
    public void Two_signatures_in_the_assertion_are_refused()
    {
        var doc = Signed();
        var assertion = AssertionOf(doc);
        var second = (XmlElement)doc.GetElementsByTagName("Signature", SamlValidator.DsigNs)[0]!.CloneNode(true);
        assertion.InsertAfter(second, assertion.ChildNodes.OfType<XmlElement>().First());
        Assert.Equal("saml_signature_invalid", Refused(Encode(doc)).Code);
    }

    [Fact]
    public void A_signature_in_an_unexpected_place_is_refused()
    {
        var doc = Signed();
        var signature = (XmlElement)doc.GetElementsByTagName("Signature", SamlValidator.DsigNs)[0]!.CloneNode(true);
        var extensions = doc.CreateElement("samlp", "Extensions", SamlValidator.ProtocolNs);
        extensions.AppendChild(signature);
        doc.DocumentElement!.InsertBefore(extensions, AssertionOf(doc));
        Assert.Equal("saml_signature_invalid", Refused(Encode(doc)).Code);
    }

    // ---------------------------------------------------------------- signature wrapping

    [Fact]
    public void Wrapping_an_evil_assertion_around_the_signed_one_is_refused()
    {
        // The signed assertion is hidden in Advice of a new unsigned one that the application would read first.
        var doc = Signed();
        var signed = AssertionOf(doc);
        var evilXml = _idp.BuildXml(Acs, Sp, new SamlOptions { NameId = "admin@example.test", Email = "admin@example.test", AssertionId = "_evil" });
        var evilDoc = new XmlDocument { PreserveWhitespace = true };
        evilDoc.LoadXml(evilXml);
        var evil = (XmlElement)doc.ImportNode(AssertionOf(evilDoc), true);
        var advice = doc.CreateElement("saml", "Advice", Assertion);
        signed.ParentNode!.ReplaceChild(evil, signed);
        advice.AppendChild(signed);
        evil.AppendChild(advice);
        Assert.Equal("saml_multiple_assertions", Refused(Encode(doc)).Code);
    }

    [Fact]
    public void An_unsigned_assertion_next_to_the_signed_one_is_refused()
    {
        var doc = Signed();
        var evilDoc = new XmlDocument { PreserveWhitespace = true };
        evilDoc.LoadXml(_idp.BuildXml(Acs, Sp, new SamlOptions { NameId = "admin@example.test", Email = "admin@example.test", AssertionId = "_evil" }));
        doc.DocumentElement!.InsertBefore(doc.ImportNode(AssertionOf(evilDoc), true), AssertionOf(doc));
        Assert.Equal("saml_multiple_assertions", Refused(Encode(doc)).Code);
    }

    [Fact]
    public void The_signed_assertion_moved_under_extensions_with_a_forged_one_in_its_place_is_refused()
    {
        var doc = Signed();
        var signed = AssertionOf(doc);
        var extensions = doc.CreateElement("samlp", "Extensions", SamlValidator.ProtocolNs);
        signed.ParentNode!.RemoveChild(signed);
        extensions.AppendChild(signed);
        doc.DocumentElement!.AppendChild(extensions);
        var forgedDoc = new XmlDocument { PreserveWhitespace = true };
        forgedDoc.LoadXml(_idp.BuildXml(Acs, Sp, new SamlOptions { NameId = "admin@example.test", Email = "admin@example.test", AssertionId = "_forged" }));
        doc.DocumentElement.AppendChild(doc.ImportNode(AssertionOf(forgedDoc), true));
        Assert.Equal("saml_multiple_assertions", Refused(Encode(doc)).Code);
    }

    [Fact]
    public void Only_a_signed_assertion_hidden_in_extensions_leaves_no_assertion_in_place()
    {
        var doc = Signed();
        var signed = AssertionOf(doc);
        var extensions = doc.CreateElement("samlp", "Extensions", SamlValidator.ProtocolNs);
        signed.ParentNode!.RemoveChild(signed);
        extensions.AppendChild(signed);
        doc.DocumentElement!.AppendChild(extensions);
        Assert.Equal("saml_invalid_xml", Refused(Encode(doc)).Code);
    }

    [Fact]
    public void An_id_shared_with_another_element_is_refused()
    {
        var doc = Signed();
        var assertion = AssertionOf(doc);
        var subject = assertion.GetElementsByTagName("Subject", Assertion).Cast<XmlElement>().First();
        subject.SetAttribute("ID", assertion.GetAttribute("ID"));
        Assert.Equal("saml_signature_invalid", Refused(Encode(doc)).Code);
    }

    [Fact]
    public void The_id_lookup_is_case_blind_for_the_attribute_name_too()
    {
        var doc = Signed();
        var assertion = AssertionOf(doc);
        var subject = assertion.GetElementsByTagName("Subject", Assertion).Cast<XmlElement>().First();
        subject.SetAttribute("id", assertion.GetAttribute("ID"));
        Assert.Equal("saml_signature_invalid", Refused(Encode(doc)).Code);
    }

    [Fact]
    public void An_assertion_that_is_not_a_child_of_the_response_is_refused()
    {
        var doc = Signed();
        var assertion = AssertionOf(doc);
        var wrapper = doc.CreateElement("samlp", "Extensions", SamlValidator.ProtocolNs);
        assertion.ParentNode!.ReplaceChild(wrapper, assertion);
        wrapper.AppendChild(assertion);
        Assert.Equal("saml_invalid_xml", Refused(Encode(doc)).Code);
    }

    // ---------------------------------------------------------------- XML safety

    [Fact]
    public void A_doctype_is_refused_so_no_entity_is_ever_expanded()
    {
        var xml = Encoding.UTF8.GetString(Convert.FromBase64String(_idp.Build(Acs, Sp)));
        var e = Refused(SamlTestIdp.Encode("<!DOCTYPE foo [<!ENTITY x \"y\">]>" + xml));
        Assert.Equal("saml_invalid_xml", e.Code);
        Assert.Contains("DTD", e.Message);
    }

    [Fact]
    public void An_external_entity_cannot_read_a_local_file()
    {
        var xml = "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_x\" Version=\"2.0\">&xxe;</samlp:Response>";
        var e = Refused(SamlTestIdp.Encode(xml));
        Assert.Equal("saml_invalid_xml", e.Code);
        Assert.DoesNotContain("root:", e.Message);
    }

    [Fact]
    public void An_entity_expansion_bomb_is_refused_without_expanding()
    {
        var xml = "<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\"><!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">]><samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">&lol3;</samlp:Response>";
        var started = System.Diagnostics.Stopwatch.StartNew();
        Assert.Equal("saml_invalid_xml", Refused(SamlTestIdp.Encode(xml)).Code);
        Assert.True(started.Elapsed < TimeSpan.FromSeconds(2));
    }

    [Fact]
    public void An_encrypted_assertion_is_refused_with_a_clear_reason()
    {
        var doc = Signed();
        var assertion = AssertionOf(doc);
        var encrypted = doc.CreateElement("saml", "EncryptedAssertion", Assertion);
        assertion.ParentNode!.ReplaceChild(encrypted, assertion);
        Assert.Equal("saml_encrypted_assertion", Refused(Encode(doc)).Code);
    }

    [Fact]
    public void A_comment_inside_the_name_cannot_truncate_it()
    {
        // "admin@example.test<!---->.evil.test" must be read as one name, as the signature (which ignores comments) saw it.
        var xml = _idp.BuildXml(Acs, Sp, new SamlOptions { NameId = "XX" }).Replace("XX", "victim@example.test<!---->.evil.test");
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(xml);
        _idp.Sign(AssertionOf(doc));
        var read = SamlValidator.Validate(Encode(doc), Expect());
        Assert.Equal("victim@example.test.evil.test", read.NameId);
    }

    [Fact]
    public void The_encoding_is_checked()
    {
        Assert.Equal("saml_invalid_encoding", Refused("").Code);
        Assert.Equal("saml_invalid_encoding", Refused("***not base64***").Code);
        Assert.Equal("saml_invalid_encoding", Refused(Convert.ToBase64String("plain text"u8.ToArray())).Code);
        Assert.Equal("saml_invalid_xml", Refused(SamlTestIdp.Encode("<a><b></a>")).Code);
    }

    [Fact]
    public void A_response_over_the_size_limit_is_refused()
    {
        var big = new string('A', SamlValidator.MaxEncodedLength + 4);
        Assert.Equal("saml_too_large", Refused(big).Code);
    }

    [Fact]
    public void Whitespace_inside_the_base64_is_tolerated_as_browsers_and_providers_wrap_lines()
    {
        var encoded = _idp.Build(Acs, Sp);
        var wrapped = string.Join("\r\n", Enumerable.Range(0, (encoded.Length + 75) / 76).Select(i => encoded.Substring(i * 76, Math.Min(76, encoded.Length - i * 76))));
        SamlValidator.Validate(wrapped, Expect());
    }

    // ---------------------------------------------------------------- claims

    [Fact]
    public void A_failed_authentication_is_reported_not_parsed()
    {
        var e = Refused(new SamlOptions { Status = "urn:oasis:names:tc:SAML:2.0:status:Responder" });
        Assert.Equal("saml_status_not_success", e.Code);
        Assert.Contains("Responder", e.Message);
    }

    [Fact]
    public void An_assertion_from_another_issuer_is_refused() => Assert.Equal("saml_issuer_mismatch", Refused(new SamlOptions { Issuer = "https://other.example.test" }).Code);

    [Fact]
    public void A_response_issuer_that_differs_is_refused()
    {
        var doc = Signed();
        doc.DocumentElement!.ChildNodes.OfType<XmlElement>().First(e => e.LocalName == "Issuer").InnerText = "https://other.example.test";
        Assert.Equal("saml_issuer_mismatch", Refused(Encode(doc)).Code);
    }

    [Fact]
    public void An_assertion_for_another_audience_is_refused() => Assert.Equal("saml_audience_mismatch", Refused(new SamlOptions { Audience = "https://other-app.example.test" }).Code);

    [Fact]
    public void An_assertion_without_an_audience_restriction_is_refused() => Assert.Equal("saml_audience_missing", Refused(new SamlOptions { OmitAudience = true }).Code);

    [Fact]
    public void Every_audience_restriction_must_name_this_service()
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(_idp.BuildXml(Acs, Sp, new SamlOptions()));
        var conditions = doc.GetElementsByTagName("Conditions", Assertion).Cast<XmlElement>().First();
        var restriction = doc.CreateElement("saml", "AudienceRestriction", Assertion);
        restriction.AppendChild(doc.CreateElement("saml", "Audience", Assertion))!.InnerText = "https://other-app.example.test";
        conditions.AppendChild(restriction);
        _idp.Sign(AssertionOf(doc));
        Assert.Equal("saml_audience_mismatch", Refused(Encode(doc)).Code);
    }

    [Fact]
    public void A_destination_for_another_address_is_refused() => Assert.Equal("saml_destination_mismatch", Refused(new SamlOptions { Destination = "https://evil.example.test/acs" }).Code);

    [Fact]
    public void A_recipient_for_another_address_is_refused() => Assert.Equal("saml_recipient_mismatch", Refused(new SamlOptions { Recipient = "https://den.example.test/api/auth/sso/saml2/sp/acs/openwork-sso-org_other" }).Code);

    [Fact]
    public void A_missing_recipient_or_bearer_confirmation_is_refused()
    {
        Assert.Equal("saml_recipient_missing", Refused(new SamlOptions { OmitRecipient = true }).Code);
        Assert.Equal("saml_bearer_confirmation_missing", Refused(new SamlOptions { OmitBearer = true }).Code);
    }

    [Fact]
    public void An_expired_assertion_is_refused_but_a_little_clock_skew_is_not()
    {
        Assert.Equal("saml_expired", Refused(new SamlOptions { NotOnOrAfterSeconds = -600, ConfirmationNotOnOrAfterSeconds = -600 }).Code);
        Ok(new SamlOptions { NotOnOrAfterSeconds = -120, ConfirmationNotOnOrAfterSeconds = -120 });
    }

    [Fact]
    public void The_confirmation_expiry_counts_on_its_own()
    {
        Assert.Equal("saml_expired", Refused(new SamlOptions { ConfirmationNotOnOrAfterSeconds = -900 }).Code);
        Assert.Equal("saml_expired", Refused(new SamlOptions { NotOnOrAfterSeconds = -900 }).Code);
    }

    [Fact]
    public void An_assertion_that_is_not_yet_valid_is_refused()
    {
        Assert.Equal("saml_not_yet_valid", Refused(new SamlOptions { NotBeforeSeconds = 900 }).Code);
        Ok(new SamlOptions { NotBeforeSeconds = 120 });
    }

    [Fact]
    public void The_skew_is_the_callers_choice()
    {
        var response = _idp.Build(Acs, Sp, new SamlOptions { NotOnOrAfterSeconds = -120, ConfirmationNotOnOrAfterSeconds = -120 });
        Refused(response, Expect(skew: TimeSpan.FromSeconds(30)));
        SamlValidator.Validate(response, Expect(skew: TimeSpan.FromMinutes(10)));
    }

    [Fact]
    public void Timestamps_are_required()
    {
        Assert.Equal("saml_timestamps_missing", Refused(new SamlOptions { OmitConditions = true }).Code);
        Assert.Equal("saml_timestamps_missing", Refused(new SamlOptions { ConfirmationNotOnOrAfterSeconds = null }).Code);
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(_idp.BuildXml(Acs, Sp, new SamlOptions()));
        var conditions = doc.GetElementsByTagName("Conditions", Assertion).Cast<XmlElement>().First();
        conditions.RemoveAttribute("NotBefore");
        conditions.RemoveAttribute("NotOnOrAfter");
        _idp.Sign(AssertionOf(doc));
        Assert.Equal("saml_timestamps_missing", Refused(Encode(doc)).Code);
    }

    [Fact]
    public void An_unknown_condition_is_refused_because_it_cannot_be_evaluated()
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(_idp.BuildXml(Acs, Sp, new SamlOptions()));
        var conditions = doc.GetElementsByTagName("Conditions", Assertion).Cast<XmlElement>().First();
        conditions.AppendChild(doc.CreateElement("saml", "Condition", Assertion));
        _idp.Sign(AssertionOf(doc));
        Assert.Equal("saml_unsupported_condition", Refused(Encode(doc)).Code);
    }

    [Fact]
    public void An_assertion_that_authenticated_nobody_is_refused() => Assert.Equal("saml_missing_subject", Refused(new SamlOptions { OmitAuthnStatement = true }).Code);

    [Fact]
    public void An_empty_name_is_refused() => Assert.Equal("saml_missing_subject", Refused(new SamlOptions { NameId = " " }).Code);

    [Fact]
    public void In_response_to_comes_from_the_signed_assertion()
    {
        Assert.Equal("_req", Ok(new SamlOptions { InResponseTo = "_req" }).InResponseTo);
        Assert.Null(Ok(new SamlOptions { OmitInResponseTo = true }).InResponseTo);
    }

    [Fact]
    public void An_in_response_to_only_on_the_unsigned_response_is_not_believed()
    {
        var o = new SamlOptions { OmitInResponseTo = true, ResponseInResponseTo = "_req" };
        Assert.Equal("saml_in_response_to_mismatch", Refused(o).Code);
        // When the response is signed too, its value is covered.
        Assert.Equal("_req", Ok(o with { SignResponse = true }).InResponseTo);
    }

    [Fact]
    public void A_response_and_assertion_answering_different_requests_are_refused() =>
        Assert.Equal("saml_in_response_to_mismatch", Refused(new SamlOptions { InResponseTo = "_a", ResponseInResponseTo = "_b" }).Code);

    [Fact]
    public void Attributes_are_collected_by_name_and_friendly_name()
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(_idp.BuildXml(Acs, Sp, new SamlOptions()).Replace("<saml:Attribute Name=\"displayName\">", "<saml:Attribute Name=\"urn:oid:2.16.840.1.113730.3.1.241\" FriendlyName=\"displayName\">"));
        _idp.Sign(AssertionOf(doc));
        var a = SamlValidator.Validate(Encode(doc), Expect());
        Assert.Equal(["Person One"], a.Attributes["displayName"]);
        Assert.Equal(["Person One"], a.Attributes["urn:oid:2.16.840.1.113730.3.1.241"]);
    }

    // ---------------------------------------------------------------- certificates and identity

    [Fact]
    public void Certificates_are_read_as_pem_or_bare_base64()
    {
        var pem = _idp.CertificatePem;
        var bare = Convert.ToBase64String(_idp.Certificate.RawData);
        Assert.Equal([bare], SamlCertificates.Normalize(pem)!);
        Assert.Equal([bare], SamlCertificates.Normalize(bare)!);
        Assert.Equal([bare], SamlCertificates.Normalize(string.Join("\n  ", bare.Chunk(64).Select(c => new string(c))))!);
        using var second = new SamlTestIdp();
        Assert.Equal(2, SamlCertificates.Normalize(pem + "\n" + second.CertificatePem)!.Length);
        Assert.Equal([bare], SamlCertificates.Normalize(pem + "\n" + pem)!);
    }

    [Fact]
    public void Garbage_is_not_a_certificate()
    {
        Assert.Null(SamlCertificates.Normalize(null));
        Assert.Null(SamlCertificates.Normalize(""));
        Assert.Null(SamlCertificates.Normalize("not a certificate"));
        Assert.Null(SamlCertificates.Normalize("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"));
        Assert.Null(SamlCertificates.Normalize(new string('A', 70_000)));
        using var rsa = RSA.Create(2048);
        Assert.Null(SamlCertificates.Normalize(rsa.ExportSubjectPublicKeyInfoPem()));
    }

    [Fact]
    public void The_identity_comes_from_the_email_attribute_then_the_name_id()
    {
        var fromAttribute = SamlFlow.ExtractIdentity(Ok(new SamlOptions { NameId = "opaque-1", NameIdFormat = null, Email = "Mixed.Case@Example.test" }))!;
        Assert.Equal("opaque-1", fromAttribute.Subject);
        Assert.Equal("mixed.case@example.test", fromAttribute.Email);
        Assert.Equal("Person One", fromAttribute.Name);
        var fromNameId = SamlFlow.ExtractIdentity(Ok(new SamlOptions { NameId = "who@example.test", Email = null }))!;
        Assert.Equal("who@example.test", fromNameId.Email);
        Assert.Null(SamlFlow.ExtractIdentity(Ok(new SamlOptions { NameId = "opaque-2", Email = null })));
    }

    [Fact]
    public void A_transient_name_id_cannot_name_a_person_so_the_address_does()
    {
        var identity = SamlFlow.ExtractIdentity(Ok(new SamlOptions { NameId = "_transient-8f3", NameIdFormat = SamlValidator.TransientNameId, Email = "p@example.test" }))!;
        Assert.Equal("email:p@example.test", identity.Subject);
    }

    [Fact]
    public void Given_and_family_names_make_the_name()
    {
        var doc = new XmlDocument { PreserveWhitespace = true };
        doc.LoadXml(_idp.BuildXml(Acs, Sp, new SamlOptions { DisplayName = null }).Replace("</saml:AttributeStatement>",
            "<saml:Attribute Name=\"givenName\"><saml:AttributeValue>Ada</saml:AttributeValue></saml:Attribute><saml:Attribute Name=\"surname\"><saml:AttributeValue>Byron</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>"));
        _idp.Sign(AssertionOf(doc));
        Assert.Equal("Ada Byron", SamlFlow.ExtractIdentity(SamlValidator.Validate(Encode(doc), Expect()))!.Name);
    }

    [Fact]
    public void Protocol_helpers_round_trip()
    {
        var xml = SamlProtocol.AuthnRequest("_id1", Sp, "https://idp.example.test/sso", Acs, DateTime.UtcNow);
        var url = SamlProtocol.RedirectUrl("https://idp.example.test/sso?tenant=1", xml, "relay-1");
        var query = System.Web.HttpUtility.ParseQueryString(new Uri(url).Query);
        Assert.Equal("1", query["tenant"]);
        Assert.Equal("relay-1", query["RelayState"]);
        Assert.Equal(xml, SamlProtocol.InflateRequest(query["SAMLRequest"]!));
        var metadata = SamlProtocol.Metadata(Sp, Acs);
        Assert.Contains($"entityID=\"{Sp}\"", metadata);
        Assert.Contains("WantAssertionsSigned=\"true\"", metadata);
        Assert.Contains($"Location=\"{Acs}\"", metadata);
        var (html, hash) = SamlProtocol.PostForm("https://idp.example.test/sso", xml, "a\"><script>");
        Assert.DoesNotContain("<script>alert", html);
        Assert.Contains("&lt;script&gt;", html);
        Assert.NotEmpty(hash);
    }
}
