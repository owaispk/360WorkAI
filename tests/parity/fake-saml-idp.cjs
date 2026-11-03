// A small fake SAML 2.0 identity provider for tests, with no dependencies: it makes its own RSA key and self-signed certificate (with `openssl`), reads an
// AuthnRequest (HTTP-Redirect or HTTP-POST binding), and answers with a signed SAMLResponse in an auto-submitting form, as a real provider's page does.
// The XML is written in exclusive-canonical form on purpose (sorted attributes, no self-closing tags, no whitespace between elements), so the enveloped
// signature can be computed with node:crypto alone.
//
//   const { startFakeSamlIdp } = require('./fake-saml-idp.cjs');
//   const idp = await startFakeSamlIdp({ host: '127.0.0.1' });   // idp.entityId, idp.ssoUrl, idp.certPem
//   idp.identity = { nameId, email, name, nameIdFormat };         // who is signed in next
//   idp.fault = '';                                               // make the next responses bad on purpose (see FAULTS)
//
// FAULTS (idp.fault): 'unsigned' | 'badsig' (another key) | 'tamper' (NameID changed after signing) | 'expired' | 'future' | 'audience' | 'recipient' | 'destination'
//   | 'sha1' | 'wrap' (signature wrapping: a forged assertion first, the real one hidden under Extensions) | 'two-assertions' | 'failed' (status AuthnFailed)
//   | 'wrong-issuer' | 'wrong-irt' (InResponseTo of another request) | 'no-authn' | 'doctype' | 'comment' (comment inside the NameID) | 'response-only' (only the Response signed)
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const { execFileSync } = require('child_process');

const NS_SAMLP = 'urn:oasis:names:tc:SAML:2.0:protocol';
const NS_SAML = 'urn:oasis:names:tc:SAML:2.0:assertion';
const NS_DS = 'http://www.w3.org/2000/09/xmldsig#';
const EMAIL_FORMAT = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';

const text = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\r/g, '&#xD;');
const attr = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;').replace(/\t/g, '&#x9;').replace(/\n/g, '&#xA;').replace(/\r/g, '&#xD;');
const iso = (offsetSeconds = 0) => new Date(Date.now() + offsetSeconds * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
const html = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

function makeKeyAndCert(dir, name) {
  const key = path.join(dir, `${name}.key`), cert = path.join(dir, `${name}.crt`);
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', cert, '-days', '3650', '-subj', `/CN=fake saml idp ${name}`], { stdio: 'ignore' });
  return { privateKey: fs.readFileSync(key, 'utf8'), certPem: fs.readFileSync(cert, 'utf8') };
}

/** The signed element's canonical text with a signature placed right after its Issuer. `element` is a function (signatureXml) => full XML. */
function signElement({ id, canonicalWithoutSignature, privateKey, sha1 = false }) {
  const digestUri = sha1 ? 'http://www.w3.org/2000/09/xmldsig#sha1' : 'http://www.w3.org/2001/04/xmlenc#sha256';
  const sigUri = sha1 ? 'http://www.w3.org/2000/09/xmldsig#rsa-sha1' : 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
  const digest = crypto.createHash(sha1 ? 'sha1' : 'sha256').update(canonicalWithoutSignature, 'utf8').digest('base64');
  const signedInfoBody = `<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:CanonicalizationMethod><ds:SignatureMethod Algorithm="${sigUri}"></ds:SignatureMethod>`
    + `<ds:Reference URI="#${attr(id)}"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"></ds:Transform>`
    + `<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="${digestUri}"></ds:DigestMethod>`
    + `<ds:DigestValue>${digest}</ds:DigestValue></ds:Reference>`;
  const canonicalSignedInfo = `<ds:SignedInfo xmlns:ds="${NS_DS}">${signedInfoBody}</ds:SignedInfo>`;
  const signature = crypto.sign(sha1 ? 'RSA-SHA1' : 'RSA-SHA256', Buffer.from(canonicalSignedInfo, 'utf8'), privateKey).toString('base64');
  return `<ds:Signature xmlns:ds="${NS_DS}"><ds:SignedInfo>${signedInfoBody}</ds:SignedInfo><ds:SignatureValue>${signature}</ds:SignatureValue></ds:Signature>`;
}

function startFakeSamlIdp({ port = 0, host = process.env.IDP_HOST || '127.0.0.1' } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fake-saml-idp-'));
  const real = makeKeyAndCert(dir, 'idp');
  const other = makeKeyAndCert(dir, 'other');
  const p = {
    url: '', entityId: '', ssoUrl: '', certPem: real.certPem, otherCertPem: other.certPem,
    identity: { nameId: 'person@example.test', email: 'person@example.test', name: 'Person One', nameIdFormat: EMAIL_FORMAT },
    fault: '', requests: [], responses: [], binding: 'redirect',
    close: () => new Promise((resolve) => { server.close(resolve); fs.rmSync(dir, { recursive: true, force: true }); }),
  };

  /** One assertion's canonical text (exclusive c14n, `xmlns:saml` on the element) before any signature is added. */
  function assertionXml({ id, issuer, audience, recipient, inResponseTo, identity, notBefore, notOnOrAfter, withAuthn = true, nameIdText }) {
    const attrs = (name, value) => `<saml:Attribute Name="${attr(name)}"><saml:AttributeValue>${text(value)}</saml:AttributeValue></saml:Attribute>`;
    const format = identity.nameIdFormat ? ` Format="${attr(identity.nameIdFormat)}"` : '';
    const scd = `<saml:SubjectConfirmationData${inResponseTo ? ` InResponseTo="${attr(inResponseTo)}"` : ''} NotOnOrAfter="${notOnOrAfter}" Recipient="${attr(recipient)}"></saml:SubjectConfirmationData>`;
    const authn = withAuthn ? `<saml:AuthnStatement AuthnInstant="${iso(-5)}" SessionIndex="_s1"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>` : '';
    const body = `<saml:Issuer>ISSUER_PLACEHOLDER</saml:Issuer>`
      + `<saml:Subject><saml:NameID${format}>${nameIdText ?? text(identity.nameId)}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">${scd}</saml:SubjectConfirmation></saml:Subject>`
      + `<saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}"><saml:AudienceRestriction><saml:Audience>${text(audience)}</saml:Audience></saml:AudienceRestriction></saml:Conditions>`
      + authn
      + `<saml:AttributeStatement>${attrs('email', identity.email)}${attrs('displayName', identity.name)}</saml:AttributeStatement>`;
    const open = `<saml:Assertion xmlns:saml="${NS_SAML}" ID="${attr(id)}" IssueInstant="${iso()}" Version="2.0">`;
    return { open, body: body.replace('ISSUER_PLACEHOLDER', text(issuer)), issuer: text(issuer), id };
  }

  /** The whole SAMLResponse XML for a request, shaped by `fault`. */
  p.buildXml = ({ acs, audience, inResponseTo, identity = p.identity, fault = p.fault, assertionId }) => {
    const issuer = fault === 'wrong-issuer' ? 'https://other-idp.example.test/metadata' : p.entityId;
    const now = 0;
    const notBefore = iso(now - 60), notOnOrAfter = fault === 'expired' ? iso(-900) : iso(300);
    const nbf = fault === 'future' ? iso(900) : notBefore;
    const id = assertionId || '_a' + crypto.randomBytes(12).toString('hex');
    const parts = assertionXml({
      id, issuer, audience: fault === 'audience' ? 'https://other-app.example.test' : audience, recipient: fault === 'recipient' ? acs + '-other' : acs,
      inResponseTo: fault === 'wrong-irt' ? '_someone-elses-request' : inResponseTo, identity, notBefore: nbf, notOnOrAfter, withAuthn: fault !== 'no-authn',
    });
    const canonical = parts.open + parts.body + '</saml:Assertion>';
    const sha1 = fault === 'sha1';
    const key = fault === 'badsig' ? other.privateKey : real.privateKey;
    let assertion;
    if (fault === 'unsigned' || fault === 'response-only') assertion = canonical;
    else {
      const sig = signElement({ id, canonicalWithoutSignature: canonical, privateKey: key, sha1 });
      // The signature sits right after the issuer, as the profile asks.
      const issuerEnd = `<saml:Issuer>${parts.issuer}</saml:Issuer>`;
      assertion = parts.open + parts.body.replace(issuerEnd, issuerEnd + sig) + '</saml:Assertion>';
    }
    if (fault === 'tamper') assertion = assertion.replace(text(identity.nameId), 'admin@' + (identity.nameId.split('@')[1] ?? 'example.test'));
    // A comment inside the name is dropped by canonicalization, so the signature still holds; a reader that stops at the comment would see another name.
    if (fault === 'comment') assertion = assertion.replace(`>${text(identity.nameId)}</saml:NameID>`, `>${text(identity.nameId.split('@')[0])}<!---->@${text(identity.nameId.split('@')[1] ?? 'x.test')}</saml:NameID>`);
    const respId = '_r' + crypto.randomBytes(12).toString('hex');
    const status = fault === 'failed' ? 'urn:oasis:names:tc:SAML:2.0:status:AuthnFailed' : 'urn:oasis:names:tc:SAML:2.0:status:Success';
    const destination = fault === 'destination' ? acs + '-elsewhere' : acs;
    let inner = assertion;
    if (fault === 'wrap') {
      // A forged assertion for an administrator is placed first; the real signed one is hidden under Extensions where nothing reads it.
      const forged = assertionXml({ id: '_forged', issuer, audience, recipient: acs, inResponseTo, identity: { ...identity, nameId: 'admin@' + (identity.nameId.split('@')[1] ?? 'example.test'), email: 'admin@' + (identity.nameId.split('@')[1] ?? 'example.test') }, notBefore: nbf, notOnOrAfter });
      inner = forged.open + forged.body + '</saml:Assertion>' + `<samlp:Extensions>${assertion}</samlp:Extensions>`;
    }
    if (fault === 'two-assertions') inner = assertion + assertion.replace(/ID="[^"]+"/, 'ID="_second"');
    if (fault === 'failed') inner = '';
    const responseOpen = `<samlp:Response xmlns:samlp="${NS_SAMLP}" xmlns:saml="${NS_SAML}" Destination="${attr(destination)}" ID="${respId}"${inResponseTo ? ` InResponseTo="${attr(fault === 'wrong-irt' ? '_someone-elses-request' : inResponseTo)}"` : ''} IssueInstant="${iso()}" Version="2.0">`;
    const head = `<saml:Issuer>${text(issuer)}</saml:Issuer>`;
    const statusXml = `<samlp:Status><samlp:StatusCode Value="${status}"></samlp:StatusCode></samlp:Status>`;
    let doc;
    if (fault === 'response-only') {
      // Only the Response is signed: the assertion itself is not, which the service provider must refuse.
      const unsignedCanonical = responseOpen + head + statusXml + inner + '</samlp:Response>';
      const sig = signElement({ id: respId, canonicalWithoutSignature: unsignedCanonical, privateKey: real.privateKey });
      doc = responseOpen + head + sig + statusXml + inner + '</samlp:Response>';
    } else doc = responseOpen + head + statusXml + inner + '</samlp:Response>';
    if (fault === 'doctype') doc = `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` + doc.replace('</samlp:Response>', '&xxe;</samlp:Response>');
    return doc;
  };

  p.buildResponse = (options) => Buffer.from(p.buildXml(options), 'utf8').toString('base64');

  const form = (acs, samlResponse, relayState) => `<!DOCTYPE html><html><body><form method="post" action="${html(acs)}"><input type="hidden" name="SAMLResponse" value="${html(samlResponse)}">`
    + (relayState ? `<input type="hidden" name="RelayState" value="${html(relayState)}">` : '') + `<noscript><button type="submit">Continue</button></noscript></form><script>document.forms[0].submit();</script></body></html>`;

  const server = http.createServer((req, res) => {
    const url = new URL(req.url, p.url || 'http://127.0.0.1');
    const send = (status, type, body) => { res.writeHead(status, { 'content-type': type, 'cache-control': 'no-store' }); res.end(body); };
    if (url.pathname === '/metadata') {
      const der = real.certPem.replace(/-----[^-]+-----|\s+/g, '');
      return send(200, 'application/xml', `<?xml version="1.0"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${attr(p.entityId)}"><md:IDPSSODescriptor protocolSupportEnumeration="${NS_SAMLP}"><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="${NS_DS}"><ds:X509Data><ds:X509Certificate>${der}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${attr(p.ssoUrl)}"></md:SingleSignOnService></md:IDPSSODescriptor></md:EntityDescriptor>`);
    }
    if (url.pathname === '/cert') return send(200, 'text/plain', real.certPem);
    if (url.pathname === '/sso') {
      const collect = (body) => {
        const params = req.method === 'POST' ? Object.fromEntries(new URLSearchParams(body)) : Object.fromEntries(url.searchParams);
        let xml;
        try {
          const raw = Buffer.from(params.SAMLRequest || '', 'base64');
          xml = req.method === 'POST' ? raw.toString('utf8') : zlib.inflateRawSync(raw).toString('utf8');
        } catch { return send(400, 'text/plain', 'bad SAMLRequest'); }
        const id = /\sID="([^"]+)"/.exec(xml)?.[1];
        const acs = /AssertionConsumerServiceURL="([^"]+)"/.exec(xml)?.[1];
        const audience = /<saml:Issuer[^>]*>([^<]+)<\/saml:Issuer>/.exec(xml)?.[1];
        p.requests.push({ method: req.method, id, acs, audience, relayState: params.RelayState, xml, query: params });
        if (!id || !acs || !audience) return send(400, 'text/plain', 'not an AuthnRequest');
        const response = p.buildResponse({ acs, audience, inResponseTo: id });
        p.responses.push({ acs, response, relayState: params.RelayState });
        return send(200, 'text/html', form(acs, response, params.RelayState));
      };
      if (req.method === 'POST') { let body = ''; req.on('data', (c) => { body += c; }); req.on('end', () => collect(body)); } else collect('');
      return;
    }
    // IdP-initiated: the provider sends a response nobody asked for (no InResponseTo, no RelayState).
    if (url.pathname === '/initiate') {
      const acs = url.searchParams.get('acs'), audience = url.searchParams.get('audience');
      const response = p.buildResponse({ acs, audience });
      p.responses.push({ acs, response, relayState: null });
      return send(200, 'text/html', form(acs, response, null));
    }
    send(404, 'text/plain', 'not found');
  });

  return new Promise((resolve) => server.listen(port, host, () => {
    p.url = `http://${host}:${server.address().port}`;
    p.entityId = `${p.url}/metadata`;
    p.ssoUrl = `${p.url}/sso`;
    resolve(p);
  }));
}

/** Reads the auto-submitting form a provider answers with: where it posts and what. */
function readForm(htmlText) {
  const action = /<form[^>]*action="([^"]*)"/.exec(htmlText)?.[1]?.replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
  const fields = {};
  for (const m of htmlText.matchAll(/<input[^>]*name="([^"]+)"[^>]*value="([^"]*)"/g)) fields[m[1]] = m[2].replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
  return { action, fields };
}

module.exports = { startFakeSamlIdp, readForm, EMAIL_FORMAT };
