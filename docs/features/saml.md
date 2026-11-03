# SAML 2.0 sign-in

Reference: Better Auth's SSO plugin (`@better-auth/sso` 1.7, which uses samlify) as configured in `ee/apps/den-api/src/sso.ts`, `sso-saml-policy.ts`,
`sso-saml-response-policy.ts`, `sso-saml-response-middleware.ts`, `routes/org/sso.ts` and `auth.ts`. Code: `Features/Sso/Saml*.cs`, `SsoService.Saml.cs`,
`Domain/Saml/`, `Features/Replay/`. Page: the SAML half of `/dashboard/sso`. Tests: `SamlValidatorTests`, `SamlSignInTests` (xUnit),
`tests/parity/area-saml.mjs` (with `fake-saml-idp.cjs`), `tests/parity/ui-saml.js`.

A workspace can now connect a SAML 2.0 identity provider next to (or instead of) OpenID Connect. A workspace has one connection, of either kind. Domain
proof, the connection test, enabling, SCIM, "SSO-enforced workspaces close password sign-in" and everything in [sso-scim.md](sso-scim.md) apply unchanged.

## Routes

| Route | What |
|---|---|
| `POST /v1/sso/saml` | `{issuer, domain, entryPoint, cert, audience?}` as the reference (`issuer` is the identity provider's entity id, `entryPoint` its sign-in URL, `cert` its signing certificate as PEM text, several PEM blocks for a key rotation, or bare base64). Adds an optional `binding`: `"redirect"` (default) or `"post"`. Answers `201 {connection, domainVerificationToken}`; saving replaces the connection and resets it to disabled, untested, unproven |
| `GET /v1/sso/metadata[?format=xml\|json]` | the service provider metadata (XML; as in the reference `format` is validated and the answer is always the XML). `404 organization_not_found` for no connection or an OpenID Connect one |
| `GET /api/auth/sso/saml2/sp/metadata?providerId=` | the same document, public (the identity provider's administrator imports it): `404` unknown, `400 Invalid SAML configuration` for a non-SAML connection |
| `POST /api/auth/sign-in/sso` | now also starts a SAML sign-in: `{url, redirect: true}` (the identity provider's address with `SAMLRequest` and `RelayState`, or this server's `login` page for the POST binding) |
| `POST /api/auth/sso/saml2/sp/acs/{providerId}` | the assertion consumer service: form (or JSON) `SAMLResponse`, `RelayState`. Always answers a redirect for the browser (`403 sso_not_enabled`, `404`, `400` aside). `GET` redirects to the error page, or to the web root for someone signed in |
| `GET /api/auth/sso/saml2/sp/continue/{providerId}?id=` | the same-site last step (below); this build only |
| `GET /api/auth/sso/saml2/sp/login/{providerId}?relay=` | the POST-binding page (an auto-submitting form to the identity provider, CSP limited to its origin and one script hash); this build only |

`GET /v1/sso` shows `kind: "saml"`, `oidc: null`, `saml: {entryPoint, audience, wantAssertionsSigned: true, binding}` (the reference has the first three), `acsUrl`
(`{web}/api/auth/sso/saml2/sp/acs/{providerId}`), `metadataUrl` and, as the reference does even for SAML, the OpenID `redirectUrl`. The certificate is public but is not
repeated in the read model. The service provider entity id (audience) defaults to the web address, as in the reference.

## What a response must pass

`SamlValidator` (pure, unit tested) then `SamlFlow`:

* **XML**: DTDs prohibited (no entity is ever expanded: XXE and entity bombs are refused), no resolver, comments dropped (a comment cannot split a name), 256 KB limit.
* **Encrypted assertions** (one `EncryptedAssertion`, a direct child of the Response) are decrypted with the connection's service provider key (below): a signature on
  the Response is verified over the encrypted form first, then the plaintext must be a SAML `Assertion`, which replaces the encrypted one and is held to every rule below,
  its own signature included. Key transport RSA-OAEP (SHA-1 or SHA-256 digest; RSA PKCS#1 v1.5 is refused, it allows padding-oracle attacks), content AES-CBC or AES-GCM
  (128 to 256 bits). Encrypted IDs and attributes are refused. Without a service provider key the answer is "no service provider key to decrypt it".
* **Signature wrapping**: exactly one `Assertion` in the whole document and it is a direct child of the `Response`; signatures only directly under the Response or that
  Assertion, at most one each; a signature must reference exactly its own parent by id (`#id`), that id must be unique in the document (attribute `ID`, `Id` or `id`), and the
  reference lookup is pinned to that parent (the stock "first element with this id" is replaced), so the verified element is the very one the claims are read from. Only the
  enveloped-signature transform and (exclusive) canonicalization are allowed (no XPath, XSLT or external references).
* **Keys**: the identity provider's pinned certificates only (never `KeyInfo` from the message); any of several verifies, so rotation works. SHA-1 and unknown algorithms are
  refused (`onDeprecated: reject`, as the reference), HMAC never verifies.
* **The assertion must be signed** (the reference's `wantAssertionsSigned`); a signature on the Response must verify too, but does not stand in for it.
* **Claims**: status Success; issuer is the configured identity provider; `Destination` (when present) and the bearer `Recipient` are this ACS address; the audience
  restriction names this service provider (every restriction); `NotBefore` / `NotOnOrAfter` of the conditions and `NotOnOrAfter` of the confirmation with a clock skew of
  5 minutes (`Sso:SamlClockSkewSeconds`); at least one timestamp; unknown conditions refused; an `AuthnStatement`; a usable email (attribute `email`/`mail`/... or an
  address-shaped NameID) inside the workspace's **proven** domain.
* **InResponseTo** comes from the signed assertion; a value only on an unsigned Response is not believed. A response that answers a request must name one this service
  sent for this connection and configuration, not yet answered. A response with no `InResponseTo` is *IdP-initiated*: accepted by default as in the reference
  (`ORGANIZATION_SAML_ALLOW_IDP_INITIATED`), refused with `unsolicited_response` when `Sso:SamlAllowIdpInitiated=false`.
* **Replay cache**: the assertion id (with issuer and connection) is reserved in a database table (`ReplayReservation`, primary key = hash) until the assertion could no longer
  be accepted; a second use is `replay_detected`. It is atomic, so six simultaneous posts of one response sign in exactly once, on any instance.

## The same-browser last step (differs from the reference, on purpose)

The identity provider's POST is cross-site, so a `SameSite=Lax` cookie does not travel with it. After the response is fully validated the ACS parks the identity on the
request row (`SamlAuthRequest`: ids stored only as SHA-256) and answers `303` to `continue`, a same-site navigation that does carry the binding cookie
(`openwork-den.saml_state`, set when the sign-in started). Only then is anybody signed in. A response an attacker obtained in their own browser cannot be handed to a
victim's (login CSRF); a captured request cannot be finished twice. The reference does no browser binding. IdP-initiated sign-ins have nothing to bind and sign in at the ACS.

Failures redirect to the sign-in's `errorCallbackURL` (else its `callbackURL`; else, for an IdP-initiated response, the workspace's `/sso/{slug}` page) with
`error` and `error_description`: `invalid_saml_response` (the reason in the description), `invalid_state`, `replay_detected`, `unsolicited_response`, and the shared SSO codes
(`email_outside_sso_domain`, `access_denied`). The `/sso/{slug}` page explains them in words.

## Differences from the reference

| Reference | Here | Why |
|---|---|---|
| samlify; any binding data from IdP metadata | A small validator on `System.Security.Cryptography.Xml`; configuration is the three fields above | Smaller, testable surface; samlify's behavior was matched where the source was readable |
| No browser binding | Binding cookie checked at a same-site last step | Login CSRF |
| `idpMetadata`, signed AuthnRequests, SLO, encrypted assertions (plugin options, not reachable through the reference's `/v1/sso/saml`) | Built (below); `idpMetadata`, `signAuthnRequests` and `singleLogoutUrl` are accepted by `/v1/sso/saml` | The plugin supports them; the routes are this build's |
| Custom SP metadata, `additionalParams`, multiple `RelayState` shapes | Not built | |
| `issuer` stored on the provider is the audience | `connection.issuer` is the identity provider's entity id, `saml.audience` the service provider's | Same as what the reference's routes show |
| A transient NameID is the account key | A transient NameID cannot name a person: the (domain-checked) email is the key | The id changes at every sign-in |
| Timestamps: NotBefore and/or NotOnOrAfter | Conditions need one of them and the bearer confirmation needs `NotOnOrAfter` | Web SSO profile |
| `RelayState` that is not one of ours when IdP-initiated: rejected | Rejected the same (`invalid_state`) | Parity |
| Plan gating (`402`), audit events | Not built (as for OIDC) | |

## Service provider key, signed requests, metadata import, Single Logout

Code: `Features/Sso/SamlServiceProvider.cs`, `SamlCrypto.cs`, `SamlLogoutFlow.cs`, entities `Domain/Saml/SamlSpEntities.cs`. Tests: `SamlExtrasTests` and friends (23),
`tests/parity/ui-saml-extras.js` (6, browser).

* **Service provider key** (`SamlSpKey`): one per connection, made on first use (RSA 2048, a self-signed certificate valid 10 years); the private key is stored encrypted
  (AES-GCM, key derived from `Auth:Secret`). The SP metadata (`/api/auth/sso/saml2/sp/metadata` and `/v1/sso/metadata`) publishes its certificate as `KeyDescriptor use="signing"`
  and `use="encryption"`, the Single Logout endpoints and `AuthnRequestsSigned`.
* **Signed AuthnRequests** (`signAuthnRequests: true` on `/v1/sso/saml`, off by default): redirect binding with a `SigAlg`/`Signature` query signature (RSA-SHA256, SAML bindings
  3.4.4.1), POST binding with an enveloped XML signature after the Issuer.
* **IdP metadata import** (`idpMetadata` on `/v1/sso/saml`): an `EntityDescriptor` (or one inside an `EntitiesDescriptor`) with an `IDPSSODescriptor` gives the entity id, the
  sign-on URL (redirect binding preferred, else POST, which sets `binding`), the signing certificates (`use="signing"` or no `use`) and the redirect-binding logout URL. Issuer,
  sign-on URL and certificate become optional; fields given explicitly win. DTDs are refused, 256 KB at most, nothing is fetched (paste the XML; no metadata URL).
* **Single Logout** (`singleLogoutUrl`, or from metadata):
  * sessions opened by a SAML sign-in remember its NameID, format and SessionIndex (`SamlSessionLink`);
  * IdP-initiated: `GET` (redirect binding) or `POST` `/api/auth/sso/saml2/sp/slo/{providerId}` with a `LogoutRequest`. It must be signed with the identity provider's
    certificate (query signature over the parameters exactly as received, repeated parameters refused, SHA-256 or stronger; or an enveloped XML signature held to the response
    rules), name the configured issuer, be addressed to this endpoint (when `Destination` is present), not have expired, and is used once (replay table). Every session that
    sign-ins with that NameID (and, when given, those session indexes) opened through this connection ends; the answer is a signed `LogoutResponse` (redirect binding, RelayState
    echoed) to the identity provider's logout URL, or "Signed out." when none is configured;
  * SP-initiated: `GET /api/auth/sso/saml2/sp/logout/{providerId}` ends the session here (server side, cookie cleared) and, when the session came from this connection and a
    logout URL is known, redirects to the identity provider with a signed `LogoutRequest`. Only a `LogoutResponse` answering a request this service sent (id hashed, 10 minutes,
    answered once) is accepted back; the person lands on the home page.
* **SSO page**: a metadata paste box, the logout URL and the "sign requests" option.

Mutation checks (16 of 17 killed): redirect and POST signatures not required, issuer, destination and expiry not checked, logout-request replay allowed, every session of the
connection ended instead of the NameID's, a LogoutResponse not matched to a sent request, own logout keeping the server session, RSA 1.5 accepted, the response signature over the
encrypted form skipped, decrypted content not required to be an assertion, the missing-key refusal, RelayState not covered by the query signature, repeated parameters
allowed. The survivor (an unknown `SigAlg` falling back to SHA-256) is equivalent: a SHA-1 signature never verifies under SHA-256.

## Not built

SAML signatures with ECDSA are accepted by the validator but only tested with RSA; the SP key is RSA. Not built: the legacy `/sso/saml2/callback/{providerId}` path, group/role
mapping from assertions, a metadata URL to fetch, SP key rotation (delete and recreate the connection), the SOAP back-channel binding for logout, encrypted NameIDs.

## Settings

| Setting | Meaning |
|---|---|
| `Sso__SamlClockSkewSeconds` | Clock skew for NotBefore / NotOnOrAfter (default 300) |
| `Sso__SamlAllowIdpInitiated` | Accept responses nobody asked for (default true, as the reference) |

## Verified

* xUnit: `SamlValidatorTests` (61), `SamlSignInTests`/connection/test-flow classes (57), including a signature-wrapping family, XXE, replay, concurrency, same-browser rule, POST binding.
* `area-saml.mjs` 43/43 against the rewrite, with a dependency-free fake provider that signs real exclusive-canonical XML (and misbehaves on demand). The reference could not be
  started where this was written, so the script has not been run against it.
* `ui-saml.js` (browser, cross-site POST through the proxy, test window, sign-in, bad signature page, replay).
* Mutation checks (one rule removed at a time, tests must fail): see [oauth-extras.md](oauth-extras.md#mutation-checks), which lists both areas' results.
