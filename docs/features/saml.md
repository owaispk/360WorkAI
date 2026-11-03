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

* **XML**: DTDs prohibited (no entity is ever expanded: XXE and entity bombs are refused), no resolver, comments dropped (a comment cannot split a name), 256 KB limit,
  encrypted assertions refused with a clear reason (not supported, see below).
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
| `idpMetadata`, custom SP metadata, signed AuthnRequests, SLO, encrypted assertions, `additionalParams`, multiple `RelayState` shapes | Not built (see below) | Not reachable through the reference's `/v1/sso/saml` either, except the metadata/encryption options of the plugin |
| `issuer` stored on the provider is the audience | `connection.issuer` is the identity provider's entity id, `saml.audience` the service provider's | Same as what the reference's routes show |
| A transient NameID is the account key | A transient NameID cannot name a person: the (domain-checked) email is the key | The id changes at every sign-in |
| Timestamps: NotBefore and/or NotOnOrAfter | Conditions need one of them and the bearer confirmation needs `NotOnOrAfter` | Web SSO profile |
| `RelayState` that is not one of ours when IdP-initiated: rejected | Rejected the same (`invalid_state`) | Parity |
| Plan gating (`402`), audit events | Not built (as for OIDC) | |

## Not built

SAML Single Logout, encrypted assertions (`EncryptedAssertion` is refused), signed AuthnRequests, importing IdP metadata XML (paste the certificate), ECDSA signatures are
accepted by the validator but are only tested with RSA, the legacy `/sso/saml2/callback/{providerId}` path, SP-side key management, group/role mapping from assertions.

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
