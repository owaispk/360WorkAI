# OAuth provider extras: client_credentials, private_key_jwt, DPoP

Reference: `@better-auth/oauth-provider` 1.7.7 as configured in `ee/apps/den-api/src/auth.ts` (`oauthProvider({...})`), read from its source
(`token endpoint`, `client-assertion`, `register`, and `@better-auth/core` `oauth2/dpop`). Code: `OAuth/Dpop.cs`, `OAuth/Jose.cs`, `OAuth/ClientAssertions.cs`,
`OAuth/OAuthExtrasService.cs`, `Features/OAuthExtras/`, `Domain/OAuthExtras/`, small edits to `OAuth/OAuthEndpoints.cs`, `TokenService.cs`, `McpAuthenticator.cs`, `McpEndpoints.cs`,
`Features/Oidc/OidcEndpoints.cs`. Tests: `OAuthExtrasTests` (registration, `client_credentials`, `private_key_jwt`), `DpopTests`, `tests/parity/area-oauth-extras.mjs`.

The reference supports all three, so all three are built, as far as its source goes.

## client_credentials

* Registration (`/register`, `/api/auth/oauth2/register`): `grant_types` may now include `client_credentials` (and `authorization_code`, `refresh_token`); **only a signed-in person**
  may register one (`400 invalid_client_metadata "client_credentials grant requires authenticated registration"`, as the reference). `redirect_uris` are needed only with the
  authorization code grant; `response_types: ["code"]` needs that grant too; unsupported grants are `unsupported grant_type X`. The response echoes `grant_types`.
* Token endpoint, in the reference's order: the client must be registered for the grant (`400 unauthorized_client "client is not authorized to use grant type ..."`; this check now
  applies to every grant, so a machine client cannot use the code grant and the reverse; clients registered the old way keep authorization code + refresh); a public client is refused;
  the client must have authorized scopes (`"client has no authorized client_credentials scopes"`); a requested `scope` must be among them and never `openid profile email offline_access`
  (`invalid_scope "The following scopes are invalid: ..."`); `resource` must be this server's (default: the MCP resource). The answer has `token_type`, `expires_in` (45 minutes),
  `expires_at`, `scope`, no refresh token and no ID token. The JWT's `sub` is the client id (also `client_id`, `azp`) and it has no `org_id` and no `token_use`.
* **A machine token is not a way into the MCP endpoint or userinfo** (they need a person in a workspace; both answer 401). Its own client can introspect it (`active: true`).
* **Difference**: in the reference a client's `client_credentials` scopes can only be set through a privileged client-management call, and Den configures no `clientPrivileges`, so
  there every `client_credentials` request ends in `unauthorized_client`. Here a **platform administrator** can grant them: `PUT /v1/admin/oauth-clients/{clientId}/client-credentials-scopes`
  with `{scopes: ["mcp:read", "mcp:write"]}` (empty list clears; only a confidential client that has the grant; only those two scopes). Until then the answer is the reference's.

## private_key_jwt

* Registration: `token_endpoint_auth_method: "private_key_jwt"` with `jwks` (a JWK Set) **or** `jwks_uri`, never both; no secret is issued or stored. Key sets are validated as the reference
  does: non-empty, public RSA (at least 2048 bits) or EC (P-256/384/521) keys only, a key's `alg` must suit its type. A `jwks_uri` must be https (http only where private URLs are allowed),
  without credentials or fragment, not a private address, and on a trusted origin (`Auth:TrustedOrigins`, the web origin), as the reference requires; keys are fetched with no redirects, a
  5 second timeout, a 64 KiB cap and a JSON media type, cached 5 minutes (stale up to 10 on failure) and fetched again once when no cached key verifies.
* Authentication at the token, introspection and revocation endpoints: `client_assertion_type` = `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and `client_assertion`.
  Checks (the reference's messages): algorithm RS/PS/ES 256-512; `iss`/`sub` = the client; client registered for the method; signature (`kid` selects a key, otherwise all fitting keys are tried; `401`);
  `aud` is the endpoint or the issuer; `exp` present, not past, at most 300 seconds ahead; `iat` not older than 300 seconds; `jti` present and **single use** (replay table). One authentication method
  per request; a client registered for secrets cannot use an assertion and the reverse. `client_id` may be omitted (the assertion's subject picks the rate-limit bucket).
* Discovery lists `private_key_jwt` and the signing algorithms for the token, introspection and revocation endpoints.

## DPoP (RFC 9449)

* A token request may carry a `DPoP` proof; the access token then has `cnf.jkt`, the response `token_type: "DPoP"`, and the refresh-token family is bound to the key. An unbound family that is refreshed
  with a proof becomes bound. A proof is **required** when the client registered `dpop_bound_access_tokens: true`, the code was requested with `dpop_jkt` (43-character thumbprint, validated at the authorization
  endpoint) or the refresh token is bound (`400 invalid_dpop_proof "DPoP proof header is required"`). Proof checks, as the reference: `typ dpop+jwt`; asymmetric allowed algorithm; public `jwk` in the header
  (no private parts); signature; `htm`/`htu`/`jti` (at most 512)/`iat`; method and URL (query ignored); `iat` at most 5 s ahead and 300 s old; at a resource `ath` and the bound key; a proof works once (replay table).
* Resources: the MCP endpoint and userinfo accept a bound token only as `Authorization: DPoP <token>` with a proof for that request and token (`401` with a `DPoP error=...` challenge otherwise); a plain token must
  not use the DPoP scheme. Introspection reports `token_type: "DPoP"` and `cnf`.
* The code is not spent when a proof is missing or wrong (the reference checks after spending it), so a client that forgot the proof can retry.
* `htu` may name the advertised token endpoint, the API's own address, or the address the request arrived at.

## Client management (`/api/auth/oauth2/*-client`)

Code: `Features/OAuthClients/OAuthClientManagement.cs` (and the shared registration core `OAuthEndpoints.RegisterFromBodyAsync`). Tests: `OAuthClientManagementTests` (5),
`area-oauth-extras.mjs` (client section).

Better Auth's client routes as Den serves them. Den configures neither `clientReference` nor `clientPrivileges`, so **a client belongs to the signed-in person
who registered it** (`OAuthClientExtras.OwnerUserId`), whether through `/register` while signed in (which now answers `user_id`) or `create-client`; a
client registered anonymously belongs to nobody and nobody can manage it.

| Route | Notes |
|---|---|
| `POST /api/auth/oauth2/create-client` | Needs a session (`401 {code: "UNAUTHORIZED"}`); the registration rules of `/register`; `201` with the client, its secret (shown once) and `user_id` |
| `GET /api/auth/oauth2/get-client?client_id=` | The owner only (`401` otherwise, `404 {error: "not_found", error_description: "client not found"}` for an unknown id); never the secret |
| `GET /api/auth/oauth2/get-clients` | The caller's own clients |
| `GET /api/auth/oauth2/public-client?client_id=` | Any signed-in person: `client_id`, `client_name`, `logo_uri`, `client_uri`, `contacts`, `tos_uri`, `policy_uri` (for sign-in and consent screens) |
| `POST /api/auth/oauth2/update-client` | `{client_id, update: {…}}`, owner only: redirect URIs, scope, names and descriptive URLs, contacts, software fields, post-logout URIs, application type, grant and response types, with the registration rules. Dropping `client_credentials` (or a public client) clears the scopes a platform admin granted for it |
| `POST /api/auth/oauth2/client/rotate-secret` | Owner only; secret clients only (`400 invalid_client "secret rotation is only available for clients using client_secret authentication"`); the old secret stops working at once |
| `POST /api/auth/oauth2/delete-client` | Owner only; removes the client and its consents, unused codes, refresh tokens (and DPoP bindings) and OpenID Connect grants. Access tokens already issued are JWTs and run out within their lifetime, as in the reference |

Descriptive RFC 7591 fields (`client_uri`, `contacts`, `tos_uri`, `policy_uri`, `software_id`, `software_version`, `software_statement`, `application_type`) are kept and shown back.
The `/admin/oauth2/*` variants are server-only in the reference (not reachable over HTTP) and are not served. Mutation checks: 8 of 8 killed (each ownership
check, list filtering, public-client session, redirect policy on update, secret replacement on rotation).

## The JWT-bearer grant (pre-claim assertions)

Code: `OAuth/PreclaimGrant.cs`. Tests: `PreclaimGrantTests` (4), `area-oauth-extras.mjs`.

`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=…` at the token endpoint, as the reference's `exchangePreclaimAssertion`: a provisional workspace's agent
(`POST /v1/bootstrap/workspace`) trades its pre-claim assertion for an MCP access token for its setup member in that workspace: 15 minutes (never past the
workspace's own expiry), `token_type: "Bearer"`, scope `mcp:read mcp:write`, client id `openwork-preclaim`, no refresh token (the agent exchanges again). It is
answered before client authentication (the assertion is the credential) but after the token endpoint's rate limits. Errors: `invalid_request "The assertion parameter is required."`,
`invalid_grant "The assertion is invalid or expired."` (bad signature, audience, type, expiry, unknown workspace or token id), `invalid_grant "This workspace was claimed or expired;
its pre-claim credentials are revoked."`. Claiming removes the setup member, so tokens already minted stop working at once. Discovery lists the grant and the reference's
`agent_auth` block (`identity_endpoint`, `claim_endpoint`, `identity_types_supported: ["anonymous"]`). Difference: the reference tells "missing its workspace" and "not recognized"
apart; here every invalid assertion gets the one "invalid or expired" message. Mutation checks: 3 of 3 killed.

## Server-provided DPoP nonces (opt-in)

Code: `OAuth/DpopNonce.cs`. Tests: `DpopNonceTests` (4). RFC 9449 sections 8 and 9; the reference does not use nonces, so this is **off** unless
`OAuth__DpopNonceRequired=true`. Then every DPoP proof at the token endpoint, the MCP endpoint and userinfo needs a recent `nonce` from this server: the token
endpoint answers `400 use_dpop_nonce` ("Authorization server requires nonce in DPoP proof"), a resource a `401` with `WWW-Authenticate: DPoP error="use_dpop_nonce"`, and every
answer of those endpoints carries a fresh `DPoP-Nonce` header (exposed to browsers). Nonces are stateless (a two-minute slot and an HMAC under a key derived from
`Auth:Secret`), so all instances accept each other's; one is valid for its slot and the next. The check runs before the proof's `jti` is reserved, so the retry with a
fresh proof works and an authorization code is not spent. Mutation checks: 3 of 3 killed.

## EdDSA

Ed25519 (`kty: OKP`, `crv: Ed25519`) is accepted for `private_key_jwt` assertions and DPoP proofs, verified with BouncyCastle (`BouncyCastle.Cryptography`, already in the
dependency graph through MailKit, now referenced directly). OKP keys register (32-byte `x`, no private members), thumbprint per RFC 8037 and verify only EdDSA; X25519 keys never
verify a signature. Discovery lists `EdDSA` for assertions and proofs. **Tokens this server issues stay ES256**: it verifies its own access tokens, and ID-token consumers
support ES256 far more widely than EdDSA (the reference signs with EdDSA). Tests: `EdDsaTests` (4, including the RFC 8037 thumbprint vector); mutation checks 4 of 4 killed.

## Differences and gaps

| Reference | Here |
|---|---|
| Tokens signed with EdDSA | ES256 (EdDSA is accepted from clients, above) |
| `client_credentials_scopes` effectively unsettable | Settable by a platform administrator (above) |
| No DPoP nonces | Optional server nonces (above), off by default |
| Opaque access tokens when no resource is given | Always JWTs with the MCP resource as audience |
| DPoP on the authorization endpoint beyond `dpop_jkt`, mTLS-bound tokens | Not built |
| JWKS fetch results cached per process | The same (in memory, per instance) |

## Mutation checks

Each rule was removed on its own (compile-safe), the area's tests had to fail. See the table at the end of this file for the run.

### Results (SAML and OAuth rules together)

Killed (a test failed): signature verification skipped; `CheckSignature` result ignored; assertion signature not required; several assertions allowed; DTD processing on; SHA-1 allowed;
issuer, audience, recipient, expiry not checked; replay cache not consulted; browser binding not checked; replay guard always "first use" (also fails the client-assertion and DPoP replay tests);
DPoP `htu`, `typ`, `ath` (required and compared) and bound key not checked; client-assertion `jti` replay, expiry and signature not checked; the JOSE algorithm allow-list dropped.

Two mutants survive and are equivalent: *id uniqueness not checked* (the reference lookup is pinned to the signed parent anyway, so uniqueness is a second line of defence), and *a request may be
answered twice* (the sequential case is stopped earlier by the answered-at check; the atomic claim only matters under a race, where the replay cache stops the second assertion too).
