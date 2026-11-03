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

## Differences and gaps

| Reference | Here |
|---|---|
| EdDSA (Ed25519) for assertions and proofs, OKP keys | Not available (.NET has no Ed25519): assertions RS/PS/ES, proofs ES256, ES512, PS256, RS256; OKP keys are refused at registration |
| `client_credentials_scopes` effectively unsettable | Settable by a platform administrator (above) |
| `/oauth2/create-client`, `update-client`, `delete-client`, `client/rotate-secret`, `get-client(s)`, `jwt-bearer` grant, DPoP `DPoP-Nonce` | Not built |
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
