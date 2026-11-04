# Single sign-on (OpenID Connect) and SCIM provisioning

Reference: `ee/apps/den-api/src/routes/org/sso.ts`, `routes/org/scim.ts`, `routes/auth/scim.ts`, `sso*.ts`, `scim*.ts`, and the Better Auth SSO and SCIM
plugins as configured in `auth.ts`. Code: `Features/Sso/`, `Features/Scim/`, `Domain/Sso/`. Pages: `/dashboard/sso`, `/dashboard/scim`, `/sso/{slug}`,
`/sso/test`, `/sso/test/complete`, and the sign-in form's SSO step.

## What a workspace can do

1. **Connect an OpenID Connect provider** (`POST /v1/sso/oidc`): issuer, email domain, client id and secret, optional scopes, optional manual endpoints
   (otherwise discovery at `{issuer}/.well-known/openid-configuration`). The secret is stored AES-GCM encrypted (key derived from `Auth:Secret`) and is never
   returned. Saving replaces everything and resets the connection to disabled, untested and unverified.
2. **Prove the domain** (`POST /v1/sso/request-domain-verification`, `POST /v1/sso/verify-domain`): publish a TXT record
   `_better-auth-token-{providerId}.{domain}` with the value `_better-auth-token-{providerId}={token}` (the bare token is accepted too). The DNS lookup is behind
   `IDnsTxtResolver` (a small built-in UDP/TCP client; tests and any deployment can replace it). All claimed domains must carry the record.
3. **Test** (`POST /v1/sso/test`, `/test/{intent}/start`, `/test/{intent}/cancel`): a five-minute, single-use intent bound to the saved configuration revision
   and to the administrator who made it. The administrator signs in at the provider; the test only succeeds if the provider authenticates *that* administrator.
   A test signs nobody in, creates nobody and changes no account.
4. **Turn on / off** (`POST /v1/sso/enable`, `/disable`): enabling needs a verified domain and a successful test of the current configuration revision.
   `DELETE /v1/sso` removes the connection and its links.
5. **Sign in**: `POST /api/auth/sign-in/sso` (by `organizationSlug`, `providerId`, `domain` or `email`) returns `{url, redirect: true}`; the provider returns to
   `GET /api/auth/sso/callback/{providerId}`, which sets the session cookie and redirects. `GET /v1/auth/login-options` answers `nextStep: "sso"` and
   `GET /v1/orgs/sso/resolve` answers `{requireSso: true, method: "sso", ...}` for an email on an enabled, verified domain. Members of such a workspace cannot
   use a password (`403 This account is managed by an organization. Use SSO to sign in.`), including for sign-up.
6. **SCIM 2.0** (`/api/auth/scim/v2`): `ServiceProviderConfig`, `Schemas`, `ResourceTypes`, `Users` (create, list with `filter=userName eq "..."`, get, PUT, PATCH,
   DELETE) and `Groups` (create, list with `displayName`/`externalId` filters and paging, get, PUT, PATCH including `members[value eq "..."]`, DELETE). The settings
   API is `GET/PATCH/DELETE /v1/scim`, `POST /v1/scim/token` (shown once, stored only as a SHA-256 hash), `POST /v1/scim/reconcile`.
   Deprovisioning (`active: false`, PUT/PATCH/DELETE) removes the membership and team places, ends **every session and agent credential** the person holds,
   records a tombstone (so SSO cannot bring them back; only the identity provider adding them again can), and deletes the person if they belong nowhere else.
   Groups are metadata by default; with `groupMappingMode: create_teams` each group becomes a team (a `(SCIM)` suffix avoids name clashes) whose people follow the
   group, and the team is locked against manual edits (`409 scim_managed_team`).

## Security rules (each one is tested, and was mutation-checked)

* **State, nonce and PKCE.** Every attempt has a random state that works **once**, for **one connection**, for **ten minutes**, only in the **browser that started it**
  (a binding cookie; stops login CSRF), and only while the **configuration is unchanged**. The authorization request carries `code_challenge` (S256) and a nonce;
  the token request carries the verifier. The state is stored hashed, the verifier encrypted, the nonce hashed. An `iss` parameter naming another provider is refused.
* **ID token.** Signature checked against the provider's own JWKS with an allow-list of asymmetric algorithms (never `none`, never HMAC: no key-confusion), then
  issuer, audience (and `azp`), expiry, not-before, issued-at, nonce and subject.
* **Who the provider may speak for.** Only a domain that was *proven in DNS* counts; the email must be on it (subdomains allowed, look-alikes not). A provider
  cannot sign in, join or link anyone with an unverified domain, and an unverified domain is never routed to SSO. A domain one workspace proved cannot be proved by another.
  A person is recognised by the provider's stable subject, not by email. An existing account that never proved its email is taken over by the verified identity
  (its password and sessions end); a verified one is linked and keeps its password.
* **Open redirects.** `callbackURL`, `errorCallbackURL`, `newUserCallbackURL` must be paths on this site or a configured trusted origin
  (`//x`, `/\x`, `javascript:`, userinfo tricks, look-alike hosts are refused with `INVALID_*_CALLBACK_URL`, before anything else).
* **Outbound requests (SSRF).** Outside Development only public https endpoints are accepted, and the connection itself refuses private, loopback and link-local
  addresses after DNS (so a name that resolves inward is stopped too). No redirects are followed; responses are size-limited.
* **Tokens.** The SCIM token is `base64url(secret:providerId:organizationId)`; the ids only pick the row, the secret hash is compared in constant time (also against
  a dummy when the row does not exist). Failed attempts are rate limited per source. SCIM cannot adopt an account that is not already in the workspace, never
  grants a role, and a workspace's token only ever reaches that workspace's people.

## Differences from the reference (on purpose)

| Reference | Here | Why |
|---|---|---|
| No `nonce` is sent or checked | Nonce is sent, required and checked | ID-token replay and injection |
| State is not bound to a browser | A binding cookie (`openwork-den.sso_state`) | Login CSRF |
| An issuer on Microsoft Entra counts as a verified domain | Not trusted: DNS proof is always needed (only a loopback issuer in Development is auto-verified, as in the reference's dev mode) | Anyone with a tenant could claim any domain |
| Removed members keep a row and cannot be re-added by SSO | Members are deleted in this rewrite, so a manually removed person can sign in through SSO again and join as a member. SCIM-deprovisioned people are blocked by a tombstone | Members are not soft-deleted here yet |
| A failed discovery or missing endpoints answer `500` | `400 invalid_request` with the reason | |
| A connection test runs the normal sign-in (which may take over an unverified admin account) | Read-only: recognises the person, changes nothing | A test must not sign the administrator out |
| Plan gating (`402 enterprise_plan_required`), billing seats, audit events | Not built (the rewrite has no plans, billing or audit yet): SSO and SCIM are available to every workspace | |
| `DELETE /Users/{unknown valid id}` answers 204 | `404` for someone this connection does not provision | |
| Users created by SSO have `emailVerified: false` | `true` (the domain is proven and the provider authenticated the address) | |
| SCIM `POST /Users` with `active:false` and the admin-plugin wording | Same `400` and wording | (kept) |
| `managedByScim` is shown on teams | The team API still reports `managedByScim: false` (the shared team payload is untouched); the lock itself (`409 scim_managed_team`) is enforced | Minimal edit to a shared file |

## Single-organization status (`GET /v1/orgs/sso/singleton`)

Public. The reference uses it in its single-organization mode, which this build does not have (every deployment here holds many workspaces), so
it answers what the reference answers with that mode off: `{configured: false, organizationSlug: "default", signInPath: "/sso/default",
signInUrl: "<web origin>/sso/default"}` ("default" is the reference's default single-organization slug). Nothing about any workspace is read.
Code: `Features/Sso/SingletonSsoStatus.cs`; test: `SingletonSsoStatusTests.cs`.

## Not built

* **SAML** is built, including single logout, encrypted assertions, signed requests and IdP metadata import: see [saml.md](saml.md).
* Audit events, plan entitlements and seat limits, the SCIM retry worker (failures are recorded in `ScimSyncEvent` and shown as health; nothing retries them),
  `SCIM` `/Users` pagination (the reference returns everything too), SCIM `Bulk`/`sort`/`etag`.
* Social sign-in (`provisionVerifiedDomainMembership` for Google/GitHub sign-ins has nothing to attach to yet).

## Settings (all optional)

| Setting | Meaning |
|---|---|
| `Sso__AllowPrivateNetworks` | Allow provider endpoints on private or loopback addresses and plain http. Default: only in Development |
| `Sso__DevLoopbackIssuerIsVerified` | An issuer on loopback counts as a proven domain. Default: only in Development |
| `Sso__DnsServers__0`… | DNS servers for domain proof (default: `/etc/resolv.conf`, then 1.1.1.1 and 8.8.8.8) |

## Testing

```bash
dotnet test --filter "FullyQualifiedName~Sso|FullyQualifiedName~Scim"          # in-process, with an in-process fake provider and fake DNS
node tests/parity/area-sso.mjs                                                  # reference (needs "127.0.0.1 fakeidp.test" in /etc/hosts, or IDP_HOST)
W=... A=... node tests/parity/area-sso.mjs                                      # rewrite; add IDP_HOST=127.0.0.1 to run the whole sign-in too
W=... A=... node tests/parity/ui-sso.js /tmp/shots                              # browser
```

The reference refuses loopback and plain-IP providers (it asks for them to be in `trustedOrigins`) and cannot prove a domain without real DNS, so the parity
script on the reference covers what is deterministic: validation, permissions, lifecycle messages, routing of an unverified domain, open-redirect refusal,
callback errors and the SCIM server's authentication. The full sign-in is covered by the in-process tests and, on the rewrite, by the script and the browser test.
