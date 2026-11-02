# Authentication completeness: OpenID Connect, social sign-in, other email codes

Reference: Better Auth's OAuth provider (`@better-auth/oauth-provider`), `socialProviders` and `emailOTP` as configured in `ee/apps/den-api/src/auth.ts`;
den-web's `den-flow-provider.tsx` (`beginSocialAuth`) and sign-in panel. Code: `Features/Oidc/`, `Features/Social/`, `Features/EmailCodes/`,
`Domain/Oidc/`, `Domain/Social/`; small edits to `OAuth/*`, `Auth/EmailVerificationService.cs`, `Endpoints/EmailAuthEndpoints.cs`. Page: the sign-in
form (`Components/Shared/SocialSignIn.razor`, one line in `Home.razor`).

## 1. OpenID Connect

The OAuth provider for MCP clients now also speaks OpenID Connect: a client that asks for the `openid` scope gets an ID token.

| Route | What |
|---|---|
| `GET /.well-known/openid-configuration[/api/auth]` (and the other discovery paths) | adds `userinfo_endpoint`, `introspection_endpoint`, `introspection_endpoint_auth_methods_supported` (`client_secret_basic`, `client_secret_post`), `end_session_endpoint`, `subject_types_supported: ["public"]`, `id_token_signing_alg_values_supported: ["ES256"]`, `claims_supported`, `acr_values_supported`; `scopes_supported` now lists `openid profile email offline_access mcp:read mcp:write` |
| token endpoint | with `openid` granted the answer carries `id_token` (and again on refresh) |
| `GET`/`POST /api/auth/oauth2/userinfo` | claims by scope: `sub` always; `profile` gives `name`, `given_name`, `family_name` (when the name has two parts or more), `picture`; `email` gives `email`, `email_verified`. `Authorization: Bearer` or (POST) form field `access_token`, not both |
| `POST /api/auth/oauth2/introspect` | RFC 7662, form body only (415 otherwise) |
| `GET`/`POST /api/auth/oauth2/end-session`, `POST .../end-session/confirm` | RP-initiated logout (see below) |
| the authorization response | now carries `iss` (RFC 9207), as the reference does |

**ID token** (the reference's claims): header `{alg: ES256, kid}` (no `typ`); `iss`, `sub`, `aud` = the client id only, `iat`, `exp` (10 hours),
`auth_time` (when the browser session began), `acr: "0"`, `at_hash` (left half of SHA-256 of the access token), `nonce` (only on the response to the
authorization request: a refresh issues a new ID token for the same sign-in with the same `auth_time` and no nonce). Profile and email claims are not in
the ID token, they are at userinfo, as in the reference. `sid` is added only for a client that may use logout.

**Introspection** answers `{"active": false}` (the same bytes) for an unknown token, an expired one, an ID token, a revoked or already exchanged refresh token,
a person who left the workspace, and any token issued to **another client**. An active access token is answered with its claims plus `client_id`, `active`,
`token_type`; an active refresh token with `active, client_id, iss, sub, exp, iat, scope, token_type`. Callers must authenticate as a confidential client
(`401 invalid_client` with no credentials, for a public client, an unknown client and a wrong secret, one message for all three); the secret must come the way the
client registered (basic or post). It has the token endpoint's rate limit numbers in budgets of its own.

**RP-initiated logout.** A client may log people out only if it was **registered by a signed-in person** with `enable_end_session: true` (and
`post_logout_redirect_uris`); an anonymous registration (every MCP client) is refused with `401 invalid_client "The client is not allowed to initiate logout"`.
A valid `id_token_hint` (ours, for that client, with a `sid`) naming the browser's current session ends that session, revokes the refresh tokens issued during it and
redirects to an exact-match registered `post_logout_redirect_uri` (with `state`). Anything else (no hint, a hint for another session, a forged hint) needs the
person: browsers get a confirmation page (no scripts, `form-action 'self'`, `frame-ancestors 'none'`) and a signed, 5-minute, `SameSite=Lax` cookie tied to
the session and the request; the confirm POST only works with that cookie. Non-browser callers get `400 invalid_request`.

### Differences from the reference

| Reference | Here | Why |
|---|---|---|
| ID tokens and access tokens signed with EdDSA | ES256 (already the case for access tokens) | .NET has no built-in Ed25519 |
| Access token `aud` is `[resource, userinfo]` for `openid` requests, claims are URL-named (`https://web/org_id`) | `aud` stays the resource string; claims keep the names this rewrite already used (`org_id`, `token_use`) | MCP clients and the existing `/mcp/agent` check read them; userinfo accepts exactly the tokens `/mcp/agent` accepts, never an ID token |
| Access tokens carry `sid` and become inactive when the session is deleted | They do not carry `sid`; logout revokes refresh tokens, access tokens live at most 45 minutes | MCP grants outlive browser sessions here (membership is rechecked on every call) |
| `enable_end_session` is never settable through the API (every dynamically registered client is refused logout) | Settable by a signed-in registrant | Otherwise the logout code could never run; an anonymous client can never use it |
| Back-channel logout, `claims` request parameter, `prompt`/`max_age`/`id_token_hint` at authorize, `private_key_jwt`, DPoP, `client_credentials`, pairwise subjects | Not built (`claims_parameter_supported: false`, `subject_types_supported: ["public"]`) | MCP clients do not use them |
| An authorize request for `openid` without `resource` | Refused with `invalid_target`, as the reference does | |
| Introspection by a resource-server client linked to a resource | Not built: a client only introspects its own tokens | no per-client resource links here |

## 2. Social sign-in (Google and GitHub)

A provider is **on only when both `SocialProviders:Google|GitHub:ClientId` and `ClientSecret` are set** (the reference's rule). Endpoints default to the real services and can
be overridden to point at a fake: `AuthorizationEndpoint`, `TokenEndpoint`, and for Google `JwksUri` and `Issuer`, for GitHub `ApiBase`. `SocialProviders:AllowPrivateNetworks`
(default true in Development) lets those endpoints be on loopback. The secrets are configuration, never stored in the database.

| Route | What |
|---|---|
| `GET /api/auth/social-providers` | `{providers: ["google", "github"]}`: which are on (the sign-in form reads it) |
| `POST /api/auth/sign-in/social` | body `{provider, callbackURL, errorCallbackURL?, newUserCallbackURL?, requestSignUp?, disableRedirect?}` answers `{url, redirect: true}`; `400 [body.provider] Invalid input`, `403 INVALID_CALLBACK_URL | INVALID_ERROR_CALLBACK_URL | INVALID_NEW_USER_CALLBACK_URL` (before the provider lookup), `404 PROVIDER_NOT_FOUND` |
| `GET /api/auth/callback/{provider}` | the provider's return: sets the session cookie and redirects to `callbackURL` (`newUserCallbackURL` for a new person), or to `errorCallbackURL` (else `/connect/error`) with `error` and `error_description` |

Error codes at the return: `state_not_found`, `state_mismatch` (unknown, expired, spent, other provider, other browser), `oauth_provider_not_found`, the provider's own error
(for example `access_denied`), `no_code`, `invalid_code`, `unable_to_get_user_info`, `email_not_found`, `email_not_verified`, `sso_required`.

**Security rules** (each tested; the mutation list is in "Verified" below):

* **State**: random, stored hashed, works once (atomically: two racing callbacks reach the provider once), for one provider, for ten minutes, and **only in the browser that started it**
  (binding cookie `openwork-den.social_state`; checked before the state is spent, so someone who saw a state cannot burn it). PKCE S256 on both providers; the verifier is stored encrypted. Google gets a nonce
  and its ID token goes through the same validation SSO uses (asymmetric algorithms only, signature against Google's JWKS, issuer, audience, expiry, nonce).
* **Verified email only**: Google needs `email_verified: true`; for GitHub the **primary, verified** address from `/user/emails` is used. The profile's public email field is never used. Unverified: refused, nothing created, nothing linked.
* **Linking**: a person is found by the provider's stable account id (`ExternalAccount`, provider `google`/`github`), never by email, so an address that changed at the provider cannot take over an account.
  The first sign-in joins an existing person only through the verified email; if that account never proved its email, the verified identity takes it over (password and sessions end), as with SSO.
* **SSO**: an address on a domain claimed by an enabled, verified SSO connection, or a person who is in such a workspace, is refused with `sso_required`; social sign-in does not bypass it.
* **Redirects**: return addresses must be paths on this site or trusted origins (the same rules as password reset and SSO), checked when the sign-in starts (what is stored is only what passed).
* **Sessions** are created like any other sign-in (`method: "social:google"`, first workspace active, audit event, cookie).
* Start and callback are rate limited per address.

### Differences from the reference

| Reference | Here | Why |
|---|---|---|
| den-web always shows both buttons | The Blazor form shows a button only for a provider that is on | A button that can only fail is noise |
| State in the database/cookie of Better Auth, no per-browser binding stated | State row plus a binding cookie, checked before use | Login CSRF |
| Unverified provider emails may create an account | Refused | No squatting of an address |
| `idToken` sign-in (an app brings its own ID token) | Not built | den-web never uses it |
| Link/unlink of social accounts for a signed-in person (`link-social`, `unlink-account`) | Not built (the reference's refusal list still applies) | den-web never calls them |
| Callback errors at the reference could not be probed for configured providers (none configured here) | Codes follow Better Auth's names | |

## 3. Other email code types

`POST /api/auth/email-otp/send-verification-otp` now accepts all four types. Shapes and codes are the reference's, probed on the live reference.

| Route | What |
|---|---|
| `send-verification-otp` type `sign-in` | `{success: true}`; a code is made for **any** address (signing in by code opens an account for a new one, as in the reference) |
| type `forget-password` | `{success: true}`; a code exists only for a real account, the answer is identical |
| type `change-email` | `400 {message: "Invalid OTP type"}` (switched off in the reference) |
| `POST /api/auth/sign-in/email-otp` `{email, otp}` | `{token, user}` and the session cookie; the account is marked verified; wrong code `400 INVALID_OTP`, expired `400 OTP_EXPIRED`, five wrong guesses `403 TOO_MANY_ATTEMPTS`; an invalid address reads as `INVALID_OTP` |
| `POST /api/auth/email-otp/check-verification-otp` `{email, type, otp}` | `{success: true}` without using the code up (every check still counts as a guess) |
| `POST /api/auth/email-otp/reset-password` `{email, otp, password}` | `{success: true}`; the password rules are checked first (a weak password does not use the code up); every session is ended |
| `POST /api/auth/email-otp/request-email-change`, `/change-email` | `401` without a session, then `400 "Change email with OTP is disabled"` (as in the reference) |

den-web only calls `send-verification-otp` (email-verification) and `verify-email`; the rest has no page. Security: the same rules as the verification code (stored only as keyed hashes,
10 minutes, five guesses counted atomically, replaced by a newer code, per-address and per-source rate limits) plus: the **type is part of the hash and the lookup**, so a code for one
purpose never works for another (a sign-in code cannot reset a password and the reverse); a code belongs to one address; nothing says whether an address has an account;
a workspace that requires SSO still closes this way in (`403`, checked after the code so it is no oracle).

Differences: reset-password uses this rewrite's password rules and messages (the reference answers with Better Auth's own `PASSWORD_TOO_SHORT`); an account that was created unverified with a
password and then signs in by code is only marked verified (its password stays), exactly as when it verifies by code, so the pre-registration risk of `verify-email` is not new here.

## Configuration

| Setting | Meaning |
|---|---|
| `SocialProviders__Google__ClientId`, `__ClientSecret` | switch Google on |
| `SocialProviders__GitHub__ClientId`, `__ClientSecret` | switch GitHub on |
| `SocialProviders__{Google,GitHub}__AuthorizationEndpoint`, `__TokenEndpoint`; `Google__JwksUri`, `__Issuer`; `GitHub__ApiBase` | point at a fake provider (tests, local runs) |
| `SocialProviders__AllowPrivateNetworks` | provider endpoints on private/loopback addresses (default: Development only) |

The redirect URI to register with the provider is `{Auth__WebUrl}/api/auth/callback/google` (or `/github`).

## Not built

`prompt`, `max_age`, `claims` and `login_hint` at authorize; back-channel logout; `client_credentials`; DPoP; pairwise subjects; `idToken` social sign-in and account linking for a signed-in person;
change-email by code (off in the reference as well).
