# 360WorkAI: .NET 10 / Blazor rewrite of OpenWork Den

A rewrite of the OpenWork Den API (`ee/apps/den-api`, TypeScript, Hono + Better Auth) and Den web
(`ee/apps/den-web`, Next.js) as ASP.NET Core 10 and Blazor. It keeps the **wire contract** the existing clients
depend on (routes, JSON shapes, cookie name, bearer = session token) and replaces the internals.

Status: **early**. Sign-in, sessions, **email verification and password reset**, organizations, desktop handoff,
device login and the **OAuth provider for MCP clients** (with a working `/mcp/agent`) are built and tested. Most of Den is not built yet (see
[Not built yet](#not-built-yet)). The route list this follows comes from the S6 spike (which `/api/auth/*` routes real
clients call).

## Layout

| Path | What |
|---|---|
| `src/WorkAI360.Api` | ASP.NET Core minimal API: `/api/auth/*`, `/v1/*`, EF Core (SQLite for now) |
| `src/WorkAI360.Web` | Blazor (Interactive Server) app and the same-origin reverse proxy (YARP) in front of the API |
| `tests/WorkAI360.Api.Tests` | xUnit tests, in-process (`WebApplicationFactory`) |
| `tests/parity` | Contract tests that run unchanged against the **reference** Den and this rewrite |
| `scripts/dev.sh` | Start / stop the API (`:5080`) and web (`:5081`) |

## Run

Requires the .NET 10 SDK.

```bash
scripts/dev.sh start      # API http://localhost:5080, web http://localhost:5081
scripts/dev.sh status
scripts/dev.sh stop
```

Open `http://localhost:5081`. The API needs `Auth__Secret` (32+ characters). Development uses a fixed dev value from
`appsettings.Development.json`; set your own anywhere else. Data lives in `src/WorkAI360.Api/workai360.db` (SQLite, created on first start).

## Test

```bash
dotnet test                                                    # 80 in-process API tests (~20 s)

# Contract tests against the running rewrite (web is W, API is A):
W=http://localhost:5081 A=http://localhost:5080 \
SECTIONS=health,auth,orgs,handoff,device,login-options,oauth-mcp,passwords,email,sign-out node tests/parity/parity.mjs

# Real-browser flows (need Playwright):
W=http://localhost:5081 node tests/parity/ui-flows.js                       # sign-in, workspace, device approval
W=http://localhost:5081 A=http://localhost:5080 node tests/parity/ui-mcp.js  # an agent connecting, end to end

# Email verification and reset (start the rewrite with the setting below; it reads the dev outbox):
Auth__RequireEmailVerification=true scripts/dev.sh restart
W=http://localhost:5081 A=http://localhost:5080 node tests/parity/ui-email.js
# ...and the contract checks for it (run on the reference too, started with DEN_REQUIRE_EMAIL_VERIFICATION=true):
W=http://localhost:5081 A=http://localhost:5080 SECTIONS=passwords,email,email-verification node tests/parity/parity.mjs
```

The same `parity.mjs`, with no `SECTIONS` and no `W`/`A`, runs against a reference Den (web `:3005`, API `:8790`).
It is the yardstick for "does the rewrite behave like Den": a route is done when its parity checks pass on both.

## What is implemented

| Area | Routes |
|---|---|
| Email auth | `POST /api/auth/sign-up/email`, `/sign-in/email`, `/sign-out`, `GET /get-session` |
| Email verification | `POST /api/auth/email-otp/send-verification-otp`, `/email-otp/verify-email`. With `Auth__RequireEmailVerification=true`, sign-up returns `{token: null}` and no session, and sign-in answers `403 EMAIL_NOT_VERIFIED` until the emailed 6-digit code is entered |
| Password reset | `POST /api/auth/request-password-reset`, `GET /api/auth/reset-password/{token}` (the emailed link; redirects to the reset page), `POST /api/auth/reset-password` |
| Sessions | signed cookie `openwork-den.session_token` (HttpOnly, SameSite=Lax) **or** `Authorization: Bearer <token>`; cookie checked first |
| Current user | `GET /v1/me`, `GET /v1/me/orgs`, `POST /v1/me/active-organization`, `POST /api/auth/organization/set-active` |
| Organizations | `POST /v1/org`, `GET /v1/org` (the caller becomes `owner`; roles beyond that are not built) |
| Desktop handoff | `POST /v1/auth/desktop-handoff`, `/status`, `/exchange` |
| Device login (RFC 8628) | `POST /api/auth/device/code`, `/device/token`, `GET /v1/auth/device/{code}`, `POST /v1/auth/device/decision` |
| OAuth discovery | `/.well-known/oauth-authorization-server[/api/auth]`, `/.well-known/openid-configuration[/api/auth]`, `/api/auth/.well-known/*`, `/.well-known/oauth-protected-resource[/mcp[/agent]]`, `/api/auth/jwks` |
| OAuth provider | `POST /register` and `/api/auth/oauth2/register` (dynamic client registration), `GET /api/auth/oauth2/authorize`, `POST /oauth2/public-client-prelogin`, `/oauth2/consent`, `/oauth2/token` (authorization code + PKCE S256, refresh), `/oauth2/revoke` |
| MCP | `POST /mcp/agent` (JSON-RPC: `initialize`, `ping`, `tools/list`, `tools/call`) with the tools `search_capabilities` and `execute_capability`; `POST /v1/mcp/token` (first-party `ow_mcp_at_…` tokens) |
| Sign-in form helpers | `GET /v1/auth/login-options`, `GET /v1/orgs/sso/resolve` (always "not SSO"), bootstrap status/verify (report "unavailable") |
| Refusals | the 28 Better Auth mutations the reference refuses answer `403`; every other unknown `/api/auth/*` path is `404` |
| Web host | `/api/auth/*`, `/api/browser/v1/*` (same-origin guard, cookie filter) proxied to the API; the aliases `login-options`, `sso-resolve`, `desktop-handoff`; `/api/health`, `/api/ready`, `/api/runtime-config`, `/api/auth/clear-session-cookie` |
| Blazor pages | `/` (email-first sign-in or sign-up; resumes an agent's authorization afterwards), `/organization`, `/dashboard`, `/device`, `/mcp/consent` and `/mcp/select-organization` (allow or deny an agent, choose or create a workspace), `/connect/error`, `/reset-password` (and the verify-code and forgot-password steps on `/`) |

## Configuration

Set with environment variables (`Auth__Secret`) or `appsettings`.

| Setting | Meaning |
|---|---|
| `Auth__Secret` | Required, 32+ characters. Signs cookies and OAuth requests; protects signing keys and hashes email codes. |
| `Auth__WebUrl`, `Auth__ApiPublicUrl` | The public web and API origins. The OAuth issuer is `WebUrl/api/auth`; changing it signs every MCP client out. |
| `Auth__RequireEmailVerification` | `true` to require an emailed code before sign-in (default `false`). |
| `Auth__TrustedProxies__0`, `__1`… | Addresses of proxies whose `X-Forwarded-*` headers are believed. Empty means loopback only. **Set this whenever the web host runs somewhere else**: until you do, the API sees every visitor as the web host, so the per-address rate limits share one bucket. |
| `Auth__TrustedOrigins__0`… | Extra origins a password-reset link may return to, besides the web origin. |
| `Auth__RateLimitsEnabled` | Rate limits on the email endpoints. Default: off in Development, on everywhere else. |
| `Email__Provider` | `dev` keeps messages in memory and exposes them at `GET /dev/outbox` (**Development only; refused anywhere else**). `smtp` sends real mail. |
| `Email__From`, `Email__Smtp__Host`, `__Port`, `__User`, `__Password`, `__Security` | SMTP settings. `Security` is `auto` (default), `starttls`, `ssl` or `none` (local test servers only). |

## Design decisions (different from the reference on purpose)

- **Session tokens are stored as SHA-256 hashes**, never in plain text. The cookie is `token.HMAC(token)`, so a forged cookie is rejected.
- **The desktop handoff exchange mints a fresh session** instead of returning the web session's own token. A stored grant therefore never holds a usable credential, and signing out the web does not sign out the desktop. Clients only read `token`, `user`, `organization`, `connectEnabled`, so they are unaffected.
- **No Redis**: sessions are read straight from the database. Add a cache only if measurements ask for one.
- **Fresh data model and ids** (TypeID-format, e.g. `usr_01m…`, `org_01m…`): users sign in again after cutover, as planned.
- **Password policy** matches the reference's rules, codes and messages (8+ characters with an uppercase letter, a lowercase letter, a special character and a digit; the first rule broken is reported). Two differences: the cap is 128 characters instead of the reference's 32, so passphrases work, and the strength score and breached-password screening are not built.
- **Email codes** are 6 digits, valid 10 minutes, stored only as a keyed hash, and replaced whenever a new one is requested. At most five guesses are possible per code even under concurrent requests (the attempt is counted atomically before the code is compared); the sixth is refused with `403 TOO_MANY_ATTEMPTS` and the code is deleted, as in the reference.
- **Reset links** are single-use and valid 1 hour, stored hashed, and only the newest link works. A reset signs the person out everywhere and lifts any sign-in lockout. Links may only return to this site (or a configured origin); the check also rejects tricks like `http://localhost@evil.example` and `//evil.example`.
- **Nothing reveals whether an account exists**: requesting a code or a reset link answers the same for known and unknown addresses, and a mail outage is logged but never shown.
- **Forwarded headers are believed only from configured proxies.** The framework's own middleware checks the caller only when `X-Forwarded-For` is present, so a spoofed `X-Forwarded-Host` sent alone would be accepted. Every forwarding header is stripped from other callers before it runs, so deep links and device-login links cannot be pointed at another site.
- **Sign-in lockout**:
- **Access tokens are ES256 JWTs**, not EdDSA like the reference: .NET has no built-in Ed25519, and ES256 is supported by every JWT library. The private key is created on first use and stored encrypted (AES-GCM, key derived from `Auth:Secret`); `/api/auth/jwks` publishes only the public half. Lifetimes match the reference: access 45 minutes, refresh 30 days.
- **The authorization request travels as a signed query string** (HMAC, 30-minute expiry) between the authorize endpoint, the sign-in page and the consent page, so no request state is kept on the server and nothing can be altered, mixed or replayed after it expires.
- **OAuth hardening**: PKCE S256 is required for every client; redirect URIs must be exact (a registered loopback URI matches on any port, per RFC 8252); resources must be ours (RFC 8707); a replayed authorization code revokes the tokens it produced; refresh tokens rotate, and presenting a rotated one after a 30-second grace window revokes the whole family; a refresh can narrow scopes but never add them; secrets, codes and refresh tokens are stored as SHA-256 only.
- **MCP access follows membership**: every `/mcp/agent` call re-checks the person still belongs to the workspace, and browsers on other origins are refused (DNS-rebinding protection from the MCP spec).
- **`execute_capability` runs two built-in read-only capabilities today** (`openwork.whoami`, `openwork.workspace.members`), so the whole path is real and testable. Connections to external services are not built yet.
- **Sign-in lockout**: 5 failures per address in 15 minutes returns `429 login_locked` with `Retry-After`. The email endpoints also have the reference's per-address and per-source limits (for example 5 reset requests per address per hour). All limits are in memory, per instance.

## Not built yet

Roughly in the order to build them:

1. **OAuth follow-ups**: Client ID Metadata Documents (clients that skip registration), a rate limit on registration and on failed token requests, signing-key rotation, ID tokens and `userinfo` (the OpenID document is served but no ID tokens are issued), and Workbot's fixed client id. Testing against real clients (Claude Code, Cursor) has not been done: the flows are exercised with a scripted client and a real browser.
2. **MCP connections**: the capabilities behind `execute_capability` (Google Workspace, Microsoft 365 and other MCP servers), plus streaming responses.
3. **More email**: invitations, a Resend provider (SMTP only today), the other code types (`sign-in`, `forget-password`, `change-email`), and a shared rate-limit store for more than one instance.
4. **Members, invitations, roles, teams, API keys**: only `owner` exists today.
5. **Social sign-in** (Google, GitHub), **SSO** (OIDC/SAML) and **SCIM**.
6. The rest of `/v1/*` (about 550 route registrations in the reference) and the other ~120 web pages.
7. **Passwords**: the reference's strength score and breached-password screening.
8. **MySQL** (today SQLite), EF Core migrations (today a dev-only bootstrap that creates missing tables), rate limiting beyond sign-in, audit log, Docker/Helm packaging, CI.
9. **Cloud web handoff return URLs** (`returnUrl`) are refused until an approved-origin list exists.

## Licensing note

The reference code this follows lives under `ee/` and is licensed under the OpenWork EE License. This directory is
currently covered by the repository's default MIT annotation in `REUSE.toml`. Decide the intended license for this
rewrite before it is released.
