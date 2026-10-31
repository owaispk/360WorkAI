# 360WorkAI: .NET 10 / Blazor rewrite of OpenWork Den

A rewrite of the OpenWork Den API (`ee/apps/den-api`, TypeScript, Hono + Better Auth) and Den web
(`ee/apps/den-web`, Next.js) as ASP.NET Core 10 and Blazor. It keeps the **wire contract** the existing clients
depend on (routes, JSON shapes, cookie name, bearer = session token) and replaces the internals.

Status: **early**. Sign-in, sessions, **email verification and password reset**, organizations, **members, roles and
invitations**, **teams and permissions**, desktop handoff, device login and the **OAuth provider for MCP clients** (with a working `/mcp/agent`) are built and tested. Most of Den is not built yet (see
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
dotnet test                                                    # 166 in-process API tests (~20 s)

# Contract tests against the running rewrite (web is W, API is A):
W=http://localhost:5081 A=http://localhost:5080 \
SECTIONS=health,auth,orgs,handoff,device,login-options,oauth-mcp,passwords,email,members,teams,sign-out node tests/parity/parity.mjs

# Real-browser flows (need Playwright):
W=http://localhost:5081 node tests/parity/ui-flows.js                       # sign-in, workspace, device approval
W=http://localhost:5081 A=http://localhost:5080 node tests/parity/ui-mcp.js  # an agent connecting, end to end
W=http://localhost:5081 A=http://localhost:5080 node tests/parity/ui-members.js  # invite, join, change role, remove
W=http://localhost:5081 A=http://localhost:5080 node tests/parity/ui-teams.js    # teams, Admin teams, roles and permissions

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
| Organizations | `POST /v1/org` (the caller becomes `owner`), `GET /v1/org` (organization, `currentMember` with its permissions, members, invitations) |
| Members and roles | `POST /v1/members/{id}/role`, `POST /v1/members/{id}/transfer-ownership`, `DELETE /v1/members/{id}`. Roles are `owner`, `admin` and `member`; each action needs a permission from the catalog (59 keys, generated from `packages/types/src/den/permissions.ts` by `scripts/gen-permissions.py`; owner has all, admin 43, member none) |
| Teams | `POST /v1/teams`, `GET`, `PATCH`, `DELETE /v1/teams/{id}`. A team has people and may be an **Admin team** (`grantsOrganizationAdmin`): everyone in it is an effective admin. `GET /v1/org` lists all teams to everyone, and the caller's own as `currentMemberTeams` |
| Permissions | `GET /v1/permissions/catalog`, `GET`/`POST /v1/permissions/sets`, `GET`/`PATCH`/`DELETE /v1/permissions/sets/{id}`, `PUT /v1/permissions/sets/{id}/permissions`, `GET /v1/permissions/sets/{id}/history`, `PUT /v1/teams/{id}/permission-set`, `GET /v1/members/{id}/permissions`. Every workspace has a **Member** set (applies to everyone, nothing on) and an **Admin** set (43 keys); a team can have one role, and a role can be shared by several teams. A person holds the union of the Member set, the Admin set (if an admin), and their teams' roles; each permission is explained by its sources |
| Invitations | `POST /v1/invitations` (create or resend), `GET /v1/invitations/{id}/link`, `POST /v1/invitations/{id}/cancel`, `GET /v1/orgs/invitations/preview`, `POST /v1/orgs/invitations/accept`; sign-up accepts `?invite=TOKEN`, which proves the address and skips the code |
| Desktop handoff | `POST /v1/auth/desktop-handoff`, `/status`, `/exchange` |
| Device login (RFC 8628) | `POST /api/auth/device/code`, `/device/token`, `GET /v1/auth/device/{code}`, `POST /v1/auth/device/decision` |
| OAuth discovery | `/.well-known/oauth-authorization-server[/api/auth]`, `/.well-known/openid-configuration[/api/auth]`, `/api/auth/.well-known/*`, `/.well-known/oauth-protected-resource[/mcp[/agent]]`, `/api/auth/jwks` |
| OAuth provider | `POST /register` and `/api/auth/oauth2/register` (dynamic client registration), `GET /api/auth/oauth2/authorize`, `POST /oauth2/public-client-prelogin`, `/oauth2/consent`, `/oauth2/token` (authorization code + PKCE S256, refresh), `/oauth2/revoke` |
| MCP | `POST /mcp/agent` (JSON-RPC: `initialize`, `ping`, `tools/list`, `tools/call`) with the tools `search_capabilities` and `execute_capability`; `POST /v1/mcp/token` (first-party `ow_mcp_at_…` tokens) |
| Sign-in form helpers | `GET /v1/auth/login-options`, `GET /v1/orgs/sso/resolve` (always "not SSO"), bootstrap status/verify (report "unavailable") |
| Refusals | the 28 Better Auth mutations the reference refuses answer `403`; every other unknown `/api/auth/*` path is `404` |
| Web host | `/api/auth/*`, `/api/browser/v1/*` (same-origin guard, cookie filter) proxied to the API; the aliases `login-options`, `sso-resolve`, `desktop-handoff`; `/api/health`, `/api/ready`, `/api/runtime-config`, `/api/auth/clear-session-cookie` |
| Blazor pages | `/` (email-first sign-in or sign-up; resumes an agent's authorization afterwards), `/organization`, `/dashboard`, `/dashboard/members` (list, invite, change role, remove, make owner, copy or cancel an invitation), `/dashboard/teams` (create, rename, delete, choose people, Admin teams), `/dashboard/permissions` (roles by area, shared roles, give to teams, history), `/join-org` (open an invitation link), `/device`, `/mcp/consent` and `/mcp/select-organization` (allow or deny an agent, choose or create a workspace), `/connect/error`, `/reset-password` (and the verify-code and forgot-password steps on `/`) |

## Configuration

Set with environment variables (`Auth__Secret`) or `appsettings`.

| Setting | Meaning |
|---|---|
| `Auth__Secret` | Required, 32+ characters. Signs cookies and OAuth requests; protects signing keys and hashes email codes. |
| `Auth__WebUrl`, `Auth__ApiPublicUrl` | The public web and API origins. The OAuth issuer is `WebUrl/api/auth`; changing it signs every MCP client out. |
| `Auth__RequireEmailVerification` | `true` to require an emailed code before sign-in (default `false`). |
| `Auth__TrustedProxies__0`, `__1`… | Addresses of proxies whose `X-Forwarded-*` headers are believed. Empty means loopback only. **Set this whenever the web host runs somewhere else**: until you do, the API sees every visitor as the web host, so the per-address rate limits share one bucket. |
| `Auth__TrustedOrigins__0`… | Extra origins a password-reset link may return to, besides the web origin. |
| `Auth__PrivilegedSessionMinutes` | How recently the person must have signed in to change members, roles or invitations (default 120). Older sessions get `403 {error: "reauth"}` and the Members page asks for the password. |
| `Database__Provider`, `ConnectionStrings__Default`, `Database__AutoMigrate` | `sqlite` (default) or `mysql`; see [docs/database.md](docs/database.md). |
| `Auth__SigningKeyRotationDays`, `Auth__SigningKeyGraceHours` | A new OAuth signing key after this many days (default 90); the old one stays published for the grace period (default 48 hours). |
| `OAuth__ClientMetadata__AllowPrivateUrls` | Let Client ID Metadata Documents be fetched from private addresses (self-hosted setups; default off). |
| `Auth__RateLimitsEnabled` | Rate limits on the email endpoints. Default: off in Development, on everywhere else. |
| `Email__Provider` | `smtp`, `resend` (needs `Email__Resend__ApiKey`) or `dev`. `dev` keeps messages in memory and exposes them at `GET /dev/outbox` (**Development only; refused anywhere else**). `smtp` and `resend` send real mail. |
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
- **Client ID Metadata Documents** (what spec-following MCP clients use instead of registering): the HTTPS client_id is fetched once under an SSRF-safe policy (public addresses only, chosen when connecting so DNS cannot swap one in; no redirects; 5 KB cap; never this deployment's own origins), must name itself, be a public client with no secret, and pass the redirect policy; it is refreshed hourly, and an unreachable document leaves a known client as it was.
- **Token endpoint limits** follow the reference: attempts per client and address (60 a minute; 20 with no client), per address (300), failures per caller (15 in five minutes) and per address (60); a dead refresh token is charged to that token only. In memory, per instance.
- **Signing keys rotate**: the newest key signs; a replaced key stays published for a grace period so tokens it signed still verify, then is retired (the row is kept).
- **Sign-in lockout**: 5 failures per address in 15 minutes returns `429 login_locked` with `Retry-After`. The email endpoints also have the reference's per-address and per-source limits (for example 5 reset requests per address per hour). All limits are in memory, per instance.

- **Members who have not accepted yet are listed as placeholder members** (no user id, `inviteId` set), as in the reference, so one list shows everyone. Removing a placeholder **cancels the invitation**; the reference leaves it pending.
- **Removing, demoting or transferring revokes access immediately**: every session, refresh token, consent, MCP token and authorization code the person holds for that workspace is deleted, so an agent they connected stops working at once. Transferring ownership signs out **both** people, as in the reference.
- **Ownership changes are atomic.** The demotion and promotion are conditional updates inside one transaction, so two concurrent transfers cannot leave two owners (found by a test, fixed). Concurrent accepts of one invitation are idempotent for the same person.
- **A role list such as `admin,member` collapses to one role** (the highest), and unknown names are refused; `Super Admin` normalizes to `admin`, matching the reference.
- **Members are deleted, not soft-deleted**, and there are no editable permission sets, teams or plan limits yet: permissions come from the role.

- **Safety rules ported from the reference**: you cannot turn on, or give a team, a permission you do not hold yourself; only an owner or admin may make or unmake an Admin team, add or remove its people, change who is an admin, or edit the Admin set; making someone an admin needs an admin who holds the whole Admin set; nobody changes their own role; a `members.delete` holder cannot remove an admin (by role or through an Admin team). Denying a key is always allowed, and restoring a key a default set shipped with needs nothing.
- **Permission history is append-only.** A change is a new row; the newest row per key applies, and a key with no row is denied. Saying what a key already is records nothing. Deleting a role archives it (the history stays readable) and it stops applying; a deleted team's role is kept, unattached.
- **A team has at most one active role, enforced by the database** (a unique index on active links), so concurrent requests cannot give it two. Team names are unique per workspace ignoring case, as with the reference's MySQL collation.
- **`GET /v1/teams/{id}` carries a `memberCount` that is always 0**, as the reference's does (a stored column nothing updates); it is kept so clients see the same shape.
- **Not carried over**: the reference's default-set reconciliation when a new permission is added to the catalog (a new key simply starts off in both sets until someone turns it on), SCIM-managed teams, stable external keys on teams, inviting people straight into a team, and audit events.

## Not built yet

Roughly in the order to build them:

1. **OAuth follow-ups**: a rate limit on registration, `client_credentials`/introspection/`private_key_jwt` (the reference offers them; no client here needs them yet), ID tokens and `userinfo` (the OpenID document is served but no ID tokens are issued), and Workbot's fixed client id. Testing against real clients (Claude Code, Cursor) has not been done: the flows are exercised with a scripted client and a real browser.
2. **MCP connections**: the capabilities behind `execute_capability` (Google Workspace, Microsoft 365 and other MCP servers), plus streaming responses.
3. **More email**: the other code types (`sign-in`, `forget-password`, `change-email`), and a shared rate-limit store for more than one instance.
4. **Members and teams follow-ups**: API keys, invitation limits, invite-into-a-team, declarative `PUT /v1/teams/by-key/{key}`, a leave-workspace action, and a re-sign-in dialog that retries in place (the Members page does ask for the password, but other pages do not).
5. **Social sign-in** (Google, GitHub), **SSO** (OIDC/SAML) and **SCIM**.
6. The rest of `/v1/*` (about 550 route registrations in the reference) and the other ~120 web pages.
7. **Passwords**: the reference's strength score and breached-password screening.
8. **Operations**: Helm packaging, a shared rate-limit store and cache for more than one instance (limits and signing-key reload are per instance today), and running the container build in CI (no Docker daemon was available here, so the Dockerfiles are written and the publishes verified, but the images were not built).
9. **Cloud web handoff return URLs** (`returnUrl`) are refused until an approved-origin list exists.

## Licensing note

The reference code this follows lives under `ee/` and is licensed under the OpenWork EE License. This directory is
currently covered by the repository's default MIT annotation in `REUSE.toml`. Decide the intended license for this
rewrite before it is released.
