# 360WorkAI: .NET 10 / Blazor rewrite of OpenWork Den

A rewrite of the OpenWork Den API (`ee/apps/den-api`, TypeScript, Hono + Better Auth) and Den web
(`ee/apps/den-web`, Next.js) as ASP.NET Core 10 and Blazor. It keeps the **wire contract** the existing clients
depend on (routes, JSON shapes, cookie name, bearer = session token) and replaces the internals.

Status: **first vertical slice**. Sign-in, sessions, organizations, desktop handoff and device login work and are
tested. Most of Den is not built yet (see [Not built yet](#not-built-yet)). The route list this slice follows comes from
the S6 spike (which `/api/auth/*` routes real clients call).

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
dotnet test                                                    # 31 in-process API tests (~20 s)

# Contract tests against the running rewrite (web is W, API is A):
W=http://localhost:5081 A=http://localhost:5080 \
SECTIONS=health,auth,orgs,handoff,device,login-options,sign-out node tests/parity/parity.mjs

# Real-browser flows (needs Playwright):
W=http://localhost:5081 node tests/parity/ui-flows.js
```

The same `parity.mjs`, with no `SECTIONS` and no `W`/`A`, runs against a reference Den (web `:3005`, API `:8790`).
It is the yardstick for "does the rewrite behave like Den": a route is done when its parity checks pass on both.

## What is implemented

| Area | Routes |
|---|---|
| Email auth | `POST /api/auth/sign-up/email`, `/sign-in/email`, `/sign-out`, `GET /get-session`, `POST /request-password-reset` (no email sent yet) |
| Sessions | signed cookie `openwork-den.session_token` (HttpOnly, SameSite=Lax) **or** `Authorization: Bearer <token>`; cookie checked first |
| Current user | `GET /v1/me`, `GET /v1/me/orgs`, `POST /v1/me/active-organization`, `POST /api/auth/organization/set-active` |
| Organizations | `POST /v1/org`, `GET /v1/org` (the caller becomes `owner`; roles beyond that are not built) |
| Desktop handoff | `POST /v1/auth/desktop-handoff`, `/status`, `/exchange` |
| Device login (RFC 8628) | `POST /api/auth/device/code`, `/device/token`, `GET /v1/auth/device/{code}`, `POST /v1/auth/device/decision` |
| Sign-in form helpers | `GET /v1/auth/login-options`, `GET /v1/orgs/sso/resolve` (always "not SSO"), bootstrap status/verify (report "unavailable") |
| Refusals | the 28 Better Auth mutations the reference refuses answer `403`; every other unknown `/api/auth/*` path is `404` |
| Web host | `/api/auth/*`, `/api/browser/v1/*` (same-origin guard, cookie filter) proxied to the API; the aliases `login-options`, `sso-resolve`, `desktop-handoff`; `/api/health`, `/api/ready`, `/api/runtime-config`, `/api/auth/clear-session-cookie` |
| Blazor pages | `/` (email-first sign-in or sign-up), `/organization`, `/dashboard`, `/device` |

## Design decisions (different from the reference on purpose)

- **Session tokens are stored as SHA-256 hashes**, never in plain text. The cookie is `token.HMAC(token)`, so a forged cookie is rejected.
- **The desktop handoff exchange mints a fresh session** instead of returning the web session's own token. A stored grant therefore never holds a usable credential, and signing out the web does not sign out the desktop. Clients only read `token`, `user`, `organization`, `connectEnabled`, so they are unaffected.
- **No Redis**: sessions are read straight from the database. Add a cache only if measurements ask for one.
- **Fresh data model and ids** (TypeID-format, e.g. `usr_01m…`, `org_01m…`): users sign in again after cutover, as planned.
- **Password policy**: 10+ characters and three of four character classes. Breach screening is not built.
- **Sign-in lockout**: 5 failures per address in 15 minutes returns `429 login_locked` with `Retry-After` (in memory, per instance).

## Not built yet

Roughly in the order to build them:

1. **OAuth provider for MCP clients**: discovery documents, dynamic client registration, authorize, consent, token, refresh, JWKS, `/mcp/agent`, protected-resource metadata. (Needed by Claude Code, Cursor, Workbot.)
2. **Email**: verification codes (`email-otp/*`), password reset, invitations.
3. **Members, invitations, roles, teams, API keys**: only `owner` exists today.
4. **Social sign-in** (Google, GitHub), **SSO** (OIDC/SAML) and **SCIM**.
5. The rest of `/v1/*` (about 550 route registrations in the reference) and the other ~120 web pages.
6. **MySQL** (today SQLite), EF Core migrations (today `EnsureCreated`), rate limiting beyond sign-in, audit log, Docker/Helm packaging, CI.
7. **Cloud web handoff return URLs** (`returnUrl`) are refused until an approved-origin list exists.

## Licensing note

The reference code this follows lives under `ee/` and is licensed under the OpenWork EE License. This directory is
currently covered by the repository's default MIT annotation in `REUSE.toml`. Decide the intended license for this
rewrite before it is released.
