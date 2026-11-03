# 360WorkAI: .NET 10 / Blazor rewrite of OpenWork Den

A rewrite of the OpenWork Den API (`ee/apps/den-api`, TypeScript, Hono + Better Auth) and Den web
(`ee/apps/den-web`, Next.js) as ASP.NET Core 10 and Blazor. It keeps the **wire contract** the existing clients
depend on (routes, JSON shapes, cookie name, bearer = session token) and replaces the internals.

Status: **a working core of Den, not all of Den.** Built and tested: sign-in, sessions, email verification and password reset, organizations,
members, roles and invitations, teams and permissions, desktop handoff, device login, the OAuth provider for MCP clients (with `/mcp/agent`),
and five larger areas: the **library** (plugins, skills, marketplaces, sharing), **org administration** (API keys, audit log, settings, web origins,
brand), **connections** (external MCP servers, tool policy, OAuth sign-in), **SSO and SCIM**, and **policy** (desktop policies, agent permissions,
prompts, default model), plus platform admin, onboarding, automations and analytics, OpenID Connect (userinfo, introspection, end-session, ID tokens), social sign-in (Google, GitHub) and sign-in/forget-password/change-email codes. It runs on SQLite or MySQL. About 40% of the reference's route registrations and a corresponding share of its web
pages exist; what is missing is listed honestly in [Not built yet](#not-built-yet), mostly features that need outside services (billing,
model gateways, cloud sandboxes, Google/Microsoft integrations). Each area has a page under [docs/features](docs/features).

## Layout

| Path | What |
|---|---|
| `src/WorkAI360.Api` | ASP.NET Core minimal API: `/api/auth/*`, `/v1/*`, EF Core (SQLite or MySQL). Areas live in `Features/<Area>/` and register themselves |
| `src/WorkAI360.Web` | Blazor (Interactive Server) app and the same-origin reverse proxy (YARP) in front of the API |
| `tests/WorkAI360.Api.Tests` | xUnit tests, in-process (`WebApplicationFactory`) |
| `tests/WorkAI360.Web.Tests` | xUnit tests for the web host: security headers, trusted proxies, the same-origin guard |
| `tests/parity` | Contract tests that run unchanged against the **reference** Den and this rewrite |
| `scripts/dev.sh` | Start / stop the API (`:5080`) and web (`:5081`) |
| `docs/` | `AREA_GUIDE.md` (how to build an area), `database.md`, and `features/*.md` (what each area implements and how it differs from the reference) |
| `deploy/` | Dockerfiles, a compose stack (MySQL + migrate + API + web) and a GitHub Actions template |

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
dotnet test                                                    # in-process API and web-host tests (~2 min)
WORKAI_TEST_MYSQL="Server=127.0.0.1;User=root;Password=..." dotnet test   # the same tests on MySQL (a throwaway database per test class)

# Contract tests against the running rewrite (web is W, API is A):
W=http://localhost:5081 A=http://localhost:5080 \
SECTIONS=health,auth,orgs,handoff,device,login-options,oauth-mcp,passwords,email,members,teams,sign-out node tests/parity/parity.mjs

# Real-browser flows (need Playwright):
W=http://localhost:5081 node tests/parity/ui-flows.js                       # sign-in, workspace, device approval
W=http://localhost:5081 A=http://localhost:5080 node tests/parity/ui-mcp.js  # an agent connecting, end to end
W=http://localhost:5081 A=http://localhost:5080 node tests/parity/real-mcp-client.mjs  # the official MCP SDK: discovery, registration, PKCE, tools, refresh
W=http://localhost:5081 A=http://localhost:5080 node tests/parity/ui-members.js  # invite, join, change role, remove
W=http://localhost:5081 A=http://localhost:5080 node tests/parity/ui-teams.js    # teams, Admin teams, roles and permissions
# One contract script and one browser script per area (each header says how to start the server for it; the reference is the default target):
#   area-library.mjs  area-org-admin.mjs  area-connections.mjs  area-policy.mjs  area-sso.mjs
#   ui-library.js     ui-org-admin.js     ui-connections.js     ui-policy.js     ui-sso.js

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
| Library ([docs](docs/features/library.md)) | Plugins, skills (config objects, versioned), marketplaces, sharing with people, teams or everyone, "my library", usage, GitHub import (real HTTP, configurable hosts), `resolved-plugins`, declarative by-key marketplaces; agents find and read the skills shared with them through `search_capabilities` / `execute_capability`. Pages under `/dashboard/plugins`, `/skills`, `/marketplaces`, `/library` |
| Org administration ([docs](docs/features/org-admin.md)) | API keys (`x-api-key` or `Bearer den_…`, hashed, rate-limited, disabled when a person loses access), the audit log (operations, events, usage, ndjson/csv export, signed cursors, capture switch), `PATCH`/`DELETE /v1/org`, approved web origins, brand assets, features, `GET /v1/org` envelope. Pages `/dashboard/api-keys`, `/audit-logs`, `/org-settings`, `/brand-appearance` |
| Connections ([docs](docs/features/connections.md)) | `/v1/mcp-connections*`: catalog presets, create/edit/delete, per-person and shared credentials, access grants, tool policy, discovery (incl. server-sent events), a real Streamable-HTTP MCP client, OAuth sign-in with protected servers (PKCE, dynamic registration, refresh), an SSRF-safe outbound guard, and a capability provider that exposes allowed tools to agents. Pages `/dashboard/mcp-connections`, `/your-connections`, `/connect/mcp` |
| SSO and SCIM ([docs](docs/features/sso-scim.md)) | `/v1/sso*` (OIDC connection, domain proof by DNS TXT, test, enable/disable), `POST /api/auth/sign-in/sso` + callback (state, nonce, PKCE, ID-token validation), SSO-enforced workspaces close password sign-in, SCIM v2 `/Users` and `/Groups` with a hashed bearer token, group-to-team mapping, reconcile, deprovisioning. Pages `/dashboard/sso`, `/scim`, `/sso/{slug}` and the sign-in form's SSO step |
| Policy ([docs](docs/features/policy.md)) | Desktop policies (default, access/execution limits, assignments by role, team or person, by-key), agent permissions (everyone/team), prompts, default model, Automation and Workbot settings; what a person's desktop receives (`/v1/me/desktop-config`, `/v1/me/prompts`). Pages `/dashboard/policy`, `/desktop-policies` |
| Onboarding and the person's own routes ([docs](docs/features/onboarding.md)) | `/v1/me/profile`, `/v1/me/invitations`, `/v1/me/send-download-link`, install config and links (`/v1/install*`, `/v1/me/install*`, `POST /v1/orgs/{id}/install-links`), bootstrap workspaces and claim links/codes (`/v1/bootstrap/*`), diagnostics and egress checks, `/v1/resources*`, `/v1/app-version`. Pages: create workspace and settings (`/organization`), `/dashboard/onboarding` (invite people, tools), `/install`, `/claim`, `/workspace-claim`, `/setup`, `/reauth/*` |
| Platform admin ([docs](docs/features/platform-admin.md)) | `/v1/admin/*` for the operator of a deployment: overview and metrics, users (search, delete), organizations (detail, plan, free seats, DPA, web access, capabilities), feature flags with per-workspace overrides, platform admins (a table plus `PlatformAdmin__BootstrapEmails`). The flags drive `GET /v1/features` and the `features` fields of `GET /v1/org`. Pages under `/admin` |
| Approved web origins in use ([docs](docs/features/web-origins.md)) | CORS for operator-configured and workspace-approved origins (cached, fail-closed), and approved web return URLs for desktop handoff |
| Automations and telemetry ([docs](docs/features/automations.md)) | `/v1/automations*` (CRUD, activate/deactivate, run now, archive), schedules with the reference's DST rules, runs with leases and the desktop-runner protocol (token, work, claim, heartbeat, events, complete, cancel), runner presence, cloud Automations stored and answered like the reference when no cloud runner exists, `/v1/telemetry/*` ingest and analytics (12 weeks, computed locally). A background scheduler starts due Automations and recovers expired leases. Pages `/dashboard/automations`, `/analytics` |
| Web host | `/api/auth/*`, `/api/browser/v1/*` (same-origin guard, cookie filter) proxied to the API; the aliases `login-options`, `sso-resolve`, `desktop-handoff`; `/api/health`, `/api/ready`, `/api/runtime-config`, `/api/auth/clear-session-cookie` |
| Blazor pages | `/` (email-first sign-in or sign-up; resumes an agent's authorization afterwards), `/organization`, `/dashboard`, `/dashboard/members` (list, invite, change role, remove, make owner, copy or cancel an invitation), `/dashboard/teams` (create, rename, delete, choose people, Admin teams), `/dashboard/permissions` (roles by area, shared roles, give to teams, history), `/join-org` (open an invitation link), `/device`, `/mcp/consent` and `/mcp/select-organization` (allow or deny an agent, choose or create a workspace), `/connect/error`, `/reset-password` (and the verify-code and forgot-password steps on `/`) |

## Configuration

Set with environment variables (`Auth__Secret`) or `appsettings`.

| Setting | Meaning |
|---|---|
| `Auth__Secret` | Required, 32+ characters. Signs cookies and OAuth requests; protects signing keys and hashes email codes. |
| `Auth__WebUrl`, `Auth__ApiPublicUrl` | The public web and API origins. The OAuth issuer is `WebUrl/api/auth`; changing it signs every MCP client out. |
| `Den__TrustedProxies__0`, `__1`… | **Web host.** Addresses or CIDR ranges (for example `10.0.0.0/8`) of the load balancer in front of it, whose `X-Forwarded-For/Proto/Host` are believed. Empty means loopback only. **Set this behind any TLS-terminating proxy**: otherwise the host sees `http`, the same-origin check on `/api/browser/v1/*` refuses every browser write, and the API sees the proxy as the visitor. |
| `Auth__RequireEmailVerification` | `true` to require an emailed code before sign-in (default `false`). |
| `Auth__TrustedProxies__0`, `__1`… | Addresses of proxies whose `X-Forwarded-*` headers are believed. Empty means loopback only. **Set this whenever the web host runs somewhere else**: until you do, the API sees every visitor as the web host, so the per-address rate limits share one bucket. |
| `Auth__TrustedOrigins__0`… | Extra origins a password-reset link may return to, besides the web origin. |
| `Auth__PrivilegedSessionMinutes` | How recently the person must have signed in to change members, roles or invitations (default 120). Older sessions get `403 {error: "reauth"}` and the Members page asks for the password. |
| `Database__Provider`, `ConnectionStrings__Default`, `Database__AutoMigrate` | `sqlite` (default) or `mysql`; see [docs/database.md](docs/database.md). |
| `Auth__SigningKeyRotationDays`, `Auth__SigningKeyGraceHours` | A new OAuth signing key after this many days (default 90); the old one stays published for the grace period (default 48 hours). |
| `OAuth__ClientMetadata__AllowPrivateUrls` | Let Client ID Metadata Documents be fetched from private addresses (self-hosted setups; default off). |
| `Connections__AllowPrivateUrls`, `__ToolTimeoutSeconds`, `__MaxResponseBytes`, `__ExpandedPresets` | Connections: outbound calls to private addresses are refused unless this is true (local runs and tests only). |
| `Library__GithubApiBase`, `Library__GithubRawBase` | Where GitHub import reads from (default GitHub). |
| `Sso__AllowPrivateNetworks` | Let SSO providers and DNS proof use private networks (never in production). |
| `Auth__PasswordBreachScreening`, `Auth__PwnedPasswordsUrl` | Refuse passwords found in public breaches. Default: on everywhere except Development. |
| `Cors__Origins__0`, `__1`… | Extra exact origins allowed to call the API from a browser, besides this deployment's own and the ones workspaces approved ([docs](docs/features/web-origins.md)). |
| `SocialProviders__Google__ClientId`, `__ClientSecret`, `SocialProviders__GitHub__ClientId`, `__ClientSecret` | Turn on Google / GitHub sign-in (the button appears when the pair is set). |
| `Auth__RateLimitsEnabled` | Rate limits on the email endpoints. Default: off in Development, on everywhere else. |
| `Email__Provider` | `smtp`, `resend` (needs `Email__Resend__ApiKey`) or `dev`. `dev` keeps messages in memory and exposes them at `GET /dev/outbox` (**Development only; refused anywhere else**). `smtp` and `resend` send real mail. |
| `Email__From`, `Email__Smtp__Host`, `__Port`, `__User`, `__Password`, `__Security` | SMTP settings. `Security` is `auto` (default), `starttls`, `ssl` or `none` (local test servers only). |

## Design decisions (different from the reference on purpose)

- **Session tokens are stored as SHA-256 hashes**, never in plain text. The cookie is `token.HMAC(token)`, so a forged cookie is rejected.
- **The desktop handoff exchange mints a fresh session** instead of returning the web session's own token. A stored grant therefore never holds a usable credential, and signing out the web does not sign out the desktop. Clients only read `token`, `user`, `organization`, `connectEnabled`, so they are unaffected.
- **No Redis**: sessions are read straight from the database. Add a cache only if measurements ask for one.
- **Fresh data model and ids** (TypeID-format, e.g. `usr_01m…`, `org_01m…`): users sign in again after cutover, as planned.
- **Password policy** matches the reference's rules, codes and messages (8+ characters with an uppercase letter, a lowercase letter, a special character and a digit; the first rule broken is reported), then a **strength score** (zxcvbn, at least 3 of 4: `400 password_too_weak` with the estimator's advice, sign-up only) and **breach screening** (Have I Been Pwned range lookups, only five hash characters leave the server; `400 password_compromised`, and `503 password_screening_unavailable` when the service cannot answer, never a silent pass). Screening is on everywhere except Development (`Auth__PasswordBreachScreening`). One difference: the cap is 128 characters instead of the reference's 32, so passphrases work. The .NET zxcvbn port's dictionaries differ slightly from the reference's, so borderline passwords can score one step differently.
- **Email codes** are 6 digits, valid 10 minutes, stored only as a keyed hash, and replaced whenever a new one is requested. At most five guesses are possible per code even under concurrent requests (the attempt is counted atomically before the code is compared); the sixth is refused with `403 TOO_MANY_ATTEMPTS` and the code is deleted, as in the reference.
- **Reset links** are single-use and valid 1 hour, stored hashed, and only the newest link works. A reset signs the person out everywhere and lifts any sign-in lockout. Links may only return to this site (or a configured origin); the check also rejects tricks like `http://localhost@evil.example` and `//evil.example`.
- **Pages and API answers cannot be framed or sniffed**: every response from the web host (Blazor pages included, whose framework default would allow the same site) and the API carries `X-Frame-Options: DENY`, `Content-Security-Policy: frame-ancestors 'none'` and `X-Content-Type-Options: nosniff` (the consent and device pages approve access, so a hidden frame must not be able to host them); the web host adds `Referrer-Policy`; `Strict-Transport-Security` (one year) is sent over HTTPS outside Development.
- **One key per purpose**: cookies, audit cursors, brand-image links, SSO revisions, token-limit ids and automation-runner tokens are each signed with a key derived from `Auth__Secret` for that purpose (HKDF), like the signing-key, email-code, OAuth-query, SSO-secret and connection-secret keys already were.
- **Nothing reveals whether an account exists**: requesting a code or a reset link answers the same for known and unknown addresses, and a mail outage is logged but never shown.
- **Forwarded headers are believed only from configured proxies.** The framework's own middleware checks the caller only when `X-Forwarded-For` is present, so a spoofed `X-Forwarded-Host` sent alone would be accepted. Every forwarding header is stripped from other callers before it runs, so deep links and device-login links cannot be pointed at another site.
- **Access tokens are ES256 JWTs**, not EdDSA like the reference: .NET has no built-in Ed25519, and ES256 is supported by every JWT library. The private key is created on first use and stored encrypted (AES-GCM, key derived from `Auth:Secret`); `/api/auth/jwks` publishes only the public half. Lifetimes match the reference: access 45 minutes, refresh 30 days.
- **The authorization request travels as a signed query string** (HMAC, 30-minute expiry) between the authorize endpoint, the sign-in page and the consent page, so no request state is kept on the server and nothing can be altered, mixed or replayed after it expires.
- **OAuth hardening**: PKCE S256 is required for every client; redirect URIs must be exact (a registered loopback URI matches on any port, per RFC 8252); resources must be ours (RFC 8707); a replayed authorization code revokes the tokens it produced; refresh tokens rotate, and presenting a rotated one after a 30-second grace window revokes the whole family; a refresh can narrow scopes but never add them; secrets, codes and refresh tokens are stored as SHA-256 only.
- **MCP access follows membership**: every `/mcp/agent` call re-checks the person still belongs to the workspace, and browsers on other origins are refused (DNS-rebinding protection from the MCP spec).
- **`execute_capability` runs two built-in read-only capabilities today** (`openwork.whoami`, `openwork.workspace.members`), so the whole path is real and testable. Connections to external services are not built yet.
- **Client ID Metadata Documents** (what spec-following MCP clients use instead of registering): the HTTPS client_id is fetched once under an SSRF-safe policy (public addresses only, chosen when connecting so DNS cannot swap one in; no redirects; 5 KB cap; never this deployment's own origins), must name itself, be a public client with no secret, and pass the redirect policy; it is refreshed hourly, and an unreachable document leaves a known client as it was.
- **Token endpoint limits** follow the reference: attempts per client and address (60 a minute; 20 with no client), per address (300), failures per caller (15 in five minutes) and per address (60); a dead refresh token is charged to that token only. In memory, per instance.
- **Signing keys rotate**: the newest key signs; a replaced key stays published for a grace period so tokens it signed still verify, then is retired (the row is kept).
- **Sign-in lockout** is per account **and visitor address**: 5 wrong passwords from one address for one account in 15 minutes returns `429 login_locked` with `Retry-After` for that address only, so someone who merely knows a person's email cannot keep them out (the sign-in rate limit is per account and address too). A higher per-account ceiling (50 failures in 15 minutes from any addresses) stops guessing spread over many addresses; past it the account is locked for everyone until the window ends or the password is reset. Behind a proxy, set `Auth__TrustedProxies` and `Den__TrustedProxies` or every visitor shares one address. The email endpoints also have the reference's per-address and per-source limits (for example 5 reset requests per address per hour). All limits are in memory, per instance.

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

The reference has about 400 distinct `/v1` paths and 129 web pages; this covers the core and the five areas above. What is **not** built, and why:

**Needs outside services that were not available (so it was not faked):**
- **Billing and plans** (Stripe checkout, plan limits, free seats), the **AI Gateway and model providers** (LiteLLM-style sync, usage limits, provider inventory, `inference*`, `llm-providers*`, the Auto Router), **managed deployments** in customers' clouds, and **cloud sandboxes** (sandbox join, headless/remote sessions, session runners, workers).
- **Google Workspace, Microsoft 365 and Gmail** integrations (and every connection of kind `native_provider`), the Slack assistant, and the GitHub App install routes.

**Not reached yet (no outside dependency):**
- **Workflows** and workflow/script runs (`/v1/workflows*`, `/v1/codemode*`, the den-web workflow-runs and script-runs pages), the runner events SSE stream and runner inventory, calendar triggers, and cloud execution of Automations (it needs a cloud runner).
- The rest of platform admin (inference usage, security, feature usage, sandbox organizations, services), first-administrator setup, activation and "my agent", and real egress probes (see [docs/features/platform-admin.md](docs/features/platform-admin.md) and [onboarding.md](docs/features/onboarding.md)).
- **SAML** sign-in (the SSO route answers 501), plugin–connection bindings, `/v1/oauth-providers*`, invite-into-a-team, declarative team keys.
- **OAuth**: `client_credentials`, DPoP and `private_key_jwt`. **OAuth-provider browser sign-in** connect (start and callback) and GitHub import bindings; memory, artifact views, direct uploads, mcp-apps and webhooks.
- **Operations**: Helm packaging; a shared store for rate limits and caches (they are per instance); the container images were written and the publishes verified, but not built (no Docker daemon here); the CI template is not enabled in the repository's own CI.

Each area's page in [docs/features](docs/features) lists its own gaps and its differences from the reference.

## Licensing note

The reference code this follows lives under `ee/` and is licensed under the OpenWork EE License. This directory is
currently covered by the repository's default MIT annotation in `REUSE.toml`. Decide the intended license for this
rewrite before it is released.
