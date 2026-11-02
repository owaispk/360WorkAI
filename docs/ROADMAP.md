# Roadmap: what is not built yet

Compiled on 2026-11-02 from the README ("Not built yet") and the "Differences" and "Not built" sections of each page in
[docs/features](features). The rewrite covers about 40% of the reference's route registrations (the reference has about 400 distinct `/v1` paths and
129 web pages). Section 6 lists gaps found by reading the code that the docs do not mention.

Status of the codebase when this was written: `dotnet build` clean (0 warnings, 0 errors), 567 of 567 in-process tests passing on SQLite. The MySQL run,
the parity and browser scripts and the container builds were not run.

## 1. Needs outside services (not faked)

- **Billing and plans**: Stripe checkout, plan limits, free seats. Every workspace is `{tier: "free", source: "default"}` and nothing is plan-gated.
- **AI Gateway and model providers**: LiteLLM-style sync, usage limits, provider inventory, `inference*`, `llm-providers*`, the Auto Router.
  Consequence: a default model can only be cleared, never chosen, until a model catalog is registered (`IDefaultModelCatalog`).
- **Managed deployments** in customers' clouds.
- **Cloud sandboxes**: sandbox join, headless and remote sessions, session runners, workers.
  Consequence: the `cloud` automation setting can never be turned on (`409 headless_runner_required`).
- **Google Workspace, Microsoft 365 and Gmail** integrations, and every connection of kind `native_provider` (create answers 400).
- **Slack assistant**, Workbot hand-off, Workbot proactive-agent settings and health, and the GitHub App install routes.
- **Social sign-in** (Google, GitHub).

## 2. Not reached yet (no outside dependency)

- **Automations and workflows**: `/v1/automations*`, `/v1/automation-runs*`, `/v1/codemode*`, workflow and script runs.
- **Telemetry and analytics**: `/v1/telemetry*`.
- **Platform admin**: `/v1/admin/*` (users, organizations, admins, feature flags, overview and metrics) and the `/admin` pages.
- **Install and installer routes**: `/v1/orgs/{id}/install-links`, `/v1/me/install-config`, `/v1/install-config`, `/v1/install/{platform}`,
  `/v1/me/install/{platform}` (need release hosting).
- **`/v1/me/*` extras**: `profile`, `invitations`, `send-download-link`, `activation` (and events), `agent` (and checks).
  `GET /v1/org/activity` returns an empty list.
- **Resource listings**: `GET /v1/org/resources`, `/v1/resources/marketplace-capabilities`.
- **Teams**: invite-into-a-team, declarative team keys, stable external keys, SCIM-managed teams (`managedByScim` is always reported `false`; the
  lock itself, `409 scim_managed_team`, is enforced).
- **Soft-deleted members**: members are hard-deleted, so SSO can re-add someone an admin removed by hand (SCIM-deprovisioned people are blocked by a tombstone).
- **Default-set reconciliation** when a new permission is added to the catalog (a new key starts off in both sets until someone turns it on).
- **Web pages**: the OpenWork Web billing page and the "advanced" redirect.

## 3. Sign-in, OAuth and email gaps

- **SAML**: `POST /v1/sso/saml` answers `501`; `/api/auth/sso/saml2/*` is not routed (404). The OIDC model (`SsoConnection.Kind`, `SamlConfigJson`) leaves room for it.
- **OAuth**: `client_credentials`, introspection, `private_key_jwt`, ID tokens and `userinfo`, a rate limit on client registration.
- **Passwords**: the strength score and breached-password screening.
- **Email**: the sign-in, forget-password and change-email code types.
- **SCIM**: the retry worker (failures are recorded in `ScimSyncEvent` and shown as health; nothing retries them), `Bulk`, `sort`, `etag`.
- **Web-origin enforcement**: the approved-origins list is stored and managed, but nothing reads it (CORS, desktop-handoff return URLs).

## 4. Gaps inside the built areas

**Library** ([library.md](features/library.md))
- Remote MCP servers in a plugin are listed on import but not imported; `POST /v1/plugins/{id}/mcp-connections` and marketplace "cloud readiness" are missing.
- Connectors, connector accounts, targets, sync events (`/v1/connectors/github/*`, `/v1/connector-*`); `/v1/me/library` lists plugins only.
- No built-in "OpenWork Marketplace" with its three plugins.
- GitHub import is simpler than the reference: no agent-plugin manifests or Claude plugin component declarations, no private repositories.
- Audit events, `x-mcp` search aliases, the OpenAPI contract, `If-Match` preconditions.
- Lists load a workspace's plugins and work out access in memory (fine for hundreds, needs SQL filters and indexes for tens of thousands).

**Connections** ([connections.md](features/connections.md))
- GitHub connector instances (`/v1/connector-instances/*`), the per-connection MCP server (`/mcp/connections/{id}`), plugin MCP requirement bindings,
  `/v1/oauth-providers/*`, OAuth issuer review, Client ID Metadata Document registration with outside servers.
- Readiness fingerprints, MCP App rendering in the host, the Slack assistant routes, Workbot hand-off.
- Simplified diagnostics, and agent search keeps this server's shape rather than the reference's `matches[]` with scores and `schemaDigest`.

**Org administration** ([org-admin.md](features/org-admin.md))
- Audit capture is best effort and the event catalog lists about 40 actions (the reference has 1,864); audit events for SSO, SCIM and unbuilt areas; retention and cleanup jobs.
- Brand images are checked but not re-encoded (no image library, so metadata is not stripped).
- `capabilities` reports only `auditLogs` as on.

**Policy** ([policy.md](features/policy.md))
- The Auto Router, `POST /v1/org/workbot-settings/test-default-model`, audit events for agent-permission changes, SCIM-managed teams' policy projection.
- Workbot settings can only be saved as the default; `GET /v1/me/desktop-config` leaves out organization branding and allowed desktop versions.
- Den-web's separate Browser, Models and Desktop-suggestion tabs (the page offers the same settings in one place).

**SSO and SCIM** ([sso-scim.md](features/sso-scim.md))
- Plan entitlements and seat limits, audit events; see section 3 for SAML and the SCIM items.

## 5. Operations

- **Helm packaging.**
- **Shared store for rate limits and caches.** They are in memory, per instance, so limits multiply with more than one API replica.
- **Container images** were written and the publishes verified, but never built (no Docker daemon).
- **CI** is only a template (`deploy/ci/360workai-ci.yml`) whose paths assume a `360workai/` subfolder; this repository has no `.github/`, so nothing runs automatically.
- **Licensing**: the reference code is under the OpenWork EE License and this rewrite is covered by a default MIT annotation in the reference repository's
  `REUSE.toml`. Decide the intended license before release.

## 6. Gaps found in code review (not in the docs): fixed

These came from reading the code, not from the project's own documentation. All six are fixed and covered by tests
(`SecurityHardeningTests`, `LoginThrottleTests`, `SignInLockoutTests` in the API tests; `WebHostSecurityTests` in `tests/WorkAI360.Web.Tests`).

| Gap | Fix | What is left |
|---|---|---|
| No clickjacking protection or HSTS | Web host and API send `X-Frame-Options: DENY`, `frame-ancestors 'none'` and `nosniff` (overriding Blazor's own `SAMEORIGIN` / `'self'`, which a run of the real host showed); the web host adds `Referrer-Policy`; HSTS over HTTPS outside Development | HSTS was tested through a trusted proxy reporting `https`, not on a real TLS listener. No full CSP (scripts and styles) yet: Blazor Server needs a policy designed for it. |
| Browser writes likely fail behind HTTPS | The web host now believes `X-Forwarded-For/Proto/Host` from `Den:TrustedProxies` only (addresses or CIDR ranges, loopback by default) and strips them from everyone else | Deployments must set `Den__TrustedProxies` (and `Auth__TrustedProxies` on the API). Without it nothing changes from before. |
| Sign-in lockout could be used against a user | Lockout and the sign-in rate limit are per account and visitor address; a 50-failure per-account ceiling covers guessing from many addresses; entries are swept as they expire | Past the ceiling, the account is locked for everyone for up to 15 minutes, so an attacker with many addresses can still deny service to one account (it takes 50 attempts, not 5). State is still in memory per instance. The time-based sweep has no test (the clock is not injectable). |
| Secret not separated by purpose | `SecretKeys.Derive` (HKDF) gives cookies, audit cursors, brand links, SSO revisions and token-limit ids their own keys | None. Nothing is deployed yet, so no migration of old cookies or stored brand links was needed (a deployment of an earlier build would see web users sign in again once, and brand logos need re-uploading). |
| `Passwords.Verify` could throw | A damaged stored hash fails verification, so sign-in answers 401 | None. |
| Doc and comment slips | Empty README bullet removed; the `PrivilegedSessionMinutes` description moved back to its property | None. |

## Not yet reviewed

The OAuth and MCP provider, SSRF guards in Connections, SSO/SCIM, permission rules, the Library GitHub importer and the Blazor pages have not been read in
depth, so this list may be missing findings there.
