# Org admin plumbing: API keys, audit log, organization settings

Reference: `ee/apps/den-api/src/routes/org/{api-keys,audit,core,activity,web-origins,brand-assets,feature-usage,delete-organization,inventory-revision}.ts`,
`src/audit/**`, `routes/features/index.ts`, `routes/me/index.ts`. Code: `src/WorkAI360.Api/Features/OrgAdmin/`, entities in `Domain/OrgAdmin/`, pages
`Components/Pages/{ApiKeys,AuditLogs,OrgSettings,BrandAppearance}.razor`. Tests: `tests/WorkAI360.Api.Tests/OrgAdminTests.cs`,
`tests/parity/area-org-admin.mjs`, `tests/parity/ui-org-admin.js`.

## Routes built

| Route | Notes |
|---|---|
| `GET/POST /v1/api-keys`, `DELETE /v1/api-keys/{id}` | `api_keys.view` / `api_keys.manage`. Secret `den_` + 64 letters and digits, shown once at creation; only its SHA-256 is stored. 90-day expiry, 600 requests a minute per key |
| API-key authentication | `x-api-key: den_...` (also `Authorization: Bearer den_...`) on every route that resolves a workspace through `OrgAccess` (all org routes) and on `GET /v1/me`, `/v1/me/orgs`. The key names its own workspace (the `x-openwork-org-id` header is ignored) and acts as the member who made it |
| `GET /v1/audit/operations`, `/operations/{id}/events`, `/event-types`, `/usage`, `/export`, `PATCH /v1/audit/settings` | Same filters, cursors, errors and headers as the reference (`audit_invalid_query`, `audit_invalid_cursor`, `410 audit_cursor_expired`, `X-Audit-*`, CSV and NDJSON exports with the reference's cell escaping) |
| `PATCH /v1/org` | Name, allowed email domains, desktop versions, SSO requirement and brand fields (kept in the organization metadata, as in the reference). The response carries the metadata as an object and `GET /v1/org` as a string, like the reference |
| `DELETE /v1/org` | Owner only, needs a recent sign-in; purges members, teams, roles, invitations, tokens, keys, settings, brand images, web origins and the workspace's audit history in one transaction |
| `GET/POST/DELETE /v1/org/web-origins` | Exact https origins, at most 20, canonical form, duplicates refused |
| `POST /v1/org/brand-assets`, `GET /v1/brand-assets/{org}/{kind}/{version}` | Wordmark and icon, PNG or JPEG under 2 MB with the reference's size and aspect rules. Stored in the database; served from an immutable URL signed with an HMAC |
| `GET /v1/org/activity` | Owners and admins; always an empty list for now (see below) |
| `GET /v1/org/inventory-revision` | Opaque hash of members, teams, roles, role links and settings |
| `POST /v1/org/feature-usage` | Validated and acknowledged; the report is dropped (no platform-admin view exists here) |
| `GET /v1/features` | Public; `engineV2ForceUpgrade` always true |
| `GET /v1/org` additions | `features`, `capabilities`, `entitlements`, `plan`, `authMethods`; `allowedEmailDomains` and `metadata` now come from the settings |

Pages: `/dashboard/api-keys`, `/dashboard/audit-logs`, `/dashboard/org-settings` (name, allowed domains, approved origins, delete workspace),
`/dashboard/brand-appearance`. Each is offered on the dashboard to people who hold the matching permission.

## Audit log: what is recorded

`IAuditLog` (`AuditLog.cs`) is called after the change committed, by: sign-in (`session.created`, `session.sign_in_failed`, `session.revoked`, in every workspace
the person belongs to), members (`member.role_updated`, `member.ownership_transferred`, `member.removed`), invitations (`invitation.created`, `.refreshed`, `.canceled`,
`.accept.confirmed`), teams (`team.create|update|delete.succeeded`, `team.permission_set.update.succeeded`), roles (`permission_set.created|renamed|permissions_changed|archived`),
API keys (`api_key.created|deleted|revoked`), web origins, organization settings and brand images, and the audit settings themselves (`audit.capture.enabled|disabled`,
`audit.policy.initialized`). Reading the history is itself recorded as a requested/served pair (category `access`). Events carry actor (with the API key's id when one was
used), resources, before/after and changed fields for changes, request id and HTTP method and route. Secrets, password hashes and key hashes never go into an event.

The policy is created on first use, ON, when the workspace is entitled (`OrgAdmin:Audit:SelfHosted`, default true). Switching capture needs the current revision
(`expectedRevision`); a stale revision is `409 audit_policy_changed`, and two simultaneous changes cannot both win (conditional update inside a transaction).

## Configuration

| Setting | Meaning |
|---|---|
| `OrgAdmin__Audit__Visible` (true) | false answers every audit route `403 audit_visibility_disabled` (after the permission check) |
| `OrgAdmin__Audit__SelfHosted` (true) | the reference's explicit self-hosted entitlement. false: `entitlement.enabled=false`, nothing is recorded, turning capture on is `402 enterprise_plan_required` |
| `OrgAdmin__Audit__CaptureAvailable` (true) | false: nothing is recorded |
| `OrgAdmin__Audit__ExportSettleSeconds` (5) | exports leave out the newest seconds, as the reference does |
| `Features__Overrides__<key>` | turns one feature flag on or off |

## Differences from the reference (and why)

* **API keys also work as `Authorization: Bearer den_...`.** The reference only reads `x-api-key` (a bearer key is 401 there). The `den_` prefix cannot be mistaken for a session token.
  Keys are accepted only through `OrgAccess`; session-only routes (`/v1/me/active-organization`, `/v1/mcp/token`, sign-out) answer 401 to a key, the reference answers 403 "Use a signed-in user session".
* **A key cannot delete a workspace** (`403`). The reference lets an owner's key do it. Ownership transfer by key is allowed, as in the reference (the key dies with it).
* **A key over its limit is `429` with `Retry-After`;** the reference answers 401. The limit is in memory per instance.
* **Audit usage totals are live;** the reference recomputes them on a schedule and reports `measuredAt`. Here `measuredAt` is the read time.
* **The event-type catalog lists the 40-odd actions this build records,** not the reference's 1,864 (most belong to areas not built here).
* **Audit writes are best effort:** if recording fails, the change stands and the failure is logged. The reference refuses the request when it cannot record (`503`).
  Operations are one per request (reads: one operation with two events); the reference groups events by an attachment window.
* **Brand images are checked, not re-encoded.** The reference runs them through sharp (which also strips metadata); there is no image library here. The checks are
  signature, structure (every PNG chunk, the JPEG markers and end), dimensions, type and size, and trailing data after the end of the image is refused.
* **No plan gating.** Everything the reference gates (SSO, desktop policies, org controls, analytics) is entitled; `plan` is `{tier: "free", source: "default"}`.
  Audit logs follow `OrgAdmin:Audit:SelfHosted`.
* **`capabilities` is honest:** only `auditLogs` is on (the reference also reports connections, workflows, install links and more). Features that need server areas not built here
  (activation checklist, gateway, connectors, remote sessions, analytics trends, MCP app libraries, Slack) are reported off even though the reference's default is on; the rest of
  the 56 keys come from the reference (`FeatureDefaults.g.cs`, regenerate with `node scripts/gen-features.mjs`).
* **Deleting a workspace ends the sessions that pointed at it** (as the reference does) and removes its audit history with it; there is no platform-level record.
* **Allowed email domains are enforced** on invitation create (`409 invite_email_domain_not_allowed`) and accept (`409 account_email_domain_not_allowed`), as in the reference.
  The invitation preview shows the limit and the brand name and images.

## Not built

* `GET /v1/org/resources`, `/v1/resources/marketplace-capabilities` (they list library resources: plugins, marketplaces, connections; those areas are separate).
* `/v1/orgs/{id}/install-links`, `/v1/me/install-config`, `/v1/install-config`, `/v1/install/{platform}`, `/v1/me/install/{platform}` (installer downloads; need release hosting).
* `/v1/me/activation` (+ events), `/v1/me/agent` (+ checks): the first needs gateway, connection and provider facts; the second is behind the `workbotProactive` feature.
* `/v1/me/profile`, `/v1/me/invitations`, `/v1/me/send-download-link`, `/v1/me/desktop-config`, `/v1/me/prompts`: not part of org admin as built here.
* `GET /v1/org/activity` returns an empty list: the reference reads connections, providers, plugins and skills, which do not exist yet.
* The den-web `web` page (OpenWork Web billing, Stripe) and `advanced` (a redirect to marketplaces).
* Enforcement of approved web origins (CORS and desktop-handoff return URLs): the list is stored and managed, but nothing reads it yet.
* Audit capture for routes of areas not yet built (they call `IAuditLog` when they are), SCIM/SSO events, retention and cleanup jobs, the platform-admin view of feature usage.
