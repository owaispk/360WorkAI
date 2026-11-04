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
| `GET/POST/DELETE /v1/org/web-origins` | Exact https origins, at most 20, canonical form, duplicates refused. Enforced for CORS and web handoff return URLs ([web-origins.md](web-origins.md)) |
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
* **The event-type catalog lists what this build records** (about 370 names), not the reference's 1,864 (most belong to areas not built here): the change
  events below, the audit-read pairs, and the request events of every change route this build serves (see "Request evidence").
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

## Request evidence and change events for newer areas

**Request evidence** (`Features/OrgAdmin/AuditRoutes.cs`): the reference declares every route's audit action (`ee/apps/den-api/src/audit/routes/*.ts`);
`scripts/gen-audit-routes.mjs` turns its 237 change and outside-call declarations into `AuditRoutes.g.cs`, and the table is matched to this build's
endpoints by method and path shape (parameter names may differ; the target id is taken by position). When such a route finishes inside a workspace, one event
is written as the reference's request capture does: `<action>.succeeded` (`.confirmed` for a call to an outside system), `<action>.attempted` with outcome
`denied` and category `security` for 401/403, `.attempted` with `failed` and a reason (`validation_failed`, `resource_not_found`, `request_conflict`,
`request_rejected`, `request_failed`) for other errors, and `.unknown` when an outside call failed. Category `request`, the target resource and the workspace
as parent, method and route. No body and no response is read. A request whose handler wrote its own change events is not recorded twice. The workspace
comes from the resolved member context; SCIM provisioning is attributed to the token's workspace with the actor `service scim:<providerId>`. 144 route
stems are live (library, connections, providers, gateway, policy, prompts, default model, SSO/SCIM admin, SCIM provisioning, workspace claims and more).

**Change events** (`Features/OrgAdmin/DomainAuditEvents.cs`), with the reference's names and allowlisted snapshots (never secrets, tokens, certificates,
configuration hashes or identity-provider text; replaced secret material is the opaque `configuration` / `credentialMaterial` marker):
`sso_connection.registered` / `.enabled` / `.disabled` / `.deleted`, `scim_connection.token_rotated` / `.deleted` / `.reconciled` (category `execution`),
`scim_group_mapping.updated`, `agent_permission_policy.updated` / `.removed`, and `account.profile_updated` (recorded in every workspace of the person).
A change that changes nothing records nothing.

Tests: `tests/WorkAI360.Api.Tests/AuditCoverageTests.cs` (19). Mutation checks (7 of 7 killed): request events on top of change events, refusals outside
`security`, the target id dropped, the workspace not remembered, SCIM attribution ignored, a re-registration without its marker, an unchanged mapping recorded.

## Retention and housekeeping

`Features/OrgAdmin/Housekeeping.cs`, a hosted job (`Housekeeping__Enabled`, default on; every `Housekeeping__IntervalMinutes`, default 60):

* Deletes rows that can no longer do anything, `Housekeeping__GraceHours` (default 24) after they expired, so a code used just too late still answers
  "expired": sessions, desktop handoff grants, device codes, OAuth authorization codes, refresh tokens, agent (MCP) tokens, email codes, password reset
  tokens, DPoP bindings, workspace claim codes, and rate-limit windows older than two days. One set-based delete per kind; two instances running it at
  once do no harm. Invitations are kept (an expired one still shows as expired, as in the reference); SSO, social and SAML states, connection OAuth
  transactions, replay reservations and the request log already clean up after themselves.
* **Audit retention** is opt-in: `OrgAdmin__Audit__RetentionDays` deletes audit history whose operation began before the cutoff, as whole operations
  (operation, its events and their resource rows), in every workspace. Unset, nothing is deleted, as in the reference (whose retention is preview-only).

Tests: `tests/WorkAI360.Api.Tests/HousekeepingTests.cs` (3). Mutation checks (6 of 6 killed): no grace period, retention ignoring its window, deleting with
no retention set, resource rows left behind, events deleted by their own date instead of their operation's, live rows deleted.

## Dashboard activity (`GET /v1/org/activity`)

The admin dashboard's Activity panel (the reference's `dashboard-activity.ts`): the workspace's five newest additions, newest first (ties by entry id),
owners and admins only, `Cache-Control: no-store`. Sources, each following its own admin list's permission: connections (`connections.view`; a connection
a plugin set up for itself counts only while that plugin is active), model providers (all with `llm_providers.view`, else the ones the caller added),
AI Gateway providers (`gateway_providers.view` with `Gateway__Enabled`), plugins added to an active marketplace (not the built-in catalog), and published
versions of active skills in active plugins (each naming its most recently updated parent). Plugins and marketplaces are all of them with Manage everything
shared, otherwise what is shared with the caller. Only stored creation dates count, so archiving a plugin removes what it contributed. Titles and details
are the reference's ("Writing Kit was added to the Shelf marketplace", "Plugin with 1 skill", "A new version of tone-guide was published"). Tests:
`DashboardActivityTests` (2); mutation checks 3 of 3 (another workspace's providers, archived plugins contributing, no overall limit).

Elsewhere in this documentation: install links, `/v1/me/*` and the activation checklist are in [onboarding.md](onboarding.md); `/v1/resources*` too.

## Not built

* The den-web `web` page (OpenWork Web billing, Stripe) and `advanced` (a redirect to marketplaces).
* The reference's `.requested` intent events (written before a handler runs), request evidence for reads (`tenant_read`, off by default in the reference),
  platform-store events (OAuth client management, sign-in routes without a workspace) and change snapshots for library, connections, providers and gateway
  objects (they get request evidence only). Automation, workflow and workspace-document runs record their own history.
