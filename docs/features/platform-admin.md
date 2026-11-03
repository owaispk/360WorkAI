# Platform administration: the operator's view of a deployment

Reference: `ee/apps/den-api/src/routes/admin/{index,organization-detail,scale-performance}.ts`, `src/middleware/admin.ts` (`adminRoute()` and `requireAdminMiddleware`),
`src/admin-allowlist.ts`, `src/features.ts`, `ee/packages/den-db/src/organization-features.ts`, `packages/features/src/resolve.ts`, and the den-web pages under
`ee/apps/den-web/app/admin/**`. Code: `src/WorkAI360.Api/Features/PlatformAdmin/`, entities in `Domain/PlatformAdmin/`, pages
`Components/Pages/Admin*.razor` (`/admin`, `/admin/users`, `/admin/organizations`, `/admin/organizations/{id}`, `/admin/features`). Tests:
`tests/WorkAI360.Api.Tests/PlatformAdminTests.cs`, `tests/parity/area-platform-admin.mjs`, `tests/parity/ui-platform-admin.js`.

A platform admin runs a whole deployment. A workspace owner is not one, and nothing a workspace can do makes someone one.

## Who is a platform admin

* A row in the admin list (`AdminAllowlistEntry`, unique lower-case email), like the reference's `admin_allowlist`.
* `PlatformAdmin__BootstrapEmails=a@x.com,b@x.com` (or an array in a settings file) lists addresses at the first admin request of each process, with the note
  "Seeded bootstrap admin". A seeded admin can be removed in the page but returns at the next start while it stays configured (as in the reference).
  On the reference the same is done with `DEN_BOOTSTRAP_ADMIN_EMAILS` or by inserting into `admin_allowlist`; the parity script header explains both.
* The guard (`PlatformAdminGuard`, applied first in every `/v1/admin` route): not signed in `401 {"error":"unauthorized"}`; no email `403 admin_email_required`;
  `Auth:RequireEmailVerification` on and the address unproven `403 admin_email_unverified`; address not listed `403 {"error":"forbidden"}` (no message, no
  workspace hints). The workspace header, workspace role and ownership are never consulted. The check is made on every request, so adding or removing an
  admin takes effect at once for sessions that already exist.

## Routes built

| Route | Notes |
|---|---|
| `GET /v1/admin/overview` | viewer, admins, totals, first page of users (reference shape: heavy numbers are deferred to `/metrics`) |
| `GET /v1/admin/users` | search (name, email, id, workspace name/id/role; an address is an exact match; `%` and `_` are literal), `limit` 1 to 100 (default 50), `offset`, `includeBilling` (shows "unpaid"; no billing provider is called) |
| `DELETE /v1/admin/users/{id}` | not yourself, bad id 400, unknown 404. Ends every session, API key, agent token, grant and SSO link, removes memberships and team links, deletes the account. Each workspace records `member.removed` and the ended sessions (actor the admin, origin `platform_admin`, reason `user_deleted`) |
| `GET /v1/admin/organizations`, `GET /v1/admin/organizations/{id}` | list and search (`includeFeatures=0` leaves out capabilities and states); detail with a searchable page of people, plan and people counts, `Cache-Control: no-store` |
| `PATCH .../plan` | `{tier: free\|team\|enterprise, seatLimit 1..100000, endsAt?}`; stored, never billed. Free: at least 5, anything above 5 is extra free seats. Team and Enterprise: seats at least 5, end date display-only (YYYY-MM-DD, real date). Shown in `GET /v1/org` `plan` |
| `PATCH .../free-seats` | `{totalFreeSeats 5..100000}` stored beside the plan |
| `PATCH .../dpa` | `{dpaSigned, reason 3..500}` strict body. Audited as `organization.dpa_signed.updated`; the reason text is never stored, only that one was given |
| `PUT .../openwork-web-access` | `{enabled, reason}`; audited (`organization.complimentary_access.granted/revoked`); `GET /v1/org` `capabilities.openworkWeb` follows it |
| `GET/PUT .../capabilities` | per-workspace overrides: `true`, `false`, or `null` to clear; every feature with `enabled`, `source`, `everyone`, `killed`, `lock`, `override`, `overrideApplies`, `lastChange`. Cloud-only keys 400; unknown keys ignored |
| `GET /v1/admin/features`, `PUT /v1/admin/features/{key}` | the 56-feature registry, on/off for everyone and the kill switch (`{enabled?, killed?}`, strict) |
| `GET /v1/admin/metrics` | counts computed from this database (below) |
| `POST /v1/admin/admins`, `DELETE /v1/admin/admins/{id}` | add (lower-cased, 409 on a duplicate) and remove (not yourself, not the last admin; the removal locks the list so two admins cannot remove each other at once) |

Changes to a workspace (plan, free seats, DPA, web access, capabilities, user removal) are written to that workspace's audit history through `IAuditLog`, so its
owner can read them. Feature rollouts have no workspace and, as in the reference, are recorded only in the feature history (`lastChange`).

| `GET /v1/admin/feature-usage[?range=7d or 30d]`, `GET /v1/admin/feature-usage/{key}`, `GET /v1/admin/organizations/{id}/feature-usage` | per feature: workspaces it is on for, members using it, last use, one health state (`not_used`, `in_use`, `healthy`, `failing`, `limited`, `mostly_skipped`) and, for the two Automation features (`automationIntervalSchedules`, `automationCalendarTriggers`), run outcomes read from this database's Automation runs (by day, status, reason); the per-workspace report lists who used each feature. Usage is recorded when a client reports it (`POST /v1/org/feature-usage`, now stored as member, feature and UTC day, only for features that are on for the caller) |
| `GET /v1/admin/security[?days=1..30]` | 14 threshold findings with their rules, in the reference's wording: sign-up bursts, unverified and throwaway sign-ups, unverified domains, accounts on many networks, many workspaces from one person, new platform admins, API key bursts, app registrations, invitation bursts, sign-ins from automation tools; the three that need model usage (spend spikes, round the clock, free allowance on day one) are always clear. App registrations are not attributed to a person here (a client has no owner), so only the volume rule applies |
| `GET /v1/admin/services`, `POST /v1/admin/services/check` | deployment readiness in the reference's v2 shape: database (a real query), email (settings only, nothing is sent), and the gateway, headless runner and Workbot as not set up; a check less than 30 seconds old is answered again (`202`) |
| `GET /v1/admin/sandbox-orgs` | `{enabled: false, sandboxes: []}`: sandbox organizations are a cloud feature (`sandboxOrgs`), off on a self-hosted deployment as in the reference |
| `GET/PUT /v1/admin/organizations/{id}/members/{memberId}/capabilities` | per-member overrides (the reference's `member-features.ts`): `{capabilities: {key: true\|false\|null}}` strict (unknown keys and extra fields 400; cloud-only keys 400 unless clearing). Each feature with `enabled`, `source` (`member` when the person's own setting decides), `everyone` (what the workspace gives them without it), `killed`, `lock`, `override` (the member's), `overrideApplies`, `lastChange` (including member-scope changes). A member of another workspace, a removed member or the setup member of an agent-provisioned workspace is `404 "Active organization member not found."`; the membership is re-read under the workspace lock before writing. Audited in the workspace as `member.capabilities.updated` (origin `platform_admin`). Page `/admin/organizations/{id}/members/{memberId}` (the Features link on each person) |
| `GET /v1/admin/dashboard` | the reference's 30-day AI usage shape (`from`, `to`, `activeOrganizations`, `totals`, 30 `daily` rows, up to 8 `organizations` by requests), read back from every workspace's AI Gateway (LiteLLM) providers ([gateway.md](gateway.md)); a proxy that cannot be read is left out. With no Gateway provider anywhere, zeros. `Cache-Control: no-store` |
| `GET /v1/admin/dashboard/active-users` | distinct people active `today`, in `days7` and `days30` (UTC calendar days), across every workspace. Active = a session created or a feature use a client reported (`POST /v1/org/feature-usage`), this build's equivalent of the reference's sign-in-or-telemetry rule. Read on request (the "Count active people" button on `/admin`). Sessions end at sign-out here, so someone who signed in and out again is still counted by their feature use only |
| `PUT /v1/admin/oauth-clients/{id}/client-credentials-scopes` | this build's only addition: lets an operator give a machine client its scopes ([oauth-extras.md](oauth-extras.md)) |

## First-administrator setup (`/setup`)

Reference: `ee/apps/den-api/src/initial-admin-bootstrap.ts`, the bootstrap routes in `routes/auth/index.ts`, and den-web `app/(den)/setup/page.tsx`. Code:
`Features/PlatformAdmin/InitialAdminSetup.cs`, the grant check in `POST /api/auth/sign-up/email`, page `Components/Pages/Setup.razor`. Tests:
`tests/WorkAI360.Api.Tests/InitialAdminSetupTests.cs` (6), `tests/parity/ui-setup.js` (11, browser; needs a fresh deployment, see its header).

A private deployment gets its first administrator without anyone choosing a password over email. The operator sets `PlatformAdmin__BootstrapEmails`
(who may become the first administrator) and `PlatformAdmin__InitialAdminCode` (a one-time code, handed over through a secret store), then opens `/setup`.

| Route | Notes |
|---|---|
| `GET /v1/auth/bootstrap/status` | Public. `available` (an address and the code are configured and no account exists), `complete` (any account exists), `unavailable` (not configured). Never names an address |
| `POST /v1/auth/bootstrap/verify` | `{email, code}`. `200 {grant, expiresAt}`: a grant (`ow_bootstrap_…`, HMAC-signed with a key derived from `Auth:Secret`, 10 minutes, bound to the address). `409 bootstrap_unavailable` when setup is not open; `403 bootstrap_verification_failed` with one message for a wrong code, an unlisted address or a bad body. 5 attempts per address per 5 minutes (`429 rate_limited` + `Retry-After`) |
| `POST /api/auth/sign-up/email` with `bootstrapGrant` | The grant must be genuine, unexpired, for this address, the address still configured, and setup still open; otherwise `403 bootstrap_verification_failed` and nothing is created. The account is created **verified**, gets a workspace it owns (`PlatformAdmin__InitialWorkspaceName`, default "OpenWork") as the session's active one, and is put on the admin list with the note "Initial administrator bootstrap" |

**While setup is open, nothing else can create the first account**: ordinary email sign-up, sign-in by email code for a new address, social sign-in
and agent workspace provisioning (`POST /v1/bootstrap/workspace`) answer `403 setup_required`. Once any account exists, status is `complete` for good:
verification is `409` and an unused grant stops working.

Differences from the reference: the reference closes public sign-up through its single-workspace mode (`DEN_SINGLE_ORG_*`), which this build does not
have, so here ordinary sign-up is closed only until setup is done and the first administrator gets an ordinary workspace. The admin addresses come from
`PlatformAdmin__BootstrapEmails` (the reference prefers `DEN_SINGLE_ORG_OWNER_EMAILS`). The code is compared as SHA-256 hashes (so its length does not
show in timing either). With `Auth__RequireEmailVerification=true` the reference completes setup only when sign-up returns a session; here the
workspace and admin entry are made either way, and the verified person signs in next.

Mutation checks (8 of 8 killed): no code check, no address check at verify, grant not bound to its address, no expiry, no signature check, grant still
valid after setup, no sign-up gate while setup is open, setup account not verified.

Member overrides are tested in `tests/WorkAI360.Api.Tests/MemberFeatureTests.cs` (4) and `tests/parity/ui-member-features.js` (10, browser). Mutation checks
(5 of 5 killed): the override following the person into another workspace, beating the operator lock, accepting another workspace's member, not reaching
`GET /v1/org`, and rows not tied to the membership.

The dashboard is tested in `tests/WorkAI360.Api.Tests/AdminDashboardTests.cs` (4: exact counts with backdated sign-ins and feature use, the shape, and access),
and in the browser by `tests/parity/ui-member-features.js`.

## How feature flags resolve

In the reference's order (`FeatureResolver`): not part of this deployment (cloud-only: `autoRouter`, `sandboxOrgs`, `managedDeployments`) off, then the kill switch (off),
then an operator lock (`Features:Overrides:<key>` in configuration, the former override setting; reported as `source: "lock"`), then the member's own override
(`source: "member"`), then the workspace's override, then on or off for everyone (the stored rollout, else this build's default). `GET /v1/features` uses
everything except the workspace and member overrides; the `features` of `GET /v1/org` use all of it for the caller, and so does `POST /v1/org/feature-usage`.
A member override belongs to the membership (`PlatformMemberFeature`, keyed by member id) and is read through it, so it never follows the person into another
workspace and stops applying when they leave; joining again starts from the workspace's value. `Features/OrgAdmin/FeatureDefaults.g.cs` still holds the defaults; `FeatureCatalog.g.cs` (generated by `scripts/gen-admin-features.mjs` from the reference's
`/v1/admin/features`) holds each feature's label, description, category and dates.

## Metrics

"Active" is a sign-in (a session created) on that UTC day, over the last 90 days; users, verified, new in 7 and 30 days, admins, inviters and the median hours to a first
invitation come from the tables; the 30-day series has sign-ups per day. There is no product telemetry, workers or billing here, so real-active users and workers are 0
and paid and unpaid are null.

## Differences from the reference (and why)

* **API keys and agent tokens never reach `/v1/admin`** (401). The reference's guard reads the request's user, which an API key also supplies. A platform route should
  need a signed-in person.
* **A feature's `author` is `"openwork"`.** The reference gives a person's handle; this repository must not name people.
* **Plan, free seats, DPA and web access are stored but not enforced.** Invitations are not capped by a plan (the reference enforces it only with its billing setup), the
  deprecated `GET /v1/org` metadata string does not carry `dpaSigned`/`complimentaryAccess`/plan, and `userLimit` is always null. `GET /v1/org` shows `plan` and `capabilities.openworkWeb`.
  The DPA decision is write-only: no route reads it back (the reference has none either).
* **The reference's default for sixteen features is "on" but this build reports them off** until their server areas exist (`FeatureState`); an admin can switch them on.
* **Deleting a user removes memberships** instead of marking them removed (this build has no soft removal); a user deleted while being a workspace's only owner leaves it
  without an owner, as in the reference. The list entry of a deleted admin stays (it is an address); signing up again with it regains access.
* **`lastSeenAt` is the newest session update**; sessions end at sign-out here, so it is the latest of the live ones.
* **Concurrency:** first-time rollout changes retry once on a unique-key race.

## Not built

* `GET /v1/admin/users/{id}/inference-usage` and the inference usage reset, free-auto (`free-auto/*`), the Stripe-backed plan, billing and `includeBilling` paid states, seat-subscription syncing.
* `control-center` (+ refresh), `security/requests` (it reads a log of refused, rate-limited and failed requests that this build does not keep, so there is nothing honest to show), `opportunities*`,
  `scale-performance`, the sandbox organization actions (create, rotate link, join role, extend, credit, close: always "turned off" on self-hosted), `mcp-registration`, organization `usage` and `insights`
  (they need gateway usage, telemetry or outside services). Feature outcomes for `slackSendAsBot` and `workbotProactive` (no Slack or Workbot here); background Automation work is not recorded as feature usage.
* The `members` admin list of a workspace beyond the detail page (the detail page shows up to 100 people with a link to each one's features).
* Pages for what is built: `/admin/feature-usage`, `/admin/security`, `/admin/services` (Blazor, in the admin navigation). The den-web pages for the rest, and a dashboard link to `/admin` (the page is reached by URL and answers anyone else with a plain message).

## Running it

```bash
export WORKAI360_API_URL=http://localhost:5170 WORKAI360_WEB_URL=http://localhost:5270 WORKAI360_RUN_DIR=/tmp/workai-padmin-run \
  ConnectionStrings__Default="Data Source=/tmp/workai-padmin.db" PlatformAdmin__BootstrapEmails=padmin.parity@example.com
rm -f /tmp/workai-padmin.db*; scripts/dev.sh start
W=$WORKAI360_WEB_URL A=$WORKAI360_API_URL node tests/parity/area-platform-admin.mjs
W=$WORKAI360_WEB_URL A=$WORKAI360_API_URL node tests/parity/ui-platform-admin.js /tmp/shots
node tests/parity/area-platform-admin.mjs          # the reference (needs mysql access to add the admin, see the script header)
```
