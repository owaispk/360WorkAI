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

## How feature flags resolve

In the reference's order (`FeatureResolver`): not part of this deployment (cloud-only: `autoRouter`, `sandboxOrgs`, `managedDeployments`) off, then the kill switch (off),
then an operator lock (`Features:Overrides:<key>` in configuration, the former override setting; reported as `source: "lock"`), then the workspace's override, then
on or off for everyone (the stored rollout, else this build's default). `GET /v1/features` uses everything except the workspace override; the `features` of `GET /v1/org`
use all of it. `Features/OrgAdmin/FeatureDefaults.g.cs` still holds the defaults; `FeatureCatalog.g.cs` (generated by `scripts/gen-admin-features.mjs` from the reference's
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
* `/v1/admin/dashboard`, `control-center` (+ refresh), `security` and `security/requests`, `feature-usage` (+ per organization), `opportunities*`, `scale-performance`, `sandbox-organizations`, `services`, `mcp-registration`,
  organization `usage` and `insights` (they need gateway usage, telemetry, security counters or outside services).
* Member-level feature overrides (`member-features`) and the `members` admin list of a workspace beyond the detail page.
* The den-web pages for those, and a dashboard link to `/admin` (the page is reached by URL and answers anyone else with a plain message).

## Running it

```bash
export WORKAI360_API_URL=http://localhost:5170 WORKAI360_WEB_URL=http://localhost:5270 WORKAI360_RUN_DIR=/tmp/workai-padmin-run \
  ConnectionStrings__Default="Data Source=/tmp/workai-padmin.db" PlatformAdmin__BootstrapEmails=padmin.parity@example.com
rm -f /tmp/workai-padmin.db*; scripts/dev.sh start
W=$WORKAI360_WEB_URL A=$WORKAI360_API_URL node tests/parity/area-platform-admin.mjs
W=$WORKAI360_WEB_URL A=$WORKAI360_API_URL node tests/parity/ui-platform-admin.js /tmp/shots
node tests/parity/area-platform-admin.mjs          # the reference (needs mysql access to add the admin, see the script header)
```
