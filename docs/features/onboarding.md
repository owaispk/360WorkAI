# Onboarding: from sign-up to a configured workspace

Reference: `ee/apps/den-api/src/routes/{me/index,me/agent,me/activation,org/install-links,bootstrap/index,org/diagnostics,org/egress-diagnostics,org/resources,version/index}.ts`,
`workspace-preclaim.ts`; den-web `app/(den)/{organization,claim,setup,install,workspace-claim,reauth}` and `dashboard/(admin)/onboarding`.
Code: `src/WorkAI360.Api/Features/Onboarding/`, entities in `Domain/Onboarding/`, pages `Components/Pages/{Organization,OnboardingPeople,OnboardingTools,OnboardingReady,Install,Claim,WorkspaceClaim,Setup,ReauthComplete,ReauthDesktop}.razor`
(shared: `Components/OnboardingPage.cs`, `Shared/OnboardingSteps.razor`, `wwwroot/onboarding.css`). Tests: `tests/WorkAI360.Api.Tests/OnboardingTests.cs`,
`tests/parity/area-onboarding.mjs`, `tests/parity/ui-onboarding.js`.

## The path a new person takes

Sign up (`/`) → `/organization` (create a workspace; shows invitations waiting for them, or a pasted invitation link) → `/dashboard/onboarding/people` (invite people, optional)
→ `/dashboard`. `/dashboard/onboarding/tools` (add team tools) and `/dashboard/onboarding` (get the desktop app, "Email me the link") are reachable from there. A person who already has
workspaces sees Settings on `/organization` (Profile: rename; Organizations: switch or create another). Pages that need a signed-in person (`/install`, `/claim`, `/workspace-claim`,
`/reauth/desktop`, the onboarding steps) send everyone else to `/?returnTo=...` and come back after sign-in; only a fixed list of paths is ever followed (`OnboardingPage.SafeReturnTo`).

## Routes built

| Route | Notes |
|---|---|
| `PATCH /v1/me/profile` | `firstName` and `lastName` (trimmed, at most 120, at least one non-empty, whitespace collapsed). Changes only the caller's own name |
| `GET /v1/me/invitations` | Pending, unexpired invitations for the caller's address in workspaces they have not joined, at most 20. **Empty unless the address is verified** (an invitation id is the secret the emailed link carries) |
| `POST /v1/me/send-download-link` | Emails the caller's own address (nothing in the request can name a recipient), 5 an hour per person (database counter, one conditional update per hit), counted even when mail fails. `429 rate_limited` + `Retry-After`; `502 download_link_email_failed` with a `reason` and no address in it |
| `GET /v1/me/install-config`, `GET /v1/install-config` | Brand name, addresses, `desktopVersion` (newest of the workspace's approved list, else the deployment's), `distribution: "cloud"`. The public one names no workspace; 60 an hour per address |
| `GET /v1/me/install/{platform}`, `GET /v1/install/{platform}` | Five platforms; a 302 to the release asset (`{ReleaseBase}/v{version}/openwork-cloud-...`), or a file from `Onboarding:Desktop:ArtifactsDir` when present (names built from constants, never from the request). 20 an hour per address. The old public route redirects to `/install` and ignores its token |
| `POST /v1/orgs/{organizationId}/install-links` | The plain install page address (no token, nothing created) |
| `GET /v1/app-version` | `minAppVersion`, `latestAppVersion`, `publishedDesktopVersions`, `webUrl`; from `Onboarding:Desktop:*` |
| `POST /v1/bootstrap/workspace` | An agent provisions a workspace before anyone has an account: provisional organization, a sign-in-less setup member, a starter skill + plugin + marketplace shared with everyone, one claim link per requested role, and a signed assertion naming it. 5 per hour per address (`Onboarding:Bootstrap:LimitPerHour`); validation errors do not use an attempt |
| `POST /v1/bootstrap/workspace/{id}/claim`, `GET .../claim` | With the assertion as a Bearer token: make a claim code (`ABCD-EFGH`, 15 minutes, a new one cancels the last), or read the claim state (`none`, `pending`, `expired`, `accepted`, `reconciled`) |
| `GET /v1/bootstrap/claim-codes/{code}`, `POST /v1/bootstrap/claim-codes/accept`, `POST /v1/bootstrap/claims/accept` | A signed-in person takes the workspace with a code (becomes owner) or a link (gets the link's role). One winner, whatever races: claims queue on the workspace row. The setup member and its user are removed, what the agent made passes to the person, unused links/codes are cancelled, the session's active workspace is set |
| `GET /v1/org/diagnostics`, `POST /v1/org/diagnostics/check`, `POST /v1/diagnostics/desktop-startup` | Sections granted or locked by permission (desktop `desktop_policies.view`, providers `llm_providers.view`, connectors `connections.view`, network `egress_diagnostics.view`; installation always locked). Desktop launches (24 hours, per-launch idempotent, 20 reports an hour per member, 7-day/5-minute window) feed the desktop section and the attention item |
| `GET /v1/diagnostics/egress`, `PUT /v1/diagnostics/egress/token`, `POST /v1/diagnostics/egress` | Configuration, an encrypted per-workspace token (never returned), and the run |
| `GET /v1/resources`, `GET /v1/resources/marketplace-capabilities` | What a desktop polls: marketplaces the member may see with their plugins and skills and update times; and the grant-scoped capability references (not widened by being an administrator) |
| `GET /v1/me/activation` | The "Get set up" checklist for the caller in the active workspace (the reference's `activation.ts`): six steps in recipe order (`first_response`, `invite_teammate`, `use_skill`, `own_provider`, `gateway_provider`, `connector`), each `{id, done, detail?, lockedReason?}`, plus `dismissed`. `Cache-Control: no-store`. How each step is decided here is below |
| `POST /v1/me/activation/events` | `{step: first_response\|use_skill\|own_provider\|dismiss, durationMs?}` (strict; `durationMs` an integer 0 to 86,400,000, kept for `first_response` only). One row per member and step (`ActivationEvent`): the first report wins, repeats change nothing. Answers the updated checklist |
| `GET/PUT /v1/me/agent`, `GET /v1/me/agent/checks` | Answer `404 {error: "feature_disabled", feature}` to members: "My agent" is off in this build (see below) |

## Differences from the reference

* **The checklist is built from what this build knows.** `first_response`: the client's report (there is no desktop telemetry or Workbot here); the detail reads "Answered in 2.1 s".
  `invite_teammate`: for someone who may invite, an invitation they sent that is pending or accepted; for others, any teammate or pending invitation; detail "N joined, M invited";
  locked with "{owner} can invite people" when nobody else is there. `use_skill`: the client's report or a skill their agent read through the library (`LibraryUsageEvent`).
  `own_provider`: the client's report ("Your key, on this device"), a provider the person added ("OpenAI added"), any provider in the workspace
  ("Models from your organization", see [llm-providers.md](llm-providers.md)), or done when the person's desktop policy does not allow custom providers ("Your team manages models"). `gateway_provider`: there is no AI Gateway
  here, so it stays open, locked with "{owner} manages AI Gateway" for anyone without `gateway_providers.manage`. `connector`: the first MCP connection usable by the person that is
  connected for them, needs no reconnect and no setup ("Linear connected"). Like the reference, the routes are not behind the `activationChecklist` flag, which is now on by
  default (the reference's default). Tests: `tests/WorkAI360.Api.Tests/ActivationTests.cs` (10); mutation checks 5 of 5 killed (reports not per member, a later report
  replacing the first, the gateway lock inverted, the caller counted as a teammate, a teammate's skill use counting).
* **"My agent" is off**, not built: it needs Workbot.
* **The pre-claim assertion cannot be exchanged for tokens.** The assertion (HS256, key derived from `Auth:Secret`, audience = the token endpoint) is issued and verified on the claim routes, but the JWT-bearer grant at
  `/api/auth/oauth2/token` is not built, so the setup agent cannot yet act on the workspace before it is claimed. The claim flows (code and link) work end to end.
* **A claim link is claimed by a click**, not automatically after sign-in (the reference auto-accepts). Members are deleted rather than soft-removed here, so the reference's `membership_removed` (403) case does not exist.
* **`POST /v1/orgs/{id}/install-links` for another workspace is `404`**; the reference answers 200 for any well-formed id (it returns a constant).
* **The download-link email points at this deployment's `/install` page** (or `Onboarding:DownloadUrl`), not a public download site; the message is plain, without the reference's capability list. Profile changes are not audited (the reference records `account.profile_updated`).
* **App versions are configured, not read from GitHub** (`Onboarding:Desktop:LatestVersion`, `MinAppVersion`, `PublishedVersions`, `ReleaseBase`, `ArtifactsDir`). Defaults match the reference's current release.
* **`PUT /v1/diagnostics/egress/token` with a short token is `400`** (the reference answers an uncaught-error 500). `POST /v1/diagnostics/egress` is `503 egress_diagnostics_not_configured` without a target and `501` with one: the fixed HTTP/OAuth/MCP probes are not built.
* **Diagnostics have no providers, connectors or installation checks** (those areas do not exist here): the sections are granted but empty, `POST .../check` just returns the current picture (202), and nothing can reach error severity.
* **`marketplace-capabilities`** follows the grant rules of the library area (a skill is visible through its own grant, or a plugin the person made or was given); it is an approximation of the reference's query.
* **Onboarding pages**: the models step does not call `/v1/inference` (not built); it says models are set up from the dashboard. The tools step can only add what the server can reach (presets point at public services; on a machine with no internet the server's refusal is shown).
  `/setup` is first-administrator setup ([platform-admin.md](platform-admin.md#first-administrator-setup-setup)). The install page is the cloud variant (the reference's enterprise step guide is not built).

## Configuration

| Setting | Meaning |
|---|---|
| `Onboarding__Bootstrap__LimitPerHour` (5), `__ExpiresHours` (72), `__CodeMinutes` (15) | Provisioning limit per address, lifetime of a provisional workspace and its links, claim code lifetime |
| `Onboarding__Desktop__LatestVersion`, `__MinAppVersion`, `__PublishedVersions__0...`, `__ReleaseBase`, `__ArtifactsDir` | Versions and where installers come from |
| `Onboarding__DownloadUrl` | Link in the download-link email (default: this deployment's `/install`) |
| `Onboarding__DiagnosticsOrigin`, `__DiagnosticsBearerToken` | Network-check target and the environment-level token |

## Security notes

Claim tokens and codes are stored as SHA-256 only; the assertion is not stored (only its token id); the egress token is encrypted (AES-GCM, `SecretBox`). The setup agent's user has an unusable password hash and a reserved
`agents.openwork.invalid` address. Claim, code and link redemption is conditional and queued on the workspace row. Rate limits for the email, installer, config, bootstrap and desktop-report routes are database counters
(so every instance agrees) updated with one conditional statement per hit. Mutation checks: see the report in the commit history; redundant layers (the code's own state check and the bootstrap-level check guard the same race) are noted there.

## Not built

* The JWT-bearer token exchange for the pre-claim assertion; My agent (above); the egress probes; provider/connector/installation diagnostics.
* Cloud sandbox joins (`join-sandbox`, sandbox join, Workbot hand-off), billing and the AI gateway, as instructed; den-web's `workspace-claim` desktop-app handoff button after claiming.
