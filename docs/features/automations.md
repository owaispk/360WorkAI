# Automations and telemetry

Code: `src/WorkAI360.Api/Features/Automations/` (schedule math, rules, routes, the run queue, the scheduler loop, telemetry), entities in
`Domain/Automations/` (`AutomationEntities.cs`, `TelemetryEntities.cs`), pages `src/WorkAI360.Web/Components/Pages/Automations.razor`
(`/dashboard/automations`), `AutomationDetail.razor` (`/dashboard/automations/{id}`) and `Analytics.razor` (`/dashboard/analytics`), dashboard buttons in
`Components/AutomationLinks.cs`, plain-words labels in `Components/AutomationFormat.cs`.
Tests: `tests/WorkAI360.Api.Tests/AutomationScheduleTests.cs` (41, pure functions), `AutomationTests.cs` (45, through the API, including the races and the cloud runtime fixture),
`tests/parity/area-automations.mjs` (61, runs on the reference and the rewrite), `tests/parity/ui-automations.js` (browser).

## What it is

**Automations** are work your agent does on a schedule. Each belongs to one person (its owner): nobody else, admins included, lists, reads, changes, runs or
cancels it (another person's id is `404`). What an Automation does lives in immutable **revisions**: a change to the instructions, schedule, model, placement
or pinned workspace makes a new revision that applies to future runs at once, while a rename (or saving the same thing again) does not. A **run** is one
occurrence. A desktop runner claims it, keeps it alive with heartbeats, reports its steps and ends it.

**Telemetry** is usage events the desktop and workers send (`user.active`, `session.started`, `task.completed`, ...) and the analytics computed from them in
this database.

## Routes built

Automations (any member, for their own): `GET`/`POST /v1/automations`, `GET`/`PATCH`/`DELETE /v1/automations/{id}` (delete archives), `POST .../activate`,
`.../deactivate`, `.../run` (optional body `{executionTarget}`), `GET .../runs`, `POST /v1/cloud-automations`. Runs: `GET /v1/automation-runs` (a calendar
range of at most 45 days), `GET /v1/automation-runs/{id}` (the receipt: run, Automation, revision, events), `POST .../cancel`. Where they can run:
`GET /v1/automation-runners` and `/presence`.

The desktop runner protocol: `POST /v1/automation-runners/token` (a session mints a 12-hour runner credential and registers the desktop), then with that
credential `GET /v1/automation-runner/work`, `POST /v1/automation-runs/{id}/claim|heartbeat|events|complete`.

Telemetry: `POST /v1/telemetry/ingest` (any member, always `204` for a valid batch), `GET /v1/telemetry/analytics|adoption|dimensions` (`usage_analytics.view`).

Whether desktop and cloud Automations are allowed comes from the Policy area's Automation settings (`GET`/`PUT /v1/org/automation-settings` is not duplicated here).

### Schedules

`once` (an instant), `daily`, `weekly` (days, 0 = Sunday), `interval` (every N hours inside a daily window, on listed days; needs the organization feature
`automationIntervalSchedules`, off by default) and `calendar` (before/after each meeting, cloud only, needs `automationCalendarTriggers`). Times are wall-clock
times in the schedule's IANA zone, validated with the reference's messages. `ScheduleMath` is a pure function (`Next`, `Occurrences`, `InRange`) with the
reference's daylight-saving rules: a time that happens twice (clocks go back) runs at its first instant; a time that does not exist (clocks go forward) runs at
the first valid minute after the gap; two wall times pushed onto one instant count once.

### The run queue and leases (the heart of it)

Every state change is **one conditional update** naming the state it expects, so racing callers cannot both win (SQLite and MySQL alike, no provider SQL):

* **Claim** moves `queued -> running` only if the run is still queued, inside its claim window, and the owner's: of any number of desktops asking at once exactly
  one gets it. The same desktop asking again gets its own assignment back (a reconnect). A desktop that does not hold the run gets `{assignment: null}`.
* **Heartbeat** extends the lease only for the lease holder, the right attempt, status `running` and an unexpired lease; otherwise `409 runner_lease_lost`.
  The answer carries `cancelRequested`, which is how a running run is told to stop.
* **Events** append in order per attempt: step N is accepted only when the run's sequence counter is N-1 (the counter move and the insert are one
  transaction); a gap is `409 automation_runner_event_sequence_gap`; a repeat of a recorded step returns that event; the same step sent twice at once makes one.
* **Complete** is final and idempotent: the first valid result wins; the same result again returns the stored run; a different one is
  `409 terminal_result_conflict`; a lost lease or wrong attempt is `409 runner_lease_lost`. A result with a `model_access_lost` or `provider_unavailable`
  error pauses the Automation (`needs_attention`) until it is activated again.
* **Recovery** (the scheduler's tick) re-queues a run whose lease expired (the first time; attempt 2 starts events over) and fails it the second time, naming the
  lease it saw expire so a runner that extended it keeps its run. Desktop runs nobody claimed within their window are recorded as **missed**, saying why ("no desktop
  was connected", "the connected desktop did not pick this up in time", "busy with another run", "no connected desktop has this workspace").
* **Starting a run** (run now, or the scheduler for an occurrence) happens in a transaction that first takes the Automation's row lock (a write that changes nothing),
  then checks for an existing run with the same idempotency key (the same occurrence made once, even with several server instances ticking) and for an active run
  (an overlapping one is recorded as `skipped`: "Skipped because another occurrence is already active"). Run now pressed eight times at once leaves one queued run.
* The scheduler loop (`Automations:SchedulerEnabled`, `PollIntervalMs` 15 s, `BatchSize`, `LeaseMs` 60 s, `RunnerClaimDeadlineMs` 15 min) starts due Automations and
  advances their schedule even when a check fails (the occurrence is recorded as skipped with the reason). A desktop occurrence's claim window never reaches the
  next occurrence and is never under a minute; a manual run's is 3 minutes.

### Runner credential and presence

The token is HMAC-signed with `Auth:Secret`, 12 hours, bound to the workspace, person, install and the server URL it was minted from, and holds no state; every request
re-checks that the person is still a member (so removing someone stops their desktop at once). A desktop counts as connected for 10 minutes after it registered or
asked for work. Registering the same install twice is one runner; one install in two workspaces is two. A session-only runner (`remote_session_only_v1`) is not
an Automation desktop.

### Telemetry

Ingest keeps `user.active`, `session.active`, `session.started`, `session.ended`, `task.started`, `task.completed`, `task.failed`; everything else (unknown, or the
server-only Workbot, connection and activation types) is dropped. Events are attributed to the sender. Per-session **dimensions** (project, model, ...) are one row per
workspace, source, session and type (an upsert that survives two batches racing); a missing `value` is derived (`slug-<10 hex>`, the reference's derivation).
Analytics compute members, pending invitations, active people, sessions and task counts for 7 and 30 days, a 12-week trend, a 30-day UTC daily trend (feature
`analyticsDailyTrends`), model usage and selection, optionally filtered by one dimension, and the adoption trend. All of it is computed from this database.

## Differences from the reference

* **Cloud Automations** are stored and answer as the reference does when the runner side is missing: `403 automation_cloud_disabled` unless the deployment has a
  headless runner configured (Policy `HeadlessRunnerConfigured`) and the organization allows it, then `409 automation_cloud_worker_required` unless an
  `ICloudAutomationRuntime` says an agent can run. Nothing executes a cloud run (no cloud sandboxes); with a runtime present a cloud run stays queued for it, without one
  the scheduler records it as skipped. Workflows (`saved_script` actions) answer `400 automation_saved_script_version_not_found` (workflows are not built).
* **No model catalog**: the reference checks models against its provider tables. Here: `openwork-cloud/default` is cloud-only, `opencode` (retired free model) is accepted
  from released desktops and refused for clients that send `x-openwork-automation-model-attention`, `openwork` and `lpr_...` providers are unavailable, anything else is a
  provider only the desktop has (desktop only). The reference's `openwork` model message is kept; its `lpr_` and cloud-default messages are identical.
* The digest of a revision is a SHA-256 prefix rather than the reference's FNV hash (it only decides "is this the same revision").
* An unknown run id that is not a valid TypeID is `404 automation_run_not_found`; the reference answers `500`.
* Validation reports the first problem only (the reference adds "(and N more)"); a body that matches neither creation shape says `Invalid input` without the union detail.
* Times are stored as epoch milliseconds (the wire format), not timestamps. Removing a person keeps their Automations (unreachable, and their desktop's credential stops
  working); deleting the workspace removes everything through foreign keys. Telemetry rows are not tied to members, so people who leave still count in the history.
* The runner's `GET /v1/automation-runner/work` always reports `enginePolicy: {upgrade: true}` (OpenCode v2 is the default engine here).
* Analytics are computed in memory from the last 12 weeks of events (the reference aggregates in SQL with index hints); fine for local data, a database aggregate is the way to
  scale it. `analyticsDailyTrends` was reported off by `GET /v1/org` until this area existed; it now follows its default (on).

## Not built

Cloud execution (cloud sandboxes, the headless runner and agent engines), workflows as Automation actions, Google Calendar triggers (calendar schedules are stored but
nothing reads a calendar), the runner notification stream `GET /v1/automation-runners/events` (desktops fall back to polling `work`), runner inventory
(`PUT /v1/automation-runner/inventory`), remote sessions (`/v1/session-runners/*`, `/v1/remote-session-*`), audit events for runs, model-attention feature usage marks,
the models analytics and Langfuse export, the admin Control Center rollups, `POST /v1/telemetry/ingest`'s Workbot/activation writers, and the den-web pages for workflow
runs and script runs.

## Checks

Mutation checks (one rule removed at a time, 19 tried, 18 caught by a failing test): claim ignores that the run is still queued, the claim window, or whose run it is;
heartbeat revives an expired lease or ignores the lease holder; complete ignores the attempt or an expired lease; a different result after the end is accepted; events skip
ahead or ignore the lease; a lost run is always re-queued; overlap not detected; an occurrence starts twice; cancel of a queued run waits; another person's Automation, list or
run is readable; a switched-off desktop can still claim. Two first survived (a stranger's claim and another desktop's heartbeat were refused only by the read-back, while the row
changed), which is why `Only_the_holder_can_touch_a_run_and_nobody_else_changes_its_state` asserts the row itself. The one survivor is equivalent: the recovery update's own
`LeaseExpiresAt < now` guard repeats the select's filter, and an expired lease cannot be revived by a heartbeat anyway, so no interleaving can reach it.

The race tests (eight desktops claiming, one desktop claiming six times at once, six simultaneous completes with mixed results, concurrent and repeated events, eight "run now"
calls, six schedulers ticking, a heartbeat racing recovery, racing telemetry batches) pass on SQLite and on MySQL (checked with a throwaway local migration, which is not
committed: the integrator regenerates the single migration).
