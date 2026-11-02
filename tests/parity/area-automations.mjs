// Contract tests for the Automations and telemetry area. Run unchanged against the reference Den and the rewrite:
//   node area-automations.mjs                                                    # reference: web :3005, api :8790
//   W=http://localhost:5280 A=http://localhost:5180 node area-automations.mjs    # rewrite
// Start the rewrite with a private database and run folder, see docs/AREA_GUIDE.md.
import { A, call, keys, suite, workspace, denied } from "./lib.mjs";

const s = suite("automations");
const ws = await workspace("Automations Probe");
const member = await ws.join("Member Person");
const admin = await ws.join("Admin Person", "admin");
const api = (u, method, path, body, extra) => ws.api(u, method, path, body, extra);
const DAY = 86_400_000;

const body = (over = {}) => ({
  name: "Daily report", instructions: "Summarize the inbox",
  schedule: { kind: "daily", timezone: "UTC", hour: 9, minute: 0 }, model: { providerId: "anthropic", modelId: "claude" }, ...over,
});
const create = (u = ws.owner, over = {}) => api(u, "POST", "/v1/automations", body(over));
const fail = (r, status, error, message) => r.status === status && r.json?.error === error && (message === undefined || r.json?.message === message) || `${r.status} ${r.text.slice(0, 300)}`;

// ---------------------------------------------------------------- create, read, validate
const made = await create();
const id = made.json?.automation?.id;
await s.t("create returns the Automation, its first revision and no run", () =>
  made.status === 201 && keys(made.json) === "automation,latestRun,revision" && made.json.latestRun === null && made.json.automation.state === "active"
  && made.json.revision.version === 1 && made.json.revision.executionTarget === "desktop" && made.json.revision.maximumRuntimeMs === 900000
  && made.json.revision.model.variant === null && made.json.revision.action.kind === "agent" && /^atm_/.test(id) && /^atv_/.test(made.json.revision.id) || JSON.stringify(made.json).slice(0, 300));
await s.t("an Automation lists the keys desktops read", () =>
  keys(made.json.automation) === "archivedAt,createdAt,currentRevisionId,id,latestRunAt,latestSuccessfulResult,latestSuccessfulRunId,name,needsAttentionReason,nextDueAt,organizationId,ownerMemberId,state,updatedAt"
  || keys(made.json.automation));
await s.t("a daily schedule is due at the next 09:00 UTC", () => {
  const next = made.json.automation.nextDueAt;
  const d = new Date(next);
  return (d.getUTCHours() === 9 && d.getUTCMinutes() === 0 && next > Date.now() && next <= Date.now() + DAY) || next;
});
await s.t("get and list return it; list is newest first with a null cursor", async () => {
  const g = await api(ws.owner, "GET", `/v1/automations/${id}`);
  const l = await api(ws.owner, "GET", "/v1/automations");
  return g.status === 200 && g.json.automation.id === id && l.status === 200 && l.json.items[0].automation.id === id && l.json.nextCursor === null || "get/list";
});
await s.t("an unknown Automation is 404 automation_not_found", async () =>
  fail(await api(ws.owner, "GET", "/v1/automations/atm_01m68tkp0qen2t1yr1r02g8dfw"), 404, "automation_not_found"));
await s.t("creating needs a name, a schedule and a model (400 invalid_request)", async () => {
  const bad = await api(ws.owner, "POST", "/v1/automations", { name: "" });
  return bad.status === 400 && bad.json.error === "invalid_request" || bad.status;
});
await s.t("an unknown timezone is refused with the field named", async () =>
  fail(await create(ws.owner, { schedule: { kind: "daily", timezone: "Nope/Zone", hour: 9, minute: 0 } }), 400, "invalid_request", "schedule.timezone: Expected a valid IANA timezone"));
await s.t("an hour of 24 is refused", async () => {
  const r = await create(ws.owner, { schedule: { kind: "daily", timezone: "UTC", hour: 24, minute: 0 } });
  return r.status === 400 && r.json.message === "schedule.hour: Too big: expected number to be <=23" || r.text.slice(0, 200);
});
await s.t("a weekly schedule keeps its days sorted and unique", async () => {
  const r = await create(ws.owner, { schedule: { kind: "weekly", timezone: "Europe/Paris", daysOfWeek: [3, 1, 3], hour: 7, minute: 30 } });
  return r.status === 201 && JSON.stringify(r.json.revision.schedule.daysOfWeek) === "[1,3]" && r.json.automation.nextDueAt > Date.now() || r.text.slice(0, 300);
});
await s.t("a one-off schedule in the past has no next run", async () => {
  const r = await create(ws.owner, { schedule: { kind: "once", timezone: "UTC", at: 1000 } });
  return r.status === 201 && r.json.automation.nextDueAt === null || r.text.slice(0, 200);
});
await s.t("a one-off schedule in the future is due at that moment", async () => {
  const at = Date.now() + 3 * DAY;
  const r = await create(ws.owner, { schedule: { kind: "once", timezone: "UTC", at } });
  return r.status === 201 && r.json.automation.nextDueAt === at || r.text.slice(0, 200);
});
await s.t("every-few-hours schedules are off by default (400 automation_interval_schedule_disabled)", async () =>
  fail(await create(ws.owner, { schedule: { kind: "interval", timezone: "UTC", everyHours: 3 } }), 400, "automation_interval_schedule_disabled"));
await s.t("a calendar trigger on a desktop Automation is refused", async () =>
  fail(await create(ws.owner, { schedule: { kind: "calendar", timezone: "UTC", edge: "start", offsetMinutes: 0 } }), 400, "automation_calendar_trigger_cloud_only"));
await s.t("the action shape only exists for the cloud", async () => {
  const r = await api(ws.owner, "POST", "/v1/automations", { name: "a", schedule: body().schedule, action: { kind: "agent", instructions: "x", model: { providerId: "a", modelId: "b" } }, executionTarget: "desktop" });
  return fail(r, 400, "invalid_request", "executionTarget: Action-based Automations are created by Web and run in OpenWork Cloud.");
});
await s.t("cloud Automations are not available without a headless runner (403 automation_cloud_disabled)", async () => {
  const r = await api(ws.owner, "POST", "/v1/cloud-automations", { name: "c", schedule: body().schedule, action: { kind: "agent", instructions: "x", model: { providerId: "openwork-cloud", modelId: "default" } } });
  return fail(r, 403, "automation_cloud_disabled");
});
await s.t("a model of a provider this build cannot reach is refused (409)", async () => {
  const a = await create(ws.owner, { model: { providerId: "lpr_01h2xcejqtf2nbrexx3vqjhp41", modelId: "x" } });
  const b = await create(ws.owner, { model: { providerId: "openwork-cloud", modelId: "default" } });
  return fail(a, 409, "provider_unavailable", "The selected model provider is no longer available.") === true
    && fail(b, 409, "model_access_lost", "The cloud default model runs only cloud Automations on the headless runtime.") === true || `${a.status} ${b.status}`;
});
await s.t("the retired free model is accepted from released desktops and refused for clients that handle model attention", async () => {
  const zen = { model: { providerId: "opencode", modelId: "big-pickle" } };
  const old = await create(ws.owner, zen);
  const modern = await api(ws.owner, "POST", "/v1/automations", body(zen), { headers: { "x-openwork-automation-model-attention": "model_attention_v1" } });
  return old.status === 201 && modern.status === 409 && modern.json.error === "model_access_lost" || `${old.status} ${modern.status}`;
});

// ---------------------------------------------------------------- change, activate, archive
await s.t("renaming keeps the revision; changing behavior makes version 2", async () => {
  const r1 = await api(ws.owner, "PATCH", `/v1/automations/${id}`, { name: "Renamed" });
  const r2 = await api(ws.owner, "PATCH", `/v1/automations/${id}`, { instructions: "New instructions", schedule: { kind: "daily", timezone: "UTC", hour: 10, minute: 0 } });
  return r1.status === 200 && r1.json.automation.name === "Renamed" && r1.json.revision.version === 1
    && r2.status === 200 && r2.json.revision.version === 2 && r2.json.revision.instructions === "New instructions" && r2.json.automation.currentRevisionId === r2.json.revision.id
    && new Date(r2.json.automation.nextDueAt).getUTCHours() === 10 || `${r1.text.slice(0, 100)} ${r2.text.slice(0, 200)}`;
});
await s.t("saving the same definition again makes no new revision", async () => {
  const r = await api(ws.owner, "PATCH", `/v1/automations/${id}`, { instructions: "New instructions" });
  return r.status === 200 && r.json.revision.version === 2 || r.text.slice(0, 200);
});
await s.t("an empty change, an unknown field and a bad schedule are 400", async () => {
  const a = await api(ws.owner, "PATCH", `/v1/automations/${id}`, {});
  const b = await api(ws.owner, "PATCH", `/v1/automations/${id}`, { nope: 1 });
  const c = await api(ws.owner, "PATCH", `/v1/automations/${id}`, { schedule: { kind: "daily", timezone: "UTC", hour: 99, minute: 0 } });
  return a.status === 400 && a.json.message === "At least one behavior-changing field is required" && b.status === 400 && c.status === 400 || `${a.status} ${b.status} ${c.status}`;
});
await s.t("deactivating clears the next run and activating restores it", async () => {
  const off = await api(ws.owner, "POST", `/v1/automations/${id}/deactivate`);
  const on = await api(ws.owner, "POST", `/v1/automations/${id}/activate`);
  return off.status === 200 && off.json.automation.state === "inactive" && off.json.automation.nextDueAt === null
    && on.json.automation.state === "active" && on.json.automation.nextDueAt > Date.now() || `${off.text.slice(0, 120)}`;
});

// ---------------------------------------------------------------- ownership
await s.t("a member sees only their own Automations; others' are 404", async () => {
  const empty = await api(member, "GET", "/v1/automations");
  const calls = [
    await api(member, "GET", `/v1/automations/${id}`), await api(member, "PATCH", `/v1/automations/${id}`, { name: "x" }),
    await api(member, "POST", `/v1/automations/${id}/activate`), await api(member, "POST", `/v1/automations/${id}/deactivate`),
    await api(member, "POST", `/v1/automations/${id}/run`, {}), await api(member, "DELETE", `/v1/automations/${id}`),
  ];
  return empty.status === 200 && empty.json.items.length === 0 && calls.every((r) => r.status === 404 && r.json.error === "automation_not_found") || calls.map((r) => r.status).join();
});
await s.t("an admin does not see someone else's Automations either", async () => {
  const l = await api(admin, "GET", "/v1/automations");
  const g = await api(admin, "GET", `/v1/automations/${id}`);
  return l.json.items.length === 0 && g.status === 404 || `${l.status} ${g.status}`;
});
await s.t("everyone can create their own", async () => {
  const mine = await create(member);
  const l = await api(member, "GET", "/v1/automations");
  return mine.status === 201 && l.json.items.length === 1 && l.json.items[0].automation.ownerMemberId === mine.json.automation.ownerMemberId || mine.status;
});
await s.t("signed-out requests are 401", async () => (await call(A, "/v1/automations", {})).status === 401);

// ---------------------------------------------------------------- runs
const run1 = await api(ws.owner, "POST", `/v1/automations/${id}/run`, {});
const runId = run1.json?.run?.id;
await s.t("run now queues a manual run (202) and an overlapping one is recorded as skipped", async () => {
  const second = await api(ws.owner, "POST", `/v1/automations/${id}/run`);
  return run1.status === 202 && run1.json.run.status === "queued" && run1.json.run.trigger === "manual" && run1.json.run.executionTarget === "desktop" && /^atr_/.test(runId) && run1.json.run.attemptCount === 0
    && second.status === 202 && second.json.run.status === "skipped" && second.json.run.resultSummary === "Skipped because another occurrence is already active." || `${run1.text.slice(0, 200)} ${second.text.slice(0, 200)}`;
});
await s.t("a bad run body is 400 and running another target that is off is refused", async () => {
  const bad = await api(ws.owner, "POST", `/v1/automations/${id}/run`, { executionTarget: "mars" });
  const cloud = await api(ws.owner, "POST", `/v1/automations/${id}/run`, { executionTarget: "cloud" });
  return bad.status === 400 && bad.json.error === "invalid_request" && cloud.status === 403 && cloud.json.error === "automation_cloud_disabled" || `${bad.status} ${cloud.status}`;
});
await s.t("the run history lists newest first and the receipt names the run, Automation and revision", async () => {
  const runs = await api(ws.owner, "GET", `/v1/automations/${id}/runs`);
  const receipt = await api(ws.owner, "GET", `/v1/automation-runs/${runId}`);
  return runs.status === 200 && runs.json.items.length === 2 && runs.json.items[0].status === "skipped" && runs.json.nextCursor === null
    && keys(receipt.json) === "automation,events,revision,run" && receipt.json.run.id === runId && receipt.json.events.length === 0 && receipt.json.automation.latestRunAt !== null || `${runs.status} ${receipt.status}`;
});
await s.t("the history pages with a cursor", async () => {
  const p1 = await api(ws.owner, "GET", `/v1/automations/${id}/runs?limit=1`);
  const p2 = await api(ws.owner, "GET", `/v1/automations/${id}/runs?limit=1&cursor=${p1.json.nextCursor}`);
  return p1.json.items.length === 1 && typeof p1.json.nextCursor === "string" && p2.json.items.length === 1 && p2.json.items[0].id !== p1.json.items[0].id || `${p1.text.slice(0, 100)}`;
});
await s.t("a limit outside 1-100 is 400", async () => (await api(ws.owner, "GET", "/v1/automations?limit=0")).status === 400 && (await api(ws.owner, "GET", "/v1/automations?limit=101")).status === 400);
await s.t("other people's runs are 404", async () => {
  const g = await api(member, "GET", `/v1/automation-runs/${runId}`);
  const c = await api(member, "POST", `/v1/automation-runs/${runId}/cancel`);
  return fail(g, 404, "automation_run_not_found") === true && fail(c, 404, "automation_run_not_found") === true || `${g.status} ${c.status}`;
});
await s.t("the calendar range lists runs in [from, to) and refuses more than 45 days or a backwards range", async () => {
  const ok = await api(ws.owner, "GET", `/v1/automation-runs?from=${Date.now() - DAY}&to=${Date.now() + DAY}`);
  const empty = await api(ws.owner, "GET", `/v1/automation-runs?from=0&to=1000`);
  const wide = await api(ws.owner, "GET", `/v1/automation-runs?from=0&to=${46 * DAY}`);
  const back = await api(ws.owner, "GET", `/v1/automation-runs?from=2000&to=1000`);
  const none = await api(ws.owner, "GET", `/v1/automation-runs`);
  return ok.status === 200 && ok.json.items.length === 2 && empty.json.items.length === 0 && wide.status === 400 && wide.json.message === "to: The range may cover at most 45 days"
    && back.status === 400 && back.json.message === "to: to must be after from" && none.status === 400 || `${ok.status} ${wide.text.slice(0, 120)} ${back.text.slice(0, 120)}`;
});
await s.t("cancelling a queued run ends it at once", async () => {
  const c = await api(ws.owner, "POST", `/v1/automation-runs/${runId}/cancel`);
  return c.status === 200 && c.json.run.status === "cancelled" && c.json.run.finishedAt > 0 || c.text.slice(0, 200);
});

// ---------------------------------------------------------------- runner protocol
const registration = (runnerId, extra = {}) => ({ runnerId, protocolVersion: 1, supportedExecutionTargets: ["desktop"], capabilities: ["model_attention_v1"], appVersion: "1.0.0", platform: "linux", concurrency: 1, ...extra });
const mint = async (u, runnerId) => (await api(u, "POST", "/v1/automation-runners/token", registration(runnerId))).json;
const R1 = (await mint(ws.owner, "runner-aaaaaaaa")).token;
const R2 = (await mint(ws.owner, "runner-bbbbbbbb")).token;
const runner = (token, method, path, b) => call(A, path, { method, bearer: token, body: b });
const MEMBER_RUNNER = (await mint(member, "runner-memberxx")).token;

await s.t("a runner credential is minted from a session, and the request is validated", async () => {
  const t = await api(ws.owner, "POST", "/v1/automation-runners/token", registration("runner-cccccccc"));
  const bad = await api(ws.owner, "POST", "/v1/automation-runners/token", registration("short"));
  const badPlatform = await api(ws.owner, "POST", "/v1/automation-runners/token", registration("runner-dddddddd", { platform: "amiga" }));
  return t.status === 200 && keys(t.json) === "eventsPath,expiresAt,token" && t.json.eventsPath === "/v1/automation-runners/events" && t.json.expiresAt > Date.now() + 11 * 3600_000
    && bad.status === 400 && badPlatform.status === 400 || `${t.status} ${bad.status} ${badPlatform.status}`;
});
await s.t("a registered desktop shows as connected and as an execution target; the cloud is not available", async () => {
  const p = await api(ws.owner, "GET", "/v1/automation-runners/presence");
  const t = await api(ws.owner, "GET", "/v1/automation-runners");
  const none = await api(admin, "GET", "/v1/automation-runners/presence");
  const desktops = t.json.items.filter((i) => i.kind === "desktop");
  const cloud = t.json.items.find((i) => i.kind === "cloud");
  return p.json.connected === true && p.json.lastSeenAt > Date.now() - 60_000 && desktops.length === 3 && desktops.every((d) => d.connected && d.platform === "linux" && /^rnr_/.test(d.id))
    && cloud.available === false && cloud.runtime === null && none.json.connected === false && none.json.lastSeenAt === null || JSON.stringify([p.json, t.json]).slice(0, 300);
});
await s.t("runner routes refuse requests without a valid runner credential", async () => {
  const a = await call(A, "/v1/automation-runner/work", {});
  const b = await runner("not.a.token", "GET", "/v1/automation-runner/work");
  const c = await runner(R1.slice(0, -3) + "xyz", "POST", `/v1/automation-runs/${runId}/claim`);
  const d = await api(ws.owner, "GET", "/v1/automation-runner/work");
  return [a, b, c].every((r) => r.status === 401 && r.json?.error === "runner_unauthorized") && d.status === 401 || `${a.status} ${b.status} ${c.status} ${d.status}`;
});

const work = await api(ws.owner, "POST", `/v1/automations/${id}/run`, {});
const workId = work.json.run.id;
await s.t("work discovery lists the owner's queued run with the engine policy; others see nothing", async () => {
  const w = await runner(R1, "GET", "/v1/automation-runner/work");
  const other = await runner(MEMBER_RUNNER, "GET", "/v1/automation-runner/work");
  return w.status === 200 && w.json.items.length === 1 && w.json.items[0].runId === workId && w.json.items[0].executionTarget === "desktop" && keys(w.json.items[0]) === "executionTarget,runId"
    && other.json.items.length === 0 || JSON.stringify(w.json).slice(0, 200);
});
await s.t("two desktops racing for one run: exactly one gets it", async () => {
  const results = await Promise.all([runner(R1, "POST", `/v1/automation-runs/${workId}/claim`), runner(R2, "POST", `/v1/automation-runs/${workId}/claim`)]);
  const winners = results.filter((r) => r.json?.assignment);
  return results.every((r) => r.status === 200) && winners.length === 1 && winners[0].json.assignment.runId === workId && winners[0].json.assignment.attempt === 1 || JSON.stringify(results.map((r) => r.json)).slice(0, 300);
});
const holder = (await runner(R1, "POST", `/v1/automation-runs/${workId}/claim`)).json.assignment ? R1 : R2;
const loser = holder === R1 ? R2 : R1;
await s.t("the assignment has what the desktop needs; the holder can claim again, another desktop and another person cannot", async () => {
  const again = await runner(holder, "POST", `/v1/automation-runs/${workId}/claim`);
  const lost = await runner(loser, "POST", `/v1/automation-runs/${workId}/claim`);
  const stranger = await runner(MEMBER_RUNNER, "POST", `/v1/automation-runs/${workId}/claim`);
  const a = again.json.assignment;
  return a && keys(a) === "attempt,automationId,automationName,executionTarget,instructions,leaseExpiresAt,model,runId,timeoutMs,workspaceId" && a.instructions === "New instructions" && a.timeoutMs === 900000
    && a.leaseExpiresAt > Date.now() && lost.json.assignment === null && stranger.json.assignment === null || JSON.stringify([again.json, lost.json, stranger.json]).slice(0, 300);
});
await s.t("a run that was claimed is no longer listed as work", async () => (await runner(R1, "GET", "/v1/automation-runner/work")).json.items.length === 0);
await s.t("unknown runs claim to null", async () => (await runner(R1, "POST", "/v1/automation-runs/atr_01m68tkp0qen2t1yr1r02g8dfw/claim")).json?.assignment === null);
await s.t("a heartbeat extends the lease; a wrong attempt or another desktop's heartbeat is a lost lease (409)", async () => {
  const ok = await runner(holder, "POST", `/v1/automation-runs/${workId}/heartbeat`, { attempt: 1 });
  const wrong = await runner(holder, "POST", `/v1/automation-runs/${workId}/heartbeat`, { attempt: 2 });
  const other = await runner(loser, "POST", `/v1/automation-runs/${workId}/heartbeat`, { attempt: 1 });
  const bad = await runner(holder, "POST", `/v1/automation-runs/${workId}/heartbeat`, {});
  return ok.status === 200 && keys(ok.json) === "attempt,cancelRequested,leaseExpiresAt,leaseValid" && ok.json.leaseValid === true && ok.json.cancelRequested === false && ok.json.leaseExpiresAt > Date.now()
    && wrong.status === 409 && wrong.json.error === "runner_lease_lost" && other.status === 409 && bad.status === 400 || `${ok.status} ${wrong.status} ${other.status} ${bad.status}`;
});
const event = (sequence, over = {}) => ({ attempt: 1, sequence, type: "assistant", payload: { text: `step ${sequence}` }, createdAt: 1, ...over });
await s.t("events append in order: a gap is refused, a repeat returns the same event, a bad type is 400", async () => {
  const gap = await runner(holder, "POST", `/v1/automation-runs/${workId}/events`, event(2));
  const one = await runner(holder, "POST", `/v1/automation-runs/${workId}/events`, event(1));
  const again = await runner(holder, "POST", `/v1/automation-runs/${workId}/events`, event(1));
  const two = await runner(holder, "POST", `/v1/automation-runs/${workId}/events`, event(2));
  const bad = await runner(holder, "POST", `/v1/automation-runs/${workId}/events`, event(3, { type: "nope" }));
  const other = await runner(loser, "POST", `/v1/automation-runs/${workId}/events`, event(3));
  return gap.status === 409 && gap.json.error === "automation_runner_event_sequence_gap" && one.status === 200 && one.json.event.sequence === 1 && one.json.event.attempt === 1 && /^ate_/.test(one.json.event.id)
    && again.status === 200 && again.json.event.id === one.json.event.id && two.json.event.sequence === 2 && bad.status === 400 && other.status === 409 && other.json.error === "runner_lease_lost"
    || JSON.stringify([gap.json, one.json, again.json, two.json]).slice(0, 400);
});
await s.t("the same step sent twice at once is recorded once", async () => {
  const both = await Promise.all([1, 2].map(() => runner(holder, "POST", `/v1/automation-runs/${workId}/events`, event(3))));
  const receipt = await api(ws.owner, "GET", `/v1/automation-runs/${workId}`);
  const ids = new Set(both.map((r) => r.json?.event?.id));
  return both.every((r) => r.status === 200) && ids.size === 1 && receipt.json.events.filter((e) => e.sequence === 3).length === 1 || JSON.stringify(both.map((r) => r.status));
});
await s.t("cancelling a running run asks the desktop to stop on its next heartbeat", async () => {
  const c = await api(ws.owner, "POST", `/v1/automation-runs/${workId}/cancel`);
  const beat = await runner(holder, "POST", `/v1/automation-runs/${workId}/heartbeat`, { attempt: 1 });
  return c.status === 200 && c.json.run.status === "running" && beat.json.cancelRequested === true || `${c.text.slice(0, 200)} ${beat.text.slice(0, 100)}`;
});
const result = (over = {}) => ({ attempt: 1, status: "succeeded", sessionId: "session-1", workspaceId: "ws-1", resultSummary: "Done", usage: { inputTokens: 10, outputTokens: 20, costMicros: null }, error: null, ...over });
await s.t("a malformed result is 400; another desktop cannot complete the run", async () => {
  const bad = await runner(holder, "POST", `/v1/automation-runs/${workId}/complete`, { attempt: 1 });
  const other = await runner(loser, "POST", `/v1/automation-runs/${workId}/complete`, result());
  const wrongAttempt = await runner(holder, "POST", `/v1/automation-runs/${workId}/complete`, result({ attempt: 2 }));
  return bad.status === 400 && other.status === 409 && other.json.error === "runner_lease_lost" && wrongAttempt.status === 409 || `${bad.status} ${other.status} ${wrongAttempt.status}`;
});
await s.t("completing is final and idempotent; a different result afterwards conflicts", async () => {
  const done = await runner(holder, "POST", `/v1/automation-runs/${workId}/complete`, result());
  const again = await runner(holder, "POST", `/v1/automation-runs/${workId}/complete`, result());
  const conflict = await runner(holder, "POST", `/v1/automation-runs/${workId}/complete`, result({ status: "failed", error: { code: "execution_failed", message: "no", retryable: false } }));
  const r = done.json?.run;
  return done.status === 200 && r.status === "succeeded" && r.resultSummary === "Done" && r.usage.inputTokens === 10 && r.leaseExpiresAt === null && r.finishedAt > 0 && r.executionThread.nativeThreadId === "session-1" && r.executionThread.workspaceId === "ws-1"
    && again.status === 200 && again.json.run.status === "succeeded" && again.json.run.finishedAt === r.finishedAt && conflict.status === 409 && conflict.json.error === "terminal_result_conflict" || JSON.stringify([done.json, conflict.json]).slice(0, 400);
});
await s.t("after the end, heartbeats and events find the lease gone", async () => {
  const beat = await runner(holder, "POST", `/v1/automation-runs/${workId}/heartbeat`, { attempt: 1 });
  const ev = await runner(holder, "POST", `/v1/automation-runs/${workId}/events`, event(4));
  return beat.status === 409 && ev.status === 409 && ev.json.error === "runner_lease_lost" || `${beat.status} ${ev.status}`;
});
await s.t("the receipt carries the events in order and the run's result", async () => {
  const receipt = await api(ws.owner, "GET", `/v1/automation-runs/${workId}`);
  const seq = receipt.json.events.map((e) => e.sequence).join();
  return receipt.json.run.status === "succeeded" && seq === "1,2,3" && receipt.json.events[0].payload.text === "step 1" && receipt.json.automation.latestRunAt >= receipt.json.run.createdAt || seq;
});
await s.t("a failed result with a model error pauses the Automation until it is activated", async () => {
  const q = await api(ws.owner, "POST", `/v1/automations/${id}/run`, {});
  const a = (await runner(holder, "POST", `/v1/automation-runs/${q.json.run.id}/claim`)).json.assignment;
  const done = await runner(holder, "POST", `/v1/automation-runs/${q.json.run.id}/complete`, result({ status: "failed", error: { code: "model_access_lost", message: "No such model", retryable: false } }));
  const after = await api(ws.owner, "GET", `/v1/automations/${id}`);
  return a && done.json.run.status === "failed" && after.json.automation.state === "needs_attention" && after.json.automation.needsAttentionReason.code === "model_access_lost" && after.json.automation.nextDueAt === null || JSON.stringify(after.json.automation).slice(0, 300);
});
await s.t("archiving ends the schedule and history stays readable", async () => {
  const arch = await api(ws.owner, "DELETE", `/v1/automations/${id}`);
  const patch = await api(ws.owner, "PATCH", `/v1/automations/${id}`, { name: "x" });
  const run = await api(ws.owner, "POST", `/v1/automations/${id}/run`, {});
  const runs = await api(ws.owner, "GET", `/v1/automations/${id}/runs`);
  return arch.status === 200 && arch.json.automation.state === "archived" && arch.json.automation.archivedAt > 0 && arch.json.automation.nextDueAt === null && patch.status === 404 && run.status === 404 && runs.json.items.length >= 3 || `${arch.status} ${patch.status} ${run.status}`;
});

// ---------------------------------------------------------------- telemetry
const iso = (msAgo) => new Date(Date.now() - msAgo).toISOString();
const ev = (type, msAgo, extra = {}) => ({ type, timestamp: iso(msAgo), source: "app", ...extra });
const tws = await workspace("Telemetry Probe");
const tmember = await tws.join("Telemetry Member");
await s.t("ingest accepts a batch (204), drops unknown and server-only types, and validates the batch", async () => {
  const ok = await tws.api(tws.owner, "POST", "/v1/telemetry/ingest", { events: [
    ev("session.started", 1000, { sessionId: "s1", dimensions: [{ type: "project", label: "Alpha Project" }, { type: "model", label: "Claude X", value: "claude-x" }, { type: "model_selection", label: "default", value: "default" }] }),
    ev("task.completed", 2000, { sessionId: "s1", durationMs: 1000, success: true }), ev("task.completed", 3000, { sessionId: "s1", durationMs: 2001 }), ev("task.failed", 3500, { sessionId: "s2" }),
    ev("user.active", 3 * DAY), ev("bogus.type", 10), ev("workbot.signed_in", 10), ev("task.completed", 20 * DAY, { sessionId: "s3", durationMs: 10, dimensions: [{ type: "project", label: "Beta" }] }),
  ] });
  const memberOk = await tws.api(tmember, "POST", "/v1/telemetry/ingest", { events: [ev("user.active", 100)] });
  const empty = await tws.api(tws.owner, "POST", "/v1/telemetry/ingest", { events: [] });
  const none = await tws.api(tws.owner, "POST", "/v1/telemetry/ingest", {});
  const badTime = await tws.api(tws.owner, "POST", "/v1/telemetry/ingest", { events: [{ type: "x", timestamp: "yesterday" }] });
  const badDim = await tws.api(tws.owner, "POST", "/v1/telemetry/ingest", { events: [{ type: "task.failed", timestamp: iso(0), dimensions: [{ type: "Bad Type!", label: "x" }] }] });
  const tooMany = await tws.api(tws.owner, "POST", "/v1/telemetry/ingest", { events: Array.from({ length: 51 }, () => ev("user.active", 1)) });
  return ok.status === 204 && memberOk.status === 204 && empty.status === 400 && empty.json.message === "events: Too small: expected array to have >=1 items"
    && none.status === 400 && none.json.message === "events: Invalid input: expected array, received undefined" && badTime.json.message === "events.0.timestamp: Invalid ISO datetime"
    && badDim.json.message.startsWith("events.0.dimensions.0.type: Dimension type must start with a lowercase letter") && tooMany.status === 400 || JSON.stringify([ok.status, memberOk.status, empty.status, none.status, badTime.json, badDim.json]).slice(0, 400);
});
await s.t("signed-out ingest is 401", async () => (await call(A, "/v1/telemetry/ingest", { method: "POST", body: { events: [ev("user.active", 1)] } })).status === 401);
await s.t("analytics and adoption need usage_analytics.view", async () => {
  const a = await tws.api(tmember, "GET", "/v1/telemetry/analytics");
  const b = await tws.api(tmember, "GET", "/v1/telemetry/adoption");
  const c = await tws.api(tmember, "GET", "/v1/telemetry/dimensions?type=project");
  return denied(a, "usage_analytics.view") && denied(b, "usage_analytics.view") && denied(c, "usage_analytics.view") || `${a.status} ${b.status} ${c.status}`;
});
let analytics;
await s.t("analytics counts members, sessions and tasks in 7 and 30 days with a 12-week trend", async () => {
  const r = await tws.api(tws.owner, "GET", "/v1/telemetry/analytics");
  analytics = r.json;
  const j = r.json;
  const lastWeek = j.weekly[11];
  return r.status === 200 && j.members === 2 && j.pendingInvites === 0 && j.activeMembers7d === 2 && j.activeMembers30d === 2 && j.sessions7d === 2 && j.sessions30d === 3
    && j.tasksCompleted7d === 2 && j.tasksFailed7d === 1 && j.tasksCompleted30d === 3 && j.tasksFailed30d === 1 && j.avgTaskDurationMs30d === 1004
    && j.weekly.length === 12 && /^\d{4}-\d\d-\d\d$/.test(j.weekly[0].weekStart) && keys(j.weekly[0]) === "activeMembers,sessions,tasksCompleted,tasksFailed,weekStart"
    && lastWeek.activeMembers === 2 && lastWeek.tasksCompleted === 2 && lastWeek.tasksFailed === 1 && lastWeek.sessions === 2 || JSON.stringify(j).slice(0, 500);
});
await s.t("the daily trend covers 30 UTC days ending today", async () => {
  const d = analytics.daily;
  return Array.isArray(d) && d.length === 30 && d[29].day === new Date().toISOString().slice(0, 10) && d[29].tasksCompleted === 2 && d[29].tasksFailed === 1 || JSON.stringify(d?.slice(-2));
});
await s.t("model usage and selection come from session dimensions", async () => {
  const m = analytics.models;
  return m.usage30d.length === 1 && m.usage30d[0].id === "claude-x" && m.usage30d[0].label === "Claude X" && m.usage30d[0].sessions === 1 && m.selection30d.default === 1 && m.selection30d.manual === 0 || JSON.stringify(m);
});
await s.t("dimensions list values with their label, session count and last seen, newest first", async () => {
  const r = await tws.api(tws.owner, "GET", "/v1/telemetry/dimensions?type=project");
  const bad = await tws.api(tws.owner, "GET", "/v1/telemetry/dimensions");
  const items = r.json.items;
  return r.status === 200 && items.length === 2 && items[0].label === "Alpha Project" && /^alpha-project-[0-9a-f]{10}$/.test(items[0].value) && items[0].sessionCount === 1 && items[1].label === "Beta"
    && keys(items[0]) === "label,lastSeenAt,sessionCount,type,value" && !Number.isNaN(Date.parse(items[0].lastSeenAt)) && bad.status === 400 || JSON.stringify(r.json).slice(0, 300);
});
await s.t("analytics filtered by a dimension counts only its sessions; half a filter is 400", async () => {
  const items = (await tws.api(tws.owner, "GET", "/v1/telemetry/dimensions?type=project")).json.items;
  const alpha = await tws.api(tws.owner, "GET", `/v1/telemetry/analytics?dimensionType=project&dimensionValue=${items[0].value}`);
  const half = await tws.api(tws.owner, "GET", "/v1/telemetry/analytics?dimensionType=project");
  const j = alpha.json;
  return alpha.status === 200 && j.sessions30d === 1 && j.tasksCompleted30d === 2 && j.tasksFailed30d === 0 && j.activeMembers30d === 1 && half.status === 400
    && half.json.message === "dimensionType and dimensionValue must be supplied together." || JSON.stringify(j).slice(0, 300);
});
await s.t("adoption reports people, invitations, active people and a weekly trend", async () => {
  const r = await tws.api(tws.owner, "GET", "/v1/telemetry/adoption");
  return r.status === 200 && keys(r.json) === "activeMembers30d,activeMembers7d,members,pendingInvites,weeklyTrend" && r.json.members === 2 && r.json.activeMembers7d === 2 && r.json.weeklyTrend.length === 12 && r.json.weeklyTrend[11] === 2 && r.json.weeklyTrend[9] === 1 || JSON.stringify(r.json);
});
await s.t("telemetry of one workspace never shows in another", async () => {
  const other = await workspace("Other Telemetry");
  const r = await other.api(other.owner, "GET", "/v1/telemetry/analytics");
  return r.status === 200 && r.json.sessions30d === 0 && r.json.activeMembers30d === 0 && r.json.models.usage30d.length === 0 || JSON.stringify(r.json).slice(0, 200);
});

s.done();
