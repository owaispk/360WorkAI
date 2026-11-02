// Contract tests for the "workspace" area: Workflows and their run receipts, generated views and apps, the Apps catalog, the removed Memory
// Bank's answers, webhook ingress and direct uploads. One script, one section per part:
//   1 memory       /v1/memory*
//   2 workflows    /v1/workflows*, /v1/workflow-runs, the legacy aliases, how the library shows a Workflow
//   3 save         POST /v1/workflows (saving a successful run) and what it refuses
//   4 views-apps   /v1/apps*, /v1/artifact-views/*, /v1/workflows/{id}/views (the reference ships them off)
//   5 mcp-apps     GET /v1/mcp-apps
//   6 webhooks     /v1/webhooks/connectors/github and /v1/webhooks/stripe (no secrets configured), /v1/direct-uploads/*
// Runs unchanged against the reference Den and the rewrite:
//   node area-workspace.mjs                                                  # reference: web :3005, api :8790
//   W=http://localhost:5291 A=http://localhost:5191 node area-workspace.mjs  # rewrite
//   ONLY=1,2 node area-workspace.mjs                                         # only some sections
// The servers must run with their defaults: generated views off, no webhook secrets. (The rewrite's tests cover those switched on.)
import { call, A, workspace, suite, denied, keys } from "./lib.mjs";

const s = suite("workspace");
const t = (name, fn) => s.t(name, fn);
const only = (process.env.ONLY ?? "1,2,3,4,5,6").split(",");
const want = (n) => only.includes(String(n));
const ok = (r, status, extra) => (r.status === status && (extra ? extra(r.json) : true)) || `${r.status} ${r.text.slice(0, 300)}`;
const NOPE = (p) => `${p}_01m6797hhce34acegcde4y57bd`;
const DIGEST = /^sha256:[0-9a-f]{64}$/;

// =====================================================================================================================================
// 1. memory
// =====================================================================================================================================
if (want(1)) {
  const ws = await workspace("Workspace Memory");
  const api = ws.api;
  await t("[1] GET /v1/memory is an empty list for a signed-in person", async () => ok(await api(ws.owner, "GET", "/v1/memory"), 200, (j) => keys(j) === "memories" && j.memories.length === 0));
  await t("[1] GET /v1/memory/search is an empty result set", async () => ok(await api(ws.owner, "GET", "/v1/memory/search?q=anything"), 200, (j) => keys(j) === "results" && j.results.length === 0));
  await t("[1] DELETE /v1/memory/{id} is 404 memory_not_found for every id (already gone)", async () => ok(await api(ws.owner, "DELETE", "/v1/memory/mem_1"), 404, (j) => keys(j) === "error" && j.error === "memory_not_found"));
  await t("[1] POST /v1/memory is 410 deprecated, even without signing in", async () =>
    ok(await call(A, "/v1/memory", { method: "POST", body: { text: "remember this" } }), 410, (j) => j.error === "deprecated" && /Memory Bank feature has been removed/.test(j.message) && keys(j) === "error,message"));
  await t("[1] reading needs a session: 401 unauthorized", async () => ok(await call(A, "/v1/memory"), 401, (j) => j.error === "unauthorized"));
  await t("[1] searching and deleting need a session too", async () => (await call(A, "/v1/memory/search")).status === 401 && (await call(A, "/v1/memory/x", { method: "DELETE" })).status === 401);
}

// =====================================================================================================================================
// 2. workflows
// =====================================================================================================================================
const CODE = "const n = input.n ?? 1;\nif (n > 5) { return { big: true } }\nreturn { doubled: n * 2, name: 'x' }";
const IN_SCHEMA = { type: "object", properties: { n: { type: "number" } } };
const OUT_SCHEMA = { type: "object" };

/** A plugin holding one Workflow (made through the library's own routes, as an import would), shared with nobody. */
async function seedWorkflow(ws, who, { name = "Doubler", description = "Doubles", code = CODE, payload } = {}) {
  const plugin = await ws.api(who, "POST", "/v1/plugins", { name: `${name} plugin` });
  if (plugin.status !== 201) throw new Error(`plugin: ${plugin.status} ${plugin.text.slice(0, 200)}`);
  const pluginId = plugin.json.item.id;
  const body = payload ?? { language: "codemode-js", inputSchema: IN_SCHEMA, outputSchema: OUT_SCHEMA, exampleInput: { n: 2 }, requiredCapabilities: [] };
  const made = await ws.api(who, "POST", "/v1/config-objects", { type: "workflow", sourceMode: "cloud", pluginIds: [pluginId], input: { rawSourceText: code, normalizedPayloadJson: body, schemaVersion: "codemode-script-v1", metadata: { name, description } } });
  if (made.status !== 201) throw new Error(`workflow object: ${made.status} ${made.text.slice(0, 200)}`);
  return { pluginId, id: made.json.item.id, versionId: made.json.item.latestVersion.id, made };
}

if (want(2)) {
  const ws = await workspace("Workspace Workflows");
  const bob = await ws.join("Bob Member");
  const other = await workspace("Workspace Workflows Other");
  const api = ws.api;
  const wf = await seedWorkflow(ws, ws.owner);
  const draft = (extra = {}) => ({ configObjectId: wf.id, name: "Doubler", description: "Doubles", code: CODE, exampleInput: { n: 3 }, inputSchema: IN_SCHEMA, outputSchema: OUT_SCHEMA, requiredCapabilities: [], ...extra });
  const VERSION_KEYS = "automationReferences,code,codeDigest,createdAt,exampleInput,graph,id,inputSchema,inputSchemaDigest,outputSchema,outputSchemaDigest,requiredCapabilities";

  // ---- the library shows a Workflow without its source ----
  await t("[2] the library's create answer hides the Workflow's source and example input", async () =>
    ok(wf.made, 201, (j) => j.item.objectType === "workflow" && j.item.latestVersion.rawSourceText === null && j.item.latestVersion.schemaVersion === "codemode-script-v1"
      && j.item.latestVersion.normalizedPayloadJson.exampleInput === undefined && j.item.latestVersion.normalizedPayloadJson.language === "codemode-js"));
  await t("[2] reading it back through the generic config-object route hides them too", async () => {
    const r = await api(ws.owner, "GET", `/v1/config-objects/${wf.id}`);
    return ok(r, 200, (j) => j.item.latestVersion.rawSourceText === null && j.item.latestVersion.normalizedPayloadJson.exampleInput === undefined);
  });

  // ---- reading ----
  await t("[2] GET /v1/workflows lists the Workflows the person was shared (the owner's own, once it is in its plugin)", async () => {
    const r = await api(ws.owner, "GET", "/v1/workflows");
    // Nothing is shared with anyone else: a Workflow reaches an agent only through a grant on it, its plugin or a marketplace.
    return ok(r, 200, (j) => keys(j) === "items" && Array.isArray(j.items));
  });
  await t("[2] a Workflow in a plugin the maker manages is listed with its latest version, schemas and capabilities", async () => {
    const r = await api(ws.owner, "GET", "/v1/workflows");
    const item = r.json.items.find((i) => i.configObjectId === wf.id);
    return (item && keys(item) === "configObjectId,configObjectVersionId,description,inputSchema,outputSchema,pluginId,requiredCapabilities,title" && item.configObjectVersionId === wf.versionId && item.title === "Doubler"
      && item.pluginId === wf.pluginId && item.requiredCapabilities.length === 0) || JSON.stringify(r.json).slice(0, 300);
  });
  await t("[2] GET /v1/workflows/{id} is the library card, the script detail and the views", async () => {
    const r = await api(ws.owner, "GET", `/v1/workflows/${wf.id}`);
    return ok(r, 200, (j) => keys(j) === "script,views,workflow"
      && keys(j.workflow) === "activeViewTitle,automationCount,description,edges,id,latestSuccessfulAt,name,plugin,resultState,role,source,state,type,viewState"
      && j.workflow.type === "workflow" && j.workflow.role === "manager" && j.workflow.resultState === "never_run" && j.workflow.viewState === "default" && j.workflow.state === "ready"
      && j.workflow.plugin.id === wf.pluginId && j.workflow.source.kind === "created" && j.workflow.edges.some((e) => e.kind === "mine")
      && keys(j.script) === "canManage,canRun,configObjectId,currentVersion,description,freshness,latestSnapshot,latestSuccessfulSnapshot,pluginId,title,versions"
      && j.script.canRun === true && j.script.canManage === true && j.script.freshness.state === "never_run" && Array.isArray(j.views) && j.views.length === 0);
  });
  await t("[2] a version carries its code, call graph, schemas, digests and automation references", async () => {
    const r = await api(ws.owner, "GET", `/v1/workflows/${wf.id}/versions`);
    return ok(r, 200, (j) => keys(j) === "items" && j.items.length === 1 && keys(j.items[0]) === VERSION_KEYS && j.items[0].code === CODE && DIGEST.test(j.items[0].codeDigest) && DIGEST.test(j.items[0].inputSchemaDigest)
      && DIGEST.test(j.items[0].outputSchemaDigest) && j.items[0].exampleInput.n === 2 && j.items[0].automationReferences.length === 0 && j.items[0].id === wf.versionId);
  });
  await t("[2] the call graph is derived from the source: input, a branch with yes/no, two returns", async () => {
    const g = (await api(ws.owner, "GET", `/v1/workflows/${wf.id}/versions`)).json.items[0].graph;
    return (g.parseError === null && g.nodes.map((n) => `${n.id}:${n.kind}:${n.label}`).join("|") === "input:input:Input|branch1:branch:n > 5|return1:return:{ big }|return2:return:{ doubled, name }"
      && g.edges.map((e) => `${e.from}>${e.to}:${e.label}:${e.kind}`).join("|") === "input>branch1:null:flow|branch1>return1:yes:flow|branch1>return2:no:flow") || JSON.stringify(g).slice(0, 400);
  });
  await t("[2] maxAgeMs outside 60 seconds to 30 days is a 400 invalid_request naming the field", async () => {
    const r = await api(ws.owner, "GET", `/v1/workflows/${wf.id}?maxAgeMs=5`);
    return ok(r, 400, (j) => j.error === "invalid_request" && j.message === "maxAgeMs: Too small: expected number to be >=60000");
  });
  await t("[2] a TypeID that is not one: 400 workflow_rejected with the id library's words", async () => {
    const r = await api(ws.owner, "GET", "/v1/workflows/abc");
    return ok(r, 400, (j) => j.error === "workflow_rejected" && j.message === "Invalid length. Suffix should have 26 characters, got 3");
  });
  await t("[2] a well-formed id that is no Workflow: 404 workflow_not_found", async () =>
    ok(await api(ws.owner, "GET", `/v1/workflows/${NOPE("cob")}`), 404, (j) => j.error === "workflow_not_found" && j.message === "workflow_not_found"));
  await t("[2] another workspace's Workflow is not found either, never forbidden", async () =>
    ok(await other.api(other.owner, "GET", `/v1/workflows/${wf.id}`), 404, (j) => j.error === "workflow_not_found"));
  await t("[2] a member with no grant is refused: 403 forbidden 'Missing viewer access for config object.'", async () =>
    ok(await api(bob, "GET", `/v1/workflows/${wf.id}`), 403, (j) => j.error === "forbidden" && j.message === "Missing viewer access for config object."));

  // ---- testing a draft ----
  await t("[2] testing with nothing in the body names every missing field (zod issues, first one in the message)", async () =>
    ok(await api(ws.owner, "POST", "/v1/workflows/test", {}), 400, (j) => j.error === "invalid_request" && j.message === "name: Invalid input: expected string, received undefined (and 3 more)"
      && j.details.map((d) => d.path.join(".")).join(",") === "name,code,requiredCapabilities,configObjectId"));
  let tested;
  await t("[2] a draft test runs the code and answers a receipt, the value, its Markdown table and the digests", async () => {
    const r = await api(ws.owner, "POST", "/v1/workflows/test", draft()); tested = r.json;
    return ok(r, 200, (j) => keys(j) === "codeDigest,finishedAt,inputSchemaDigest,markdown,outputSchemaDigest,receiptId,rendererVersion,requiredCapabilities,resultDigest,value"
      && /^wfr_[0-9a-z]{26}$/.test(j.receiptId) && j.value.doubled === 6 && j.value.name === "x" && j.markdown === "| Key | Value |\n| --- | --- |\n| doubled | 6 |\n| name | x |"
      && j.rendererVersion === "codemode-markdown-v1" && j.codeDigest === (JSON.stringify(j.codeDigest) && j.codeDigest) && DIGEST.test(j.resultDigest) && DIGEST.test(j.codeDigest));
  });
  await t("[2] the result digest is that of the canonical JSON (keys sorted), the same on every server", async () =>
    tested.resultDigest === "sha256:b7a143f8f3a5e50542226ca8b765b6f48f492e53d29a759fde21437130049463" || tested.resultDigest);
  await t("[2] an input that breaks the inputSchema: 400 invalid_arguments, with the fixed message", async () =>
    ok(await api(ws.owner, "POST", "/v1/workflows/test", draft({ exampleInput: { n: "x" } })), 400, (j) => j.error === "invalid_arguments" && j.message === "The arguments do not match the Workflow's inputSchema."));
  await t("[2] a script that throws: 400 script_failed 'Uncaught: boom'", async () =>
    ok(await api(ws.owner, "POST", "/v1/workflows/test", draft({ code: "throw new Error('boom')" })), 400, (j) => j.error === "script_failed" && j.message === "Uncaught: boom"));
  await t("[2] a result that breaks the outputSchema: 400 invalid_result", async () =>
    ok(await api(ws.owner, "POST", "/v1/workflows/test", draft({ code: "return 5" })), 400, (j) => j.error === "invalid_result" && j.message === "The Workflow result does not match its outputSchema."));
  await t("[2] a capability the person is not offered: 400 capability_unavailable naming it", async () =>
    ok(await api(ws.owner, "POST", "/v1/workflows/test", draft({ requiredCapabilities: [{ capabilityName: "mcp:x:y", scriptPath: "tools.x.y" }] })), 400,
      (j) => j.error === "capability_unavailable" && j.message === "Required capability tools.x.y (mcp:x:y) is unavailable or disabled for this organization."));
  await t("[2] results are plain data: undefined becomes null, dates and arrays survive, console and Promise.all work", async () => {
    const r = await api(ws.owner, "POST", "/v1/workflows/test", draft({ outputSchema: undefined, code: "console.log('hi'); const r = await Promise.all([1, 2].map(async (x) => x * 3)); return { a: [1, 2, { b: undefined }], d: new Date(0).toISOString(), m: Math.max(1, 2), r }" }));
    return ok(r, 200, (j) => JSON.stringify(j.value) === '{"a":[1,2,{"b":null}],"d":"1970-01-01T00:00:00.000Z","m":2,"r":[3,6]}' && j.outputSchemaDigest === null && j.markdown.startsWith("```json\n{"));
  });
  await t("[2] a script with no return gives null, rendered as fenced JSON", async () => {
    const r = await api(ws.owner, "POST", "/v1/workflows/test", draft({ outputSchema: undefined, code: "const x = 1" }));
    return ok(r, 200, (j) => j.value === null && j.markdown === "```json\nnull\n```");
  });
  await t("[2] testing needs manager access: the Workflow's viewer gets 403 'Missing manager access'", async () => {
    await api(ws.owner, "POST", `/v1/plugins/${wf.pluginId}/access`, { orgMembershipId: bob.memberId, role: "viewer" });
    return ok(await api(bob, "POST", "/v1/workflows/test", draft()), 403, (j) => j.error === "forbidden" && j.message === "Missing manager access for config object.");
  });

  // ---- a new version needs the receipt of the exact test ----
  await t("[2] a version without a matching receipt: 400 workflow_matching_test_receipt_required", async () =>
    ok(await api(ws.owner, "POST", `/v1/workflows/${wf.id}/versions`, { ...draft(), configObjectId: undefined, receiptId: NOPE("wfr") }), 400, (j) => j.error === "workflow_matching_test_receipt_required"));
  await t("[2] a draft changed after the test no longer matches its receipt", async () =>
    ok(await api(ws.owner, "POST", `/v1/workflows/${wf.id}/versions`, { ...draft({ name: "Doubler 2" }), configObjectId: undefined, receiptId: tested.receiptId }), 400, (j) => j.error === "workflow_matching_test_receipt_required"));
  let created;
  await t("[2] the unchanged draft and its receipt make a new immutable version (201, the whole detail)", async () => {
    const r = await api(ws.owner, "POST", `/v1/workflows/${wf.id}/versions`, { ...draft(), configObjectId: undefined, receiptId: tested.receiptId }); created = r.json;
    return ok(r, 201, (j) => keys(j) === "canManage,canRun,configObjectId,currentVersion,description,freshness,latestSnapshot,latestSuccessfulSnapshot,pluginId,title,versions"
      && j.versions.length === 2 && j.currentVersion.id !== wf.versionId && j.currentVersion.exampleInput.n === 3 && j.versions[1].id === wf.versionId);
  });
  await t("[2] a receipt makes one version only: 400 workflow_rejected 'workflow_test_receipt_already_used'", async () =>
    ok(await api(ws.owner, "POST", `/v1/workflows/${wf.id}/versions`, { ...draft(), configObjectId: undefined, receiptId: tested.receiptId }), 400, (j) => j.error === "workflow_rejected" && j.message === "workflow_test_receipt_already_used"));

  // ---- running an exact version ----
  const runBody = (extra = {}) => ({ pluginId: wf.pluginId, configObjectVersionId: created.currentVersion.id, ...extra });
  await t("[2] POST /run executes the version and answers the value, its Markdown, a receipt and the digests", async () => {
    const r = await api(ws.owner, "POST", `/v1/workflows/${wf.id}/run`, runBody({ input: { n: 4 } }));
    return ok(r, 200, (j) => keys(j) === "executionType,fetchedAt,inputSchemaDigest,markdown,mode,outputSchemaDigest,receiptId,rendererVersion,resultDigest,status,value"
      && j.status === "succeeded" && j.executionType === "saved-workflow" && j.mode === "adhoc" && j.value.doubled === 8 && /^wfr_/.test(j.receiptId) && j.timeZone === undefined);
  });
  await t("[2] input that breaks the schema: 400 invalid_capability_arguments", async () =>
    ok(await api(ws.owner, "POST", `/v1/workflows/${wf.id}/run`, runBody({ input: { n: "z" } })), 400, (j) => j.error === "invalid_capability_arguments" && j.message === "The arguments do not match the Workflow's inputSchema."));
  await t("[2] a live run generates input.runtime and says which time zone it used", async () => {
    const r = await api(ws.owner, "POST", `/v1/workflows/${wf.id}/run`, runBody({ mode: "live", timeZone: "UTC" }));
    return ok(r, 200, (j) => j.mode === "live" && j.timeZone === "UTC" && j.value.doubled === 2);
  });
  await t("[2] a live run takes no caller input: 400 invalid_request on input", async () =>
    ok(await api(ws.owner, "POST", `/v1/workflows/${wf.id}/run`, runBody({ mode: "live", input: {} })), 400, (j) => j.error === "invalid_request" && j.message === "input: Live runs generate input.runtime; omit caller input."));
  await t("[2] a time zone is for live runs only", async () =>
    ok(await api(ws.owner, "POST", `/v1/workflows/${wf.id}/run`, runBody({ timeZone: "UTC" })), 400, (j) => j.message === "timeZone: timeZone is only supported in live mode."));
  await t("[2] a version that does not exist: 400 script_not_executable, worded for a plugin that has not synced", async () =>
    ok(await api(ws.owner, "POST", `/v1/workflows/${wf.id}/run`, runBody({ configObjectVersionId: NOPE("cov") })), 400,
      (j) => j.error === "script_not_executable" && j.message === `Marketplace plugin "Doubler plugin" has not synced content for "Doubler" yet. Connect or sync the source, then try again.`));
  await t("[2] a plugin that does not exist or ids that are not ids: 400 unknown_capability", async () => {
    const a = await api(ws.owner, "POST", `/v1/workflows/${wf.id}/run`, runBody({ pluginId: NOPE("plg") }));
    const b = await api(ws.owner, "POST", `/v1/workflows/${wf.id}/run`, { pluginId: "x", configObjectVersionId: "y" });
    return (a.status === 400 && a.json.error === "unknown_capability" && a.json.message === "No such capability." && b.status === 400 && b.json.error === "unknown_capability") || `${a.text} ${b.text}`;
  });
  await t("[2] running needs the Workflow shared with you: a person it was not shared with gets 400 forbidden", async () => {
    const carol = await ws.join("Carol Member");
    const r = await api(carol, "POST", `/v1/workflows/${wf.id}/run`, runBody());
    return ok(r, 400, (j) => j.error === "forbidden" && j.message === "You have not been granted access to this plugin capability.");
  });

  // ---- receipts ----
  await t("[2] snapshots lists the receipts of saved versions, newest first, with a cursor for the next page", async () => {
    const r = await api(ws.owner, "GET", `/v1/workflows/${wf.id}/snapshots?limit=1`);
    return ok(r, 200, (j) => keys(j) === "items,nextCursor" && j.items.length === 1 && typeof j.nextCursor === "string"
      && keys(j.items[0]) === "automationRunId,codeDigest,configObjectId,configObjectVersionId,contentDeletedAt,errorKind,errorMessage,finishedAt,inputSchemaDigest,markdown,outputSchemaDigest,pluginId,receiptId,rendererVersion,resultDigest,source,startedAt,status,toolCalls,value");
  });
  await t("[2] the next page, and a cursor that is not one: 400 'cursor: Invalid cursor.'", async () => {
    const first = await api(ws.owner, "GET", `/v1/workflows/${wf.id}/snapshots?limit=1`);
    const next = await api(ws.owner, "GET", `/v1/workflows/${wf.id}/snapshots?limit=2&cursor=${first.json.nextCursor}`);
    const bad = await api(ws.owner, "GET", `/v1/workflows/${wf.id}/snapshots?cursor=%%%`);
    const worse = await api(ws.owner, "GET", `/v1/workflows/${wf.id}/snapshots?cursor=bm90anNvbg`);
    return (next.status === 200 && next.json.items.length >= 1 && next.json.items[0].receiptId !== first.json.items[0].receiptId && worse.status === 400 && worse.json.message === "cursor: Invalid cursor.") || `${next.text.slice(0, 200)} ${bad.status} ${worse.text.slice(0, 200)}`;
  });
  await t("[2] a failed run is a receipt too (status failed, the error kind and message, no value)", async () => {
    const all = (await api(ws.owner, "GET", `/v1/workflows/${wf.id}/snapshots`)).json.items;
    const failed = all.find((i) => i.status === "failed");
    return (failed && failed.errorKind === "InvalidArguments" && failed.errorMessage === "The arguments do not match the Workflow's inputSchema." && failed.value === null && failed.markdown === null && failed.rendererVersion === null) || JSON.stringify(failed);
  });
  let snap;
  await t("[2] one snapshot: the value, Markdown, tool calls and digests; a live receipt says it was manual", async () => {
    const all = (await api(ws.owner, "GET", `/v1/workflows/${wf.id}/snapshots`)).json.items;
    snap = all.find((i) => i.status === "succeeded");
    const r = await api(ws.owner, "GET", `/v1/workflows/${wf.id}/snapshots/${snap.receiptId}`);
    return ok(r, 200, (j) => j.receiptId === snap.receiptId && j.source === "manual" && j.toolCalls.length === 0 && j.contentDeletedAt === null && j.value !== null);
  });
  await t("[2] a receipt that is not there: 404 workflow_snapshot_not_found; one that is not an id: 400 workflow_rejected", async () => {
    const a = await api(ws.owner, "GET", `/v1/workflows/${wf.id}/snapshots/${NOPE("wfr")}`);
    const b = await api(ws.owner, "GET", `/v1/workflows/${wf.id}/snapshots/zzz`);
    return (a.status === 404 && a.json.error === "workflow_snapshot_not_found" && b.status === 400 && b.json.error === "workflow_rejected") || `${a.text} ${b.text}`;
  });
  await t("[2] erasing a snapshot's content keeps the receipt (digests, status, timings) and stamps contentDeletedAt; doing it twice changes nothing", async () => {
    const a = await api(ws.owner, "DELETE", `/v1/workflows/${wf.id}/snapshots/${snap.receiptId}/content`);
    const b = await api(ws.owner, "DELETE", `/v1/workflows/${wf.id}/snapshots/${snap.receiptId}/content`);
    return (a.status === 200 && a.json.value === null && a.json.markdown === null && typeof a.json.contentDeletedAt === "string" && a.json.resultDigest === snap.resultDigest && b.status === 200
      && b.json.contentDeletedAt === a.json.contentDeletedAt) || `${a.text.slice(0, 200)} ${b.text.slice(0, 200)}`;
  });
  await t("[2] only managers erase content: the Workflow's viewer gets 403", async () =>
    ok(await api(bob, "DELETE", `/v1/workflows/${wf.id}/snapshots/${snap.receiptId}/content`), 403, (j) => j.error === "forbidden"));
  await t("[2] the Workflow's freshness follows its receipts (a failed latest run needs attention)", async () => {
    const r = await api(ws.owner, "GET", `/v1/workflows/${wf.id}`);
    return ok(r, 200, (j) => ["fresh", "needs_attention", "stale"].includes(j.script.freshness.state) && j.script.latestSnapshot !== null);
  });
  await t("[2] a viewer reads the Workflow with its source, example input and graph labels redacted, and cannot manage", async () => {
    const r = await api(bob, "GET", `/v1/workflows/${wf.id}`);
    const v = r.json?.script?.currentVersion;
    return (r.status === 200 && r.json.script.canManage === false && r.json.script.canRun === true && v.code === null && v.exampleInput === null
      && v.graph.nodes.filter((n) => n.kind === "branch").every((n) => n.label === "Condition") && v.graph.nodes.filter((n) => n.kind === "return").every((n) => n.label === "Result")
      && v.inputSchema !== null && DIGEST.test(v.codeDigest)) || `${r.status} ${r.text.slice(0, 300)}`;
  });
  await t("[2] a viewer's version list is redacted the same way", async () => {
    const r = await api(bob, "GET", `/v1/workflows/${wf.id}/versions`);
    return ok(r, 200, (j) => j.items.every((v) => v.code === null && v.exampleInput === null));
  });

  // ---- run receipts of the person ----
  await t("[2] GET /v1/workflow-runs lists the person's own receipts newest first, with the Workflow's title and graph", async () => {
    const r = await api(ws.owner, "GET", "/v1/workflow-runs?limit=3");
    return ok(r, 200, (j) => keys(j) === "nextCursor,runs" && j.runs.length === 3 && typeof j.nextCursor === "string"
      && keys(j.runs[0]) === "createdAt,durationMs,errorKind,errorMessage,finishedAt,id,orgMembershipId,source,startedAt,status,toolCallCount,toolCalls,workflow"
      && j.runs.every((x) => x.orgMembershipId === j.runs[0].orgMembershipId) && j.runs[0].workflow.title === "Doubler" && j.runs[0].workflow.graph.nodes.length > 0
      && new Date(j.runs[0].createdAt) >= new Date(j.runs[2].createdAt));
  });
  await t("[2] a run of a draft test is listed with its own source and, as no version ran, the Workflow only by title", async () => {
    const r = await api(ws.owner, "GET", "/v1/workflow-runs?limit=200");
    const draftRun = r.json.runs.find((x) => x.source.startsWith("workflow-test:"));
    return (draftRun && draftRun.workflow.title === "Doubler" && draftRun.workflow.graph === null) || JSON.stringify(draftRun);
  });
  await t("[2] runs: limit 0 is 400 'limit: Too small: expected number to be >=1'", async () =>
    ok(await api(ws.owner, "GET", "/v1/workflow-runs?limit=0"), 400, (j) => j.message === "limit: Too small: expected number to be >=1"));
  await t("[2] runs paginate by cursor", async () => {
    const p1 = await api(ws.owner, "GET", "/v1/workflow-runs?limit=2");
    const p2 = await api(ws.owner, "GET", `/v1/workflow-runs?limit=2&cursor=${p1.json.nextCursor}`);
    return (p2.status === 200 && p2.json.runs.length >= 1 && !p2.json.runs.some((x) => p1.json.runs.some((y) => y.id === x.id))) || p2.text.slice(0, 300);
  });
  await t("[2] a person sees only their own receipts: Bob's list is empty", async () =>
    ok(await api(bob, "GET", "/v1/workflow-runs"), 200, (j) => j.runs.length === 0 && j.nextCursor === null));
  await t("[2] the legacy aliases answer as the new routes do (/v1/codemode-runs, /v1/codemode-scripts)", async () => {
    const a = await api(ws.owner, "GET", "/v1/codemode-runs?limit=1");
    const b = await api(ws.owner, "GET", "/v1/codemode-scripts");
    const c = await api(ws.owner, "GET", `/v1/codemode-scripts/${wf.id}/versions`);
    return (a.status === 200 && a.json.runs.length === 1 && b.status === 200 && Array.isArray(b.json.items) && c.status === 200 && c.json.items.length === 2) || `${a.status} ${b.status} ${c.status}`;
  });

  // ---- my library ----
  await t("[2] my library lists the Workflow beside its plugin, with its result state and the ways it reaches the person", async () => {
    const r = await api(ws.owner, "GET", "/v1/me/library");
    const item = r.json.items.find((i) => i.type === "workflow" && i.id === wf.id);
    return (r.status === 200 && item && item.plugin.id === wf.pluginId && item.role === "manager" && ["fresh", "needs_attention"].includes(item.resultState) && r.json.items.some((i) => i.type === "plugin" && i.id === wf.pluginId)) || r.text.slice(0, 400);
  });
  await t("[2] a viewer's library card for a shared Workflow has the viewer role and the plugin's door", async () => {
    const r = await api(bob, "GET", "/v1/me/library");
    const item = r.json.items.find((i) => i.type === "workflow" && i.id === wf.id);
    return (item && item.role === "viewer" && item.edges.some((e) => e.kind === "person")) || r.text.slice(0, 400);
  });
}

// =====================================================================================================================================
// 3. saving a run as a Workflow
// =====================================================================================================================================
if (want(3)) {
  const ws = await workspace("Workspace Save");
  const api = ws.api;
  const save = (body) => api(ws.owner, "POST", "/v1/workflows", body);
  await t("[3] neither code nor receiptId: 400 invalid_request 'Provide code or receiptId.'", async () =>
    ok(await save({ name: "x" }), 400, (j) => j.error === "invalid_request" && j.message === "Provide code or receiptId." && j.details[0].code === "custom"));
  await t("[3] a name is required and at most 255 characters", async () => {
    const a = await save({ code: "return 1" });
    const b = await save({ name: "x".repeat(256), code: "return 1" });
    return (a.status === 400 && a.json.message === "name: Invalid input: expected string, received undefined" && b.status === 400 && b.json.message === "name: Too big: expected string to have <=255 characters") || `${a.text} ${b.text}`;
  });
  await t("[3] code that was never run: 400 workflow_recent_receipt_required", async () => {
    const r = await save({ name: "x", code: "return 1" });
    return ok(r, 400, (j) => j.error === "workflow_recent_receipt_required" && /Run the exact procedure successfully with execute_capability_script/.test(j.message));
  });
  await t("[3] a receipt id with no retained source: 400 workflow_authoring_receipt_required", async () => {
    const r = await save({ name: "x", receiptId: NOPE("wfr") });
    return ok(r, 400, (j) => j.error === "workflow_authoring_receipt_required" && /A matching successful authoring receipt and its retained source are required/.test(j.message));
  });
  await t("[3] a receipt id that is not an id says the same", async () => ok(await save({ name: "x", receiptId: "nope" }), 400, (j) => j.error === "workflow_authoring_receipt_required"));
  await t("[3] source that holds a literal credential is refused before anything else: 400 workflow_source_contains_secret", async () => {
    const a = await save({ name: "x", code: "const token = 'abcdef123456'; return token" });
    const b = await save({ name: "x", code: "return fetchIt('https://u:p@example.com/')" });
    const c = await save({ name: "x", code: "return { headers: { Authorization: 'Bearer abcdefgh12345' } }" });
    return [a, b, c].every((r) => r.status === 400 && r.json.error === "workflow_source_contains_secret" && /may contain a literal credential/.test(r.json.message)) || `${a.text} ${b.text} ${c.text}`;
  });
  await t("[3] naming a plugin the person cannot edit: 403; one that does not exist: 403 too (the role check comes first)", async () => {
    const r = await save({ pluginId: NOPE("plg"), name: "x", code: "return 1" });
    return ok(r, 403, (j) => j.error === "forbidden" && j.message === "Missing editor access for plugin.");
  });
  await t("[3] a draft run is a receipt for saving that code: the same source, run by the same person, is accepted as 'recently run'", async () => {
    const wf = await seedWorkflow(ws, ws.owner, { name: "Source for save" });
    const code = "return { fromSave: true }";
    await api(ws.owner, "POST", "/v1/workflows/test", { configObjectId: wf.id, name: "Source for save", code, outputSchema: { type: "object" }, requiredCapabilities: [] });
    const r = await save({ name: "Saved from a run", code, outputSchema: { type: "object" } });
    // The reference's lookup matches any recent successful run of the same source by the same person, a draft test included.
    return ok(r, 201, (j) => keys(j) === "configObjectId,configObjectVersionId,graph,mermaid,pluginId" && /^plg_/.test(j.pluginId) && j.mermaid.startsWith("flowchart TD") && j.graph.parseError === null);
  });
  await t("[3] the saved Workflow lives in the person's private 'My Workflows' plugin and is theirs to manage", async () => {
    const lib = await api(ws.owner, "GET", "/v1/me/library");
    const saved = lib.json.items.find((i) => i.type === "workflow" && i.name === "Saved from a run");
    const plugin = lib.json.items.find((i) => i.type === "plugin" && i.name === "My Workflows");
    return (saved && plugin && saved.plugin.id === plugin.id && saved.role === "manager") || lib.text.slice(0, 400);
  });
  await t("[3] saving the same name again makes a new version of the same Workflow, not a second one", async () => {
    const code = "return { fromSave: true }";
    const again = await save({ name: "Saved from a run", code, outputSchema: { type: "object" } });
    const list = (await api(ws.owner, "GET", "/v1/me/library")).json.items.filter((i) => i.type === "workflow" && i.name === "Saved from a run");
    const versions = (await api(ws.owner, "GET", `/v1/workflows/${again.json.configObjectId}/versions`)).json.items;
    return (again.status === 201 && list.length === 1 && list[0].id === again.json.configObjectId && versions.length === 2) || `${again.status} ${list.length} ${versions.length}`;
  });
}

// =====================================================================================================================================
// 4. views and apps (off in the reference unless DEN_GENERATED_ARTIFACT_VIEWS_ENABLED is set)
// =====================================================================================================================================
if (want(4)) {
  const ws = await workspace("Workspace Views");
  const api = ws.api;
  const wf = await seedWorkflow(ws, ws.owner, { name: "Viewed" });
  const V = NOPE("arv");
  const R = NOPE("avr");
  await t("[4] GET /v1/apps says views are off: enabled false, nothing listed", async () => ok(await api(ws.owner, "GET", "/v1/apps"), 200, (j) => keys(j) === "enabled,items,sharingEnabled" && j.enabled === false && j.sharingEnabled === false && j.items.length === 0));
  await t("[4] opening, sharing, saving and placing an app are 404 artifact_view_not_found while views are off", async () => {
    const rs = [await api(ws.owner, "GET", `/v1/apps/${V}`), await api(ws.owner, "POST", `/v1/apps/${V}/share`, { email: "a@example.com" }), await api(ws.owner, "POST", `/v1/apps/${V}/dashboard`, { added: true }),
      await api(ws.owner, "POST", `/v1/apps/${V}/save`, { revisionId: R, title: "x", useInWorkflow: true, expectedActiveRevisionId: null })];
    return rs.every((r) => r.status === 404 && r.json.error === "artifact_view_not_found" && keys(r.json) === "error") || rs.map((r) => `${r.status} ${r.text}`).join(" | ");
  });
  await t("[4] activating and retiring a view are 404 artifact_view_not_found too", async () => {
    const a = await api(ws.owner, "POST", `/v1/artifact-views/${V}/revisions/${R}/activate`);
    const b = await api(ws.owner, "POST", `/v1/artifact-views/${V}/retire`);
    return (a.status === 404 && a.json.error === "artifact_view_not_found" && b.status === 404 && b.json.error === "artifact_view_not_found") || `${a.text} ${b.text}`;
  });
  await t("[4] a Workflow's views are an empty list, its card says default", async () => {
    const a = await api(ws.owner, "GET", `/v1/workflows/${wf.id}/views`);
    const b = await api(ws.owner, "GET", `/v1/workflows/${wf.id}`);
    return (a.status === 200 && keys(a.json) === "items" && a.json.items.length === 0 && b.json.workflow.viewState === "default" && b.json.workflow.activeViewTitle === null && b.json.views.length === 0) || `${a.text} ${b.text.slice(0, 200)}`;
  });
  await t("[4] the views route does not even look at the Workflow while views are off (an unknown id is still an empty list)", async () =>
    ok(await api(ws.owner, "GET", `/v1/workflows/${NOPE("cob")}/views`), 200, (j) => j.items.length === 0));
  await t("[4] app bodies are checked before the switch: sharing without an email is 400 invalid_request", async () =>
    ok(await api(ws.owner, "POST", `/v1/apps/${V}/share`, {}), 400, (j) => j.error === "invalid_request" && j.message === "email: Invalid input: expected string, received undefined"));
  await t("[4] and a dashboard change without 'added' is 400 invalid_request", async () =>
    ok(await api(ws.owner, "POST", `/v1/apps/${V}/dashboard`, {}), 400, (j) => j.error === "invalid_request" && j.message === "added: Invalid input: expected boolean, received undefined"));
}

// =====================================================================================================================================
// 5. the Apps catalog
// =====================================================================================================================================
if (want(5)) {
  const ws = await workspace("Workspace Apps");
  await t("[5] GET /v1/mcp-apps is an empty list for a workspace with no Apps", async () => ok(await ws.api(ws.owner, "GET", "/v1/mcp-apps"), 200, (j) => keys(j) === "apps" && j.apps.length === 0));
  await t("[5] it needs a session: 401", async () => (await call(A, "/v1/mcp-apps")).status === 401);
  await t("[5] and a workspace the caller belongs to: 404 for one they do not", async () => {
    const other = await workspace("Workspace Apps Other");
    const r = await call(A, "/v1/mcp-apps", { bearer: ws.owner.token, headers: { "x-openwork-org-id": other.orgId } });
    return r.status === 404 || r.status === 403 || `${r.status} ${r.text.slice(0, 200)}`;
  });
}

// =====================================================================================================================================
// 6. webhooks and direct uploads
// =====================================================================================================================================
if (want(6)) {
  await t("[6] the GitHub webhook with no secret configured is 503 with no body", async () => {
    const r = await call(A, "/v1/webhooks/connectors/github", { method: "POST", body: { zen: "x" }, headers: { "x-hub-signature-256": "sha256=00", "x-github-event": "push", "x-github-delivery": "d1" } });
    return (r.status === 503 && r.text === "") || `${r.status} ${r.text}`;
  });
  await t("[6] the Stripe webhook with no secret configured is 400 stripe_webhook_secret_missing", async () =>
    ok(await call(A, "/v1/webhooks/stripe", { method: "POST", body: {} }), 400, (j) => j.error === "stripe_webhook_secret_missing"));
  await t("[6] the webhooks are public: no session, no origin header needed", async () => {
    const r = await fetch(`${A}/v1/webhooks/stripe`, { method: "POST", body: "{}" });
    return r.status === 400 || r.status;
  });
  await t("[6] direct uploads without a bearer token: 401 missing_mcp_token", async () => {
    const paths = [["POST", "/v1/direct-uploads/google-workspace/drive-files"], ["POST", "/v1/direct-uploads/google-workspace/gmail-drafts"], ["POST", "/v1/direct-uploads/google-workspace/drive-upload-sessions"],
      ["POST", "/v1/direct-uploads/microsoft-365/mail-drafts"], ["POST", "/v1/direct-uploads/microsoft-365/drive-upload-sessions"]];
    const rs = [];
    for (const [method, path] of paths) rs.push(await call(A, path, { method, body: {} }));
    return rs.every((r) => r.status === 401 && r.json.error === "missing_mcp_token") || rs.map((r) => `${r.status} ${r.text.slice(0, 80)}`).join(" | ");
  });
}

s.done();
