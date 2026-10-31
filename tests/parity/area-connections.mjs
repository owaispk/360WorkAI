// Contract test for the "connections" area: external MCP servers a workspace connects, who may use them, tool policy, OAuth sign-in with a
// protected server, and agents using the tools through /mcp/agent. It starts a fake MCP server and fake OAuth provider on 127.0.0.1 (fake-mcp.mjs).
//
//   node area-connections.mjs                                              # reference: web :3005, api :8790
//   W=http://localhost:5230 A=http://localhost:5130 node area-connections.mjs   # rewrite (start it with Connections__AllowPrivateUrls=true)
//
// Both servers must allow private addresses (the reference does in dev mode) because the fake servers listen on loopback.
import { call, workspace, person, suite, A, W } from "./lib.mjs";
import { startFake } from "./fake-mcp.mjs";

const s = suite("connections");
const fake = await startFake();
const ws = await workspace("Connections Probe");
const bob = await ws.join("Bob Member");
const carol = await ws.join("Carol Member");
const admin = await ws.join("Ada Admin", "admin");
const bobId = bob.memberId, ownerId = ws.owner.memberId ?? (await ws.memberId(ws.owner));
const api = (u, m, p, b, x) => ws.api(u, m, p, b, x);
const post = (u, b) => api(u, "POST", "/v1/mcp-connections", b);
const errOf = (r) => r.json?.error;
const NONE = { name: "Fake none", url: fake.url("none"), authType: "none" };
const FORBIDDEN_PERM = (r, key) => r.status === 403 && r.json?.requiredPermission === key;
const noSecrets = (text) => !text.includes(fake.key);
const rpc = (tok, method, params, id = 1) => call(A, "/mcp/agent", { method: "POST", bearer: tok, headers: { accept: "application/json, text/event-stream" }, body: { jsonrpc: "2.0", id, method, params } });
/** The result of an MCP tools/call, whether the server answers JSON or an event stream. */
const result = (r) => { const t = r.text.startsWith("event:") ? r.text.split("\n").find((l) => l.startsWith("data:"))?.slice(5) : r.text; return JSON.parse(t).result; };
const sc = (r) => { const x = result(r); return x.structuredContent ?? JSON.parse(x.content[0].text); };
const mint = async (u, scopes) => (await api(u, "POST", "/v1/mcp/token", { scopes })).json.token;

// ---------- creating ----------
let none;
await s.t("an admin adds a server with no sign-in: 200, connected, shared with everyone, no secrets, with hand-off links", async () => {
  const r = await post(ws.owner, NONE); none = r.json;
  return (r.status === 200 && /^emc_[0-9a-z]{26}$/.test(none.id) && none.authType === "none" && none.credentialMode === "shared" && none.connected === true && none.connectedForMe === true
    && none.access?.orgWide === true && none.createdByYou === true && none.canRemove === true && none.readiness?.status === "ready" && typeof none.links?.yourConnections === "string" && typeof none.links?.signIn === "string"
    && Array.isArray(none.requestHeaderNames)) || `${r.status} ${r.text.slice(0, 300)}`;
});
await s.t("the server was really asked: initialize and a tool list reached the fake", async () => fake.mcpCalls("none", "initialize").length >= 1 && fake.mcpCalls("none", "tools/list").length >= 1);
await s.t("an empty body is a 400 invalid_request", async () => { const r = await post(ws.owner, {}); return (r.status === 400 && errOf(r) === "invalid_request") || r.status; });
await s.t("a url that is not http(s) is refused with the reference's message", async () => { const r = await post(ws.owner, { ...NONE, url: "ftp://x" }); return (r.status === 400 && r.json.message === "url: MCP URLs must use HTTP or HTTPS.") || r.text.slice(0, 200); });
await s.t("a url with embedded credentials is refused", async () => { const r = await post(ws.owner, { ...NONE, url: "http://u:p@x.example/mcp" }); return (r.status === 400 && r.json.message === "url: MCP URLs must not contain embedded credentials.") || r.text.slice(0, 200); });
await s.t("a url with a credential query parameter is refused", async () => { const r = await post(ws.owner, { ...NONE, url: "https://x.example/mcp?token=abc" }); return (r.status === 400 && r.json.message === 'url: MCP URL query parameter "token" must not contain credentials.') || r.text.slice(0, 200); });
await s.t("a reserved request header is refused", async () => { const r = await post(ws.owner, { ...NONE, requestHeaders: [{ name: "Host", value: "x" }] }); return (r.status === 400 && r.json.message === 'The request header "Host" is set by OpenWork and can\'t be added.') || r.text.slice(0, 200); });
await s.t("a wrong API key is caught before saving: 502 connection_validation_failed with a diagnostic reference", async () => {
  const r = await post(ws.owner, { name: "Bad key", url: fake.url("key"), authType: "apikey", apiKey: "wrong" });
  return (r.status === 502 && errOf(r) === "connection_validation_failed" && typeof r.json.diagnostic?.referenceId === "string" && !r.text.includes("wrong\"")) || `${r.status} ${r.text.slice(0, 300)}`;
});
await s.t("nothing was saved by the failed attempt", async () => !(await api(ws.owner, "GET", "/v1/mcp-connections?scope=manageable")).json.connections.some((c) => c.name === "Bad key"));

let keyed;
await s.t("a shared API key connection works and the key is never returned (create, get, list)", async () => {
  const r = await post(ws.owner, { name: "Fake key", url: fake.url("key"), authType: "apikey", apiKey: fake.key }); keyed = r.json;
  const g = await api(ws.owner, "GET", `/v1/mcp-connections/${keyed.id}`);
  const l = await api(ws.owner, "GET", "/v1/mcp-connections?scope=manageable");
  return (r.status === 200 && keyed.connected && keyed.readiness?.status === "ready" && noSecrets(r.text) && noSecrets(g.text) && noSecrets(l.text)) || `${r.status} ${r.text.slice(0, 200)}`;
});
await s.t("the key reached the server as a bearer credential", async () => fake.mcpCalls("key", "tools/list").some((c) => c.auth === `Bearer ${fake.key}`));
await s.t("administrator request headers are sent to the server and only their names are returned", async () => {
  const r = await post(ws.owner, { ...NONE, name: "With header", requestHeaders: [{ name: "X-Test-One", value: "secret-header-value" }] });
  const sent = fake.mcpCalls("none").some((c) => c.extra.includes("x-test-one=secret-header-value"));
  return (r.status === 200 && JSON.stringify(r.json.requestHeaderNames) === '["X-Test-One"]' && !r.text.includes("secret-header-value") && sent) || `${r.status} ${r.text.slice(0, 200)}`;
});
await s.t("a key-less shared API key connection waits for its key and offers a private prompt", async () => {
  const r = await post(ws.owner, { name: "Awaiting key", url: fake.url("key"), authType: "apikey" });
  keyed.waiting = r.json;
  return (r.status === 200 && r.json.connected === false && r.json.credentialPrompt?.kind === "credential_prompt" && r.json.credentialPrompt?.target?.type === "mcp_connection_key" && r.json.credentialPrompt?.target?.connectionId === r.json.id) || `${r.status} ${r.text.slice(0, 300)}`;
});
await s.t("its tools cannot be listed before the key is entered (409 connection_not_ready)", async () => { const r = await api(ws.owner, "GET", `/v1/mcp-connections/${keyed.waiting.id}/tools`); return (r.status === 409 && errOf(r) === "connection_not_ready") || r.status; });
await s.t("a key with spaces is refused without echoing it", async () => { const r = await api(ws.owner, "PUT", `/v1/mcp-connections/${keyed.waiting.id}/shared-credential`, { apiKey: "has space" }); return (r.status === 400 && errOf(r) === "invalid_request" && !r.text.includes("has space")) || r.text.slice(0, 200); });
await s.t("a key the server rejects is refused (400 credential_rejected) and not kept", async () => {
  const r = await api(ws.owner, "PUT", `/v1/mcp-connections/${keyed.waiting.id}/shared-credential`, { apiKey: "wrongkey" });
  const g = await api(ws.owner, "GET", `/v1/mcp-connections/${keyed.waiting.id}`);
  return (r.status === 400 && errOf(r) === "credential_rejected" && g.json.connected === false) || `${r.status} ${r.text.slice(0, 200)}`;
});
await s.t("the right key is saved: ok, readiness ready, and the tools can be listed", async () => {
  const r = await api(ws.owner, "PUT", `/v1/mcp-connections/${keyed.waiting.id}/shared-credential`, { apiKey: fake.key });
  const t = await api(ws.owner, "GET", `/v1/mcp-connections/${keyed.waiting.id}/tools`);
  return (r.status === 200 && r.json.ok === true && r.json.readiness?.status === "ready" && t.status === 200 && t.json.tools.length === 3) || `${r.status} ${r.text.slice(0, 200)} / ${t.status}`;
});
await s.t("a member cannot enter the shared key (403 connections.manage)", async () => FORBIDDEN_PERM(await api(bob, "PUT", `/v1/mcp-connections/${keyed.waiting.id}/shared-credential`, { apiKey: fake.key }), "connections.manage") || "not denied");

// ---------- members adding their own ----------
await s.t("a member may add a no-sign-in server for themselves and always keeps access, never org-wide", async () => {
  const r = await post(bob, { name: "Bobs none", url: fake.url("none"), authType: "none", access: { orgWide: false, memberIds: [], teamIds: [] } });
  return (r.status === 200 && r.json.access?.orgWide === false && r.json.access.memberIds.includes(bobId) && r.json.createdByYou === true) || `${r.status} ${r.text.slice(0, 200)}`;
});
await s.t("a member cannot add a key connection, share with everyone, or add a shared OAuth connection (403 with the reference's messages)", async () => {
  const a = await post(bob, { name: "K", url: fake.url("key"), authType: "apikey", apiKey: fake.key });
  const b = await post(bob, NONE);
  const c = await post(bob, { name: "O", url: fake.url("oauth"), authType: "oauth" });
  return (a.status === 403 && a.json.message === "Only workspace owners and admins can add a connection that uses a key."
    && b.status === 403 && b.json.message === "Only workspace owners and admins can share a connection with everyone."
    && c.status === 403 && c.json.message === "Connections you add sign each person in with their own account.") || `${a.status} ${b.status} ${c.status}`;
});
await s.t("a duplicate stable key is a 409 external_key_exists", async () => {
  const one = await post(ws.owner, { ...NONE, name: "Keyed", externalKey: "k1" });
  const two = await post(ws.owner, { ...NONE, name: "Keyed again", externalKey: "k1" });
  return (one.status === 200 && two.status === 409 && errOf(two) === "external_key_exists") || `${one.status} ${two.status}`;
});
await s.t("PUT by-key creates (201) then replaces (200) and DELETE by-key reports whether it deleted", async () => {
  const a = await api(ws.owner, "PUT", "/v1/mcp-connections/by-key/upsert-1", { name: "Upserted", url: fake.url("none"), authType: "none", credentialMode: "shared" });
  const b = await api(ws.owner, "PUT", "/v1/mcp-connections/by-key/upsert-1", { name: "Upserted 2", url: fake.url("none"), authType: "none", credentialMode: "shared" });
  const d1 = await api(ws.owner, "DELETE", "/v1/mcp-connections/by-key/upsert-1");
  const d2 = await api(ws.owner, "DELETE", "/v1/mcp-connections/by-key/upsert-1");
  return (a.status === 201 && b.status === 200 && b.json.id === a.json.id && b.json.name === "Upserted 2" && d1.json?.deleted === true && d2.status === 200 && d2.json?.deleted === false) || `${a.status} ${b.status} ${d1.text} ${d2.text}`;
});

// ---------- who can use a connection ----------
let shared;   // a connection granted to nobody yet
await s.t("a connection granted to nobody is hidden from members, and admins do not get it by being admins either", async () => {
  const r = await post(ws.owner, { name: "Private one", url: fake.url("none"), authType: "none", access: { orgWide: false, memberIds: [], teamIds: [] } }); shared = r.json;
  const bobs = await api(bob, "GET", "/v1/mcp-connections");
  const owners = await api(ws.owner, "GET", "/v1/mcp-connections");
  return (r.status === 200 && !bobs.json.connections.some((c) => c.id === shared.id) && !owners.json.connections.some((c) => c.id === shared.id)) || "visible";
});
await s.t("a member cannot list all connections or read one (403 connections.view)", async () => {
  const l = await api(bob, "GET", "/v1/mcp-connections?scope=manageable");
  const g = await api(bob, "GET", `/v1/mcp-connections/${shared.id}`);
  return (l.status === 403 && l.json.message === "Only workspace owners and admins can list all MCP connections." && FORBIDDEN_PERM(g, "connections.view")) || `${l.status} ${g.status}`;
});
await s.t("a member without a grant cannot list its tools (403), but an admin with connections.view can inspect them", async () => {
  const b = await api(bob, "GET", `/v1/mcp-connections/${shared.id}/tools`);
  const o = await api(ws.owner, "GET", `/v1/mcp-connections/${shared.id}/tools`);
  return (b.status === 403 && b.json.message === 'You have not been granted access to "Private one".' && o.status === 200 && o.json.tools.length === 3) || `${b.status} ${o.status}`;
});
await s.t("sharing with a person makes it appear for them and not for others", async () => {
  const r = await api(ws.owner, "PUT", `/v1/mcp-connections/${shared.id}/access`, { access: { orgWide: false, memberIds: [bobId], teamIds: [] } });
  const b = await api(bob, "GET", "/v1/mcp-connections");
  const c = await api(carol, "GET", "/v1/mcp-connections");
  const mine = b.json.connections.find((x) => x.id === shared.id);
  return (r.status === 200 && r.json.access.memberIds.length === 1 && mine && mine.access === null && !("createdByName" in mine) && !c.json.connections.some((x) => x.id === shared.id)) || `${r.status} ${b.text.slice(0, 200)}`;
});
await s.t("sharing with a team reaches its people", async () => {
  const team = await api(ws.owner, "POST", "/v1/teams", { name: "Readers", memberIds: [carol.memberId] });
  const r = await api(ws.owner, "PUT", `/v1/mcp-connections/${shared.id}/access`, { access: { orgWide: false, memberIds: [bobId], teamIds: [team.json.team.id] } });
  const c = await api(carol, "GET", "/v1/mcp-connections");
  return (r.status === 200 && c.json.connections.some((x) => x.id === shared.id)) || `${r.status} ${c.text.slice(0, 200)}`;
});
await s.t("a member's tools list works with a grant, and a member cannot run tools by hand (403 connections.manage)", async () => {
  const t = await api(bob, "GET", `/v1/mcp-connections/${shared.id}/tools`);
  const c = await api(bob, "POST", `/v1/mcp-connections/${shared.id}/tools/call`, { toolName: "echo", arguments: { message: "hi" } });
  return (t.status === 200 && t.json.tools.map((x) => x.name).join() === "echo,add,delete_everything" && t.json.policy.updatedBy === null && FORBIDDEN_PERM(c, "connections.manage")) || `${t.status} ${c.status}`;
});
await s.t("only the creator or a manager may change access; a member cannot give everyone access", async () => {
  const other = await api(carol, "PUT", `/v1/mcp-connections/${shared.id}/access`, { access: { orgWide: true, memberIds: [], teamIds: [] } });
  const own = await post(bob, { name: "Bobs for all", url: fake.url("none"), authType: "none", access: { orgWide: false, memberIds: [], teamIds: [] } });
  const everyone = await api(bob, "PUT", `/v1/mcp-connections/${own.json.id}/access`, { access: { orgWide: true, memberIds: [], teamIds: [] } });
  return (other.status === 403 && everyone.status === 403 && everyone.json.message === "Only workspace owners and admins can share a connection with everyone.") || `${other.status} ${everyone.status}`;
});
await s.t("access validation: a malformed id is a 400", async () => (await api(ws.owner, "PUT", `/v1/mcp-connections/${shared.id}/access`, { access: { orgWide: false, memberIds: ["nope"], teamIds: [] } })).status === 400);

// ---------- running tools by hand and the tool policy ----------
await s.t("an admin who is granted a connection can run a tool by hand and gets the result and an inspection", async () => {
  await api(ws.owner, "PUT", `/v1/mcp-connections/${shared.id}/access`, { access: { orgWide: false, memberIds: [bobId, ownerId], teamIds: [] } });
  const r = await api(ws.owner, "POST", `/v1/mcp-connections/${shared.id}/tools/call`, { toolName: "echo", arguments: { message: "hi" } });
  return (r.status === 200 && r.json.result?.content?.[0]?.text === "echo: hi" && typeof r.json.referenceId === "string" && r.json.inspection?.diagnosis?.status === "succeeded") || `${r.status} ${r.text.slice(0, 300)}`;
});
await s.t("an admin who is not granted cannot run a tool by hand (403)", async () => {
  const mine = await post(ws.owner, { name: "Not mine", url: fake.url("none"), authType: "none", access: { orgWide: false, memberIds: [bobId], teamIds: [] } });
  const r = await api(ws.owner, "POST", `/v1/mcp-connections/${mine.json.id}/tools/call`, { toolName: "echo", arguments: { message: "x" } });
  return (r.status === 403 && r.json.message === 'You have not been granted access to "Not mine".') || `${r.status} ${r.text.slice(0, 200)}`;
});
await s.t("an unknown tool is a 502 tool_execution_failed with a diagnostic", async () => {
  const r = await api(ws.owner, "POST", `/v1/mcp-connections/${shared.id}/tools/call`, { toolName: "nope", arguments: {} });
  return (r.status === 502 && errOf(r) === "tool_execution_failed" && r.json.diagnostic?.referenceId) || `${r.status} ${r.text.slice(0, 200)}`;
});
await s.t("tool arguments over 1 MB are a 413", async () => {
  const r = await api(ws.owner, "POST", `/v1/mcp-connections/${shared.id}/tools/call`, { toolName: "echo", arguments: { message: "x".repeat(1100 * 1024) } });
  return (r.status === 413 && errOf(r) === "payload_too_large") || r.status;
});
await s.t("the tool policy starts empty; a member cannot read it (403 connections.view)", async () => {
  const g = await api(ws.owner, "GET", `/v1/mcp-connections/${shared.id}/tool-policy`);
  const m = await api(bob, "GET", `/v1/mcp-connections/${shared.id}/tool-policy`);
  return (g.status === 200 && g.json.policy.allDisabled === false && g.json.policy.disabledTools.length === 0 && FORBIDDEN_PERM(m, "connections.view")) || `${g.status} ${m.status}`;
});
await s.t("saving a policy collapses duplicates and records who and when; a member cannot save one", async () => {
  const bad = await api(ws.owner, "PUT", `/v1/mcp-connections/${shared.id}/tool-policy`, { allDisabled: "x" });
  const r = await api(ws.owner, "PUT", `/v1/mcp-connections/${shared.id}/tool-policy`, { allDisabled: false, disabledTools: ["delete_everything", "delete_everything"] });
  const m = await api(bob, "PUT", `/v1/mcp-connections/${shared.id}/tool-policy`, { allDisabled: true, disabledTools: [] });
  return (bad.status === 400 && r.status === 200 && r.json.policy.disabledTools.length === 1 && r.json.policy.updatedBy === "Owner Person" && !!r.json.policy.updatedAt && FORBIDDEN_PERM(m, "connections.manage")) || `${bad.status} ${r.text}`;
});
await s.t("a policy-blocked tool is refused when run by hand (403 policy_blocked, naming who)", async () => {
  const r = await api(ws.owner, "POST", `/v1/mcp-connections/${shared.id}/tools/call`, { toolName: "delete_everything", arguments: {} });
  return (r.status === 403 && errOf(r) === "policy_blocked" && r.json.message === "delete_everything is disabled for your organization." && r.json.disabledBy === "Owner Person") || `${r.status} ${r.text}`;
});
await s.t("the fake never received the blocked call", async () => !fake.calls.some((c) => c.kind === "mcp" && c.method === "tools/call" && c.tool === "delete_everything"));
await s.t("a member sees the policy without who set it", async () => { const t = await api(bob, "GET", `/v1/mcp-connections/${shared.id}/tools`); return (t.json.policy.disabledTools[0] === "delete_everything" && t.json.policy.updatedBy === null) || t.text.slice(0, 300); });

// ---------- editing, removing ----------
await s.t("a stale edit is a 409 connection_conflict; a current one renames", async () => {
  const stale = await api(ws.owner, "PUT", `/v1/mcp-connections/${none.id}`, { expectedUpdatedAt: "2020-01-01T00:00:00.000Z", name: "N", url: fake.url("none"), authType: "none", credentialMode: "shared", access: { orgWide: true, memberIds: [], teamIds: [] } });
  const cur = await api(ws.owner, "GET", `/v1/mcp-connections/${none.id}`);
  const ok = await api(ws.owner, "PUT", `/v1/mcp-connections/${none.id}`, { expectedUpdatedAt: cur.json.updatedAt, name: "Renamed", url: fake.url("none"), authType: "none", credentialMode: "shared", access: { orgWide: true, memberIds: [], teamIds: [] } });
  return (stale.status === 409 && errOf(stale) === "connection_conflict" && ok.status === 200 && ok.json.name === "Renamed" && ok.json.identityChanged === false) || `${stale.status} ${ok.status} ${ok.text.slice(0, 200)}`;
});
await s.t("a member cannot edit, remove or disconnect a connection they did not add", async () => {
  const cur = await api(ws.owner, "GET", `/v1/mcp-connections/${none.id}`);
  const e = await api(bob, "PUT", `/v1/mcp-connections/${none.id}`, { expectedUpdatedAt: cur.json.updatedAt, name: "X", url: fake.url("none"), authType: "none", credentialMode: "shared", access: { orgWide: true, memberIds: [], teamIds: [] } });
  const d = await api(bob, "DELETE", `/v1/mcp-connections/${none.id}`);
  const x = await api(bob, "POST", `/v1/mcp-connections/${none.id}/disconnect`);
  return (e.status === 403 && d.status === 403 && FORBIDDEN_PERM(x, "connections.disconnect")) || `${e.status} ${d.status} ${x.status}`;
});
await s.t("a malformed id is a 400 and an unknown id a 404 connection_not_found", async () => {
  const a = await api(ws.owner, "GET", "/v1/mcp-connections/nope");
  const b = await api(ws.owner, "GET", "/v1/mcp-connections/emc_01m6798bqbeaeagm9dmr8grtrt");
  return (a.status === 400 && b.status === 404 && errOf(b) === "connection_not_found") || `${a.status} ${b.status}`;
});
await s.t("another workspace's connection reads as not found, for every route", async () => {
  const other = await workspace("Other Place");
  const own = await other.api(other.owner, "POST", "/v1/mcp-connections", NONE);
  const rs = [await api(ws.owner, "GET", `/v1/mcp-connections/${own.json.id}`), await api(ws.owner, "GET", `/v1/mcp-connections/${own.json.id}/tools`), await api(ws.owner, "PUT", `/v1/mcp-connections/${own.json.id}/tool-policy`, { allDisabled: true, disabledTools: [] }),
    await api(ws.owner, "DELETE", `/v1/mcp-connections/${own.json.id}`), await api(ws.owner, "PUT", `/v1/mcp-connections/${own.json.id}/access`, { access: { orgWide: true } })];
  return rs.every((r) => r.status === 404) || rs.map((r) => r.status).join();
});
await s.t("removal-request names the exact connection and a confirm link, and refuses a wrong name", async () => {
  const r = await api(ws.owner, "POST", `/v1/mcp-connections/${none.id}/removal-request`, { expectedName: "Renamed" });
  const w = await api(ws.owner, "POST", `/v1/mcp-connections/${none.id}/removal-request`, { expectedName: "X" });
  return (r.status === 200 && r.json.status === "confirmation_required" && r.json.handoff?.action === "open_link" && w.status === 409 && errOf(w) === "connection_name_mismatch") || `${r.status} ${w.status}`;
});
await s.t("disconnecting a shared connection clears its credential, keeps the connection; removing deletes it", async () => {
  const d = await api(ws.owner, "POST", `/v1/mcp-connections/${keyed.id}/disconnect`);
  const g = await api(ws.owner, "GET", `/v1/mcp-connections/${keyed.id}`);
  const del = await api(ws.owner, "DELETE", `/v1/mcp-connections/${keyed.id}`);
  const again = await api(ws.owner, "DELETE", `/v1/mcp-connections/${keyed.id}`);
  return (d.json?.ok === true && g.json.connected === false && del.json?.ok === true && again.status === 404) || `${d.status} ${g.text.slice(0, 100)} ${del.status} ${again.status}`;
});
await s.t("readiness: check records a result; readiness-checks reports each id", async () => {
  const c = await api(ws.owner, "POST", `/v1/mcp-connections/${shared.id}/check`);
  const r = await api(ws.owner, "POST", "/v1/mcp-connections/readiness-checks", { connectionIds: [shared.id, "emc_01m6798bqbeaeagm9dmr8grtrt"] });
  const bad = await api(ws.owner, "POST", "/v1/mcp-connections/readiness-checks", { connectionIds: [] });
  return (c.status === 200 && c.json.readiness.status === "ready" && r.json.results.find((x) => x.connectionId === shared.id).outcome === "already_checked" && r.json.results[1].outcome === "not_found" && bad.status === 400) || `${c.status} ${r.text}`;
});

// ---------- per-person sign-in with OAuth ----------
let oc;
await s.t("a per-person OAuth connection is created unconnected, with the shared callback address", async () => {
  const r = await post(ws.owner, { name: "Fake oauth", url: fake.url("oauth"), authType: "oauth", credentialMode: "per_member" }); oc = r.json;
  return (r.status === 200 && oc.connected === false && oc.connectedForMe === false && oc.authType === "oauth" && oc.credentialMode === "per_member" && /\/v1\/mcp-connections\/oauth\/callback$/.test(oc.oauthCallbackUrl)) || `${r.status} ${r.text.slice(0, 300)}`;
});
await s.t("tools cannot be listed before a person connects (409 connection_not_ready)", async () => (await api(ws.owner, "GET", `/v1/mcp-connections/${oc.id}/tools`)).status === 409);
await s.t("a shared OAuth connection can only be started by a manager (403)", async () => {
  const sh = await post(ws.owner, { name: "Shared oauth", url: fake.url("oauth"), authType: "oauth", credentialMode: "shared" });
  const r = await api(bob, "GET", `/v1/mcp-connections/${sh.json.id}/connect/start`);
  return FORBIDDEN_PERM(r, "connections.manage") || `${r.status} ${r.text.slice(0, 200)}`;
});
let authorizeUrl;
await s.t("starting sign-in finds the provider, registers this app and returns a PKCE authorize address naming the resource", async () => {
  const r = await api(ws.owner, "GET", `/v1/mcp-connections/${oc.id}/connect/start`);
  authorizeUrl = r.json?.authorizeUrl;
  const u = new URL(authorizeUrl ?? "http://x");
  return (r.status === 200 && r.json.status === "needs_auth" && u.origin === fake.origin && u.pathname === "/authorize" && u.searchParams.get("code_challenge_method") === "S256" && !!u.searchParams.get("code_challenge")
    && u.searchParams.get("response_type") === "code" && u.searchParams.get("resource") === fake.url("oauth") && !!u.searchParams.get("state") && u.searchParams.get("redirect_uri")?.endsWith("/v1/mcp-connections/oauth/callback")) || `${r.status} ${r.text.slice(0, 300)}`;
});
await s.t("the callback with the code connects the person: an HTML page, then connected, scopes granted, ready", async () => {
  const a = await fetch(authorizeUrl, { redirect: "manual" });
  const callback = a.headers.get("location");
  const page = await fetch(callback, { redirect: "manual" });
  const html = await page.text();
  const g = await api(ws.owner, "GET", `/v1/mcp-connections/${oc.id}`);
  return (page.status === 200 && /connected/i.test(html) && g.json.connected === true && g.json.connectedForMe === true && g.json.grantedScopes.join() === "mcp" && g.json.credentialHealth === "ready" && g.json.readiness?.status === "ready" && g.json.oauthRegistrationSource === "dynamic" && !!g.json.oauthClientId) || `${page.status} ${g.text.slice(0, 400)}`;
});
await s.t("the provider saw the code exchange with a PKCE verifier", async () => fake.calls.some((c) => c.kind === "token" && c.grant === "authorization_code" && c.hasVerifier));
await s.t("replaying the same callback is refused (single use)", async () => {
  const start = await api(ws.owner, "GET", `/v1/mcp-connections/${oc.id}/connect/start`);
  const a = await fetch(start.json.authorizeUrl, { redirect: "manual" });
  const callback = a.headers.get("location");
  const first = await fetch(callback, { redirect: "manual" }); await first.text();
  const second = await fetch(callback, { redirect: "manual" });
  return (first.status === 200 && second.status === 400) || `${first.status} ${second.status}`;
});
await s.t("a callback with no or a forged state is a 400 invalid_request", async () => {
  const a = await call(A, "/v1/mcp-connections/oauth/callback");
  const b = await call(A, "/v1/mcp-connections/oauth/callback?state=forged&code=x");
  return (a.status === 400 && errOf(a) === "invalid_request" && b.status === 400 && b.json.message === "Invalid or expired state.") || `${a.status} ${b.status} ${b.text}`;
});
await s.t("the connected person's tools list uses their own token", async () => {
  fake.reset();
  const t = await api(ws.owner, "GET", `/v1/mcp-connections/${oc.id}/tools`);
  return (t.status === 200 && t.json.tools.length === 3 && fake.mcpCalls("oauth", "tools/list").every((c) => c.auth.startsWith("Bearer at_"))) || `${t.status} ${t.text.slice(0, 200)}`;
});
await s.t("another person is not connected until they sign in themselves", async () => {
  const g = await api(bob, "GET", "/v1/mcp-connections");
  const mine = g.json.connections.find((c) => c.id === oc.id);
  return (mine && mine.connectedForMe === false && mine.connected === false) || g.text.slice(0, 300);
});
await s.t("an expired token is refreshed with the refresh token and the call succeeds", async () => {
  fake.calls.length = 0;
  await fetch(fake.origin + "/__expire");
  const t = await api(ws.owner, "GET", `/v1/mcp-connections/${oc.id}/tools`);
  return (t.status === 200 && fake.calls.some((c) => c.kind === "token" && c.grant === "refresh_token")) || `${t.status} ${t.text.slice(0, 200)} ${JSON.stringify(fake.calls.filter((c) => c.kind === "token"))}`;
});
await s.t("a refresh the provider rejects signs the person out and asks them to reconnect", async () => {
  await fetch(fake.origin + "/__expire");
  await fetch(fake.origin + "/__state", { method: "POST", body: JSON.stringify({ rejectRefresh: true }) });
  const t = await api(ws.owner, "GET", `/v1/mcp-connections/${oc.id}/tools`);
  const g = await api(ws.owner, "GET", `/v1/mcp-connections/${oc.id}`);
  await fetch(fake.origin + "/__state", { method: "POST", body: JSON.stringify({ rejectRefresh: false }) });
  return (t.status >= 400 && g.json.connectedForMe === false && g.json.needsReconnect === true && g.json.credentialHealth === "reconnect_required") || `${t.status} ${g.text.slice(0, 300)}`;
});
await s.t("a provider that denies the sign-in gives a failure page and records why, without connecting", async () => {
  const start = await api(ws.owner, "GET", `/v1/mcp-connections/${oc.id}/connect/start`);
  const u = new URL(start.json.authorizeUrl); u.searchParams.set("deny", "1");
  const a = await fetch(u, { redirect: "manual" });
  const page = await fetch(a.headers.get("location"), { redirect: "manual" });
  const html = await page.text();
  const g = await api(ws.owner, "GET", `/v1/mcp-connections/${oc.id}`);
  return (page.status === 400 && /Connection failed/.test(html) && g.json.connectedForMe === false && g.json.readiness?.status === "could_not_verify" && g.json.readiness?.failure === "sign_in_rejected") || `${page.status} ${g.text.slice(0, 300)}`;
});
await s.t("disconnect-my-account removes only the caller's account (200, then 404 nothing connected); shared connections refuse (400)", async () => {
  const start = await api(ws.owner, "GET", `/v1/mcp-connections/${oc.id}/connect/start`);
  const a = await fetch(start.json.authorizeUrl, { redirect: "manual" });
  await (await fetch(a.headers.get("location"), { redirect: "manual" })).text();
  const one = await api(ws.owner, "POST", `/v1/mcp-connections/${oc.id}/disconnect-my-account`);
  const two = await api(ws.owner, "POST", `/v1/mcp-connections/${oc.id}/disconnect-my-account`);
  const sh = await api(ws.owner, "POST", `/v1/mcp-connections/${shared.id}/disconnect-my-account`);
  return (one.json?.ok === true && two.status === 404 && sh.status === 400) || `${one.status} ${two.status} ${sh.status}`;
});
await s.t("OAuth client metadata is public and names the callback", async () => {
  const r = await call(A, "/oauth/client-metadata.json");
  return (r.status === 200 && r.json.client_name === "OpenWork" && r.json.token_endpoint_auth_method === "none" && r.json.redirect_uris?.[0]?.endsWith("/v1/mcp-connections/oauth/callback")) || `${r.status} ${r.text.slice(0, 200)}`;
});

// ---------- a personal key per member ----------
let pm;
await s.t("a per-person API key connection: each person enters their own key; it is write-only and used for their calls", async () => {
  const r = await post(ws.owner, { name: "Personal keys", url: fake.url("key"), authType: "apikey", credentialMode: "per_member" }); pm = r.json;
  const save = await api(bob, "PUT", `/v1/mcp-connections/${pm.id}/my-credential`, { apiKey: fake.key });
  const mine = (await api(bob, "GET", "/v1/mcp-connections")).json.connections.find((c) => c.id === pm.id);
  fake.reset();
  const tools = await api(bob, "GET", `/v1/mcp-connections/${pm.id}/tools`);
  const carolTools = await api(carol, "GET", `/v1/mcp-connections/${pm.id}/tools`);
  return (r.status === 200 && pm.connected === false && save.status === 200 && save.json.ok === true && mine.connectedForMe === true && noSecrets(JSON.stringify(mine)) && tools.status === 200
    && fake.mcpCalls("key", "tools/list").some((c) => c.auth === `Bearer ${fake.key}`) && carolTools.status === 409) || `${r.status} ${save.status} ${tools.status} ${carolTools.status}`;
});
await s.t("a personal key is refused on a shared connection, and without a grant", async () => {
  const sharedKey = await post(ws.owner, { name: "Shared key", url: fake.url("key"), authType: "apikey", apiKey: fake.key });
  const a = await api(bob, "PUT", `/v1/mcp-connections/${sharedKey.json.id}/my-credential`, { apiKey: fake.key });
  const ungranted = await post(ws.owner, { name: "Not for carol", url: fake.url("key"), authType: "apikey", credentialMode: "per_member", access: { orgWide: false, memberIds: [bobId], teamIds: [] } });
  const b = await api(carol, "PUT", `/v1/mcp-connections/${ungranted.json.id}/my-credential`, { apiKey: fake.key });
  return (a.status === 400 && b.status === 403) || `${a.status} ${b.status}`;
});

// ---------- catalog, discovery ----------
await s.t("the catalog lists the preset servers with their addresses", async () => {
  const r = await api(bob, "GET", "/v1/mcp-connections/presets");
  const ids = r.json.presets.map((p) => p.presetId);
  const notion = r.json.presets.find((p) => p.presetId === "notion");
  const github = r.json.presets.find((p) => p.presetId === "github");
  return (r.status === 200 && ids.length === 11 && notion.url === "https://mcp.notion.com/mcp" && notion.authType === "oauth" && github.requiresOAuthClient === true && /oauth\/callback$/.test(github.oauthCallbackUrl) && ids.includes("context7") && ids.includes("exa")) || `${r.status} ${ids.join()}`;
});
await s.t("discover tells what a server needs: OAuth with dynamic registration, or no sign-in with its tools", async () => {
  const o = await api(bob, "POST", "/v1/mcp-connections/discover", { url: fake.url("oauth") });
  const n = await api(bob, "POST", "/v1/mcp-connections/discover", { url: fake.url("none") });
  return (o.status === 200 && o.json.status === "ready" && o.json.server.initialize === "authentication_required" && o.json.authentication.kind === "oauth" && o.json.authentication.recommendedRegistrationMethod === "dynamic"
    && o.json.authentication.authorizationServers[0].issuer === fake.origin && o.json.tools.visibility === "requires_auth"
    && n.json.status === "ready" && n.json.server.initialize === "succeeded" && n.json.authentication.kind === "none" && n.json.tools.count === 3 && n.json.tools.items[0].name === "echo") || `${o.status} ${o.text.slice(0, 300)} / ${n.text.slice(0, 300)}`;
});
await s.t("discover registers nothing and saves nothing", async () => !fake.calls.some((c) => c.kind === "authorize"));
await s.t("discover validates the url (400) and needs a signed-in member (401)", async () => {
  const bad = await api(bob, "POST", "/v1/mcp-connections/discover", { url: "ftp://x" });
  const anon = await call(A, "/v1/mcp-connections/discover", { method: "POST", body: { url: fake.url("none") } });
  return (bad.status === 400 && anon.status === 401) || `${bad.status} ${anon.status}`;
});
await s.t("discover/stream sends ordered check events and then the result", async () => {
  const r = await api(ws.owner, "POST", "/v1/mcp-connections/discover/stream", { url: fake.url("none") });
  const events = [...r.text.matchAll(/event: (\w+)\ndata: (.*)\n/g)].map((m) => [m[1], JSON.parse(m[2])]);
  const checks = events.filter((e) => e[0] === "check").map((e) => `${e[1].id}:${e[1].status}`);
  return (r.status === 200 && checks[0] === "server:running" && checks.includes("server:passed") && events.at(-1)[0] === "result" && events.at(-1)[1].status === "ready") || `${r.status} ${r.text.slice(0, 300)}`;
});
await s.t("resolve (managers only) finds a server from its address; a member is refused (403 connections.manage)", async () => {
  const r = await api(ws.owner, "POST", "/v1/mcp-connections/resolve", { query: fake.url("none") });
  const m = await api(bob, "POST", "/v1/mcp-connections/resolve", { query: "x" });
  return (r.status === 200 && r.json.resolution === "discovered" && r.json.match.url === fake.url("none") && FORBIDDEN_PERM(m, "connections.manage")) || `${r.status} ${r.text.slice(0, 300)}`;
});

// ---------- agents through the gateway ----------
const gw = await workspace("Gateway Place");
const gbob = await gw.join("Gina Member");
const gconn = (await gw.api(gw.owner, "POST", "/v1/mcp-connections", { name: "Gateway none", url: fake.url("none"), authType: "none", access: { orgWide: false, memberIds: [gbob.memberId], teamIds: [] } })).json;
const gid = gconn.id;
const tokenOf = async (u, scopes) => (await gw.api(u, "POST", "/v1/mcp/token", { scopes })).json.token;
const ginTok = await tokenOf(gbob, ["mcp:read", "mcp:write"]);
const gRead = await tokenOf(gbob, ["mcp:read"]);
const gOwner = await tokenOf(gw.owner, ["mcp:read", "mcp:write"]);
const search = async (tok, query) => { const r = await call(A, "/mcp/agent", { method: "POST", bearer: tok, headers: { accept: "application/json, text/event-stream" }, body: { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "search_capabilities", arguments: { query } } } }); const o = sc(r); return (o.matches ?? o.capabilities ?? []).map((m) => m.name ?? m.id); };
const exec = async (tok, name, body) => { const r = await call(A, "/mcp/agent", { method: "POST", bearer: tok, headers: { accept: "application/json, text/event-stream" }, body: { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "execute_capability", arguments: { name, body } } } }); return result(r); };
const errorOf = (res) => { try { return JSON.parse(res.content[0].text).error; } catch { return res.content?.[0]?.text; } };
await s.t("an agent searching finds the granted connection's tools by the reference's ids (mcp:<connectionId>:<tool>)", async () => {
  const ids = await search(ginTok, "echo");
  return ids.includes(`mcp:${gid}:echo`) || ids.join();
});
await s.t("a person without a grant finds none of them (an admin gets nothing by being an admin)", async () => !(await search(gOwner, "echo")).some((id) => id.startsWith(`mcp:${gid}:`)));
await s.t("running a found tool returns the server's own result unchanged", async () => {
  const r = await exec(ginTok, `mcp:${gid}:echo`, { message: "hello" });
  return (r.isError !== true && r.content?.[0]?.text === "echo: hello" && r.structuredContent?.echoed === "hello") || JSON.stringify(r).slice(0, 300);
});
await s.t("running needs the write scope", async () => { const r = await exec(gRead, `mcp:${gid}:echo`, { message: "hello" }); return (r.isError === true && /insufficient_(mcp_)?scope/.test(errorOf(r))) || JSON.stringify(r).slice(0, 300); });
await s.t("running a tool without a grant is forbidden, and the server is not asked", async () => {
  fake.reset();
  const r = await exec(gOwner, `mcp:${gid}:echo`, { message: "x" });
  return (r.isError === true && errorOf(r) === "forbidden" && fake.mcpCalls(undefined, "tools/call").length === 0) || JSON.stringify(r).slice(0, 300);
});
await s.t("a tool the policy switched off is hidden from search and refused at execution", async () => {
  await gw.api(gw.owner, "PUT", `/v1/mcp-connections/${gid}/tool-policy`, { allDisabled: false, disabledTools: ["delete_everything"] });
  fake.reset();
  const ids = await search(ginTok, "dangerous");
  const r = await exec(ginTok, `mcp:${gid}:delete_everything`, {});
  return (!ids.includes(`mcp:${gid}:delete_everything`) && r.isError === true && errorOf(r) === "policy_blocked" && !fake.calls.some((c) => c.tool === "delete_everything")) || `${ids.join()} ${JSON.stringify(r).slice(0, 200)}`;
});
await s.t("an unknown tool and an unknown connection are refused as unknown_capability", async () => {
  const a = await exec(ginTok, `mcp:${gid}:nope`, {});
  const b = await exec(ginTok, "mcp:emc_01m6798bqbeaeagm9dmr8grtrt:echo", {});
  return (errorOf(a) === "unknown_capability" && errorOf(b) === "unknown_capability") || `${JSON.stringify(a).slice(0, 150)} ${JSON.stringify(b).slice(0, 150)}`;
});
await s.t("another workspace's person cannot use this workspace's connection id", async () => {
  const outsider = await ws.join("Zed Outsider").catch(() => null);
  const strangerWs = await workspace("Stranger Place");
  const tok = await strangerWs.api(strangerWs.owner, "POST", "/v1/mcp/token", { scopes: ["mcp:read", "mcp:write"] });
  const r = await exec(tok.json.token, `mcp:${gid}:echo`, { message: "x" });
  return (r.isError === true && ["unknown_capability", "forbidden"].includes(errorOf(r)) && !!outsider) || JSON.stringify(r).slice(0, 300);
});
await s.t("a per-person OAuth connection a person has not signed in to shows up as one needs-connection entry, not tools", async () => {
  await gw.api(gw.owner, "POST", "/v1/mcp-connections", { name: "Gateway oauth", url: fake.url("oauth"), authType: "oauth", credentialMode: "per_member" });
  const ids = await search(ginTok, "oauth");
  return ids.some((id) => /^mcp:emc_[0-9a-z]{26}:\*$/.test(id)) || ids.join();
});
await s.t("removing a connection removes its tools from agents at once", async () => {
  await gw.api(gw.owner, "DELETE", `/v1/mcp-connections/${gid}`);
  const r = await exec(ginTok, `mcp:${gid}:echo`, { message: "x" });
  return (r.isError === true && errorOf(r) === "unknown_capability") || JSON.stringify(r).slice(0, 200);
});

await fake.close();
s.done();
