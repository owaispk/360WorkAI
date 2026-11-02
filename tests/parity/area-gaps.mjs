// Contract tests for the "gaps" that were left inside areas that already exist. One script, one section per part:
//   1 plugin-connections  plugins that need MCP connections: bindings, requiredBy, readiness
//   2 oauth-providers     organization-owned OAuth apps
//   3 team-invites        inviting a person into a team
//   4 small-routes        memory, artifact views, direct uploads, MCP apps, webhooks
// Runs unchanged against the reference Den and the rewrite:
//   node area-gaps.mjs                                                      # reference: web :3005, api :8790
//   W=http://localhost:5284 A=http://localhost:5184 node area-gaps.mjs      # rewrite (start it with Connections__AllowPrivateUrls=true)
//   ONLY=1,3 node area-gaps.mjs                                             # only some sections
// Both servers must allow private addresses (the reference does in dev mode) because the fake MCP server listens on loopback.
import { call, A, W, workspace, person, suite, denied, keys, PW } from "./lib.mjs";
import { startFake } from "./fake-mcp.mjs";

const s = suite("gaps");
const t = (name, fn) => s.t(name, fn);
const only = (process.env.ONLY ?? "1,2,3,4").split(",");
const want = (n) => only.includes(String(n));
const ok = (r, status, extra) => (r.status === status && (extra ? extra(r.json) : true)) || `${r.status} ${r.text.slice(0, 300)}`;
const NOPE = (p) => `${p}_01m6797hhce34acegcde4y57bd`;
const skillText = (name) => `---\nname: ${name}\ndescription: A skill\n---\n\nBody of ${name}.\n`;

// =====================================================================================================================================
// 1. plugin-connections
// =====================================================================================================================================
if (want(1)) {
  const fake = await startFake();
  const ws = await workspace("Gaps Plugin Connections");
  const bob = await ws.join("Bob Member");
  const carol = await ws.join("Carol Member");
  const other = await workspace("Gaps Plugin Connections Other");
  const api = ws.api;
  const bobId = bob.memberId;
  // Servers with the same address share one connection, so every plugin gets its own address unless the address already carries a "?".
  let n = 0;
  const mcp = (url0, extra = {}, name = "docs") => {
    const url = url0.includes("?") || url0.startsWith("http://127.0.0.1:9/") ? url0 : `${url0}?t=${++n}`;
    return { type: "mcp", input: { rawSourceText: JSON.stringify({ mcpServers: { [name]: { type: "remote", url, ...extra } } }), normalizedPayloadJson: { mcpServers: { [name]: { type: "remote", url, ...extra } } }, metadata: { name: "Docs MCP" } } };
  };
  const KEYED = `${fake.url("key")}?t=keyed`;
  const skill = (n = "s1") => ({ type: "skill", input: { rawSourceText: skillText(n) } });
  const mkPlugin = async (name, components, extra = {}, who = ws.owner, w = ws) => {
    const r = await w.api(who, "POST", "/v1/plugins", { name, components, ...extra });
    if (r.status !== 201) throw new Error(`plugin ${name}: ${r.status} ${r.text.slice(0, 200)}`);
    return r.json.item.id;
  };
  const cobOf = async (pid) => (await api(ws.owner, "GET", `/v1/plugins/${pid}/config-objects`)).json.items.find((i) => i.configObject.objectType === "mcp").configObjectId;
  const configure = (who, pid, cob, body = {}) => api(who, "POST", `/v1/plugins/${pid}/mcp-connections`, { configObjectId: cob, serverName: "docs", authType: "none", ...body });
  const manageable = async () => (await api(ws.owner, "GET", "/v1/mcp-connections?scope=manageable")).json.connections;
  const usable = async (who) => (await api(who, "GET", "/v1/mcp-connections?scope=usable")).json.connections;
  const SHAPE = (j) => j.ok === true && keys(j.item) === "binding,connection,links" && keys(j.item.binding) === "configObjectId,externalMcpConnectionId,id,pluginId,serverName"
    && keys(j.item.connection) === "authType,connected,connectedAt,credentialMode,id,name,url" && typeof j.item.links.yourConnections === "string";

  // ---- configuring a server a plugin declares ----
  const p1 = await mkPlugin("Docs plugin", [skill(), mcp(fake.url("none"))]);
  const c1 = await cobOf(p1);
  let first;
  await t("[1] configure a no-sign-in server: 200, the reference's shape, a binding id, the connection is named 'plugin / server' and is connected", async () => {
    const r = await configure(ws.owner, p1, c1); first = r.json;
    return ok(r, 200, (j) => SHAPE(j) && /^pmr_[0-9a-z]{26}$/.test(j.item.binding.id) && j.item.connection.name === "Docs plugin / docs" && j.item.connection.connected === true
      && j.item.connection.authType === "none" && j.item.connection.credentialMode === "shared" && j.item.binding.serverName === "docs" && j.item.binding.pluginId === p1
      && /\/dashboard\/your-connections\?connectionId=emc_/.test(j.item.links.yourConnections));
  });
  await t("[1] the server was really asked (initialize reached the fake)", async () => fake.mcpCalls("none", "initialize").length >= 1);
  await t("[1] the connection is listed with requiredBy, identityManagedBy and requiredAuthType", async () => {
    const c = (await manageable()).find((x) => x.id === first.item.connection.id);
    return (c && c.requiredBy.length === 1 && c.requiredBy[0].pluginId === p1 && c.requiredBy[0].name === "Docs plugin" && c.identityManagedBy.length === 1 && c.requiredAuthType === "none"
      && c.authTypeMismatch === false && c.setupRequired === false && c.access.orgWide === false) || JSON.stringify(c);
  });
  await t("[1] configuring again reuses the same binding and connection", async () => {
    const r = await configure(ws.owner, p1, c1);
    return ok(r, 200, (j) => j.item.binding.id === first.item.binding.id && j.item.connection.id === first.item.connection.id);
  });
  await t("[1] a member cannot configure (403 connections.manage)", async () => denied(await configure(bob, p1, c1), "connections.manage") || "not denied");

  await t("[1] validation: missing configObjectId, bad authType, bad serverName, bad plugin id are 400 invalid_request", async () => {
    const a = await api(ws.owner, "POST", `/v1/plugins/${p1}/mcp-connections`, { serverName: "docs", authType: "none" });
    const b = await configure(ws.owner, p1, c1, { authType: "bogus" });
    const c = await configure(ws.owner, p1, c1, { serverName: "" });
    const d = await api(ws.owner, "POST", "/v1/plugins/bad/mcp-connections", { configObjectId: c1, serverName: "docs" });
    return (a.status === 400 && a.json.error === "invalid_request" && a.json.message.startsWith("configObjectId:") && b.status === 400 && b.json.message === 'authType: Invalid option: expected one of "oauth"|"apikey"|"none"'
      && c.status === 400 && c.json.error === "invalid_request" && d.status === 400 && d.json.message.startsWith("pluginId:")) || [a, b, c, d].map((x) => x.status + x.text.slice(0, 100)).join(" | ");
  });
  await t("[1] an unknown config object, a skill, a server name that is not declared: 404 with the reference's codes", async () => {
    const skillCob = (await api(ws.owner, "GET", `/v1/plugins/${p1}/config-objects`)).json.items.find((i) => i.configObject.objectType === "skill").configObjectId;
    const a = await configure(ws.owner, p1, NOPE("cob"));
    const b = await configure(ws.owner, p1, skillCob);
    const c = await configure(ws.owner, p1, c1, { serverName: "nope" });
    return (a.status === 404 && a.json.error === "mcp_requirement_not_found" && a.json.message === "Active plugin MCP requirement not found." && b.status === 404 && b.json.error === "mcp_requirement_not_found"
      && c.status === 404 && c.json.error === "mcp_server_not_found" && c.json.message === "MCP server declaration not found on this config object.") || [a, b, c].map((x) => x.status + x.text.slice(0, 100)).join(" | ");
  });
  await t("[1] another workspace's plugin is 404 mcp_requirement_not_found (nothing about it leaks)", async () => {
    const op = await mkPlugin("Their plugin", [mcp(fake.url("none"))], {}, other.owner, other);
    const ocob = (await other.api(other.owner, "GET", `/v1/plugins/${op}/config-objects`)).json.items[0].configObjectId;
    const r = await configure(ws.owner, op, ocob);
    const r2 = await configure(ws.owner, p1, ocob);
    return (r.status === 404 && r.json.error === "mcp_requirement_not_found" && r2.status === 404 && r2.json.error === "mcp_requirement_not_found") || `${r.status} ${r2.status}`;
  });
  await t("[1] sign-in rules: apiKey needs authType apikey and shared mode; a key is refused for none; oauthClient only for oauth (invalid_mcp_auth)", async () => {
    const a = await configure(ws.owner, p1, c1, { apiKey: "x" });
    const b = await configure(ws.owner, p1, c1, { authType: "apikey", credentialMode: "per_member", apiKey: "x" });
    const c = await configure(ws.owner, p1, c1, { authType: "none", oauthClient: { clientId: "abc" } });
    const d = await configure(ws.owner, p1, c1, { authType: "none", credentialMode: "per_member" });
    return (a.status === 400 && a.json.error === "invalid_mcp_auth" && a.json.message === "apiKey is only allowed when authType is apikey."
      && b.json.error === "invalid_mcp_auth" && b.json.message === "authType apikey requires credentialMode shared."
      && c.json.error === "invalid_mcp_auth" && c.json.message === "oauthClient is only allowed when authType is oauth."
      && d.json.error === "invalid_mcp_auth" && d.json.message === "credentialMode per_member requires authType oauth.") || [a, b, c, d].map((x) => x.status + x.text.slice(0, 120)).join(" | ");
  });
  await t("[1] a server that declares oauth cannot be set up with no sign-in (409 mcp_auth_type_mismatch)", async () => {
    const p = await mkPlugin("OAuth declared", [mcp(fake.url("oauth"), { oauth: true })]);
    const r = await configure(ws.owner, p, await cobOf(p), { authType: "none" });
    return ok(r, 409, (j) => j.error === "mcp_auth_type_mismatch" && j.message === "This MCP requirement must use oauth authentication.");
  });
  await t("[1] a server with a credential in its address is refused (400 invalid_mcp_url)", async () => {
    const p = await mkPlugin("Query token", [mcp(`${fake.url("none")}?token=abc`)]);
    const r = await configure(ws.owner, p, await cobOf(p));
    return ok(r, 400, (j) => j.error === "invalid_mcp_url" && j.message === 'MCP URL query parameter "token" must not contain credentials.');
  });
  await t("[1] an archived plugin cannot be configured (404 mcp_requirement_not_found)", async () => {
    const p = await mkPlugin("Soon archived", [mcp(fake.url("none"), {}, "docs")]);
    const cob = await cobOf(p);
    await api(ws.owner, "POST", `/v1/plugins/${p}/archive`, {});
    return ok(await configure(ws.owner, p, cob), 404, (j) => j.error === "mcp_requirement_not_found");
  });

  // ---- API keys ----
  const pk = await mkPlugin("Keyed plugin", [mcp(KEYED)]);
  const ck = await cobOf(pk);
  let keyed;
  await t("[1] an API-key server with no key waits for it: not connected, a plugin_connection_key prompt, never asks for the key in chat", async () => {
    const r = await configure(ws.owner, pk, ck, { authType: "apikey" }); keyed = r.json;
    return ok(r, 200, (j) => SHAPE(j) && j.item.connection.connected === false && j.credentialPrompt?.kind === "credential_prompt" && j.credentialPrompt.target.type === "plugin_connection_key"
      && j.credentialPrompt.target.pluginId === pk && j.credentialPrompt.target.configObjectId === ck && j.credentialPrompt.target.serverName === "docs" && j.credentialPrompt.target.connectionId === j.item.connection.id
      && j.credentialPrompt.name === "Keyed plugin / docs" && /Never ask them to paste the key in chat/.test(j.nextStep));
  });
  await t("[1] a wrong key is refused (400 credential_rejected) without echoing it, and no connection is left over", async () => {
    const before = (await manageable()).length;
    const r = await configure(ws.owner, pk, ck, { authType: "apikey", apiKey: "wrongkey-123" });
    const after = (await manageable()).length;
    return (r.status === 400 && r.json.error === "credential_rejected" && r.json.message === "Keyed plugin / docs did not accept this key." && !r.text.includes("wrongkey-123") && after === before) || `${r.status} ${r.text.slice(0, 200)} ${before}/${after}`;
  });
  let keyedOk;
  await t("[1] the right key is saved: connected, the key is never returned, the key reached the server", async () => {
    const r = await configure(ws.owner, pk, ck, { authType: "apikey", apiKey: fake.key }); keyedOk = r.json;
    const list = await api(ws.owner, "GET", "/v1/mcp-connections?scope=manageable");
    return ok(r, 200, (j) => SHAPE(j) && j.item.connection.connected === true && j.credentialPrompt === undefined && !r.text.includes(fake.key) && !list.text.includes(fake.key))
      && fake.mcpCalls("key", "initialize").some((c) => c.auth === `Bearer ${fake.key}`);
  });
  await t("[1] the binding moved to the connection that has the key; the waiting one is gone", async () => {
    const all = await manageable();
    return (!all.some((c) => c.id === keyed.item.connection.id) && all.some((c) => c.id === keyedOk.item.connection.id)) || "old connection still listed";
  });
  await t("[1] an API-key connection a plugin owns refuses a new shared key (409 marketplace_managed) and a changed address, but may be renamed", async () => {
    const id = keyedOk.item.connection.id;
    const a = await api(ws.owner, "PUT", `/v1/mcp-connections/${id}/shared-credential`, { apiKey: fake.key });
    const g = (await api(ws.owner, "GET", `/v1/mcp-connections/${id}`)).json;
    const base = { name: "Renamed", url: g.url, authType: "apikey", credentialMode: "shared", expectedUpdatedAt: g.updatedAt, access: { orgWide: false, memberIds: [], teamIds: [] } };
    const b = await api(ws.owner, "PUT", `/v1/mcp-connections/${id}`, { ...base, url: g.url + "x" });
    const c = await api(ws.owner, "PUT", `/v1/mcp-connections/${id}`, base);
    return (a.status === 409 && a.json.error === "marketplace_managed" && a.json.message === "A marketplace plugin manages this connection's key. Change it in the marketplace definition."
      && b.status === 409 && b.json.error === "marketplace_managed" && b.json.message === "Keyed plugin owns this connection's server and authentication settings. Edit those values in the marketplace definition."
      && c.status === 200 && c.json.name === "Renamed") || [a, b, c].map((x) => x.status + x.text.slice(0, 160)).join(" | ");
  });
  await t("[1] a second plugin with the same server and key shares the connection; requiredBy lists both, only the first owns its identity", async () => {
    const p = await mkPlugin("Second keyed", [mcp(KEYED)]);
    const r = await configure(ws.owner, p, await cobOf(p), { authType: "apikey", apiKey: fake.key });
    const c = (await manageable()).find((x) => x.id === keyedOk.item.connection.id);
    return (r.status === 200 && r.json.item.connection.id === keyedOk.item.connection.id && c.requiredBy.map((x) => x.name).join() === "Keyed plugin,Second keyed" && c.identityManagedBy.map((x) => x.name).join() === "Keyed plugin") || JSON.stringify(c);
  });

  // ---- who may use a connection through a plugin; what they may learn ----
  const pa = await mkPlugin("Shared plugin", [mcp(fake.url("none"), {}, "docs")]);
  const ca = await cobOf(pa);
  const connA = (await configure(ws.owner, pa, ca)).json.item.connection.id;
  await t("[1] before the plugin is shared, a member has no use of the connection and sees no plugin names", async () => {
    const u = await usable(bob);
    return !u.some((c) => c.id === connA) || "visible";
  });
  await t("[1] sharing the plugin with everyone makes the connection usable and names the plugin; the owner's other (unshared) plugin stays unnamed", async () => {
    const hidden = await mkPlugin("Hidden plugin", [mcp(fake.url("none"), {}, "docs")]);
    await configure(ws.owner, hidden, await cobOf(hidden));
    await api(ws.owner, "POST", `/v1/plugins/${pa}/access`, { orgWide: true, role: "viewer" });
    const c = (await usable(bob)).find((x) => x.id === connA);
    return (c && c.requiredBy.map((x) => x.name).join() === "Shared plugin" && c.access === null) || JSON.stringify(c);
  });
  await t("[1] a member may list the tools of it through use (it is usable) but cannot list all connections", async () => {
    const r = await api(bob, "GET", "/v1/mcp-connections?scope=manageable");
    return r.status === 403;
  });
  await t("[1] archiving the plugin withdraws the use at once and retires the connection it made from the lists; restoring brings both back", async () => {
    await api(ws.owner, "POST", `/v1/plugins/${pa}/archive`, {});
    const c = (await usable(bob)).find((x) => x.id === connA);
    const owner = (await manageable()).find((x) => x.id === connA);
    await api(ws.owner, "POST", `/v1/plugins/${pa}/restore`, {});
    const back = (await usable(bob)).find((x) => x.id === connA);
    const restored = (await manageable()).find((x) => x.id === connA);
    return (!c && !owner && back && restored && restored.requiredBy.length >= 1) || JSON.stringify({ c, owner: owner?.requiredBy, back: Boolean(back) });
  });
  await t("[1] sharing with a team reaches only its members (and not a person outside)", async () => {
    const p = await mkPlugin("Team plugin", [mcp(fake.url("none"), {}, "docs")]);
    const cid = (await configure(ws.owner, p, await cobOf(p))).json.item.connection.id;
    const team = (await api(ws.owner, "POST", "/v1/teams", { name: "Gaps readers", memberIds: [carol.memberId] })).json.team.id;
    await api(ws.owner, "POST", `/v1/plugins/${p}/access`, { teamId: team, role: "viewer" });
    const inTeam = (await usable(carol)).some((c) => c.id === cid);
    const outside = (await usable(bob)).some((c) => c.id === cid);
    return (inTeam && !outside) || `${inTeam} ${outside}`;
  });

  // ---- deleting a connection ----
  await t("[1] deleting a connection removes the binding: the plugin needs setup again", async () => {
    const mk = (await api(ws.owner, "POST", "/v1/marketplaces", { name: "Gaps shelf" })).json.item.id;
    const p = await mkPlugin("On the shelf", [skill("shelf-skill"), mcp(fake.url("none"), {}, "docs")], { marketplaceId: mk });
    const cob = await cobOf(p);
    const cid = (await configure(ws.owner, p, cob)).json.item.connection.id;
    const before = (await api(ws.owner, "GET", `/v1/marketplaces/${mk}/resolved`)).json.item.plugins.find((x) => x.id === p).cloudReadiness;
    const del = await api(ws.owner, "DELETE", `/v1/mcp-connections/${cid}`);
    const after = (await api(ws.owner, "GET", `/v1/marketplaces/${mk}/resolved`)).json.item.plugins.find((x) => x.id === p).cloudReadiness;
    return (del.status === 200 && before.state === "ready" && after.state === "ready" === false && after.connections[0].id === null) || JSON.stringify({ before: before.state, after });
  });

  // ---- inline connections when a plugin is created ----
  await t("[1] components[].connection: the plugin is made and its server is configured in one step", async () => {
    const r = await api(ws.owner, "POST", "/v1/plugins", { name: "Inline none", components: [skill("inline-skill"), mcp(fake.url("none"), {}, "docs")].map((c, i) => (i === 1 ? { ...c, connection: { authType: "none" } } : c)) });
    const pid = r.json?.item?.id;
    const c = (await manageable()).find((x) => x.name === "Inline none / docs");
    return (r.status === 201 && c && c.connected === true && c.requiredBy.some((x) => x.pluginId === pid)) || `${r.status} ${r.text.slice(0, 200)}`;
  });
  await t("[1] components[].connection with a rejected key: 400 credential_rejected and no plugin is left behind", async () => {
    const r = await api(ws.owner, "POST", "/v1/plugins", { name: "Inline bad key", components: [{ ...mcp(fake.url("key")), connection: { authType: "apikey", apiKey: "nope-nope" } }] });
    const list = await api(ws.owner, "GET", "/v1/plugins?q=Inline%20bad%20key");
    return (r.status === 400 && r.json.error === "credential_rejected" && !(list.json.items ?? []).some((p) => p.name === "Inline bad key" && p.status === "active")) || `${r.status} ${r.text.slice(0, 200)} ${list.text.slice(0, 100)}`;
  });
  await t("[1] components[].connection validation: apikey without a key is 400 invalid_mcp_auth; on a skill, or with connectionId, is 400 invalid_request", async () => {
    const a = await api(ws.owner, "POST", "/v1/plugins", { name: "Inline nokey", components: [{ ...mcp(fake.url("key")), connection: { authType: "apikey" } }] });
    const b = await api(ws.owner, "POST", "/v1/plugins", { name: "Inline skill conn", components: [{ ...skill("x1"), connection: { authType: "none" } }] });
    const c = await api(ws.owner, "POST", "/v1/plugins", { name: "Inline both", components: [{ type: "mcp", connection: { authType: "none" }, connectionId: "emc_x" }] });
    const d = await api(ws.owner, "POST", "/v1/plugins", { name: "Inline neither", components: [{ type: "mcp" }] });
    return (a.status === 400 && a.json.error === "invalid_mcp_auth" && a.json.message === "authType apikey requires apiKey."
      && b.status === 400 && b.json.message === "components.0.connection: connection is only allowed on mcp components."
      && c.status === 400 && c.json.message === "components.0.connectionId: Provide either connection or connectionId, not both."
      && d.status === 400 && d.json.message === "components.0.input: input is required unless connectionId is provided.") || [a, b, c, d].map((x) => x.status + x.text.slice(0, 140)).join(" | ");
  });
  await t("[1] a member may not configure a connection while creating a plugin (403)", async () => {
    const r = await api(bob, "POST", "/v1/plugins", { name: "Bob inline", components: [{ ...mcp(fake.url("none")), connection: { authType: "none" } }] });
    return ok(r, 403, (j) => j.error === "forbidden" && j.message === "Only organization owners and admins can configure plugin MCP connections.");
  });
  let backedPlugin;
  await t("[1] components[].connectionId: the component points at an existing connection (name, address, managed payload) and the binding is not owned by the plugin", async () => {
    const r = await api(ws.owner, "POST", "/v1/plugins", { name: "By id", components: [{ type: "mcp", connectionId: connA }] });
    backedPlugin = r.json?.item?.id;
    const objs = await api(ws.owner, "GET", `/v1/plugins/${backedPlugin}/config-objects`);
    const o = objs.json.items?.[0]?.configObject;
    const payload = o?.latestVersion?.normalizedPayloadJson;
    const c = (await manageable()).find((x) => x.id === connA);
    return (r.status === 201 && o.title === "Docs plugin / docs".replace("Docs plugin", "Shared plugin") && payload.externalMcpConnectionId === connA && payload.externalMcpConnectionOwnedByPlugin === false
      && payload.requiredAuthType === "none" && Object.values(payload.mcpServers)[0].url === c.url && c.requiredBy.some((x) => x.pluginId === backedPlugin) && !c.identityManagedBy.some((x) => x.pluginId === backedPlugin)) || `${r.status} ${r.text.slice(0, 200)} ${JSON.stringify(payload)}`;
  });
  await t("[1] connectionId: unknown connection is 404 mcp_connection_not_found; a member may bind only a connection they made", async () => {
    const a = await api(ws.owner, "POST", "/v1/plugins", { name: "By bad id", components: [{ type: "mcp", connectionId: NOPE("emc") }] });
    const b = await api(bob, "POST", "/v1/plugins", { name: "Bob by id", components: [{ type: "mcp", connectionId: connA }] });
    return (a.status === 404 && a.json.error === "mcp_connection_not_found" && a.json.message === "That connector was not found in this organization."
      && b.status === 403 && b.json.message === "Only organization owners and admins can bind plugin MCP servers to organization connections.") || [a, b].map((x) => x.status + x.text.slice(0, 160)).join(" | ");
  });

  // ---- readiness of plugins on a marketplace ----
  await t("[1] cloudReadiness on a marketplace's plugins: ready / needs_admin_setup / needs_signin / skill-only, with the reference's connection entries", async () => {
    const mk = (await api(ws.owner, "POST", "/v1/marketplaces", { name: "Readiness shelf" })).json.item.id;
    const unset = await mkPlugin("Unset", [skill("u-skill"), mcp("http://127.0.0.1:9/unset/mcp", {}, "unset")], { marketplaceId: mk });
    const done = await mkPlugin("Done", [mcp(fake.url("none"), {}, "docs")], { marketplaceId: mk });
    await configure(ws.owner, done, await cobOf(done));
    const signin = await mkPlugin("Signin", [mcp(fake.url("oauth"), { oauth: true })], { marketplaceId: mk });
    await configure(ws.owner, signin, await cobOf(signin), { authType: "oauth" });
    const onlySkill = await mkPlugin("Only skill", [skill("o-skill")], { marketplaceId: mk });
    const res = (await api(ws.owner, "GET", `/v1/marketplaces/${mk}/resolved`)).json.item.plugins;
    const r = (id) => res.find((x) => x.id === id).cloudReadiness;
    const u = r(unset), d = r(done), si = r(signin), o = r(onlySkill);
    return (u.state === "needs_admin_setup" && u.hasInstructional === true && u.connections.length === 1 && u.connections[0].id === null && u.connections[0].serverName === "unset" && u.connections[0].url === "http://127.0.0.1:9/unset/mcp" && keys(u.connections[0]) === "configObjectId,id,name,serverName,url"
      && d.state === "ready" && d.hasInstructional === false && d.connections[0].connectedForMe === true && d.connections[0].credentialMode === "shared" && d.connections[0].authType === "none" && d.connections[0].authTypeMismatch === false
      && si.state === "needs_signin" && si.connections[0].connectedForMe === false && si.connections[0].credentialMode === "per_member" && si.connections[0].requiredAuthType === "oauth" && si.connections[0].oauthClientConfigured === false
      && o.state === "ready" && o.hasInstructional === true && o.connections.length === 0) || JSON.stringify({ u, d, si, o });
  });

  await fake.close();
}

s.done();
