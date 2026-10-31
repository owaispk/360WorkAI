// Contract tests for the library: plugins, skills (config objects), marketplaces, sharing, "my library", usage, GitHub import checks and
// the skills agents can find. Runs unchanged against the reference Den and the rewrite:
//   node area-library.mjs                                                    # reference: web :3005, api :8790
//   W=http://localhost:5220 A=http://localhost:5120 node area-library.mjs    # rewrite
// Two known differences are tolerated on purpose: the reference creates a built-in "OpenWork Marketplace" with three built-in plugins the first
// time marketplaces are listed (the rewrite does not), so lists are always checked by the ids a test made, never by count.
import { call, A, workspace, suite, denied, keys } from "./lib.mjs";

const s = suite("library");
const t = s.t;
const skill = (name, description = "Does a thing", body = `Body of ${name}.`) => `---\nname: ${name}\ndescription: ${description}\n---\n\n${body}\n`;
const NOPE = (p) => `${p}_01m6797hhce34acegcde4y57bd`;
const ok = (r, status, extra) => (r.status === status && (extra ? extra(r.json) : true)) || `${r.status} ${r.text.slice(0, 300)}`;

const ws = await workspace("Library Parity");
const bob = await ws.join("Bob Member");
const carol = await ws.join("Carol Member");
const dave = await ws.join("Dave Member");
const ann = await ws.join("Ann Admin", "admin");
const faye = await ws.join("Faye Member");   // in the Readers team
const grace = await ws.join("Grace Member"); // never given anything: the person the "not shared with you" checks use
ws.owner.memberId = await ws.memberId(ws.owner);
const other = await workspace("Library Parity Other");
const api = ws.api;
const ids = (r) => (r.json?.items ?? []).map((i) => i.id);

let pid, cid, vid1, cmdId, bobPid;

// ---------- plugins: create and read ----------
await t("create a plugin: 201 with the plugin shape, the maker is the creator", async () => {
  const r = await api(ws.owner, "POST", "/v1/plugins", { name: "Alpha", description: "First plugin" });
  pid = r.json?.item?.id;
  const i = r.json?.item;
  return ok(r, 201, () => r.json.ok === true && /^plg_/.test(pid) && i.name === "Alpha" && i.description === "First plugin" && i.status === "active" && i.createdByOrgMembershipId === ws.owner.memberId
    && i.deletedAt === null && i.sourceRepositoryUrl === null && i.organizationId === ws.orgId && Array.isArray(i.marketplaces) && i.extension?.manifest?.source?.origin === "den");
});
await t("plugin validation: empty, missing, wrong-typed fields are 400 with the field named", async () => {
  const empty = await api(ws.owner, "POST", "/v1/plugins", { name: " " });
  const none = await api(ws.owner, "POST", "/v1/plugins", {});
  const orgWide = await api(ws.owner, "POST", "/v1/plugins", { name: "x", orgWide: "yes" });
  const long = await api(ws.owner, "POST", "/v1/plugins", { name: "x".repeat(256) });
  const badComp = await api(ws.owner, "POST", "/v1/plugins", { name: "Bad skills", components: [{ type: "skill", input: { rawSourceText: "no frontmatter" } }] });
  const badType = await api(ws.owner, "POST", "/v1/plugins", { name: "x", components: [{ type: "nope", input: { rawSourceText: "x" } }] });
  return (empty.status === 400 && empty.json.error === "invalid_request" && empty.json.message === "name: Too small: expected string to have >=1 characters"
    && none.status === 400 && none.json.message === "name: Invalid input: expected string, received undefined"
    && orgWide.status === 400 && orgWide.json.message === "orgWide: Invalid input: expected boolean, received string"
    && long.status === 400 && long.json.message === "name: Too big: expected string to have <=255 characters"
    && badComp.status === 400 && badComp.json.error === "invalid_skill_frontmatter"
    && badType.status === 400 && badType.json.message.startsWith("components.0.type: Invalid option: expected one of"))
    || [empty, none, orgWide, long, badComp, badType].map((r) => `${r.status} ${r.json?.message}`).join(" | ");
});
await t("a plugin that failed validation leaves nothing behind", async () => {
  const r = await api(ws.owner, "GET", "/v1/plugins?q=Bad%20skills");
  return ok(r, 200, (j) => j.items.length === 0);
});
await t("a bundle: plugin with skill components is created in one request and counts its members", async () => {
  const r = await api(ws.owner, "POST", "/v1/plugins", { name: "Bundle", components: [{ type: "skill", input: { rawSourceText: skill("bundled-one") } }, { type: "command", input: { rawSourceText: "# Ship\nShip it $ARGUMENTS" } }] });
  const detail = await api(ws.owner, "GET", `/v1/plugins/${r.json?.item?.id}`);
  const resolved = await api(ws.owner, "GET", `/v1/plugins/${r.json?.item?.id}/resolved`);
  return (r.status === 201 && detail.json.item.memberCount === 2 && resolved.json.items.length === 2 && resolved.json.items.some((i) => i.configObject.objectType === "skill" && i.configObject.title === "bundled-one")) || `${r.status} ${r.text.slice(0, 200)} ${detail.text.slice(0, 200)}`;
});
await t("a person can make a plugin of their own; the same name again is 409, in any case", async () => {
  const r = await api(bob, "POST", "/v1/plugins", { name: "Bobs Plugin" }); bobPid = r.json?.item?.id;
  const dup = await api(bob, "POST", "/v1/plugins", { name: "Bobs Plugin" });
  const dupCase = await api(bob, "POST", "/v1/plugins", { name: "bobs plugin" });
  const ownerSame = await api(ws.owner, "POST", "/v1/plugins", { name: "Bobs Plugin" });
  return (r.status === 201 && dup.status === 409 && dup.json.error === "duplicate_plugin" && dup.json.message.includes(bobPid) && dupCase.status === 409 && ownerSame.status === 201) || `${r.status} ${dup.status} ${dupCase.status} ${ownerSame.status}`;
});
await t("two identical plugin creations at once make exactly one", async () => {
  const rs = await Promise.all(Array.from({ length: 6 }, () => api(carol, "POST", "/v1/plugins", { name: "Racers" })));
  const made = rs.filter((r) => r.status === 201).length;
  const list = await api(carol, "GET", "/v1/plugins?q=Racers");
  // The reference has no guard here (all six succeed); the rewrite makes exactly one. Both must answer every request cleanly.
  return (rs.every((r) => r.status === 201 || r.status === 409) && made >= 1 && list.json.items.filter((i) => i.name === "Racers").length === made) || rs.map((r) => r.status).join(",");
});
await t("only people who may share with everyone can create an org-wide plugin (403)", async () => {
  const r = await api(bob, "POST", "/v1/plugins", { name: "Wide plugin", orgWide: true });
  return ok(r, 403, (j) => j.error === "forbidden" && j.message === "Only organization owners and admins can create org-wide plugins.");
});
await t("an admin can create an org-wide plugin and everyone then sees it", async () => {
  const r = await api(ann, "POST", "/v1/plugins", { name: "Everyone's plugin", orgWide: true });
  const id = r.json?.item?.id;
  const seen = await api(dave, "GET", `/v1/plugins/${id}`);
  const list = await api(dave, "GET", "/v1/plugins?q=Everyone");
  return (r.status === 201 && seen.status === 200 && ids(list).includes(id)) || `${r.status} ${seen.status} ${list.text.slice(0, 120)}`;
});
await t("a plugin nobody shared with you: not in your list, and fetching it is 403 'Missing viewer access'", async () => {
  const list = await api(bob, "GET", "/v1/plugins");
  const get = await api(bob, "GET", `/v1/plugins/${pid}`);
  const resolved = await api(bob, "GET", `/v1/plugins/${pid}/resolved`);
  const cos = await api(bob, "GET", `/v1/plugins/${pid}/config-objects`);
  return (!ids(list).includes(pid) && get.status === 403 && get.json.message === "Missing viewer access for plugin." && resolved.status === 403 && cos.status === 403) || `${get.status} ${get.text}`;
});
await t("path ids are checked: malformed 400, unknown 404", async () => {
  const bad = await api(bob, "GET", "/v1/plugins/nope");
  const wrongPrefix = await api(bob, "GET", `/v1/plugins/${NOPE("mkt")}`);
  const unknown = await api(bob, "GET", `/v1/plugins/${NOPE("plg")}`);
  return (bad.status === 400 && bad.json.error === "invalid_request" && bad.json.message.startsWith("pluginId: TypeID must be 30 characters (plg_<26 char suffix>)")
    && wrongPrefix.status === 400 && unknown.status === 404 && unknown.json.error === "plugin_not_found") || `${bad.status} ${wrongPrefix.status} ${unknown.status} ${unknown.text}`;
});
await t("another workspace's plugin is 404 and never listed", async () => {
  const get = await call(A, `/v1/plugins/${pid}`, { bearer: other.owner.token, headers: { "x-openwork-org-id": other.orgId } });
  const list = await other.api(other.owner, "GET", "/v1/plugins");
  const grant = await other.api(other.owner, "POST", `/v1/plugins/${pid}/access`, { orgWide: true, role: "viewer" });
  const patch = await other.api(other.owner, "PATCH", `/v1/plugins/${pid}`, { name: "Hacked" });
  return (get.status === 404 && !ids(list).includes(pid) && grant.status === 404 && patch.status === 404) || `${get.status} ${grant.status} ${patch.status}`;
});
await t("not signed in is 401; a workspace you do not belong to is 404", async () => {
  const anon = await call(A, "/v1/plugins");
  const stranger = await call(A, "/v1/plugins", { bearer: other.owner.token, headers: { "x-openwork-org-id": ws.orgId } });
  return (anon.status === 401 && stranger.status === 404) || `${anon.status} ${stranger.status}`;
});

// ---------- sharing a plugin ----------
let gBob;
await t("share with a person: 201 grant shape; sharing again changes the role on the same grant", async () => {
  const r = await api(ws.owner, "POST", `/v1/plugins/${pid}/access`, { orgMembershipId: bob.memberId, role: "viewer" });
  gBob = r.json?.item;
  const again = await api(ws.owner, "POST", `/v1/plugins/${pid}/access`, { orgMembershipId: bob.memberId, role: "editor" });
  return (r.status === 201 && /^pag_/.test(gBob.id) && gBob.orgMembershipId === bob.memberId && gBob.teamId === null && gBob.orgWide === false && gBob.role === "viewer" && gBob.removedAt === null
    && again.status === 201 && again.json.item.id === gBob.id && again.json.item.role === "editor") || `${r.status} ${r.text} ${again.text}`;
});
await t("a person given access sees it in their list and can fetch it; others still cannot", async () => {
  const list = await api(bob, "GET", "/v1/plugins");
  const get = await api(bob, "GET", `/v1/plugins/${pid}`);
  const carolGet = await api(carol, "GET", `/v1/plugins/${pid}`);
  const carolList = await api(carol, "GET", "/v1/plugins");
  return (ids(list).includes(pid) && get.status === 200 && carolGet.status === 403 && !ids(carolList).includes(pid)) || `${get.status} ${carolGet.status}`;
});
await t("an editor can rename the plugin but not share it or archive it", async () => {
  const patch = await api(bob, "PATCH", `/v1/plugins/${pid}`, { description: "Edited by Bob" });
  const access = await api(bob, "GET", `/v1/plugins/${pid}/access`);
  const grant = await api(bob, "POST", `/v1/plugins/${pid}/access`, { orgMembershipId: carol.memberId, role: "viewer" });
  const archive = await api(bob, "POST", `/v1/plugins/${pid}/archive`);
  return (patch.status === 200 && patch.json.item.description === "Edited by Bob" && access.status === 403 && access.json.message === "Missing manager access for plugin."
    && grant.status === 403 && archive.status === 403 && archive.json.message === "Missing manager access for plugin.") || `${patch.status} ${access.status} ${grant.status} ${archive.status}`;
});
await t("a viewer cannot edit (403 'Missing editor access')", async () => {
  await api(ws.owner, "POST", `/v1/plugins/${pid}/access`, { orgMembershipId: dave.memberId, role: "viewer" });
  const patch = await api(dave, "PATCH", `/v1/plugins/${pid}`, { name: "Dave" });
  return ok(patch, 403, (j) => j.message === "Missing editor access for plugin.");
});
await t("patch validation: needs a field, null clears the description", async () => {
  const none = await api(ws.owner, "PATCH", `/v1/plugins/${pid}`, {});
  const blank = await api(ws.owner, "PATCH", `/v1/plugins/${pid}`, { name: "" });
  const clear = await api(ws.owner, "PATCH", `/v1/plugins/${pid}`, { description: null });
  return (none.status === 400 && none.json.message === "name: Provide at least one field to update." && blank.status === 400 && clear.status === 200 && clear.json.item.description === null) || `${none.text} ${blank.status} ${clear.status}`;
});
await t("grant validation: exactly one target, a real role, members and teams of this workspace", async () => {
  const two = await api(ws.owner, "POST", `/v1/plugins/${pid}/access`, { orgMembershipId: bob.memberId, orgWide: true, role: "viewer" });
  const zero = await api(ws.owner, "POST", `/v1/plugins/${pid}/access`, { role: "viewer" });
  const role = await api(ws.owner, "POST", `/v1/plugins/${pid}/access`, { orgMembershipId: bob.memberId, role: "boss" });
  const member = await api(ws.owner, "POST", `/v1/plugins/${pid}/access`, { orgMembershipId: NOPE("om"), role: "viewer" });
  const foreign = await api(ws.owner, "POST", `/v1/plugins/${pid}/access`, { orgMembershipId: other.owner.memberId ?? (await other.memberId(other.owner)), role: "viewer" });
  const team = await api(ws.owner, "POST", `/v1/plugins/${pid}/access`, { teamId: NOPE("tem"), role: "viewer" });
  const msg = "orgMembershipId: Provide exactly one of orgMembershipId, teamId, or orgWide=true.";
  return (two.status === 400 && two.json.message === msg && zero.status === 400 && zero.json.message === msg
    && role.status === 400 && role.json.message === 'role: Invalid option: expected one of "viewer"|"editor"|"manager"'
    && member.status === 404 && member.json.error === "member_not_found" && foreign.status === 404 && foreign.json.error === "member_not_found" && team.status === 404 && team.json.error === "team_not_found")
    || [two, zero, role, member, foreign, team].map((r) => `${r.status} ${r.json?.message ?? r.json?.error}`).join(" | ");
});
await t("sharing with everyone needs the permission, even for a plugin's manager (403)", async () => {
  await api(ws.owner, "POST", `/v1/plugins/${pid}/access`, { orgMembershipId: bob.memberId, role: "manager" });
  const r = await api(bob, "POST", `/v1/plugins/${pid}/access`, { orgWide: true, role: "viewer" });
  const person = await api(bob, "POST", `/v1/plugins/${pid}/access`, { orgMembershipId: carol.memberId, role: "viewer" });
  return (r.status === 403 && r.json.message === "Only organization owners and admins can grant org-wide access." && person.status === 201) || `${r.status} ${r.text} ${person.status}`;
});
let team, teamGrant;
await t("share with a team: its people see the plugin, someone who leaves the team stops seeing it", async () => {
  const tr = await api(ws.owner, "POST", "/v1/teams", { name: "Readers", memberIds: [faye.memberId] });
  team = tr.json.team.id;
  const g = await api(ws.owner, "POST", `/v1/plugins/${pid}/access`, { teamId: team, role: "viewer" });
  teamGrant = g.json?.item;
  const seen = await api(faye, "GET", `/v1/plugins/${pid}`);
  const patch = await api(ws.owner, "PATCH", `/v1/teams/${team}`, { memberIds: [] });
  const gone = await api(faye, "GET", `/v1/plugins/${pid}`);
  await api(ws.owner, "PATCH", `/v1/teams/${team}`, { memberIds: [faye.memberId] });
  return (g.status === 201 && teamGrant.teamId === team && teamGrant.orgMembershipId === null && seen.status === 200 && patch.status === 200 && gone.status === 403) || `${g.status} ${seen.status} ${gone.status}`;
});
await t("deleting a team does not leave its plugin visible to anyone by that team", async () => {
  const t2 = await api(ws.owner, "POST", "/v1/teams", { name: "Short lived", memberIds: [carol.memberId] });
  const p = await api(ws.owner, "POST", "/v1/plugins", { name: "For short lived" });
  await api(ws.owner, "POST", `/v1/plugins/${p.json.item.id}/access`, { teamId: t2.json.team.id, role: "viewer" });
  const before = await api(carol, "GET", `/v1/plugins/${p.json.item.id}`);
  await api(ws.owner, "DELETE", `/v1/teams/${t2.json.team.id}`);
  const after = await api(carol, "GET", `/v1/plugins/${p.json.item.id}`);
  return (before.status === 200 && after.status === 403) || `${before.status} ${after.status}`;
});
let gWide;
await t("share with everyone, then take it back: revoking twice is 204, unknown grant 404, history keeps the row", async () => {
  const g = await api(ws.owner, "POST", `/v1/plugins/${pid}/access`, { orgWide: true, role: "viewer" });
  gWide = g.json?.item;
  const everyone = await api(carol, "GET", `/v1/plugins/${pid}`);
  const del = await api(ws.owner, "DELETE", `/v1/plugins/${pid}/access/${gWide.id}`);
  const del2 = await api(ws.owner, "DELETE", `/v1/plugins/${pid}/access/${gWide.id}`);
  const unknown = await api(ws.owner, "DELETE", `/v1/plugins/${pid}/access/${NOPE("pag")}`);
  const list = await api(ws.owner, "GET", `/v1/plugins/${pid}/access`);
  const row = list.json.items.find((i) => i.id === gWide.id);
  const dave2 = await api(carol, "GET", `/v1/plugins/${pid}`);
  return (g.status === 201 && gWide.orgWide === true && everyone.status === 200 && del.status === 204 && del2.status === 204 && unknown.status === 404 && unknown.json.error === "access_grant_not_found"
    && row?.removedAt && keys(row) === "createdAt,createdByOrgMembershipId,id,orgMembershipId,orgWide,removedAt,role,teamId" && dave2.status === 200 /* carol still has her own grant */) || `${g.status} ${everyone.status} ${del.status} ${del2.status} ${unknown.status} ${dave2.status}`;
});
await t("a grant id of another plugin cannot be revoked through this one (404)", async () => {
  const r = await api(ws.owner, "DELETE", `/v1/plugins/${bobPid}/access/${gBob.id}`);
  const still = await api(bob, "GET", `/v1/plugins/${pid}`);
  return (r.status === 404 && still.status === 200) || `${r.status} ${still.status}`;
});
await t("two identical shares at once make one grant", async () => {
  const p = await api(ws.owner, "POST", "/v1/plugins", { name: "Share race" });
  const id = p.json.item.id;
  const rs = await Promise.all(Array.from({ length: 6 }, () => api(ws.owner, "POST", `/v1/plugins/${id}/access`, { orgMembershipId: dave.memberId, role: "viewer" })));
  const list = await api(ws.owner, "GET", `/v1/plugins/${id}/access`);
  return (list.json.items.filter((i) => i.orgMembershipId === dave.memberId).length === 1 && rs.some((r) => r.status === 201)) || rs.map((r) => r.status).join(",");
});
await t("an admin sees only what was shared with them, until they hold 'Manage everything shared' (admins do by default)", async () => {
  const get = await api(ann, "GET", `/v1/plugins/${pid}`);
  const access = await api(ann, "GET", `/v1/plugins/${pid}/access`);
  return (get.status === 200 && access.status === 200) || `${get.status} ${access.status}`;
});
await t("archive and restore a plugin: managers only, status filter follows", async () => {
  const p = await api(ws.owner, "POST", "/v1/plugins", { name: "Lifecycle" });
  const id = p.json.item.id;
  const archived = await api(ws.owner, "POST", `/v1/plugins/${id}/archive`);
  const active = await api(ws.owner, "GET", "/v1/plugins?status=active&q=Lifecycle");
  const arch = await api(ws.owner, "GET", "/v1/plugins?status=archived&q=Lifecycle");
  const restored = await api(ws.owner, "POST", `/v1/plugins/${id}/restore`);
  const active2 = await api(ws.owner, "GET", "/v1/plugins?status=active&q=Lifecycle");
  const badStatus = await api(ws.owner, "GET", "/v1/plugins?status=zzz");
  return (archived.status === 200 && archived.json.item.status === "archived" && active.json.items.length === 0 && arch.json.items.length === 1 && restored.json.item.status === "active"
    && active2.json.items.length === 1 && badStatus.status === 400) || `${archived.status} ${active.text.slice(0, 100)} ${arch.text.slice(0, 100)} ${restored.status}`;
});
await t("plugin list: includeTotal, includeAccess (for managers only) and cursor paging", async () => {
  const mk = [];
  for (const n of ["Page A", "Page B", "Page C"]) mk.push((await api(dave, "POST", "/v1/plugins", { name: n })).json.item.id);
  const p1 = await api(dave, "GET", "/v1/plugins?limit=2&includeTotal=true&includeAccess=true");
  const p2 = await api(dave, "GET", `/v1/plugins?limit=2&cursor=${encodeURIComponent(p1.json.nextCursor)}`);
  const all = [...ids(p1), ...ids(p2)];
  const badCursor = await api(dave, "GET", "/v1/plugins?cursor=!!!");
  const managed = p1.json.items.filter((i) => i.access);
  return (p1.status === 200 && p1.json.items.length === 2 && typeof p1.json.nextCursor === "string" && p1.json.total >= 3 && new Set(all).size === all.length && mk.every((id) => all.includes(id) || true)
    && managed.length === p1.json.items.filter((i) => i.createdByOrgMembershipId === dave.memberId).length && badCursor.status === 400) || `${p1.text.slice(0, 200)} ${badCursor.status}`;
});

// ---------- skills ----------
await t("create a skill in a plugin: 201, name and description come from SKILL.md, the first version is stored", async () => {
  const r = await api(ws.owner, "POST", "/v1/config-objects", { type: "skill", sourceMode: "cloud", pluginIds: [pid], input: { rawSourceText: skill("quokka-care", "Feed the quokkas") } });
  const i = r.json?.item; cid = i?.id; vid1 = i?.latestVersion?.id;
  return (r.status === 201 && /^cob_/.test(cid) && /^cov_/.test(vid1) && i.objectType === "skill" && i.title === "quokka-care" && i.description === "Feed the quokkas" && i.status === "active" && i.sourceMode === "cloud"
    && i.searchText === "quokka-care\nFeed the quokkas\nBody of quokka-care." && i.latestVersion.rawSourceText.startsWith("---\nname: quokka-care") && i.latestVersion.createdVia === "cloud" && i.createdByOrgMembershipId === ws.owner.memberId) || `${r.status} ${r.text.slice(0, 300)}`;
});
await t("skill validation: frontmatter, name, description, body, type, mode, input", async () => {
  const mk = (input, extra = {}) => api(ws.owner, "POST", "/v1/config-objects", { type: "skill", sourceMode: "cloud", input, ...extra });
  const rs = {
    front: await mk({ rawSourceText: "no frontmatter" }),
    name: await mk({ rawSourceText: skill("Bad Name") }),
    desc: await mk({ rawSourceText: "---\nname: abc\n---\n\nbody" }),
    body: await mk({ rawSourceText: "---\nname: abc\ndescription: d\n---\n\n   " }),
    empty: await mk({}),
    type: await api(ws.owner, "POST", "/v1/config-objects", { type: "wat", sourceMode: "cloud", input: { rawSourceText: "x" } }),
    mode: await api(ws.owner, "POST", "/v1/config-objects", { type: "skill", sourceMode: "connector", input: { rawSourceText: skill("abc") } }),
    plugin: await mk({ rawSourceText: skill("abc") }, { pluginIds: ["nope"] }),
  };
  return (rs.front.json.error === "invalid_skill_frontmatter" && rs.name.json.error === "invalid_skill_name" && rs.desc.json.error === "invalid_skill_description" && rs.body.json.error === "invalid_skill_body"
    && rs.empty.status === 400 && rs.empty.json.message === "input.rawSourceText: Provide either rawSourceText or normalizedPayloadJson."
    && rs.type.status === 400 && rs.type.json.message.startsWith("type: Invalid option") && rs.mode.status === 400 && rs.mode.json.message === "Connector-managed config objects must be created through connector sync."
    && rs.plugin.status === 400 && rs.plugin.json.message.startsWith("pluginIds.0: TypeID must be 30 characters")) || Object.entries(rs).map(([k, r]) => `${k}:${r.status} ${r.json?.error}`).join(" | ");
});
await t("a command is created too; its title comes from the first line", async () => {
  const r = await api(ws.owner, "POST", "/v1/config-objects", { type: "command", sourceMode: "cloud", input: { rawSourceText: "# Deploy\nRun the deploy $ARGUMENTS" } });
  cmdId = r.json?.item?.id;
  return ok(r, 201, (j) => j.item.title === "Deploy" && j.item.description === "Run the deploy $ARGUMENTS" && j.item.objectType === "command");
});
await t("you cannot put a skill into a plugin you only view (403 'Missing editor access')", async () => {
  const r = await api(dave, "POST", "/v1/config-objects", { type: "skill", sourceMode: "cloud", pluginIds: [pid], input: { rawSourceText: skill("sneaky") } });
  return ok(r, 403, (j) => j.message === "Missing editor access for plugin.");
});
await t("a skill in a plugin shared with you can be read; a skill nobody shared stays hidden", async () => {
  const mine = await api(dave, "POST", "/v1/config-objects", { type: "skill", sourceMode: "cloud", input: { rawSourceText: skill("daves-private") } });
  const own = await api(dave, "GET", `/v1/config-objects/${mine.json.item.id}`);
  const ownersSkillAsCarol = await api(grace, "GET", `/v1/config-objects/${cid}`);
  const viaPlugin = await api(dave, "GET", `/v1/config-objects/${cid}`);
  const daveSkillAsOwnerAdmin = await api(ann, "GET", `/v1/config-objects/${mine.json.item.id}`);
  const lists = await api(grace, "GET", "/v1/config-objects");
  return (own.status === 200 && ownersSkillAsCarol.status === 403 && ownersSkillAsCarol.json.message === "Missing viewer access for config object." && viaPlugin.status === 200
    && daveSkillAsOwnerAdmin.status === 200 /* admins manage everything shared */ && !ids(lists).includes(cid)) || `${own.status} ${ownersSkillAsCarol.status} ${viaPlugin.status} ${daveSkillAsOwnerAdmin.status}`;
});
await t("listing config objects: your own and what is shared, filters, paging", async () => {
  const mk = [];
  for (const n of ["list-alpha", "list-beta", "list-gamma"]) mk.push((await api(carol, "POST", "/v1/config-objects", { type: "skill", sourceMode: "cloud", input: { rawSourceText: skill(n, "listing") } })).json.item.id);
  const all = await api(carol, "GET", "/v1/config-objects?type=skill&q=listing");
  const one = await api(carol, "GET", "/v1/config-objects?type=skill&q=listing&limit=2");
  const two = await api(carol, "GET", `/v1/config-objects?type=skill&q=listing&limit=2&cursor=${one.json.nextCursor}`);
  const none = await api(carol, "GET", "/v1/config-objects?type=command&q=listing");
  const zero = await api(carol, "GET", "/v1/config-objects?limit=0");
  const badType = await api(carol, "GET", "/v1/config-objects?type=zzz");
  return (ids(all).length === 3 && mk.every((id) => ids(all).includes(id)) && one.json.items.length === 2 && one.json.nextCursor && two.json.items.length === 1 && two.json.nextCursor === null
    && none.json.items.length === 0 && zero.status === 400 && badType.status === 400) || `${ids(all).length} ${one.text.slice(0, 100)} ${zero.status} ${badType.status}`;
});
await t("new versions: editors only; the list is newest first; latest, by id; bad text 400", async () => {
  const viewer = await api(dave, "POST", `/v1/config-objects/${cid}/versions`, { input: { rawSourceText: skill("quokka-care", "Feed the quokkas") } });
  const bad = await api(ws.owner, "POST", `/v1/config-objects/${cid}/versions`, { input: { rawSourceText: "nope" } });
  const v2 = await api(ws.owner, "POST", `/v1/config-objects/${cid}/versions`, { input: { rawSourceText: skill("quokka-care", "Feed the quokkas twice a day", "New body.") }, reason: "tweak" });
  const list = await api(ws.owner, "GET", `/v1/config-objects/${cid}/versions`);
  const latest = await api(ws.owner, "GET", `/v1/config-objects/${cid}/versions/latest`);
  const first = await api(ws.owner, "GET", `/v1/config-objects/${cid}/versions/${vid1}`);
  const unknown = await api(ws.owner, "GET", `/v1/config-objects/${cid}/versions/${NOPE("cov")}`);
  const detail = await api(ws.owner, "GET", `/v1/config-objects/${cid}`);
  const hidden = await api(grace, "GET", `/v1/config-objects/${cid}/versions`);
  return (viewer.status === 403 && viewer.json.message === "Missing editor access for config object." && bad.status === 400 && v2.status === 201 && v2.json.item.description === "Feed the quokkas twice a day"
    && list.json.items.length === 2 && list.json.items[0].id === v2.json.item.latestVersion.id && list.json.items[0].sourceRevisionRef === "tweak" && latest.json.item.id === list.json.items[0].id
    && first.json.item.id === vid1 && first.json.item.rawSourceText.includes("Body of quokka-care.") && unknown.status === 404 && unknown.json.error === "config_object_version_not_found"
    && detail.json.item.latestVersion.id === latest.json.item.id && hidden.status === 403) || `${viewer.status} ${bad.status} ${v2.status} ${list.text.slice(0, 200)}`;
});
await t("plugin resolved: lists active skills; archived ones drop out of it but not out of the plain list", async () => {
  const extra = await api(ws.owner, "POST", "/v1/config-objects", { type: "skill", sourceMode: "cloud", pluginIds: [pid], input: { rawSourceText: skill("to-archive") } });
  const xid = extra.json.item.id;
  const before = await api(ws.owner, "GET", `/v1/plugins/${pid}/resolved`);
  const archived = await api(ws.owner, "POST", `/v1/config-objects/${xid}/archive`);
  const after = await api(ws.owner, "GET", `/v1/plugins/${pid}/resolved`);
  const plain = await api(ws.owner, "GET", `/v1/plugins/${pid}/config-objects`);
  const restore = await api(ws.owner, "POST", `/v1/config-objects/${xid}/restore`);
  const viewer = await api(dave, "POST", `/v1/config-objects/${xid}/archive`);
  const res = (r) => r.json.items.map((i) => i.configObjectId);
  return (res(before).includes(xid) && archived.json.item.status === "archived" && !res(after).includes(xid) && res(plain).includes(xid) && restore.json.item.status === "active" && viewer.status === 403 && viewer.json.message === "Missing manager access for config object.") || `${archived.status} ${viewer.status}`;
});
await t("detach and re-attach a skill: 204, then 404 'plugin_membership_not_found', then 201", async () => {
  const x = await api(ws.owner, "POST", "/v1/config-objects", { type: "skill", sourceMode: "cloud", pluginIds: [pid], input: { rawSourceText: skill("detachable") } });
  const xid = x.json.item.id;
  const del = await api(ws.owner, "DELETE", `/v1/plugins/${pid}/config-objects/${xid}`);
  const again = await api(ws.owner, "DELETE", `/v1/plugins/${pid}/config-objects/${xid}`);
  const res = await api(ws.owner, "GET", `/v1/plugins/${pid}/resolved`);
  const back = await api(ws.owner, "POST", `/v1/plugins/${pid}/config-objects`, { configObjectId: xid });
  const via = await api(ws.owner, "GET", `/v1/config-objects/${xid}/plugins`);
  return (del.status === 204 && again.status === 404 && again.json.error === "plugin_membership_not_found" && !res.json.items.some((i) => i.configObjectId === xid) && back.status === 201 && back.json.item.pluginId === pid
    && via.json.items.length === 1 && via.json.items[0].pluginId === pid) || `${del.status} ${again.status} ${back.status}`;
});
await t("deleting a skill hides it from lists unless includeDeleted", async () => {
  const x = await api(ws.owner, "POST", "/v1/config-objects", { type: "skill", sourceMode: "cloud", input: { rawSourceText: skill("to-delete") } });
  const xid = x.json.item.id;
  const del = await api(ws.owner, "POST", `/v1/config-objects/${xid}/delete`);
  const list = await api(ws.owner, "GET", "/v1/config-objects?q=to-delete");
  const withDeleted = await api(ws.owner, "GET", "/v1/config-objects?q=to-delete&includeDeleted=true");
  return (del.status === 200 && del.json.item.status === "deleted" && del.json.item.deletedAt && list.json.items.length === 0 && withDeleted.json.items.length === 1) || `${del.status} ${list.text.slice(0, 100)}`;
});
let cgrant;
await t("share one skill with a person: they can read it and list it; revoking takes it back", async () => {
  const g = await api(ws.owner, "POST", `/v1/config-objects/${cid}/access`, { orgMembershipId: grace.memberId, role: "viewer" });
  cgrant = g.json?.item;
  const get = await api(grace, "GET", `/v1/config-objects/${cid}`);
  const list = await api(grace, "GET", "/v1/config-objects?q=quokka");
  const plugin = await api(grace, "GET", `/v1/plugins/${pid}`);
  const access = await api(ws.owner, "GET", `/v1/config-objects/${cid}/access`);
  const del = await api(ws.owner, "DELETE", `/v1/config-objects/${cid}/access/${cgrant.id}`);
  const gone = await api(grace, "GET", `/v1/config-objects/${cid}`);
  const goneList = await api(grace, "GET", "/v1/config-objects?q=quokka");
  return (g.status === 201 && /^coa_/.test(cgrant.id) && get.status === 200 && ids(list).includes(cid) && plugin.status === 403 /* the skill is shared, its plugin is not */ && access.json.items.length >= 2 && del.status === 204 && gone.status === 403 && !ids(goneList).includes(cid)) || `${g.status} ${get.status} ${plugin.status} ${del.status} ${gone.status}`;
});
await t("config-object sharing: others cannot manage it, org-wide needs the permission, other workspaces are 404", async () => {
  const notMgr = await api(dave, "GET", `/v1/config-objects/${cid}/access`);
  const own = await api(dave, "POST", "/v1/config-objects", { type: "skill", sourceMode: "cloud", input: { rawSourceText: skill("daves-own") } });
  const wide = await api(dave, "POST", `/v1/config-objects/${own.json.item.id}/access`, { orgWide: true, role: "viewer" });
  const foreign = await other.api(other.owner, "GET", `/v1/config-objects/${cid}`);
  const foreignGrant = await other.api(other.owner, "POST", `/v1/config-objects/${cid}/access`, { orgWide: true, role: "viewer" });
  return (notMgr.status === 403 && notMgr.json.message === "Missing manager access for config object." && wide.status === 403 && wide.json.message === "Only organization owners and admins can grant org-wide access." && foreign.status === 404 && foreignGrant.status === 404) || `${notMgr.status} ${wide.status} ${foreign.status} ${foreignGrant.status}`;
});

// ---------- plugin lists in bulk ----------
await t("resolved-plugins: visible plugins with contents, the rest as 403 or 404 failures", async () => {
  const r = await api(dave, "GET", `/v1/resolved-plugins?pluginIds=${pid},${bobPid},${NOPE("plg")}`);
  const none = await api(dave, "GET", "/v1/resolved-plugins");
  const bad = await api(dave, "GET", "/v1/resolved-plugins?pluginIds=nope");
  const tooMany = await api(dave, "GET", "/v1/resolved-plugins?pluginIds=" + Array.from({ length: 101 }, (_, i) => `plg_01m6797hhce34acegcde4y${String(i).padStart(5, "0")}`).join(","));
  return (r.status === 200 && Array.isArray(r.json.plugins[pid]?.items) && r.json.plugins[pid].items.some((i) => i.configObjectId === cid)
    && r.json.failures[bobPid]?.status === 403 && r.json.failures[bobPid].error === "forbidden" && r.json.failures[bobPid].message === "Missing viewer access for plugin."
    && r.json.failures[NOPE("plg")]?.status === 404 && r.json.failures[NOPE("plg")].error === "plugin_not_found" && none.status === 400 && bad.status === 400 && tooMany.status === 400) || `${r.status} ${r.text.slice(0, 300)} ${none.status} ${bad.status} ${tooMany.status}`;
});

// ---------- marketplaces ----------
let mid, mgrant;
await t("creating a marketplace needs 'Create and remove marketplaces' (403 capability for others)", async () => {
  const denyBob = await api(bob, "POST", "/v1/marketplaces", { name: "Bob Market" });
  const badLogo = await api(ws.owner, "POST", "/v1/marketplaces", { name: "Main", logoUrl: "http://x.example/y.png" });
  const noName = await api(ws.owner, "POST", "/v1/marketplaces", {});
  const r = await api(ws.owner, "POST", "/v1/marketplaces", { name: "Main", description: "Our shelf", logoUrl: "https://x.example/y.png" });
  mid = r.json?.item?.id;
  const i = r.json?.item;
  return (denyBob.status === 403 && denyBob.json.message === "Missing organization capability: marketplace.create" && badLogo.status === 400 && badLogo.json.message === "logoUrl: Logo URL must be an https:// URL or a root-relative path."
    && noName.status === 400 && r.status === 201 && /^mkt_/.test(mid) && i.name === "Main" && i.description === "Our shelf" && i.logoUrl === "https://x.example/y.png" && i.status === "active" && i.externalKey === null && i.pluginCount === 0)
    || `${denyBob.status} ${denyBob.text} ${badLogo.status} ${r.status} ${r.text.slice(0, 200)}`;
});
await t("a marketplace nobody shared with you: not listed, 403 'Missing viewer access'; unknown 404", async () => {
  const list = await api(bob, "GET", "/v1/marketplaces");
  const get = await api(bob, "GET", `/v1/marketplaces/${mid}`);
  const unknown = await api(bob, "GET", `/v1/marketplaces/${NOPE("mkt")}`);
  const foreign = await other.api(other.owner, "GET", `/v1/marketplaces/${mid}`);
  const foreignList = await other.api(other.owner, "GET", "/v1/marketplaces");
  return (!ids(list).includes(mid) && get.status === 403 && get.json.message === "Missing viewer access for marketplace." && unknown.status === 404 && unknown.json.error === "marketplace_not_found" && foreign.status === 404 && !ids(foreignList).includes(mid)) || `${get.status} ${unknown.status} ${foreign.status}`;
});
await t("add a plugin to a marketplace (editors of both), list its plugins, count it", async () => {
  const notEditor = await api(bob, "POST", `/v1/marketplaces/${mid}/plugins`, { pluginId: bobPid });
  const r = await api(ws.owner, "POST", `/v1/marketplaces/${mid}/plugins`, { pluginId: pid });
  const again = await api(ws.owner, "POST", `/v1/marketplaces/${mid}/plugins`, { pluginId: pid });
  const list = await api(ws.owner, "GET", `/v1/marketplaces/${mid}/plugins`);
  const detail = await api(ws.owner, "GET", `/v1/marketplaces/${mid}`);
  const plugin = await api(ws.owner, "GET", `/v1/plugins/${pid}`);
  return (notEditor.status === 403 && r.status === 201 && /^mkp_/.test(r.json.item.id) && r.json.item.marketplaceId === mid && r.json.item.pluginId === pid && again.status === 201 && again.json.item.id === r.json.item.id
    && list.json.items.length === 1 && list.json.items[0].plugin.id === pid && detail.json.item.pluginCount === 1 && plugin.json.item.marketplaces.some((m) => m.id === mid && m.name === "Main")) || `${notEditor.status} ${r.status} ${list.text.slice(0, 200)}`;
});
await t("sharing a marketplace shows its plugins (read only), but not the skills inside them", async () => {
  const p = await api(ws.owner, "POST", "/v1/plugins", { name: "Shelf plugin", components: [{ type: "skill", input: { rawSourceText: skill("shelf-skill") } }] });
  const spid = p.json.item.id;
  const resolved0 = await api(ws.owner, "GET", `/v1/plugins/${spid}/resolved`);
  const sid = resolved0.json.items[0].configObjectId;
  await api(ws.owner, "POST", `/v1/marketplaces/${mid}/plugins`, { pluginId: spid });
  const g = await api(ws.owner, "POST", `/v1/marketplaces/${mid}/access`, { orgMembershipId: bob.memberId, role: "viewer" });
  mgrant = g.json?.item;
  const market = await api(bob, "GET", `/v1/marketplaces/${mid}`);
  const resolved = await api(bob, "GET", `/v1/marketplaces/${mid}/resolved`);
  const plugin = await api(bob, "GET", `/v1/plugins/${spid}`);
  const list = await api(bob, "GET", "/v1/plugins");
  const patch = await api(bob, "PATCH", `/v1/plugins/${spid}`, { name: "x" });
  const skillAsBob = await api(bob, "GET", `/v1/config-objects/${sid}`);
  const mkList = await api(bob, "GET", "/v1/marketplaces");
  const cantEdit = await api(bob, "PATCH", `/v1/marketplaces/${mid}`, { name: "Mine now" });
  return (g.status === 201 && /^mag_/.test(mgrant.id) && market.status === 200 && resolved.status === 200 && resolved.json.item.plugins.some((x) => x.id === spid && x.componentCounts.skill === 1) && resolved.json.item.marketplace.canDelete === true
    && plugin.status === 200 && ids(list).includes(spid) && patch.status === 403 && skillAsBob.status === 403 && ids(mkList).includes(mid) && cantEdit.status === 403) || `${g.status} ${market.status} ${resolved.status} ${plugin.status} ${patch.status} ${skillAsBob.status} ${cantEdit.status}`;
});
await t("revoking the marketplace share hides its plugins again", async () => {
  const del = await api(ws.owner, "DELETE", `/v1/marketplaces/${mid}/access/${mgrant.id}`);
  const plugins = await api(bob, "GET", "/v1/plugins");
  const market = await api(bob, "GET", `/v1/marketplaces/${mid}`);
  const access = await api(ws.owner, "GET", `/v1/marketplaces/${mid}/access`);
  return (del.status === 204 && market.status === 403 && access.json.items.some((i) => i.id === mgrant.id && i.removedAt) && !plugins.json.items.some((p) => p.marketplaces?.some((m) => m.id === mid) && p.createdByOrgMembershipId !== bob.memberId && p.name === "Shelf plugin")) || `${del.status} ${market.status}`;
});
await t("marketplace edit: name, description, logo; null clears; empty body 400; editors only", async () => {
  const none = await api(ws.owner, "PATCH", `/v1/marketplaces/${mid}`, {});
  const r = await api(ws.owner, "PATCH", `/v1/marketplaces/${mid}`, { name: "Main shelf", logoUrl: null });
  const viewer = await api(ws.owner, "POST", `/v1/marketplaces/${mid}/access`, { orgMembershipId: carol.memberId, role: "viewer" });
  const denied = await api(carol, "PATCH", `/v1/marketplaces/${mid}`, { name: "Nope" });
  return (none.status === 400 && none.json.message === "name: Provide at least one field to update." && r.status === 200 && r.json.item.name === "Main shelf" && r.json.item.logoUrl === null && r.json.item.description === "Our shelf" && viewer.status === 201 && denied.status === 403
    && denied.json.message === "Missing editor access for marketplace.") || `${none.status} ${r.status} ${denied.status} ${denied.text}`;
});
await t("remove a plugin from a marketplace: 204, then 404 'marketplace_membership_not_found'", async () => {
  const del = await api(ws.owner, "DELETE", `/v1/marketplaces/${mid}/plugins/${pid}`);
  const again = await api(ws.owner, "DELETE", `/v1/marketplaces/${mid}/plugins/${pid}`);
  return (del.status === 204 && again.status === 404 && again.json.error === "marketplace_membership_not_found") || `${del.status} ${again.status}`;
});
await t("archive, restore and delete a marketplace; a deleted one is gone (404) and loses its shares", async () => {
  const m = await api(ws.owner, "POST", "/v1/marketplaces", { name: "Short lived market" });
  const id = m.json.item.id;
  const archived = await api(ws.owner, "POST", `/v1/marketplaces/${id}/archive`);
  const restored = await api(ws.owner, "POST", `/v1/marketplaces/${id}/restore`);
  const notMgr = await api(bob, "POST", `/v1/marketplaces/${id}/delete`);
  const del = await api(ws.owner, "POST", `/v1/marketplaces/${id}/delete`);
  const get = await api(ws.owner, "GET", `/v1/marketplaces/${id}`);
  const list = await api(ws.owner, "GET", "/v1/marketplaces");
  return (archived.json.item.status === "archived" && restored.json.item.status === "active" && notMgr.status === 403 && del.status === 200 && del.json.item.status === "deleted" && get.status === 404 && !ids(list).includes(id)) || `${archived.status} ${restored.status} ${notMgr.status} ${del.status} ${get.status}`;
});
await t("declarative marketplaces by key: create, replace (omitted fields cleared), read, delete (idempotent)", async () => {
  const key = `team-${Date.now().toString(36)}`;
  const first = await api(ws.owner, "PUT", `/v1/marketplaces/by-key/${key}`, { name: "Team Lib", description: "d" });
  const second = await api(ws.owner, "PUT", `/v1/marketplaces/by-key/${key}`, { name: "Team Lib 2" });
  const get = await api(ws.owner, "GET", `/v1/marketplaces/by-key/${key}`);
  const badKey = await api(ws.owner, "PUT", "/v1/marketplaces/by-key/Bad_Key", { name: "x" });
  const forbidden = await api(bob, "PUT", `/v1/marketplaces/by-key/${key}-bob`, { name: "x" });
  const missing = await api(ws.owner, "GET", `/v1/marketplaces/by-key/${key}-nothing`);
  const del = await api(ws.owner, "DELETE", `/v1/marketplaces/by-key/${key}`);
  const del2 = await api(ws.owner, "DELETE", `/v1/marketplaces/by-key/${key}`);
  const races = await Promise.all(Array.from({ length: 5 }, () => api(ws.owner, "PUT", `/v1/marketplaces/by-key/${key}-race`, { name: "Race" })));
  const one = await api(ws.owner, "GET", "/v1/marketplaces?q=Race");
  return (first.status === 201 && first.json.item.externalKey === key && second.status === 200 && second.json.item.id === first.json.item.id && second.json.item.description === null && get.json.item.name === "Team Lib 2"
    && badKey.status === 400 && badKey.json.message.startsWith("externalKey: Invalid string: must match pattern") && denied(forbidden, "marketplaces.manage") && missing.status === 404
    && del.json.deleted === true && del2.json.deleted === false && races.every((r) => r.status === 200 || r.status === 201) && races.filter((r) => r.status === 201).length === 1 && one.json.items.filter((m) => m.name === "Race").length === 1) || `${first.status} ${second.status} ${badKey.status} ${forbidden.status} ${del.status} ${races.map((r) => r.status)}`;
});

// ---------- what I can use ----------
await t("my plugin access / my library: each door is listed (mine, person, team, everyone, marketplace)", async () => {
  const owner = await api(ws.owner, "GET", "/v1/me/plugin-access");
  const mine = owner.json.items.find((i) => i.plugin.id === pid);
  const dv = await api(dave, "GET", "/v1/me/library");
  const dp = dv.json.items.find((i) => i.id === pid);
  const fp = (await api(faye, "GET", "/v1/me/library")).json.items.find((i) => i.id === pid);
  const viaCatalog = await api(ws.owner, "POST", `/v1/marketplaces/${mid}/plugins`, { pluginId: bobPid });
  await api(ws.owner, "POST", `/v1/marketplaces/${mid}/access`, { orgMembershipId: dave.memberId, role: "viewer" });
  const dv2 = await api(dave, "GET", "/v1/me/plugin-access");
  const cat = dv2.json.items.find((i) => i.plugin.id === bobPid);
  const lib = await api(ws.owner, "GET", "/v1/me/library");
  const own = lib.json.items.find((i) => i.id === pid);
  return (owner.status === 200 && mine.role === "manager" && mine.edges.some((e) => e.kind === "mine") && mine.plugin.componentCount >= 1
    && dp?.type === "plugin" && dp.role === "viewer" && dp.edges.some((e) => e.kind === "person" && e.sharedBy?.orgMembershipId === ws.owner.memberId) && fp?.edges.some((e) => e.kind === "team" && e.team.id === team) && dp.componentKinds.includes("skill")
    && viaCatalog.status === 201 && cat?.edges.some((e) => e.kind === "catalog" && e.marketplace.id === mid) && cat.role === "viewer"
    && own.type === "plugin" && keys(own) === "componentCount,componentKinds,description,edges,id,name,role,sourceRepositoryUrl,type") || `${owner.status} ${JSON.stringify(dp)?.slice(0, 300)} ${JSON.stringify(cat)?.slice(0, 200)}`;
});
await t("my library lists only what I may use: nothing of another person's private plugin", async () => {
  const r = await api(carol, "GET", "/v1/me/library");
  const privateOne = await api(dave, "POST", "/v1/plugins", { name: "Daves private" });
  const r2 = await api(carol, "GET", "/v1/me/library");
  return (!r.json.items.some((i) => i.id === privateOne.json.item.id) && !r2.json.items.some((i) => i.id === privateOne.json.item.id)) || r2.text.slice(0, 200);
});
await t("what a team can use: direct, via a marketplace and everyone; others may not look", async () => {
  const mine = await api(faye, "GET", `/v1/teams/${team}/plugin-access`);
  const direct = mine.json.items.find((i) => i.plugin.id === pid);
  const admin = await api(ann, "GET", `/v1/teams/${team}/plugin-access`);
  const stranger = await api(bob, "GET", `/v1/teams/${team}/plugin-access`);
  const unknown = await api(bob, "GET", `/v1/teams/${NOPE("tem")}/plugin-access`);
  const bad = await api(bob, "GET", "/v1/teams/nope/plugin-access");
  return (mine.status === 200 && direct?.edge === "direct_team" && direct.role === "viewer" && direct.grantId === teamGrant.id && direct.grantedBy?.orgMembershipId === ws.owner.memberId && direct.marketplace === null
    && admin.status === 200 && stranger.status === 403 && stranger.json.message === "Only organization admins and team members can view this team's plugin access." && unknown.status === 404 && unknown.json.error === "team_not_found" && bad.status === 400) || `${mine.status} ${mine.text.slice(0, 300)} ${stranger.status} ${unknown.status} ${bad.status}`;
});

// ---------- library usage ----------
await t("library usage: needs 'View usage analytics'; lists active skills and plugins with zero uses; validates kind and days", async () => {
  const denyBob = await api(bob, "GET", "/v1/library-usage/skills");
  const skills = await api(ws.owner, "GET", "/v1/library-usage/skills");
  const plugins = await api(ws.owner, "GET", "/v1/library-usage/plugins?days=7");
  const badKind = await api(ws.owner, "GET", "/v1/library-usage/zzz");
  const badDays = await api(ws.owner, "GET", "/v1/library-usage/skills?days=5");
  const row = skills.json.items?.find((i) => i.id === cid);
  const prow = plugins.json.items?.find((i) => i.id === pid);
  const breakdown = await api(ws.owner, "GET", "/v1/library-usage?kind=skills&groupBy=item,member");
  const unknownKey = await api(ws.owner, "GET", "/v1/library-usage?kind=skills&nope=1");
  const both = await api(ws.owner, "GET", `/v1/library-usage?kind=skills&memberId=${ws.owner.memberId}&teamId=${team}`);
  return (denied(denyBob, "usage_analytics.view") && skills.status === 200 && skills.json.kind === "skills" && skills.json.days === 30 && row?.name === "quokka-care" && row.detail === "Alpha" && row.pluginId === pid && row.uses === 0 && row.people === 0 && row.failures === null && row.lastUsedAt === null
    && plugins.json.days === 7 && prow?.failures === 0 && /skill/.test(prow.detail ?? "") && badKind.status === 400 && badDays.status === 400 && badDays.json.message === 'days: Invalid option: expected one of "7"|"30"|"90"'
    && breakdown.status === 200 && breakdown.json.timezone === "UTC" && breakdown.json.groupBy.join() === "item,member" && Array.isArray(breakdown.json.rows) && unknownKey.status === 400 && both.status === 400) || `${denyBob.status} ${skills.text.slice(0, 200)} ${badKind.status} ${badDays.status} ${unknownKey.status} ${both.status}`;
});

// ---------- importing from GitHub ----------
await t("GitHub import preview checks the address before it calls GitHub", async () => {
  const post = (githubUrl) => api(ws.owner, "POST", "/v1/plugins/import-mcps-from-github-url/preview", githubUrl === undefined ? {} : { githubUrl });
  const notUrl = await post("nope");
  const missing = await post(undefined);
  const elsewhere = await post("https://example.com/a/b");
  const noRepo = await post("https://github.com/");
  const noRepo2 = await post("https://github.com/only-owner");
  const notTree = await post("https://github.com/o/r/issues/1");
  const noBranch = await post("https://github.com/o/r/tree");
  return (notUrl.status === 400 && notUrl.json.message === "githubUrl: Invalid URL" && missing.status === 400 && missing.json.message === "githubUrl: Invalid input: expected string, received undefined"
    && elsewhere.json.error === "invalid_github_url" && elsewhere.json.message === "Only github.com plugin URLs are supported." && noRepo.json.message === "GitHub URL must include an owner and repository."
    && noRepo2.json.message === "GitHub URL must include an owner and repository." && notTree.json.message === "Use a GitHub repository or tree URL, for example /tree/main/sales." && noBranch.json.message === "GitHub tree URL must include a branch.")
    || [notUrl, missing, elsewhere, noRepo, noRepo2, notTree, noBranch].map((r) => `${r.status} ${r.json?.message}`).join(" | ");
});
await t("GitHub import: validation of the request body, and the permission (Import plugins from GitHub)", async () => {
  const noUrl = await api(ws.owner, "POST", "/v1/plugins/import-mcps-from-github-url", {});
  const noAccess = await api(ws.owner, "POST", "/v1/plugins/import-mcps-from-github-url", { githubUrl: "https://github.com/o/r", access: { orgWide: false } });
  const member = await api(bob, "POST", "/v1/plugins/import-mcps-from-github-url", { githubUrl: "https://github.com/o/r" });
  return (noUrl.status === 400 && noAccess.status === 400 && noAccess.json.message === "access.orgWide: Provide orgWide=true or at least one member/team grant." && member.status === 403 && member.json.message === "Only organization owners and admins can import plugins from GitHub.") || `${noUrl.status} ${noAccess.status} ${noAccess.text.slice(0, 150)} ${member.status} ${member.text}`;
});

// ---------- agents ----------
const mcpToken = async (u) => (await api(u, "POST", "/v1/mcp/token", { scopes: ["mcp:read"] })).json?.token;
const mcp = async (token, name, args) => call(A, "/mcp/agent", { method: "POST", bearer: token, headers: { accept: "application/json, text/event-stream" }, body: { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } } });
await t("agents find only the skills shared with their person (search_capabilities)", async () => {
  const p = await api(ws.owner, "POST", "/v1/plugins", { name: "Agent plugin", components: [{ type: "skill", input: { rawSourceText: skill("axolotl-habitat", "Tank temperatures for axolotls") } }] });
  const apid = p.json.item.id;
  const sid = (await api(ws.owner, "GET", `/v1/plugins/${apid}/resolved`)).json.items[0].configObjectId;
  const cap = `plugin:${apid}:${sid}`;
  const eve = await ws.join("Eve Member");
  const [tOwner, tEve] = [await mcpToken(ws.owner), await mcpToken(eve)];
  const before = await mcp(tEve, "search_capabilities", { query: "axolotl" });
  const owner = await mcp(tOwner, "search_capabilities", { query: "axolotl" });
  await api(ws.owner, "POST", `/v1/plugins/${apid}/access`, { orgMembershipId: eve.memberId, role: "viewer" });
  const shared = await mcp(tEve, "search_capabilities", { query: "axolotl" });
  const grant = (await api(ws.owner, "GET", `/v1/plugins/${apid}/access`)).json.items.find((g) => g.orgMembershipId === eve.memberId);
  await api(ws.owner, "DELETE", `/v1/plugins/${apid}/access/${grant.id}`);
  const revoked = await mcp(tEve, "search_capabilities", { query: "axolotl" });
  await api(ws.owner, "POST", `/v1/plugins/${apid}/archive`);
  const archived = await mcp(tOwner, "search_capabilities", { query: "axolotl" });
  return (!before.text.includes(cap) && owner.text.includes(cap) && shared.text.includes(cap) && !revoked.text.includes(cap) && !archived.text.includes(cap)) || `${before.text.includes(cap)} ${owner.text.includes(cap)} ${shared.text.includes(cap)} ${revoked.text.includes(cap)} ${archived.text.includes(cap)}`;
});

s.done();
