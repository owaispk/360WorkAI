// Contract test for policy: desktop policies, agent permissions, prompts, default model, Automation and Workbot settings, and what a person's
// desktop receives (/v1/me/desktop-config, /v1/me/prompts). Runs unchanged against the reference Den and the rewrite:
//   node area-policy.mjs                                                    # reference: web :3005, api :8790
//   W=http://localhost:5250 A=http://localhost:5150 node area-policy.mjs    # rewrite
import { A, call, denied, keys, suite, workspace } from "./lib.mjs";

const s = suite("policy");
const t = s.t.bind(s);
const ws = await workspace("Policy Probe");
const o = ws.owner;
const mia = await ws.join("Mia Member");
const bob = await ws.join("Bob Member");
const ann = await ws.join("Ann Admin", "admin");
const api = (u, m, p, b, e) => ws.api(u, m, p, b, e);
const team = async (name, ...members) => {
  const r = await api(o, "POST", "/v1/teams", { name, memberIds: members.map((m) => m.memberId) });
  if (!r.json?.team) throw new Error(`could not create team ${name}: ${r.status} ${r.text.slice(0, 200)}`);
  return r.json.team.id;
};
const design = await team("Design", mia);
const audit = await team("Audit", mia, bob);
const zeta = await team("Zeta");
const MISSING_TEAM = "tem_01h2xcejqtf2nbrexx3vqjhp41";
const MISSING_MEMBER = "om_01h2xcejqtf2nbrexx3vqjhp41";
const MISSING_POLICY = "dpo_01h2xcejqtf2nbrexx3vqjhp41";
const invalid = (r) => r.status === 400 && r.json?.error === "invalid_request";
const KEYS = ["allowCustomProviders", "allowZenModel", "allowMultipleWorkspaces", "allowControlSettings", "allowManageExtensions", "allowBuiltInExtensions", "allowAlphaUpdates", "showWelcomePage"];
const ALL_TRUE = Object.fromEntries(KEYS.map((k) => [k, true]));
const deepEq = (a, b) => JSON.stringify(sortDeep(a)) === JSON.stringify(sortDeep(b));
function sortDeep(v) { return Array.isArray(v) ? v.map(sortDeep) : v && typeof v === "object" ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortDeep(v[k])])) : v; }
/** The part of /v1/me/desktop-config that comes from policies. */
const eff = async (u) => {
  const r = await api(u, "GET", "/v1/me/desktop-config");
  if (r.status !== 200) throw new Error(`desktop-config ${r.status}`);
  const j = r.json;
  const out = Object.fromEntries(KEYS.map((k) => [k, j[k]]));
  out.execution = j.execution;
  if (j.onboardingPrompts) out.onboardingPrompts = j.onboardingPrompts;
  if (j.onboardingPromptDescriptions) out.onboardingPromptDescriptions = j.onboardingPromptDescriptions;
  return out;
};
const off = (...ks) => ({ ...ALL_TRUE, ...Object.fromEntries(ks.map((k) => [k, false])) });
const EXEC0 = { commands: "allow", blockedCommands: [], blockBrowserUploads: false };
const mk = (body) => api(o, "POST", "/v1/desktop-policies", body);
const listPolicies = async () => (await api(o, "GET", "/v1/desktop-policies")).json.desktopPolicies;

// ------------------------------------------------------------------ desktop policies: listing and permissions
await t("a new workspace lists its default desktop policy first, with the catalog of 8 settings", async () => {
  const r = await api(o, "GET", "/v1/desktop-policies");
  const p = r.json?.desktopPolicies?.[0];
  return r.status === 200 && r.json.definitions.length === 8 && keys(r.json.definitions[0]) === "defaultValue,description,group,id,name,restrictedValue,teamLabel,userNotice"
    && r.json.definitions.map((d) => d.id).join() === KEYS.join()
    && r.json.desktopPolicies.length === 1 && p.isDefault === true && p.isEnabled === true && p.priority === 0 && p.policyName === "Default desktop policy"
    && deepEq(p.policy, ALL_TRUE) && p.roles.length === 0 && p.assignments.length === 0 && p.externalKey === null && p.deletedAt === null
    && keys(p) === "assignments,createdAt,createdByOrgMemberId,deletedAt,externalKey,id,isDefault,isEnabled,organizationId,policyName,priority,roles,updatedAt,policy".split(",").sort().join()
    || JSON.stringify(r.json).slice(0, 300);
});
await t("listing needs desktop_policies.view, managing needs desktop_policies.manage; an admin may view", async () => {
  const m = await api(mia, "GET", "/v1/desktop-policies");
  const c = await api(mia, "POST", "/v1/desktop-policies", { policyName: "x", policy: {} });
  const a = await api(ann, "GET", "/v1/desktop-policies");
  const anon = await call(A, "/v1/desktop-policies");
  return denied(m, "desktop_policies.view") && denied(c, "desktop_policies.manage") && a.status === 200 && anon.status === 401 || [m.status, c.status, a.status, anon.status].join();
});
await t("creating validates the request (400 invalid_request) and the people and teams it names (404)", async () => {
  const bad = [
    await mk({ policyName: " ", policy: {} }),
    await mk({ policyName: "x", policy: { allowZenModel: "no" } }),
    await mk({ policyName: "x", policy: {}, roles: ["boss"] }),
    await mk({ policyName: "x", policy: {}, priority: -1 }),
    await mk({ policyName: "x", policy: {}, priority: 1000001 }),
    await mk({ policyName: "x", policy: {}, priority: 1.5 }),
    await mk({ policyName: "x".repeat(256), policy: {} }),
    await mk({ policyName: "x", policy: {}, teamIds: ["nope"] }),
    await mk({ policyName: "x", policy: { onboardingPrompts: ["only one"] } }),
    await mk({ policyName: "x", policy: { access: { mode: "weird", capabilities: {} } } }),
    await mk({ policyName: "x", policy: { execution: { commands: "maybe" } } }),
    await mk({ policyName: "x", policy: { execution: { nope: 1 } } }),
    await mk({ policyName: "x", policy: { execution: { browserOrigins: ["https://a.com/path"] } } }),
  ];
  const missing = [await mk({ policyName: "x", policy: {}, teamIds: [MISSING_TEAM] }), await mk({ policyName: "x", policy: {}, memberIds: [MISSING_MEMBER] })];
  return bad.every(invalid) && missing[0].status === 404 && missing[0].json.error === "team_not_found" && missing[1].status === 404 && missing[1].json.error === "member_not_found"
    || bad.map((r) => r.status).join() + missing.map((r) => r.status).join();
});
await t("a created policy is trimmed, drops unknown keys, defaults to enabled with priority 0, and lists its assignments", async () => {
  const r = await mk({ policyName: "  Designers  ", policy: { allowZenModel: false, nonsense: true }, teamIds: [design], priority: 5 });
  const p = r.json?.desktopPolicy;
  return r.status === 201 && p.policyName === "Designers" && deepEq(p.policy, { allowZenModel: false }) && p.priority === 5 && p.isEnabled === true && p.isDefault === false
    && p.assignments.length === 1 && p.assignments[0].teamId === design && p.assignments[0].orgMemberId === null && p.assignments[0].role === null && /^dpm_/.test(p.assignments[0].id) && /^dpo_/.test(p.id)
    && (await listPolicies()).map((x) => x.policyName).join() === "Default desktop policy,Designers" || JSON.stringify(r.json).slice(0, 300);
});
await t("a policy can be read by id; a malformed id is 400, an unknown one 404", async () => {
  const id = (await listPolicies()).find((p) => p.policyName === "Designers").id;
  const ok = await api(o, "GET", `/v1/desktop-policies/${id}`);
  const bad = await api(o, "GET", "/v1/desktop-policies/nope");
  const none = await api(o, "GET", `/v1/desktop-policies/${MISSING_POLICY}`);
  return ok.status === 200 && ok.json.desktopPolicy.id === id && invalid(bad) && none.status === 404 && none.json.error === "desktop_policy_not_found";
});
await t("the default policy cannot be disabled or deleted, keeps its name, priority and assignments, and fills unnamed settings from the catalog", async () => {
  const def = (await listPolicies())[0];
  const dis = await api(o, "PATCH", `/v1/desktop-policies/${def.id}`, { policyName: "x", policy: {}, isEnabled: false });
  const del = await api(o, "DELETE", `/v1/desktop-policies/${def.id}`);
  const patch = await api(o, "PATCH", `/v1/desktop-policies/${def.id}`, { policyName: "renamed", policy: { showWelcomePage: false }, priority: 9, teamIds: [design] });
  const p = patch.json?.desktopPolicy;
  const restore = await api(o, "PATCH", `/v1/desktop-policies/${def.id}`, { policyName: "x", policy: {} });
  return dis.status === 400 && dis.json.error === "default_policy_required" && dis.json.message === "The default desktop policy cannot be disabled."
    && del.status === 400 && del.json.error === "default_policy_required" && del.json.message === "The default desktop policy cannot be deleted."
    && patch.status === 200 && p.policyName === "Default desktop policy" && p.priority === 0 && p.assignments.length === 0 && deepEq(p.policy, off("showWelcomePage"))
    && deepEq(restore.json.desktopPolicy.policy, ALL_TRUE) || JSON.stringify([dis.json, del.json, patch.json]).slice(0, 500);
});
await t("updating replaces the settings and the assignments; deleting hides the policy, and a second delete is 404", async () => {
  const mine = await mk({ policyName: "Temp", policy: { allowZenModel: false }, teamIds: [design], roles: ["member", "member"] });
  const id = mine.json.desktopPolicy.id;
  const up = await api(o, "PATCH", `/v1/desktop-policies/${id}`, { policyName: "Temp 2", policy: { allowControlSettings: false }, isEnabled: false, priority: 3, teamIds: [audit] });
  const p = up.json?.desktopPolicy;
  const gone = await api(o, "DELETE", `/v1/desktop-policies/${id}`);
  const again = await api(o, "DELETE", `/v1/desktop-policies/${id}`);
  const read = await api(o, "GET", `/v1/desktop-policies/${id}`);
  const patch = await api(o, "PATCH", `/v1/desktop-policies/${id}`, { policyName: "x", policy: {} });
  return mine.json.desktopPolicy.roles.join() === "member" && up.status === 200 && p.policyName === "Temp 2" && p.isEnabled === false && p.priority === 3 && deepEq(p.policy, { allowControlSettings: false })
    && p.assignments.length === 1 && p.assignments[0].teamId === audit && p.roles.length === 0
    && gone.status === 204 && again.status === 404 && read.status === 404 && patch.status === 404 && (await listPolicies()).every((x) => x.id !== id) || JSON.stringify([up.json, gone.status, again.status]).slice(0, 400);
});
await t("policies of another workspace are invisible and cannot be assigned", async () => {
  const other = await workspace("Other Policy Workspace");
  const theirs = (await other.api(other.owner, "GET", "/v1/desktop-policies")).json.desktopPolicies[0].id;
  const a = await api(o, "GET", `/v1/desktop-policies/${theirs}`);
  const b = await api(o, "PATCH", `/v1/desktop-policies/${theirs}`, { policyName: "x", policy: {} });
  const c = await api(o, "DELETE", `/v1/desktop-policies/${theirs}`);
  const otherTeam = (await other.api(other.owner, "POST", "/v1/teams", { name: "Theirs" })).json.team.id;
  const d = await mk({ policyName: "x", policy: {}, teamIds: [otherTeam] });
  return [a, b, c, d].every((r) => r.status === 404) || [a, b, c, d].map((r) => r.status).join();
});

// ------------------------------------------------------------------ desktop policies: who gets what
// State so far: Design = {Mia}, Audit = {Mia, Bob}. Ann is an admin, Owner the owner.
await t("with only the default policy everyone gets every setting and the default execution limits", async () => {
  const got = [await eff(mia), await eff(bob), await eff(ann), await eff(o)];
  return got.every((g) => deepEq(g, { ...ALL_TRUE, execution: EXEC0 })) || JSON.stringify(got[0]);
});
await t("a custom access limit through a team turns a setting off for its members only, whatever other policies grant", async () => {
  await mk({ policyName: "A", policy: { access: { mode: "custom", capabilities: { allowCustomProviders: false } } }, teamIds: [design] });
  const got = [await eff(mia), await eff(bob)];
  return deepEq(got[0], { ...off("allowCustomProviders"), execution: EXEC0 }) && deepEq(got[1], { ...ALL_TRUE, execution: EXEC0 }) || JSON.stringify(got);
});
await t("a locked access limit switches off every restrictable setting but leaves the welcome page; disabling it lifts it", async () => {
  const b = await mk({ policyName: "B", policy: { access: { mode: "locked", capabilities: {} } }, teamIds: [audit] });
  const locked = off(...KEYS.filter((k) => k !== "showWelcomePage"));
  const during = [await eff(mia), await eff(bob), await eff(ann)];
  await api(o, "PATCH", `/v1/desktop-policies/${b.json.desktopPolicy.id}`, { policyName: "B", policy: {}, isEnabled: false, teamIds: [audit] });
  const after = [await eff(mia), await eff(bob)];
  return deepEq(during[0], { ...locked, execution: EXEC0 }) && deepEq(during[1], { ...locked, execution: EXEC0 }) && deepEq(during[2], { ...ALL_TRUE, execution: EXEC0 })
    && deepEq(after[0], { ...off("allowCustomProviders"), execution: EXEC0 }) && deepEq(after[1], { ...ALL_TRUE, execution: EXEC0 }) || JSON.stringify([during, after]).slice(0, 600);
});
await t("grants add up: a setting the default turns off stays off unless a policy assigned to the person turns it on", async () => {
  const def = (await listPolicies())[0];
  await api(o, "PATCH", `/v1/desktop-policies/${def.id}`, { policyName: "x", policy: { allowZenModel: false, allowAlphaUpdates: false } });
  const before = await eff(mia);
  await mk({ policyName: "E", policy: { allowZenModel: true }, roles: ["admin"] });
  const got = { mia: await eff(mia), ann: await eff(ann), owner: await eff(o), bob: await eff(bob) };
  return deepEq(before, { ...off("allowCustomProviders", "allowZenModel", "allowAlphaUpdates"), execution: EXEC0 })
    && deepEq(got.mia, { ...off("allowCustomProviders", "allowZenModel", "allowAlphaUpdates"), execution: EXEC0 })
    && deepEq(got.ann, { ...off("allowAlphaUpdates"), execution: EXEC0 }) && deepEq(got.owner, { ...off("allowAlphaUpdates"), execution: EXEC0 })
    && deepEq(got.bob, { ...off("allowZenModel", "allowAlphaUpdates"), execution: EXEC0 }) || JSON.stringify(got).slice(0, 600);
});
await t("an Admin team makes its members match the admin role", async () => {
  const ops = (await api(o, "POST", "/v1/teams", { name: "Ops", memberIds: [bob.memberId], grantsOrganizationAdmin: true }));
  const got = await eff(bob);
  await api(o, "DELETE", `/v1/teams/${ops.json.team.id}`);
  const back = await eff(bob);
  return ops.status === 201 && got.allowZenModel === true && back.allowZenModel === false || JSON.stringify([ops.status, got.allowZenModel, back.allowZenModel]);
});
await t("execution limits intersect: deny wins, blocked commands add up, uploads block if any blocks, origins narrow", async () => {
  await mk({ policyName: "X1", policy: { execution: { commands: "allow", blockedCommands: ["a", "b"], browserOrigins: ["https://a.com", "https://b.com"] } }, teamIds: [design] });
  await mk({ policyName: "X2", policy: { execution: { commands: "deny", blockedCommands: ["b", "c"], browserOrigins: ["https://b.com", "https://c.com"], blockBrowserUploads: true } }, teamIds: [audit] });
  const m = (await eff(mia)).execution, b = (await eff(bob)).execution, a = (await eff(ann)).execution;
  return deepEq(m, { commands: "deny", blockedCommands: ["a", "b", "c"], blockBrowserUploads: true, browserOrigins: ["https://b.com"] })
    && deepEq(b, { commands: "deny", blockedCommands: ["b", "c"], blockBrowserUploads: true, browserOrigins: ["https://b.com", "https://c.com"] })
    && deepEq(a, EXEC0) || JSON.stringify([m, b, a]);
});
let p2;
await t("onboarding suggestions: the highest priority wins, the older breaks a tie, the default is the fallback", async () => {
  await mk({ policyName: "P1", policy: { onboardingPrompts: ["one", "two"] }, teamIds: [design], priority: 1 });
  p2 = (await mk({ policyName: "P2", policy: { onboardingPrompts: ["three", "four", "five"], onboardingPromptDescriptions: ["d3", "d4", "d5"] }, teamIds: [audit], priority: 1 })).json.desktopPolicy.id;
  const tie = [await eff(mia), await eff(bob), await eff(ann)];
  await api(o, "PATCH", `/v1/desktop-policies/${p2}`, { policyName: "P2", policy: { onboardingPrompts: ["three", "four", "five"] }, teamIds: [audit], priority: 2 });
  const higher = await eff(mia);
  const def = (await listPolicies())[0];
  await api(o, "PATCH", `/v1/desktop-policies/${def.id}`, { policyName: "x", policy: { allowZenModel: false, allowAlphaUpdates: false, onboardingPrompts: ["def1", "def2"] } });
  const fallback = await eff(ann);
  return deepEq(tie[0].onboardingPrompts, ["one", "two"]) && tie[0].onboardingPromptDescriptions === undefined
    && deepEq(tie[1].onboardingPrompts, ["three", "four", "five"]) && deepEq(tie[1].onboardingPromptDescriptions, ["d3", "d4", "d5"]) && tie[2].onboardingPrompts === undefined
    && deepEq(higher.onboardingPrompts, ["three", "four", "five"]) && deepEq(fallback.onboardingPrompts, ["def1", "def2"]) || JSON.stringify([tie, higher, fallback]).slice(0, 600);
});
await t("an update that leaves out the onboarding prompts keeps them; a null clears them; descriptions of the wrong count are dropped", async () => {
  const kept = await api(o, "PATCH", `/v1/desktop-policies/${p2}`, { policyName: "P2", policy: { allowZenModel: true }, teamIds: [audit], priority: 2 });
  const cleared = await api(o, "PATCH", `/v1/desktop-policies/${p2}`, { policyName: "P2", policy: { onboardingPrompts: null }, teamIds: [audit], priority: 2 });
  const mism = await mk({ policyName: "dm", policy: { onboardingPrompts: ["a", "b", "c"], onboardingPromptDescriptions: ["x", "y"] } });
  return deepEq(kept.json.desktopPolicy.policy, { allowZenModel: true, onboardingPrompts: ["three", "four", "five"] }) && deepEq(cleared.json.desktopPolicy.policy, {})
    && deepEq(mism.json.desktopPolicy.policy, { onboardingPrompts: ["a", "b", "c"] }) || JSON.stringify([kept.json, cleared.json, mism.json]).slice(0, 500);
});
await t("a policy assigned to one person applies to them alone; deleting it lifts it", async () => {
  const m = await mk({ policyName: "M", policy: {}, memberIds: [mia.memberId, mia.memberId] });
  const mm = await mk({ policyName: "M2", policy: { access: { mode: "custom", capabilities: { allowManageExtensions: false } } }, memberIds: [mia.memberId] });
  const during = [(await eff(mia)).allowManageExtensions, (await eff(bob)).allowManageExtensions];
  await api(o, "DELETE", `/v1/desktop-policies/${mm.json.desktopPolicy.id}`);
  return m.json.desktopPolicy.assignments.length === 1 && during.join() === "false,true" && (await eff(mia)).allowManageExtensions === true || during.join();
});
await t("deleting a team removes its policy assignments, so the policy stops applying to its members", async () => {
  const before = await eff(mia);
  const del = await api(o, "DELETE", `/v1/teams/${design}`);
  const after = await eff(mia);
  const a = (await listPolicies()).find((p) => p.policyName === "A");
  return del.status === 204 && before.allowCustomProviders === false && after.allowCustomProviders === true && a.assignments.length === 0 || JSON.stringify([before.allowCustomProviders, after.allowCustomProviders, a.assignments]);
});
await t("removing a person removes what was assigned to them", async () => {
  const cara = await ws.join("Cara Member");
  const p = await mk({ policyName: "Cara only", policy: {}, memberIds: [cara.memberId] });
  const rm = await api(o, "DELETE", `/v1/members/${cara.memberId}`);
  const after = (await listPolicies()).find((x) => x.id === p.json.desktopPolicy.id);
  return rm.status === 204 && after.assignments.length === 0 || JSON.stringify([rm.status, after?.assignments]);
});

// ------------------------------------------------------------------ declarative (by key)
await t("a policy can be applied by stable key: created (201), replaced (200), read, and deleted idempotently", async () => {
  const put = await api(o, "PUT", "/v1/desktop-policies/by-key/pol-one", { policyName: "Keyed", policy: { onboardingPrompts: ["k1", "k2"], execution: { commands: "deny" } } });
  const again = await api(o, "PUT", "/v1/desktop-policies/by-key/pol-one", { policyName: "Keyed 2", policy: { showWelcomePage: false } });
  const get = await api(o, "GET", "/v1/desktop-policies/by-key/pol-one");
  const miss = await api(o, "GET", "/v1/desktop-policies/by-key/pol-two");
  const del = await api(o, "DELETE", "/v1/desktop-policies/by-key/pol-one");
  const del2 = await api(o, "DELETE", "/v1/desktop-policies/by-key/pol-one");
  const reuse = await api(o, "PUT", "/v1/desktop-policies/by-key/pol-one", { policyName: "Keyed 3", policy: {} });
  return put.status === 201 && put.json.desktopPolicy.externalKey === "pol-one" && again.status === 200 && again.json.desktopPolicy.id === put.json.desktopPolicy.id
    && deepEq(again.json.desktopPolicy.policy, { showWelcomePage: false, execution: { commands: "deny", blockedCommands: [], blockBrowserUploads: false } })   // replaced: prompts gone, execution kept
    && get.status === 200 && miss.status === 404 && del.status === 200 && del.json.deleted === true && del2.json.deleted === false && deepEq(del2.json, { ok: true, deleted: false })
    && reuse.status === 201 && reuse.json.desktopPolicy.id !== put.json.desktopPolicy.id || JSON.stringify([put.json, again.json]).slice(0, 500);
});
await t("a bad key is 400, a conditional header is refused, and by-key writes need the manage permission", async () => {
  const bad = await api(o, "GET", "/v1/desktop-policies/by-key/Bad_Key");
  const cond = await api(o, "PUT", "/v1/desktop-policies/by-key/pol-cond", { policyName: "x", policy: {} }, { headers: { "If-Match": "x" } });
  const nope = await api(mia, "PUT", "/v1/desktop-policies/by-key/pol-cond", { policyName: "x", policy: {} });
  return invalid(bad) && cond.status === 400 && cond.json.error === "unsupported_precondition" && denied(nope, "desktop_policies.manage");
});

// ------------------------------------------------------------------ agent permissions
const SETTINGS_EVERYONE = {
  commands: { decision: "ask", allow: ["npm test *", "npm test *", " git status "], block: ["rm *"] },
  websites: { block: ["Evil.COM", "https://*.bad.com/x/*"] },
  webSearch: { decision: "deny" },
};
await t("agent permissions start empty, every team listed by name with its size; canEdit follows the permission", async () => {
  const r = await api(o, "GET", "/v1/agent-permissions");
  const a = await api(ann, "GET", "/v1/agent-permissions");
  const m = await api(mia, "GET", "/v1/agent-permissions");
  return r.status === 200 && deepEq(r.json.everyone, { teamId: null, name: "Everyone", memberCount: null, settings: {}, updatedAt: null })
    && r.json.teams.map((x) => x.name).join() === "Audit,Zeta" && r.json.teams[0].memberCount === 2 && r.json.canEdit === true
    && a.status === 200 && a.json.canEdit === false && denied(m, "agent_permissions.view") || JSON.stringify(r.json).slice(0, 300);
});
await t("saving agent permissions normalizes patterns, and writes need agent_permissions.manage", async () => {
  const r = await api(o, "PUT", "/v1/agent-permissions/everyone", { settings: SETTINGS_EVERYONE });
  const m = await api(mia, "PUT", "/v1/agent-permissions/everyone", { settings: {} });
  const a = await api(ann, "PUT", "/v1/agent-permissions/everyone", { settings: {} });
  const p = r.json?.policy;
  return r.status === 200 && p.name === "Everyone" && p.teamId === null && /^\d{4}-/.test(p.updatedAt)
    && deepEq(p.settings, { commands: { decision: "ask", allow: ["npm test *", "git status"], block: ["rm *"] }, websites: { block: ["evil.com", "https://*.bad.com/x"] }, webSearch: { decision: "deny" } })
    && denied(m, "agent_permissions.manage") && denied(a, "agent_permissions.manage") || JSON.stringify(r.json).slice(0, 400);
});
await t("agent permission writes are validated", async () => {
  const put = (settings, extra) => api(o, "PUT", "/v1/agent-permissions/everyone", { settings, ...extra });
  const bad = [
    await put({ webSearch: { decision: "ask" } }), await put({ websites: { allow: ["a b"] } }), await put({ fileEdits: { allow: ["x"] } }), await put({ nope: {} }),
    await put({}, { extra: 1 }), await api(o, "PUT", "/v1/agent-permissions/everyone", {}), await put({ commands: { decision: "maybe" } }), await put({ commands: { colour: 1 } }),
    await put({ websites: { block: ["*.exa*mple.com"] } }), await put({ commands: { allow: ["x".repeat(301)] } }),
  ];
  const messages = [bad[0].json.message, bad[1].json.message, bad[2].json.message];
  const stored = (await api(o, "GET", "/v1/agent-permissions")).json.everyone.settings;
  return bad.every(invalid) && messages[0] === "settings.webSearch.decision: Search the web is either allowed or blocked."
    && messages[1] === "settings.websites.allow.0: Enter a site like docs.example.com, *.example.com or example.com/docs." && messages[2] === "settings.fileEdits.allow: Edit files has no allowed list."
    && stored.commands.decision === "ask" || JSON.stringify(bad.map((r) => r.status + (r.json?.message ?? ""))).slice(0, 600);
});
await t("a team's settings are saved, listed and removed idempotently; unknown, malformed and foreign teams are refused", async () => {
  const put = await api(o, "PUT", `/v1/agent-permissions/teams/${audit}`, { settings: { commands: { decision: "deny", allow: ["git *"] } } });
  const list = (await api(o, "GET", "/v1/agent-permissions")).json.teams.find((x) => x.teamId === audit);
  const del = await api(o, "DELETE", `/v1/agent-permissions/teams/${audit}`);
  const del2 = await api(o, "DELETE", `/v1/agent-permissions/teams/${audit}`);
  const empty = await api(o, "PUT", `/v1/agent-permissions/teams/${audit}`, { settings: { commands: {} } });
  const missing = await api(o, "PUT", `/v1/agent-permissions/teams/${MISSING_TEAM}`, { settings: {} });
  const delMissing = await api(o, "DELETE", `/v1/agent-permissions/teams/${MISSING_TEAM}`);
  const bad = await api(o, "PUT", "/v1/agent-permissions/teams/nope", { settings: {} });
  const other = await workspace("Other Agent Workspace");
  const otherTeam = (await other.api(other.owner, "POST", "/v1/teams", { name: "Theirs" })).json.team.id;
  const foreign = await api(o, "PUT", `/v1/agent-permissions/teams/${otherTeam}`, { settings: { commands: { decision: "deny" } } });
  return put.status === 200 && put.json.policy.name === "Audit" && put.json.policy.memberCount === 2 && deepEq(list.settings, { commands: { decision: "deny", allow: ["git *"] } })
    && del.status === 204 && del2.status === 204 && empty.status === 200 && empty.json.policy.updatedAt === null && deepEq(empty.json.policy.settings, {})
    && missing.status === 404 && missing.json.error === "team_not_found" && delMissing.status === 404 && invalid(bad) && foreign.status === 404 || JSON.stringify([put.status, del.status, foreign.status]);
});
await t("a person's rules: strictest team decision wins, allowed patterns survive only when every restricting team allows them, blocks add up", async () => {
  const d2 = await team("Design Two", mia);
  await api(o, "PUT", `/v1/agent-permissions/teams/${d2}`, { settings: { commands: { decision: "deny", allow: ["git *"] }, fileEdits: { decision: "ask" } } });
  await api(o, "PUT", `/v1/agent-permissions/teams/${audit}`, { settings: { commands: { decision: "ask", allow: ["git *", "ls"] } } });
  const rules = async (u) => (await api(u, "GET", "/v1/me/desktop-config")).json.agentPermissions.rules;
  const miaRules = await rules(mia), annRules = await rules(ann), bobRules = await rules(bob), ownerRules = await rules(o);
  const E = "Everyone";
  const everyoneRules = [
    ["shell", "npm test *", "allow", E], ["shell", "git status", "allow", E], null, ["shell", "rm *", "deny", E],
  ];
  const tail = [["webfetch", "evil.com", "deny", E], ["webfetch", "https://*.bad.com/x", "deny", E], ["websearch", "*", "deny", E]];
  const r = (x) => ({ action: x[0], resource: x[1], effect: x[2], source: x[3] });
  // Mia is in "Audit" (ask, git *, ls) and "Design Two" (deny, git *, edits ask): deny from Design Two, with the git * both allow.
  const expectMia = [["shell", "*", "deny", "Design Two"], everyoneRules[0], everyoneRules[1], ["shell", "git *", "allow", "Design Two"], everyoneRules[3], ["edit", "*", "ask", "Design Two"], ...tail].map(r);
  // Bob is only in Audit: ask, with everyone's and Audit's allowed patterns.
  const expectBob = [["shell", "*", "ask", "Audit"], everyoneRules[0], everyoneRules[1], ["shell", "git *", "allow", "Audit"], ["shell", "ls", "allow", "Audit"], everyoneRules[3], ...tail].map(r);
  // Ann is in no team: everyone's ask.
  const expectAnn = [["shell", "*", "ask", E], everyoneRules[0], everyoneRules[1], everyoneRules[3], ...tail].map(r);
  return deepEq(miaRules, expectMia) && deepEq(bobRules, expectBob) && deepEq(annRules, expectAnn) && deepEq(ownerRules, expectAnn)
    || JSON.stringify({ mia: miaRules, bob: bobRules, ann: annRules }).slice(0, 900);
});
await t("blocking file edits also blocks every command, last", async () => {
  await api(o, "PUT", "/v1/agent-permissions/everyone", { settings: { fileEdits: { decision: "deny" }, commands: { decision: "allow", allow: ["ls"] } } });
  const rules = (await api(ann, "GET", "/v1/me/desktop-config")).json.agentPermissions.rules;
  const last = rules[rules.length - 1];
  return deepEq(rules.find((x) => x.action === "edit"), { action: "edit", resource: "*", effect: "deny", source: "Everyone" }) && deepEq(last, { action: "shell", resource: "*", effect: "deny", source: "Everyone" }) || JSON.stringify(rules);
});
await t("deleting a team removes its agent permissions", async () => {
  const tm = await team("Short Lived", ann);
  await api(o, "PUT", `/v1/agent-permissions/teams/${tm}`, { settings: { webSearch: { decision: "deny" } } });
  await api(o, "PUT", "/v1/agent-permissions/everyone", { settings: {} });
  const before = (await api(ann, "GET", "/v1/me/desktop-config")).json.agentPermissions.rules.length;
  await api(o, "DELETE", `/v1/teams/${tm}`);
  const after = (await api(ann, "GET", "/v1/me/desktop-config")).json.agentPermissions.rules.length;
  const list = (await api(o, "GET", "/v1/agent-permissions")).json.teams;
  return before === 1 && after === 0 && list.every((x) => x.teamId !== tm) || JSON.stringify([before, after]);
});

// ------------------------------------------------------------------ prompts
await t("prompts are set for everyone and per team, listed with every team, and delivered in order: everyone, then teams by name", async () => {
  const d3 = await team("Beta", mia);
  const e = await api(o, "PUT", "/v1/org/prompts/everyone", { content: "Be kind." });
  await api(o, "PUT", `/v1/org/prompts/teams/${audit}`, { content: "  Audit rules  " });
  await api(o, "PUT", `/v1/org/prompts/teams/${d3}`, { content: "Beta rules" });
  const view = (await api(o, "GET", "/v1/org/prompts")).json;
  const miaP = (await api(mia, "GET", "/v1/me/prompts")).json.prompts;
  const bobP = (await api(bob, "GET", "/v1/me/prompts")).json.prompts;
  const annP = (await api(ann, "GET", "/v1/me/prompts")).json.prompts;
  const ev = e.json.everyone;
  return e.status === 200 && ev.name === "Everyone" && ev.content === "Be kind." && deepEq(ev.assignment, { everyone: true, teamIds: [], memberIds: [] }) && /^osp_/.test(ev.id) && e.json.canEdit === true
    && view.teams.map((x) => x.name).join() === "Audit,Beta,Design Two,Zeta" && view.teams[0].prompt.content === "  Audit rules  " && deepEq(view.teams[0].prompt.assignment, { everyone: false, teamIds: [audit], memberIds: [] }) && view.teams[3].prompt === null
    && deepEq(miaP.map((p) => [p.source, p.teamName ?? null, p.content]), [["organization", null, "Be kind."], ["team", "Audit", "  Audit rules  "], ["team", "Beta", "Beta rules"]])
    && deepEq(bobP.map((p) => p.content), ["Be kind.", "  Audit rules  "]) && deepEq(annP.map((p) => p.source), ["organization"]) || JSON.stringify([e.json, miaP]).slice(0, 500);
});
await t("a prompt is replaced in place, removed idempotently, and needs prompts.manage; reading needs prompts.view", async () => {
  const id1 = (await api(o, "GET", "/v1/org/prompts")).json.everyone.id;
  const again = await api(o, "PUT", "/v1/org/prompts/everyone", { content: "Be very kind." });
  const adm = await api(ann, "PUT", "/v1/org/prompts/everyone", { content: "Admin wrote" });
  const m = await api(mia, "PUT", "/v1/org/prompts/everyone", { content: "x" });
  const mr = await api(mia, "GET", "/v1/org/prompts");
  const del = await api(o, "DELETE", `/v1/org/prompts/teams/${audit}`);
  const del2 = await api(o, "DELETE", `/v1/org/prompts/teams/${audit}`);
  const miss = await api(o, "DELETE", `/v1/org/prompts/teams/${MISSING_TEAM}`);
  return again.json.everyone.id === id1 && adm.status === 200 && adm.json.everyone.content === "Admin wrote" && denied(m, "prompts.manage") && denied(mr, "prompts.view")
    && del.status === 200 && del.json.teams.find((x) => x.teamId === audit).prompt === null && del2.status === 200 && miss.status === 404 && miss.json.error === "team_not_found";
});
await t("prompt writes are validated (empty, too long, extra keys, unknown or malformed teams)", async () => {
  const bad = [
    await api(o, "PUT", "/v1/org/prompts/everyone", { content: "   " }), await api(o, "PUT", "/v1/org/prompts/everyone", { content: "x".repeat(20001) }),
    await api(o, "PUT", "/v1/org/prompts/everyone", { content: "a", extra: 1 }), await api(o, "PUT", "/v1/org/prompts/everyone", {}), await api(o, "PUT", "/v1/org/prompts/teams/nope", { content: "x" }),
  ];
  const ok = await api(o, "PUT", `/v1/org/prompts/teams/${zeta}`, { content: "x".repeat(20000) });
  const missing = await api(o, "PUT", `/v1/org/prompts/teams/${MISSING_TEAM}`, { content: "x" });
  return bad.every(invalid) && bad[0].json.message === "content: Write a prompt before saving." && ok.status === 200 && missing.status === 404 && missing.json.error === "team_not_found" || bad.map((r) => r.status).join();
});
await t("deleting a team removes its prompt", async () => {
  const tm = await team("Prompted", ann);
  await api(o, "PUT", `/v1/org/prompts/teams/${tm}`, { content: "Only for Prompted" });
  const before = (await api(ann, "GET", "/v1/me/prompts")).json.prompts.map((p) => p.content);
  await api(o, "DELETE", `/v1/teams/${tm}`);
  const after = (await api(ann, "GET", "/v1/me/prompts")).json.prompts.map((p) => p.content);
  return before.includes("Only for Prompted") && !after.includes("Only for Prompted") || JSON.stringify([before, after]);
});

// ------------------------------------------------------------------ default model
await t("default models: nothing set, no models to choose from, so a model is refused and null clears", async () => {
  const get = await api(o, "GET", "/v1/org/default-model");
  const opts = await api(o, "GET", "/v1/org/default-model/options");
  const unknown = await api(o, "PUT", "/v1/org/default-model/everyone", { model: { providerId: "openwork", modelId: "x" } });
  const unknownTeam = await api(o, "PUT", `/v1/org/default-model/teams/${audit}`, { model: { providerId: "x", modelId: "y" } });
  const clear = await api(o, "PUT", "/v1/org/default-model/everyone", { model: null });
  const clearTeam = await api(o, "PUT", `/v1/org/default-model/teams/${audit}`, { model: null });
  const adm = await api(ann, "PUT", "/v1/org/default-model/everyone", { model: null });
  return get.status === 200 && get.json.everyone === null && get.json.canEdit === true && deepEq(get.json.teams.find((x) => x.teamId === audit), { teamId: audit, name: "Audit", memberCount: 2, model: null, conflictingMemberCount: 0 })
    && deepEq(opts.json, { options: [], unavailableSources: [] }) && unknown.status === 400 && unknown.json.error === "unknown_model" && unknown.json.message === "That model isn't one your organization has. Choose one from the list."
    && unknownTeam.json.error === "unknown_model" && clear.status === 200 && clearTeam.status === 200 && adm.status === 200 || JSON.stringify([get.json, opts.json, unknown.json]).slice(0, 500);
});
await t("default model writes are validated and permissioned (inference.manage / inference.view)", async () => {
  const bad = [
    await api(o, "PUT", "/v1/org/default-model/everyone", { model: { providerId: "", modelId: "x" } }), await api(o, "PUT", "/v1/org/default-model/everyone", {}),
    await api(o, "PUT", "/v1/org/default-model/teams/nope", { model: null }),
  ];
  const missing = await api(o, "PUT", `/v1/org/default-model/teams/${MISSING_TEAM}`, { model: null });
  const m = await api(mia, "PUT", "/v1/org/default-model/everyone", { model: null });
  const mr = await api(mia, "GET", "/v1/org/default-model");
  const mo = await api(mia, "GET", "/v1/org/default-model/options");
  return bad.every(invalid) && missing.status === 404 && missing.json.error === "team_not_found" && denied(m, "inference.manage") && denied(mr, "inference.view") && denied(mo, "inference.view");
});

// ------------------------------------------------------------------ Automations, Workbot, Auto Router
await t("Automation settings: any member reads, organization.update writes; both on by default, Cloud needs a runner this deployment lacks", async () => {
  const get = await api(mia, "GET", "/v1/org/automation-settings");
  const both = await api(o, "PUT", "/v1/org/automation-settings", { desktop: false });
  const memberRead = await api(mia, "GET", "/v1/org/automation-settings");
  const cfg = (await api(mia, "GET", "/v1/me/desktop-config")).json;
  const cloud = await api(o, "PUT", "/v1/org/automation-settings", { cloud: true });
  const off2 = await api(o, "PUT", "/v1/org/automation-settings", { cloud: false });
  const back = await api(o, "PUT", "/v1/org/automation-settings", { desktop: true });
  const bad = [await api(o, "PUT", "/v1/org/automation-settings", {}), await api(o, "PUT", "/v1/org/automation-settings", { desktop: true, x: 1 }), await api(o, "PUT", "/v1/org/automation-settings", { desktop: "yes" })];
  const m = await api(mia, "PUT", "/v1/org/automation-settings", { desktop: true });
  const a = await api(ann, "PUT", "/v1/org/automation-settings", { desktop: true });
  return get.status === 200 && deepEq(get.json.settings, { desktop: true, cloud: true }) && get.json.deploymentEnabled === true
    && both.status === 200 && deepEq(both.json.settings, { desktop: false, cloud: true }) && both.json.available.desktop === false && memberRead.json.settings.desktop === false
    && cfg.desktopAutomationsEnabled === false && cfg.automationsEnabled === false
    && cloud.status === 409 && cloud.json.error === "headless_runner_required" && off2.status === 200 && deepEq(off2.json.settings, { desktop: false, cloud: false }) && deepEq(back.json.settings, { desktop: true, cloud: false })
    && bad.every(invalid) && bad[0].json.message === "Provide desktop, cloud or both." && denied(m, "organization.update") && denied(a, "organization.update") || JSON.stringify([get.json, both.json, cloud.json]).slice(0, 500);
});
await t("Workbot: readiness is open to members, settings read needs inference.view, only 'the default' can be saved without a runner", async () => {
  const ready = await api(mia, "GET", "/v1/org/workbot-readiness");
  const get = await api(o, "GET", "/v1/org/workbot-settings");
  const adm = await api(ann, "GET", "/v1/org/workbot-settings");
  const denyRead = await api(mia, "GET", "/v1/org/workbot-settings");
  const putNull = await api(o, "PUT", "/v1/org/workbot-settings", { model: null });
  const putModel = await api(o, "PUT", "/v1/org/workbot-settings", { model: "openai/gpt-5" });
  const bad = await api(o, "PUT", "/v1/org/workbot-settings", {});
  const m = await api(mia, "PUT", "/v1/org/workbot-settings", { model: null });
  return ready.status === 200 && deepEq(ready.json, { gatewayRequired: true, hasGatewayProvider: false })
    && deepEq(get.json, { model: null, gatewayModels: true, defaultModel: "openai/gpt-6-luna", defaultReadiness: "unverified", models: [], modelAvailable: true, runnerReachable: false }) && adm.status === 200 && denied(denyRead, "inference.view")
    && putNull.status === 200 && putModel.status === 503 && putModel.json.error === "workbot_runner_unavailable" && invalid(bad) && denied(m, "inference.manage") || JSON.stringify([ready.json, get.json, putModel.json]).slice(0, 500);
});
await t("the Auto Router and Workbot's proactive agents answer 404 feature_disabled while their features are off", async () => {
  const rs = [await api(o, "GET", "/v1/org/auto-router"), await api(mia, "GET", "/v1/org/auto-router/options"), await api(o, "GET", "/v1/org/auto-router/connect"), await api(o, "GET", "/v1/org/workbot-settings/proactive")];
  return rs.every((r) => r.status === 404 && r.json.error === "feature_disabled") && rs[0].json.feature === "autoRouter" && rs[3].json.feature === "workbotProactive" || JSON.stringify(rs.map((r) => r.status));
});
await t("/v1/me/desktop-config carries the delivered fields and needs a session and membership", async () => {
  const j = (await api(mia, "GET", "/v1/me/desktop-config")).json;
  const anon = await call(A, "/v1/me/desktop-config");
  const stranger = await call(A, "/v1/me/desktop-config", { bearer: (await (await import("./lib.mjs")).person("Stranger Person")).token, headers: { "x-openwork-org-id": ws.orgId } });
  return j.connectEnabled === true && j.localProviderMirror === true && j.removeOpencodeZen === true && j.liveProviderSync === true && j.dashboardEnabled === false && Array.isArray(j.agentPermissions.rules)
    && anon.status === 401 && stranger.status === 404 || JSON.stringify([Object.keys(j), anon.status, stranger.status]);
});

s.done();
