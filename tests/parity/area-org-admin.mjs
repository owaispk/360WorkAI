// Contract test for the "org admin" area: API keys, the audit log, organization settings, approved web origins, brand assets, features and
// the small read routes. Runs unchanged against the reference Den and the rewrite (see ../../docs/AREA_GUIDE.md):
//   node area-org-admin.mjs                                                  # reference: web :3005, api :8790
//   W=http://localhost:5210 A=http://localhost:5110 node area-org-admin.mjs  # rewrite
// The reference has no audit entitlement unless started with one, so the audit checks that need captured events run only when
// GET /v1/audit/usage reports an entitlement (the rewrite does by default); the shape and validation checks always run.
import { deflateSync, crc32 } from "node:zlib";
import { A, W, call, denied, keys, person, suite, workspace } from "./lib.mjs";

const s = suite("org-admin");
const t = s.t.bind(s);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** A valid, plain PNG of the given size (RGB, one colour). */
function png(width, height) {
  const chunk = (type, data) => {
    const body = Buffer.concat([Buffer.from(type), data]);
    const out = Buffer.alloc(12 + data.length);
    out.writeUInt32BE(data.length, 0);
    body.copy(out, 4);
    out.writeUInt32BE(crc32(body) >>> 0, 8 + data.length);
    return out;
  };
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0); header.writeUInt32BE(height, 4); header[8] = 8; header[9] = 2;
  const row = Buffer.alloc(1 + width * 3, 0x55); row[0] = 0;
  const raw = Buffer.concat(Array.from({ length: height }, () => row));
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk("IHDR", header), chunk("IDAT", deflateSync(raw)), chunk("IEND", Buffer.alloc(0))]);
}

async function upload(ws, user, parts) {
  const form = new FormData();
  for (const [name, bytes, type, file] of parts) form.append(name, new Blob([bytes], { type }), file ?? `${name}.png`);
  const res = await fetch(A + "/v1/org/brand-assets", { method: "POST", headers: { authorization: `Bearer ${user.token}`, "x-openwork-org-id": ws.orgId, origin: W }, body: form });
  const text = await res.text();
  let json = null; try { json = JSON.parse(text); } catch {}
  return { status: res.status, json, text };
}

const ws = await workspace("Org Admin Probe");
const owner = ws.owner;
const plain = await ws.join("Plain Member");
const admin = await ws.join("Admin Person", "admin");
const api = (u, method, path, body, extra) => ws.api(u, method, path, body, extra);
const withKey = (key, path, { method = "GET", body, org } = {}) => call(A, path, { method, body, headers: { "x-api-key": key, ...(org ? { "x-openwork-org-id": org } : {}) } });

// ---- API keys ---------------------------------------------------------------------------------------------------------------------
let created; let secret; let keyId;
await t("api keys: name is validated (2 to 64 characters, required)", async () => {
  const short = await api(owner, "POST", "/v1/api-keys", { name: "a" });
  const missing = await api(owner, "POST", "/v1/api-keys", {});
  const long = await api(owner, "POST", "/v1/api-keys", { name: "x".repeat(65) });
  const ok = [short, missing, long].every((r) => r.status === 400 && r.json?.error === "invalid_request" && r.json.message.startsWith("name: "));
  return ok && short.json.message.includes(">=2") && long.json.message.includes("<=64") || JSON.stringify([short.json, missing.json, long.json]);
});
await t("api keys: create answers 201 with the key once, a prefix, a short start and the default limits", async () => {
  created = await api(owner, "POST", "/v1/api-keys", { name: "  Build Server  " });
  secret = created.json?.key; keyId = created.json?.apiKey?.id;
  const k = created.json?.apiKey;
  return created.status === 201
    && keys(created.json) === "apiKey,key"
    && keys(k) === "createdAt,enabled,expiresAt,id,name,prefix,rateLimitEnabled,rateLimitMax,rateLimitTimeWindow,start,updatedAt"
    && k.name === "Build Server" && k.prefix === "den_" && secret.startsWith("den_") && secret.length >= 40 && k.start === secret.slice(0, 6)
    && k.enabled === true && k.rateLimitEnabled === true && k.rateLimitMax === 600 && k.rateLimitTimeWindow === 60000
    && k.id.startsWith("apk_") && Math.round((Date.parse(k.expiresAt) - Date.parse(k.createdAt)) / 86400000) === 90
    || created.text;
});
await t("api keys: two keys never share a secret", async () => {
  const other = await api(owner, "POST", "/v1/api-keys", { name: "Second Key" });
  return other.status === 201 && other.json.key !== secret && other.json.apiKey.start !== undefined;
});
await t("api keys: the list shows every key with its owner and never a secret", async () => {
  const list = await api(owner, "GET", "/v1/api-keys");
  const k = list.json?.apiKeys?.find((x) => x.id === keyId);
  return list.status === 200 && keys(list.json) === "apiKeys" && k
    && keys(k) === "configId,createdAt,enabled,expiresAt,id,lastRequest,name,owner,prefix,rateLimitEnabled,rateLimitMax,rateLimitTimeWindow,start,updatedAt"
    && keys(k.owner) === "email,image,memberId,name,userId" && k.owner.userId === owner.userId && !list.text.includes(secret)
    && list.json.apiKeys.map((x) => x.createdAt).join() === [...list.json.apiKeys.map((x) => x.createdAt)].sort().reverse().join() || list.text.slice(0, 300);
});
await t("api keys: viewing needs api_keys.view and creating or deleting needs api_keys.manage (owner only by default)", async () => {
  const a = await api(plain, "GET", "/v1/api-keys");
  const b = await api(plain, "POST", "/v1/api-keys", { name: "Mine" });
  const c = await api(admin, "GET", "/v1/api-keys");
  const d = await api(admin, "POST", "/v1/api-keys", { name: "Admin key" });
  const e = await api(plain, "DELETE", `/v1/api-keys/${keyId}`);
  return denied(a, "api_keys.view") && denied(b, "api_keys.manage") && c.status === 200 && denied(d, "api_keys.manage") && denied(e, "api_keys.manage")
    || JSON.stringify([a.status, b.status, c.status, d.status, e.status]);
});
await t("api keys: x-api-key signs a request in as the key's member, in the key's workspace only", async () => {
  const org = await withKey(secret, "/v1/org");
  const other = await workspace("Org Admin Other");
  const wrongOrg = await withKey(secret, "/v1/org", { org: other.orgId });
  const me = await withKey(secret, "/v1/me");
  const orgs = await withKey(secret, "/v1/me/orgs");
  return org.status === 200 && org.json.organization.id === ws.orgId && org.json.currentMember.userId === owner.userId
    && wrongOrg.status === 200 && wrongOrg.json.organization.id === ws.orgId     // the header cannot point a key at another workspace
    && me.status === 200 && me.json.user.id === owner.userId && me.json.session === null
    && orgs.status === 200 && orgs.json.activeOrgId === ws.orgId
    || JSON.stringify([org.status, wrongOrg.status, me.status, me.json, orgs.status]);
});
await t("api keys: a wrong or missing key is 401", async () => {
  const a = await withKey(secret + "x", "/v1/org");
  const b = await withKey("den_" + "z".repeat(64), "/v1/org");
  const c = await call(A, "/v1/org");
  return [a, b, c].every((r) => r.status === 401 && r.json?.error === "unauthorized") || JSON.stringify([a.status, b.status, c.status]);
});
await t("api keys: a key holds exactly its member's permissions (owner key creates invitations; the list shows last use)", async () => {
  const invite = await withKey(secret, "/v1/invitations", { method: "POST", body: { email: `key.${Date.now()}@example.com`, role: "member" } });
  const list = await api(owner, "GET", "/v1/api-keys");
  const k = list.json.apiKeys.find((x) => x.id === keyId);
  return invite.status === 201 && k.lastRequest !== null && !Number.isNaN(Date.parse(k.lastRequest)) || JSON.stringify([invite.status, k?.lastRequest]);
});
await t("api keys: a member who may manage keys makes one; removing that member turns the key off at once", async () => {
  const maker = await ws.join("Key Maker");
  const team = await api(owner, "POST", "/v1/teams", { name: "Key Team", memberIds: [maker.memberId] });
  const role = await api(owner, "POST", "/v1/permissions/sets", { teamId: team.json.team.id, permissions: [{ key: "api_keys.manage", status: "allow" }, { key: "api_keys.view", status: "allow" }] });
  const made = await api(maker, "POST", "/v1/api-keys", { name: "Maker key" });
  const works = await withKey(made.json?.key, "/v1/api-keys");
  const removed = await api(owner, "DELETE", `/v1/members/${maker.memberId}`);
  const after = await withKey(made.json?.key, "/v1/api-keys");
  const list = await api(owner, "GET", "/v1/api-keys");
  return role.status === 201 && made.status === 201 && works.status === 200 && removed.status === 204 && after.status === 401
    && !list.json.apiKeys.some((x) => x.id === made.json.apiKey.id) || JSON.stringify([made.status, works.status, removed.status, after.status]);
});
await t("api keys: delete answers 404 for an unknown or another workspace's key, 204 for ours, and the key stops working", async () => {
  const other = await workspace("Org Admin Keys B");
  const theirKey = await other.api(other.owner, "POST", "/v1/api-keys", { name: "Their key" });
  const theirs = theirKey.status;
  const unknown = await api(owner, "DELETE", "/v1/api-keys/zzz");
  const foreign = await other.api(other.owner, "DELETE", `/v1/api-keys/${keyId}`);
  const ourAttempt = await api(owner, "DELETE", `/v1/api-keys/${theirKey.json.apiKey.id}`);
  const theirsStill = await withKey(theirKey.json.key, "/v1/org");
  const removed = await api(owner, "DELETE", `/v1/api-keys/${keyId}`);
  const after = await withKey(secret, "/v1/org");
  const again = await api(owner, "DELETE", `/v1/api-keys/${keyId}`);
  const list = await api(owner, "GET", "/v1/api-keys");
  return theirs === 201 && unknown.status === 404 && unknown.json?.error === "api_key_not_found" && foreign.status === 404 && removed.status === 204 && after.status === 401
    && ourAttempt.status === 404 && theirsStill.status === 200 && again.status === 404 && !list.json.apiKeys.some((x) => x.id === keyId) || JSON.stringify([unknown.status, foreign.status, removed.status, after.status, again.status]);
});

// ---- audit log --------------------------------------------------------------------------------------------------------------------
let entitled = false;
await t("audit: reading needs audit.view (members denied, admins allowed) and answers are not cached", async () => {
  const a = await api(plain, "GET", "/v1/audit/operations");
  const b = await api(admin, "GET", "/v1/audit/operations");
  const c = await api(plain, "GET", "/v1/audit/usage");
  return denied(a, "audit.view") && denied(c, "audit.view") && b.status === 200 && b.headers.get("cache-control") === "no-store" || JSON.stringify([a.status, b.status]);
});
await t("audit: usage has the documented shape", async () => {
  const r = await api(owner, "GET", "/v1/audit/usage");
  entitled = r.json?.entitlement?.enabled === true;
  return r.status === 200 && keys(r.json) === "billing,captureAvailable,captureEnabled,captureOn,cleanup,drains,entitlement,eventCount,logicalBytes,measuredAt,oldestAvailableAt,policy,retainedOperations"
    && keys(r.json.entitlement) === "enabled,source" && r.json.billing === "disabled" && r.json.cleanup === "dry_run" && r.json.drains === "not_configured"
    && (r.json.policy === null || keys(r.json.policy) === "allowance,attachmentWindowSeconds,captureStartedAt,categories,effectiveAt,enabled,excessMode,organizationId,revision,source") || r.text;
});
await t("audit: event types are a sorted, unique list of stable names", async () => {
  const r = await api(owner, "GET", "/v1/audit/event-types");
  const list = r.json?.eventTypes ?? [];
  const sorted = [...list].sort();
  return r.status === 200 && keys(r.json) === "eventTypes" && list.length > 10 && new Set(list).size === list.length && list.join() === sorted.join()
    && list.every((x) => /^[a-z][a-z0-9_.-]*$/.test(x)) && ["api_key.created", "api_key.deleted", "member.removed", "invitation.created", "permission_set.created", "web_origin.approved"].every((x) => list.includes(x))
    || r.text.slice(0, 200);
});
await t("audit: operations list has the page shape and the first-event header", async () => {
  const r = await api(owner, "GET", "/v1/audit/operations?limit=5");
  return r.status === 200 && keys(r.json) === "nextCursor,operations,snapshotAt" && Array.isArray(r.json.operations) && !Number.isNaN(Date.parse(r.json.snapshotAt))
    && r.headers.get("x-audit-resource-scope") === "first_event" || r.text.slice(0, 200);
});
await t("audit: bad queries are 400 audit_invalid_query, a bad cursor is audit_invalid_cursor", async () => {
  const bad = ["limit=0", "limit=101", "limit=abc", "outcome=zzz", "origin=zzz", "limit=1&limit=2", "foo=1", "actorId=abc", "from=yesterday", "from=2026-01-01T00:00:00",
    "from=2026-02-01&to=2026-01-01", "resourceType=team", "action=Bad%20Action", "searchId=" + "x".repeat(256)];
  for (const q of bad) {
    const r = await api(owner, "GET", `/v1/audit/operations?${q}`);
    if (r.status !== 400 || r.json?.error !== "audit_invalid_query") return `${q} -> ${r.status} ${r.text.slice(0, 100)}`;
  }
  const cursor = await api(owner, "GET", "/v1/audit/operations?cursor=abc");
  const extra = await api(owner, "GET", "/v1/audit/event-types?x=1");
  const usage = await api(owner, "GET", "/v1/audit/usage?x=1");
  return cursor.status === 400 && cursor.json?.error === "audit_invalid_cursor" && extra.status === 400 && usage.status === 400 || JSON.stringify([cursor.json, extra.status, usage.status]);
});
await t("audit: good filters are accepted", async () => {
  const r = await api(owner, "GET", "/v1/audit/operations?from=2026-01-01&to=2099-12-31T00:00:00Z&limit=100&outcome=succeeded&origin=api&action=team.create.succeeded&searchId=abc&resourceId=abc&resourceType=team");
  return r.status === 200 && r.json.operations.length === 0 || r.text.slice(0, 200);
});
await t("audit: an operation that does not exist (or is malformed) is 404 or 400, never someone else's", async () => {
  const unknown = await api(owner, "GET", "/v1/audit/operations/aop_01m679526ge3yv9fx8c8thmxd4/events");
  const bad = await api(owner, "GET", "/v1/audit/operations/zzz/events");
  return unknown.status === 404 && unknown.json?.error === "audit_operation_not_found" && bad.status === 400 && bad.json?.error === "audit_invalid_query" || JSON.stringify([unknown.status, bad.status]);
});
await t("audit: export is ndjson by default or csv with a header row; other formats are refused", async () => {
  const nd = await api(owner, "GET", "/v1/audit/export");
  const csv = await api(owner, "GET", "/v1/audit/export?format=csv");
  const bad = await api(owner, "GET", "/v1/audit/export?format=xml");
  return nd.status === 200 && nd.headers.get("content-type").startsWith("application/x-ndjson") && /^attachment; filename="audit-\d+\.ndjson"$/.test(nd.headers.get("content-disposition"))
    && nd.headers.get("x-audit-snapshot-at") !== null
    && csv.status === 200 && csv.headers.get("content-type").startsWith("text/csv") && csv.text.startsWith('"schema_version","event_id","operation_id"') && bad.status === 400
    || JSON.stringify([nd.status, csv.status, bad.status]);
});
await t("audit: changing capture validates its body and needs audit.manage", async () => {
  const empty = await api(owner, "PATCH", "/v1/audit/settings", {});
  const extra = await api(owner, "PATCH", "/v1/audit/settings", { captureOn: false, expectedRevision: 0, x: 1 });
  const float = await api(owner, "PATCH", "/v1/audit/settings", { captureOn: false, expectedRevision: 1.5 });
  const neg = await api(owner, "PATCH", "/v1/audit/settings", { captureOn: false, expectedRevision: -1 });
  const member = await api(plain, "PATCH", "/v1/audit/settings", { captureOn: false, expectedRevision: 0 });
  return empty.status === 400 && empty.json.message.startsWith("captureOn: ") && extra.status === 400 && extra.json.message.startsWith("Unrecognized key")
    && float.status === 400 && float.json.message.includes("expected int") && neg.status === 400 && denied(member, "audit.manage") || JSON.stringify([empty.status, extra.status, float.status, neg.status, member.status]);
});
if (!entitled) {
  await t("audit (no entitlement): turning capture on is 402, a stale revision is 409, off from nothing is a no-op", async () => {
    const on = await api(owner, "PATCH", "/v1/audit/settings", { captureOn: true, expectedRevision: 0 });
    const stale = await api(owner, "PATCH", "/v1/audit/settings", { captureOn: false, expectedRevision: 1 });
    const off = await api(owner, "PATCH", "/v1/audit/settings", { captureOn: false, expectedRevision: 0 });
    return on.status === 402 && on.json.error === "enterprise_plan_required" && on.json.feature === "auditLogs"
      && stale.status === 409 && stale.json.error === "audit_policy_changed" && off.status === 200 && off.json.captureOn === false && off.json.policy === null
      || JSON.stringify([on.status, stale.status, off.status]);
  });
} else {
  let revision;
  await t("audit (entitled): the first read starts capture, with a lifecycle event", async () => {
    const usage = await api(owner, "GET", "/v1/audit/usage");
    revision = usage.json.policy?.revision;
    const types = (await api(owner, "GET", "/v1/audit/operations?action=audit.policy.initialized")).json.operations;
    return usage.json.captureOn === true && usage.json.captureEnabled === true && revision === 1 && types.length === 1 && types[0].initiatingActor.type === "system" || JSON.stringify(usage.json);
  });
  await t("audit (entitled): changes are recorded with who, what and before/after, and can be found by id", async () => {
    const team = await api(owner, "POST", "/v1/teams", { name: "Audited Team" });
    const teamId = team.json.team.id;
    await api(owner, "PATCH", `/v1/teams/${teamId}`, { name: "Audited Team Renamed" });
    const found = await api(owner, "GET", `/v1/audit/operations?resourceType=team&resourceId=${teamId}`);
    const ops = found.json.operations;
    if (ops.length !== 2) return `expected 2 operations for the team, got ${ops.length}: ${found.text.slice(0, 300)}`;
    const newest = ops[0];   // newest first
    const events = await api(owner, "GET", `/v1/audit/operations/${newest.id}/events`);
    const e = events.json.events[0];
    const bySearch = await api(owner, "GET", `/v1/audit/operations?searchId=${e.id}`);
    return newest.action === "team.update.succeeded" && ops[1].action === "team.create.succeeded" && newest.initiatingActor.id === owner.userId && newest.origin === "api" && newest.outcome === "succeeded"
      && newest.resources.some((r) => r.type === "team" && r.id === teamId && r.relationship === "target")
      && keys(e) === "action,actor,category,changes,http,id,logicalBytes,occurredAt,operation,operationId,organizationId,outcome,recordedAt,requestId,resources,schemaVersion"
      && e.schemaVersion === 2 && e.actor.memberId === (await ws.memberId(owner)) && e.changes.before.name === "Audited Team" && e.changes.after.name === "Audited Team Renamed" && e.changes.changedFields.includes("name")
      && e.http.method === "PATCH" && bySearch.json.operations.some((o) => o.id === newest.id) || JSON.stringify(e);
  });
  await t("audit (entitled): an API key's actions name the key, and secrets never appear", async () => {
    const made = await api(owner, "POST", "/v1/api-keys", { name: "Audited Key" });
    const via = await withKey(made.json.key, "/v1/teams/tem_01m679526ge3yv9fx8c8thmxd4");   // any key request is fine; creating a web origin is the audited one
    const origin = await call(A, "/v1/org/web-origins", { method: "POST", headers: { "x-api-key": made.json.key }, body: { origin: "https://keyed.example.com" } });
    const created = await api(owner, "GET", `/v1/audit/operations?resourceId=${made.json.apiKey.id}`);
    const approved = await api(owner, "GET", "/v1/audit/operations?action=web_origin.approved");
    const op = approved.json.operations[0];
    const ev = (await api(owner, "GET", `/v1/audit/operations/${op.id}/events`)).json.events[0];
    const dump = JSON.stringify([created.json, approved.json, ev]);
    return via.status === 404 && origin.status === 201 && created.json.operations.some((o) => o.action === "api_key.created") && ev.actor.credentialId === made.json.apiKey.id
      && !dump.includes(made.json.key) && !dump.includes(made.json.key.slice(0, 20)) || dump.slice(0, 400);
  });
  await t("audit (entitled): sign-in, member and invitation events are recorded in the workspace", async () => {
    const who = await person("Audit Joiner");
    const inv = await api(owner, "POST", "/v1/invitations", { email: who.email, role: "member" });
    await call(A, "/v1/orgs/invitations/accept", { method: "POST", bearer: who.token, body: { id: inv.json.invitationId } });
    const list = await api(owner, "GET", "/v1/audit/operations?limit=100");
    const actions = list.json.operations.map((o) => o.action);
    return ["invitation.created", "invitation.accept.confirmed"].every((a) => actions.includes(a)) || actions.join();
  });
  await t("audit (entitled): switching capture needs the current revision, records itself, and no-ops change nothing", async () => {
    const stale = await api(owner, "PATCH", "/v1/audit/settings", { captureOn: false, expectedRevision: 99 });
    const off = await api(owner, "PATCH", "/v1/audit/settings", { captureOn: false, expectedRevision: revision });
    const again = await api(owner, "PATCH", "/v1/audit/settings", { captureOn: false, expectedRevision: revision });
    const same = await api(owner, "PATCH", "/v1/audit/settings", { captureOn: false, expectedRevision: revision + 1 });
    const on = await api(owner, "PATCH", "/v1/audit/settings", { captureOn: true, expectedRevision: revision + 1 });
    const types = (await api(owner, "GET", "/v1/audit/operations?action=audit.capture.disabled")).json.operations;
    return stale.status === 409 && stale.json.error === "audit_policy_changed" && off.status === 200 && off.json.captureOn === false && off.json.policy.revision === revision + 1
      && again.status === 409 && same.status === 200 && same.json.policy.revision === revision + 1 && on.status === 200 && on.json.captureOn === true && on.json.policy.revision === revision + 2
      && types.length === 1 || JSON.stringify([stale.status, off.json, again.status, same.status, on.json, types.length]);
  });
  await t("audit (entitled): pages follow a signed cursor and stay inside the snapshot; a cursor from other filters is refused", async () => {
    const first = await api(owner, "GET", "/v1/audit/operations?limit=2");
    if (!first.json.nextCursor) return "expected more than two operations";
    const second = await api(owner, "GET", `/v1/audit/operations?limit=2&cursor=${encodeURIComponent(first.json.nextCursor)}`);
    const mismatch = await api(owner, "GET", `/v1/audit/operations?limit=2&outcome=failed&cursor=${encodeURIComponent(first.json.nextCursor)}`);
    const forged = await api(owner, "GET", `/v1/audit/operations?cursor=${encodeURIComponent(first.json.nextCursor.slice(0, -2) + "xx")}`);
    const ids = [...first.json.operations, ...second.json.operations].map((o) => o.id);
    return second.status === 200 && new Set(ids).size === ids.length && second.json.snapshotAt === first.json.snapshotAt && mismatch.json?.error === "audit_invalid_cursor" && forged.json?.error === "audit_invalid_cursor"
      || JSON.stringify([second.status, mismatch.json, forged.json]);
  });
  await t("audit (entitled): the CSV export quotes every cell and neutralizes formulas", async () => {
    await api(owner, "POST", "/v1/teams", { name: "=cmd|' /C calc'!A0" });
    await sleep(Number(process.env.AUDIT_SETTLE_MS ?? 5200));
    const csv = await api(owner, "GET", "/v1/audit/export?format=csv&limit=100");
    const nd = await api(owner, "GET", "/v1/audit/export?limit=100");
    const lines = csv.text.trim().split("\r\n");
    return csv.status === 200 && lines.length > 5 && lines.every((l) => l.startsWith('"')) && nd.text.trim().split("\n").every((l) => JSON.parse(l).schemaVersion === 2)
      && !csv.text.includes(',"=cmd') || csv.text.slice(0, 300);
  });
}

// ---- organization settings --------------------------------------------------------------------------------------------------------
await t("org settings: a change needs at least one valid field", async () => {
  const empty = await api(owner, "PATCH", "/v1/org", {});
  const short = await api(owner, "PATCH", "/v1/org", { name: "a" });
  const unknown = await api(owner, "PATCH", "/v1/org", { name: "Fine Name", foo: 1 });
  const url = await api(owner, "PATCH", "/v1/org", { brandLogoUrl: "notaurl" });
  const badDomain = await api(owner, "PATCH", "/v1/org", { allowedEmailDomains: ["not a domain", "good.com"] });
  return empty.status === 400 && empty.json.message === "Provide at least one organization field to update."
    && short.status === 400 && short.json.message === "name: Too small: expected string to have >=2 characters"
    && unknown.status === 400 && unknown.json.message.startsWith('Unrecognized key: "foo"')
    && url.status === 400 && url.json.message === "brandLogoUrl: Invalid URL"
    && badDomain.status === 400 && badDomain.json.error === "invalid_email_domain" && badDomain.json.invalidDomains.join() === "not a domain"
    || JSON.stringify([empty.json, short.json, unknown.json, url.json, badDomain.json]);
});
await t("org settings: members and admins may not edit them (organization.update is the owner's)", async () => {
  const a = await api(plain, "PATCH", "/v1/org", { name: "Nope Nope" });
  const b = await api(admin, "PATCH", "/v1/org", { name: "Nope Nope" });
  return denied(a, "organization.update") && denied(b, "organization.update") || JSON.stringify([a.status, b.status]);
});
await t("org settings: renaming trims, answers the organization (metadata as an object) and shows in GET /v1/org", async () => {
  const r = await api(owner, "PATCH", "/v1/org", { name: "  Renamed Org  " });
  const org = r.json?.organization;
  const got = await api(owner, "GET", "/v1/org");
  return r.status === 200 && org.name === "Renamed Org" && org.id === ws.orgId && org.slug === got.json.organization.slug && typeof org.metadata === "object" && org.logo === null
    && ["id", "name", "slug", "logo", "allowedEmailDomains", "metadata", "createdAt", "updatedAt"].every((k) => k in org)
    && got.json.organization.name === "Renamed Org" && typeof got.json.organization.metadata === "string" || JSON.stringify(r.json);
});
await t("org settings: allowed email domains are normalized (case, @, duplicates, order), cleared by null or empty, and enforced on invitations", async () => {
  const set = await api(owner, "PATCH", "/v1/org", { allowedEmailDomains: ["Zeta.COM", "@alpha.org", "alpha.org"] });
  const got = await api(owner, "GET", "/v1/org");
  const outside = await api(owner, "POST", "/v1/invitations", { email: "x@other.net", role: "member" });
  const inside = await api(owner, "POST", "/v1/invitations", { email: "x@alpha.org", role: "member" });
  const cleared = await api(owner, "PATCH", "/v1/org", { allowedEmailDomains: [] });
  const anyone = await api(owner, "POST", "/v1/invitations", { email: "y@other.net", role: "member" });
  return set.json.organization.allowedEmailDomains.join() === "alpha.org,zeta.com" && got.json.organization.allowedEmailDomains.join() === "alpha.org,zeta.com"
    && outside.status === 409 && outside.json.error === "invite_email_domain_not_allowed" && outside.json.emailDomain === "other.net" && outside.json.allowedEmailDomains.join() === "alpha.org,zeta.com"
    && inside.status === 201 && cleared.json.organization.allowedEmailDomains === null && anyone.status === 201
    || JSON.stringify([set.json, outside.status, outside.json, inside.status, anyone.status]);
});
await t("org settings: brand fields are kept in the metadata and can be removed with null", async () => {
  const set = await api(owner, "PATCH", "/v1/org", { brandAppName: "Acme Work", brandAccentColor: "#336699", brandLogoUrl: "https://example.com/logo.png" });
  const got = JSON.parse((await api(owner, "GET", "/v1/org")).json.organization.metadata);
  const cleared = await api(owner, "PATCH", "/v1/org", { brandAppName: null, brandLogoUrl: null });
  const after = JSON.parse((await api(owner, "GET", "/v1/org")).json.organization.metadata);
  return set.status === 200 && got.brandAppName === "Acme Work" && got.brandAccentColor === "#336699" && got.brandLogoUrl === "https://example.com/logo.png"
    && cleared.status === 200 && !("brandAppName" in after) && !("brandLogoUrl" in after) && after.brandAccentColor === "#336699" || JSON.stringify([got, after]);
});
await t("org settings: GET /v1/org carries features, capabilities, entitlements and plan", async () => {
  const r = await api(owner, "GET", "/v1/org");
  return typeof r.json.features === "object" && r.json.features.engineV2ForceUpgrade === true && Object.values(r.json.features).every((v) => typeof v === "boolean")
    && typeof r.json.capabilities.auditLogs === "boolean" && typeof r.json.entitlements.auditLogs === "boolean" && r.json.plan.tier === "free" && "authMethods" in r.json || JSON.stringify(Object.keys(r.json));
});

// ---- approved web origins ---------------------------------------------------------------------------------------------------------
let originId;
await t("web origins: only exact https origins are accepted", async () => {
  for (const origin of ["http://x.com", "https://x.com/path", "https://*.x.com", "https://user@x.com", "https://x.com?q=1", "notaurl", "https://"]) {
    const r = await api(owner, "POST", "/v1/org/web-origins", { origin });
    if (r.status !== 400 || r.json?.error !== "invalid_web_origin") return `${origin} -> ${r.status} ${r.text.slice(0, 100)}`;
  }
  const empty = await api(owner, "POST", "/v1/org/web-origins", { origin: "" });
  const extra = await api(owner, "POST", "/v1/org/web-origins", { origin: "https://a.example.com", x: 1 });
  return empty.status === 400 && empty.json.message === "origin: Too small: expected string to have >=1 characters" && extra.status === 400 && extra.json.message.startsWith("Unrecognized key") || JSON.stringify([empty.json, extra.json]);
});
await t("web origins: approving normalizes (case, default port, trailing slash), rejects duplicates and lists with who approved", async () => {
  const r = await api(owner, "POST", "/v1/org/web-origins", { origin: "HTTPS://Work.Example.com:443/" });
  originId = r.json?.id;
  const dup = await api(owner, "POST", "/v1/org/web-origins", { origin: "https://work.example.com" });
  const port = await api(owner, "POST", "/v1/org/web-origins", { origin: "https://work.example.com:8443" });
  const list = await api(owner, "GET", "/v1/org/web-origins");
  return r.status === 201 && keys(r.json) === "createdAt,createdByName,id,origin" && r.json.origin === "https://work.example.com" && r.json.createdByName === "Owner Person" && originId.startsWith("owo_")
    && dup.status === 409 && dup.json.error === "web_origin_already_approved" && port.status === 201
    && list.status === 200 && keys(list.json) === "limit,origins" && list.json.limit === 20 && list.json.origins.length === 2 || JSON.stringify([r.text, dup.text, list.text]);
});
await t("web origins: viewing is for admins, managing is the owner's", async () => {
  const a = await api(plain, "GET", "/v1/org/web-origins");
  const b = await api(admin, "GET", "/v1/org/web-origins");
  const c = await api(admin, "POST", "/v1/org/web-origins", { origin: "https://adm.example.com" });
  const d = await api(admin, "DELETE", `/v1/org/web-origins/${originId}`);
  return denied(a, "web_origins.view") && b.status === 200 && denied(c, "web_origins.manage") && denied(d, "web_origins.manage") || JSON.stringify([a.status, b.status, c.status, d.status]);
});
await t("web origins: removing answers 204, then 404 web_origin_not_found; a malformed id is 400; another workspace's id is 404", async () => {
  const other = await workspace("Org Admin Origins B");
  const theirs = await other.api(other.owner, "POST", "/v1/org/web-origins", { origin: "https://theirs.example.com" });
  const foreign = await api(owner, "DELETE", `/v1/org/web-origins/${theirs.json.id}`);
  const bad = await api(owner, "DELETE", "/v1/org/web-origins/zzz");
  const removed = await api(owner, "DELETE", `/v1/org/web-origins/${originId}`);
  const again = await api(owner, "DELETE", `/v1/org/web-origins/${originId}`);
  const still = await other.api(other.owner, "GET", "/v1/org/web-origins");
  return foreign.status === 404 && foreign.json.error === "web_origin_not_found" && bad.status === 400 && bad.json.error === "invalid_request" && removed.status === 204
    && again.status === 404 && still.json.origins.length === 1 || JSON.stringify([foreign.status, bad.status, removed.status, again.status]);
});
await t("web origins: at most 20 per workspace", async () => {
  const current = (await api(owner, "GET", "/v1/org/web-origins")).json.origins.length;
  let last;
  for (let i = current; i <= 20; i++) { last = await api(owner, "POST", "/v1/org/web-origins", { origin: `https://o${i}.example.com` }); if (last.status !== 201) break; }
  return last.status === 409 && last.json.error === "web_origin_limit_reached" && last.json.message.includes("20") || last.text;
});

// ---- brand assets -----------------------------------------------------------------------------------------------------------------
await t("brand assets: needs branding.update, multipart data and at least one file", async () => {
  const member = await api(plain, "POST", "/v1/org/brand-assets", {});
  const json = await api(owner, "POST", "/v1/org/brand-assets", {});
  const none = await upload(ws, owner, []);
  const text = await upload(ws, owner, [["logo", Buffer.from("hello"), "text/plain", "x.txt"]]);
  const mismatch = await upload(ws, owner, [["logo", png(256, 64), "image/jpeg", "x.jpg"]]);
  const junk = await upload(ws, owner, [["logo", Buffer.from("not an image"), "image/png", "x.png"]]);
  return denied(member, "branding.update")
    && json.status === 400 && json.json.reason === "invalid-request" && none.status === 400 && none.json.reason === "missing-file" && none.json.kind === null
    && text.status === 400 && text.json.reason === "unsupported-format" && text.json.kind === "logo"
    && mismatch.status === 400 && mismatch.json.error === "invalid_brand_asset" && junk.status === 400 && junk.json.reason === "invalid-image" || JSON.stringify([json.json, none.json, text.json, mismatch.json, junk.json]);
});
await t("brand assets: the shape of the image is checked (wordmark wide, icon square, minimum sizes)", async () => {
  const tooSmall = await upload(ws, owner, [["logo", png(100, 30), "image/png"]]);
  const square = await upload(ws, owner, [["logo", png(200, 200), "image/png"]]);
  const wide = await upload(ws, owner, [["logo", png(2000, 100), "image/png"]]);
  const iconWide = await upload(ws, owner, [["icon", png(256, 64), "image/png"]]);
  const iconSmall = await upload(ws, owner, [["icon", png(32, 32), "image/png"]]);
  return [tooSmall, square, wide, iconWide, iconSmall].every((r) => r.status === 400 && r.json.error === "invalid_brand_asset")
    && tooSmall.json.reason === "too-small" && square.json.reason === "invalid-aspect" && wide.json.reason === "invalid-aspect" && iconWide.json.reason === "invalid-aspect" && iconSmall.json.reason === "too-small"
    || JSON.stringify([tooSmall.json, square.json, wide.json, iconWide.json, iconSmall.json]);
});
await t("brand assets: an upload is stored, answered with a signed immutable URL, served publicly and shown in the settings", async () => {
  const r = await upload(ws, owner, [["logo", png(256, 64), "image/png", "wordmark.png"], ["icon", png(128, 128), "image/png", "icon.png"]]);
  const logo = r.json?.assets?.logo, icon = r.json?.assets?.icon;
  const shape = logo && keys(logo) === "byteLength,contentType,extension,height,kind,originalName,uploadedAt,url,version,width" && /^[a-f0-9]{64}$/.test(logo.version)
    && logo.kind === "logo" && logo.width === 256 && logo.height === 64 && logo.extension === "png" && logo.contentType === "image/png" && icon.width === 128 && logo.originalName === "wordmark.png";
  const image = await fetch(logo.url, { redirect: "manual" });
  const bytes = Buffer.from(await image.arrayBuffer());
  const unsigned = await fetch(logo.url.split("?")[0]);
  const forged = await fetch(logo.url.replace(/signature=.{4}/, "signature=AAAA"));
  const meta = JSON.parse((await api(owner, "GET", "/v1/org")).json.organization.metadata);
  return r.status === 200 && shape && image.status === 200 && image.headers.get("content-type") === "image/png" && /immutable/.test(image.headers.get("cache-control")) && bytes.subarray(1, 4).toString() === "PNG"
    && unsigned.status === 404 && forged.status === 404 && meta.brandLogoUrl === logo.url && meta.brandLogoAsset.version === logo.version && meta.brandIconAsset.version === icon.version
    || JSON.stringify([r.status, r.text.slice(0, 300), image.status]);
});

// ---- small read routes ------------------------------------------------------------------------------------------------------------
await t("features: GET /v1/features is public, versioned and cacheable", async () => {
  const r = await call(A, "/v1/features");
  return r.status === 200 && r.json.version === 1 && r.json.deployment === "self_hosted" && r.json.features.engineV2ForceUpgrade === true
    && Object.values(r.json.features).every((v) => typeof v === "boolean") && /max-age=60/.test(r.headers.get("cache-control")) || r.text.slice(0, 200);
});
await t("feature usage: accepted from members, validated, always ok", async () => {
  const ok = await api(plain, "POST", "/v1/org/feature-usage", { features: ["mermaidZoom", "not-a-feature"] });
  const bad = await api(plain, "POST", "/v1/org/feature-usage", { features: "x" });
  const extra = await api(plain, "POST", "/v1/org/feature-usage", { features: [], z: 1 });
  const none = await call(A, "/v1/org/feature-usage", { method: "POST", bearer: plain.token, headers: { "x-openwork-org-id": ws.orgId } });
  const anon = await call(A, "/v1/org/feature-usage", { method: "POST", body: { features: [] } });
  return ok.status === 200 && ok.json.ok === true && bad.status === 400 && bad.json.message === "features: Invalid input: expected array, received string" && extra.status === 400
    && none.status === 400 && anon.status === 401 || JSON.stringify([ok.status, bad.json, extra.status, none.status, anon.status]);
});
await t("activity: owners and admins read it, members do not", async () => {
  const a = await api(admin, "GET", "/v1/org/activity");
  const b = await api(plain, "GET", "/v1/org/activity");
  return a.status === 200 && keys(a.json) === "activity" && Array.isArray(a.json.activity) && b.status === 403 && b.json.error === "forbidden" && b.json.message.startsWith("Only workspace owners and admins") && a.headers.get("cache-control") === "no-store"
    || JSON.stringify([a.status, b.status]);
});
await t("inventory revision: an opaque string every member can read, changing when teams change", async () => {
  const r1 = await api(plain, "GET", "/v1/org/inventory-revision");
  const same = await api(plain, "GET", "/v1/org/inventory-revision");
  await api(owner, "POST", "/v1/teams", { name: "Revision Team" });
  const r2 = await api(plain, "GET", "/v1/org/inventory-revision");
  return r1.status === 200 && typeof r1.json.revision === "string" && r1.json.revision === same.json.revision && r2.json.revision !== r1.json.revision && r1.headers.get("cache-control") === "no-store"
    && (await call(A, "/v1/org/inventory-revision")).status === 401 || JSON.stringify([r1.json, r2.json]);
});

// ---- deleting a workspace ---------------------------------------------------------------------------------------------------------
await t("delete workspace: owner only; it removes the workspace and its keys, leaves other workspaces alone", async () => {
  const doomed = await workspace("Org Admin Doomed");
  const member = await doomed.join("Doomed Member");
  const bystander = await workspace("Org Admin Bystander");
  const key = (await doomed.api(doomed.owner, "POST", "/v1/api-keys", { name: "Doomed key" })).json.key;
  await doomed.api(doomed.owner, "POST", "/v1/teams", { name: "Doomed Team" });
  const byMember = await doomed.api(member, "DELETE", "/v1/org");
  const stillThere = await doomed.api(doomed.owner, "GET", "/v1/org");
  const del = await doomed.api(doomed.owner, "DELETE", "/v1/org");
  const keyAfter = await withKey(key, "/v1/org");
  const memberAfter = await doomed.api(member, "GET", "/v1/org");
  const bystanderOrg = await bystander.api(bystander.owner, "GET", "/v1/org");
  return byMember.status === 403 && byMember.json.error === "forbidden" && stillThere.status === 200
    && del.status === 200 && del.json.ok === true && del.json.organization.id === doomed.orgId && del.json.organization.name === "Org Admin Doomed"
    && keyAfter.status === 401 && [401, 404].includes(memberAfter.status) && bystanderOrg.status === 200 && bystanderOrg.json.organization.id === bystander.orgId
    || JSON.stringify([byMember.status, del.status, del.text, keyAfter.status, memberAfter.status, bystanderOrg.status]);
});

s.done();
