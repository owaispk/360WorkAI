// Shared helpers for per-area contract tests (tests/parity/area-<name>.mjs). Each area script runs unchanged against the reference Den and
// the rewrite:
//   node area-<name>.mjs                                                    # reference: web :3005, api :8790
//   W=http://localhost:5081 A=http://localhost:5080 node area-<name>.mjs    # rewrite
// Needs a server where sign-up returns a session (email verification off). See ../../docs/AREA_GUIDE.md.
import { randomBytes } from "node:crypto";

export const W = process.env.W ?? "http://localhost:3005";
export const A = process.env.A ?? "http://localhost:8790";
export const PW = "Str0ng!Passw0rd#2026x";
export const email = (p) => `${p}.${Date.now()}.${randomBytes(2).toString("hex")}@example.com`;

export async function call(base, path, { method = "GET", body, bearer, headers = {}, raw, origin = W } = {}) {
  const h = { origin, ...headers };
  if (bearer) h.authorization = `Bearer ${bearer}`;
  let payload;
  if (raw !== undefined) payload = raw;
  else if (body !== undefined) { h["content-type"] = "application/json"; payload = JSON.stringify(body); }
  const res = await fetch(base + path, { method, headers: h, body: payload, redirect: "manual", signal: AbortSignal.timeout(60000) });
  const text = await res.text();
  let json = null; try { json = JSON.parse(text); } catch {}
  return { status: res.status, json, text, headers: res.headers };
}

/** A person with a session (signed up through the API). */
export async function person(name) {
  const e = email(name.toLowerCase().replace(/\s+/g, "."));
  const r = await call(W, "/api/auth/sign-up/email", { method: "POST", body: { name, email: e, password: PW } });
  if (!r.json?.token) throw new Error(`sign-up returned no session (is email verification on?): ${r.status} ${r.text.slice(0, 120)}`);
  return { name, email: e, token: r.json.token, userId: r.json.user?.id };
}

/** A workspace with an owner. `ws.api(user, method, path, body)` calls the API as that person in this workspace. */
export async function workspace(name = "Area Probe") {
  const owner = await person("Owner Person");
  const org = await call(A, "/v1/org", { method: "POST", bearer: owner.token, body: { name } });
  const ws = { owner, orgId: org.json?.organization?.id };
  if (!ws.orgId) throw new Error(`could not create a workspace: ${org.status} ${org.text.slice(0, 120)}`);
  ws.api = (u, method, path, body, extra = {}) => call(A, path, { method, bearer: u.token, headers: { "x-openwork-org-id": ws.orgId, ...(extra.headers ?? {}) }, body, ...extra });
  ws.memberId = async (u) => ((await ws.api(ws.owner, "GET", "/v1/org")).json.members.find((m) => m.userId === u.userId) ?? {}).id;
  ws.join = async (name, role = "member") => {
    const u = await person(name);
    const inv = await ws.api(ws.owner, "POST", "/v1/invitations", { email: u.email, role });
    await call(A, "/v1/orgs/invitations/accept", { method: "POST", bearer: u.token, body: { id: inv.json.invitationId } });
    u.memberId = await ws.memberId(u);
    return u;
  };
  return ws;
}

/** Collects PASS/FAIL lines. `await s.t("name", async () => true | "reason when false")`, then `s.done()` sets the exit code. */
export function suite(section) {
  const results = [];
  return {
    async t(name, fn) {
      try {
        const r = await fn();
        const ok = r === true || r === undefined;
        results.push({ name, ok });
        console.log(`${ok ? "PASS" : "FAIL"}  [${section}] ${name}${ok ? "" : "  -> " + (typeof r === "string" ? r : JSON.stringify(r)).slice(0, 400)}`);
      } catch (e) {
        results.push({ name, ok: false });
        console.log(`FAIL  [${section}] ${name}  -> ${String(e?.message ?? e).slice(0, 400)}`);
      }
    },
    done() {
      const failed = results.filter((r) => !r.ok).length;
      console.log(`\n==== ${results.length - failed}/${results.length} passed, ${failed} failed ====`);
      process.exit(failed ? 1 : 0);
    },
  };
}

export const keys = (o) => Object.keys(o ?? {}).sort().join(",");
/** The 403 the API sends when a permission is missing. */
export const denied = (r, key) => r.status === 403 && r.json?.error === "forbidden" && r.json?.code === "requires_admin" && r.json?.requiredPermission === key;
