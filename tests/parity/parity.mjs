// Contract (parity) test: the same checks run against the reference Den (TypeScript) and the .NET rewrite.
//
//   node parity.mjs                                              # reference: web :3005, api :8790, all sections
//   W=http://localhost:5081 A=http://localhost:5080 \
//   SECTIONS=health,auth,orgs,handoff,device,login-options,oauth-mcp,passwords,email,members,sign-out node parity.mjs   # .NET rewrite
//   (add email-verification when the server requires it: DEN_REQUIRE_EMAIL_VERIFICATION=true / Auth__RequireEmailVerification=true;
//    then leave out auth, orgs, handoff, device, oauth-mcp, which sign up and expect a session straight away)
//
// W is the web origin (serves /api/auth, /api/browser/v1, /.well-known); A is the API origin (serves /v1/*).
import { createHash, randomBytes } from "node:crypto";

const W = process.env.W ?? "http://localhost:3005";
const A = process.env.A ?? "http://localhost:8790";
const SECTIONS = process.env.SECTIONS ? process.env.SECTIONS.split(",") : null;
const PW = "Str0ng!Passw0rd#2026x";
const results = [];
let section = "";

function rec(name, ok, detail = "") {
  results.push({ section, name, ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"}  [${section}] ${name}${ok ? "" : "  -> " + detail}`);
}
const t = async (name, fn) => {
  if (SECTIONS && !SECTIONS.includes(section)) return;
  try {
    const r = await fn();
    rec(name, r === true || r === undefined, typeof r === "string" ? r : "");
  } catch (e) {
    rec(name, false, String(e?.message ?? e).slice(0, 200));
  }
};

class Jar {
  c = new Map();
  absorb(res) {
    for (const sc of res.headers.getSetCookie?.() ?? []) {
      const [pair, ...attrs] = sc.split(";");
      const i = pair.indexOf("=");
      const k = pair.slice(0, i).trim(), v = pair.slice(i + 1).trim();
      const expired = attrs.some((a) => /^\s*max-age=0/i.test(a)) || v === "";
      if (expired) this.c.delete(k); else this.c.set(k, v);
    }
  }
  header() { return [...this.c].map(([k, v]) => `${k}=${v}`).join("; "); }
}

async function call(base, path, { method = "GET", body, jar, bearer, headers = {}, form, redirect = "manual", origin = W } = {}) {
  const h = { origin, ...headers };
  if (jar?.c.size) h.cookie = jar.header();
  if (bearer) h.authorization = `Bearer ${bearer}`;
  let payload;
  if (form) { h["content-type"] = "application/x-www-form-urlencoded"; payload = new URLSearchParams(form).toString(); }
  else if (body !== undefined) { h["content-type"] = "application/json"; payload = JSON.stringify(body); }
  const res = await fetch(base + path, { method, headers: h, body: payload, redirect, signal: AbortSignal.timeout(60000) });
  jar?.absorb(res);
  const text = await res.text();
  let json = null; try { json = JSON.parse(text); } catch {}
  return { status: res.status, json, text, headers: res.headers };
}

const email = (p) => `${p}.${Date.now()}.${randomBytes(2).toString("hex")}@example.com`;
const b64u = (b) => b.toString("base64url");

// ---------- 1. Health & static discovery ----------
section = "health";
await t("API /health", async () => (await call(A, "/health")).json?.ok === true);
await t("Web /api/health", async () => (await call(W, "/api/health")).json?.ok === true);
await t("Web /api/ready", async () => { const r = await call(W, "/api/ready"); return r.status < 500 || `status ${r.status}`; });
await t("Web /api/runtime-config exposes API origin", async () => { const r = await call(W, "/api/runtime-config"); return (r.status === 200 && JSON.stringify(r.json).includes(new URL(A).port)) || `${r.status} ${r.text.slice(0, 120)}`; });

// ---------- 2. Email/password auth ----------
section = "auth";
const jar = new Jar();
const em = email("e2e");
let token = null, userId = null;
await t("sign-up/email returns token+user", async () => {
  const r = await call(W, "/api/auth/sign-up/email", { method: "POST", jar, body: { name: "E2E User", email: em, password: PW } });
  token = r.json?.token; userId = r.json?.user?.id;
  return (r.status === 200 && typeof token === "string" && token.length >= 20 && userId?.startsWith("usr_")) || `${r.status} ${r.text.slice(0, 150)}`;
});
await t("sign-up sets signed session cookie", async () => [...jar.c.keys()].some((k) => k.includes("session_token")) || [...jar.c.keys()].join(","));
await t("duplicate sign-up rejected (4xx)", async () => {
  const r = await call(W, "/api/auth/sign-up/email", { method: "POST", body: { name: "Dup", email: em, password: PW } });
  return (r.status >= 400 && r.status < 500) || `${r.status}`;
});
await t("weak password rejected with policy payload", async () => {
  const r = await call(W, "/api/auth/sign-up/email", { method: "POST", body: { name: "W", email: email("weak"), password: "abc12345" } });
  return (r.status >= 400 && r.status < 500) || `${r.status} ${r.text.slice(0, 120)}`;
});
await t("sign-in wrong password -> INVALID_EMAIL_OR_PASSWORD", async () => {
  const r = await call(W, "/api/auth/sign-in/email", { method: "POST", body: { email: em, password: "Wrong!Passw0rd#999" } });
  return (r.status === 401 && r.json?.code === "INVALID_EMAIL_OR_PASSWORD") || `${r.status} ${r.text.slice(0, 120)}`;
});
const jar2 = new Jar(); let token2 = null;
await t("sign-in/email returns token", async () => {
  const r = await call(W, "/api/auth/sign-in/email", { method: "POST", jar: jar2, body: { email: em, password: PW } });
  token2 = r.json?.token;
  return (r.status === 200 && typeof token2 === "string" && r.json?.user?.email === em) || `${r.status} ${r.text.slice(0, 120)}`;
});
await t("get-session (cookie, via web proxy)", async () => { const r = await call(W, "/api/auth/get-session", { jar: jar2 }); return (r.status === 200 && r.json?.user?.id === userId) || `${r.status} ${r.text.slice(0, 120)}`; });
await t("get-session without cookie -> null", async () => { const r = await call(W, "/api/auth/get-session"); return (r.status === 200 && r.text.trim() === "null") || `${r.status} body=${JSON.stringify(r.text.slice(0, 40))}`; });
await t("/v1/me with bearer (API origin)", async () => { const r = await call(A, "/v1/me", { bearer: token2 }); return (r.status === 200 && r.json?.user?.id === userId) || `${r.status}`; });
await t("/v1/me with cookie (browser proxy)", async () => { const r = await call(W, "/api/browser/v1/me", { jar: jar2 }); return (r.status === 200 && r.json?.user?.id === userId) || `${r.status}`; });
await t("/v1/me with garbage bearer -> 401", async () => (await call(A, "/v1/me", { bearer: "x".repeat(32) })).status === 401);
await t("/v1/me no auth -> 401", async () => (await call(A, "/v1/me")).status === 401);
await t("browser proxy rejects cross-origin write (403)", async () => {
  const r = await call(W, "/api/browser/v1/me/active-organization", { method: "POST", jar: jar2, origin: "https://evil.example", body: {} });
  return r.status === 403 || `${r.status}`;
});
await t("request-password-reset accepts known email", async () => { const r = await call(W, "/api/auth/request-password-reset", { method: "POST", body: { email: em, redirectTo: `${W}/reset-password` } }); return r.status === 200 || `${r.status} ${r.text.slice(0, 120)}`; });
await t("request-password-reset unknown email does not leak (same status)", async () => { const r = await call(W, "/api/auth/request-password-reset", { method: "POST", body: { email: email("nobody"), redirectTo: `${W}/reset-password` } }); return r.status === 200 || `${r.status}`; });
await t("reset-password invalid token -> 4xx", async () => { const r = await call(W, "/api/auth/reset-password", { method: "POST", body: { newPassword: PW, token: "bogus-token" } }); return (r.status >= 400 && r.status < 500) || `${r.status}`; });
await t("email-otp/send-verification-otp responds", async () => { const r = await call(W, "/api/auth/email-otp/send-verification-otp", { method: "POST", body: { email: em, type: "email-verification" } }); return r.status < 500 || `${r.status} ${r.text.slice(0, 120)}`; });
await t("email-otp/verify-email wrong code -> 4xx", async () => { const r = await call(W, "/api/auth/email-otp/verify-email", { method: "POST", body: { email: em, otp: "000000" } }); return (r.status >= 400 && r.status < 500) || `${r.status}`; });
await t("sign-in/social unconfigured provider -> 4xx (no 5xx)", async () => { const r = await call(W, "/api/auth/sign-in/social", { method: "POST", body: { provider: "google", callbackURL: `${W}/`, errorCallbackURL: `${W}/` } }); return r.status < 500 || `${r.status}`; });
await t("get-session POST variant / list-sessions respond without 5xx", async () => { const r = await call(W, "/api/auth/list-sessions", { jar: jar2 }); return r.status < 500 || `${r.status}`; });

// ---------- 3. Orgs & active org ----------
section = "orgs";
let orgId = null;
await t("create org (POST /v1/org)", async () => { const r = await call(A, "/v1/org", { method: "POST", bearer: token2, body: { name: "E2E Workspace" } }); orgId = r.json?.organization?.id; return (r.status < 300 && orgId?.startsWith("org_")) || `${r.status} ${r.text.slice(0, 150)}`; });
await t("/v1/me/orgs lists org, role owner", async () => { const r = await call(A, "/v1/me/orgs", { bearer: token2 }); return (r.json?.orgs?.some((o) => o.id === orgId && o.role === "owner")) || r.text.slice(0, 150); });
await t("POST /api/auth/organization/set-active (Better Auth route)", async () => { const r = await call(W, "/api/auth/organization/set-active", { method: "POST", jar: jar2, body: { organizationId: orgId } }); return r.status === 200 || `${r.status} ${r.text.slice(0, 150)}`; });
await t("POST /v1/me/active-organization (replacement route)", async () => { const r = await call(A, "/v1/me/active-organization", { method: "POST", bearer: token2, body: { organizationId: orgId } }); return r.status < 300 || `${r.status} ${r.text.slice(0, 150)}`; });
await t("/v1/org with org header returns the org", async () => { const r = await call(A, "/v1/org", { bearer: token2, headers: { "x-openwork-org-id": orgId } }); return r.status === 200 || `${r.status} ${r.text.slice(0, 120)}`; });
await t("other user cannot read this org (403/404)", async () => {
  const o = await call(W, "/api/auth/sign-up/email", { method: "POST", body: { name: "Other", email: email("other"), password: PW } });
  const r = await call(A, "/v1/org", { bearer: o.json?.token, headers: { "x-openwork-org-id": orgId } });
  return (r.status === 403 || r.status === 404 || r.status === 401) || `${r.status} ${r.text.slice(0, 120)}`;
});
await t("raw BA org mutation refused: /organization/update -> 403", async () => { const r = await call(W, "/api/auth/organization/update", { method: "POST", jar: jar2, body: { data: { name: "x" }, organizationId: orgId } }); return r.status === 403 || `${r.status} ${r.text.slice(0, 120)}`; });
await t("raw BA mutation refused: /organization/invite-member -> 403", async () => { const r = await call(W, "/api/auth/organization/invite-member", { method: "POST", jar: jar2, body: { email: email("inv"), role: "member", organizationId: orgId } }); return r.status === 403 || `${r.status} ${r.text.slice(0, 120)}`; });
await t("raw BA mutation refused: /api-key/create -> 403", async () => { const r = await call(W, "/api/auth/api-key/create", { method: "POST", jar: jar2, body: { name: "k" } }); return r.status === 403 || `${r.status} ${r.text.slice(0, 120)}`; });
await t("raw BA mutation refused: /device/approve -> 403", async () => { const r = await call(W, "/api/auth/device/approve", { method: "POST", jar: jar2, body: { userCode: "AAAABBBB" } }); return r.status === 403 || `${r.status} ${r.text.slice(0, 120)}`; });

// ---------- 4. Desktop handoff ----------
section = "handoff";
let grant = null;
await t("create handoff (bearer)", async () => { const r = await call(A, "/v1/auth/desktop-handoff", { method: "POST", bearer: token2, body: { desktopScheme: "openwork" } }); grant = r.json?.grant; return (r.status === 200 && grant && r.json?.openworkUrl?.startsWith("openwork://")) || `${r.status} ${r.text.slice(0, 120)}`; });
await t("create handoff via web alias /api/auth/desktop-handoff (cookie)", async () => { const r = await call(W, "/api/auth/desktop-handoff", { method: "POST", jar: jar2, body: { desktopScheme: "openwork" } }); return (r.status === 200 && !!r.json?.grant) || `${r.status} ${r.text.slice(0, 120)}`; });
await t("handoff without auth -> 401", async () => (await call(A, "/v1/auth/desktop-handoff", { method: "POST", body: { desktopScheme: "openwork" } })).status === 401);
await t("handoff status = pending", async () => (await call(A, "/v1/auth/desktop-handoff/status", { method: "POST", body: { grant } })).json?.status === "pending");
await t("exchange returns token/user/organization/connectEnabled", async () => { const r = await call(A, "/v1/auth/desktop-handoff/exchange", { method: "POST", body: { grant } }); return (r.status === 200 && r.json?.token && r.json?.user?.id === userId && "organization" in r.json && "connectEnabled" in r.json) || `${r.status} ${r.text.slice(0, 150)}`; });
await t("handoff status after exchange = consumed", async () => (await call(A, "/v1/auth/desktop-handoff/status", { method: "POST", body: { grant } })).json?.status === "consumed");
await t("exchange replay -> 404 grant_not_found", async () => { const r = await call(A, "/v1/auth/desktop-handoff/exchange", { method: "POST", body: { grant } }); return (r.status === 404 && r.json?.error === "grant_not_found") || `${r.status}`; });
await t("exchange short/invalid grant -> 400", async () => (await call(A, "/v1/auth/desktop-handoff/exchange", { method: "POST", body: { grant: "short" } })).status === 400);
await t("web handoff with unapproved returnUrl -> 400 invalid_return_url", async () => { const r = await call(A, "/v1/auth/desktop-handoff", { method: "POST", bearer: token2, body: { returnUrl: "https://evil.example/cb" } }); return (r.status === 400) || `${r.status} ${r.text.slice(0, 120)}`; });

// ---------- 5. Device authorization (CLI / OpenCode plugin) ----------
section = "device";
let dev = null;
await t("device/code (openwork-cli)", async () => { const r = await call(A, "/api/auth/device/code", { method: "POST", body: { client_id: "openwork-cli" } }); dev = r.json; return (r.status === 200 && dev?.device_code && dev?.user_code && !!dev?.verification_uri_complete) || `${r.status} ${r.text.slice(0, 150)}`; });
await t("device/code unknown client -> 400 invalid_client", async () => { const r = await call(A, "/api/auth/device/code", { method: "POST", body: { client_id: "nope" } }); return (r.status === 400 && r.json?.error === "invalid_client") || `${r.status} ${r.text.slice(0, 120)}`; });
const dgrant = "urn:ietf:params:oauth:grant-type:device_code";
await t("device/token pending -> authorization_pending", async () => { const r = await call(A, "/api/auth/device/token", { method: "POST", body: { grant_type: dgrant, device_code: dev?.device_code, client_id: "openwork-cli" } }); return r.json?.error === "authorization_pending" || `${r.status} ${r.text.slice(0, 120)}`; });
await t("device lookup (signed-in user)", async () => { const r = await call(A, `/v1/auth/device/${dev?.user_code}`, { bearer: token2 }); return (r.status === 200 && r.json?.status === "pending") || `${r.status} ${r.text.slice(0, 120)}`; });
await t("device decision requires auth (401)", async () => (await call(A, "/v1/auth/device/decision", { method: "POST", body: { userCode: dev?.user_code, decision: "approve" } })).status === 401);
await t("device decision approve", async () => { const r = await call(A, "/v1/auth/device/decision", { method: "POST", bearer: token2, body: { userCode: dev?.user_code, decision: "approve", organizationId: orgId } }); return (r.status === 200 && r.json?.status === "approved") || `${r.status} ${r.text.slice(0, 150)}`; });
let cliToken = null;
await t("device/token after approve -> access_token", async () => { await new Promise((r) => setTimeout(r, 5500)); const r = await call(A, "/api/auth/device/token", { method: "POST", body: { grant_type: dgrant, device_code: dev?.device_code, client_id: "openwork-cli" } }); cliToken = r.json?.access_token; return (r.status === 200 && !!cliToken) || `${r.status} ${r.text.slice(0, 150)}`; });
await t("CLI access_token works on /v1/me", async () => { const r = await call(A, "/v1/me", { bearer: cliToken }); return (r.status === 200 && r.json?.user?.id === userId) || `${r.status}`; });
await t("CLI sign-out with bearer revokes it", async () => { const r = await call(A, "/api/auth/sign-out", { method: "POST", bearer: cliToken, body: {} }); const m = await call(A, "/v1/me", { bearer: cliToken }); return (r.status === 200 && m.status === 401) || `${r.status}/${m.status}`; });
let dev2 = null;
await t("device deny flow -> access_denied", async () => {
  dev2 = (await call(A, "/api/auth/device/code", { method: "POST", body: { client_id: "openwork-opencode-plugin" } })).json;
  const d = await call(A, "/v1/auth/device/decision", { method: "POST", bearer: token2, body: { userCode: dev2.user_code, decision: "deny" } });
  await new Promise((r) => setTimeout(r, 5500));
  const p = await call(A, "/api/auth/device/token", { method: "POST", body: { grant_type: dgrant, device_code: dev2.device_code, client_id: "openwork-opencode-plugin" } });
  return (d.status === 200 && p.json?.error === "access_denied") || `${d.status} ${p.text.slice(0, 120)}`;
});

// ---------- 6. Login options / SSO resolve / bootstrap ----------
section = "login-options";
await t("login-options known email -> password", async () => { const r = await call(W, `/api/auth/login-options?email=${encodeURIComponent(em)}`); return (r.status === 200 && r.json?.nextStep === "password") || `${r.status} ${r.text.slice(0, 120)}`; });
await t("login-options new email -> new_account", async () => { const r = await call(W, `/api/auth/login-options?email=${encodeURIComponent(email("fresh"))}`); return (r.status === 200 && r.json?.nextStep === "new_account") || `${r.status} ${r.text.slice(0, 120)}`; });
await t("login-options invalid email -> 400", async () => (await call(W, "/api/auth/login-options?email=notanemail")).status === 400);
await t("sso-resolve (no SSO) -> method != sso", async () => { const r = await call(W, `/api/auth/sso-resolve?email=${encodeURIComponent(em)}`); return (r.status === 200 && r.json?.method !== "sso") || `${r.status} ${r.text.slice(0, 120)}`; });
await t("bootstrap/status", async () => { const r = await call(A, "/v1/auth/bootstrap/status"); return (r.status === 200 && ["available", "complete", "unavailable"].includes(r.json?.status)) || `${r.status} ${r.text.slice(0, 100)}`; });
await t("bootstrap/verify wrong code -> 403/409", async () => { const r = await call(A, "/v1/auth/bootstrap/verify", { method: "POST", body: { email: "admin@example.com", code: "wrong" } }); return [403, 409].includes(r.status) || `${r.status}`; });
await t("sign-in/sso unknown org -> 4xx (no 5xx)", async () => { const r = await call(W, "/api/auth/sign-in/sso", { method: "POST", body: { organizationSlug: "no-such-org", callbackURL: `${W}/` } }); return (r.status >= 400 && r.status < 500) || `${r.status} ${r.text.slice(0, 120)}`; });

// ---------- 7. OAuth / MCP ----------
section = "oauth-mcp";
await t("AS metadata at /.well-known/oauth-authorization-server/api/auth (web)", async () => { const r = await call(W, "/.well-known/oauth-authorization-server/api/auth"); return (r.status === 200 && r.json?.issuer === `${W}/api/auth` && r.json?.token_endpoint && !!r.json?.registration_endpoint) || `${r.status} ${r.text.slice(0, 150)}`; });
await t("OIDC config at /.well-known/openid-configuration/api/auth (web)", async () => { const r = await call(W, "/.well-known/openid-configuration/api/auth"); return (r.status === 200 && !!r.json?.issuer) || `${r.status}`; });
await t("AS metadata served on API origin (3 forms)", async () => { for (const p of ["/.well-known/oauth-authorization-server", "/.well-known/oauth-authorization-server/api/auth", "/api/auth/.well-known/oauth-authorization-server"]) { const r = await call(A, p); if (r.status !== 200) return `${p} ${r.status}`; } return true; });
await t("protected-resource metadata (/mcp/agent)", async () => { const r = await call(A, "/.well-known/oauth-protected-resource/mcp/agent"); return (r.status === 200 && r.json?.authorization_servers?.[0] === `${W}/api/auth`) || `${r.status} ${r.text.slice(0, 150)}`; });
await t("jwks served", async () => { const r = await call(W, "/api/auth/jwks"); return (r.status === 200 && Array.isArray(r.json?.keys)) || `${r.status} ${r.text.slice(0, 100)}`; });
await t("/mcp/agent without token -> 401 + WWW-Authenticate resource_metadata", async () => { const r = await call(A, "/mcp/agent", { method: "POST", headers: { accept: "application/json, text/event-stream" }, body: { jsonrpc: "2.0", id: 1, method: "initialize", params: {} } }); return (r.status === 401 && /resource_metadata/.test(r.headers.get("www-authenticate") ?? "")) || `${r.status} ${r.headers.get("www-authenticate")}`; });

let client = null;
const redirectUri = "http://127.0.0.1:9999/callback";
await t("DCR /register (loopback redirect, public client)", async () => { const r = await call(A, "/register", { method: "POST", body: { client_name: "E2E MCP Client", redirect_uris: [redirectUri], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] } }); client = r.json; return (r.status < 300 && !!client?.client_id) || `${r.status} ${r.text.slice(0, 150)}`; });
await t("DCR with non-allowed http redirect -> 400 invalid_redirect_uri", async () => { const r = await call(A, "/register", { method: "POST", body: { client_name: "bad", redirect_uris: ["http://attacker.example/cb"], token_endpoint_auth_method: "none" } }); return (r.status === 400 && r.json?.error === "invalid_redirect_uri") || `${r.status} ${r.text.slice(0, 150)}`; });

const verifier = b64u(randomBytes(32));
const challenge = b64u(createHash("sha256").update(verifier).digest());
const resource = `${A}/mcp`; // normalized server-side to the canonical agent resource
const authParams = () => new URLSearchParams({ response_type: "code", client_id: client?.client_id ?? "", redirect_uri: redirectUri, scope: "mcp:read mcp:write offline_access", state: "st8", code_challenge: challenge, code_challenge_method: "S256", resource: `${A}/mcp/agent` });
let authLoc = null;
await t("authorize without session -> redirect to login page w/ signed query", async () => { const r = await call(A, `/api/auth/oauth2/authorize?${authParams()}`); authLoc = r.headers.get("location"); return ([302, 303, 307].includes(r.status) && !!authLoc) || `${r.status} ${r.text.slice(0, 150)}`; });
await t("authorize missing resource -> invalid_target", async () => { const p = authParams(); p.delete("resource"); const r = await call(A, `/api/auth/oauth2/authorize?${p}`); return (r.status === 400 && r.json?.error === "invalid_target") || `${r.status} ${r.text.slice(0, 150)}`; });
let consentQuery = null;
await t("authorize with session (org active) -> consent redirect", async () => {
  const r = await call(A, `/api/auth/oauth2/authorize?${authParams()}`, { jar: jar2 });
  const loc = r.headers.get("location") ?? "";
  consentQuery = loc.includes("?") ? loc.slice(loc.indexOf("?") + 1) : null;
  return ([302, 303, 307].includes(r.status) && /\/mcp\/(consent|select-organization)/.test(loc) && !!consentQuery) || `${r.status} ${loc.slice(0, 200)}`;
});
await t("public-client-prelogin returns client name", async () => { const r = await call(W, "/api/auth/oauth2/public-client-prelogin", { method: "POST", body: { client_id: client?.client_id, oauth_query: consentQuery } }); return (r.status === 200 && r.json?.client_name === "E2E MCP Client") || `${r.status} ${r.text.slice(0, 150)}`; });
let code = null;
await t("oauth2/consent accept -> redirect url with code", async () => {
  const r = await call(W, "/api/auth/oauth2/consent", { method: "POST", jar: jar2, body: { accept: true, scope: "mcp:read mcp:write offline_access", oauth_query: consentQuery } });
  const url = r.json?.url ? new URL(r.json.url) : null;
  code = url?.searchParams.get("code");
  return (r.status === 200 && code && url.searchParams.get("state") === "st8") || `${r.status} ${r.text.slice(0, 200)}`;
});
let at = null, rt = null;
await t("oauth2/token authorization_code (PKCE) -> access+refresh", async () => {
  const r = await call(W, "/api/auth/oauth2/token", { method: "POST", form: { grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: client?.client_id, code_verifier: verifier, resource: `${A}/mcp/agent` } });
  at = r.json?.access_token; rt = r.json?.refresh_token;
  return (r.status === 200 && !!at && !!rt) || `${r.status} ${r.text.slice(0, 200)}`;
});
await t("MCP initialize with OAuth access token", async () => { const r = await call(A, "/mcp/agent", { method: "POST", bearer: at, headers: { accept: "application/json, text/event-stream" }, body: { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "e2e", version: "1" } } } }); return (r.status === 200 && /serverInfo|protocolVersion/.test(r.text)) || `${r.status} ${r.text.slice(0, 200)}`; });
await t("MCP tools/list exposes search_capabilities + execute_capability", async () => { const r = await call(A, "/mcp/agent", { method: "POST", bearer: at, headers: { accept: "application/json, text/event-stream" }, body: { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} } }); return (/search_capabilities/.test(r.text) && /execute_capability/.test(r.text)) || `${r.status} ${r.text.slice(0, 200)}`; });
await t("refresh_token grant", async () => { const r = await call(W, "/api/auth/oauth2/token", { method: "POST", form: { grant_type: "refresh_token", refresh_token: rt, client_id: client?.client_id, resource: `${A}/mcp/agent` } }); return (r.status === 200 && !!r.json?.access_token) || `${r.status} ${r.text.slice(0, 200)}`; });
await t("auth code replay -> invalid_grant", async () => { const r = await call(W, "/api/auth/oauth2/token", { method: "POST", form: { grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: client?.client_id, code_verifier: verifier, resource: `${A}/mcp/agent` } }); return (r.status >= 400 && r.status < 500) || `${r.status}`; });
await t("OAuth access token is NOT accepted as a session on /v1/me", async () => { const r = await call(A, "/v1/me", { bearer: at }); return r.status === 401 || `${r.status}`; });
await t("consent deny -> redirect url with error=access_denied", async () => {
  const r0 = await call(A, `/api/auth/oauth2/authorize?${new URLSearchParams({ ...Object.fromEntries(authParams()), state: "deny1", prompt: "consent" })}`, { jar: jar2 });
  const loc = r0.headers.get("location") ?? ""; const q = loc.includes("?") ? loc.slice(loc.indexOf("?") + 1) : "";
  const r = await call(W, "/api/auth/oauth2/consent", { method: "POST", jar: jar2, body: { accept: false, scope: "mcp:read", oauth_query: q } });
  return (r.status === 200 && /error=access_denied/.test(r.json?.url ?? "")) || `${r.status} ${r.text.slice(0, 200)}`;
});
await t("/v1/mcp/token first-party mint", async () => { const r = await call(A, "/v1/mcp/token", { method: "POST", bearer: token2, headers: { "x-openwork-org-id": orgId }, body: { scopes: ["mcp:read", "mcp:write"] } }); return (r.status === 200 && r.json?.token?.startsWith("ow_mcp_at_")) || `${r.status} ${r.text.slice(0, 150)}`; });

// ---------- 7b. Password rules, verification codes and password reset (same shapes on both implementations) ----------
section = "passwords";
const sendPlain = (path, body) => call(W, path, { method: "POST", body });
const policy = async (password) => { const r = await sendPlain("/api/auth/sign-up/email", { name: "P", email: email("pw"), password }); return { status: r.status, error: r.json?.error, message: r.json?.message }; };
await t("password rules: too short", async () => { const r = await policy("Aa1!"); return (r.status === 400 && r.error === "password_too_short" && r.message === "Password must be at least 8 characters.") || JSON.stringify(r); });
await t("password rules: no uppercase", async () => { const r = await policy("abc12345!"); return (r.status === 400 && r.error === "password_missing_uppercase" && r.message === "Password must include at least one uppercase letter.") || JSON.stringify(r); });
await t("password rules: no lowercase", async () => { const r = await policy("ABC12345!"); return (r.status === 400 && r.error === "password_missing_lowercase" && r.message === "Password must include at least one lowercase letter.") || JSON.stringify(r); });
await t("password rules: no special character", async () => { const r = await policy("Abcdefg12345"); return (r.status === 400 && r.error === "password_missing_special_character" && r.message === "Password must include at least one special character.") || JSON.stringify(r); });
await t("password rules: no digit", async () => { const r = await policy("Abcdefgh!!!!"); return (r.status === 400 && r.error === "password_missing_digit" && r.message === "Password must include at least one digit.") || JSON.stringify(r); });

section = "email";
const known = email("known"); await sendPlain("/api/auth/sign-up/email", { name: "Known", email: known, password: PW });
await t("send-verification-otp: same answer for a real and an unknown address", async () => {
  const a = await sendPlain("/api/auth/email-otp/send-verification-otp", { email: known, type: "email-verification" });
  const b = await sendPlain("/api/auth/email-otp/send-verification-otp", { email: email("ghost"), type: "email-verification" });
  return (a.status === 200 && a.text === '{"success":true}' && b.status === 200 && b.text === a.text) || `${a.status} ${a.text} / ${b.status} ${b.text}`;
});
await t("send-verification-otp: invalid type -> 400 VALIDATION_ERROR with the reference message", async () => {
  const r = await sendPlain("/api/auth/email-otp/send-verification-otp", { email: known, type: "nope" });
  return (r.status === 400 && r.json?.code === "VALIDATION_ERROR" && r.json?.message === '[body.type] Invalid option: expected one of "email-verification"|"sign-in"|"forget-password"|"change-email"') || `${r.status} ${r.text}`;
});
await t("send-verification-otp: invalid email -> 400 INVALID_EMAIL", async () => { const r = await sendPlain("/api/auth/email-otp/send-verification-otp", { email: "nope", type: "email-verification" }); return (r.status === 400 && r.json?.message === "Invalid email" && r.json?.code === "INVALID_EMAIL") || `${r.status} ${r.text}`; });
await t("verify-email: invalid email -> 400 INVALID_EMAIL", async () => { const r = await sendPlain("/api/auth/email-otp/verify-email", { email: "nope", otp: "123456" }); return (r.status === 400 && r.json?.message === "Invalid email" && r.json?.code === "INVALID_EMAIL") || `${r.status} ${r.text}`; });
await t("verify-email: missing otp message", async () => { const r = await sendPlain("/api/auth/email-otp/verify-email", { email: known }); return (r.status === 400 && r.json?.message === "[body.otp] Invalid input: expected string, received undefined" && r.json?.code === "VALIDATION_ERROR") || `${r.status} ${r.text}`; });
await t("verify-email: a code that was never issued -> 400 INVALID_OTP", async () => { const r = await sendPlain("/api/auth/email-otp/verify-email", { email: email("ghost"), otp: "123456" }); return (r.status === 400 && r.json?.code === "INVALID_OTP" && r.json?.message === "Invalid OTP") || `${r.status} ${r.text}`; });

await t("request-password-reset: identical answer for a real and an unknown address", async () => {
  const a = await sendPlain("/api/auth/request-password-reset", { email: known, redirectTo: `${W}/reset-password` });
  const b = await sendPlain("/api/auth/request-password-reset", { email: email("ghost"), redirectTo: `${W}/reset-password` });
  const expected = '{"status":true,"message":"If this email exists in our system, check your email for the reset link"}';
  return (a.status === 200 && a.text === expected && b.text === expected) || `${a.status} ${a.text} / ${b.text}`;
});
await t("request-password-reset: a redirect to another site is refused", async () => { const r = await sendPlain("/api/auth/request-password-reset", { email: known, redirectTo: "https://evil.example/reset" }); return (r.status === 403 && r.json?.code === "INVALID_REDIRECT_URL" && r.json?.message === "Invalid redirectURL") || `${r.status} ${r.text}`; });
await t("request-password-reset: no redirectTo is fine", async () => (await sendPlain("/api/auth/request-password-reset", { email: known })).status === 200);
await t("request-password-reset: invalid email message", async () => { const r = await sendPlain("/api/auth/request-password-reset", { email: "nope" }); return (r.status === 400 && r.json?.message === "[body.email] Invalid email address") || `${r.status} ${r.text}`; });
await t("reset-password: unknown token -> 400 INVALID_TOKEN", async () => { const r = await sendPlain("/api/auth/reset-password", { newPassword: PW, token: "bogus" }); return (r.status === 400 && r.json?.code === "INVALID_TOKEN" && r.json?.message === "Invalid token") || `${r.status} ${r.text}`; });
await t("reset-password: missing token -> 400 INVALID_TOKEN", async () => (await sendPlain("/api/auth/reset-password", { newPassword: PW })).json?.code === "INVALID_TOKEN");
await t("reset-password: the password rules are checked before the token", async () => { const r = await sendPlain("/api/auth/reset-password", { newPassword: "abc12345!", token: "bogus" }); return (r.status === 400 && r.json?.error === "password_missing_uppercase") || `${r.status} ${r.text}`; });
await t("reset link with an unknown token redirects to the reset page with an error", async () => {
  const r = await call(W, `/api/auth/reset-password/bogus?callbackURL=${encodeURIComponent(W + "/reset-password")}`);
  return (r.status === 302 && r.headers.get("location") === `${W}/reset-password?error=INVALID_TOKEN`) || `${r.status} ${r.headers.get("location")}`;
});
await t("reset link naming another site is refused", async () => { const r = await call(W, `/api/auth/reset-password/bogus?callbackURL=${encodeURIComponent("https://evil.example/x")}`); return (r.status === 403 && r.json?.code === "INVALID_CALLBACK_URL" && r.json?.message === "Invalid callbackURL") || `${r.status} ${r.text}`; });

// Only meaningful when the server requires email verification (DEN_REQUIRE_EMAIL_VERIFICATION=true / Auth__RequireEmailVerification=true).
section = "email-verification";
const unverified = email("unverified");
await t("sign-up needs verification: 200, no session, user not verified", async () => {
  const jarV = new Jar(); const r = await call(W, "/api/auth/sign-up/email", { method: "POST", jar: jarV, body: { name: "U", email: unverified, password: PW } });
  return (r.status === 200 && r.json && r.json.token === null && r.json.user?.emailVerified === false && jarV.c.size === 0) || `${r.status} ${r.text.slice(0, 160)} cookies=${jarV.c.size}`;
});
await t("sign-in before verifying -> 403 EMAIL_NOT_VERIFIED", async () => { const r = await sendPlain("/api/auth/sign-in/email", { email: unverified, password: PW }); return (r.status === 403 && r.json?.code === "EMAIL_NOT_VERIFIED" && r.json?.message === "Email not verified") || `${r.status} ${r.text}`; });
await t("a wrong password is still 401 (the account state is not revealed)", async () => { const r = await sendPlain("/api/auth/sign-in/email", { email: unverified, password: "Wrong!Passw0rd#999" }); return (r.status === 401 && r.json?.code === "INVALID_EMAIL_OR_PASSWORD") || `${r.status} ${r.text}`; });
await t("five wrong codes are 400, the sixth is 403 TOO_MANY_ATTEMPTS, then the code is gone", async () => {
  const results = [];
  for (let i = 0; i < 7; i++) { const r = await sendPlain("/api/auth/email-otp/verify-email", { email: unverified, otp: "000000" }); results.push(`${r.status}:${r.json?.code}`); }
  const expected = ["400:INVALID_OTP", "400:INVALID_OTP", "400:INVALID_OTP", "400:INVALID_OTP", "400:INVALID_OTP", "403:TOO_MANY_ATTEMPTS", "400:INVALID_OTP"];
  return JSON.stringify(results) === JSON.stringify(expected) || results.join(" ");
});

// ---------- 7c. Members, roles and invitations (same behavior on both implementations) ----------
// Needs a server where sign-up returns a session (email verification off).
section = "members";
const person = async (name) => { const e = email(name); const r = await call(W, "/api/auth/sign-up/email", { method: "POST", body: { name, email: e, password: PW } }); return { email: e, token: r.json?.token, id: r.json?.user?.id }; };
const relogin = async (u) => { u.token = (await call(W, "/api/auth/sign-in/email", { method: "POST", body: { email: u.email, password: PW } })).json?.token; };
let M = null;
await t("members: set up a workspace with an owner", async () => {
  const owner = await person("m-owner"); if (!owner.token) return "sign-up returned no session (is email verification on?)";
  const org = await call(A, "/v1/org", { method: "POST", bearer: owner.token, body: { name: "Members Probe" } });
  M = { owner, org: org.json?.organization?.id }; return !!M.org || org.text;
});
const mcall = (u, method, path, body) => call(A, path, { method, bearer: u.token, headers: { "x-openwork-org-id": M?.org ?? "" }, body });
const mid = async (u) => ((await mcall(M.owner, "GET", "/v1/org")).json.members.find((m) => m.userId === u.id) ?? {}).id;
const join = async (name, role) => { const u = await person(name); const inv = await mcall(M.owner, "POST", "/v1/invitations", { email: u.email, role }); await call(A, "/v1/orgs/invitations/accept", { method: "POST", bearer: u.token, body: { id: inv.json.invitationId } }); u.memberId = await mid(u); return u; };
let admin, member, member2, inviteeEmail, inv;
await t("members: invitations create (201) with the documented shape", async () => {
  inviteeEmail = email("Invitee").toUpperCase();
  const r = await mcall(M.owner, "POST", "/v1/invitations", { email: inviteeEmail, role: "member" }); inv = r.json;
  return (r.status === 201 && /^inv_/.test(inv?.invitationId) && inv.email === inviteeEmail.toLowerCase() && inv.role === "member" && inv.inviteToken?.length === 21 && !Number.isNaN(Date.parse(inv.expiresAt))) || `${r.status} ${r.text}`;
});
await t("members: inviting the same address again resends (200, same id and link)", async () => { const r = await mcall(M.owner, "POST", "/v1/invitations", { email: inviteeEmail, role: "member" }); return (r.status === 200 && r.json?.invitationId === inv.invitationId && r.json?.inviteToken === inv.inviteToken) || `${r.status} ${r.text}`; });
await t("members: inviting as owner is refused (403, reference message)", async () => { const r = await mcall(M.owner, "POST", "/v1/invitations", { email: email("o"), role: "owner" }); return (r.status === 403 && r.json?.error === "forbidden" && r.json?.message === "Owner can only be assigned by the Den ownership transfer API.") || `${r.status} ${r.text}`; });
await t("members: an unknown role is invalid_role", async () => { const r = await mcall(M.owner, "POST", "/v1/invitations", { email: email("o"), role: "superuser" }); return (r.status === 400 && r.json?.error === "invalid_role" && r.json?.message === "Choose Member or Admin.") || `${r.status} ${r.text}`; });
await t("members: missing role / bad email are invalid_request with the field named", async () => {
  const a = await mcall(M.owner, "POST", "/v1/invitations", { email: email("o") }); const b = await mcall(M.owner, "POST", "/v1/invitations", { email: "nope", role: "member" });
  return (a.status === 400 && a.json?.error === "invalid_request" && a.json?.message === "role: Invalid input: expected string, received undefined" && b.status === 400 && b.json?.message === "email: Invalid email address") || `${a.text} / ${b.text}`;
});
await t("members: inviting someone already in the workspace is 409 member_exists", async () => { const r = await mcall(M.owner, "POST", "/v1/invitations", { email: M.owner.email, role: "member" }); return (r.status === 409 && r.json?.error === "member_exists" && r.json?.message === "That email address is already a member of this organization.") || `${r.status} ${r.text}`; });
await t("members: preview is public and works by id or token", async () => {
  const byId = await call(A, `/v1/orgs/invitations/preview?id=${inv.invitationId}`); const byToken = await call(A, `/v1/orgs/invitations/preview?id=${inv.inviteToken}`);
  const ok = (r) => r.status === 200 && r.json?.invitation?.status === "pending" && r.json?.invitation?.id === inv.invitationId && r.json?.organization?.id === M.org && r.json?.organization?.branding?.appName === "OpenWork";
  return (ok(byId) && ok(byToken)) || `${byId.status} ${byId.text.slice(0, 160)}`;
});
await t("members: preview of an unknown invitation is 404, without an id 400", async () => { const a = await call(A, "/v1/orgs/invitations/preview?id=bogus"); const b = await call(A, "/v1/orgs/invitations/preview"); return (a.status === 404 && a.json?.error === "invitation_not_found" && b.status === 400 && b.json?.message === "id: Invalid input: expected string, received undefined") || `${a.text} / ${b.text}`; });
await t("members: accepting needs a session, and only the invited address can accept", async () => {
  const stranger = await person("stranger");
  const anon = await call(A, "/v1/orgs/invitations/accept", { method: "POST", body: { id: inv.invitationId } });
  const wrong = await call(A, "/v1/orgs/invitations/accept", { method: "POST", bearer: stranger.token, body: { id: inv.invitationId } });
  return (anon.status === 401 && wrong.status === 404 && wrong.json?.error === "invitation_not_found") || `${anon.status} ${wrong.status} ${wrong.text}`;
});
await t("members: the invitee accepts (200, documented shape) and accepting again is harmless", async () => {
  const invitee = await call(W, "/api/auth/sign-up/email", { method: "POST", body: { name: "Invitee", email: inviteeEmail.toLowerCase(), password: PW } });
  const a = await call(A, "/v1/orgs/invitations/accept", { method: "POST", bearer: invitee.json.token, body: { id: inv.invitationId } });
  const b = await call(A, "/v1/orgs/invitations/accept", { method: "POST", bearer: invitee.json.token, body: { id: inv.inviteToken } });
  return (a.status === 200 && a.json?.accepted === true && a.json?.organizationId === M.org && typeof a.json?.organizationSlug === "string" && a.json?.invitationId === inv.invitationId && b.status === 200) || `${a.status} ${a.text} / ${b.status}`;
});
admin = await join("m-admin", "admin"); member = await join("m-member", "member"); member2 = await join("m-member2", "member");
await t("members: GET /v1/org describes the workspace, the caller and everyone", async () => {
  const r = await mcall(member, "GET", "/v1/org"); const j = r.json; if (r.status !== 200) return `${r.status} ${r.text.slice(0, 120)}`;
  const m0 = j.members.find((x) => x.userId === M.owner.id); const cm = j.currentMember;
  const shape = m0 && /^om_/.test(m0.id) && "inviteId" in m0 && m0.role === "owner" && m0.isOwner === true && m0.user?.email === M.owner.email && Array.isArray(m0.adminTeams) && m0.effectiveRole === "owner" && !!m0.joinedAt;
  const me = cm.role === "member" && cm.directRole === "member" && cm.isOwner === false && Array.isArray(cm.permissions) && cm.permissions.length === 0 && Array.isArray(cm.adminTeams);
  const own = j.organization.owner?.userId === M.owner.id && j.organization.owner?.memberId === m0.id;
  return (shape && me && own) || JSON.stringify({ shape, me, own, m0, cm });
});
await t("members: permissions per role (owner 59, admin 43, member 0, sorted)", async () => {
  const get = async (u) => (await mcall(u, "GET", "/v1/org")).json.currentMember.permissions;
  const [o, a, m] = [await get(M.owner), await get(admin), await get(member)];
  const sorted = (x) => JSON.stringify(x) === JSON.stringify([...x].sort());
  return (o.length === 59 && a.length === 43 && m.length === 0 && sorted(o) && sorted(a) && a.includes("invitations.manage") && a.includes("members.delete") && !a.includes("members.update") && o.includes("members.update")) || `${o.length}/${a.length}/${m.length}`;
});
const pendingEmail = email("pend"); let pend;
await t("members: a pending invitation is listed as a placeholder member and in invitations", async () => {
  pend = (await mcall(M.owner, "POST", "/v1/invitations", { email: pendingEmail, role: "member" })).json;
  const j = (await mcall(M.owner, "GET", "/v1/org")).json; const ph = j.members.find((x) => x.inviteId === pend.invitationId && x.userId === null);
  const row = j.invitations.find((i) => i.id === pend.invitationId);
  return (ph && ph.joinedAt === null && ph.user?.email === pendingEmail && ph.user?.id === ph.id && row && row.status === "pending" && row.email === pendingEmail && row.role === "member") || JSON.stringify({ ph, row });
});
await t("members: copying the link works for admins and is denied to members with the reference's message", async () => {
  const ok = await mcall(admin, "GET", `/v1/invitations/${pend.invitationId}/link`); const no = await mcall(member, "GET", `/v1/invitations/${pend.invitationId}/link`);
  const shape = ok.status === 200 && ok.json?.invitationId === pend.invitationId && /\/join-org\?invite=[A-Za-z0-9]+$/.test(ok.json?.inviteLink) && ok.json.inviteLink.includes(pend.inviteToken) && !Number.isNaN(Date.parse(ok.json?.expiresAt));
  const denied = no.status === 403 && no.json?.error === "forbidden" && no.json?.code === "requires_admin" && no.json?.message === "You don't have permission to invite people. Ask an admin to change your permissions." && no.json?.requiredPermission === "invitations.manage" && no.json?.retryable === false && /\/dashboard\/members$/.test(no.json?.action_url);
  return (shape && denied) || `${ok.status} ${ok.text} / ${no.status} ${no.text}`;
});
await t("members: members cannot invite, admins can invite members but not admins", async () => {
  const a = await mcall(member, "POST", "/v1/invitations", { email: email("x"), role: "member" });
  const b = await mcall(admin, "POST", "/v1/invitations", { email: email("x"), role: "member" });
  const c = await mcall(admin, "POST", "/v1/invitations", { email: email("x"), role: "admin" });
  return (a.status === 403 && a.json?.requiredPermission === "invitations.manage" && b.status === 201 && c.status === 403 && c.json?.requiredPermission === "members.update" && c.json?.message === "You don't have permission to change member roles. Ask the organization owner.") || `${a.status} ${b.status} ${c.status} ${c.text}`;
});
await t("members: cancelling works once; a second cancel and the link then answer 409 with the status", async () => {
  const a = await mcall(admin, "POST", `/v1/invitations/${pend.invitationId}/cancel`); const b = await mcall(admin, "POST", `/v1/invitations/${pend.invitationId}/cancel`); const c = await mcall(admin, "GET", `/v1/invitations/${pend.invitationId}/link`);
  return (a.status === 200 && a.json?.success === true && b.status === 409 && b.json?.error === "invitation_not_pending" && b.json?.message === "Only pending invitations can be canceled." && b.json?.status === "canceled" && c.status === 409 && c.json?.message === "This invitation can no longer be used. Resend it to create a new link." && c.json?.status === "canceled") || `${a.status} ${b.text} ${c.text}`;
});
await t("members: an accepted or canceled invitation can no longer be accepted", async () => {
  const stray = await person("late"); const inv2 = (await mcall(M.owner, "POST", "/v1/invitations", { email: stray.email, role: "member" })).json;
  await mcall(M.owner, "POST", `/v1/invitations/${inv2.invitationId}/cancel`);
  const r = await call(A, "/v1/orgs/invitations/accept", { method: "POST", bearer: stray.token, body: { id: inv2.invitationId } });
  return (r.status === 404 && r.json?.error === "invitation_not_found") || `${r.status} ${r.text}`;
});
await t("members: only the owner changes roles (members and admins get the reference's denial)", async () => {
  for (const u of [member, admin]) { const r = await mcall(u, "POST", `/v1/members/${member2.memberId}/role`, { role: "admin" }); if (!(r.status === 403 && r.json?.error === "forbidden" && r.json?.code === "requires_admin" && r.json?.requiredPermission === "members.update" && r.json?.message === "You don't have permission to change member roles. Ask the organization owner.")) return `${r.status} ${r.text}`; }
  return true;
});
await t("members: invalid roles, the owner's role, unknown and malformed ids", async () => {
  const bad = await mcall(M.owner, "POST", `/v1/members/${member2.memberId}/role`, { role: "bogus" }); const own = await mcall(M.owner, "POST", `/v1/members/${M.owner.memberId ?? await mid(M.owner)}/role`, { role: "member" });
  const asOwner = await mcall(M.owner, "POST", `/v1/members/${member2.memberId}/role`, { role: "owner" });
  const unknown = await mcall(M.owner, "POST", "/v1/members/om_01m00000000000000000000000/role", { role: "admin" }); const malformed = await mcall(M.owner, "POST", "/v1/members/nope/role", { role: "admin" });
  return (bad.status === 400 && bad.json?.error === "invalid_role" && bad.json?.message === "Choose one of the existing organization roles." && asOwner.json?.error === "invalid_role"
    && own.status === 400 && own.json?.error === "owner_role_locked" && own.json?.message === "The organization owner role cannot be changed."
    && unknown.status === 404 && unknown.json?.error === "member_not_found" && unknown.json?.message === "The organization member could not be found."
    && malformed.status === 400 && malformed.json?.error === "invalid_request" && malformed.json?.message === "memberId: TypeID must be 29 characters (om_<26 char suffix>) (and 3 more)") || JSON.stringify([bad.text, own.text, unknown.text, malformed.text]);
});
await t("members: promoting keeps the session; demoting ends all of the person's sessions", async () => {
  const up = await mcall(M.owner, "POST", `/v1/members/${member2.memberId}/role`, { role: " Admin " }); const stillIn = await call(A, "/v1/me", { bearer: member2.token });
  const down = await mcall(M.owner, "POST", `/v1/members/${member2.memberId}/role`, { role: "member" }); const gone = await call(A, "/v1/me", { bearer: member2.token });
  return (up.status === 200 && up.json?.success === true && stillIn.status === 200 && down.status === 200 && gone.status === 401) || `${up.status} ${stillIn.status} ${down.status} ${gone.status}`;
});
await t("members: only the owner can transfer ownership, and only to an admin", async () => {
  await relogin(member2);
  const byAdmin = await mcall(admin, "POST", `/v1/members/${member.memberId}/transfer-ownership`);
  const self = await mcall(M.owner, "POST", `/v1/members/${await mid(M.owner)}/transfer-ownership`); const toMember = await mcall(M.owner, "POST", `/v1/members/${member.memberId}/transfer-ownership`);
  const unknown = await mcall(M.owner, "POST", "/v1/members/om_01m00000000000000000000000/transfer-ownership");
  return (byAdmin.status === 403 && byAdmin.json?.code === "requires_admin" && byAdmin.json?.message === "Only the workspace owner can do this." && !("requiredPermission" in byAdmin.json)
    && self.status === 400 && self.json?.error === "owner_transfer_invalid" && self.json?.message === "Choose a different active member to become workspace owner."
    && toMember.status === 400 && toMember.json?.message === "Choose an active workspace admin to become owner."
    && unknown.status === 404 && unknown.json?.error === "target_member_not_found" && unknown.json?.message === "Choose an active member to become workspace owner.") || JSON.stringify([byAdmin.text, self.text, toMember.text, unknown.text]);
});
await t("members: removal rules (members denied, the owner is protected, admins can remove)", async () => {
  const byMember = await mcall(member, "DELETE", `/v1/members/${member2.memberId}`); const owner = await mcall(admin, "DELETE", `/v1/members/${await mid(M.owner)}`);
  return (byMember.status === 403 && byMember.json?.requiredPermission === "members.delete" && byMember.json?.message === "You don't have permission to remove members. Ask an admin to change your permissions."
    && owner.status === 400 && owner.json?.error === "owner_role_locked" && owner.json?.message === "The organization owner cannot be removed.") || `${byMember.text} / ${owner.text}`;
});
await t("members: removing someone ends their sessions and their view of the workspace", async () => {
  const gone = await mcall(admin, "DELETE", `/v1/members/${member2.memberId}`); const session = await call(A, "/v1/me", { bearer: member2.token });
  await relogin(member2); const org = await mcall(member2, "GET", "/v1/org"); const orgs = await call(A, "/v1/me/orgs", { bearer: member2.token }); const again = await mcall(M.owner, "DELETE", `/v1/members/${member2.memberId}`);
  return (gone.status === 204 && session.status === 401 && org.status === 404 && org.json?.error === "organization_not_found" && orgs.json?.orgs?.length === 0 && orgs.json?.activeOrgId === null && again.status === 404 && again.json?.error === "member_not_found" && again.json?.message === "The organization member could not be found.") || `${gone.status} ${session.status} ${org.status} ${org.text} ${orgs.text} ${again.status} ${again.text}`;
});
await t("members: a workspace you are not in does not exist for you, and no session is 401", async () => {
  const outsider = await person("outsider"); const a = await mcall(outsider, "GET", "/v1/org"); const b = await mcall(outsider, "POST", "/v1/invitations", { email: email("x"), role: "member" }); const c = await call(A, "/v1/org", { headers: { "x-openwork-org-id": M.org } });
  return (a.status === 404 && a.json?.error === "organization_not_found" && b.status === 404 && c.status === 401) || `${a.status} ${b.status} ${c.status}`;
});
await t("members: ownership transfer swaps the roles and signs the previous owner out", async () => {
  const ownerMid = await mid(M.owner); const t1 = await mcall(M.owner, "POST", `/v1/members/${admin.memberId}/transfer-ownership`); const oldGone = await call(A, "/v1/me", { bearer: M.owner.token });
  const stale = await call(A, "/v1/me", { bearer: admin.token }); await relogin(admin);   // the new owner is signed out too
  const j = (await mcall(admin, "GET", "/v1/org")).json; const roles = Object.fromEntries(j.members.filter((m) => m.userId).map((m) => [m.userId, m.role]));
  return (t1.status === 200 && t1.json?.success === true && oldGone.status === 401 && stale.status === 401 && roles[admin.id] === "owner" && roles[M.owner.id] === "admin" && j.organization.owner.userId === admin.id && j.currentMember.permissions.length === 59) || JSON.stringify([t1.status, oldGone.status, roles, ownerMid]);
});

// ---------- 8. SSO / SCIM surfaces ----------
section = "sso-scim";
await t("SCIM /Users without token -> 401", async () => { const r = await call(W, "/api/auth/scim/v2/Users"); return [401, 403].includes(r.status) || `${r.status} ${r.text.slice(0, 100)}`; });
await t("SCIM /Schemas without token handled (no 5xx)", async () => { const r = await call(W, "/api/auth/scim/v2/Schemas"); return r.status < 500 || `${r.status}`; });
await t("SCIM generate-token w/o session -> 401/403", async () => { const r = await call(W, "/api/auth/scim/generate-token", { method: "POST", body: { providerId: "x" } }); return [401, 403].includes(r.status) || `${r.status} ${r.text.slice(0, 100)}`; });
await t("SAML SP metadata unknown provider -> 4xx", async () => { const r = await call(W, "/api/auth/sso/saml2/sp/metadata?providerId=nope"); return (r.status >= 400 && r.status < 500) || `${r.status}`; });
await t("OIDC SSO callback unknown provider -> 4xx/redirect (no 5xx)", async () => { const r = await call(W, "/api/auth/sso/callback/nope?code=x&state=y"); return r.status < 500 || `${r.status}`; });
await t("SSO admin API requires auth (/v1/sso/...)", async () => { const r = await call(A, "/v1/sso/oidc", { method: "POST", body: {} }); return [401, 403, 404, 405].includes(r.status) || `${r.status}`; });

// ---------- 9. Sign-out ----------
section = "sign-out";
await t("sign-out (cookie) revokes cookie session", async () => { const r = await call(W, "/api/auth/sign-out", { method: "POST", jar: jar2, body: {} }); const m = await call(W, "/api/auth/get-session", { jar: jar2 }); return (r.status === 200 && (m.json === null || m.text === "null")) || `${r.status} ${m.text.slice(0, 80)}`; });
await t("sign-out (bearer) revokes bearer session", async () => { const r = await call(A, "/api/auth/sign-out", { method: "POST", bearer: token, body: {} }); const m = await call(A, "/v1/me", { bearer: token }); return (r.status === 200 && m.status === 401) || `${r.status}/${m.status}`; });
await t("clear-session-cookie route (web local)", async () => { const r = await call(W, "/api/auth/clear-session-cookie", { method: "POST" }); return (r.status === 200 && r.json?.ok === true && r.headers.getSetCookie().length > 0) || `${r.status}`; });
await t("unknown /api/auth path -> 404 (not 5xx)", async () => { const r = await call(W, "/api/auth/definitely-not-a-route"); return r.status === 404 || `${r.status}`; });

// ---------- summary ----------
const fail = results.filter((r) => !r.ok);
console.log(`\n==== ${results.length - fail.length}/${results.length} passed, ${fail.length} failed ====`);
for (const f of fail) console.log(`FAILED [${f.section}] ${f.name} -> ${f.detail}`);
process.exit(fail.length ? 1 : 0);
