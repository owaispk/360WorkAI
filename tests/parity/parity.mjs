// Contract (parity) test: the same checks run against the reference Den (TypeScript) and the .NET rewrite.
//
//   node parity.mjs                                              # reference: web :3005, api :8790, all sections
//   W=http://localhost:5081 A=http://localhost:5080 \
//   SECTIONS=health,auth,orgs,handoff,device,login-options,sign-out node parity.mjs   # .NET rewrite
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
