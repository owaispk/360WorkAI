// Contract test for the OpenID Connect surface of the OAuth provider: discovery, ID tokens (signature checked against the published keys,
// nonce, at_hash, audience), userinfo (scope-dependent claims), token introspection (client authentication, never another client's token),
// and what RP-initiated logout refuses. Runs unchanged against the reference and the rewrite:
//   node area-oidc.mjs                                                     # reference: web :3005, api :8790
//   W=http://localhost:5290 A=http://localhost:5190 node area-oidc.mjs     # rewrite
// The reference signs with EdDSA and the rewrite with ES256, so the checks accept either and verify the signature for whichever it is.
import { createHash, createPublicKey, randomBytes, verify as cryptoVerify } from "node:crypto";
import { W, A, PW, suite, email } from "./lib.mjs";

class Jar {
  c = new Map();
  absorb(res) { for (const sc of res.headers.getSetCookie?.() ?? []) { const [pair, ...attrs] = sc.split(";"); const i = pair.indexOf("="); const k = pair.slice(0, i).trim(), v = pair.slice(i + 1).trim(); if (v === "" || attrs.some((a) => /^\s*max-age=0/i.test(a))) this.c.delete(k); else this.c.set(k, v); } }
  header() { return [...this.c].map(([k, v]) => `${k}=${v}`).join("; "); }
}
async function call(base, path, { method = "GET", body, form, headers = {}, jar } = {}) {
  const h = { origin: W, ...headers };
  if (jar?.c.size) h.cookie = jar.header();
  let payload;
  if (form) { h["content-type"] = "application/x-www-form-urlencoded"; payload = new URLSearchParams(form).toString(); }
  else if (body !== undefined) { h["content-type"] = "application/json"; payload = JSON.stringify(body); }
  const res = await fetch(base + path, { method, headers: h, body: payload, redirect: "manual", signal: AbortSignal.timeout(60000) });
  jar?.absorb(res);
  const text = await res.text(); let json = null; try { json = JSON.parse(text); } catch {}
  return { status: res.status, json, text, headers: res.headers };
}
const decode = (t) => { const [h, p] = t.split("."); return [JSON.parse(Buffer.from(h, "base64url")), JSON.parse(Buffer.from(p, "base64url"))]; };
const basicOf = (c) => "Basic " + Buffer.from(`${c.client_id}:${c.client_secret}`).toString("base64");
const redirect = "http://127.0.0.1:9/cb";
const resource = `${A}/mcp/agent`;

async function signedInPerson(name) {
  const jar = new Jar(); const e = email("oidc");
  const su = await call(W, "/api/auth/sign-up/email", { method: "POST", jar, body: { name, email: e, password: PW } });
  if (!su.json?.token) throw new Error(`sign-up returned no session: ${su.status} ${su.text.slice(0, 100)}`);
  const org = await call(A, "/v1/org", { method: "POST", jar, headers: { authorization: `Bearer ${su.json.token}` }, body: { name: "OIDC Probe" } });
  await call(A, "/v1/me/active-organization", { method: "POST", jar, body: { organizationId: org.json.organization.id } });
  return { jar, email: e, userId: su.json.user.id, name };
}
async function registerClient(extra = {}) {
  const r = await call(A, "/register", { method: "POST", body: { client_name: "oidc contract client", redirect_uris: [redirect], token_endpoint_auth_method: "client_secret_basic", grant_types: ["authorization_code", "refresh_token"], scope: "openid profile email offline_access mcp:read mcp:write", ...extra } });
  return { ...r.json, status: r.status };
}
/** Authorization request -> consent -> the code. Returns { code, verifier, redirected } */
async function authorizeFor(person, client, { scope, nonce, state = "st-1" }) {
  const verifier = randomBytes(32).toString("base64url");
  const p = { response_type: "code", client_id: client.client_id, redirect_uri: redirect, scope, state, code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256", resource };
  if (nonce) p.nonce = nonce;
  const au = await call(A, `/api/auth/oauth2/authorize?${new URLSearchParams(p)}`, { jar: person.jar });
  const loc = au.headers.get("location") ?? "";
  let url = loc.includes("code=") ? new URL(loc) : null;
  if (!url) {
    const con = await call(W, "/api/auth/oauth2/consent", { method: "POST", jar: person.jar, body: { accept: true, scope, oauth_query: loc.slice(loc.indexOf("?") + 1) } });
    url = con.json?.url ? new URL(con.json.url) : null;
  }
  return { code: url?.searchParams.get("code"), verifier, url };
}
const tokenRequest = (client, form) => call(W, "/api/auth/oauth2/token", { method: "POST", headers: { authorization: basicOf(client) }, form });
async function fullFlow(person, client, scope, nonce) {
  const a = await authorizeFor(person, client, { scope, nonce });
  const t = await tokenRequest(client, { grant_type: "authorization_code", code: a.code, redirect_uri: redirect, code_verifier: a.verifier, resource });
  return { ...a, token: t };
}

const s = suite("oidc");
const person = await signedInPerson("Ada Lovelace");
const client = await registerClient();
const other = await registerClient();
const publicClient = await registerClient({ token_endpoint_auth_method: "none" });
const FULL = "openid profile email offline_access mcp:read";

// ---------- discovery ----------
let meta;
await s.t("discovery advertises userinfo, introspection, end-session, subject types, ID token algorithms and the OIDC scopes", async () => {
  const r = await call(W, "/.well-known/openid-configuration/api/auth"); meta = r.json;
  const ok = r.status === 200 && meta.userinfo_endpoint === `${W}/api/auth/oauth2/userinfo` && meta.introspection_endpoint === `${W}/api/auth/oauth2/introspect`
    && meta.end_session_endpoint === `${W}/api/auth/oauth2/end-session` && meta.subject_types_supported?.includes("public") && meta.id_token_signing_alg_values_supported?.length > 0
    && ["openid", "profile", "email"].every((x) => meta.scopes_supported?.includes(x)) && meta.jwks_uri === `${W}/api/auth/jwks`;
  return ok || JSON.stringify(meta).slice(0, 300);
});
await s.t("the OAuth and OpenID documents agree on the endpoints", async () => {
  const r = await call(W, "/.well-known/oauth-authorization-server/api/auth");
  return (r.json?.userinfo_endpoint === meta.userinfo_endpoint && r.json?.introspection_endpoint === meta.introspection_endpoint && r.json?.issuer === meta.issuer) || r.text.slice(0, 200);
});
await s.t("introspection is advertised for authenticated clients only (no 'none')", async () => !(meta.introspection_endpoint_auth_methods_supported ?? []).includes("none") && (meta.introspection_endpoint_auth_methods_supported ?? []).includes("client_secret_basic"));
await s.t("registration accepts the OIDC scopes", async () => client.status === 201 && ["openid", "profile", "email"].every((x) => client.scope.split(" ").includes(x)) || `${client.status} ${client.scope}`);

// ---------- ID token ----------
const main = await fullFlow(person, client, FULL, "nonce-abc-123");
await s.t("the authorization response names the issuer (RFC 9207) and returns the state", async () => main.url?.searchParams.get("state") === "st-1" && main.url.searchParams.get("iss") === meta.issuer || String(main.url));
await s.t("the token response carries an access token, a refresh token and an id_token", async () => (main.token.status === 200 && !!main.token.json.access_token && !!main.token.json.refresh_token && main.token.json.id_token?.split(".").length === 3 && main.token.json.scope === FULL) || main.token.text.slice(0, 200));
const [idHeader, idClaims] = decode(main.token.json.id_token);
await s.t("the ID token is signed with a published key (signature verified against the JWKS)", async () => {
  const jwks = (await call(W, "/api/auth/jwks")).json;
  const jwk = jwks.keys.find((k) => k.kid === idHeader.kid);
  if (!jwk) return `kid ${idHeader.kid} is not in the JWKS`;
  const [h, p, sig] = main.token.json.id_token.split(".");
  const key = createPublicKey({ key: jwk, format: "jwk" });
  const data = Buffer.from(`${h}.${p}`);
  const ok = idHeader.alg === "EdDSA" ? cryptoVerify(null, data, key, Buffer.from(sig, "base64url")) : idHeader.alg === "ES256" ? cryptoVerify("sha256", data, { key, dsaEncoding: "ieee-p1363" }, Buffer.from(sig, "base64url")) : `unexpected alg ${idHeader.alg}`;
  return ok === true || String(ok);
});
await s.t("claims: iss, sub (the person), aud (the client id only), nonce echoed, iat/exp, auth_time, acr", async () =>
  (idClaims.iss === meta.issuer && idClaims.sub === person.userId && idClaims.aud === client.client_id && idClaims.nonce === "nonce-abc-123" && idClaims.exp > idClaims.iat
    && Math.abs(idClaims.iat - Date.now() / 1000) < 120 && typeof idClaims.auth_time === "number" && idClaims.auth_time <= idClaims.iat && idClaims.acr === "0") || JSON.stringify(idClaims));
await s.t("at_hash matches the access token (left half of its hash)", async () => {
  const hashAlg = idHeader.alg === "EdDSA" ? "sha512" : "sha256";
  const digest = createHash(hashAlg).update(main.token.json.access_token, "ascii").digest();
  return idClaims.at_hash === digest.subarray(0, digest.length / 2).toString("base64url") || `${idClaims.at_hash}`;
});
await s.t("the ID token carries no profile or email claims (those come from userinfo)", async () => !("email" in idClaims) && !("name" in idClaims));
await s.t("without a nonce in the request the ID token has none", async () => {
  const f = await fullFlow(person, client, "openid mcp:read", undefined);
  const [, c] = decode(f.token.json.id_token); return (f.token.status === 200 && !("nonce" in c)) || JSON.stringify(c);
});
await s.t("an ID token is only issued when the openid scope was granted", async () => {
  const f = await fullFlow(person, client, "mcp:read", "n1"); return (f.token.status === 200 && !("id_token" in f.token.json)) || f.token.text.slice(0, 200);
});
let refreshed;
await s.t("a refresh issues a new ID token for the same sign-in (same auth_time, no nonce, same audience)", async () => {
  refreshed = await tokenRequest(client, { grant_type: "refresh_token", refresh_token: main.token.json.refresh_token, resource });
  if (refreshed.status !== 200 || !refreshed.json.id_token) return refreshed.text.slice(0, 200);
  const [, c] = decode(refreshed.json.id_token);
  return (c.aud === client.client_id && c.sub === person.userId && c.auth_time === idClaims.auth_time && !("nonce" in c)) || JSON.stringify(c);
});

// ---------- userinfo ----------
const info = (token, opts = {}) => call(W, "/api/auth/oauth2/userinfo", { ...opts, headers: token ? { authorization: `Bearer ${token}`, ...(opts.headers ?? {}) } : opts.headers });
await s.t("userinfo with openid profile email: sub, name, given/family name, email, email_verified", async () => {
  const r = await info(main.token.json.access_token);
  return (r.status === 200 && r.json.sub === person.userId && r.json.name === "Ada Lovelace" && r.json.given_name === "Ada" && r.json.family_name === "Lovelace" && r.json.email === person.email && typeof r.json.email_verified === "boolean") || `${r.status} ${r.text}`;
});
await s.t("userinfo with openid only: just sub", async () => {
  const f = await fullFlow(person, client, "openid", "n2"); const r = await info(f.token.json.access_token);
  return (r.status === 200 && Object.keys(r.json).join() === "sub") || `${r.status} ${r.text}`;
});
await s.t("userinfo with openid email: no name", async () => {
  const f = await fullFlow(person, client, "openid email", "n3"); const r = await info(f.token.json.access_token);
  return (r.status === 200 && r.json.email === person.email && !("name" in r.json)) || `${r.status} ${r.text}`;
});
await s.t("userinfo with openid profile: no email", async () => {
  const f = await fullFlow(person, client, "openid profile", "n4"); const r = await info(f.token.json.access_token);
  return (r.status === 200 && r.json.name === "Ada Lovelace" && !("email" in r.json)) || `${r.status} ${r.text}`;
});
await s.t("userinfo without the openid scope: 400 invalid_scope", async () => {
  const f = await fullFlow(person, client, "mcp:read", "n5"); const r = await info(f.token.json.access_token);
  return (r.status === 400 && r.json?.error === "invalid_scope" && r.json?.error_description === "Missing required scope") || `${r.status} ${r.text}`;
});
await s.t("userinfo without a token: 401 invalid_request", async () => { const r = await info(null); return (r.status === 401 && r.json?.error === "invalid_request") || `${r.status} ${r.text}`; });
await s.t("userinfo with a garbage token: 401 invalid_token and a Bearer challenge", async () => {
  const r = await info("not-a-token"); return (r.status === 401 && r.json?.error === "invalid_token" && /^Bearer .*invalid_token/.test(r.headers.get("www-authenticate") ?? "")) || `${r.status} ${r.text}`;
});
await s.t("an ID token is not accepted as an access token at userinfo", async () => (await info(main.token.json.id_token)).status === 401);
await s.t("userinfo also answers POST with the token in the form body", async () => {
  const r = await call(W, "/api/auth/oauth2/userinfo", { method: "POST", form: { access_token: main.token.json.access_token } }); return (r.status === 200 && r.json?.sub === person.userId) || `${r.status} ${r.text}`;
});
await s.t("a token in the header and in the body is refused", async () => {
  const r = await call(W, "/api/auth/oauth2/userinfo", { method: "POST", headers: { authorization: `Bearer ${main.token.json.access_token}` }, form: { access_token: main.token.json.access_token } }); return (r.status === 400 && r.json?.error === "invalid_request") || `${r.status} ${r.text}`;
});

// ---------- introspection ----------
const introspect = (headers, form) => call(W, "/api/auth/oauth2/introspect", { method: "POST", headers, form });
await s.t("introspect: the client's own access token is active, with its client, scope and subject", async () => {
  const r = await introspect({ authorization: basicOf(client) }, { token: main.token.json.access_token });
  return (r.status === 200 && r.json.active === true && r.json.client_id === client.client_id && r.json.sub === person.userId && r.json.scope === FULL && r.json.iss === meta.issuer && r.json.token_type === "Bearer" && r.json.exp > Date.now() / 1000) || `${r.status} ${r.text.slice(0, 300)}`;
});
await s.t("introspect: the client's own refresh token is active", async () => {
  const r = await introspect({ authorization: basicOf(client) }, { token: refreshed.json.refresh_token });
  return (r.status === 200 && r.json.active === true && r.json.client_id === client.client_id && r.json.sub === person.userId && r.json.scope?.includes("openid")) || `${r.status} ${r.text.slice(0, 300)}`;
});
await s.t("introspect: another client's access token is inactive (no oracle)", async () => {
  const r = await introspect({ authorization: basicOf(other) }, { token: main.token.json.access_token }); return (r.status === 200 && r.text === '{"active":false}') || `${r.status} ${r.text}`;
});
await s.t("introspect: another client's refresh token is inactive", async () => {
  const r = await introspect({ authorization: basicOf(other) }, { token: refreshed.json.refresh_token }); return (r.status === 200 && r.text === '{"active":false}') || `${r.status} ${r.text}`;
});
await s.t("introspect: an unknown token and an ID token are inactive", async () => {
  const a = await introspect({ authorization: basicOf(client) }, { token: "garbage" }); const b = await introspect({ authorization: basicOf(client) }, { token: main.token.json.id_token });
  return (a.status === 200 && a.json?.active === false && b.status === 200 && b.json?.active === false) || `${a.status} ${a.text} / ${b.status} ${b.text}`;
});
await s.t("introspect: no credentials -> 401 invalid_client", async () => { const r = await introspect({}, { token: main.token.json.access_token }); return (r.status === 401 && r.json?.error === "invalid_client") || `${r.status} ${r.text}`; });
await s.t("introspect: a wrong secret -> 401 invalid_client", async () => { const r = await introspect({ authorization: "Basic " + Buffer.from(`${client.client_id}:wrong`).toString("base64") }, { token: main.token.json.access_token }); return (r.status === 401 && r.json?.error === "invalid_client") || `${r.status} ${r.text}`; });
await s.t("introspect: a public client cannot introspect", async () => { const r = await introspect({}, { client_id: publicClient.client_id, token: main.token.json.access_token }); return (r.status === 401 && r.json?.error === "invalid_client") || `${r.status} ${r.text}`; });
await s.t("introspect: no token -> 400 invalid_request", async () => { const r = await introspect({ authorization: basicOf(client) }, {}); return (r.status === 400 && r.json?.error === "invalid_request") || `${r.status} ${r.text}`; });
await s.t("introspect: a JSON body is refused (415)", async () => { const r = await call(W, "/api/auth/oauth2/introspect", { method: "POST", headers: { authorization: basicOf(client) }, body: { token: main.token.json.access_token } }); return r.status === 415 || `${r.status}`; });
await s.t("introspect: a revoked refresh token is inactive", async () => {
  await call(W, "/api/auth/oauth2/revoke", { method: "POST", headers: { authorization: basicOf(client) }, form: { token: refreshed.json.refresh_token } });
  const r = await introspect({ authorization: basicOf(client) }, { token: refreshed.json.refresh_token }); return (r.status === 200 && r.json?.active === false) || `${r.status} ${r.text}`;
});

// ---------- RP-initiated logout: what is refused ----------
const endSession = (q, opts = {}) => call(W, `/api/auth/oauth2/end-session?${new URLSearchParams(q)}`, opts);
await s.t("end-session: a client registered anonymously may not log people out (401 invalid_client)", async () => {
  const r = await endSession({ id_token_hint: main.token.json.id_token, client_id: client.client_id }); return (r.status === 401 && r.json?.error === "invalid_client") || `${r.status} ${r.text}`;
});
await s.t("end-session: an unknown client (400 invalid_client)", async () => { const r = await endSession({ id_token_hint: "a.b.c", client_id: "nobody" }); return (r.status === 400 && r.json?.error === "invalid_client") || `${r.status} ${r.text}`; });
await s.t("end-session: no hint and no client from a non-browser caller needs the person's confirmation (400 invalid_request)", async () => {
  const r = await endSession({}, { jar: person.jar }); return (r.status === 400 && r.json?.error === "invalid_request") || `${r.status} ${r.text}`;
});
await s.t("end-session: an anonymous registration's post_logout_redirect_uris are not an open door (the request is still refused)", async () => {
  const c2 = await registerClient({ post_logout_redirect_uris: ["http://127.0.0.1:9/bye"], enable_end_session: true });
  const f = await fullFlow(person, c2, "openid mcp:read", "n6");
  const r = await endSession({ id_token_hint: f.token.json.id_token, client_id: c2.client_id, post_logout_redirect_uri: "http://127.0.0.1:9/bye" }, { jar: person.jar });
  return (r.status === 401 && !r.headers.get("location")) || `${r.status} ${r.headers.get("location")}`;
});
await s.t("the person is still signed in after all of that", async () => (await call(A, "/v1/me", { jar: person.jar })).status === 200);
s.done();
