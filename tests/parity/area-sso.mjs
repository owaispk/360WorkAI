// SSO and SCIM contract test: the same checks against the reference Den and the .NET rewrite.
//   node area-sso.mjs                                                      # reference (web :3005, api :8790)
//   W=http://localhost:5240 A=http://localhost:5140 node area-sso.mjs      # rewrite
// Only what is deterministic without outside network. The identity provider is a local fake (fake-oidc.cjs). Its host name must not be loopback
// and must resolve to this machine (the reference refuses loopback addresses and plain-IP issuers): add `127.0.0.1 fakeidp.test` to /etc/hosts
// (override with IDP_HOST). A domain cannot be proven in DNS here, so the connection stays unverified; the sign-in flow itself is covered by
// the rewrite's own tests, and by this script when the server proves loopback issuers in development (run it with IDP_HOST=127.0.0.1).
import { createRequire } from "node:module";
import { call, workspace, suite, keys, PW, W, A } from "./lib.mjs";
const { startFakeOidc } = createRequire(import.meta.url)("./fake-oidc.cjs");

const s = suite("sso");
const idp = await startFakeOidc({ host: process.env.IDP_HOST || "fakeidp.test" });
const ws = await workspace("SSO Parity");
// Registering a provider needs a cookie session on the reference (it calls Better Auth with the request's headers); send both.
const signIn = await fetch(W + "/api/auth/sign-in/email", { method: "POST", headers: { "content-type": "application/json", origin: W }, body: JSON.stringify({ email: ws.owner.email, password: PW }) });
const cookie = signIn.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
const as = (u, method, path, body) => ws.api(u, method, path, body, { headers: u === ws.owner ? { cookie } : {} });
const owner = (method, path, body) => as(ws.owner, method, path, body);
const member = await ws.join("Plain Member");
const domain = `corp-${Date.now()}.test`;
const reg = (extra = {}) => owner("POST", "/v1/sso/oidc", { issuer: idp.issuer, domain, clientId: idp.clientId, clientSecret: idp.clientSecret, ...extra });
const msg = (r) => r.json?.details?.[0]?.message ?? r.json?.message;

await s.t("nothing configured: GET /v1/sso", async () => { const r = await owner("GET", "/v1/sso"); return (r.status === 200 && keys(r.json) === "connection" && r.json.connection === null) || r.text; });
await s.t("GET /v1/scim shape before a connection", async () => {
  const r = await owner("GET", "/v1/scim");
  return (r.status === 200 && keys(r.json) === "baseUrl,connection,health,ssoReady" && r.json.connection === null && r.json.ssoReady === false && r.json.baseUrl.endsWith("/api/auth/scim/v2")
    && keys(r.json.health) === "lastFailureAction,lastFailureAt,lastFailureMessage,lastSuccessfulSyncAt,nextRetryAt,unresolvedFailureCount") || r.text;
});
await s.t("no connection: lifecycle routes answer the same", async () => {
  const t = await owner("POST", "/v1/sso/test", {}), en = await owner("POST", "/v1/sso/enable", {}), di = await owner("POST", "/v1/sso/disable", {}), vd = await owner("POST", "/v1/sso/verify-domain", {});
  const rq = await owner("POST", "/v1/sso/request-domain-verification", {}), md = await owner("GET", "/v1/sso/metadata"), dl = await owner("DELETE", "/v1/sso"), cn = await owner("POST", "/v1/sso/test/abc/cancel", {});
  return (t.status === 404 && t.json.error === "organization_not_found" && en.status === 409 && en.json.error === "sso_lifecycle_error" && en.json.message === "SSO configuration was not found."
    && di.status === 404 && vd.status === 404 && rq.status === 404 && md.status === 404 && dl.status === 204 && cn.status === 204) || `${t.status} ${en.status} ${di.status} ${vd.status} ${rq.status} ${md.status} ${dl.status} ${cn.status}`;
});
await s.t("saving validates the body in zod wording", async () => {
  const empty = await owner("POST", "/v1/sso/oidc", {});
  const bad = await owner("POST", "/v1/sso/oidc", { issuer: "x", domain: "", clientId: "a", clientSecret: "" });
  return (empty.status === 400 && empty.json.error === "invalid_request" && empty.json.details.map((d) => d.path[0]).join() === "issuer,domain,clientId,clientSecret"
    && empty.json.details[0].message === "Invalid input: expected string, received undefined"
    && bad.json.details.map((d) => d.message).join("|") === "Invalid URL|Too small: expected string to have >=1 characters|Too small: expected string to have >=1 characters") || JSON.stringify([empty.json, bad.json]).slice(0, 300);
});
await s.t("permissions: a plain member cannot read or change SSO or SCIM", async () => {
  const a = await as(member, "GET", "/v1/sso"), b = await as(member, "POST", "/v1/sso/oidc", {}), c = await as(member, "GET", "/v1/scim"), d = await as(member, "POST", "/v1/scim/token", {});
  const anon = await call(A, "/v1/sso");
  return (a.status === 403 && a.json.requiredPermission === "sso.view" && b.json.requiredPermission === "sso.manage" && c.json.requiredPermission === "scim.view" && d.json.requiredPermission === "scim.manage" && anon.status === 401 && anon.json.error === "unauthorized")
    || `${a.status} ${b.text.slice(0, 80)} ${c.text.slice(0, 80)} ${d.text.slice(0, 80)} ${anon.status}`;
});

let connection, token, verified = false;
await s.t("saving OIDC: 201, unverified, disabled, endpoints from discovery, secret never shown", async () => {
  const r = await reg();
  connection = r.json?.connection; token = r.json?.domainVerificationToken; verified = connection?.domainVerified === true;
  const c = connection;
  const get = await owner("GET", "/v1/sso");
  return (r.status === 201 && keys(c) === "acsUrl,createdAt,domain,domainVerificationDnsName,domainVerificationHost,domainVerified,id,issuer,kind,lastError,lastTestedAt,metadataUrl,oidc,providerId,redirectUrl,saml,signInPath,signInUrl,status,testExpiresAt,testStatus,updatedAt"
    && c.kind === "oidc" && c.status === "disabled" && c.testStatus === "untested" && c.domain === domain && c.issuer === idp.issuer && c.saml === null && c.acsUrl === null
    && c.providerId === `openwork-sso-${ws.orgId}` && c.signInPath.startsWith("/sso/") && c.redirectUrl.endsWith(`/api/auth/sso/callback/${c.providerId}`)
    && c.domainVerificationHost === `_better-auth-token-${c.providerId}` && c.domainVerificationDnsName === `${c.domainVerificationHost}.${domain}`
    && keys(c.oidc) === "authorizationEndpoint,clientId,jwksEndpoint,scopes,skipDiscovery,tokenEndpoint,tokenEndpointAuthentication,userInfoEndpoint"
    && c.oidc.tokenEndpoint === `${idp.url}/token` && c.oidc.scopes.join() === "openid,email,profile" && c.oidc.skipDiscovery === true && c.oidc.tokenEndpointAuthentication === "client_secret_basic"
    && !r.text.includes(idp.clientSecret) && !get.text.includes(idp.clientSecret) && (verified || typeof token === "string")) || r.text.slice(0, 400);
});
if (!verified) {
  await s.t("domain proof: the token is stable and the DNS check fails until the record exists", async () => {
    const again = await owner("POST", "/v1/sso/request-domain-verification", {});
    const v = await owner("POST", "/v1/sso/verify-domain", {});
    return (again.status === 201 && again.json.domainVerificationToken === token && v.status === 400 && v.json.error === "invalid_request" && msg(v).startsWith("Unable to verify domain ownership for")) || `${again.text} ${v.text}`;
  });
  await s.t("unverified: enable and test are refused with the lifecycle messages", async () => {
    const en = await owner("POST", "/v1/sso/enable", {}), t = await owner("POST", "/v1/sso/test", {}), st = await owner("POST", "/v1/sso/test/abc/start", {});
    return (en.status === 409 && en.json.message === "Verify the SSO domain before enabling SSO." && t.status === 409 && t.json.message === "Verify the SSO domain before testing this configuration."
      && st.status === 409 && st.json.message === "This SSO authentication test is no longer available. Start a new test.") || `${en.text} ${t.text} ${st.text}`;
  });
  await s.t("unverified: sign-in is refused and the domain is not routed to SSO", async () => {
    const si = await call(W, "/api/auth/sign-in/sso", { method: "POST", body: { organizationSlug: connection.signInPath.slice(5), callbackURL: "/dashboard" } });
    const e = `someone@${domain}`;
    const rs = await call(A, `/v1/orgs/sso/resolve?email=${e}`), lo = await call(A, `/v1/auth/login-options?email=${e}`);
    return (si.status === 403 && si.json.message === "SSO is not enabled for this organization. An administrator must test and enable the saved configuration first."
      && rs.status === 200 && rs.json.requireSso === false && rs.json.method === "signup" && lo.status === 200 && lo.json.nextStep === "new_account" && keys(lo.json) === "allowInvitationSignup,allowPublicSignup,email,nextStep")
      || `${si.status} ${si.text} ${rs.text} ${lo.text}`;
  });
}
await s.t("sign-in start: unknown provider 404, unknown slug 400, no identifier 400", async () => {
  const a = await call(W, "/api/auth/sign-in/sso", { method: "POST", body: { providerId: "nope", callbackURL: "/dashboard" } });
  const b = await call(W, "/api/auth/sign-in/sso", { method: "POST", body: { organizationSlug: "nope-nope", callbackURL: "/dashboard" } });
  return (a.status === 404 && a.json.message === "No provider found for the issuer" && b.status === 400 && b.json.message === "providerId, orgId or domain is required") || `${a.status} ${a.text} ${b.status} ${b.text}`;
});
await s.t("sign-in start never redirects to another site", async () => {
  const slug = connection.signInPath.slice(5);
  for (const target of ["https://evil.example/x", "//evil.example", "javascript:alert(1)", "http://localhost@evil.example/"]) {
    const r = await call(W, "/api/auth/sign-in/sso", { method: "POST", body: { organizationSlug: slug, callbackURL: target } });
    if (r.status !== 403 || r.json?.code !== "INVALID_CALLBACK_URL") return `${target}: ${r.status} ${r.text}`;
  }
  return true;
});
await s.t("callback: unknown provider redirects to the error page; unknown state on a disabled connection is 403", async () => {
  const a = await call(W, "/api/auth/sso/callback/nope?code=x&state=y");
  const b = await call(W, `/api/auth/sso/callback/${connection.providerId}?code=x&state=y`);
  return (a.status === 302 && new URL(a.headers.get("location")).pathname === "/connect/error" && new URL(a.headers.get("location")).searchParams.get("error") === "state_mismatch"
    && (verified || (b.status === 403 && b.json.error === "sso_not_enabled"))) || `${a.status} ${a.headers.get("location")} ${b.status} ${b.text}`;
});
await s.t("saving again forgets everything and replaces the configuration", async () => {
  const r = await reg({ clientId: "c2", clientSecret: "s2", scopes: ["openid"], tokenEndpointAuthentication: "client_secret_post" });
  const c = r.json?.connection;
  return (r.status === 201 && c.oidc.clientId === "c2" && c.oidc.scopes.join() === "openid" && c.oidc.tokenEndpointAuthentication === "client_secret_post" && c.status === "disabled" && c.testStatus === "untested") || r.text.slice(0, 300);
});
await s.t("save without discovery needs the endpoints (4xx)", async () => {
  const r = await reg({ skipDiscovery: true });
  return (r.status >= 400 && r.status < 500 || r.status === 500) || r.text;   // the reference answers 500 here, the rewrite 400 (documented difference); both refuse
});
await s.t("deleting removes the connection", async () => {
  const d = await owner("DELETE", "/v1/sso"), g = await owner("GET", "/v1/sso");
  return (d.status === 204 && g.json.connection === null) || `${d.status} ${g.text}`;
});

// ---- SCIM ----
await s.t("SCIM token needs an enabled SSO connection", async () => { const r = await owner("POST", "/v1/scim/token", {}); return (r.status === 409 && r.json.error === "sso_required" && r.json.message === "Configure an enabled SSO connection before creating or rotating a SCIM token.") || r.text; });
await s.t("SCIM settings without a connection", async () => {
  const p = await owner("PATCH", "/v1/scim", { groupMappingMode: "create_teams" }), rc = await owner("POST", "/v1/scim/reconcile", {}), dl = await owner("DELETE", "/v1/scim");
  return (p.status === 404 && p.json.error === "not_found" && p.json.message === "Create the SCIM connector before enabling group mapping." && rc.status === 200 && JSON.stringify(rc.json) === '{"checked":0,"repaired":0,"failures":0}' && dl.status === 204) || `${p.text} ${rc.text} ${dl.status}`;
});
await s.t("SCIM server: no token and a bad token are 401, the support document is public", async () => {
  const none = await call(W, "/api/auth/scim/v2/Users"), bad = await call(W, "/api/auth/scim/v2/Users", { bearer: "garbage" }), cfg = await call(W, "/api/auth/scim/v2/ServiceProviderConfig");
  const sch = await call(W, "/api/auth/scim/v2/Schemas"), grp = await call(W, "/api/auth/scim/v2/Groups"), mk = await call(W, "/api/auth/scim/v2/Users", { method: "POST", body: { userName: "a@b.test" } });
  return (none.status === 401 && none.json.detail === "SCIM token is required" && none.json.status === "401" && none.json.schemas[0] === "urn:ietf:params:scim:api:messages:2.0:Error"
    && bad.status === 401 && bad.json.detail === "Invalid SCIM token" && cfg.status === 200 && cfg.json.patch.supported === true && cfg.json.filter.supported === true && cfg.json.bulk.supported === false
    && [sch.status, grp.status, mk.status].every((x) => x === 401)) || `${none.status} ${none.text} ${bad.text} ${cfg.status} ${sch.status} ${grp.status} ${mk.status}`;
});

// ---- Only when this server proves loopback issuers (rewrite in development, run with IDP_HOST=127.0.0.1): the whole sign-in ----
if (verified) {
  const slug = ws.orgId;
  const hop = (url, jar) => fetch(url, { redirect: "manual", headers: jar ? { cookie: jar } : {} });
  const jarOf = (r) => (r.headers.getSetCookie?.() ?? []).map((c) => c.split(";")[0]).join("; ");
  // A fresh workspace so the earlier steps cannot interfere.
  // (Its own email domain, so the connection it enables claims no domain other tests use.)
  const dom2 = `flow-${Date.now()}.test`;
  const o2 = { email: `owner@${dom2}` };
  const su = await call(W, "/api/auth/sign-up/email", { method: "POST", body: { name: "Flow Owner", email: o2.email, password: PW } });
  o2.token = su.json.token;
  const org2 = await call(A, "/v1/org", { method: "POST", bearer: o2.token, body: { name: "SSO Flow" } });
  const w2 = { owner: o2, orgId: org2.json.organization.id, api: (u, method, path, body) => call(A, path, { method, bearer: u.token, headers: { "x-openwork-org-id": org2.json.organization.id }, body }) };
  idp.identity = { sub: "owner-sub", email: w2.owner.email, email_verified: true, name: "Owner" };
  const r2 = await w2.api(w2.owner, "POST", "/v1/sso/oidc", { issuer: idp.issuer, domain: dom2, clientId: idp.clientId, clientSecret: idp.clientSecret });
  await s.t("loopback issuer is proven and the connection test works end to end", async () => {
    const t = await w2.api(w2.owner, "POST", "/v1/sso/test", {});
    const st = await w2.api(w2.owner, "POST", `/v1/sso/test/${t.json.intentId}/start`, {});
    const jar = jarOf({ headers: st.headers });
    const toCb = await hop(st.json.url); const cb = await hop(toCb.headers.get("location"), jar);
    const after = await w2.api(w2.owner, "GET", "/v1/sso");
    const second = await w2.api(w2.owner, "POST", `/v1/sso/test/${t.json.intentId}/start`, {});
    return (r2.json.connection.domainVerified && t.status === 201 && st.status === 200 && cb.status === 302 && cb.headers.get("location").includes("/sso/test/complete?openworkSsoTest=") && after.json.connection.testStatus === "succeeded" && second.status === 409) || `${t.status} ${st.status} ${cb.status} ${cb.headers.get("location")} ${after.text.slice(0, 200)}`;
  });
  await s.t("enable, then the domain goes to SSO and members lose their password", async () => {
    const en = await w2.api(w2.owner, "POST", "/v1/sso/enable", {});
    const e = `anyone@${dom2}`;
    const rs = await call(A, `/v1/orgs/sso/resolve?email=${e}`), lo = await call(A, `/v1/auth/login-options?email=${e}`);
    const pw = await call(W, "/api/auth/sign-in/email", { method: "POST", body: { email: w2.owner.email, password: PW } });
    return (en.status === 204 && rs.json.requireSso === true && rs.json.method === "sso" && rs.json.signInPath.startsWith("/sso/") && lo.json.nextStep === "sso" && pw.status === 403 && pw.json.message === "This account is managed by an organization. Use SSO to sign in.")
      || `${en.status} ${rs.text} ${lo.text} ${pw.status} ${pw.text}`;
  });
  await s.t("signing in through SSO creates the person, joins them and sets a session", async () => {
    idp.identity = { sub: "new-sub", email: `fresh.${Date.now()}@${dom2}`, email_verified: true, name: "Fresh Person" };
    const st = await call(W, "/api/auth/sign-in/sso", { method: "POST", body: { organizationSlug: w2.orgId, callbackURL: "/dashboard" } });
    const toCb = await hop(st.json.url); const cb = await hop(toCb.headers.get("location"), jarOf({ headers: st.headers }));
    const session = jarOf(cb);
    const me = await fetch(A + "/v1/me", { headers: { cookie: session, origin: W } });
    const body = await me.json();
    return (st.json.redirect === true && cb.status === 302 && new URL(cb.headers.get("location"), W).pathname === "/dashboard" && me.status === 200 && body.user.email === idp.identity.email) || `${st.status} ${cb.status} ${cb.headers.get("location")} ${me.status}`;
  });
  await s.t("a replayed callback and a forged state are refused", async () => {
    idp.identity = { sub: "new-sub2", email: `again.${Date.now()}@${dom2}`, email_verified: true, name: "Again" };
    const st = await call(W, "/api/auth/sign-in/sso", { method: "POST", body: { organizationSlug: w2.orgId, callbackURL: "/dashboard" } });
    const jar = jarOf({ headers: st.headers }); const toCb = await hop(st.json.url); const url = toCb.headers.get("location");
    const first = await hop(url, jar); const replay = await hop(url, jar); const forged = await hop(`${A}/api/auth/sso/callback/openwork-sso-${w2.orgId}?code=x&state=nope`);
    return (first.status === 302 && replay.status === 302 && !jarOf(replay).includes("session_token") && forged.status === 302) || `${first.status} ${replay.status} ${replay.headers.get("location")} ${forged.status}`;
  });
  void slug;
}
await idp.close();
s.done();
