// OAuth provider extras contract test: the client_credentials grant, private_key_jwt client authentication and DPoP (RFC 9449), with real signatures
// made by node:crypto. The expectations are the reference OAuth provider's (Better Auth's oauth-provider 1.7 source was read for them).
//   W=http://localhost:5290 A=http://localhost:5190 node area-oauth-extras.mjs     # the rewrite
//   node area-oauth-extras.mjs                                                       # a reference Den (web :3005, api :8790), see below
// Start the rewrite with a platform admin (it can give a client its client_credentials scopes, which the reference has no way to do):
//   PlatformAdmin__BootstrapEmails=padmin.parity@example.com scripts/dev.sh start        (override the address with ADMIN_EMAIL)
// The reference could not be started where this was written, so this script has been run against the rewrite only. Checks marked "(rewrite)" use behavior
// that is this build's (the operator route for scopes); set REFERENCE=1 to skip them. EdDSA is not available in .NET, so no check uses it.
import { createHash, createPublicKey, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { call, workspace, suite, PW, W, A } from "./lib.mjs";

const REFERENCE = process.env.REFERENCE === "1";
const ADMIN_EMAIL = process.env.ADMIN_EMAIL ?? "padmin.parity@example.com";
const s = suite("oauth-extras");
const ws = await workspace("OAuth Extras");
const REDIRECT = "http://127.0.0.1:9999/callback";
const TOKEN_URL = `${W}/api/auth/oauth2/token`;
const ISSUER = `${W}/api/auth`;
const RESOURCE = `${A}/mcp/agent`;

const b64u = (b) => Buffer.from(b).toString("base64url");
const sha256b64u = (v) => b64u(createHash("sha256").update(v).digest());
function newKey(kind = "ec") {
  const pair = kind === "ec" ? generateKeyPairSync("ec", { namedCurve: "P-256" }) : generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = pair.publicKey.export({ format: "jwk" });
  const kid = "k" + randomBytes(4).toString("hex");
  const alg = kind === "ec" ? "ES256" : "RS256";
  const thumbprint = b64u(createHash("sha256").update(kind === "ec" ? `{"crv":"${jwk.crv}","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}` : `{"e":"${jwk.e}","kty":"RSA","n":"${jwk.n}"}`).digest());
  const signJwt = (header, claims, useAlg = alg) => {
    const input = `${b64u(JSON.stringify(header))}.${b64u(JSON.stringify(claims))}`;
    const sig = kind === "ec" ? sign("sha256", Buffer.from(input), { key: pair.privateKey, dsaEncoding: "ieee-p1363" }) : sign(useAlg === "PS256" ? "sha256" : "sha256", Buffer.from(input), useAlg === "PS256" ? { key: pair.privateKey, padding: 6 /* RSA_PKCS1_PSS_PADDING */, saltLength: 32 } : pair.privateKey);
    return `${input}.${b64u(sig)}`;
  };
  return {
    kind, alg, kid, jwk, thumbprint, jwks: { keys: [{ ...jwk, kid }] },
    assertion: (clientId, aud = TOKEN_URL, over = {}) => { const now = Math.floor(Date.now() / 1000); return signJwt({ alg, typ: "JWT", kid }, { iss: clientId, sub: clientId, aud, jti: randomBytes(8).toString("hex"), iat: now, exp: now + 120, ...over }); },
    dpop: (method, url, { token, jti, iat, htm, over, headerOver } = {}) => signJwt({ typ: "dpop+jwt", alg, jwk, ...headerOver }, { htm: htm ?? method, htu: url, jti: jti ?? randomBytes(8).toString("hex"), iat: iat ?? Math.floor(Date.now() / 1000), ...(token ? { ath: sha256b64u(token) } : {}), ...over }),
  };
}
const form = (o) => new URLSearchParams(o).toString();
const token = (body, { basic, dpop, bearer } = {}) =>
  call(W, "/api/auth/oauth2/token", { method: "POST", raw: form(body), headers: { "content-type": "application/x-www-form-urlencoded", ...(basic ? { authorization: `Basic ${Buffer.from(basic).toString("base64")}` } : {}), ...(dpop ? { dpop } : {}) } });
const register = (body, bearer = ws.owner.token) => call(W, "/api/auth/oauth2/register", { method: "POST", body, bearer });
const basicOf = (id, secret) => `${encodeURIComponent(id)}:${encodeURIComponent(secret)}`;
const err = (r) => `${r.status} ${r.json?.error}: ${r.json?.error_description}`;

// The platform administrator who can grant a machine client its scopes (the rewrite's operator route).
let admin = null;
if (!REFERENCE) {
  let r = await call(W, "/api/auth/sign-in/email", { method: "POST", body: { email: ADMIN_EMAIL, password: PW } });
  if (!r.json?.token) r = await call(W, "/api/auth/sign-up/email", { method: "POST", body: { name: "Platform Admin", email: ADMIN_EMAIL, password: PW } });
  if (r.json?.token) {
    const probe = await call(A, "/v1/admin/overview?limit=1", { bearer: r.json.token });
    if (probe.status === 200) admin = r.json.token;
  }
  if (!admin) console.log(`note: ${ADMIN_EMAIL} is not a platform admin here: the client_credentials grant checks are skipped`);
}
const grant = async (clientId, scopes) => (await call(A, `/v1/admin/oauth-clients/${clientId}/client-credentials-scopes`, { method: "PUT", bearer: admin, body: { scopes } })).status === 200;

async function codeFlow(clientId, { scope = "mcp:read mcp:write offline_access", extra = "", user = ws.owner } = {}) {
  const verifier = b64u(randomBytes(32)), challenge = sha256b64u(verifier);
  const url = `/api/auth/oauth2/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(REDIRECT)}&scope=${encodeURIComponent(scope)}&state=st&code_challenge=${challenge}&code_challenge_method=S256&resource=${encodeURIComponent(RESOURCE)}${extra}`;
  const authorize = await call(W, url, { bearer: user.token });
  const location = authorize.headers.get("location") ?? "";
  if (!location.includes("/mcp/consent")) return { verifier, location, code: new URL(location, "http://x").searchParams.get("code") ?? undefined };   // already consented: the code is in the redirect
  const consent = await call(W, "/api/auth/oauth2/consent", { method: "POST", bearer: user.token, body: { accept: true, scope, oauth_query: location.slice(location.indexOf("?") + 1) } });
  return { verifier, location: consent.json?.url ?? "", code: new URL(consent.json?.url ?? "http://x/").searchParams.get("code") };
}
const codeForm = (clientId, f) => ({ grant_type: "authorization_code", code: f.code, redirect_uri: REDIRECT, client_id: clientId, code_verifier: f.verifier, resource: RESOURCE });
const claims = (jwt) => JSON.parse(Buffer.from(jwt.split(".")[1], "base64url").toString());

// ---------------------------------------------------------------- discovery and registration

await s.t("discovery lists the extra grant, the signed-assertion method and the DPoP algorithms", async () => {
  const d = (await call(A, "/.well-known/oauth-authorization-server")).json;
  return (d.grant_types_supported.includes("client_credentials") && d.token_endpoint_auth_methods_supported.includes("private_key_jwt")
    && d.introspection_endpoint_auth_methods_supported.includes("private_key_jwt") && d.revocation_endpoint_auth_methods_supported.includes("private_key_jwt")
    && d.token_endpoint_auth_signing_alg_values_supported.includes("ES256") && d.dpop_signing_alg_values_supported.includes("ES256")) || JSON.stringify(d).slice(0, 400);
});
await s.t("only a signed-in person may register a client that acts as itself", async () => {
  const anon = await call(W, "/api/auth/oauth2/register", { method: "POST", body: { client_name: "m", token_endpoint_auth_method: "client_secret_basic", grant_types: ["client_credentials"] } });
  const ok = await register({ client_name: "m", token_endpoint_auth_method: "client_secret_basic", grant_types: ["client_credentials"] });
  return (anon.status === 400 && anon.json.error === "invalid_client_metadata" && anon.json.error_description === "client_credentials grant requires authenticated registration" && ok.status === 201 && ok.json.grant_types.join() === "client_credentials")
    || `${err(anon)} / ${ok.status} ${ok.text.slice(0, 120)}`;
});
await s.t("a private_key_jwt client needs keys, inline or by address, never both", async () => {
  const k = newKey();
  const none = await register({ client_name: "k", token_endpoint_auth_method: "private_key_jwt", grant_types: ["client_credentials"] });
  const both = await register({ client_name: "k", token_endpoint_auth_method: "private_key_jwt", grant_types: ["client_credentials"], jwks: k.jwks, jwks_uri: "https://example.test/jwks" });
  const ok = await register({ client_name: "k", token_endpoint_auth_method: "private_key_jwt", grant_types: ["client_credentials"], jwks: k.jwks });
  return (none.json.error_description === "private_key_jwt requires either jwks or jwks_uri" && both.json.error_description === "jwks and jwks_uri are mutually exclusive"
    && ok.status === 201 && ok.json.client_secret === undefined && ok.json.token_endpoint_auth_method === "private_key_jwt") || `${none.text.slice(0, 100)} ${both.text.slice(0, 100)} ${ok.text.slice(0, 100)}`;
});
await s.t("bad key sets are refused with the reference's reasons", async () => {
  const k = newKey();
  const withPrivate = { keys: [{ ...k.jwk, d: "AAAA" }] };
  const a = await register({ client_name: "k", token_endpoint_auth_method: "private_key_jwt", grant_types: ["client_credentials"], jwks: { keys: [] } });
  const b = await register({ client_name: "k", token_endpoint_auth_method: "private_key_jwt", grant_types: ["client_credentials"], jwks: withPrivate });
  return (a.json.error_description === "jwks must be an RFC 7517 JWK Set object with a non-empty keys array" && b.json.error_description === "jwks must contain only public asymmetric keys") || `${a.text} ${b.text}`;
});
await s.t("dpop_bound_access_tokens must be a boolean", async () => {
  const r = await register({ client_name: "d", redirect_uris: [REDIRECT], dpop_bound_access_tokens: "yes" });
  return (r.status === 400 && r.json.error_description === "dpop_bound_access_tokens must be a boolean") || err(r);
});

// ---------------------------------------------------------------- client_credentials

const machine = await register({ client_name: "Machine", token_endpoint_auth_method: "client_secret_basic", grant_types: ["client_credentials"] });
const m = { id: machine.json.client_id, secret: machine.json.client_secret };
await s.t("a client with no authorized client_credentials scopes is refused (as in the reference)", async () => {
  const r = await token({ grant_type: "client_credentials" }, { basic: basicOf(m.id, m.secret) });
  return (r.status === 400 && r.json.error === "unauthorized_client" && r.json.error_description === "client has no authorized client_credentials scopes") || err(r);
});
await s.t("a wrong secret is invalid_client", async () => {
  const r = await token({ grant_type: "client_credentials" }, { basic: basicOf(m.id, m.secret + "x") });
  return (r.status === 401 && r.json.error === "invalid_client") || err(r);
});
await s.t("a client may use only the grants it registered for", async () => {
  const r = await token({ grant_type: "refresh_token", refresh_token: "x" }, { basic: basicOf(m.id, m.secret) });
  return (r.status === 400 && r.json.error === "unauthorized_client" && r.json.error_description === "client is not authorized to use grant type refresh_token") || err(r);
});
await s.t("a public client cannot use client_credentials", async () => {
  const pub = await register({ client_name: "p", token_endpoint_auth_method: "none", grant_types: ["client_credentials"] });
  const r = await token({ grant_type: "client_credentials", client_id: pub.json.client_id });
  return (r.json.error === "unauthorized_client" && r.json.error_description === "public clients cannot use the client_credentials grant") || err(r);
});
if (admin) {
  await s.t("(rewrite) an administrator grants scopes; the token speaks for the client alone", async () => {
    const ok = await grant(m.id, ["mcp:read", "mcp:write"]);
    const r = await token({ grant_type: "client_credentials" }, { basic: basicOf(m.id, m.secret) });
    const c = r.status === 200 ? claims(r.json.access_token) : {};
    const mcp = await call(A, "/mcp/agent", { method: "POST", bearer: r.json.access_token, body: { jsonrpc: "2.0", id: 1, method: "ping" } });
    return (ok && r.status === 200 && r.json.token_type === "Bearer" && r.json.scope === "mcp:read mcp:write" && r.json.refresh_token === undefined && r.json.id_token === undefined
      && c.sub === m.id && c.azp === m.id && c.org_id === undefined && c.aud === RESOURCE && mcp.status === 401) || `${ok} ${err(r)} ${JSON.stringify(c)} ${mcp.status}`;
  });
  await s.t("(rewrite) fewer scopes are fine, more or a person's scopes are invalid_scope", async () => {
    await grant(m.id, ["mcp:read"]);
    const fewer = await token({ grant_type: "client_credentials", scope: "mcp:read" }, { basic: basicOf(m.id, m.secret) });
    const more = await token({ grant_type: "client_credentials", scope: "mcp:read mcp:write" }, { basic: basicOf(m.id, m.secret) });
    const person = await token({ grant_type: "client_credentials", scope: "openid" }, { basic: basicOf(m.id, m.secret) });
    return (fewer.status === 200 && more.json.error === "invalid_scope" && more.json.error_description === "The following scopes are invalid: mcp:write" && person.json.error === "invalid_scope") || `${err(fewer)} ${err(more)} ${err(person)}`;
  });
  await s.t("(rewrite) the client introspects its own machine token, another client sees it inactive", async () => {
    const r = await token({ grant_type: "client_credentials" }, { basic: basicOf(m.id, m.secret) });
    const own = await call(W, "/api/auth/oauth2/introspect", { method: "POST", raw: form({ token: r.json.access_token }), headers: { "content-type": "application/x-www-form-urlencoded", authorization: `Basic ${Buffer.from(basicOf(m.id, m.secret)).toString("base64")}` } });
    const other = await register({ client_name: "m2", token_endpoint_auth_method: "client_secret_basic", grant_types: ["client_credentials"] });
    const foreign = await call(W, "/api/auth/oauth2/introspect", { method: "POST", raw: form({ token: r.json.access_token }), headers: { "content-type": "application/x-www-form-urlencoded", authorization: `Basic ${Buffer.from(basicOf(other.json.client_id, other.json.client_secret)).toString("base64")}` } });
    return (own.json.active === true && own.json.client_id === m.id && foreign.json.active === false) || `${own.text.slice(0, 200)} ${foreign.text}`;
  });
  await s.t("(rewrite) only a platform administrator can grant scopes", async () => {
    const r = await call(A, `/v1/admin/oauth-clients/${m.id}/client-credentials-scopes`, { method: "PUT", bearer: ws.owner.token, body: { scopes: ["mcp:read"] } });
    return r.status === 403 || r.status;
  });
}

// ---------------------------------------------------------------- private_key_jwt

const pk = newKey("ec");
const pkClient = await register({ client_name: "Signer", token_endpoint_auth_method: "private_key_jwt", grant_types: ["client_credentials"], jwks: pk.jwks });
const pid = pkClient.json.client_id;
if (admin) await grant(pid, ["mcp:read"]);
const assertionForm = (assertion, extra = {}) => ({ grant_type: "client_credentials", client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: assertion, ...extra });
const status = admin ? 200 : 400;   // without scopes the grant itself is refused after authentication succeeded
await s.t("a signed assertion authenticates the client", async () => {
  const r = await token(assertionForm(pk.assertion(pid)));
  return admin ? (r.status === 200 && claims(r.json.access_token).sub === pid) || err(r) : (r.status === 400 && r.json.error === "unauthorized_client") || err(r);
});
await s.t("RS256 assertions work too", async () => {
  const rk = newKey("rsa");
  const c = await register({ client_name: "Rsa", token_endpoint_auth_method: "private_key_jwt", grant_types: ["client_credentials"], jwks: rk.jwks });
  if (admin) await grant(c.json.client_id, ["mcp:read"]);
  const r = await token(assertionForm(rk.assertion(c.json.client_id)));
  return r.status === status || err(r);
});
await s.t("an assertion works once", async () => {
  const a = pk.assertion(pid);
  const first = await token(assertionForm(a)), second = await token(assertionForm(a));
  return (first.status === status && second.status === 400 && second.json.error === "invalid_client" && second.json.error_description === "client assertion jti has already been used") || `${err(first)} / ${err(second)}`;
});
await s.t("a signature by another key is refused (401)", async () => {
  const other = newKey("ec");
  const r = await token(assertionForm(other.assertion(pid)));
  return (r.status === 401 && r.json.error === "invalid_client" && r.json.error_description === "client assertion signature verification failed") || err(r);
});
await s.t("claims are checked: expired, too far ahead, no jti, wrong audience", async () => {
  const now = Math.floor(Date.now() / 1000);
  const expired = await token(assertionForm(pk.assertion(pid, TOKEN_URL, { exp: now - 10 })));
  const far = await token(assertionForm(pk.assertion(pid, TOKEN_URL, { exp: now + 3600 })));
  const noJti = await token(assertionForm(pk.assertion(pid, TOKEN_URL, { jti: undefined })));
  const aud = await token(assertionForm(pk.assertion(pid, "https://elsewhere.example.test/token")));
  return (expired.json.error_description === "client assertion has expired" && far.json.error_description === "client assertion exp is too far in the future (max 300s)"
    && noJti.json.error_description === "client assertion must include jti claim" && aud.status === 401) || `${err(expired)} | ${err(far)} | ${err(noJti)} | ${err(aud)}`;
});
await s.t("one way of authenticating per request, and the registered method must be used", async () => {
  const both = await token(assertionForm(pk.assertion(pid)), { basic: basicOf(pid, "secret") });
  const secretFlow = await token({ grant_type: "client_credentials", client_id: pid, client_secret: "guess" });
  const wrongType = await token(assertionForm(pk.assertion(pid), { client_assertion_type: "urn:other" }));
  return (both.json.error === "invalid_request" && both.json.error_description === "A request must use only one client authentication method"
    && secretFlow.json.error_description === "client registered for private_key_jwt must use client_assertion" && wrongType.json.error_description === "unsupported client_assertion_type") || `${err(both)} | ${err(secretFlow)} | ${err(wrongType)}`;
});
await s.t("unsupported assertion algorithms are named", async () => {
  const none = `${b64u(JSON.stringify({ alg: "none" }))}.${b64u(JSON.stringify({ iss: pid, sub: pid }))}.AAAA`;
  const r = await token(assertionForm(none));
  return (r.json.error_description === "unsupported assertion signing algorithm: none") || err(r);
});
await s.t("the same assertion authentication works at introspection", async () => {
  const r = await call(W, "/api/auth/oauth2/introspect", { method: "POST", raw: form({ token: "not-a-token", client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: pk.assertion(pid, `${W}/api/auth/oauth2/introspect`) }), headers: { "content-type": "application/x-www-form-urlencoded" } });
  return (r.status === 200 && r.json.active === false) || `${r.status} ${r.text.slice(0, 160)}`;
});

// ---------------------------------------------------------------- DPoP

const dk = newKey("ec");
async function publicClient(extra = {}) {
  const r = await register({ client_name: "Public", redirect_uris: [REDIRECT], token_endpoint_auth_method: "none", ...extra });
  return r.json.client_id;
}
const pubId = await publicClient();
let bound;
await s.t("a proof binds the access token and the refresh token to its key", async () => {
  const f = await codeFlow(pubId);
  const r = await token(codeForm(pubId, f), { dpop: dk.dpop("POST", TOKEN_URL) });
  bound = r.json;
  const c = r.status === 200 ? claims(r.json.access_token) : {};
  return (r.status === 200 && r.json.token_type === "DPoP" && c.cnf?.jkt === dk.thumbprint && typeof r.json.refresh_token === "string") || `${err(r)} ${JSON.stringify(c)}`;
});
await s.t("a plain token request still gives a bearer token", async () => {
  const f = await codeFlow(pubId);
  const r = await token(codeForm(pubId, f));
  return (r.status === 200 && r.json.token_type === "Bearer" && claims(r.json.access_token).cnf === undefined) || err(r);
});
await s.t("bad proofs are invalid_dpop_proof with the reference's reasons, and a proof works once", async () => {
  const f = async () => codeForm(pubId, await codeFlow(pubId));
  const wrongMethod = await token(await f(), { dpop: dk.dpop("GET", TOKEN_URL) });
  const wrongUrl = await token(await f(), { dpop: dk.dpop("POST", `${W}/api/auth/oauth2/revoke`) });
  const old = await token(await f(), { dpop: dk.dpop("POST", TOKEN_URL, { iat: Math.floor(Date.now() / 1000) - 600 }) });
  const wrongTyp = await token(await f(), { dpop: dk.dpop("POST", TOKEN_URL, { headerOver: { typ: "JWT" } }) });
  const proof = dk.dpop("POST", TOKEN_URL);
  const ok = await token(await f(), { dpop: proof });
  const replay = await token(await f(), { dpop: proof });
  return (wrongMethod.json.error === "invalid_dpop_proof" && wrongMethod.json.error_description === "DPoP proof htm does not match the request method"
    && wrongUrl.json.error_description === "DPoP proof htu does not match the request URL" && old.json.error_description === "DPoP proof iat is outside the accepted window"
    && wrongTyp.json.error_description === "DPoP proof typ must be \"dpop+jwt\"" && ok.status === 200 && replay.json.error_description === "DPoP proof jti has already been used")
    || [wrongMethod, wrongUrl, old, wrongTyp, ok, replay].map(err).join(" | ");
});
await s.t("a code requested with dpop_jkt can be exchanged only with that key, and is not spent by a refusal", async () => {
  const other = newKey("ec");
  const f = await codeFlow(pubId, { extra: `&dpop_jkt=${dk.thumbprint}` });
  const none = await token(codeForm(pubId, f)), wrong = await token(codeForm(pubId, f), { dpop: other.dpop("POST", TOKEN_URL) }), ok = await token(codeForm(pubId, f), { dpop: dk.dpop("POST", TOKEN_URL) });
  return (none.json.error_description === "DPoP proof header is required" && wrong.json.error_description === "DPoP proof key does not match the bound token" && ok.status === 200 && ok.json.token_type === "DPoP") || `${err(none)} | ${err(wrong)} | ${err(ok)}`;
});
await s.t("a client that wants bound tokens must send a proof", async () => {
  const id = await publicClient({ dpop_bound_access_tokens: true });
  const f = await codeFlow(id);
  const without = await token(codeForm(id, f)), withProof = await token(codeForm(id, f), { dpop: dk.dpop("POST", TOKEN_URL) });
  return (without.json.error === "invalid_dpop_proof" && withProof.json.token_type === "DPoP") || `${err(without)} | ${err(withProof)}`;
});
await s.t("a bound refresh token needs a proof by the same key and rotates bound", async () => {
  const other = newKey("ec");
  const refreshForm = (t) => ({ grant_type: "refresh_token", refresh_token: t, client_id: pubId, resource: RESOURCE });
  const none = await token(refreshForm(bound.refresh_token)), wrong = await token(refreshForm(bound.refresh_token), { dpop: other.dpop("POST", TOKEN_URL) });
  const ok = await token(refreshForm(bound.refresh_token), { dpop: dk.dpop("POST", TOKEN_URL) });
  const again = ok.status === 200 ? await token(refreshForm(ok.json.refresh_token)) : null;
  return (none.json.error_description === "DPoP proof header is required" && wrong.json.error_description === "DPoP proof key does not match the bound token" && ok.status === 200 && ok.json.token_type === "DPoP"
    && again?.json.error === "invalid_dpop_proof") || `${err(none)} | ${err(wrong)} | ${err(ok)} | ${again && err(again)}`;
});
await s.t("a bound token works at the MCP endpoint only with the DPoP scheme and a proof for it", async () => {
  const bearer = await call(A, "/mcp/agent", { method: "POST", bearer: bound.access_token, body: { jsonrpc: "2.0", id: 1, method: "ping" } });
  const dpopCall = (proof, scheme = "DPoP") => call(A, "/mcp/agent", { method: "POST", headers: { authorization: `${scheme} ${bound.access_token}`, ...(proof ? { dpop: proof } : {}) }, body: { jsonrpc: "2.0", id: 1, method: "ping" } });
  const other = newKey("ec");
  const noProof = await dpopCall(null);
  const wrongKey = await dpopCall(other.dpop("POST", RESOURCE, { token: bound.access_token }));
  const wrongAth = await dpopCall(dk.dpop("POST", RESOURCE, { token: "another.token" }));
  const proof = dk.dpop("POST", RESOURCE, { token: bound.access_token });
  const ok = await dpopCall(proof), replay = await dpopCall(proof);
  return (bearer.status === 401 && /^DPoP error="invalid_token"/.test(bearer.headers.get("www-authenticate") ?? "") && noProof.status === 401 && wrongKey.status === 401 && wrongAth.status === 401
    && ok.status === 200 && replay.status === 401) || [bearer, noProof, wrongKey, wrongAth, ok, replay].map((r) => r.status).join() + " " + bearer.headers.get("www-authenticate");
});
await s.t("a token that is not bound cannot use the DPoP scheme", async () => {
  const f = await codeFlow(pubId);
  const plain = await token(codeForm(pubId, f));
  const r = await call(A, "/mcp/agent", { method: "POST", headers: { authorization: `DPoP ${plain.json.access_token}`, dpop: dk.dpop("POST", RESOURCE, { token: plain.json.access_token }) }, body: { jsonrpc: "2.0", id: 1, method: "ping" } });
  const ok = await call(A, "/mcp/agent", { method: "POST", bearer: plain.json.access_token, body: { jsonrpc: "2.0", id: 1, method: "ping" } });
  return (r.status === 401 && ok.status === 200) || `${r.status} ${ok.status}`;
});
await s.t("introspection reports the binding", async () => {
  const conf = await register({ client_name: "Confidential", redirect_uris: [REDIRECT], token_endpoint_auth_method: "client_secret_basic" });
  const cid = conf.json.client_id, secret = conf.json.client_secret;
  const f = await codeFlow(cid);
  const body = codeForm(cid, f); delete body.client_id;
  const t = await token(body, { basic: basicOf(cid, secret), dpop: dk.dpop("POST", TOKEN_URL) });
  const i = await call(W, "/api/auth/oauth2/introspect", { method: "POST", raw: form({ token: t.json.access_token }), headers: { "content-type": "application/x-www-form-urlencoded", authorization: `Basic ${Buffer.from(basicOf(cid, secret)).toString("base64")}` } });
  return (i.json.active === true && i.json.token_type === "DPoP" && i.json.cnf?.jkt === dk.thumbprint) || `${err(t)} ${i.text.slice(0, 200)}`;
});

s.done();
