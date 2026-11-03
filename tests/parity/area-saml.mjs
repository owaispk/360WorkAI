// SAML 2.0 sign-in contract test, with a local fake identity provider (fake-saml-idp.cjs: its own key and certificate, real signatures, bad responses on demand).
//   W=http://localhost:5290 A=http://localhost:5190 node area-saml.mjs         # the rewrite
//   node area-saml.mjs                                                         # a reference Den (web :3005, api :8790), see below
//
// Start the rewrite for it (Development, so a loopback identity provider counts as a proven domain, as the reference's dev mode does):
//   export WORKAI360_API_URL=http://localhost:5190 WORKAI360_WEB_URL=http://localhost:5290 WORKAI360_RUN_DIR=/tmp/workai-saml-run
//   export ConnectionStrings__Default="Data Source=/tmp/workai-saml.db"; rm -f /tmp/workai-saml.db*; scripts/dev.sh start
// The reference could not be started where this was written, so this script has been run against the rewrite only. Checks that name behavior this build
// adds (the same-browser last step, `binding`, the POST-binding page) are marked "(rewrite)"; set REFERENCE=1 to skip them.
import { createRequire } from "node:module";
import { call, suite, PW, W, A } from "./lib.mjs";
const { startFakeSamlIdp, readForm } = createRequire(import.meta.url)("./fake-saml-idp.cjs");

const REFERENCE = process.env.REFERENCE === "1";
const s = suite("saml");
const idp = await startFakeSamlIdp({ host: process.env.IDP_HOST || "127.0.0.1" });
const domain = `corp-${Date.now()}.test`;
// The workspace's owner has an address on the claimed domain: the administrator's test must be signed in by the same account that started it.
const ownerEmail = `owner.${Math.random().toString(36).slice(2, 8)}@${domain}`;
const signUp = await call(W, "/api/auth/sign-up/email", { method: "POST", body: { name: "Owner Person", email: ownerEmail, password: PW } });
const owner0 = { name: "Owner Person", email: ownerEmail, token: signUp.json?.token, userId: signUp.json?.user?.id };
const created = await call(A, "/v1/org", { method: "POST", bearer: owner0.token, body: { name: "SAML Parity" } });
const ws = { owner: owner0, orgId: created.json?.organization?.id };
ws.api = (u, method, path, body, extra = {}) => call(A, path, { method, bearer: u.token, headers: { "x-openwork-org-id": ws.orgId, ...(extra.headers ?? {}) }, body, ...extra });
ws.join = async (name, role = "member") => {
  const email = `${name.toLowerCase().replace(/\s+/g, ".")}.${Math.random().toString(36).slice(2, 8)}@example.com`;
  const r = await call(W, "/api/auth/sign-up/email", { method: "POST", body: { name, email, password: PW } });
  const u = { name, email, token: r.json.token, userId: r.json.user.id };
  const inv = await ws.api(ws.owner, "POST", "/v1/invitations", { email, role });
  await call(A, "/v1/orgs/invitations/accept", { method: "POST", bearer: u.token, body: { id: inv.json.invitationId } });
  return u;
};
const orgInfo = await ws.api(ws.owner, "GET", "/v1/org");
const slug = orgInfo.json.organization.slug;
const signInRef = await fetch(W + "/api/auth/sign-in/email", { method: "POST", headers: { "content-type": "application/json", origin: W }, body: JSON.stringify({ email: ws.owner.email, password: PW }) });
const ownerCookie = signInRef.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
const owner = (method, path, body) => ws.api(ws.owner, method, path, body, { headers: { cookie: ownerCookie } });
const member = await ws.join("Plain Member");
const reg = (extra = {}) => owner("POST", "/v1/sso/saml", { issuer: idp.entityId, domain, entryPoint: idp.ssoUrl, cert: idp.certPem, ...extra });
const personEmail = (local) => `${local}.${Math.random().toString(36).slice(2, 8)}@${domain}`;
const msg = (r) => r.json?.details?.[0]?.message ?? r.json?.message;

/** A browser's cookie jar: enough to carry the sign-in's binding cookie and the session. */
function browser() {
  const jar = new Map();
  return {
    jar,
    async f(url, init = {}) {
      const headers = { ...(init.headers ?? {}) };
      if (jar.size) headers.cookie = [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
      const r = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(30000), ...init, headers });
      for (const sc of r.headers.getSetCookie()) {
        const [pair] = sc.split(";"); const i = pair.indexOf("="); const k = pair.slice(0, i), v = pair.slice(i + 1);
        if (/max-age=0|expires=thu, 01 jan 1970/i.test(sc) || v === "") jar.delete(k); else jar.set(k, v);
      }
      return r;
    },
    hasSession: () => [...jar.keys()].some((k) => k.endsWith("session_token")),
  };
}
const q = (location, name) => new URL(location, W).searchParams.get(name);
const toWeb = (location) => new URL(location, W).toString();

/** The identity provider's page for a request, then the browser posting its answer to the ACS. Returns the ACS answer. With the POST binding the address first serves a page that posts the request. */
async function viaIdp(b, startUrl) {
  let url = startUrl, page;
  if (startUrl.includes("/sp/login/")) {
    const submit = readForm(await (await b.f(startUrl)).text());
    page = await fetch(submit.action, { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(submit.fields) });
  } else page = await fetch(url, { redirect: "manual" });
  const html = await page.text();
  const { action, fields } = readForm(html);
  if (!action) throw new Error(`the identity provider did not answer with a form: ${page.status} ${html.slice(0, 120)}`);
  return b.f(action, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(fields) });
}

/** The whole sign-in: start, identity provider, ACS, the same-site last step. */
async function signIn(b, { body = { organizationSlug: slug, callbackURL: "/dashboard" } } = {}) {
  const start = await b.f(A + "/api/auth/sign-in/sso", { method: "POST", headers: { "content-type": "application/json", origin: W }, body: JSON.stringify(body) });
  const started = await start.json();
  if (!started.url) return { start, started };
  const acs = await viaIdp(b, started.url);
  let final = null;
  if (acs.status === 303) final = await b.f(toWeb(acs.headers.get("location")));
  return { start, started, acs, final };
}
const me = async (b) => { const r = await b.f(A + "/v1/me"); return r.status === 200 ? (await r.json()).user.email : null; };
const loggedInAs = async (b, email) => (await me(b)) === email;

// ---------------------------------------------------------------- registration

await s.t("nothing configured: GET /v1/sso and the metadata route", async () => {
  const r = await owner("GET", "/v1/sso"), md = await owner("GET", "/v1/sso/metadata");
  return (r.status === 200 && r.json.connection === null && md.status === 404 && md.json.error === "organization_not_found") || `${r.text} ${md.status}`;
});
await s.t("saving validates the body in zod wording", async () => {
  const empty = await owner("POST", "/v1/sso/saml", {});
  const bad = await owner("POST", "/v1/sso/saml", { issuer: "x", domain: "", entryPoint: "nope", cert: "", audience: "no" });
  return (empty.status === 400 && empty.json.error === "invalid_request" && empty.json.details.map((d) => d.path[0]).join() === "issuer,domain,entryPoint,cert"
    && bad.json.details.map((d) => d.message).slice(0, 4).join("|") === "Invalid URL|Too small: expected string to have >=1 characters|Invalid URL|Too small: expected string to have >=1 characters"
    && bad.json.details.at(-1).path[0] === "audience") || JSON.stringify([empty.json, bad.json]).slice(0, 300);
});
await s.t("permissions: a plain member cannot save or read the metadata, nobody signed in is 401", async () => {
  const a = await ws.api(member, "POST", "/v1/sso/saml", {}), b = await ws.api(member, "GET", "/v1/sso/metadata"), anon = await call(A, "/v1/sso/saml", { method: "POST", body: {} });
  return (a.status === 403 && a.json.requiredPermission === "sso.manage" && b.json.requiredPermission === "sso.view" && anon.status === 401 && anon.json.error === "unauthorized") || `${a.status} ${b.status} ${anon.status}`;
});

let connection, token;
await s.t("saving SAML: 201, disabled, untested, the service provider addresses, no oidc", async () => {
  const r = await reg();
  connection = r.json?.connection; token = r.json?.domainVerificationToken;
  const c = connection;
  return (r.status === 201 && c.kind === "saml" && c.status === "disabled" && c.testStatus === "untested" && c.domain === domain && c.issuer === idp.entityId && c.oidc === null
    && c.saml.entryPoint === idp.ssoUrl && typeof c.saml.audience === "string" && c.saml.wantAssertionsSigned === true
    && c.providerId === `openwork-sso-${ws.orgId}` && c.acsUrl.endsWith(`/api/auth/sso/saml2/sp/acs/${c.providerId}`)
    && c.metadataUrl.endsWith(`/api/auth/sso/saml2/sp/metadata?providerId=${c.providerId}`) && c.signInPath.startsWith("/sso/")
    && c.domainVerificationHost === `_better-auth-token-${c.providerId}`) || r.text.slice(0, 400);
});
await s.t("the private certificate material is not echoed back and the read model matches", async () => {
  const r = await owner("GET", "/v1/sso");
  return (!r.text.includes("BEGIN CERTIFICATE") && r.json.connection.id === connection.id && r.json.connection.saml.entryPoint === idp.ssoUrl) || r.text.slice(0, 200);
});
await s.t("service provider metadata: XML with the entity id, the ACS address and signed assertions wanted", async () => {
  const r = await ws.api(ws.owner, "GET", "/v1/sso/metadata", undefined, { headers: { cookie: ownerCookie } });
  const pub = await call(W, new URL(connection.metadataUrl).pathname + new URL(connection.metadataUrl).search);
  return (r.status === 200 && /xml/.test(r.headers.get("content-type")) && r.text.includes(`entityID="${connection.saml.audience}"`) && r.text.includes(connection.acsUrl) && /WantAssertionsSigned="true"/.test(r.text)
    && pub.status === 200 && pub.text.includes(connection.acsUrl)) || `${r.status} ${r.text.slice(0, 200)} ${pub.status}`;
});
await s.t("metadata: format is validated, an unknown provider is 404", async () => {
  const bad = await owner("GET", "/v1/sso/metadata?format=yaml"), unknown = await call(W, "/api/auth/sso/saml2/sp/metadata?providerId=nope");
  return (bad.status === 400 && bad.json.error === "invalid_request" && unknown.status === 404) || `${bad.status} ${unknown.status}`;
});

const proven = connection?.domainVerified === true;
if (!proven) console.log("note: the domain is not proven (a loopback identity provider only counts in Development): the sign-in checks are skipped");

// ---------------------------------------------------------------- the administrator's test and enabling

async function runTest(b, identity) {
  idp.identity = identity;
  const made = await owner("POST", "/v1/sso/test", {});
  const start = await b.f(A + `/v1/sso/test/${made.json.intentId}/start`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${ws.owner.token}`, "x-openwork-org-id": ws.orgId, origin: W }, body: "{}" });
  const url = (await start.json()).url;
  const acs = await viaIdp(b, url);
  const final = acs.status === 303 ? await b.f(toWeb(acs.headers.get("location"))) : acs;
  return { made, final };
}
if (proven) {
  await s.t("a test by someone else fails, and enabling is refused", async () => {
    const { final } = await runTest(browser(), { nameId: personEmail("not.admin"), email: personEmail("not.admin"), name: "Not Admin", nameIdFormat: undefined });
    const c = (await owner("GET", "/v1/sso")).json.connection, en = await owner("POST", "/v1/sso/enable", {});
    return (final.status === 302 && c.testStatus === "failed" && en.status === 409) || `${final.status} ${c.testStatus} ${en.status}`;
  });
  await s.t("a test by the administrator passes and signs nobody in", async () => {
    const b = browser();
    const { final } = await runTest(b, { nameId: ws.owner.email, email: ws.owner.email, name: "Owner Person" });
    const c = (await owner("GET", "/v1/sso")).json.connection;
    return (final.status === 302 && final.headers.get("location").includes("/sso/test/complete") && c.testStatus === "succeeded" && !b.hasSession()) || `${final.status} ${c.testStatus}`;
  });
  await s.t("enabling works after a good test", async () => (await owner("POST", "/v1/sso/enable", {})).status === 204);

  // ------------------------------------------------------------ signing in
  await s.t("a new person signs in through SAML and joins as a member", async () => {
    const email = personEmail("new.person");
    idp.identity = { nameId: email, email, name: "New Person", nameIdFormat: undefined };
    const b = browser();
    const { acs, final } = await signIn(b);
    const orgNow = await owner("GET", "/v1/org");
    const joined = orgNow.json.members.some((m) => m.user?.email === email && m.role === "member");
    return (acs.status === 303 && acs.headers.get("location").includes("/api/auth/sso/saml2/sp/continue/") && final.status === 302 && q(final.headers.get("location"), "error") === null
      && b.hasSession() && (await loggedInAs(b, email)) && joined) || `${acs?.status} ${final?.status} ${final?.headers.get("location")}`;
  });
  await s.t("the ACS post alone signs nobody in (rewrite)", async () => {
    if (REFERENCE) return true;
    const email = personEmail("early");
    idp.identity = { nameId: email, email, name: "Early", nameIdFormat: undefined };
    const b = browser();
    const start = await b.f(A + "/api/auth/sign-in/sso", { method: "POST", headers: { "content-type": "application/json", origin: W }, body: JSON.stringify({ organizationSlug: slug, callbackURL: "/dashboard" }) });
    const acs = await viaIdp(b, (await start.json()).url);
    return (acs.status === 303 && !b.hasSession() && (await me(b)) === null) || `${acs.status} ${b.hasSession()}`;
  });
  await s.t("a returning person is recognised by the name id, not the email", async () => {
    const first = personEmail("stable"), later = personEmail("renamed");
    const b1 = browser();
    idp.identity = { nameId: "stable-subject-" + first, email: first, name: "Stable", nameIdFormat: undefined };
    await signIn(b1);
    const b2 = browser();
    idp.identity = { nameId: "stable-subject-" + first, email: later, name: "Stable", nameIdFormat: undefined };
    await signIn(b2);
    return ((await loggedInAs(b2, first)) && (await me(b2)) !== later) || (await me(b2));
  });
  await s.t("a response with a comment inside the name cannot change who signs in", async () => {
    const email = personEmail("comment.person");
    idp.identity = { nameId: email, email, name: "Comment", nameIdFormat: EMAIL_FORMAT_VALUE() };
    idp.fault = "comment";
    const b = browser();
    const { final } = await signIn(b);
    idp.fault = "";
    return (final?.status === 302 && (await loggedInAs(b, email))) || `${final?.status} ${await me(b)}`;
  });
  await s.t("an address outside the verified domain signs nobody in", async () => {
    idp.identity = { nameId: "someone@elsewhere.test", email: "someone@elsewhere.test", name: "Else", nameIdFormat: undefined };
    const b = browser();
    const { final } = await signIn(b);
    return (final.status === 302 && q(final.headers.get("location"), "error") === "email_outside_sso_domain" && !b.hasSession()) || final.headers.get("location");
  });
  await s.t("the sign-in start refuses a return address on another site", async () => {
    const r = await call(A, "/api/auth/sign-in/sso", { method: "POST", body: { organizationSlug: slug, callbackURL: "https://evil.example.test/" } });
    return (r.status === 403 && r.json.code === "INVALID_CALLBACK_URL") || r.text;
  });

  // ------------------------------------------------------------ bad responses
  const bad = {
    unsigned: "signed by the identity provider", badsig: "could not be verified", tamper: "could not be verified", expired: "expired", future: "not yet valid", audience: "audience",
    recipient: "Recipient", destination: "Destination", sha1: "deprecated", wrap: "assertions", "two-assertions": "assertions", failed: "did not authenticate", "wrong-issuer": "different identity provider",
    "wrong-irt": "request", "no-authn": "AuthnStatement", doctype: "DTD", "response-only": "signed",
  };
  for (const [fault, word] of Object.entries(bad)) {
    await s.t(`a bad response (${fault}) is refused with a reason and nobody is signed in`, async () => {
      const email = personEmail("victim." + fault.replace(/[^a-z]/g, ""));
      idp.identity = { nameId: email, email, name: "Victim", nameIdFormat: undefined };
      idp.fault = fault;
      const b = browser();
      const { acs } = await signIn(b);
      idp.fault = "";
      const location = acs.headers.get("location") ?? "";
      const error = q(location, "error"), description = q(location, "error_description") ?? "";
      return (acs.status === 302 && error !== null && description.toLowerCase().includes(word.toLowerCase()) && !b.hasSession() && (await me(b)) === null) || `${acs.status} ${location}`;
    });
  }
  await s.t("a failed response does not spend the request: the right one still works (rewrite)", async () => {
    if (REFERENCE) return true;
    const email = personEmail("retry");
    idp.identity = { nameId: email, email, name: "Retry", nameIdFormat: undefined };
    const b = browser();
    const start = await b.f(A + "/api/auth/sign-in/sso", { method: "POST", headers: { "content-type": "application/json", origin: W }, body: JSON.stringify({ organizationSlug: slug, callbackURL: "/dashboard" }) });
    const url = (await start.json()).url;
    idp.fault = "badsig";
    const first = await viaIdp(b, url);
    idp.fault = "";
    const second = await viaIdp(b, url);
    const final = await b.f(toWeb(second.headers.get("location")));
    return (first.status === 302 && second.status === 303 && final.status === 302 && (await loggedInAs(b, email))) || `${first.status} ${second.status} ${final.status}`;
  });

  // ------------------------------------------------------------ replay and unsolicited responses
  await s.t("a replayed response is refused", async () => {
    const email = personEmail("replay");
    idp.identity = { nameId: email, email, name: "Replay", nameIdFormat: undefined };
    const b = browser();
    const { started } = await signIn(b);
    const sent = idp.responses.at(-1);
    const again = await fetch(sent.acs, { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ SAMLResponse: sent.response, RelayState: sent.relayState }) });
    return (started.url && again.status === 302 && q(again.headers.get("location"), "error") !== null && !(await loggedInAs(browser(), email))) || `${again.status} ${again.headers.get("location")}`;
  });
  await s.t("an unsolicited response (IdP-initiated) signs in, and only once", async () => {
    const email = personEmail("idpinit");
    idp.identity = { nameId: email, email, name: "IdP Init", nameIdFormat: undefined };
    const audience = connection.saml.audience;
    const page = await fetch(`${idp.url}/initiate?acs=${encodeURIComponent(connection.acsUrl)}&audience=${encodeURIComponent(audience)}`);
    const { action, fields } = readForm(await page.text());
    const post = () => browser().f(action, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(fields) });
    const b = browser();
    const first = await b.f(action, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(fields) });
    const second = await post();
    return (first.status === 302 && first.headers.get("location").endsWith("/dashboard") && (await loggedInAs(b, email)) && q(second.headers.get("location"), "error") === "replay_detected") || `${first.status} ${first.headers.get("location")} ${second.headers.get("location")}`;
  });
  await s.t("the same response posted six times at once is accepted exactly once", async () => {
    const email = personEmail("race");
    idp.identity = { nameId: email, email, name: "Race", nameIdFormat: undefined };
    const page = await fetch(`${idp.url}/initiate?acs=${encodeURIComponent(connection.acsUrl)}&audience=${encodeURIComponent(connection.saml.audience)}`);
    const { action, fields } = readForm(await page.text());
    const results = await Promise.all(Array.from({ length: 6 }, () => fetch(action, { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(fields) })));
    const wins = results.filter((r) => r.headers.get("location")?.endsWith("/dashboard")).length;
    return (wins === 1 && results.filter((r) => q(r.headers.get("location") ?? "", "error") === "replay_detected").length === 5) || results.map((r) => `${r.status}`).join();
  });

  // ------------------------------------------------------------ the same browser (this build)
  await s.t("a response obtained in one browser cannot sign in another (rewrite)", async () => {
    if (REFERENCE) return true;
    const email = personEmail("csrf");
    idp.identity = { nameId: email, email, name: "Csrf", nameIdFormat: undefined };
    const attacker = browser(), victim = browser();
    const start = await attacker.f(A + "/api/auth/sign-in/sso", { method: "POST", headers: { "content-type": "application/json", origin: W }, body: JSON.stringify({ organizationSlug: slug, callbackURL: "/dashboard" }) });
    const url = (await start.json()).url;
    const acs = await viaIdp(browser(), url);                                    // the answer is posted from nowhere in particular
    const last = toWeb(acs.headers.get("location"));
    const landed = await victim.f(last);
    const real = await attacker.f(last);
    return (acs.status === 303 && q(landed.headers.get("location"), "error") === "state_mismatch" && !victim.hasSession() && real.status === 302 && attacker.hasSession()) || `${acs.status} ${landed.headers.get("location")} ${real.status}`;
  });

  // ------------------------------------------------------------ closed doors
  await s.t("members of the workspace cannot use a password while SAML is on", async () => {
    const r = await call(A, "/api/auth/sign-in/email", { method: "POST", body: { email: ws.owner.email, password: PW } });
    const o = await call(A, `/v1/auth/login-options?email=anyone@${domain}`);
    return (r.status === 403 && /managed by an organization/.test(r.text) && o.json.nextStep === "sso") || `${r.status} ${r.text.slice(0, 120)} ${o.text.slice(0, 100)}`;
  });
  await s.t("a disabled connection answers 403 sso_not_enabled at the ACS", async () => {
    await owner("POST", "/v1/sso/disable", {});
    const email = personEmail("off");
    idp.identity = { nameId: email, email, name: "Off", nameIdFormat: undefined };
    const page = await fetch(`${idp.url}/initiate?acs=${encodeURIComponent(connection.acsUrl)}&audience=${encodeURIComponent(connection.saml.audience)}`);
    const { action, fields } = readForm(await page.text());
    const r = await fetch(action, { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(fields) });
    const body = await r.json().catch(() => ({}));
    return (r.status === 403 && body.error === "sso_not_enabled") || `${r.status} ${JSON.stringify(body)}`;
  });
}

await s.t("the ACS answers 404 for an unknown provider and 400 for an empty post", async () => {
  const unknown = await fetch(W + "/api/auth/sso/saml2/sp/acs/nope", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "SAMLResponse=x" });
  const empty = await fetch(connection.acsUrl, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: "" });
  return (unknown.status === 404 && empty.status === 400) || `${unknown.status} ${empty.status}`;
});

// ---------------------------------------------------------------- the POST binding (this build)
if (!REFERENCE && proven) {
  await s.t("the POST binding: a page that submits the request, only to the browser that started it (rewrite)", async () => {
    await owner("POST", "/v1/sso/disable", {});
    const re = await reg({ binding: "post" });
    const b = browser();
    const { final } = await runTest(b, { nameId: ws.owner.email, email: ws.owner.email, name: "Owner Person" });
    const enabled = await owner("POST", "/v1/sso/enable", {});
    const start = await b.f(A + "/api/auth/sign-in/sso", { method: "POST", headers: { "content-type": "application/json", origin: W }, body: JSON.stringify({ organizationSlug: slug, callbackURL: "/dashboard" }) });
    const url = (await start.json()).url;
    const page = await b.f(url);
    const html = await page.text();
    const { action, fields } = readForm(html);
    const csp = page.headers.get("content-security-policy") ?? "";
    const stranger = await browser().f(url);
    // The identity provider reads the POST binding and answers.
    idp.identity = { nameId: personEmail("post.binding"), email: personEmail("post.binding"), name: "Post Binding", nameIdFormat: undefined };
    const acs = await viaIdp(b, url);
    const done = acs.status === 303 ? await b.f(toWeb(acs.headers.get("location"))) : acs;
    return (re.status === 201 && re.json.connection.saml.binding === "post" && final.status === 302 && enabled.status === 204 && url.includes("/sp/login/") && action === idp.ssoUrl && "SAMLRequest" in fields
      && /form-action http/.test(csp) && /script-src 'sha256-/.test(csp) && q(stranger.headers.get("location") ?? "", "error") === "state_mismatch" && done.status === 302 && b.hasSession())
      || `${re.status} ${final.status} ${enabled.status} ${url} ${action} ${csp} ${stranger.status} ${done.status}`;
  });
}

await s.t("deleting the connection answers 204 and leaves nothing", async () => {
  const d = await owner("DELETE", "/v1/sso"), g = await owner("GET", "/v1/sso");
  return (d.status === 204 && g.json.connection === null) || `${d.status} ${g.text}`;
});

await idp.close();
s.done();

function EMAIL_FORMAT_VALUE() { return "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"; }
