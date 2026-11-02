// Contract test for sign-in with Google and GitHub.
//
// The reference enables a provider only when its client id and secret are configured, and the reference Den here has none, so against it only
// the part that does not need a provider runs: request validation, the open-redirect guard, "provider not found", and that a callback without a
// valid state is sent to the error page. Against a rewrite started with the fake providers below, the whole flow runs (state, PKCE, nonce, account
// linking, error redirects). Which mode runs is decided by whether the target answers GET /api/auth/social-providers with providers.
//
//   node area-social.mjs                                                   # reference: web :3005, api :8790 (provider-free checks)
//   # rewrite, with fake providers on 127.0.0.1:5391 (this script starts the fakes; the rewrite must be told where they are):
//   eval "$(FAKE_SOCIAL_PORT=5391 node -e 'const {startFakeSocial}=require("./fake-social.cjs");startFakeSocial({port:5391}).then(p=>{for(const [k,v] of Object.entries(p.env()))console.log(`export ${k}=${v}`);p.close()})')"
//   scripts/dev.sh restart            # with those variables exported, then:
//   W=http://localhost:5290 A=http://localhost:5190 node area-social.mjs
import { createRequire } from "node:module";
import { randomBytes } from "node:crypto";
import { W, A, PW, suite, email } from "./lib.mjs";
const { startFakeSocial } = createRequire(import.meta.url)("./fake-social.cjs");

class Jar {
  c = new Map();
  absorb(res) { for (const sc of res.headers.getSetCookie?.() ?? []) { const [pair, ...attrs] = sc.split(";"); const i = pair.indexOf("="); const k = pair.slice(0, i).trim(), v = pair.slice(i + 1).trim(); if (v === "" || attrs.some((a) => /^\s*max-age=0/i.test(a))) this.c.delete(k); else this.c.set(k, v); } }
  header() { return [...this.c].map(([k, v]) => `${k}=${v}`).join("; "); }
  has(part) { return [...this.c.keys()].some((k) => k.includes(part)); }
}
async function call(base, path, { method = "GET", body, headers = {}, jar } = {}) {
  const h = { origin: W, ...headers };
  if (jar?.c.size) h.cookie = jar.header();
  let payload;
  if (body !== undefined) { h["content-type"] = "application/json"; payload = JSON.stringify(body); }
  const res = await fetch(base + path, { method, headers: h, body: payload, redirect: "manual", signal: AbortSignal.timeout(30000) });
  jar?.absorb(res);
  const text = await res.text(); let json = null; try { json = JSON.parse(text); } catch {}
  return { status: res.status, json, text, headers: res.headers };
}
const start = (jar, body) => call(W, "/api/auth/sign-in/social", { method: "POST", jar, body });

const s = suite("social");
const providers = await call(W, "/api/auth/social-providers");
const configured = providers.status === 200 && providers.json?.providers?.length === 2;

// ---------- provider-free behavior (the reference and a rewrite with no providers) ----------
await s.t("a body without a provider is a validation error", async () => {
  const r = await start(null, {}); return (r.status === 400 && r.json?.code === "VALIDATION_ERROR" && r.json?.message === "[body.provider] Invalid input") || `${r.status} ${r.text}`;
});
await s.t("an unknown provider: 404 PROVIDER_NOT_FOUND", async () => {
  const r = await start(null, { provider: "nope", callbackURL: `${W}/` }); return (r.status === 404 && r.json?.code === "PROVIDER_NOT_FOUND" && r.json?.message === "Provider not found") || `${r.status} ${r.text}`;
});
await s.t("the open-redirect guard answers before the provider is looked up (callbackURL on another site: 403 INVALID_CALLBACK_URL)", async () => {
  const r = await start(null, { provider: "google", callbackURL: "http://evil.example/" }); return (r.status === 403 && r.json?.code === "INVALID_CALLBACK_URL" && r.json?.message === "Invalid callbackURL") || `${r.status} ${r.text}`;
});
await s.t("the guard also refuses protocol-relative, userinfo and javascript: callbacks", async () => {
  for (const bad of ["//evil.example/x", `http://localhost@evil.example/`, "javascript:alert(1)", "https://evil.example.attacker/"]) {
    const r = await start(null, { provider: "google", callbackURL: bad });
    if (r.status !== 403) return `${bad} -> ${r.status} ${r.text}`;
  }
  return true;
});
await s.t("errorCallbackURL is guarded too (403 INVALID_ERROR_CALLBACK_URL or INVALID_CALLBACKURL-style code)", async () => {
  const r = await start(null, { provider: "google", callbackURL: `${W}/`, errorCallbackURL: "http://evil.example/e" }); return (r.status === 403 && /ERROR_CALLBACK/.test(r.json?.code ?? "")) || `${r.status} ${r.text}`;
});
await s.t("a callback without a usable state goes to the error page, never to a session", async () => {
  const r = await call(W, "/api/auth/callback/google?code=x&state=nope");
  return (r.status === 302 && new URL(r.headers.get("location"), W).pathname === "/connect/error" && /error=/.test(r.headers.get("location"))) || `${r.status} ${r.headers.get("location")}`;
});
await s.t("a callback from a provider that returns an error, with no known state, is also sent to the error page", async () => {
  const r = await call(W, "/api/auth/callback/github?error=access_denied&state=nope"); return (r.status === 302 && /\/connect\/error\?error=/.test(r.headers.get("location") ?? "")) || `${r.status} ${r.headers.get("location")}`;
});

if (!configured) {
  console.log("\n(no social providers configured on this target: the flow checks below were skipped)");
  s.done();
}

// ---------- the whole flow, against fake providers (rewrite) ----------
const fake = await startFakeSocial({ port: Number(process.env.FAKE_SOCIAL_PORT ?? 5391) });
const back = `${W}/dashboard`, errBack = `${W}/?social=1`, newBack = `${W}/organization`;

/** Runs a complete attempt: start -> provider authorize -> callback. Returns what the browser would end up with. */
async function signInWith(provider, { jar = new Jar(), body = {}, callbackJar } = {}) {
  const started = await start(jar, { provider, callbackURL: back, errorCallbackURL: errBack, newUserCallbackURL: newBack, ...body });
  if (started.status !== 200) return { started };
  const boundToBrowser = jar.has("social_state");
  const hop = await fetch(started.json.url, { redirect: "manual" });
  const cb = new URL(hop.headers.get("location"));
  const landed = await call(W, cb.pathname + cb.search, { jar: callbackJar ?? jar });
  return { jar: callbackJar ?? jar, started, boundToBrowser, authorizeUrl: new URL(started.json.url), callbackUrl: cb, landed, location: landed.headers.get("location") };
}
const sessionOf = async (jar) => { const r = await call(A, "/v1/me", { jar }); return r.status === 200 ? r.json : null; };
const errorOf = (loc) => { const u = new URL(loc, W); return { path: u.pathname, error: u.searchParams.get("error"), description: u.searchParams.get("error_description") }; };

await s.t("the providers endpoint lists exactly the configured providers", async () => providers.json.providers.join() === "google,github" || providers.text);
let g;
await s.t("google: starting answers {url, redirect:true} with a PKCE challenge, a nonce and a state, and binds the attempt to this browser with a cookie", async () => {
  fake.google = { ...fake.google, email: email("gsign"), sub: "g-" + randomBytes(4).toString("hex"), fault: "" };
  g = await signInWith("google");
  const u = g.authorizeUrl;
  return (g.started.json.redirect === true && u.origin === fake.url && u.searchParams.get("client_id") === "g-client" && u.searchParams.get("redirect_uri") === `${W}/api/auth/callback/google`
    && u.searchParams.get("code_challenge_method") === "S256" && u.searchParams.get("code_challenge")?.length >= 43 && u.searchParams.get("nonce")?.length >= 16 && u.searchParams.get("state")?.length >= 32
    && u.searchParams.get("scope") === "openid email profile" && g.boundToBrowser) || `${g.started.text} cookies=${[...g.jar.c.keys()]}`;
});
await s.t("google: the code is exchanged with the client secret and the PKCE verifier", async () => {
  const t = fake.tokenRequests.filter((x) => x.provider === "google").at(-1);
  return (t?.client_secret === "g-secret" && t.code_verifier?.length >= 43 && t.redirect_uri === `${W}/api/auth/callback/google`) || JSON.stringify(t);
});
await s.t("google: a new person lands on newUserCallbackURL, signed in, with the verified email, the name and no password to guess", async () => {
  const me = await sessionOf(g.jar);
  return (g.landed.status === 302 && g.location === newBack && g.jar.has("session_token") && me?.user?.email === fake.google.email && me.user.name === "Gee Person" && me.user.emailVerified === true) || `${g.landed.status} ${g.location} ${JSON.stringify(me)?.slice(0, 200)}`;
});
await s.t("google: the same account signing in again lands on callbackURL and is the same person", async () => {
  const again = await signInWith("google"); const me1 = await sessionOf(g.jar); const me2 = await sessionOf(again.jar);
  return (again.location === back && me2?.user?.id === me1?.user?.id) || `${again.location} ${me2?.user?.id} ${me1?.user?.id}`;
});
await s.t("google: a person is found by the provider's account id, not by the email it reports today", async () => {
  const sub = fake.google.sub; const first = await sessionOf(g.jar);
  fake.google = { ...fake.google, sub, email: email("changed") };
  const again = await signInWith("google"); const me = await sessionOf(again.jar);
  return (me?.user?.id === first?.user?.id) || JSON.stringify(me)?.slice(0, 200);
});
await s.t("the state works once: replaying the same callback is refused and signs nobody in", async () => {
  const r = await signInWith("google", {}); const replayJar = new Jar(); for (const [k, v] of r.jar.c) replayJar.c.set(k, v);
  const again = await call(W, r.callbackUrl.pathname + r.callbackUrl.search, { jar: replayJar });
  return (again.status === 302 && errorOf(again.headers.get("location")).error === "state_mismatch") || `${again.status} ${again.headers.get("location")}`;
});
await s.t("the state is bound to the browser that started it: another browser gets state_mismatch and does not spend it", async () => {
  fake.google = { ...fake.google, sub: "g-" + randomBytes(4).toString("hex"), email: email("bind") };
  const victim = new Jar();
  const started = await start(victim, { provider: "google", callbackURL: back });
  const hop = await fetch(started.json.url, { redirect: "manual" }); const cb = new URL(hop.headers.get("location"));
  const attacker = await call(W, cb.pathname + cb.search, { jar: new Jar() });
  const own = await call(W, cb.pathname + cb.search, { jar: victim });
  return (attacker.status === 302 && errorOf(attacker.headers.get("location")).error === "state_mismatch" && !attacker.headers.getSetCookie().some((c) => /session_token=[^;]+/.test(c)) && own.headers.get("location") === back) || `${attacker.headers.get("location")} / ${own.headers.get("location")}`;
});
await s.t("a forged or missing state never signs anyone in", async () => {
  const a = await call(W, "/api/auth/callback/google?code=x&state=forged"); const b = await call(W, "/api/auth/callback/google?code=x");
  return (errorOf(a.headers.get("location")).error === "state_mismatch" && errorOf(b.headers.get("location")).error === "state_not_found") || `${a.headers.get("location")} ${b.headers.get("location")}`;
});
await s.t("a state made for one provider is refused at the other provider's callback", async () => {
  const jar = new Jar(); const started = await start(jar, { provider: "google", callbackURL: back });
  const state = new URL(started.json.url).searchParams.get("state");
  const r = await call(W, `/api/auth/callback/github?code=x&state=${state}`, { jar }); return errorOf(r.headers.get("location")).error === "state_mismatch" || r.headers.get("location");
});
await s.t("the provider refusing the person returns to errorCallbackURL with the error, and no session", async () => {
  fake.google = { ...fake.google, fault: "error" };
  const r = await signInWith("google"); const e = errorOf(r.location);
  fake.google = { ...fake.google, fault: "" };
  return (e.error === "access_denied" && e.description === "The person said no" && new URL(r.location).pathname === "/" && !r.jar.has("session_token")) || `${r.location} cookies=${[...r.jar.c.keys()]}`;
});
for (const fault of ["nonce", "aud", "iss", "exp", "sig", "no-nonce"]) {
  await s.t(`google: an ID token with a bad ${fault} is refused and signs nobody in`, async () => {
    fake.google = { ...fake.google, sub: "g-" + randomBytes(4).toString("hex"), email: email("bad"), fault };
    const r = await signInWith("google"); fake.google = { ...fake.google, fault: "" };
    const e = errorOf(r.location);
    return (e.error === "unable_to_get_user_info" && !r.jar.has("session_token")) || `${r.location}`;
  });
}
await s.t("google: an unverified email never signs anyone in", async () => {
  fake.google = { ...fake.google, sub: "g-" + randomBytes(4).toString("hex"), email: email("unv"), email_verified: false };
  const r = await signInWith("google"); fake.google = { ...fake.google, email_verified: true };
  return (errorOf(r.location).error === "email_not_verified" && !r.jar.has("session_token")) || r.location;
});
await s.t("an existing account whose email was never verified is taken over by the verified identity: its password stops working", async () => {
  const e = email("squat");
  const su = await call(W, "/api/auth/sign-up/email", { method: "POST", body: { name: "Squatter", email: e, password: PW } });
  fake.google = { ...fake.google, sub: "g-" + randomBytes(4).toString("hex"), email: e, name: "Real Owner" };
  const r = await signInWith("google"); const me = await sessionOf(r.jar);
  const old = await call(W, "/api/auth/sign-in/email", { method: "POST", body: { email: e, password: PW } });
  const oldToken = await call(A, "/v1/me", { headers: { authorization: `Bearer ${su.json.token}` } });
  return (me?.user?.email === e && me.user.emailVerified === true && old.status === 401 && oldToken.status === 401) || `${me?.user?.email} sign-in ${old.status} old session ${oldToken.status}`;
});

// ---------- GitHub ----------
const ghEmail = email("octo");
await s.t("github: the primary verified email is used (the profile's public email is ignored), and the person is signed in", async () => {
  fake.github = { ...fake.github, id: 1000 + Math.floor(Math.random() * 9000), name: "Octo Person", profileEmail: "public@example.test", emails: [
    { email: "secondary@example.test", primary: false, verified: true }, { email: ghEmail, primary: true, verified: true }], fault: "" };
  const r = await signInWith("github"); const me = await sessionOf(r.jar); const t = fake.tokenRequests.filter((x) => x.provider === "github").at(-1);
  const api = fake.apiCalls.filter((c) => c.path === "/user" || c.path === "/user/emails");
  return (r.location === newBack && me?.user?.email === ghEmail && me.user.name === "Octo Person" && t.client_secret === "h-secret" && t.code_verifier?.length >= 43 && api.every((c) => /^Bearer gho_/.test(c.authorization) && c.userAgent)) || `${r.location} ${JSON.stringify(me)?.slice(0, 160)}`;
});
await s.t("github: a primary email that is not verified is refused (email_not_verified)", async () => {
  fake.github = { ...fake.github, id: 2000 + Math.floor(Math.random() * 9000), emails: [{ email: email("unv"), primary: true, verified: false }, { email: email("other"), primary: false, verified: true }] };
  const r = await signInWith("github"); return (errorOf(r.location).error === "email_not_verified" && !r.jar.has("session_token")) || r.location;
});
await s.t("github: a verified email that is not the primary is never used (email_not_found)", async () => {
  fake.github = { ...fake.github, id: 3000 + Math.floor(Math.random() * 9000), emails: [{ email: email("sec"), primary: false, verified: true }] };
  const r = await signInWith("github"); return (errorOf(r.location).error === "email_not_found" && !r.jar.has("session_token")) || r.location;
});
await s.t("github: the profile's public email alone is not enough (no /user/emails, no sign-in)", async () => {
  fake.github = { ...fake.github, id: 4000 + Math.floor(Math.random() * 9000), profileEmail: email("profile"), emails: [] };
  const r = await signInWith("github"); return (errorOf(r.location).error === "email_not_found" && !r.jar.has("session_token")) || r.location;
});

fake.close();
s.done();
