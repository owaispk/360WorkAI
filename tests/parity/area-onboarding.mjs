// Onboarding area: the person's own routes (/v1/me/*), the install page's routes, "provision now, claim later" (/v1/bootstrap/*), diagnostics and resources.
//   node area-onboarding.mjs                                                                      # the reference (web :3005, api :8790)
//   W=http://localhost:5260 A=http://localhost:5160 node area-onboarding.mjs                      # the rewrite
// The reference allows 5 bootstrap workspaces per hour per address and this script makes 2 (the rewrite's limit is configurable:
// start it with Onboarding__Bootstrap__LimitPerHour=1000 to rerun freely; SKIP_BOOTSTRAP=1 leaves that section out). The download-link email limit is per person, so each run uses a new one.
import { A, W, PW, call, person, workspace, suite, denied, email } from "./lib.mjs";

const s = suite("onboarding");
const ws = await workspace("Onboarding Probe");
const bob = await ws.join("Bob Builder");
const NOPE = (p) => `${p}_01jzzzzzzzzzzzzzzzzzzzzzzz`;
const me = (u, path, o = {}) => call(A, path, { bearer: u.token, ...o });
const json = (r) => r.json ?? {};

// ---- profile --------------------------------------------------------------------------------------------------------------------------
await s.t("profile: names are trimmed, joined and returned; /v1/me shows them", async () => {
  const u = await person("Prof Person");
  const r = await me(u, "/v1/me/profile", { method: "PATCH", body: { firstName: "  Ann ", lastName: "  Bee   Cee " } });
  const after = await me(u, "/v1/me");
  return (r.status === 200 && r.json?.user?.name === "Ann Bee Cee" && r.json.user.id === u.userId && r.json.user.email === u.email && !("passwordHash" in r.json.user)
    && after.json?.user?.name === "Ann Bee Cee") || `${r.status} ${r.text}`;
});
await s.t("profile: one name is enough; both blank is the reference's 400; too long; wrong type; not signed in", async () => {
  const u = await person("Prof Two");
  const one = await me(u, "/v1/me/profile", { method: "PATCH", body: { firstName: "", lastName: "Solo" } });
  const blank = await me(u, "/v1/me/profile", { method: "PATCH", body: { firstName: "", lastName: " " } });
  const long = await me(u, "/v1/me/profile", { method: "PATCH", body: { firstName: "x".repeat(121), lastName: "" } });
  const missing = await me(u, "/v1/me/profile", { method: "PATCH", body: { firstName: "A" } });
  const anon = await call(A, "/v1/me/profile", { method: "PATCH", body: { firstName: "a", lastName: "" } });
  return (one.status === 200 && one.json.user.name === "Solo"
    && blank.status === 400 && blank.json?.error === "invalid_request" && blank.json?.message === "Enter a first or last name."
    && long.status === 400 && long.json?.message === "firstName: Too big: expected string to have <=120 characters"
    && missing.status === 400 && missing.json?.message === "lastName: Invalid input: expected string, received undefined"
    && anon.status === 401 && anon.json?.error === "unauthorized") || [one, blank, long, missing, anon].map((r) => `${r.status} ${r.text}`).join(" | ");
});

// ---- invitations the person has ---------------------------------------------------------------------------------------------------------
await s.t("my invitations: empty for a new account, 401 without a session", async () => {
  const u = await person("Inv Empty");
  const r = await me(u, "/v1/me/invitations");
  const anon = await call(A, "/v1/me/invitations");
  return (r.status === 200 && JSON.stringify(r.json) === '{"invitations":[]}' && anon.status === 401) || `${r.status} ${r.text} ${anon.status}`;
});
await s.t("my invitations: an unverified address sees none; one that arrived through its invitation link sees it until it joins", async () => {
  const addr = email("invitee");
  const inv = await ws.api(ws.owner, "POST", "/v1/invitations", { email: addr, role: "member" });
  // Signed up the ordinary way the address is not proven, so the list stays empty (it would hand out the invitation id).
  const plain = await call(W, "/api/auth/sign-up/email", { method: "POST", body: { name: "Plain Invitee", email: addr, password: PW } });
  const before = await me({ token: plain.json?.token }, "/v1/me/invitations");
  // The same address, signing up from the emailed link, is proven.
  const addr2 = email("invitee2");
  const inv2 = await ws.api(ws.owner, "POST", "/v1/invitations", { email: addr2, role: "admin" });
  const viaLink = await call(W, `/api/auth/sign-up/email?invite=${encodeURIComponent(inv2.json?.inviteToken)}`, { method: "POST", body: { name: "Link Invitee", email: addr2, password: PW } });
  let tok = viaLink.json?.token;
  if (!tok) tok = (await call(W, "/api/auth/sign-in/email", { method: "POST", body: { email: addr2, password: PW } })).json?.token;
  const list = await me({ token: tok }, "/v1/me/invitations");
  const row = list.json?.invitations?.[0];
  const accepted = await call(A, "/v1/orgs/invitations/accept", { method: "POST", bearer: tok, body: { id: inv2.json?.invitationId } });
  const after = await me({ token: tok }, "/v1/me/invitations");
  return (before.status === 200 && before.json?.invitations?.length === 0
    && list.status === 200 && list.json.invitations.length === 1 && row.id === inv2.json.invitationId && row.organization?.id === ws.orgId && row.organization?.name === "Onboarding Probe" && row.role === "admin" && !Number.isNaN(Date.parse(row.expiresAt))
    && Object.keys(row).sort().join() === "expiresAt,id,organization,role"
    && accepted.status === 200 && after.json?.invitations?.length === 0 && inv.status < 300)
    || `${before.text} | ${list.text} | ${accepted.status} ${after.text}`;
});

// ---- the download-link email ---------------------------------------------------------------------------------------------------------------
await s.t("download link: sends to the person's own address, five an hour, then 429 with Retry-After; not signed in is 401", async () => {
  const u = await person("Mail Person");
  const first = await me(u, "/v1/me/send-download-link", { method: "POST" });
  const more = [];
  for (let i = 0; i < 4; i++) more.push(await me(u, "/v1/me/send-download-link", { method: "POST" }));
  const sixth = await me(u, "/v1/me/send-download-link", { method: "POST" });
  const other = await person("Mail Other");
  const otherFirst = await me(other, "/v1/me/send-download-link", { method: "POST" });
  const anon = await call(A, "/v1/me/send-download-link", { method: "POST" });
  return (first.status === 200 && first.json?.ok === true && more.every((r) => r.status === 200)
    && sixth.status === 429 && sixth.json?.error === "rate_limited" && sixth.json?.message === "Too many download link emails. Try again later." && Number(sixth.headers.get("retry-after")) > 0
    && otherFirst.status === 200 && anon.status === 401) || [first, sixth, otherFirst, anon].map((r) => `${r.status} ${r.text}`).join(" | ");
});

// ---- install -------------------------------------------------------------------------------------------------------------------------------
await s.t("install config: the workspace's name and brand, the cloud distribution, a version; 401 without a session", async () => {
  const r = await ws.api(bob, "GET", "/v1/me/install-config");
  const anon = await call(A, "/v1/me/install-config");
  const c = r.json ?? {};
  return (r.status === 200 && Object.keys(c).sort().join() === "apiUrl,appName,clientName,desktopVersion,distribution,iconUrl,logoUrl,requireSignin,webUrl"
    && c.appName === "OpenWork" && c.clientName === "Onboarding Probe" && c.requireSignin === true && c.distribution === "cloud" && /^\d+\.\d+\.\d+/.test(c.desktopVersion)
    && c.logoUrl === null && c.iconUrl === null && /^https?:\/\//.test(c.webUrl) && /^https?:\/\//.test(c.apiUrl) && anon.status === 401) || `${r.status} ${r.text}`;
});
await s.t("install config follows the workspace's brand name and the newest approved desktop version", async () => {
  const patch = await ws.api(ws.owner, "PATCH", "/v1/org", { brandAppName: "Acme Work", allowedDesktopVersions: ["0.17.0", "0.18.1", "0.17.9"] });
  const r = await ws.api(bob, "GET", "/v1/me/install-config");
  const dl = await ws.api(bob, "GET", "/v1/me/install/mac-arm64");
  const loc = dl.headers.get("location") ?? "";
  return (patch.status === 200 && r.json?.appName === "Acme Work" && r.json?.desktopVersion === "0.18.1" && dl.status === 302 && loc.includes("0.18.1") && loc.endsWith("openwork-cloud-mac-arm64-0.18.1.dmg")) || `${patch.status} ${r.text} ${dl.status} ${loc}`;
});
await s.t("public install config names no workspace; the old install route sends people to the install page", async () => {
  const r = await call(A, "/v1/install-config");
  const old = await call(A, "/v1/install/mac-arm64");
  const c = r.json ?? {};
  return (r.status === 200 && c.clientName === "OpenWork Cloud" && c.appName === "OpenWork" && c.requireSignin === true && c.distribution === "cloud" && c.logoUrl === null
    && old.status === 302 && (old.headers.get("location") ?? "").endsWith("/install")) || `${r.status} ${r.text} ${old.status} ${old.headers.get("location")}`;
});
await s.t("installer download: one redirect per platform, a 400 for an unknown one, 401 when signed out", async () => {
  const names = { "mac-arm64": /openwork-cloud-mac-arm64-[\d.]+\.dmg$/, "mac-x64": /openwork-cloud-mac-x64-[\d.]+\.dmg$/, "win-x64": /openwork-cloud-win-x64-[\d.]+\.exe$/, "linux-x64": /openwork-cloud-linux-x86_64-[\d.]+\.AppImage$/, "linux-arm64": /openwork-cloud-linux-arm64-[\d.]+\.AppImage$/ };
  const bad = [];
  for (const [platform, re] of Object.entries(names)) { const r = await ws.api(ws.owner, "GET", `/v1/me/install/${platform}`); if (r.status !== 302 || !re.test(r.headers.get("location") ?? "")) bad.push(`${platform}: ${r.status} ${r.headers.get("location")}`); }
  const unknown = await ws.api(ws.owner, "GET", "/v1/me/install/beos");
  const anon = await call(A, "/v1/me/install/mac-arm64");
  return (bad.length === 0 && unknown.status === 400 && unknown.json?.error === "invalid_request" && anon.status === 401) || `${bad.join("; ")} ${unknown.status} ${unknown.text} ${anon.status}`;
});
await s.t("install page link: any member gets the plain page address; a malformed id is 400; signed out is 401", async () => {
  const r = await ws.api(bob, "POST", `/v1/orgs/${ws.orgId}/install-links`, {});
  const rotate = await ws.api(bob, "POST", `/v1/orgs/${ws.orgId}/install-links`, { rotate: true });
  const bad = await ws.api(bob, "POST", "/v1/orgs/xx/install-links", {});
  const anon = await call(A, `/v1/orgs/${ws.orgId}/install-links`, { method: "POST", body: {} });
  return (r.status === 200 && Object.keys(r.json).join() === "installPageUrl" && /^https?:\/\/[^?#]+\/install$/.test(r.json.installPageUrl) && rotate.status === 200 && rotate.json.installPageUrl === r.json.installPageUrl
    && bad.status === 400 && bad.json?.error === "invalid_request" && anon.status === 401) || [r, bad, anon].map((x) => `${x.status} ${x.text}`).join(" | ");
});
await s.t("app version: supported range, published versions, this deployment's web address, cacheable", async () => {
  const r = await call(A, "/v1/app-version");
  const c = r.json ?? {};
  return (r.status === 200 && /^\d+\.\d+\.\d+/.test(c.minAppVersion) && /^\d+\.\d+\.\d+/.test(c.latestAppVersion) && Array.isArray(c.publishedDesktopVersions) && c.publishedDesktopVersions.includes(c.latestAppVersion)
    && /^https?:\/\//.test(c.webUrl) && /max-age=300/.test(r.headers.get("cache-control") ?? "")) || `${r.status} ${r.text.slice(0, 200)}`;
});

// ---- my agent ---------------------------------------------------------------------------------------------------------------------------------
await s.t("my agent: off here (Workbot is not enabled), as the reference answers for an organization without it; signed out is 401", async () => {
  const get = await ws.api(bob, "GET", "/v1/me/agent");
  const put = await ws.api(bob, "PUT", "/v1/me/agent", { on: true });
  const checks = await ws.api(bob, "GET", "/v1/me/agent/checks");
  const anon = await call(A, "/v1/me/agent");
  const off = (r, f) => r.status === 404 && r.json?.error === "feature_disabled" && r.json?.feature === f;
  return (off(get, "workbotProactive") && off(put, "workbotProactive") && (off(checks, "workbotProactive") || off(checks, "workbotAgentLibrary")) && anon.status === 401) || [get, put, checks, anon].map((r) => `${r.status} ${r.text}`).join(" | ");
});

if (!process.env.SKIP_BOOTSTRAP) {
// ---- provision now, claim later --------------------------------------------------------------------------------------------------------
const created = await call(A, "/v1/bootstrap/workspace", { method: "POST", body: { workspaceName: "Agent Built", ownerEmail: "Owner@Example.com", teammateEmails: ["a@example.com", "A@example.com"], claimRoles: ["owner", "member"], skillName: "Hello Skill" } });
await s.t("bootstrap: validation errors are the reference's; none of them uses up an attempt", async () => {
  const short = await call(A, "/v1/bootstrap/workspace", { method: "POST", body: { workspaceName: "x" } });
  const role = await call(A, "/v1/bootstrap/workspace", { method: "POST", body: { workspaceName: "Fine Name", claimRoles: ["root"] } });
  const mail = await call(A, "/v1/bootstrap/workspace", { method: "POST", body: { workspaceName: "Fine Name", ownerEmail: "nope" } });
  const none = await call(A, "/v1/bootstrap/workspace", { method: "POST", body: {} });
  return (short.status === 400 && short.json?.message === "workspaceName: Too small: expected string to have >=2 characters"
    && role.status === 400 && role.json?.message === 'claimRoles.0: Invalid option: expected one of "owner"|"admin"|"member"'
    && mail.status === 400 && mail.json?.message === "ownerEmail: Invalid email address"
    && none.status === 400 && none.json?.message === "workspaceName: Invalid input: expected string, received undefined") || [short, role, mail, none].map((r) => `${r.status} ${r.text}`).join(" | ");
});
const c = created.json ?? {};
await s.t("bootstrap: a provisional workspace with a starter skill, claim links per role and an agent identity", async () => {
  const owner = c.claimLinks?.find((l) => l.role === "owner");
  const member = c.claimLinks?.find((l) => l.role === "member");
  return (created.status === 200 && c.ok === true && c.organization?.name === "Agent Built" && c.organization.status === "provisional" && c.organization.slug === c.organization.id && /^org_/.test(c.organization.id)
    && /^wbt_/.test(c.setup?.id) && !Number.isNaN(Date.parse(c.setup.expiresAt))
    && /^cob_/.test(c.skill?.id) && c.skill.title === "Hello Skill" && c.skill.output === "OPENWORK_BOOTSTRAP_SKILL_TRIGGERED"
    && c.claimLinks.length === 2 && /^wcl_/.test(owner?.id) && owner.token.length >= 24 && member.token !== owner.token
    && owner.url.includes("/workspace-claim?token=" + encodeURIComponent(owner.token)) && owner.url.includes("email=owner%40example.com") && owner.url.includes("invite=") && !member.url.includes("email=") && !member.url.includes("invite=")
    && c.identity?.type === "anonymous" && c.identity.assertion?.split(".").length === 3 && c.identity.assertionType === "urn:ietf:params:oauth:grant-type:jwt-bearer" && c.identity.scope === "mcp:read mcp:write"
    && /\/oauth2\/token$/.test(c.identity.tokenEndpoint) && c.identity.claimEndpoint.endsWith(`/v1/bootstrap/workspace/${c.setup.id}/claim`)
    && created.headers.get("cache-control") === "no-store") || `${created.status} ${created.text.slice(0, 500)}`;
});
const bid = c.setup?.id, assertion = c.identity?.assertion;
await s.t("claim state and codes are for the agent's assertion only", async () => {
  const noToken = await call(A, `/v1/bootstrap/workspace/${bid}/claim`);
  const junk = await call(A, `/v1/bootstrap/workspace/${bid}/claim`, { bearer: "abc.def.ghi" });
  const other = await call(A, `/v1/bootstrap/workspace/${NOPE("wbt")}/claim`, { bearer: assertion });
  const malformed = await call(A, `/v1/bootstrap/workspace/xx/claim`, { bearer: assertion });
  const state = await call(A, `/v1/bootstrap/workspace/${bid}/claim`, { bearer: assertion });
  return (noToken.status === 401 && noToken.json?.error === "invalid_token" && noToken.json?.error_description === "Send the pre-claim assertion as a Bearer token."
    && junk.status === 401 && junk.json?.error_description === "The pre-claim assertion is invalid for this workspace."
    && other.status === 401 && other.json?.error_description === "The pre-claim assertion is invalid for this workspace."
    && malformed.status === 400 && malformed.json?.error === "invalid_request"
    && state.status === 200 && JSON.stringify(state.json) === '{"state":"none","reconciled":false}') || [noToken, junk, other, malformed, state].map((r) => `${r.status} ${r.text}`).join(" | ");
});
const code1 = await call(A, `/v1/bootstrap/workspace/${bid}/claim`, { method: "POST", bearer: assertion });
const code2 = await call(A, `/v1/bootstrap/workspace/${bid}/claim`, { method: "POST", bearer: assertion });
const userCode = code2.json?.user_code ?? "";
await s.t("claim code: ABCD-EFGH, 15 minutes, a new code cancels the last; the state turns pending", async () => {
  const state = await call(A, `/v1/bootstrap/workspace/${bid}/claim`, { bearer: assertion });
  const person1 = await person("Early Claimer");
  const oldLookup = await call(A, `/v1/bootstrap/claim-codes/${code1.json?.user_code}`, { bearer: person1.token });
  return (code1.status === 200 && /^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/.test(userCode) && userCode !== code1.json.user_code && code2.json.expires_in === 900 && code2.json.interval === 5
    && /\/claim$/.test(code2.json.verification_uri) && code2.json.verification_uri_complete === `${code2.json.verification_uri}?user_code=${userCode}` && code2.headers.get("cache-control") === "no-store"
    && state.json?.state === "pending" && oldLookup.status === 404 && oldLookup.json?.error === "invalid_user_code") || `${code2.text} ${state.text} ${oldLookup.status}`;
});
const claimer = await person("Code Claimer");
await s.t("claim code lookup and accept: signed in only, validated, the workspace named, one use", async () => {
  const anon = await call(A, `/v1/bootstrap/claim-codes/${userCode}`);
  const found = await call(A, `/v1/bootstrap/claim-codes/${userCode.replace("-", "").toLowerCase()}`, { bearer: claimer.token });
  const wrong = await call(A, `/v1/bootstrap/claim-codes/ZZZZZZZZ`, { bearer: claimer.token });
  const short = await call(A, `/v1/bootstrap/claim-codes/ab`, { bearer: claimer.token });
  const anonAccept = await call(A, `/v1/bootstrap/claim-codes/accept`, { method: "POST", body: { userCode } });
  const noCode = await call(A, `/v1/bootstrap/claim-codes/accept`, { method: "POST", bearer: claimer.token, body: {} });
  const badMode = await call(A, `/v1/bootstrap/claim-codes/accept`, { method: "POST", bearer: claimer.token, body: { userCode, mode: "x" } });
  const accepted = await call(A, `/v1/bootstrap/claim-codes/accept`, { method: "POST", bearer: claimer.token, body: { userCode, mode: "new_org" } });
  const again = await call(A, `/v1/bootstrap/claim-codes/accept`, { method: "POST", bearer: claimer.token, body: { userCode } });
  return (anon.status === 401 && found.status === 200 && found.json?.organization?.id === c.organization.id && found.json.organization.name === "Agent Built"
    && wrong.status === 404 && wrong.json?.message === "This code is invalid or has expired. Ask your agent for a new one."
    && short.status === 400 && short.json?.message === "userCode: Too small: expected string to have >=4 characters"
    && anonAccept.status === 401 && noCode.status === 400 && noCode.json?.message === "userCode: Invalid input: expected string, received undefined"
    && badMode.status === 400 && badMode.json?.message === 'mode: Invalid input: expected "new_org"'
    && accepted.status === 200 && accepted.json?.ok === true && accepted.json.organization?.id === c.organization.id && accepted.json.organization.role === "owner" && accepted.json.organization.slug === c.organization.id
    && JSON.stringify(accepted.json.teammateEmails) === '["a@example.com"]' && again.status === 404) || [anon, found, wrong, short, accepted, again].map((r) => `${r.status} ${r.text}`).join(" | ");
});
await s.t("after a code claim: the person owns it alone, the starter skill is theirs, the agent's credentials are finished, the links are dead", async () => {
  const org = await call(A, "/v1/org", { bearer: claimer.token, headers: { "x-openwork-org-id": c.organization.id } });
  const orgs = await call(A, "/v1/me/orgs", { bearer: claimer.token });
  const plugins = await call(A, "/v1/plugins", { bearer: claimer.token, headers: { "x-openwork-org-id": c.organization.id } });
  const state = await call(A, `/v1/bootstrap/workspace/${bid}/claim`, { bearer: assertion });
  const newCode = await call(A, `/v1/bootstrap/workspace/${bid}/claim`, { method: "POST", bearer: assertion });
  const memberLink = c.claimLinks.find((l) => l.role === "member");
  const late = await person("Late Claimer");
  const link = await call(A, "/v1/bootstrap/claims/accept", { method: "POST", bearer: late.token, body: { token: memberLink.token } });
  const members = org.json?.members ?? [];
  return (org.status === 200 && members.length === 1 && members[0].role === "owner" && members[0].user?.email === claimer.email
    && orgs.json?.activeOrgId === c.organization.id && orgs.json.orgs.length === 1
    && plugins.status === 200 && (plugins.json?.items ?? []).some((p) => p.name === "Hello Skill")
    && state.status === 200 && JSON.stringify(state.json) === '{"state":"reconciled","reconciled":true}'
    && newCode.status === 401 && newCode.json?.error_description === "This workspace was already claimed or expired."
    && link.status === 404 && link.json?.error === "claim_not_found") || [org, orgs, state, newCode, link].map((r) => `${r.status} ${r.text.slice(0, 200)}`).join(" | ");
});
const created2 = await call(A, "/v1/bootstrap/workspace", { method: "POST", body: { workspaceName: "Link Built", teammateEmails: ["t@example.com"] } });
await s.t("claim link: signed in only, token validated, the role of the link, one use; the agent sees the claim as done", async () => {
  const d = created2.json ?? {};
  const tok = d.claimLinks?.[0]?.token;
  const taker = await person("Link Claimer");
  const anon = await call(A, "/v1/bootstrap/claims/accept", { method: "POST", body: { token: tok } });
  const short = await call(A, "/v1/bootstrap/claims/accept", { method: "POST", bearer: taker.token, body: { token: "abc" } });
  const wrong = await call(A, "/v1/bootstrap/claims/accept", { method: "POST", bearer: taker.token, body: { token: "x".repeat(43) } });
  const ok = await call(A, "/v1/bootstrap/claims/accept", { method: "POST", bearer: taker.token, body: { token: tok } });
  const again = await call(A, "/v1/bootstrap/claims/accept", { method: "POST", bearer: taker.token, body: { token: tok } });
  const state = await call(A, `/v1/bootstrap/workspace/${d.setup?.id}/claim`, { bearer: d.identity?.assertion });
  const stranger = await call(A, `/v1/bootstrap/workspace/${d.setup?.id}/claim`, { bearer: assertion });
  return (created2.status === 200 && d.claimLinks.length === 1 && d.claimLinks[0].role === "owner" && anon.status === 401
    && short.status === 400 && short.json?.message === "token: Too small: expected string to have >=24 characters"
    && wrong.status === 404 && wrong.json?.error === "claim_not_found" && wrong.json?.message === "This workspace claim link is missing, expired, or already used."
    && ok.status === 200 && ok.json?.organization?.role === "owner" && ok.json.organization.name === "Link Built" && JSON.stringify(ok.json.teammateEmails) === '["t@example.com"]'
    && again.status === 404 && state.json?.state === "reconciled" && stranger.status === 401) || [created2, anon, short, wrong, ok, again, state, stranger].map((r) => `${r.status} ${r.text.slice(0, 200)}`).join(" | ");
});

}

// ---- diagnostics --------------------------------------------------------------------------------------------------------------------------
const report = (over = {}) => ({ attemptId: crypto.randomUUID(), appVersion: "0.18.46", platform: "linux", observedAt: new Date().toISOString(), success: true, steps: { window: 100, engine: 300, signed_in: 500, org_tools: 900 }, failedStep: null, reason: null, ...over });
await s.t("diagnostics: a member sees every section locked, with the permission that opens it", async () => {
  const r = await ws.api(bob, "GET", "/v1/org/diagnostics");
  const d = r.json ?? {};
  return (r.status === 200 && d.version === 1 && d.deployment && d.checking === false && Array.isArray(d.attention) && /no-store/.test(r.headers.get("cache-control") ?? "")
    && d.desktop?.access === "locked" && d.desktop.permission === "desktop_policies.view" && d.connectors?.access === "locked" && d.connectors.permission === "connections.view"
    && d.network?.access === "locked" && d.network.permission === "egress_diagnostics.view" && d.installation?.access === "locked" && d.installation.reason === "installation_admin_required"
    && d.providers?.access === "locked") || `${r.status} ${r.text}`;
});
await s.t("desktop startup report: accepted once per launch, validated like the reference, rate limited per member", async () => {
  const one = report();
  const first = await ws.api(bob, "POST", "/v1/diagnostics/desktop-startup", one);
  const again = await ws.api(bob, "POST", "/v1/diagnostics/desktop-startup", one);
  const fail = await ws.api(ws.owner, "POST", "/v1/diagnostics/desktop-startup", report({ success: false, failedStep: "engine", reason: "timeout", steps: { window: 100, engine: null, signed_in: null, org_tools: null } }));
  const old = await ws.api(bob, "POST", "/v1/diagnostics/desktop-startup", report({ observedAt: new Date(Date.now() - 9 * 864e5).toISOString() }));
  const badId = await ws.api(bob, "POST", "/v1/diagnostics/desktop-startup", report({ attemptId: "x" }));
  const refine = await ws.api(bob, "POST", "/v1/diagnostics/desktop-startup", report({ success: false }));
  const extra = await ws.api(bob, "POST", "/v1/diagnostics/desktop-startup", { ...report(), extra: 1 });
  const anon = await call(A, "/v1/diagnostics/desktop-startup", { method: "POST", body: report() });
  return (first.status === 204 && again.status === 204 && fail.status === 204 && old.status === 204
    && badId.status === 400 && badId.json?.message === "attemptId: Invalid UUID"
    && refine.status === 400 && refine.json?.message === "failedStep: A failed startup names its failed step and reason."
    && extra.status === 400 && extra.json?.message === 'Unrecognized key: "extra"' && anon.status === 401) || [first, again, fail, old, badId, refine, extra, anon].map((r) => `${r.status} ${r.text}`).join(" | ");
});
await s.t("diagnostics: the owner sees the launches (one repeated report counts once), the failure and the attention item", async () => {
  const r = await ws.api(ws.owner, "GET", "/v1/org/diagnostics");
  const d = r.json?.desktop ?? {};
  const att = r.json?.attention?.[0];
  return (r.status === 200 && d.access === "granted" && d.windowHours === 24 && d.startups === 2 && d.connected === 1 && d.failed === 1 && d.people === 2
    && d.typicalMs === 900 && d.slowestMs === 900 && JSON.stringify(d.steps) === '[{"step":"window","typicalMs":100},{"step":"engine","typicalMs":200},{"step":"signed_in","typicalMs":200},{"step":"org_tools","typicalMs":400}]'
    && d.failures?.length === 1 && d.failures[0].step === "engine" && d.failures[0].reason === "timeout" && d.failures[0].count === 1 && d.failures[0].people === 1
    && JSON.stringify(d.versions) === '[{"version":"0.18.46","startups":2}]'
    && att?.section === "desktop" && att.code === "desktop_startup_failures" && att.severity === "warning" && att.count === 1 && att.detail === "timeout"
    && r.json.network?.access === "granted" && r.json.network.canRun === true && r.json.connectors?.access === "granted" && r.json.providers?.access === "granted") || `${r.status} ${r.text.slice(0, 900)}`;
});
await s.t("diagnostics: strict is validated and the check answers 202 with the current picture", async () => {
  const ok = await ws.api(ws.owner, "GET", "/v1/org/diagnostics?strict=1");
  const bad = await ws.api(ws.owner, "GET", "/v1/org/diagnostics?strict=maybe");
  const check = await ws.api(ws.owner, "POST", "/v1/org/diagnostics/check");
  const anon = await call(A, "/v1/org/diagnostics");
  return (ok.status === 200 && bad.status === 400 && bad.json?.message === 'strict: Invalid option: expected one of "0"|"1"|"true"|"false"' && check.status === 202 && check.json?.version === 1 && anon.status === 401) || [ok, bad, check, anon].map((r) => `${r.status} ${r.text.slice(0, 160)}`).join(" | ");
});
await s.t("network check: configuration for people who may view it, the token only for those who may run it", async () => {
  const owner = await ws.api(ws.owner, "GET", "/v1/diagnostics/egress");
  const member = await ws.api(bob, "GET", "/v1/diagnostics/egress");
  const put = await ws.api(bob, "PUT", "/v1/diagnostics/egress/token", { bearerToken: "x".repeat(30) });
  const post = await ws.api(bob, "POST", "/v1/diagnostics/egress");
  return (owner.status === 200 && typeof owner.json?.available === "boolean" && Array.isArray(owner.json.missingConfiguration) && "targetOrigin" in owner.json
    && denied(member, "egress_diagnostics.view") && denied(put, "egress_diagnostics.manage") && denied(post, "egress_diagnostics.manage")) || [owner, member, put, post].map((r) => `${r.status} ${r.text.slice(0, 200)}`).join(" | ");
});

// ---- resources ----------------------------------------------------------------------------------------------------------------------------
await s.t("resources: a marketplace shared with everyone shows its plugins and skills to a member, with update times", async () => {
  const skill = "---\nname: shared-one\ndescription: Does a thing\n---\n\nBody.\n";
  const plugin = await ws.api(ws.owner, "POST", "/v1/plugins", { name: "Shared Bundle", orgWide: true, components: [{ type: "skill", input: { rawSourceText: skill } }] });
  const pid = plugin.json?.item?.id;
  const market = await ws.api(ws.owner, "POST", "/v1/marketplaces", { name: "Shelf" });
  const mid = market.json?.item?.id;
  const attach = await ws.api(ws.owner, "POST", `/v1/marketplaces/${mid}/plugins`, { pluginId: pid });
  const shareM = await ws.api(ws.owner, "POST", `/v1/marketplaces/${mid}/access`, { orgWide: true, role: "viewer" });
  const snapshot = await ws.api(bob, "GET", "/v1/resources");
  const caps = await ws.api(bob, "GET", "/v1/resources/marketplace-capabilities");
  const anon = await call(A, "/v1/resources");
  const m = snapshot.json?.resources?.marketplaces?.[mid];
  const p = m?.plugins?.find((x) => x.pluginId === pid);
  return (plugin.status === 201 && attach.status < 300 && shareM.status < 300 && snapshot.status === 200 && snapshot.json.organizationId === ws.orgId && snapshot.json.orgMemberId === bob.memberId && Array.isArray(snapshot.json.teamIds)
    && snapshot.json.resources.llmProviders && typeof snapshot.json.resources.llmProviders === "object"
    && !Number.isNaN(Date.parse(m?.lastUpdatedAt)) && p && !Number.isNaN(Date.parse(p.lastUpdatedAt)) && p.configItems.length === 1 && /^cob_/.test(p.configItems[0].configItemId)
    && caps.status === 200 && caps.json.items.some((i) => i.pluginId === pid && i.marketplaceId === mid && i.objectType === "skill" && i.configObjectId === p.configItems[0].configItemId) && anon.status === 401)
    || [plugin, market, attach, shareM, snapshot, caps].map((r) => `${r.status} ${r.text.slice(0, 300)}`).join(" | ");
});
await s.t("resources: another workspace's marketplace never appears", async () => {
  const other = await workspace("Elsewhere");
  const market = await other.api(other.owner, "POST", "/v1/marketplaces", { name: "Their Shelf" });
  const mid = market.json?.item?.id;
  const mine = await ws.api(ws.owner, "GET", "/v1/resources");
  return (market.status === 201 && mine.status === 200 && !(mid in mine.json.resources.marketplaces)) || `${market.status} ${mine.text.slice(0, 200)}`;
});

s.done();
