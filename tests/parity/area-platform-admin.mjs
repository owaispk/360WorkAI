// Contract test for the "platform admin" area: who is a platform admin and the guard on /v1/admin, users, organizations (plan fields, DPA, web access,
// capabilities), feature flags (deployment-wide and per organization) and how they show up in GET /v1/features and GET /v1/org, overview, metrics and
// the admin list. Runs unchanged against the reference Den and the rewrite (see ../../docs/AREA_GUIDE.md):
//   node area-platform-admin.mjs                                                  # reference: web :3005, api :8790
//   W=http://localhost:5270 A=http://localhost:5170 node area-platform-admin.mjs  # rewrite
//
// The script needs one platform admin, the fixed address padmin.parity@example.com (override with PADMIN_EMAIL), and creates it when missing:
//  * reference: a platform admin is an address on the `admin_allowlist` table (or DEN_BOOTSTRAP_ADMIN_EMAILS at start). The script inserts the row with the
//    mysql client: PADMIN_MYSQL="-uroot -ppassword -h127.0.0.1 openwork_den" (that is the default for the local reference). If your database is
//    elsewhere, insert it yourself: insert into admin_allowlist (id, email) values ('aal_01<24 base32 characters>', 'padmin.parity@example.com');
//  * rewrite: start the API with PlatformAdmin__BootstrapEmails=padmin.parity@example.com (the dev.sh run in docs/features/platform-admin.md does).
// It changes deployment-wide feature state for one feature (computerUseBackground) and puts it back; run it on a throwaway deployment, not a shared one.
import { execSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { A, PW, W, call, keys, person, suite, workspace } from "./lib.mjs";

const s = suite("platform-admin");
const t = s.t.bind(s);
const ADMIN_EMAIL = process.env.PADMIN_EMAIL ?? "padmin.parity@example.com";
const MYSQL = process.env.PADMIN_MYSQL ?? "-uroot -ppassword -h127.0.0.1 openwork_den";
const B32 = "0123456789abcdefghjkmnpqrstvwxyz";
const aalId = () => "aal_01" + Array.from(randomBytes(24), (b) => B32[b % 32]).join("");

/** The platform admin: signs up (or signs in) and, on the reference, is added to the allowlist table when needed. */
async function platformAdmin() {
  let r = await call(W, "/api/auth/sign-up/email", { method: "POST", body: { name: "Platform Admin", email: ADMIN_EMAIL, password: PW } });
  if (!r.json?.token) r = await call(W, "/api/auth/sign-in/email", { method: "POST", body: { email: ADMIN_EMAIL, password: PW } });
  if (!r.json?.token) throw new Error(`cannot sign in as ${ADMIN_EMAIL}: ${r.status} ${r.text.slice(0, 120)}`);
  const me = { email: ADMIN_EMAIL, token: r.json.token, userId: r.json.user?.id };
  let probe = await call(A, "/v1/admin/overview?limit=1", { bearer: me.token });
  if (probe.status === 403) {
    try { execSync(`mysql ${MYSQL} -e "insert ignore into admin_allowlist (id, email, note) values ('${aalId()}', '${ADMIN_EMAIL}', 'parity script')"`, { stdio: "ignore" }); } catch {}
    probe = await call(A, "/v1/admin/overview?limit=1", { bearer: me.token });
  }
  if (probe.status !== 200) throw new Error(`${ADMIN_EMAIL} is not a platform admin (${probe.status} ${probe.text.slice(0, 80)}); see the header of this script`);
  return me;
}

const admin = await platformAdmin();
const g = (path, method = "GET", body) => call(A, path, { method, bearer: admin.token, body });
const as = (user, path, method = "GET", body) => call(A, path, { method, bearer: user.token, body });
const TAG = randomBytes(3).toString("hex");
const ORG_NAME = `Platform Admin Probe ${TAG}`;
const ws = await workspace(ORG_NAME);
const owner = ws.owner;
const adminRoleMember = await ws.join(`Org Admin Role ${TAG}`, "admin");
const member = await ws.join("Plain Member");
const orgOf = async (user = owner) => (await ws.api(user, "GET", "/v1/org")).json;
const noWorkspace = await person("Bystander");
const PROBE_FEATURE = "computerUseBackground";

// ---- who may use the routes ---------------------------------------------------------------------------------------------------------
const READS = ["/v1/admin/overview", "/v1/admin/users", "/v1/admin/organizations", `/v1/admin/organizations/${ws.orgId}`, `/v1/admin/organizations/${ws.orgId}/capabilities`, "/v1/admin/features", "/v1/admin/metrics"];
const WRITES = [
  ["POST", "/v1/admin/admins", { email: "nobody@example.com" }],
  ["DELETE", "/v1/admin/admins/aal_01jzzzzzzzzzzzzzzzzzzzzzzz"],
  ["DELETE", `/v1/admin/users/${noWorkspace.userId}`],
  ["PATCH", `/v1/admin/organizations/${ws.orgId}/plan`, { tier: "team", seatLimit: 9 }],
  ["PATCH", `/v1/admin/organizations/${ws.orgId}/free-seats`, { totalFreeSeats: 9 }],
  ["PATCH", `/v1/admin/organizations/${ws.orgId}/dpa`, { dpaSigned: true, reason: "not allowed" }],
  ["PUT", `/v1/admin/organizations/${ws.orgId}/openwork-web-access`, { enabled: true, reason: "not allowed" }],
  ["PUT", `/v1/admin/organizations/${ws.orgId}/capabilities`, { capabilities: { [PROBE_FEATURE]: true } }],
  ["PUT", `/v1/admin/features/${PROBE_FEATURE}`, { enabled: true }],
];
await t("guard: nobody signed in gets 401 unauthorized on every admin route", async () => {
  for (const p of READS) { const r = await call(A, p); if (r.status !== 401 || r.json?.error !== "unauthorized") return `${p}: ${r.status} ${r.text}`; }
  for (const [m, p, b] of WRITES) { const r = await call(A, p, { method: m, body: b }); if (r.status !== 401 || r.json?.error !== "unauthorized") return `${m} ${p}: ${r.status} ${r.text}`; }
});
await t("guard: a made-up token is 401, not 403", async () => {
  const r = await call(A, "/v1/admin/overview", { bearer: "not-a-real-token" });
  return r.status === 401 && r.json?.error === "unauthorized" || r.text;
});
await t("guard: a workspace owner is not a platform admin (403 forbidden on every route)", async () => {
  for (const p of READS) { const r = await as(owner, p); if (r.status !== 403 || r.json?.error !== "forbidden") return `${p}: ${r.status} ${r.text}`; }
  for (const [m, p, b] of WRITES) { const r = await as(owner, p, m, b); if (r.status !== 403 || r.json?.error !== "forbidden") return `${m} ${p}: ${r.status} ${r.text}`; }
});
await t("guard: an organization admin, a plain member and someone with no workspace get the same 403", async () => {
  for (const u of [adminRoleMember, member, noWorkspace]) {
    for (const p of ["/v1/admin/overview", "/v1/admin/users", "/v1/admin/features"]) { const r = await as(u, p); if (r.status !== 403 || r.json?.error !== "forbidden") return `${u.name} ${p}: ${r.status} ${r.text}`; }
    const w = await as(u, `/v1/admin/features/${PROBE_FEATURE}`, "PUT", { enabled: true }); if (w.status !== 403) return `${u.name} PUT: ${w.status}`;
  }
});
await t("guard: the workspace header does not turn an owner into an admin", async () => {
  const r = await call(A, "/v1/admin/overview", { bearer: owner.token, headers: { "x-openwork-org-id": ws.orgId } });
  return r.status === 403 && r.json?.error === "forbidden" || r.text;
});
await t("guard: the refused calls changed nothing", async () => {
  const f = (await g("/v1/admin/features")).json.features.find((x) => x.key === PROBE_FEATURE);
  const org = (await g(`/v1/admin/organizations/${ws.orgId}?limit=1`)).json.organization;
  const admins = (await g("/v1/admin/overview?limit=1")).json.admins.map((a) => a.email);
  return f.enabled === false && f.lastChange?.by?.email !== owner.email && org.planTier === "free" && org.plan.source === "default" && !admins.includes("nobody@example.com")
    && (await as(noWorkspace, "/v1/me")).status === 200 || JSON.stringify({ f, org, admins });
});
await t("guard: the platform admin passes", async () => {
  const r = await g("/v1/admin/overview?limit=1");
  return r.status === 200 && r.json.viewer.email === ADMIN_EMAIL && r.json.viewer.id === admin.userId || r.text.slice(0, 300);
});

// ---- overview, users -----------------------------------------------------------------------------------------------------------------
await t("overview: shape of the first page (viewer, admins, summary totals, one page of users)", async () => {
  const r = await g("/v1/admin/overview?limit=2");
  const j = r.json;
  return r.status === 200 && keys(j) === "admins,generatedAt,organizationPage,organizations,summary,userPage,users,viewer" && keys(j.viewer) === "email,id,name"
    && j.users.length === 2 && j.organizations.length === 0 && j.userPage.limit === 2 && j.userPage.total >= 4 && j.userPage.hasMore === true
    && j.summary.totalUsers === j.userPage.total && j.summary.totalOrganizations >= 1 && j.summary.adminCount === j.admins.length && j.summary.billingLoaded === false
    && keys(j.admins[0]) === "createdAt,email,id,note" && j.admins.some((a) => a.email === ADMIN_EMAIL) || r.text.slice(0, 400);
});
await t("users: one user with their memberships, sessions and sign-in method", async () => {
  const r = await g(`/v1/admin/users?search=${encodeURIComponent(member.email)}`);
  const u = r.json?.users?.[0];
  return r.status === 200 && keys(r.json) === "billing,generatedAt,page,users" && r.json.users.length === 1 && r.json.page.total === 1
    && keys(u) === "activeDayCount,authProviders,billing,cloudWorkerCount,createdAt,email,emailVerified,firstInviteAt,hoursToFirstInvite,id,invitesSent,isRecurring,lastActiveAt,lastSeenAt,latestWorkerCreatedAt,localWorkerCount,name,organizations,sessionCount,updatedAt,workerCount"
    && u.id === member.userId && u.email === member.email && u.sessionCount >= 1 && u.authProviders.join() === "email" && u.billing === null
    && u.organizations.length === 1 && keys(u.organizations[0]) === "id,joinedAt,memberCount,name,role" && u.organizations[0].id === ws.orgId && u.organizations[0].role === "member" && u.organizations[0].memberCount === 3
    || r.text.slice(0, 500);
});
await t("users: search by part of a name, by workspace name and by a workspace role; no match is an empty page", async () => {
  const byName = await g(`/v1/admin/users?search=${encodeURIComponent(`org admin role ${TAG}`)}`);
  const byOrg = await g(`/v1/admin/users?search=${encodeURIComponent(ORG_NAME)}`);
  const none = await g(`/v1/admin/users?search=${encodeURIComponent("zz-nobody-" + Date.now())}`);
  return byName.json.users.some((u) => u.id === adminRoleMember.userId) && byOrg.json.users.length === 3 && byOrg.json.page.total === 3
    && none.json.users.length === 0 && none.json.page.total === 0 && none.json.page.hasMore === false || JSON.stringify([byName.json.page, byOrg.json.page, none.json.page]);
});
await t("users: a search for an address is an exact match, and % and _ are literal", async () => {
  const exact = await g(`/v1/admin/users?search=${encodeURIComponent(member.email.toUpperCase())}`);
  const wild = await g(`/v1/admin/users?search=${encodeURIComponent("%")}`);
  const partial = await g(`/v1/admin/users?search=${encodeURIComponent(member.email.slice(0, 10) + "@example.com")}`);
  return exact.json.users.length === 1 && wild.json.page.total === 0 && partial.json.page.total === 0 || JSON.stringify([exact.json.page, wild.json.page, partial.json.page]);
});
await t("users: paging (limit 1 to 100, default 50, offset), newest first", async () => {
  const one = await g("/v1/admin/users?limit=1");
  const two = await g("/v1/admin/users?limit=1&offset=1");
  const big = await g("/v1/admin/users?limit=500");
  const bad = await g("/v1/admin/users?limit=abc&offset=-3");
  const zero = await g("/v1/admin/users?limit=0");
  const all = await g("/v1/admin/users?limit=100");
  const dates = all.json.users.map((u) => Date.parse(u.createdAt));
  return one.json.page.limit === 1 && one.json.page.returned === 1 && one.json.page.hasMore === true && two.json.page.offset === 1 && one.json.users[0].id !== two.json.users[0].id
    && big.json.page.limit === 100 && bad.json.page.limit === 50 && bad.json.page.offset === 0 && zero.json.page.limit === 1
    && dates.every((d, i) => i === 0 || dates[i - 1] >= d) && all.json.users[0].id === one.json.users[0].id
    && keys(one.json.page) === "durationMs,hasMore,limit,offset,returned,search,total" || JSON.stringify([one.json.page, bad.json.page]);
});
await t("users: includeBilling shows an unpaid state for each user on the page; no billing provider is called", async () => {
  const r = await g(`/v1/admin/users?includeBilling=1&search=${encodeURIComponent(member.email)}`);
  const u = r.json.users[0];
  return r.json.billing.loaded === true && r.json.billing.unpaidUsers === 1 && r.json.billing.paidUsers === 0 && u.billing.status === "unpaid" && u.billing.subscriptionId === null && u.billing.source === "subscription" || r.text.slice(0, 400);
});

// ---- organizations -------------------------------------------------------------------------------------------------------------------
await t("organizations: list shape, defaults (free plan, 5 free seats), search by id and by name", async () => {
  const r = await g(`/v1/admin/organizations?search=${ws.orgId}`);
  const o = r.json?.organizations?.[0];
  const byName = await g(`/v1/admin/organizations?search=${encodeURIComponent(ORG_NAME.toLowerCase())}`);
  return r.status === 200 && keys(r.json) === "generatedAt,organizations,page" && r.json.organizations.length === 1 && r.json.page.total === 1
    && keys(o) === "billableSeatCount,capabilities,createdAt,ended,endsAt,featureStates,freeSeatCount,id,memberCount,name,openworkWebAccess,paidBy,plan,seatLimit,seatsFreeAdditional,slug,updatedAt,userLimit"
    && o.id === ws.orgId && o.name === ORG_NAME && o.memberCount === 3 && o.plan.tier === "free" && o.plan.source === "default" && keys(o.plan) === "source,tier"
    && o.seatLimit === 5 && o.freeSeatCount === 5 && o.seatsFreeAdditional === 0 && o.endsAt === null && o.ended === false && o.paidBy === "none" && o.userLimit === null
    && o.openworkWebAccess.hasAccess === false && o.openworkWebAccess.complimentaryAccess === false && byName.json.organizations.some((x) => x.id === ws.orgId)
    || r.text.slice(0, 500);
});
await t("organizations: includeFeatures=0 leaves out capabilities and featureStates", async () => {
  const r = await g(`/v1/admin/organizations?search=${ws.orgId}&includeFeatures=0`);
  const o = r.json.organizations[0];
  return !("capabilities" in o) && !("featureStates" in o) && o.id === ws.orgId || keys(o);
});
await t("organizations: one organization with a page of its people (searchable), plan and people counts", async () => {
  const r = await g(`/v1/admin/organizations/${ws.orgId}`);
  const found = await g(`/v1/admin/organizations/${ws.orgId}?search=${encodeURIComponent(member.email)}`);
  const j = r.json;
  return r.status === 200 && r.headers.get("cache-control") === "no-store" && keys(j) === "generatedAt,members,organization,page"
    && keys(j.organization) === "createdAt,id,memberCount,name,openworkWeb,people,plan,planTier,seatLimit,slug,subscriptions"
    && j.organization.memberCount === 3 && j.organization.people.joined === 3 && j.organization.people.invited === 0 && j.organization.planTier === "free"
    && keys(j.organization.plan) === "ended,endsAt,paidBy,seats,source,tier,userLimit,users"
    && j.members.length === 3 && keys(j.members[0]) === "email,id,joinedAt,name,role,userId" && j.members.some((m) => m.role === "owner" && m.userId === owner.userId)
    && found.json.members.length === 1 && found.json.page.total === 1 && j.page.total === 3 || r.text.slice(0, 600);
});
await t("organizations: a malformed id is 400, an unknown one 404 (same shapes as the other admin routes)", async () => {
  const bad = await g("/v1/admin/organizations/abc");
  const unknown = await g("/v1/admin/organizations/org_01m68tknxje18aqs60j2j437zz");
  return bad.status === 400 && bad.json.error === "invalid_request" && bad.json.message === "Invalid organization id."
    && unknown.status === 404 && unknown.json.error === "not_found" && unknown.json.message === "Organization not found." || JSON.stringify([bad.json, unknown.json]);
});

const planPatch = (b) => g(`/v1/admin/organizations/${ws.orgId}/plan`, "PATCH", b);
await t("plan: the body is validated with the reference's messages", async () => {
  const cases = [
    [{ tier: "x", seatLimit: 3 }, 'Invalid option: expected one of "free"|"team"|"enterprise"'],
    [{}, 'Invalid option: expected one of "free"|"team"|"enterprise"'],
    [{ tier: "team" }, "Invalid input: expected number, received undefined"],
    [{ tier: "team", seatLimit: "7" }, "Invalid input: expected number, received string"],
    [{ tier: "team", seatLimit: 0 }, "Too small: expected number to be >=1"],
    [{ tier: "team", seatLimit: 1.5 }, "Invalid input: expected int, received number"],
    [{ tier: "team", seatLimit: 100001 }, "Too big: expected number to be <=100000"],
    [{ tier: "free", seatLimit: 5, endsAt: "2027-01-31" }, "A Free plan has no end date."],
    [{ tier: "team", seatLimit: 5, endsAt: "nope" }, "Use a date such as 2026-11-22."],
    [{ tier: "team", seatLimit: 5, endsAt: "2027-02-30" }, "Use a date such as 2026-11-22."],
    [{ tier: "team", seatLimit: 5, endsAt: 5 }, "Invalid input: expected string, received number"],
    [null, "Invalid input: expected object, received null"],
  ];
  for (const [body, message] of cases) {
    const r = await planPatch(body);
    if (r.status !== 400 || r.json?.error !== "invalid_request" || r.json.message !== message) return `${JSON.stringify(body)}: ${r.status} ${r.text}`;
  }
});
await t("plan: unknown and malformed organizations (400 for a bad id, 404 for an unknown one)", async () => {
  const bad = await g("/v1/admin/organizations/xyz/plan", "PATCH", { tier: "team", seatLimit: 8 });
  const unknown = await g("/v1/admin/organizations/org_01m68tknxje18aqs60j2j437zz/plan", "PATCH", { tier: "team", seatLimit: 8 });
  return bad.status === 400 && bad.json.message === "Invalid organization id." && unknown.status === 404 && unknown.json.error === "not_found" || JSON.stringify([bad.json, unknown.json]);
});
await t("plan: a Team plan with users allowed and an end date is stored and shown everywhere", async () => {
  const r = await planPatch({ tier: "team", seatLimit: 12, endsAt: "2027-01-31" });
  const plan = r.json?.organization?.plan;
  const list = (await g(`/v1/admin/organizations?search=${ws.orgId}&includeFeatures=0`)).json.organizations[0];
  const detail = (await g(`/v1/admin/organizations/${ws.orgId}?limit=1`)).json.organization;
  const mine = await orgOf();
  return r.status === 200 && keys(r.json) === "ok,organization" && keys(r.json.organization) === "id,plan,seatLimit" && r.json.organization.seatLimit === 12
    && keys(plan) === "ended,endsAt,paidBy,seats,source,tier,userLimit,users" && plan.tier === "team" && plan.source === "manual" && plan.seats === 12 && plan.endsAt === "2027-01-31" && plan.ended === false && plan.paidBy === "none" && plan.users === 3
    && list.plan.tier === "team" && list.plan.source === "manual" && list.seatLimit === 12 && list.endsAt === "2027-01-31" && list.seatsFreeAdditional === 0
    && detail.planTier === "team" && detail.seatLimit === 12 && detail.plan.seats === 12
    && mine.plan.tier === "team" && mine.plan.source === "manual" || r.text;
});
await t("plan: a seat limit under 5 is raised to 5; Enterprise with no end date; a past end date shows as ended", async () => {
  const low = await planPatch({ tier: "team", seatLimit: 3 });
  const ent = await planPatch({ tier: "enterprise", seatLimit: 100, endsAt: null });
  const past = await planPatch({ tier: "team", seatLimit: 10, endsAt: "2020-01-01" });
  return low.json.organization.plan.seats === 5 && low.json.organization.seatLimit === 5 && ent.json.organization.plan.tier === "enterprise" && ent.json.organization.plan.endsAt === null
    && past.json.organization.plan.ended === true && past.json.organization.plan.endsAt === "2020-01-01" || JSON.stringify([low.json, ent.json, past.json]);
});
await t("plan: Free takes users above 5 as extra free seats and clears the end date", async () => {
  const r = await planPatch({ tier: "free", seatLimit: 50 });
  const list = (await g(`/v1/admin/organizations?search=${ws.orgId}&includeFeatures=0`)).json.organizations[0];
  const low = await planPatch({ tier: "free", seatLimit: 3 });
  const list2 = (await g(`/v1/admin/organizations?search=${ws.orgId}&includeFeatures=0`)).json.organizations[0];
  return r.json.organization.plan.tier === "free" && r.json.organization.plan.seats === null && r.json.organization.plan.endsAt === null && r.json.organization.seatLimit === 50
    && list.plan.source === "manual" && list.seatLimit === 50 && list.freeSeatCount === 50 && list.seatsFreeAdditional === 45
    && low.json.organization.seatLimit === 3 && list2.seatLimit === 5 && list2.freeSeatCount === 5 || JSON.stringify([r.json, list, low.json, list2]);
});
await t("free seats: validated (whole number, 5 to 100000) and stored beside the plan", async () => {
  const small = await g(`/v1/admin/organizations/${ws.orgId}/free-seats`, "PATCH", { totalFreeSeats: 2 });
  const frac = await g(`/v1/admin/organizations/${ws.orgId}/free-seats`, "PATCH", { totalFreeSeats: 5.5 });
  const big = await g(`/v1/admin/organizations/${ws.orgId}/free-seats`, "PATCH", { totalFreeSeats: 200000 });
  const missing = await g(`/v1/admin/organizations/${ws.orgId}/free-seats`, "PATCH", {});
  const ok = await g(`/v1/admin/organizations/${ws.orgId}/free-seats`, "PATCH", { totalFreeSeats: 9 });
  const list = (await g(`/v1/admin/organizations?search=${ws.orgId}&includeFeatures=0`)).json.organizations[0];
  const msgs = [small, frac, big, missing].map((r) => r.status + r.json?.message);
  return msgs.join("|") === "400Too small: expected number to be >=5|400Invalid input: expected int, received number|400Too big: expected number to be <=100000|400Invalid input: expected number, received undefined"
    && ok.status === 200 && keys(ok.json.organization) === "billableSeatCount,freeSeatCount,id,memberCount,seatsFreeAdditional" && ok.json.organization.freeSeatCount === 9 && ok.json.organization.seatsFreeAdditional === 4
    && list.freeSeatCount === 9 && list.seatsFreeAdditional === 4 || JSON.stringify([msgs, ok.json, list]);
});
await t("dpa: validated like the reference (strict body, reason of 3 to 500 characters)", async () => {
  const dpa = (b, org = ws.orgId) => g(`/v1/admin/organizations/${org}/dpa`, "PATCH", b);
  const short = await dpa({ dpaSigned: true, reason: "x" });
  const extra = await dpa({ dpaSigned: true, reason: "signed on file", foo: 1 });
  const missing = await dpa({});
  const bad = await dpa({ dpaSigned: true, reason: "signed" }, "xyz");
  const unknown = await dpa({ dpaSigned: true, reason: "signed" }, "org_01m68tknxje18aqs60j2j437zz");
  return short.status === 400 && short.json.message === "reason: Too small: expected string to have >=3 characters"
    && extra.status === 400 && extra.json.message === 'Unrecognized key: "foo"'
    && missing.status === 400 && missing.json.message === "dpaSigned: Invalid input: expected boolean, received undefined (and 1 more)"
    && bad.status === 400 && bad.json.message === "Invalid organization id." && unknown.status === 404 && unknown.json.error === "not_found" || JSON.stringify([short.json, extra.json, missing.json, bad.json, unknown.json]);
});
await t("dpa: the decision is recorded and can be changed back", async () => {
  const on = await g(`/v1/admin/organizations/${ws.orgId}/dpa`, "PATCH", { dpaSigned: true, reason: "  signed on file  " });
  const off = await g(`/v1/admin/organizations/${ws.orgId}/dpa`, "PATCH", { dpaSigned: false, reason: "withdrawn" });
  return on.status === 200 && keys(on.json) === "ok,organization" && keys(on.json.organization) === "dpaSigned,id" && on.json.organization.dpaSigned === true && off.json.organization.dpaSigned === false || JSON.stringify([on.json, off.json]);
});
await t("web access: validated; granted and revoked with a reason; shown on the list and in GET /v1/org capabilities", async () => {
  const put = (b) => g(`/v1/admin/organizations/${ws.orgId}/openwork-web-access`, "PUT", b);
  const short = await put({ enabled: true, reason: "x" });
  const type = await put({ enabled: "yes", reason: "abc" });
  const on = await put({ enabled: true, reason: "trial grant" });
  const list = (await g(`/v1/admin/organizations?search=${ws.orgId}&includeFeatures=0`)).json.organizations[0];
  const caps = (await orgOf()).capabilities;
  const off = await put({ enabled: false, reason: "trial over" });
  return short.status === 400 && short.json.message === "Too small: expected string to have >=3 characters" && type.status === 400 && type.json.message === "Invalid input: expected boolean, received string"
    && on.status === 200 && keys(on.json.organization.openworkWebAccess) === "accessSource,complimentaryAccess,hasAccess,hasEligibleSubscription,hasOngoingSubscription,subscriptionStatus"
    && on.json.organization.openworkWebAccess.accessSource === "complimentary" && on.json.organization.openworkWebAccess.hasAccess === true
    && list.openworkWebAccess.complimentaryAccess === true && caps.openworkWeb === true
    && off.json.organization.openworkWebAccess.hasAccess === false && off.json.organization.openworkWebAccess.accessSource === null || JSON.stringify([short.json, type.json, on.json, list.openworkWebAccess, caps]);
});

// ---- features: per organization -------------------------------------------------------------------------------------------------------
const caps = (b) => g(`/v1/admin/organizations/${ws.orgId}/capabilities`, "PUT", b);
await t("capabilities: every feature with its source and what an override would do", async () => {
  const r = await g(`/v1/admin/organizations/${ws.orgId}/capabilities`);
  const k = Object.keys(r.json.capabilities);
  const st = r.json.featureStates[PROBE_FEATURE];
  return r.status === 200 && keys(r.json) === "capabilities,featureStates" && k.length === 57 && r.json.capabilities.gatewayDashboard === true && Object.keys(r.json.featureStates).length === 56
    && keys(st) === "enabled,everyone,killed,lastChange,lock,override,overrideApplies,source" && st.source === "everyone" && st.enabled === false && st.override === null && st.overrideApplies === true && st.lastChange?.scope !== "organization"
    && r.json.featureStates.autoRouter.source === "unavailable" && r.json.featureStates.autoRouter.overrideApplies === false || r.text.slice(0, 400);
});
await t("capabilities: body validation (an object, true, false or null per key; cloud-only keys refused; unknown keys ignored)", async () => {
  const none = await caps({});
  const nul = await caps(null);
  const type = await caps({ capabilities: { [PROBE_FEATURE]: "yes" } });
  const cloud = await caps({ capabilities: { autoRouter: true } });
  const bad = await g("/v1/admin/organizations/xyz/capabilities", "PUT", { capabilities: {} });
  const unknown = await g("/v1/admin/organizations/org_01m68tknxje18aqs60j2j437zz/capabilities", "PUT", { capabilities: {} });
  const ignored = await caps({ capabilities: { notAFeature: true } });
  return none.status === 400 && none.json.message === "Invalid input: expected object, received undefined" && nul.json.message === "Invalid input: expected object, received null"
    && type.json.message === "Invalid input: expected boolean, received string" && cloud.status === 400 && cloud.json.message === "autoRouter is not part of this deployment."
    && bad.status === 400 && unknown.status === 404 && ignored.status === 200 || JSON.stringify([none.json, nul.json, type.json, cloud.json, bad.status, unknown.status, ignored.status]);
});
await t("capabilities: an override takes effect for that organization only, through GET /v1/org, and is cleared with null", async () => {
  const before = (await orgOf()).features;
  const on = await caps({ capabilities: { [PROBE_FEATURE]: true, mermaidZoom: false, browserFloatingView: null } });
  const st = on.json.featureStates;
  const mine = (await orgOf()).features;
  const theirs = (await as(noWorkspace, "/v1/me")).status; // another person's workspace is untouched: check through the public flags too
  const publicFlags = (await call(A, "/v1/features")).json.features;
  const cleared = await caps({ capabilities: { [PROBE_FEATURE]: null, mermaidZoom: null } });
  const after = (await orgOf()).features;
  return on.status === 200 && keys(on.json) === "capabilities,featureStates,ok,organization" && on.json.capabilities[PROBE_FEATURE] === true && st[PROBE_FEATURE].source === "override" && st[PROBE_FEATURE].override === true && st[PROBE_FEATURE].everyone === false
    && keys(st[PROBE_FEATURE].lastChange) === "action,at,by,scope" && st[PROBE_FEATURE].lastChange.scope === "organization" && st[PROBE_FEATURE].lastChange.action === "on" && keys(st[PROBE_FEATURE].lastChange.by) === "email,id,name" && st[PROBE_FEATURE].lastChange.by.email === ADMIN_EMAIL
    && st.mermaidZoom.enabled === false && st.mermaidZoom.everyone === true && st.mermaidZoom.lastChange.action === "off"
    && before[PROBE_FEATURE] === false && mine[PROBE_FEATURE] === true && before.mermaidZoom === true && mine.mermaidZoom === false && theirs === 200 && publicFlags[PROBE_FEATURE] === false
    && cleared.json.featureStates[PROBE_FEATURE].source === "everyone" && cleared.json.featureStates[PROBE_FEATURE].lastChange.action === "reset" && after[PROBE_FEATURE] === false && after.mermaidZoom === true
    || JSON.stringify([before[PROBE_FEATURE], mine[PROBE_FEATURE], mine.mermaidZoom, publicFlags[PROBE_FEATURE], st[PROBE_FEATURE]]);
});
await t("capabilities: another workspace never sees this workspace's overrides", async () => {
  const other = await workspace("Platform Admin Other");
  const before = (await other.api(other.owner, "GET", "/v1/org")).json.features[PROBE_FEATURE];
  await caps({ capabilities: { [PROBE_FEATURE]: true } });
  const mine = (await orgOf()).features[PROBE_FEATURE];
  const theirs = (await other.api(other.owner, "GET", "/v1/org")).json.features[PROBE_FEATURE];
  await caps({ capabilities: { [PROBE_FEATURE]: null } });
  return before === false && mine === true && theirs === false || JSON.stringify({ before, mine, theirs });
});

// ---- features: deployment-wide ---------------------------------------------------------------------------------------------------------
await t("features: the registry with one entry per feature, its default and what is fixed in code", async () => {
  const r = await g("/v1/admin/features");
  const f = r.json.features.find((x) => x.key === PROBE_FEATURE);
  const cloud = r.json.features.find((x) => x.key === "autoRouter");
  return r.status === 200 && keys(r.json) === "deployment,features" && r.json.deployment === "self_hosted" && r.json.features.length === 56
    && keys(f) === "added,author,available,category,categoryLabel,default,deployments,description,docs,docsUrl,enabled,key,killed,label,lastChange,lock,since"
    && f.default === false && f.available === true && f.enabled === false && f.killed === false && f.lock === null && f.deployments.includes("self_hosted")
    && cloud.available === false && cloud.deployments.join() === "cloud" && new Set(r.json.features.map((x) => x.key)).size === 56 || r.text.slice(0, 400);
});
await t("features: the body is validated (strict, boolean, at least one field) and unknown or cloud-only features refused", async () => {
  const put = (key, b) => g(`/v1/admin/features/${key}`, "PUT", b);
  const unknown = await put("nope", { enabled: true });
  const empty = await put(PROBE_FEATURE, {});
  const extra = await put(PROBE_FEATURE, { enabled: true, zzz: 1 });
  const type = await put(PROBE_FEATURE, { enabled: "x" });
  const nul = await put(PROBE_FEATURE, null);
  const cloud = await put("autoRouter", { enabled: true });
  const msgs = [unknown, empty, extra, type, nul, cloud].map((r) => r.status + r.json?.message);
  return msgs.join("|") === ["400Unknown feature.", "400Set enabled, killed, or both.", '400Unrecognized key: "zzz"', "400Invalid input: expected boolean, received string", "400Invalid input: expected object, received null", "400autoRouter is not part of this deployment."].join("|") || msgs.join("|");
});
await t("features: on for everyone shows in GET /v1/features and in every workspace; off again; the kill switch beats an organization override", async () => {
  const put = (b) => g(`/v1/admin/features/${PROBE_FEATURE}`, "PUT", b);
  const start = (await g("/v1/admin/features")).json.features.find((x) => x.key === PROBE_FEATURE);
  if (start.enabled || start.killed) throw new Error("the probe feature is not in its default state; reset it first");
  try {
    const on = await put({ enabled: true });
    const f = on.json.feature;
    const pub = (await call(A, "/v1/features")).json.features[PROBE_FEATURE];
    const mine = (await orgOf()).features[PROBE_FEATURE];
    await caps({ capabilities: { [PROBE_FEATURE]: false } });
    const overridden = (await orgOf()).features[PROBE_FEATURE];
    const killed = await put({ killed: true });
    await caps({ capabilities: { [PROBE_FEATURE]: true } });
    const afterKill = (await orgOf()).features[PROBE_FEATURE];
    const pubKilled = (await call(A, "/v1/features")).json.features[PROBE_FEATURE];
    const state = (await g(`/v1/admin/organizations/${ws.orgId}/capabilities`)).json.featureStates[PROBE_FEATURE];
    await put({ killed: false });
    const restored = (await g("/v1/admin/features")).json.features.find((x) => x.key === PROBE_FEATURE);
    return on.status === 200 && keys(on.json) === "feature,ok" && f.enabled === true && f.killed === false && f.lastChange.scope === "everyone" && f.lastChange.action === "on" && f.lastChange.by.email === ADMIN_EMAIL
      && pub === true && mine === true && overridden === false && killed.json.feature.killed === true && killed.json.feature.lastChange.action === "killed"
      && afterKill === false && pubKilled === false && state.source === "killed" && state.overrideApplies === false && state.override === true
      && restored.killed === false && restored.enabled === true && restored.lastChange.action === "restored" || JSON.stringify({ f, pub, mine, overridden, afterKill, pubKilled, state, restored });
  } finally {
    await put({ enabled: false, killed: false });
    await caps({ capabilities: { [PROBE_FEATURE]: null } });
  }
  return true;
});
await t("features: back to off, nothing left over", async () => {
  const f = (await g("/v1/admin/features")).json.features.find((x) => x.key === PROBE_FEATURE);
  const pub = (await call(A, "/v1/features")).json.features[PROBE_FEATURE];
  const mine = (await orgOf()).features[PROBE_FEATURE];
  return f.enabled === false && f.killed === false && pub === false && mine === false || JSON.stringify({ f, pub, mine });
});

// ---- the admin list ---------------------------------------------------------------------------------------------------------------------
await t("admins: add (the address is lower-cased), list, refuse a duplicate, and refuse bad input", async () => {
  const email = `Second.Admin.${Date.now()}@Example.com`;
  const r = await g("/v1/admin/admins", "POST", { email, note: "second" });
  const dup = await g("/v1/admin/admins", "POST", { email: email.toLowerCase() });
  const bad = await g("/v1/admin/admins", "POST", { email: "nope" });
  const missing = await g("/v1/admin/admins", "POST", {});
  const long = await g("/v1/admin/admins", "POST", { email: "a@example.com", note: "x".repeat(256) });
  const list = (await g("/v1/admin/overview?limit=1")).json.admins;
  globalThis.secondAdmin = { email: email.toLowerCase(), id: r.json?.admin?.id };
  return r.status === 200 && keys(r.json.admin) === "createdAt,email,id,note" && r.json.admin.email === email.toLowerCase() && r.json.admin.note === "second" && r.json.admin.id.startsWith("aal_")
    && dup.status === 409 && dup.json.error === "conflict" && dup.json.message === `An admin with email ${email.toLowerCase()} already exists.`
    && bad.status === 400 && bad.json.message === "Invalid email address" && missing.status === 400 && missing.json.message === "Invalid input: expected string, received undefined"
    && long.status === 400 && long.json.message === "Too big: expected string to have <=255 characters" && list.some((a) => a.email === email.toLowerCase()) || JSON.stringify([r.json, dup.json, bad.json, missing.json, long.json]);
});
await t("admins: a newly added address is an admin as soon as that person signs in, and loses access the moment it is removed", async () => {
  const second = await person("Second Admin");
  const add = await g("/v1/admin/admins", "POST", { email: second.email.toUpperCase() });
  const before = await as(second, "/v1/admin/features");
  const del = await g(`/v1/admin/admins/${add.json.admin.id}`, "DELETE");
  const after = await as(second, "/v1/admin/features");
  return add.status === 200 && before.status === 200 && del.status === 200 && del.json.ok === true && after.status === 403 && after.json.error === "forbidden" || JSON.stringify([add.status, before.status, del.json, after.status]);
});
await t("admins: removal is validated (bad id 400, unknown 404, not yourself)", async () => {
  const bad = await g("/v1/admin/admins/xyz", "DELETE");
  const unknown = await g("/v1/admin/admins/aal_01jzzzzzzzzzzzzzzzzzzzzzzq", "DELETE");
  const me = (await g("/v1/admin/overview?limit=1")).json.admins.find((a) => a.email === ADMIN_EMAIL);
  const self = await g(`/v1/admin/admins/${me.id}`, "DELETE");
  const still = await g("/v1/admin/overview?limit=1");
  return bad.status === 400 && bad.json.message === "Invalid admin id." && unknown.status === 404 && unknown.json.message === "Admin not found."
    && self.status === 400 && self.json.message === "You cannot delete your own admin access." && still.status === 200 || JSON.stringify([bad.json, unknown.json, self.json]);
});

// ---- metrics ---------------------------------------------------------------------------------------------------------------------------
await t("metrics: the deferred numbers computed from the data (users, activity series of 30 days)", async () => {
  const r = await g("/v1/admin/metrics");
  const m = r.json?.summary;
  const today = new Date().toISOString().slice(0, 10);
  return r.status === 200 && keys(r.json) === "generatedAt,summary" && m.totalUsers >= 5 && m.totalOrganizations >= 2 && m.verifiedUsers <= m.totalUsers && m.recentUsers7d >= 5 && m.recentUsers30d >= m.recentUsers7d
    && m.adminCount >= 1 && m.billingLoaded === false && m.activeUsers1d >= 5 && m.activeUsers7d >= m.activeUsers1d && m.activeUsers30d >= m.activeUsers7d && m.inviters >= 1
    && m.activitySeries.length === 30 && keys(m.activitySeries[0]) === "activeUsers,day,realActiveUsers,signups" && m.activitySeries.at(-1).day === today && m.activitySeries.at(-1).signups >= 5
    && m.usersWithoutWorkers >= 0 || r.text.slice(0, 600);
});

// ---- deleting a user --------------------------------------------------------------------------------------------------------------------
await t("delete user: refused for yourself, a malformed id and an unknown user", async () => {
  const self = await g(`/v1/admin/users/${admin.userId}`, "DELETE");
  const bad = await g("/v1/admin/users/xyz", "DELETE");
  const unknown = await g("/v1/admin/users/usr_01m68tknxje18aqs60j2j437zz", "DELETE");
  return self.status === 400 && self.json.message === "You cannot delete your own admin user." && bad.status === 400 && bad.json.message === "Invalid user id."
    && unknown.status === 404 && unknown.json.message === "User not found." && (await g("/v1/admin/overview?limit=1")).status === 200 || JSON.stringify([self.json, bad.json, unknown.json]);
});
await t("delete user: sessions end, the person leaves every workspace, cannot sign in again; other people are untouched", async () => {
  const before = (await g("/v1/admin/overview?limit=1")).json.userPage.total;
  const meBefore = await as(member, "/v1/me");
  const del = await g(`/v1/admin/users/${member.userId}`, "DELETE");
  const meAfter = await as(member, "/v1/me");
  const org = await orgOf();
  const search = await g(`/v1/admin/users?search=${encodeURIComponent(member.email)}`);
  const signIn = await call(W, "/api/auth/sign-in/email", { method: "POST", body: { email: member.email, password: PW } });
  const after = (await g("/v1/admin/overview?limit=1")).json.userPage.total;
  const detail = (await g(`/v1/admin/organizations/${ws.orgId}?limit=10`)).json;
  return meBefore.status === 200 && del.status === 200 && keys(del.json) === "ok,user" && del.json.user.id === member.userId && del.json.user.email === member.email
    && meAfter.status === 401 && !org.members.some((m) => m.userId === member.userId) && org.members.length === 2 && search.json.page.total === 0
    && signIn.status === 401 && after === before - 1 && detail.organization.memberCount === 2 && (await as(owner, "/v1/me")).status === 200 && (await as(adminRoleMember, "/v1/me")).status === 200 || JSON.stringify({ del: del.json, meAfter: meAfter.status, signIn: signIn.status, before, after });
});

s.done();
