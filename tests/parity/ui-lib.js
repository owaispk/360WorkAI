// Shared helpers for per-area browser tests (tests/parity/ui-<name>.js). See ../../docs/AREA_GUIDE.md.
//   W=http://localhost:5081 A=http://localhost:5080 node ui-<name>.js [screenshot-dir]
const W = process.env.W || 'http://localhost:5081';
const A = process.env.A || 'http://localhost:5080';
const PW = 'Str0ng!Passw0rd#2026x';
let pass = 0, fail = 0;
const check = (name, ok, detail = '') => { ok ? pass++ : fail++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '  -> ' + detail}`); };
const uniq = (p) => `${p}.${Date.now()}.${Math.floor(Math.random() * 1e4)}@example.com`;
const api = async (method, path, body, token, org) => {
  const r = await fetch(A + path, { method, headers: { 'content-type': 'application/json', origin: W, ...(token ? { authorization: `Bearer ${token}` } : {}), ...(org ? { 'x-openwork-org-id': org } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const text = await r.text(); let json = null; try { json = JSON.parse(text); } catch {}
  return { status: r.status, json };
};
const person = async (name) => { const email = uniq(name.toLowerCase().replace(/\s+/g, '.')); const r = await api('POST', '/api/auth/sign-up/email', { name, email, password: PW }); return { name, email, token: r.json.token }; };
/** An owner with a workspace, plus `join(name, role)` for people who accept an invitation. */
const workspace = async (name = 'Area Workspace') => {
  const owner = await person('Olive Owner');
  const orgId = (await api('POST', '/v1/org', { name }, owner.token)).json.organization.id;
  const join = async (n, role = 'member') => {
    const u = await person(n);
    const inv = await api('POST', '/v1/invitations', { email: u.email, role }, owner.token, orgId);
    await api('POST', '/v1/orgs/invitations/accept', { id: inv.json.invitationId }, u.token);
    u.memberId = (await api('GET', '/v1/org', null, owner.token, orgId)).json.members.find((m) => m.user.email === u.email).id;
    return u;
  };
  return { owner, orgId, join, api: (u, method, path, body) => api(method, path, body, u.token, orgId) };
};
/** Polls until fn() is truthy (a notice from an earlier action can still be on screen, so wait for the effect itself). */
const until = async (fn, ms = 10000) => { const end = Date.now() + ms; let last; while (Date.now() < end) { last = await fn(); if (last) return last; await new Promise((r) => setTimeout(r, 150)); } return last; };
async function signIn(page, email) {
  await page.goto(W + '/', { waitUntil: 'networkidle', timeout: 120000 });
  await page.locator('input[type="email"]').fill(email);
  await page.getByRole('button', { name: /^next$/i }).click();
  await page.locator('input[type="password"]').waitFor({ timeout: 30000 });
  await page.locator('input[type="password"]').fill(PW);
  await page.getByRole('button', { name: /^sign in$/i }).click();
  await page.waitForURL(/\/dashboard/, { timeout: 60000 });
}
const finish = async (browser, errors) => {
  check('no page errors', errors.length === 0, errors.join(' | '));
  console.log(`\n${pass} passed, ${fail} failed`);
  await browser.close();
  process.exit(fail ? 1 : 0);
};
module.exports = { W, A, PW, check, uniq, api, person, workspace, until, signIn, finish };
