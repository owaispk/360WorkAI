// Teams and permissions in a real browser against the rewrite.
//   W=http://localhost:5081 A=http://localhost:5080 node ui-teams.js [screenshot-dir]
const { chromium } = require('playwright');
const W = process.env.W || 'http://localhost:5081';
const A = process.env.A || 'http://localhost:5080';
const PW = 'Str0ng!Passw0rd#2026x';
const shots = process.argv[2];
let pass = 0, fail = 0;
const check = (name, ok, detail = '') => { ok ? pass++ : fail++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '  -> ' + detail}`); };
const uniq = (p) => `${p}.${Date.now()}.${Math.floor(Math.random() * 1e4)}@example.com`;
const api = async (method, path, body, token, org) => {
  const r = await fetch(A + path, { method, headers: { 'content-type': 'application/json', origin: W, ...(token ? { authorization: `Bearer ${token}` } : {}), ...(org ? { 'x-openwork-org-id': org } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const text = await r.text(); let json = null; try { json = JSON.parse(text); } catch {}
  return { status: r.status, json };
};
const person = async (name) => { const email = uniq(name.toLowerCase().replace(/\s+/g, '.')); const r = await api('POST', '/api/auth/sign-up/email', { name, email, password: PW }); return { name, email, token: r.json.token }; };
const text = (page) => page.locator('body').innerText();
// Waits for something to become true (the notice text from an earlier save can still be on screen, so check the effect itself).
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

(async () => {
  const browser = await chromium.launch();
  const errors = [];

  const owner = await person('Olive Owner');
  const org = (await api('POST', '/v1/org', { name: 'Teams Workspace' }, owner.token)).json.organization.id;
  const join = async (name) => {
    const u = await person(name);
    const inv = await api('POST', '/v1/invitations', { email: u.email, role: 'member' }, owner.token, org);
    await api('POST', '/v1/orgs/invitations/accept', { id: inv.json.invitationId }, u.token);
    u.mid = (await api('GET', '/v1/org', null, owner.token, org)).json.members.find((m) => m.user.email === u.email).id;
    return u;
  };
  const mia = await join('Mia Member'); const bob = await join('Bob Builder');
  const perms = async (u) => (await api('GET', '/v1/org', null, u.token, org)).json.currentMember.permissions;

  const ctx = await browser.newContext({ viewport: { width: 1280, height: 1000 } });
  const page = await ctx.newPage(); page.on('pageerror', (e) => errors.push(String(e).slice(0, 120)));
  await signIn(page, owner.email);
  await page.getByTestId('teams-link').click();
  await page.getByTestId('teams-page').waitFor({ timeout: 30000 });
  await page.getByTestId('no-teams').waitFor({ timeout: 15000 });
  check('owner opens Teams from the dashboard and sees an empty list', /\/dashboard\/teams/.test(page.url()));

  // Create a team, put Mia in it.
  await page.locator('#team-name').fill('Design');
  await page.getByRole('button', { name: 'Create team' }).click();
  const row = page.locator('[data-testid="team-row"][data-name="Design"]');
  await row.waitFor({ timeout: 15000 });
  check('creating a team shows it with "No one yet"', /No one yet/.test(await row.innerText()) && (await page.getByTestId('notice').innerText()).includes('Design'));
  await row.getByRole('button', { name: 'Edit people' }).click();
  await page.getByTestId('people-panel').waitFor({ timeout: 10000 });
  await page.locator(`input[data-email="${mia.email}"]`).check();
  await page.getByRole('button', { name: 'Save people' }).click();
  await page.getByTestId('notice').filter({ hasText: /People in Design saved/ }).waitFor({ timeout: 15000 });
  check('adding a person lists them in the team', /Mia Member/.test(await page.locator('[data-testid="team-row"][data-name="Design"] [data-testid="team-people"]').innerText()));
  if (shots) await page.screenshot({ path: shots + '/ui-teams.png' });

  // A duplicate name is explained.
  await page.locator('#team-name').fill('design');
  await page.getByRole('button', { name: 'Create team' }).click();
  await page.getByTestId('error').waitFor({ timeout: 15000 });
  check('a duplicate team name is refused with a clear message', /already exists/.test(await page.getByTestId('error').innerText()));

  // An Admin team makes its members admins.
  await page.locator('#team-name').fill('Ops');
  await page.locator('#team-admin').check();
  await page.getByRole('button', { name: 'Create team' }).click();
  const ops = page.locator('[data-testid="team-row"][data-name="Ops"]');
  await ops.waitFor({ timeout: 15000 });
  check('an Admin team is marked as one', (await ops.getAttribute('data-admin')) === 'true' && /Admin team/.test(await ops.innerText()));
  await ops.getByRole('button', { name: 'Edit people' }).click();
  await page.locator(`input[data-email="${bob.email}"]`).check();
  await page.getByRole('button', { name: 'Save people' }).click();
  await page.getByTestId('notice').filter({ hasText: /People in Ops saved/ }).waitFor({ timeout: 15000 });
  const bobOrg = (await api('GET', '/v1/org', null, bob.token, org)).json.currentMember;
  check('someone in an Admin team becomes an effective admin', bobOrg.role === 'member,admin' && bobOrg.permissions.length === 43, JSON.stringify(bobOrg).slice(0, 200));

  // Rename.
  await row.getByRole('button', { name: 'Rename' }).click();
  await page.getByTestId('rename-input').fill('Design Team');
  await page.getByRole('button', { name: 'Save', exact: true }).click();
  await page.locator('[data-testid="team-row"][data-name="Design Team"]').waitFor({ timeout: 15000 });
  check('renaming a team updates the list', true);

  // Permissions for the team.
  await page.locator('[data-testid="team-row"][data-name="Design Team"]').getByRole('link', { name: 'Permissions' }).click();
  await page.getByTestId('permissions-page').waitFor({ timeout: 30000 });
  await page.getByTestId('set-row').first().waitFor({ timeout: 15000 });
  const kinds = await page.getByTestId('set-row').evaluateAll((els) => els.map((e) => e.getAttribute('data-kind')));
  check('the page lists Member and Admin permissions first', kinds[0] === 'member_default' && kinds[1] === 'admin_default', kinds.join());
  await page.locator('[data-testid="setup-role"][data-team="Design Team"]').click();
  await page.getByTestId('detail-name').waitFor({ timeout: 15000 });
  check('setting up permissions for a team creates its own role', /Design Team Permissions/.test(await page.getByTestId('detail-name').innerText()));
  await page.locator('[data-key="prompts.view"] input').check();
  await page.locator('[data-key="teams.view"] input').check();
  if (shots) await page.screenshot({ path: shots + '/ui-permissions.png', fullPage: true });
  await page.getByTestId('save-permissions').click();
  const saved = await until(async () => (await perms(mia)).sort().join() === 'prompts.view,teams.view');
  check('saving turns the permissions on for the team\'s members', saved, (await perms(mia)).join());
  await page.getByTestId('notice').filter({ hasText: /Permissions saved/ }).waitFor({ timeout: 15000 });
  await page.waitForTimeout(500);

  // The member sees teams read-only, and no permissions page.
  const ctx2 = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const page2 = await ctx2.newPage(); page2.on('pageerror', (e) => errors.push(String(e).slice(0, 120)));
  await signIn(page2, mia.email);
  await page2.goto(W + '/dashboard/teams', { waitUntil: 'networkidle' });
  await page2.getByTestId('team-row').first().waitFor({ timeout: 30000 });
  check('a member sees the teams but gets no controls to change them', (await page2.getByRole('button', { name: 'Edit people' }).count()) === 0 && (await page2.locator('#team-name').count()) === 0 && (await page2.getByRole('button', { name: 'Delete' }).count()) === 0);
  await page2.goto(W + '/dashboard/permissions', { waitUntil: 'networkidle' });
  await page2.getByTestId('no-access').waitFor({ timeout: 30000 });
  check('a member without permissions.view is told they have no access', /don't have access/.test(await page2.getByTestId('no-access').innerText()));

  // Turning a permission off takes it away at once.
  await page.locator('[data-key="teams.view"] input').uncheck();
  await page.getByTestId('save-permissions').click();
  const off = await until(async () => (await perms(mia)).join() === 'prompts.view');
  check('turning one off removes it from the member immediately', off, (await perms(mia)).join());
  await page.waitForTimeout(800);

  // History shows the changes.
  await page.getByTestId('toggle-history').click();
  await page.getByTestId('history').getByText('View any team').first().waitFor({ timeout: 15000 });
  const history = await page.getByTestId('history').innerText();
  check('the history lists each change', /View any team/.test(history) && /View prompts/.test(history) && /Olive Owner/.test(history), history.slice(0, 200));

  // A shared role given to a team.
  await page.getByPlaceholder('New role name').fill('Reviewers');
  await page.getByRole('button', { name: 'Create a shared role' }).click();
  await page.getByTestId('detail-name').filter({ hasText: 'Reviewers' }).waitFor({ timeout: 15000 });
  await page.locator('[data-key="billing.view"] input').check();
  await page.getByTestId('save-permissions').click();
  await until(async () => (await api('GET', '/v1/permissions/sets', null, owner.token, org)).json.sets.find((x) => x.name === 'Reviewers')?.allowedCount === 1);
  await page.waitForTimeout(800);
  await page.locator('[data-testid="give-to"][data-team="Design Team"]').click();
  await page.getByTestId('notice').filter({ hasText: /Given to the team/ }).waitFor({ timeout: 15000 });
  check('a shared role given to a team replaces the team\'s own role', await until(async () => (await perms(mia)).join() === 'billing.view'), (await perms(mia)).join());

  // A change the server refuses is explained (Mia, who has permissions.manage by role, cannot turn on what she lacks).
  await api('PUT', `/v1/permissions/sets/${(await api('GET', '/v1/permissions/sets', null, owner.token, org)).json.sets.find((s) => s.name === 'Reviewers').id}/permissions`, { changes: [{ key: 'permissions.manage', status: 'allow' }, { key: 'permissions.view', status: 'allow' }] }, owner.token, org);
  await page2.goto(W + '/dashboard/permissions', { waitUntil: 'networkidle' });
  await page2.getByTestId('set-row').first().waitFor({ timeout: 30000 });
  await page2.locator('[data-testid="set-row"][data-name="Reviewers"]').getByRole('button', { name: 'Open' }).click();
  await page2.getByTestId('detail-name').waitFor({ timeout: 15000 });
  await page2.locator('[data-key="organization.update"] input').check();
  await page2.getByTestId('save-permissions').click();
  await page2.getByTestId('error').waitFor({ timeout: 15000 });
  check('turning on a permission you do not hold is refused and says why', /only turn on permissions you have yourself/i.test(await page2.getByTestId('error').innerText()), await page2.getByTestId('error').innerText());

  // Deleting a team asks first.
  await page.goto(W + '/dashboard/teams', { waitUntil: 'networkidle' });
  const design = page.locator('[data-testid="team-row"][data-name="Design Team"]');
  await design.waitFor({ timeout: 30000 });
  await design.getByRole('button', { name: 'Delete', exact: true }).click();
  await design.getByRole('button', { name: 'Confirm delete' }).waitFor({ timeout: 10000 });
  await design.getByRole('button', { name: 'Confirm delete' }).click();
  await page.getByTestId('notice').filter({ hasText: /was deleted/ }).waitFor({ timeout: 15000 });
  check('deleting a team removes it and its permissions stop applying', (await page.locator('[data-testid="team-row"][data-name="Design Team"]').count()) === 0 && (await perms(mia)).length === 0, (await perms(mia)).join());

  check('no page errors', errors.length === 0, errors.join(' | '));
  console.log(`\n${pass} passed, ${fail} failed`);
  await browser.close();
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('UI FAIL', e.message.slice(0, 600)); process.exit(1); });
