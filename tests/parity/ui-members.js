// Members, roles and invitations in a real browser against the rewrite.
//   W=http://localhost:5081 A=http://localhost:5080 node ui-members.js [screenshot-dir]
const { chromium } = require('playwright');
const W = process.env.W || 'http://localhost:5081';
const A = process.env.A || 'http://localhost:5080';
const PW = 'Str0ng!Passw0rd#2026x';
const shots = process.argv[2];
let pass = 0, fail = 0;
const check = (name, ok, detail = '') => { ok ? pass++ : fail++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '  -> ' + detail}`); };
const uniq = (p) => `${p}.${Date.now()}.${Math.floor(Math.random() * 1e4)}@example.com`;
const post = async (path, body, token) => {
  const r = await fetch(A + path, { method: 'POST', headers: { 'content-type': 'application/json', origin: W, ...(token ? { authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify(body) });
  return { status: r.status, json: await r.json().catch(() => null) };
};
const text = (page) => page.locator('body').innerText();

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

  // Owner and a workspace, set up through the API so the browser steps are only about members.
  const owner = uniq('owner');
  const up = await post('/api/auth/sign-up/email', { name: 'Olive Owner', email: owner, password: PW });
  const org = await post('/v1/org', { name: 'Members Workspace' }, up.json.token);
  check('setup: owner and workspace exist', org.status === 201 || org.status === 200, JSON.stringify(org));

  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const page = await ctx.newPage(); page.on('pageerror', e => errors.push(String(e).slice(0, 120)));
  await signIn(page, owner);
  await page.getByTestId('members-link').click();
  await page.getByTestId('members-page').waitFor({ timeout: 30000 });
  await page.getByTestId('member-row').first().waitFor({ timeout: 30000 });
  check('owner reaches Members from the dashboard', /\/dashboard\/members/.test(page.url()));
  const rows = await page.getByTestId('member-row').all();
  check('only the owner is listed at first', rows.length === 1 && (await rows[0].getAttribute('data-role')) === 'owner');
  check('the owner has no role/remove controls on their own row', (await rows[0].locator('button, select').count()) === 0);

  // Invite someone.
  const invited = uniq('invitee');
  await page.locator('#invite-email').fill('not-an-email');
  await page.getByRole('button', { name: 'Send invitation' }).click();
  check('a bad address is rejected before sending', /email address/i.test(await page.getByTestId('error').innerText()));
  await page.locator('#invite-email').fill(invited);
  await page.getByRole('button', { name: 'Send invitation' }).click();
  await page.getByTestId('notice').waitFor({ timeout: 15000 });
  check('inviting shows a confirmation', (await page.getByTestId('notice').innerText()).includes(invited));
  const pending = page.locator(`[data-testid="member-row"][data-email="${invited}"]`);
  await pending.waitFor({ timeout: 15000 });
  check('the invitation appears as Pending', (await pending.getAttribute('data-pending')) === 'true' && /Pending/.test(await pending.innerText()));
  if (shots) await page.screenshot({ path: shots + '/ui-members-pending.png' });

  await pending.getByRole('button', { name: 'Copy link' }).click();
  await page.getByTestId('invite-link').waitFor({ timeout: 15000 });
  const link = await page.getByTestId('invite-link').inputValue();
  check('the invitation link points at the join page', link.startsWith(W + '/join-org?invite='), link);

  // The invitee opens the link signed out, creates the account, and joins.
  const ctx2 = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const page2 = await ctx2.newPage(); page2.on('pageerror', e => errors.push(String(e).slice(0, 120)));
  await page2.goto(link, { waitUntil: 'networkidle', timeout: 120000 });
  await page2.getByTestId('join-org').getByText(/Join Members Workspace/).waitFor({ timeout: 30000 });
  check('the link shows the workspace and the invited address', (await page2.getByTestId('join-email').innerText()) === invited);
  if (shots) await page2.screenshot({ path: shots + '/ui-join.png' });
  await page2.getByRole('button', { name: /Continue with/ }).click();
  await page2.locator('input[type="password"]').waitFor({ timeout: 30000 });
  check('the invited address is already filled in and goes straight to sign-up', (await page2.getByRole('button', { name: 'Sign up', exact: true }).count()) === 1);
  await page2.locator('input[type="password"]').fill(PW);
  const nm = page2.locator('input[autocomplete="name"]'); if (await nm.count()) await nm.fill('Ivy Invitee');
  await page2.getByRole('button', { name: 'Sign up', exact: true }).click();
  await page2.waitForURL(/\/join-org/, { timeout: 60000 });
  await page2.getByRole('button', { name: /^Join Members Workspace$/ }).click();
  await page2.waitForURL(/\/dashboard/, { timeout: 60000 });
  check('after joining the invitee lands on the dashboard', true);
  const orgRes = await page2.evaluate(async () => (await (await fetch('/api/browser/v1/org', { credentials: 'include' })).json()).currentMember.role);
  check('the invitee is a member', orgRes === 'member', String(orgRes));

  // A different signed-in person following the same (now used) link is told it is no longer valid.
  const ctx3 = await browser.newContext(); const page3 = await ctx3.newPage();
  await page3.goto(link, { waitUntil: 'networkidle', timeout: 120000 });
  await page3.getByTestId('join-unusable').waitFor({ timeout: 30000 });
  check('a used invitation says it can no longer be used', /accepted|used/i.test(await page3.getByTestId('join-unusable').innerText()), await text(page3));
  await ctx3.close();

  // Owner promotes, demotes and removes.
  await page.reload({ waitUntil: 'networkidle' });
  const row = page.locator(`[data-testid="member-row"][data-email="${invited}"]`);
  await row.waitFor({ timeout: 30000 });
  check('the member is no longer Pending', (await row.getAttribute('data-pending')) === 'false' && (await row.getAttribute('data-role')) === 'member');
  await row.locator('select').selectOption('admin');
  await page.getByTestId('notice').filter({ hasText: /is now an admin/ }).waitFor({ timeout: 15000 });
  check('promoting to admin updates the row', (await page.locator(`[data-testid="member-row"][data-email="${invited}"]`).getAttribute('data-role')) === 'admin');
  if (shots) await page.screenshot({ path: shots + '/ui-members-admin.png' });

  // The admin sees the page but cannot transfer ownership or change the owner.
  await page2.goto(W + '/dashboard/members', { waitUntil: 'networkidle' });
  await page2.getByTestId('member-row').first().waitFor({ timeout: 30000 });
  check('an admin cannot see "Make owner"', (await page2.getByRole('button', { name: 'Make owner' }).count()) === 0);
  const ownerRow = page2.locator(`[data-testid="member-row"][data-role="owner"]`);
  check('an admin gets no controls on the owner row', (await ownerRow.locator('button, select').count()) === 0);

  await page.locator(`[data-testid="member-row"][data-email="${invited}"] select`).selectOption('member');
  await page.getByTestId('notice').filter({ hasText: /is now a member/ }).waitFor({ timeout: 15000 });
  check('demoting back to member works', (await page.locator(`[data-testid="member-row"][data-email="${invited}"]`).getAttribute('data-role')) === 'member');

  const target = page.locator(`[data-testid="member-row"][data-email="${invited}"]`);
  await target.getByRole('button', { name: 'Remove', exact: true }).click();
  await target.getByRole('button', { name: 'Confirm remove' }).waitFor({ timeout: 10000 });
  check('removing asks for confirmation first', (await target.getByRole('button', { name: 'Confirm remove' }).count()) === 1);
  await target.getByRole('button', { name: 'Confirm remove' }).click();
  await page.getByTestId('notice').filter({ hasText: /was removed/ }).waitFor({ timeout: 15000 });
  check('the removed member disappears from the list', (await page.locator(`[data-testid="member-row"][data-email="${invited}"]`).count()) === 0);
  const gone = await page2.evaluate(async () => (await fetch('/api/browser/v1/me', { credentials: 'include' })).status);
  check('the removed person is signed out of the workspace (session revoked)', gone === 401, String(gone));

  // Cancel an invitation.
  const second = uniq('cancel');
  await page.locator('#invite-email').fill(second);
  await page.getByRole('button', { name: 'Send invitation' }).click();
  const pending2 = page.locator(`[data-testid="member-row"][data-email="${second}"]`);
  await pending2.waitFor({ timeout: 15000 });
  await pending2.getByRole('button', { name: 'Cancel invitation' }).click();
  await page.getByTestId('notice').filter({ hasText: /was canceled/ }).waitFor({ timeout: 15000 });
  check('canceling removes the pending row', (await page.locator(`[data-testid="member-row"][data-email="${second}"]`).count()) === 0);

  // Wrong account following an invitation.
  const third = uniq('wrong');
  const sent = await post('/v1/invitations', { email: third, role: 'member' }, up.json.token);
  const wrongLink = (await (await fetch(`${A}/v1/invitations/${sent.json.invitationId}/link`, { headers: { authorization: `Bearer ${up.json.token}` } })).json()).inviteLink;
  await page.goto(wrongLink, { waitUntil: 'networkidle' });
  await page.getByTestId('join-wrong-account').waitFor({ timeout: 30000 });
  check('signed in as someone else shows a clear "for someone else" message', (await text(page)).includes(third) && (await text(page)).includes(owner));

  // Missing token.
  await page.goto(W + '/join-org?invite=nope', { waitUntil: 'networkidle' });
  await page.getByTestId('join-missing').waitFor({ timeout: 30000 });
  check('an unknown invitation says it was not found', true);

  check('no page errors', errors.length === 0, errors.join(' | '));
  console.log(`\n${pass} passed, ${fail} failed`);
  await browser.close();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('UI FAIL', e.message.slice(0, 500)); process.exit(1); });
