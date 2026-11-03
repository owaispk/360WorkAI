// Per-member feature overrides on /admin in a real browser. The API must list padmin.parity@example.com as a platform admin:
//   PlatformAdmin__BootstrapEmails=padmin.parity@example.com (see docs/features/platform-admin.md)
//   W=http://localhost:5081 A=http://localhost:5080 node tests/parity/ui-member-features.js [screenshot-dir]
const { chromium } = require('playwright');
const { W, PW, check, api, workspace, until, signIn, finish } = require('./ui-lib');
const shots = process.argv[2];
const ADMIN_EMAIL = process.env.PADMIN_EMAIL || 'padmin.parity@example.com';
const FEATURE = 'computerUseBackground';

(async () => {
  let r = await api('POST', '/api/auth/sign-up/email', { name: 'Platform Admin', email: ADMIN_EMAIL, password: PW });
  if (!r.json?.token) r = await api('POST', '/api/auth/sign-in/email', { email: ADMIN_EMAIL, password: PW });
  const adminToken = r.json.token;
  if (!(await api('GET', '/v1/me/orgs', null, adminToken)).json?.orgs?.length) await api('POST', '/v1/org', { name: 'Operators' }, adminToken);
  if ((await api('GET', '/v1/admin/overview?limit=1', null, adminToken)).status !== 200) { console.log(`${ADMIN_EMAIL} is not a platform admin`); process.exit(2); }

  const ws = await workspace(`Member Features ${Math.floor(Math.random() * 1e6).toString(36)}`);
  const casey = await ws.join('Casey Member');
  const dana = await ws.join('Dana Member');
  const feature = async (u) => (await ws.api(u, 'GET', '/v1/org')).json.features[FEATURE];

  const browser = await chromium.launch();
  const errors = [];
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const page = await ctx.newPage();
  page.on('pageerror', (e) => errors.push(String(e).slice(0, 160)));
  await signIn(page, ADMIN_EMAIL);

  await page.goto(`${W}/admin/organizations/${ws.orgId}`, { waitUntil: 'networkidle', timeout: 60000 });
  const row = page.getByTestId('person-row').filter({ hasText: casey.email });
  await row.getByTestId('person-features').click();
  await page.getByTestId('admin-member-features-page').waitFor({ timeout: 30000 });
  await page.getByTestId('member-override-list').waitFor({ timeout: 30000 });
  check('the workspace page links to a member\'s features', page.url().endsWith(`/members/${casey.memberId}`), page.url());
  check('the member page names the person', (await page.getByTestId('member-name').innerText()).includes('Casey'));

  check(`${FEATURE} starts off for Casey`, (await feature(casey)) === false);
  const select = page.locator(`[data-testid="member-override-row"][data-key="${FEATURE}"]`).getByTestId('member-override-select');
  await select.selectOption('on');
  await page.getByTestId('save-member-features').click();
  await page.getByTestId('notice').filter({ hasText: /Saved 1 feature setting/ }).waitFor({ timeout: 20000 });
  check('saving one setting says so', true);
  if (shots) await page.screenshot({ path: `${shots}/member-features.png`, fullPage: true });
  check(`${FEATURE} is on for Casey`, await until(async () => (await feature(casey)) === true));
  check(`${FEATURE} stays off for Dana and the owner`, (await feature(dana)) === false && (await feature(ws.owner)) === false);
  const rowText = await page.locator(`[data-testid="member-override-row"][data-key="${FEATURE}"]`).innerText();
  check('the row says on for them, from the member setting', /On for them \(member\)/.test(rowText), rowText);

  await select.selectOption('follow');
  await page.getByTestId('save-member-features').click();
  check(`following the workspace again turns ${FEATURE} back off`, await until(async () => (await feature(casey)) === false));

  // Somebody who is not a platform admin cannot open it.
  const other = await browser.newContext();
  const ownerPage = await other.newPage();
  await signIn(ownerPage, ws.owner.email);
  await ownerPage.goto(`${W}/admin/organizations/${ws.orgId}/members/${casey.memberId}`, { waitUntil: 'networkidle', timeout: 60000 });
  await ownerPage.getByTestId('no-access').waitFor({ timeout: 20000 });
  check('a workspace owner is shown "no access"', true);
  await finish(browser, errors);
})();
