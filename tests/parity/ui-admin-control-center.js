// The Control Center, the security request log and the dashboard's platform-admin link, in a real browser. The API must list
// padmin.parity@example.com as a platform admin:
//   PlatformAdmin__BootstrapEmails=padmin.parity@example.com (see docs/features/platform-admin.md)
//   W=http://localhost:5081 A=http://localhost:5080 node tests/parity/ui-admin-control-center.js [screenshot-dir]
const { chromium } = require('playwright');
const { W, PW, check, api, workspace, until, signIn, finish } = require('./ui-lib');
const shots = process.argv[2];
const ADMIN_EMAIL = process.env.PADMIN_EMAIL || 'padmin.parity@example.com';
const text = (page) => page.locator('body').innerText();

(async () => {
  let r = await api('POST', '/api/auth/sign-up/email', { name: 'Platform Admin', email: ADMIN_EMAIL, password: PW });
  if (!r.json?.token) r = await api('POST', '/api/auth/sign-in/email', { email: ADMIN_EMAIL, password: PW });
  const adminToken = r.json.token;
  if (!(await api('GET', '/v1/me/orgs', null, adminToken)).json?.orgs?.length) await api('POST', '/v1/org', { name: 'Operators' }, adminToken);
  if ((await api('GET', '/v1/admin/overview?limit=1', null, adminToken)).status !== 200) { console.log(`${ADMIN_EMAIL} is not a platform admin`); process.exit(2); }

  // Some activity: a team workspace with a member who used a feature, and refused sign-ins for the request log.
  const ws = await workspace(`Control Center ${Math.floor(Math.random() * 1e6).toString(36)}`);
  const member = await ws.join('Casey Member');
  await ws.api(member, 'POST', '/v1/org/feature-usage', { features: ['mermaidZoom'] });
  for (let i = 0; i < 2; i++) await api('POST', '/api/auth/sign-in/email', { email: 'nobody.cc@example.com', password: 'wrong-password' });

  const browser = await chromium.launch();
  const errors = [];
  const page = await (await browser.newContext({ viewport: { width: 1280, height: 900 } })).newPage();
  page.on('pageerror', (e) => errors.push(String(e).slice(0, 160)));
  await signIn(page, ADMIN_EMAIL);
  await page.getByTestId('platform-admin-link').waitFor({ timeout: 30000 });
  check('the dashboard offers platform admins a link to /admin', true);

  await page.goto(`${W}/admin/control-center`, { waitUntil: 'networkidle', timeout: 60000 });
  await page.getByTestId('admin-control-center-page').waitFor({ timeout: 30000 });
  await page.getByTestId('refresh').click();
  const refreshed = await until(async () => {
    await page.getByTestId('range-7d').click();
    return (await page.getByTestId('section-pulse').getAttribute('data-stale')) === 'false' && (await page.getByTestId('section-accounts').getAttribute('data-stale')) === 'false';
  }, 60000);
  check('refresh computes every section (pulse and accounts no longer stale)', refreshed);
  const activeWeek = Number((await page.getByTestId('active-week').innerText()).split('\n')[0]);
  check('people active in 7 days counts the people of this test', activeWeek >= 3, activeWeek);
  const accounts = await page.getByTestId('accounts').innerText();
  check('the workspace of this test is among the workspaces to watch', accounts.includes(ws.orgName ?? 'Control Center') || accounts.includes('Control Center'), accounts.slice(0, 200));
  check('revenue says there is no billing', /No billing runs/.test(await page.getByTestId('revenue-note').innerText()));
  if (shots) await page.screenshot({ path: `${shots}/admin-control-center.png`, fullPage: true });

  await page.getByTestId('refresh').click();
  await page.getByTestId('notice').filter({ hasText: /less than a minute/ }).waitFor({ timeout: 15000 });
  check('a second refresh within a minute is refused with a notice', true);
  await page.getByTestId('range-90d').click();
  check('switching range keeps the sections', await until(async () => (await page.locator('[data-testid^="section-"]').count()) === 6));

  // The security page shows the refused sign-ins (the log is written every couple of seconds).
  const seen = await until(async () => {
    await page.goto(`${W}/admin/security`, { waitUntil: 'networkidle', timeout: 60000 });
    await page.getByTestId('request-totals').waitFor({ timeout: 20000 });
    return (await page.locator('[data-testid="request-endpoint"][data-action="auth.sign_in.email"]').count()) === 1;
  }, 30000);
  check('the security page lists refused sign-ins by route', seen);
  check('no address appears on the security page', !/127\.0\.0\.1|nobody\.cc@example\.com/.test(await text(page)));
  if (shots) await page.screenshot({ path: `${shots}/admin-security-requests.png`, fullPage: true });

  // A workspace owner is not a platform admin: no link, no access.
  const ownerPage = await (await browser.newContext()).newPage();
  await signIn(ownerPage, ws.owner.email);
  await ownerPage.waitForTimeout(1500);
  check('the dashboard has no platform-admin link for a workspace owner', (await ownerPage.getByTestId('platform-admin-link').count()) === 0);
  await ownerPage.goto(`${W}/admin/control-center`, { waitUntil: 'networkidle', timeout: 60000 });
  await ownerPage.getByTestId('no-access').waitFor({ timeout: 20000 });
  check('a workspace owner is shown "no access" on the Control Center', true);
  await finish(browser, errors);
})();
