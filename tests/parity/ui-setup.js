// First-administrator setup in a real browser: /setup on a fresh deployment, a wrong code, the right code, the account, and setup closing.
// Needs a deployment with NO accounts, started with an administrator address and a one-time code, e.g.:
//   export WORKAI360_API_URL=http://localhost:5190 WORKAI360_WEB_URL=http://localhost:5290 WORKAI360_RUN_DIR=/tmp/workai-setup-run \
//     ConnectionStrings__Default="Data Source=/tmp/workai-setup.db" PlatformAdmin__BootstrapEmails=first.admin@example.com \
//     PlatformAdmin__InitialAdminCode=correct-horse-battery-staple-42
//   rm -f /tmp/workai-setup.db*; scripts/dev.sh start
//   W=$WORKAI360_WEB_URL A=$WORKAI360_API_URL node tests/parity/ui-setup.js [screenshot-dir]
const { chromium } = require('playwright');
const { W, PW, check, api, finish } = require('./ui-lib');

const EMAIL = process.env.SETUP_EMAIL || 'first.admin@example.com';
const CODE = process.env.SETUP_CODE || 'correct-horse-battery-staple-42';
const shots = process.argv[2];

(async () => {
  const status = (await api('GET', '/v1/auth/bootstrap/status')).json?.status;
  if (status !== 'available') { console.log(`setup status is "${status}": start a fresh deployment as the header says`); process.exit(2); }

  const browser = await chromium.launch();
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  const shot = async (name) => { if (shots) await page.screenshot({ path: `${shots}/setup-${name}.png`, fullPage: true }); };

  // Ordinary sign-up waits for setup.
  const early = await api('POST', '/api/auth/sign-up/email', { name: 'Early Bird', email: 'early.bird@example.com', password: PW });
  check('ordinary sign-up is refused while setup is open', early.status === 403 && early.json?.error === 'setup_required', JSON.stringify(early));

  await page.goto(W + '/setup', { waitUntil: 'networkidle', timeout: 120000 });
  await page.getByTestId('setup-verify').waitFor({ timeout: 30000 });
  check('/setup offers the verification form', true);
  await shot('1-verify');

  await page.locator('#setup-email').fill(EMAIL);
  await page.locator('#setup-code').fill('wrong-code');
  await page.getByRole('button', { name: /^continue$/i }).click();
  const alert = await page.getByRole('alert').textContent({ timeout: 15000 });
  check('a wrong code is refused with the generic message', /could not be verified/i.test(alert || ''), alert);

  await page.locator('#setup-code').fill(CODE);
  await page.getByRole('button', { name: /^continue$/i }).click();
  await page.getByTestId('setup-create').waitFor({ timeout: 15000 });
  check('the right code leads to the account step', true);
  await shot('2-create');

  await page.locator('#setup-name').fill('First Admin');
  await page.locator('#setup-password').fill(PW);
  await page.getByRole('button', { name: /^create administrator$/i }).click();
  await page.waitForURL(/\/install/, { timeout: 60000 });
  check('creating the account signs in and goes to /install', true);
  await shot('3-install');

  // The new person owns a workspace and can open the platform admin pages.
  const signIn = await api('POST', '/api/auth/sign-in/email', { email: EMAIL, password: PW });
  const orgs = (await api('GET', '/v1/me/orgs', null, signIn.json?.token)).json?.orgs || [];
  check('the first administrator owns a workspace', orgs.length === 1 && orgs[0].role === 'owner', JSON.stringify(orgs));
  const overview = await api('GET', '/v1/admin/overview', null, signIn.json?.token);
  check('the first administrator is a platform admin', overview.status === 200, overview.status);
  await page.goto(W + '/admin', { waitUntil: 'networkidle', timeout: 60000 });
  check('/admin opens for them', !/not a platform admin|forbidden/i.test(await page.locator('body').innerText()));

  await page.goto(W + '/setup', { waitUntil: 'networkidle', timeout: 60000 });
  await page.getByTestId('setup-state').waitFor({ timeout: 30000 });
  check('/setup now says setup is permanently disabled', /permanently disabled/.test(await page.getByTestId('setup-state').innerText()));
  await shot('4-complete');

  const later = await api('POST', '/api/auth/sign-up/email', { name: 'Later Person', email: 'later.person@example.com', password: PW });
  check('ordinary sign-up opens after setup', later.status === 200, JSON.stringify(later));
  await finish(browser, errors);
})();
