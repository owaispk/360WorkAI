// Platform admin pages (/admin) in a real browser against the rewrite. The API must list padmin.parity@example.com as a platform admin
// (PlatformAdmin__BootstrapEmails=padmin.parity@example.com; see docs/features/platform-admin.md):
//   W=http://localhost:5270 A=http://localhost:5170 node ui-platform-admin.js [screenshot-dir]
const { chromium } = require('playwright');
const { W, A, PW, check, api, person, workspace, until, signIn, finish } = require('./ui-lib');
const shots = process.argv[2];
const ADMIN_EMAIL = process.env.PADMIN_EMAIL || 'padmin.parity@example.com';
const text = (page) => page.locator('body').innerText();
const shot = async (page, name) => { if (shots) await page.screenshot({ path: `${shots}/${name}.png`, fullPage: true }); };
const FEATURE = 'computerUseBackground';

/** The platform admin: signs up when new, otherwise signs in; has a workspace so the sign-in lands on the dashboard. */
async function platformAdmin() {
  let r = await api('POST', '/api/auth/sign-up/email', { name: 'Platform Admin', email: ADMIN_EMAIL, password: PW });
  if (!r.json?.token) r = await api('POST', '/api/auth/sign-in/email', { email: ADMIN_EMAIL, password: PW });
  const token = r.json.token;
  const mine = await api('GET', '/v1/me/orgs', null, token);
  if (!(mine.json?.orgs ?? mine.json?.organizations ?? []).length) await api('POST', '/v1/org', { name: 'Operators' }, token);
  return { email: ADMIN_EMAIL, token };
}

(async () => {
  const browser = await chromium.launch();
  const errors = [];
  const admin = await platformAdmin();
  if ((await api('GET', '/v1/admin/overview?limit=1', null, admin.token)).status !== 200) { console.log(`${ADMIN_EMAIL} is not a platform admin: start the API with PlatformAdmin__BootstrapEmails=${ADMIN_EMAIL}`); process.exit(2); }
  const tag = Math.floor(Math.random() * 1e6).toString(36);
  const ws = await workspace(`Umbrella ${tag}`);
  const member = await ws.join(`Casey ${tag}`);
  const extraAdmin = await person('Extra Admin');

  // ---- someone who is not a platform admin -----------------------------------------------------------------------------------------
  const ownerCtx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const ownerPage = await ownerCtx.newPage();
  ownerPage.on('pageerror', (e) => errors.push(String(e).slice(0, 160)));
  await signIn(ownerPage, ws.owner.email);
  for (const path of ['/admin', '/admin/users', '/admin/organizations', '/admin/features', '/admin/feature-usage', '/admin/security', '/admin/services', `/admin/organizations/${ws.orgId}`]) {
    await ownerPage.goto(W + path, { waitUntil: 'networkidle', timeout: 60000 });
    await ownerPage.getByTestId('no-access').waitFor({ timeout: 20000 });
    const body = await text(ownerPage);
    check(`a workspace owner sees only "not for you" on ${path}`, /Your account is not one of them/.test(body) && !body.includes(member.email) && !body.includes(ADMIN_EMAIL) && (await ownerPage.getByTestId('admin-list').count()) === 0, body.slice(0, 200));
  }
  await ownerCtx.close();

  // ---- the platform admin ------------------------------------------------------------------------------------------------------------
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 1200 } });
  const page = await ctx.newPage();
  page.on('pageerror', (e) => errors.push(String(e).slice(0, 160)));
  await signIn(page, admin.email);
  await page.goto(W + '/admin', { waitUntil: 'networkidle', timeout: 60000 });
  await page.getByTestId('metrics').waitFor({ timeout: 30000 });
  const overview = await text(page);
  const users = await api('GET', '/v1/admin/metrics', null, admin.token);
  check('overview shows the totals from this database', (await page.getByTestId('tile-users').innerText()).startsWith(String(users.json.summary.totalUsers)) && /Platform administration/.test(overview), overview.slice(0, 300));
  check('overview lists the platform admins, marking the signed-in one', (await page.locator(`[data-testid="admin-row"][data-email="${ADMIN_EMAIL}"]`).innerText()).includes('You'));
  check('the signed-in admin has no remove button on their own row', (await page.locator(`[data-testid="admin-row"][data-email="${ADMIN_EMAIL}"] [data-testid="remove-admin"]`).count()) === 0);
  await shot(page, 'platform-admin-overview');

  await page.locator('#admin-email').fill('not-an-email');
  await page.getByTestId('add-admin').click();
  check('a bad address is refused with the server message', /Invalid email address/.test(await page.getByTestId('error').innerText()));
  await page.locator('#admin-email').fill(extraAdmin.email);
  await page.locator('#admin-note').fill('second operator');
  await page.getByTestId('add-admin').click();
  await page.locator(`[data-testid="admin-row"][data-email="${extraAdmin.email}"]`).waitFor({ timeout: 15000 });
  check('an added administrator appears and can use the admin API at once', (await api('GET', '/v1/admin/features', null, extraAdmin.token)).status === 200);
  await page.locator(`[data-testid="admin-row"][data-email="${extraAdmin.email}"] [data-testid="remove-admin"]`).click();
  await page.locator(`[data-testid="admin-row"][data-email="${extraAdmin.email}"] [data-testid="confirm-remove-admin"]`).click();
  await until(async () => (await page.locator(`[data-testid="admin-row"][data-email="${extraAdmin.email}"]`).count()) === 0);
  check('removing an administrator takes their access away at once', (await page.locator(`[data-testid="admin-row"][data-email="${extraAdmin.email}"]`).count()) === 0 && (await api('GET', '/v1/admin/features', null, extraAdmin.token)).status === 403);

  // ---- users -------------------------------------------------------------------------------------------------------------------------
  await page.getByTestId('nav-users').click();
  await page.getByTestId('admin-users-page').waitFor({ timeout: 15000 });
  await page.getByTestId('user-list').waitFor({ timeout: 15000 });
  await page.locator('#user-search').fill(member.email);
  await page.getByTestId('search').click();
  await until(async () => /1 user matching/.test(await page.getByTestId('user-count').innerText()));
  await page.locator(`[data-testid="user-row"][data-email="${member.email}"]`).waitFor({ timeout: 15000 });
  const row = await page.locator(`[data-testid="user-row"][data-email="${member.email}"]`).innerText();
  check('searching by email finds the person with their workspace and role', /1 user matching/.test(await page.getByTestId('user-count').innerText()) && row.includes(`Umbrella ${tag}`) && /member/.test(row), row);
  await page.locator(`[data-testid="user-row"][data-email="${member.email}"] [data-testid="delete-user"]`).click();
  check('deleting asks to confirm and says what happens', /signs them out everywhere/.test(await page.getByTestId('delete-warning').innerText()));
  await page.locator(`[data-testid="user-row"][data-email="${member.email}"] [data-testid="confirm-delete-user"]`).click();
  await until(async () => (await page.locator(`[data-testid="user-row"][data-email="${member.email}"]`).count()) === 0);
  check('the deleted person is gone, signed out and out of the workspace', (await page.locator(`[data-testid="user-row"][data-email="${member.email}"]`).count()) === 0
    && (await api('GET', '/v1/me', null, member.token)).status === 401 && !(await api('GET', '/v1/org', null, ws.owner.token, ws.orgId)).json.members.some((m) => m.user.email === member.email));

  // ---- workspaces -------------------------------------------------------------------------------------------------------------------
  await page.getByTestId('nav-organizations').click();
  await page.getByTestId('admin-organizations-page').waitFor({ timeout: 15000 });
  await page.locator('#org-search').fill(`Umbrella ${tag}`);
  await page.getByTestId('search').click();
  await page.locator(`[data-testid="org-row"][data-name="Umbrella ${tag}"]`).waitFor({ timeout: 15000 });
  await page.locator(`[data-testid="org-row"][data-name="Umbrella ${tag}"] [data-testid="open-org"]`).click();
  await page.getByTestId('org-name').waitFor({ timeout: 15000 });
  await page.getByTestId('override-list').waitFor({ timeout: 15000 });
  check('a workspace page shows its people and plan', (await page.getByTestId('org-name').innerText()) === `Umbrella ${tag}` && (await page.getByTestId('person-row').count()) === 1 && /free plan/.test(await text(page)));

  await page.locator('#plan-tier').selectOption('team');
  await page.locator('#plan-users').fill('12');
  await page.locator('#plan-ends').fill('nope');
  await page.getByTestId('save-plan').click();
  check('a bad end date is refused with the server message', /Use a date such as/.test(await page.getByTestId('error').innerText()));
  await page.locator('#plan-ends').fill('2027-01-31');
  await page.getByTestId('save-plan').click();
  await page.getByTestId('notice').waitFor({ timeout: 15000 });
  const plan = (await api('GET', `/v1/admin/organizations/${ws.orgId}`, null, admin.token)).json.organization.plan;
  check('saving a plan stores it (no billing involved)', plan.tier === 'team' && plan.seats === 12 && plan.endsAt === '2027-01-31' && plan.paidBy === 'none' && /team plan · 12 users allowed · ends 2027-01-31/.test(await text(page)), JSON.stringify(plan));

  await page.locator('#free-seats').fill('9');
  await page.getByTestId('save-seats').click();
  await until(async () => /Free seats were saved/.test(await text(page)));
  check('free seats are stored', (await api('GET', `/v1/admin/organizations?search=${ws.orgId}&includeFeatures=0`, null, admin.token)).json.organizations[0].freeSeatCount === 9);

  await page.locator('#dpa-reason').fill('x');
  await page.getByTestId('save-dpa').click();
  check('a too short reason is refused', /reason: Too small/.test(await page.getByTestId('error').innerText()));
  await page.locator('#dpa-reason').fill('signed copy on file');
  await page.getByTestId('save-dpa').click();
  await until(async () => /decision was recorded/.test(await text(page)));
  const audit = await api('GET', '/v1/audit/operations?limit=100', null, ws.owner.token, ws.orgId);
  check('the DPA decision is recorded and the workspace owner can see it in the audit log', JSON.stringify(audit.json).includes('organization.dpa_signed.updated') && !JSON.stringify(audit.json).includes('signed copy on file'));

  await page.locator('#web-reason').fill('pilot access');
  await page.getByTestId('save-web').click();
  await until(async () => /Complimentary access is on/.test(await page.getByTestId('web-state').innerText()));
  check('web access is granted', (await api('GET', '/v1/org', null, ws.owner.token, ws.orgId)).json.capabilities.openworkWeb === true);

  const select = page.locator(`[data-testid="override-row"][data-key="browserUse"] [data-testid="override-select"]`);
  await select.selectOption('on');
  await page.getByTestId('save-features').click();
  await until(async () => /Saved 1 feature setting/.test(await text(page)));
  const mine = (await api('GET', '/v1/org', null, ws.owner.token, ws.orgId)).json.features;
  const other = await workspace(`Other ${tag}`);
  const theirs = (await api('GET', '/v1/org', null, other.owner.token, other.orgId)).json.features;
  check('a workspace feature setting applies to that workspace only', mine.browserUse === true && theirs.browserUse === false);
  check('the page shows it as set for this workspace', /browserUse · On here \(override\)/.test(await text(page)));
  await shot(page, 'platform-admin-organization');
  await select.selectOption('follow');
  await page.getByTestId('save-features').click();
  await until(async () => /Saved 1 feature setting/.test(await text(page)) && /browserUse · Off here \(everyone\)/.test(await text(page)));
  check('choosing "follow everyone" clears it', (await api('GET', '/v1/org', null, ws.owner.token, ws.orgId)).json.features.browserUse === false);

  // ---- features -----------------------------------------------------------------------------------------------------------------------
  await page.getByTestId('nav-features').click();
  await page.getByTestId('admin-features-page').waitFor({ timeout: 15000 });
  await page.locator(`[data-testid="feature-row"][data-key="${FEATURE}"]`).waitFor({ timeout: 15000 });
  check('the feature list shows every feature that exists on this deployment', (await page.getByTestId('feature-row').count()) === 56);
  const frow = page.locator(`[data-testid="feature-row"][data-key="${FEATURE}"]`);
  try {
    await frow.locator('[data-testid="toggle"]').click();
    await until(async () => (await frow.innerText()).includes('On for everyone'));
    const publicOn = (await (await fetch(A + '/v1/features')).json()).features[FEATURE];
    check('turning a feature on for everyone shows in the public feature list', publicOn === true && /is now on for everyone/.test(await text(page)));
    await frow.locator('[data-testid="kill"]').click();
    await frow.locator('[data-testid="badge-killed"]').waitFor({ timeout: 15000 });
    const killed = (await (await fetch(A + '/v1/features')).json()).features[FEATURE];
    check('the kill switch turns it off everywhere and says so', killed === false && /killed everywhere/.test(await text(page)));
    await shot(page, 'platform-admin-features');
  } finally {
    await api('PUT', `/v1/admin/features/${FEATURE}`, { enabled: false, killed: false }, admin.token);
  }
  check('the feature is back to its default afterwards', (await api('GET', '/v1/admin/features', null, admin.token)).json.features.find((f) => f.key === FEATURE).enabled === false);

  // ---- feature use, security, services -------------------------------------------------------------------------------------------
  await api('POST', '/v1/org/feature-usage', { features: ['libraryDetailBreadcrumbs'] }, ws.owner.token, ws.orgId);
  await page.getByTestId('nav-feature-usage').click();
  await page.getByTestId('admin-feature-usage-page').waitFor({ timeout: 15000 });
  await page.locator('[data-testid="usage-row"][data-key="libraryDetailBreadcrumbs"]').waitFor({ timeout: 15000 });
  const usageRow = page.locator('[data-testid="usage-row"][data-key="libraryDetailBreadcrumbs"]');
  check('feature use lists every available feature with who uses it', (await page.getByTestId('usage-row').count()) > 40 && Number(await usageRow.getByTestId('members-using').innerText()) >= 1 && (await usageRow.getByTestId('health').innerText()) === 'In use');
  await page.getByTestId('range-30d').click();
  await until(async () => (await page.getByTestId('range-30d').getAttribute('class'))?.includes('current'));
  await usageRow.getByTestId('open-feature').click();
  await page.getByTestId('detail-title').waitFor({ timeout: 15000 });
  check('opening a feature shows the workspaces that use it', /libraryDetailBreadcrumbs/.test(await page.getByTestId('detail-title').innerText()) && (await page.getByTestId('detail-org').count()) >= 1);
  await shot(page, 'platform-admin-feature-use');

  await page.getByTestId('nav-security').click();
  await page.getByTestId('admin-security-page').waitFor({ timeout: 15000 });
  await page.locator('[data-testid="finding"][data-id="admin-grants"]').waitFor({ timeout: 15000 });
  check('security lists the findings, each with its severity and the rule that raised it', (await page.getByTestId('finding').count()) === 14 && (await page.locator('[data-testid="finding"][data-id="admin-grants"] [data-testid="rule"]').textContent()).length > 20);
  check('findings that need model usage are shown as clear', (await page.locator('[data-testid="finding"][data-id="spend-spikes"]').getAttribute('data-severity')) === 'clear');
  await page.getByTestId('days-30').click();
  await until(async () => (await page.getByTestId('days-30').getAttribute('class'))?.includes('current'));
  await shot(page, 'platform-admin-security');

  await page.getByTestId('nav-services').click();
  await page.getByTestId('admin-services-page').waitFor({ timeout: 15000 });
  await page.locator('[data-testid="service-row"][data-id="database"]').waitFor({ timeout: 15000 });
  check('services shows the database as ready and the cloud-only services as not set up', (await page.locator('[data-testid="service-row"][data-id="database"]').getAttribute('data-state')) === 'ready' && (await page.locator('[data-testid="service-row"][data-id="gateway"]').getAttribute('data-state')) === 'not_configured');
  await page.getByTestId('check-now').click();
  await page.getByTestId('notice').waitFor({ timeout: 15000 });
  check('a check can be made from the page and sandbox organizations are said to be off', /Checked/.test(await page.getByTestId('notice').innerText()) && /turned off/.test(await page.getByTestId('sandboxes').innerText()));
  await shot(page, 'platform-admin-services');

  await finish(browser, errors);
})().catch((e) => { console.error(e); process.exit(1); });
