// Organization admin pages in a real browser against the rewrite: API keys, organization settings, brand and appearance, audit logs.
//   W=http://localhost:5210 A=http://localhost:5110 node ui-org-admin.js [screenshot-dir]
const { chromium } = require('playwright');
const zlib = require('node:zlib');
const { W, A, check, workspace, until, signIn, finish } = require('./ui-lib');
const shots = process.argv[2];

const png = (width, height) => {
  const chunk = (type, data) => {
    const body = Buffer.concat([Buffer.from(type), data]);
    const out = Buffer.alloc(12 + data.length);
    out.writeUInt32BE(data.length, 0); body.copy(out, 4); out.writeUInt32BE(zlib.crc32(body) >>> 0, 8 + data.length);
    return out;
  };
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0); header.writeUInt32BE(height, 4); header[8] = 8; header[9] = 2;
  const row = Buffer.alloc(1 + width * 3, 0x33); row[0] = 0;
  const raw = Buffer.concat(Array.from({ length: height }, () => row));
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', header), chunk('IDAT', zlib.deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]);
};
const text = (page) => page.locator('body').innerText();
const shot = async (page, name) => { if (shots) await page.screenshot({ path: `${shots}/${name}.png`, fullPage: true }); };

(async () => {
  const browser = await chromium.launch();
  const errors = [];
  const ws = await workspace('Admin Workspace');
  const member = await ws.join('Mia Member');
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 1100 } });
  const page = await ctx.newPage();
  page.on('pageerror', (e) => errors.push(String(e).slice(0, 160)));
  await signIn(page, ws.owner.email);
  const dashboard = await text(page);
  check('the dashboard offers the four admin pages to the owner', (await Promise.all(['org-settings-link', 'brand-link', 'api-keys-link', 'audit-link'].map((id) => page.getByTestId(id).count()))).every((n) => n === 1), dashboard.slice(0, 200));

  // ---- API keys ------------------------------------------------------------------------------------------------------------------
  await page.getByTestId('api-keys-link').click();
  await page.getByTestId('api-keys-page').waitFor({ timeout: 30000 });
  await page.getByTestId('no-keys').waitFor({ timeout: 15000 });
  check('API keys opens empty', /\/dashboard\/api-keys/.test(page.url()));
  await page.locator('#key-name').fill('x');
  await page.getByRole('button', { name: 'Create key' }).click();
  check('a name that is too short is refused on the page', /at least 2 characters/.test(await page.getByTestId('error').innerText()));
  await page.locator('#key-name').fill('Build Server');
  await page.getByRole('button', { name: 'Create key' }).click();
  await page.getByTestId('new-key').waitFor({ timeout: 15000 });
  const secret = await page.getByTestId('new-key').inputValue();
  check('creating a key shows the secret once', /^den_[A-Za-z0-9]{64}$/.test(secret));
  const worksWithKey = await fetch(A + '/v1/org', { headers: { 'x-api-key': secret } });
  check('the key signs requests in as the owner', worksWithKey.status === 200 && (await worksWithKey.json()).organization.id === ws.orgId);
  await page.locator('[data-testid="key-row"][data-name="Build Server"]').waitFor({ timeout: 15000 });
  const row = await page.locator('[data-testid="key-row"][data-name="Build Server"]').innerText();
  check('the list shows the key by its first characters, never the secret', row.includes(secret.slice(0, 6)) && !row.includes(secret) && /never used/.test(row), row);
  await shot(page, 'org-admin-api-keys');
  await page.getByTestId('dismiss-key').click();
  check('dismissing hides the secret for good', (await page.getByTestId('new-key').count()) === 0 && !(await text(page)).includes(secret));
  await page.reload({ waitUntil: 'networkidle' });
  await page.getByTestId('key-list').waitFor({ timeout: 15000 });
  check('after a reload the secret is nowhere on the page', !(await page.content()).includes(secret));
  await page.getByTestId('delete-key').click();
  await page.getByTestId('confirm-delete').click();
  await page.getByTestId('no-keys').waitFor({ timeout: 15000 });
  const afterDelete = await fetch(A + '/v1/org', { headers: { 'x-api-key': secret } });
  check('deleting a key (after confirming) stops it working', afterDelete.status === 401);

  // A plain member sees why they cannot.
  const memberPage = await (await browser.newContext({ viewport: { width: 1100, height: 800 } })).newPage();
  memberPage.on('pageerror', (e) => errors.push(String(e).slice(0, 160)));
  await signIn(memberPage, member.email);
  await memberPage.goto(W + '/dashboard/api-keys', { waitUntil: 'networkidle' });
  await memberPage.getByTestId('no-access').waitFor({ timeout: 20000 });
  check('a member without permission is told so and cannot create keys', (await memberPage.locator('#key-name').count()) === 0);
  await memberPage.goto(W + '/dashboard/audit-logs', { waitUntil: 'networkidle' });
  await memberPage.getByTestId('audit-locked').waitFor({ timeout: 20000 });
  check('a member cannot open the audit log', true);

  // ---- organization settings -----------------------------------------------------------------------------------------------------
  await page.goto(W + '/dashboard/org-settings', { waitUntil: 'networkidle' });
  await page.getByTestId('org-settings-page').waitFor({ timeout: 30000 });
  await page.locator('#org-name').fill('Renamed Workspace');
  await page.locator('#org-domains').fill('Example.COM, other.org');
  await page.getByRole('button', { name: 'Save settings' }).click();
  await until(async () => /Settings saved/.test(await text(page)));
  const org = (await ws.api(ws.owner, 'GET', '/v1/org')).json.organization;
  check('saving settings renames the workspace and normalizes the allowed domains', org.name === 'Renamed Workspace' && org.allowedEmailDomains.join() === 'example.com,other.org', JSON.stringify(org).slice(0, 200));
  await page.locator('#org-domains').fill('not a domain');
  await page.getByRole('button', { name: 'Save settings' }).click();
  await until(async () => (await page.getByTestId('error').count()) > 0);
  check('a bad domain is explained', /valid email domains/.test(await page.getByTestId('error').innerText()));
  await page.locator('#org-domains').fill('');
  await page.getByRole('button', { name: 'Save settings' }).click();
  await until(async () => (await ws.api(ws.owner, 'GET', '/v1/org')).json.organization.allowedEmailDomains === null);
  await page.locator('#origin-input').fill('http://not-secure.example.com');
  await page.getByRole('button', { name: 'Approve origin' }).click();
  await until(async () => (await page.getByTestId('error').count()) > 0);
  check('an origin that is not https is refused', /exact HTTPS origin/.test(await page.getByTestId('error').innerText()));
  await page.locator('#origin-input').fill('https://Workspace.Example.com/');
  await page.getByRole('button', { name: 'Approve origin' }).click();
  await page.locator('[data-testid="origin-row"][data-origin="https://workspace.example.com"]').waitFor({ timeout: 15000 });
  check('an origin is normalized and listed', true);
  await shot(page, 'org-admin-settings');
  await page.locator('[data-testid="origin-row"] >> text=Remove').click();
  await page.getByTestId('no-origins').waitFor({ timeout: 15000 });
  check('removing an origin empties the list', true);

  // ---- brand and appearance ------------------------------------------------------------------------------------------------------
  await page.goto(W + '/dashboard/brand-appearance', { waitUntil: 'networkidle' });
  await page.getByTestId('brand-page').waitFor({ timeout: 30000 });
  await page.locator('#brand-app-name').fill('Acme Work');
  await page.locator('#brand-accent').fill('#336699');
  await page.getByRole('button', { name: 'Save name and colour' }).click();
  await until(async () => /Name and colour saved/.test(await text(page)));
  const meta = JSON.parse((await ws.api(ws.owner, 'GET', '/v1/org')).json.organization.metadata);
  check('name and colour are saved in the organization metadata', meta.brandAppName === 'Acme Work' && meta.brandAccentColor === '#336699', JSON.stringify(meta));
  await page.locator('#brand-logo-upload').setInputFiles({ name: 'square.png', mimeType: 'image/png', buffer: png(200, 200) });
  await page.getByTestId('brand-upload').click();
  await until(async () => (await page.getByTestId('error').count()) > 0);
  const refusal = await page.getByTestId('error').innerText();
  check('the refusal says what is wrong', /horizontal wordmark/.test(refusal), refusal);
  await page.locator('#brand-logo-upload').setInputFiles({ name: 'wordmark.png', mimeType: 'image/png', buffer: png(256, 64) });
  await page.locator('#brand-icon-upload').setInputFiles({ name: 'icon.png', mimeType: 'image/png', buffer: png(128, 128) });
  await page.getByTestId('brand-upload').click();
  await page.getByTestId('brand-logo-preview').waitFor({ timeout: 20000 });
  await page.getByTestId('brand-icon-preview').waitFor({ timeout: 20000 });
  const sizes = await page.evaluate(() => ['brand-logo-preview', 'brand-icon-preview'].map((id) => { const i = document.querySelector(`[data-testid="${id}"]`); return [i.complete, i.naturalWidth]; }));
  check('uploaded images are stored and previews load from their signed URLs', sizes[0][1] === 256 && sizes[1][1] === 128, JSON.stringify(sizes));
  check('the page says where the image lives and its size', /Stored in OpenWork · 256×64/.test(await page.getByTestId('brand-logo-status').innerText()));
  await shot(page, 'org-admin-brand');
  await page.getByRole('button', { name: 'Use the default wordmark' }).click();
  await until(async () => (await page.getByTestId('brand-logo-preview').count()) === 0);
  check('going back to the default wordmark removes the preview', true);

  // ---- audit logs -----------------------------------------------------------------------------------------------------------------
  await page.goto(W + '/dashboard/audit-logs', { waitUntil: 'networkidle' });
  await page.getByTestId('audit-page').waitFor({ timeout: 30000 });
  await page.getByTestId('audit-list').waitFor({ timeout: 15000 });
  await until(async () => (await page.getByTestId('audit-row').count()) >= 5);
  const actions = await page.locator('[data-testid="audit-row"]').evaluateAll((rows) => rows.map((r) => r.getAttribute('data-action')));
  check('the log lists what happened in this session (key created, settings updated, origin approved)',
    ['api_key.created', 'api_key.deleted', 'organization.settings.update.succeeded', 'web_origin.approved', 'web_origin.removed', 'organization.brand_assets.update.succeeded'].every((a) => actions.includes(a)), actions.join());
  await page.locator('[data-testid="audit-row"][data-action="organization.settings.update.succeeded"]').first().locator('button.audit-summary').click();
  await page.getByTestId('audit-detail').waitFor({ timeout: 15000 });
  await until(async () => (await page.getByTestId('audit-change').count()) > 0);
  const change = (await page.getByTestId('audit-change').allInnerTexts()).join(' | ');
  check('opening an operation shows what changed, before and after', /name|allowedEmailDomains|brand/.test(change) && change.includes('→'), change);
  await shot(page, 'org-admin-audit');
  await page.locator('#audit-action').selectOption('web_origin.approved');
  await page.getByRole('button', { name: 'Apply filters' }).click();
  await until(async () => (await page.getByTestId('audit-row').count()) === 1);
  check('filtering by event type narrows the list', (await page.locator('[data-testid="audit-row"]').getAttribute('data-action')) === 'web_origin.approved');
  await page.getByRole('button', { name: 'Clear filters' }).click();
  await until(async () => (await page.getByTestId('audit-row').count()) > 1);
  const download = page.waitForEvent('download');
  await page.getByTestId('export-csv').click();
  const file = await download;
  const fs = require('node:fs');
  const csv = fs.readFileSync(await file.path(), 'utf8');
  check('the CSV export downloads with a header row', csv.startsWith('"schema_version","event_id"') && file.suggestedFilename().endsWith('.csv'), csv.slice(0, 80));
  check('capture starts on', /on/.test(await page.getByTestId('capture-state').innerText()));
  await page.getByTestId('toggle-capture').click();
  await until(async () => (await page.getByTestId('capture-state').innerText()) === 'off');
  check('capture can be turned off from the page', true);
  await page.getByTestId('toggle-capture').click();
  await until(async () => (await page.getByTestId('capture-state').innerText()) === 'on');
  check('and on again', true);

  // ---- deleting a workspace -------------------------------------------------------------------------------------------------------
  await page.goto(W + '/dashboard/org-settings', { waitUntil: 'networkidle' });
  await page.getByTestId('delete-form').waitFor({ timeout: 20000 });
  const button = page.getByTestId('delete-workspace');
  check('delete stays disabled until the name is typed', await button.isDisabled());
  await page.locator('#delete-confirm').fill('Renamed Workspace');
  await until(async () => !(await button.isDisabled()));
  await button.click();
  await page.waitForURL((url) => url.pathname === '/', { timeout: 30000 });
  check('after deleting, the owner lands on the sign-in page and the workspace is gone', (await ws.api(ws.owner, 'GET', '/v1/org')).status !== 200);
  await finish(browser, errors);
})().catch((e) => { console.error(e); process.exit(1); });
