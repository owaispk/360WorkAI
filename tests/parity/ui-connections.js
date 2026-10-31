// Connections in a real browser against the rewrite: the connections list, the catalog and add form, a connection's tools and sharing, Your connections
// (sign in with an OAuth server, a personal key), the sign-in landing page, and removing. A fake MCP server and OAuth provider run on loopback, so start
// the rewrite with Connections__AllowPrivateUrls=true.
//   W=http://localhost:5230 A=http://localhost:5130 Connections__AllowPrivateUrls=true node ui-connections.js [screenshot-dir]
const { chromium } = require('playwright');
const { W, A, PW, check, person, workspace, until, signIn, finish } = require('./ui-lib.js');
const shots = process.argv[2];
const text = (page) => page.locator('body').innerText();

(async () => {
  const { startFake } = await import('./fake-mcp.mjs');
  const fake = await startFake();
  const browser = await chromium.launch();
  const errors = [];
  const ws = await workspace('Connections Workspace');
  const bob = await ws.join('Bob Builder');
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 1100 } });
  const page = await ctx.newPage(); page.on('pageerror', (e) => errors.push(String(e).slice(0, 120)));
  await signIn(page, ws.owner.email);

  // ---- the list and the add form ----
  await page.getByTestId('connections-link').click();
  await page.getByTestId('connections-page').waitFor({ timeout: 30000 });
  await page.getByTestId('no-connections').waitFor({ timeout: 15000 });
  check('the owner opens Connections from the dashboard and sees an empty list', /\/dashboard\/mcp-connections/.test(page.url()));
  await page.getByTestId('add-connection').click();
  await page.getByTestId('catalog').waitFor({ timeout: 15000 });
  check('the catalog shows the preset apps', (await page.locator('[data-testid^="preset-"]').count()) >= 11 && await page.getByTestId('preset-notion').isVisible());
  await page.getByTestId('preset-notion').click();
  await until(async () => (await page.locator('#cx-name').inputValue()) === 'Notion');
  check('choosing a preset fills in its name and address', (await page.locator('#cx-name').inputValue()) === 'Notion' && (await page.locator('#cx-url').inputValue()) === 'https://mcp.notion.com/mcp');
  await page.locator('#cx-name').fill('Fake tools');
  await page.locator('#cx-url').fill(fake.url('none'));
  await page.locator('#cx-auth').selectOption('none');
  await page.getByTestId('check-server').click();
  await page.getByTestId('discovery').waitFor({ timeout: 15000 });
  check('checking the server says what it needs', /Works without signing in \(3 tools\)/.test(await page.getByTestId('discovery').innerText()), await page.getByTestId('discovery').innerText());
  await page.getByTestId('share-some').check();
  await page.locator(`input[data-email="${bob.email}"]`).check();
  if (shots) await page.screenshot({ path: shots + '/ui-connections-new.png' });
  await page.getByTestId('create-connection').click();
  await page.getByTestId('connection-name').waitFor({ timeout: 30000 });
  check('adding a connection opens it, connected', (await page.getByTestId('connection-name').innerText()) === 'Fake tools' && /Connected/.test(await page.getByTestId('status').innerText()));
  const id = page.url().split('/').pop();
  const access = (await ws.api(ws.owner, 'GET', `/v1/mcp-connections/${id}`)).json.access;
  check('it is shared with just the person chosen', access.orgWide === false && access.memberIds.length === 1 && access.memberIds[0] === bob.memberId);

  // ---- tools and policy ----
  await page.getByTestId('tool-list').waitFor({ timeout: 15000 });
  check('its three tools are listed, all allowed', (await page.getByTestId('tool-row').count()) === 3 && (await page.locator('[data-tool="delete_everything"] input').isChecked()));
  await page.locator('[data-tool="delete_everything"] input').uncheck();
  await page.getByTestId('save-policy').click();
  await page.getByTestId('notice').filter({ hasText: /Tool settings saved/ }).waitFor({ timeout: 15000 });
  const policy = (await ws.api(ws.owner, 'GET', `/v1/mcp-connections/${id}/tool-policy`)).json.policy;
  check('switching a tool off saves the policy and records who', policy.disabledTools.join() === 'delete_everything' && policy.updatedBy === 'Olive Owner');
  await page.reload({ waitUntil: 'networkidle' });
  await page.getByTestId('tool-list').waitFor({ timeout: 15000 });
  check('the switched-off tool stays off after reloading', !(await page.locator('[data-tool="delete_everything"] input').isChecked()) && (await page.locator('[data-tool="echo"] input').isChecked()));
  if (shots) await page.screenshot({ path: shots + '/ui-connections-detail.png', fullPage: true });

  // ---- sharing ----
  await page.getByTestId('share-everyone').check();
  await page.getByTestId('save-access').click();
  await page.getByTestId('notice').filter({ hasText: /Sharing saved/ }).waitFor({ timeout: 15000 });
  check('sharing with everyone saves', (await ws.api(ws.owner, 'GET', `/v1/mcp-connections/${id}`)).json.access.orgWide === true);

  // ---- the list shows it ----
  await page.goto(W + '/dashboard/mcp-connections', { waitUntil: 'networkidle' });
  const row = page.locator('[data-testid="connection-row"][data-name="Fake tools"]');
  await row.waitFor({ timeout: 15000 });
  check('the list shows it as ready and shared with everyone', /Ready/.test(await row.innerText()) && /Shared with everyone/.test(await row.innerText()), await row.innerText());
  if (shots) await page.screenshot({ path: shots + '/ui-connections-list.png' });

  // ---- a member's own page ----
  const bobCtx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const bobPage = await bobCtx.newPage(); bobPage.on('pageerror', (e) => errors.push(String(e).slice(0, 120)));
  await signIn(bobPage, bob.email);
  await bobPage.getByTestId('your-connections-link').waitFor({ timeout: 15000 });
  check('a plain member has no Connections button but has Your connections', (await bobPage.getByTestId('connections-link').count()) === 0 && (await bobPage.getByTestId('your-connections-link').count()) === 1);
  await bobPage.goto(W + '/dashboard/mcp-connections', { waitUntil: 'networkidle' });
  await bobPage.getByTestId('no-access').waitFor({ timeout: 15000 });
  check('the admin list explains itself to a member instead of showing connections', !/Fake tools/.test(await text(bobPage)));

  // ---- a per-person OAuth connection: sign in from Your connections ----
  const oauth = (await ws.api(ws.owner, 'POST', '/v1/mcp-connections', { name: 'Fake oauth', url: fake.url('oauth'), authType: 'oauth', credentialMode: 'per_member' })).json;
  const personalKey = (await ws.api(ws.owner, 'POST', '/v1/mcp-connections', { name: 'Fake personal key', url: fake.url('key'), authType: 'apikey', credentialMode: 'per_member' })).json;
  await page.goto(W + `/dashboard/your-connections?connectionId=${oauth.id}`, { waitUntil: 'networkidle' });
  const oauthRow = page.locator(`[data-testid="connection-row"][data-id="${oauth.id}"]`);
  await oauthRow.waitFor({ timeout: 15000 });
  check('Your connections lists it as not signed in, and marks the one the link named', /Not signed in/.test(await oauthRow.innerText()) && (await oauthRow.getAttribute('data-focus')) === 'true');
  if (shots) await page.screenshot({ path: shots + '/ui-connections-yours-before.png' });
  await oauthRow.getByTestId('connect').click();
  await page.waitForURL(/\/v1\/mcp-connections\/oauth\/callback/, { timeout: 30000 });
  check('Connect goes to the provider and comes back to the callback page: "You\'re connected"', /connected to OpenWork/.test(await text(page)), await text(page));
  if (shots) await page.screenshot({ path: shots + '/ui-connections-callback.png' });
  await page.goto(W + '/dashboard/your-connections', { waitUntil: 'networkidle' });
  const after = page.locator(`[data-testid="connection-row"][data-id="${oauth.id}"]`);
  await after.waitFor({ timeout: 15000 });
  check('afterwards Your connections shows it connected', /Connected/.test(await after.getByTestId('status').innerText()));
  if (shots) await page.screenshot({ path: shots + '/ui-connections-yours-after.png' });
  const used = await ws.api(ws.owner, 'GET', `/v1/mcp-connections/${oauth.id}/tools`);
  check('and its tools can be listed with that sign-in', used.status === 200 && used.json.tools.length === 3);
  await after.getByTestId('disconnect').click();
  await page.locator(`[data-testid="connection-row"][data-id="${oauth.id}"] [data-testid="connect"]`).waitFor({ timeout: 15000 });
  check('Disconnect signs the person out again', true);

  // ---- a personal API key ----
  await bobPage.goto(W + '/dashboard/your-connections', { waitUntil: 'networkidle' });
  const keyRow = bobPage.locator(`[data-testid="connection-row"][data-id="${personalKey.id}"]`);
  await keyRow.waitFor({ timeout: 15000 });
  await keyRow.getByTestId('enter-key').click();
  await keyRow.getByTestId('key-input').fill(fake.key);
  await keyRow.getByTestId('save-key').click();
  await bobPage.getByTestId('notice').filter({ hasText: /Your key was saved/ }).waitFor({ timeout: 15000 });
  check('a member saves their own key and the connection shows connected, without showing the key', /Connected/.test(await keyRow.getByTestId('status').innerText()) && !(await text(bobPage)).includes(fake.key));

  // ---- the sign-in landing page (the link an agent hands out) ----
  await bobPage.goto(W + `/connect/mcp?connectionId=${oauth.id}&org=${ws.orgId}&name=Fake+oauth`, { waitUntil: 'networkidle' });
  await bobPage.getByTestId('connect-title').waitFor({ timeout: 20000 });
  check('the sign-in link opens a page that names the connection', /Sign in to Fake oauth/.test(await bobPage.getByTestId('connect-title').innerText()));
  await bobPage.goto(W + `/connect/mcp?connectionId=${(await ws.api(ws.owner, 'GET', '/v1/mcp-connections')).json.connections.length ? 'emc_01m6798bqbeaeagm9dmr8grtrt' : ''}`, { waitUntil: 'networkidle' });
  await bobPage.getByTestId('error').waitFor({ timeout: 20000 });
  check('a link to a connection the person cannot use explains that', /not available to you/.test(await bobPage.getByTestId('error').innerText()));

  // ---- removing ----
  await page.goto(W + `/dashboard/mcp-connections/${id}?remove=1`, { waitUntil: 'networkidle' });
  await page.getByTestId('confirm-remove').waitFor({ timeout: 15000 });
  check('the removal link asks for confirmation first', /Fake tools/.test(await page.getByTestId('confirm-remove').innerText()));
  await page.getByTestId('confirm-remove').click();
  await page.waitForURL(/\/dashboard\/mcp-connections$/, { timeout: 30000 });
  await until(async () => (await page.locator('[data-testid="connection-row"][data-name="Fake tools"]').count()) === 0);
  check('removing returns to the list without the connection', (await page.locator('[data-testid="connection-row"][data-name="Fake tools"]').count()) === 0 && (await ws.api(ws.owner, 'GET', `/v1/mcp-connections/${id}`)).status === 404);

  await fake.close();
  await finish(browser, errors);
})().catch((e) => { console.error(e); process.exit(1); });
