// The pages for the gaps in a real browser against the rewrite: a plugin's connection panel (set up the connection a plugin needs, see it served),
// and inviting a person into a team from the Members page (the pending person shows in the team, accepting keeps them in it).
// Start the rewrite with Connections__AllowPrivateUrls=true (the fake MCP server listens on loopback).
//   W=http://localhost:5284 A=http://localhost:5184 node ui-gaps.js [screenshot-dir]
const { chromium } = require('playwright');
const { W, A, PW, check, person, workspace, until, signIn, finish } = require('./ui-lib.js');
const shots = process.argv[2];

(async () => {
  const { startFake } = await import('./fake-mcp.mjs');
  const fake = await startFake();
  const browser = await chromium.launch();
  const errors = [];
  const ws = await workspace('Gaps Workspace');
  const bob = await ws.join('Bob Builder');
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 1100 } });
  const page = await ctx.newPage(); page.on('pageerror', (e) => errors.push(String(e).slice(0, 120)));
  await signIn(page, ws.owner.email);

  // ---- a plugin that needs a connection ----
  const url = `${fake.url('none')}?ui=1`;
  const payload = { mcpServers: { docs: { type: 'remote', url } } };
  const made = await ws.api(ws.owner, 'POST', '/v1/plugins', { name: 'Docs helper', components: [{ type: 'mcp', input: { normalizedPayloadJson: payload, metadata: { name: 'Docs MCP' } } }] });
  const pluginId = made.json.item.id;
  await page.goto(`${W}/dashboard/plugins/${pluginId}`, { waitUntil: 'networkidle' });
  await page.getByTestId('plugin-connections').waitFor({ timeout: 30000 });
  const row = page.getByTestId('server-row').first();
  check('the plugin page lists the server the plugin declares as not set up', (await row.getAttribute('data-server')) === 'docs' && (await row.getAttribute('data-state')) === 'needs_setup' && /Not set up/.test(await row.innerText()), await row.innerText());
  if (shots) await page.screenshot({ path: shots + '/ui-gaps-plugin-before.png', fullPage: true });
  await page.getByTestId('set-up-connection').click();
  await page.getByTestId('auth-type').selectOption('none');
  await page.getByTestId('save-connection').click();
  await page.getByTestId('connections-notice').waitFor({ timeout: 30000 });
  await until(async () => (await page.getByTestId('server-row').first().getAttribute('data-state')) === 'ready');
  check('setting it up says so and the server reads as ready, served by a connection named for the plugin', (await page.getByTestId('server-row').first().getAttribute('data-state')) === 'ready' && /Docs helper \/ docs/.test(await page.getByTestId('connection-link').innerText()), await page.getByTestId('plugin-connections').innerText());
  const list = (await ws.api(ws.owner, 'GET', '/v1/mcp-connections?scope=manageable')).json.connections;
  check('the connection exists and names the plugin that needs it', list.length === 1 && list[0].requiredBy[0]?.pluginId === pluginId && list[0].connected === true);
  if (shots) await page.screenshot({ path: shots + '/ui-gaps-plugin-after.png', fullPage: true });
  await page.getByTestId('connection-link').click();
  await page.getByTestId('connection-name').waitFor({ timeout: 30000 });
  check('the link opens the connection', /Docs helper \/ docs/.test(await page.getByTestId('connection-name').innerText()));

  // a person who may not manage connections sees the need but not the setup button
  const page2 = await (await browser.newContext({ viewport: { width: 1280, height: 900 } })).newPage();
  await ws.api(ws.owner, 'POST', `/v1/plugins/${pluginId}/access`, { orgMembershipId: bob.memberId, role: 'viewer' });
  await signIn(page2, bob.email);
  await page2.goto(`${W}/dashboard/plugins/${pluginId}`, { waitUntil: 'networkidle' });
  await page2.getByTestId('plugin-connections').waitFor({ timeout: 30000 });
  check('a member sees the plugin needs a connection but has no setup button', (await page2.getByTestId('set-up-connection').count()) === 0 && (await page2.getByTestId('server-row').count()) === 1);

  // ---- inviting into a team ----
  const team = (await ws.api(ws.owner, 'POST', '/v1/teams', { name: 'Writers', memberIds: [] })).json.team.id;
  await page.goto(`${W}/dashboard/members`, { waitUntil: 'networkidle' });
  await page.getByTestId('invite-form').waitFor({ timeout: 30000 });
  check('the invite form offers the teams', (await page.getByTestId('invite-team').locator('option').count()) === 2);
  const invitee = await person('Ivy Invitee');
  await page.locator('#invite-email').fill(invitee.email);
  await page.getByTestId('invite-team').selectOption(team);
  if (shots) await page.screenshot({ path: shots + '/ui-gaps-invite-form.png', fullPage: true });
  await page.getByRole('button', { name: /send invitation/i }).click();
  await page.getByTestId('notice').filter({ hasText: /Invitation sent/ }).waitFor({ timeout: 30000 });
  const pendingRow = page.locator(`[data-testid="member-row"][data-email="${invitee.email}"]`);
  check('the pending person shows in the list as joining the team', /joins Writers/.test(await pendingRow.innerText()), await pendingRow.innerText());
  const org = (await ws.api(ws.owner, 'GET', '/v1/org')).json;
  const placeholder = org.members.find((m) => m.userId === null)?.id;
  check('and the team has them already (as the pending member)', org.teams.find((t) => t.id === team).memberIds.includes(placeholder));
  if (shots) await page.screenshot({ path: shots + '/ui-gaps-invite-pending.png', fullPage: true });

  await api2(invitee, org, placeholder);
  async function api2(user, orgNow, ph) {
    const inv = orgNow.invitations[0];
    await fetch(A + '/v1/orgs/invitations/accept', { method: 'POST', headers: { 'content-type': 'application/json', origin: W, authorization: `Bearer ${user.token}` }, body: JSON.stringify({ id: inv.id }) });
    return ph;
  }
  await page.reload({ waitUntil: 'networkidle' });
  await page.getByTestId('member-list').waitFor({ timeout: 30000 });
  const accepted = page.locator(`[data-testid="member-row"][data-email="${invitee.email}"]`);
  check('after accepting they are a member and stay in the team', (await accepted.getAttribute('data-pending')) === 'false' && /in Writers/.test(await accepted.innerText()), await accepted.innerText());
  await page.goto(`${W}/dashboard/teams`, { waitUntil: 'networkidle' });
  await page.getByTestId('team-list').waitFor({ timeout: 30000 });
  check('the Teams page lists them in the team', /Ivy/.test(await page.locator('[data-testid="team-row"][data-name="Writers"]').innerText()), await page.locator('[data-testid="team-row"][data-name="Writers"]').innerText());
  if (shots) await page.screenshot({ path: shots + '/ui-gaps-teams.png', fullPage: true });

  await fake.close();
  await finish(browser, errors);
})();
