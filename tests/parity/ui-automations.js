// Automations and analytics pages in a real browser against the rewrite: create, run now, watch a desktop run it, change, pause, cancel, archive; privacy; analytics.
//   W=http://localhost:5280 A=http://localhost:5180 node ui-automations.js [screenshot-dir]
const { chromium } = require('playwright');
const { check, api, workspace, until, signIn, finish, W, A } = require('./ui-lib.js');
const shots = process.argv[2];

(async () => {
  const browser = await chromium.launch();
  const errors = [];
  const ws = await workspace('Automations Workspace');
  const mia = await ws.join('Mia Member');
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 1100 } });
  const page = await ctx.newPage(); page.on('pageerror', (e) => errors.push(String(e).slice(0, 120)));
  await signIn(page, ws.owner.email);

  // ---- the list and the form
  await page.getByTestId('automations-link').waitFor({ timeout: 30000 });
  check('the dashboard offers Automations and analytics to the owner', (await page.getByTestId('automations-link').count()) === 1 && (await page.getByTestId('analytics-link').count()) === 1);
  await page.getByTestId('automations-link').click();
  await page.getByTestId('automations-page').waitFor({ timeout: 30000 });
  await page.getByTestId('presence').waitFor({ timeout: 15000 });
  check('a new person has no Automations and no desktop is connected', (await page.getByTestId('automations-empty').count()) === 1 && (await page.getByTestId('presence').getAttribute('data-connected')) === 'false' && /No desktop is connected/.test(await page.getByTestId('presence').innerText()));

  await page.getByTestId('auto-create').click();
  await page.getByTestId('error').waitFor({ timeout: 10000 });
  check('creating without a name is explained', /name/i.test(await page.getByTestId('error').innerText()));
  await page.getByTestId('auto-name').fill('Morning summary');
  await page.getByTestId('auto-instructions').fill('Summarize my inbox and list what needs an answer.');
  await page.getByTestId('auto-tz').fill('Not/AZone');
  await page.getByTestId('auto-create').click();
  await page.getByTestId('error').filter({ hasText: /time zone/ }).waitFor({ timeout: 10000 });
  check('an unknown time zone is explained', true);
  await page.getByTestId('auto-tz').fill('Europe/Paris');
  await page.getByTestId('auto-time').fill('08:30');
  await page.getByTestId('auto-kind').selectOption('weekly');
  for (const d of [1, 2, 3, 4, 5]) if (!(await page.getByTestId(`auto-day-${d}`).isChecked())) await page.getByTestId(`auto-day-${d}`).check();
  for (const d of [0, 6]) if (await page.getByTestId(`auto-day-${d}`).isChecked()) await page.getByTestId(`auto-day-${d}`).uncheck();
  await page.getByTestId('auto-create').click();
  await page.getByTestId('notice').filter({ hasText: /Automation created/ }).waitFor({ timeout: 15000 });
  const row = page.getByTestId('automation-row').filter({ hasText: 'Morning summary' });
  await row.waitFor({ timeout: 15000 });
  check('the new Automation is listed with its schedule in words and a next run', /Weekly · Mon, Tue, Wed, Thu, Fri · 08:30 · Europe\/Paris/.test(await row.getByTestId('automation-schedule').innerText()) && /UTC/.test(await row.getByTestId('automation-next').innerText()));
  const mine = (await ws.api(ws.owner, 'GET', '/v1/automations')).json.items;
  check('it is stored for its owner with the schedule that was chosen', mine.length === 1 && mine[0].revision.schedule.kind === 'weekly' && JSON.stringify(mine[0].revision.schedule.daysOfWeek) === '[1,2,3,4,5]' && mine[0].revision.schedule.hour === 8 && mine[0].revision.schedule.minute === 30);
  check('it is private: the other member sees none', (await ws.api(mia, 'GET', '/v1/automations')).json.items.length === 0);
  const id = mine[0].automation.id;
  if (shots) await page.screenshot({ path: shots + '/ui-automations-list.png', fullPage: true });

  // ---- a desktop connects, a run is queued from the page
  const reg = await ws.api(ws.owner, 'POST', '/v1/automation-runners/token', { runnerId: 'ui-runner-0001', protocolVersion: 1, supportedExecutionTargets: ['desktop'], capabilities: ['model_attention_v1'], appVersion: '1.0.0', platform: 'linux', concurrency: 1 });
  const runner = async (method, path, body) => { const r = await fetch(A + path, { method, headers: { 'content-type': 'application/json', authorization: `Bearer ${reg.json.token}` }, body: body ? JSON.stringify(body) : undefined }); const t = await r.text(); return { status: r.status, json: t ? JSON.parse(t) : null }; };
  await page.reload({ waitUntil: 'networkidle' });
  await page.getByTestId('presence').waitFor({ timeout: 15000 });
  check('once a desktop registers the page says it is connected', await until(async () => (await page.getByTestId('presence').getAttribute('data-connected')) === 'true'));
  await page.getByTestId('automation-row').filter({ hasText: 'Morning summary' }).getByTestId('automation-run').click();
  await page.getByTestId('notice').filter({ hasText: /Run queued/ }).waitFor({ timeout: 15000 });
  check('run now queues a run the desktop can see', await until(async () => ((await runner('GET', '/v1/automation-runner/work')).json.items || []).length === 1));
  check('the list says the last run is waiting for the desktop', /Waiting for your desktop/.test(await page.getByTestId('automation-latest').first().innerText()));

  // ---- the detail page
  await page.getByTestId('automation-open').first().click();
  await page.getByTestId('automation-page').waitFor({ timeout: 15000 });
  await page.getByTestId('run-row').first().waitFor({ timeout: 15000 });
  check('the detail page shows the Automation, its state and its queued run', /Morning summary/.test(await page.getByTestId('automation-title').innerText()) && (await page.getByTestId('automation-state').innerText()) === 'On' && (await page.getByTestId('run-row').first().getAttribute('data-status')) === 'queued');
  await page.getByTestId('run-cancel').click();
  await page.getByTestId('run-row').first().filter({ has: page.locator('[data-testid="run-status"]', { hasText: 'Cancelled' }) }).waitFor({ timeout: 15000 });
  check('a queued run can be cancelled from the page', (await ws.api(ws.owner, 'GET', `/v1/automations/${id}/runs`)).json.items[0].status === 'cancelled');

  // The desktop does a run end to end.
  await page.getByTestId('run-now').click();
  await page.getByTestId('notice').filter({ hasText: /Run queued/ }).waitFor({ timeout: 15000 });
  const work = await until(async () => { const w = await runner('GET', '/v1/automation-runner/work'); return (w.json.items || [])[0]; });
  const claimed = await runner('POST', `/v1/automation-runs/${work.runId}/claim`);
  check('the desktop claims it and gets the instructions', claimed.json.assignment && /Summarize my inbox/.test(claimed.json.assignment.instructions) && claimed.json.assignment.attempt === 1);
  await runner('POST', `/v1/automation-runs/${work.runId}/events`, { attempt: 1, sequence: 1, type: 'assistant', payload: { text: 'Found 3 emails' }, createdAt: 1 });
  await runner('POST', `/v1/automation-runs/${work.runId}/complete`, { attempt: 1, status: 'succeeded', sessionId: 's1', workspaceId: 'w1', resultSummary: 'Three emails need an answer.', usage: { inputTokens: 1, outputTokens: 2, costMicros: null }, error: null });
  await page.reload({ waitUntil: 'networkidle' });
  const done = page.locator('[data-testid="run-row"][data-status="succeeded"]');
  await done.waitFor({ timeout: 15000 });
  check('the finished run shows its status and result', /Done/.test(await done.getByTestId('run-status').innerText()) && /Three emails need an answer/.test(await done.getByTestId('run-summary').innerText()));
  await done.getByTestId('run-details').click();
  await done.getByTestId('run-events').waitFor({ timeout: 10000 });
  check('its steps can be shown', /Found 3 emails/.test(await done.getByTestId('run-events').innerText()));
  if (shots) await page.screenshot({ path: shots + '/ui-automations-detail.png', fullPage: true });

  // ---- change, pause, archive
  await page.getByTestId('edit-instructions').fill('Summarize my inbox, newest first.');
  await page.getByTestId('edit-save').click();
  await page.getByTestId('notice').filter({ hasText: /Saved/ }).waitFor({ timeout: 15000 });
  check('changing the instructions makes version 2', await until(async () => (await page.getByTestId('automation-version').innerText()) === '2') && (await ws.api(ws.owner, 'GET', `/v1/automations/${id}`)).json.revision.instructions === 'Summarize my inbox, newest first.');
  await page.getByTestId('pause').click();
  await page.getByTestId('resume').waitFor({ timeout: 15000 });
  check('pausing stops the schedule', (await page.getByTestId('automation-state').innerText()) === 'Paused' && (await ws.api(ws.owner, 'GET', `/v1/automations/${id}`)).json.automation.nextDueAt === null);
  await page.getByTestId('resume').click();
  await page.getByTestId('pause').waitFor({ timeout: 15000 });
  check('turning it on again restores the next run', (await page.getByTestId('automation-state').innerText()) === 'On' && (await ws.api(ws.owner, 'GET', `/v1/automations/${id}`)).json.automation.nextDueAt > Date.now());

  // Someone else cannot open it.
  const other = await ctx.browser().newContext({ viewport: { width: 1000, height: 800 } });
  const op = await other.newPage();
  await signIn(op, mia.email);
  await op.getByTestId('automations-link').waitFor({ timeout: 30000 });
  check('another member does not see the Automation or the analytics button', (await op.getByTestId('analytics-link').count()) === 0 && (await op.getByTestId('automations-link').count()) === 1);
  await op.goto(W + `/dashboard/automations/${id}`, { waitUntil: 'networkidle' });
  await op.getByText('Automation not found').waitFor({ timeout: 15000 });
  check('another member opening its address is told it was not found', true);

  await page.getByTestId('archive').click();
  await page.getByTestId('archive').filter({ hasText: /Confirm/ }).waitFor({ timeout: 5000 });
  await page.getByTestId('archive').click();
  await page.getByTestId('notice').filter({ hasText: /Archived/ }).waitFor({ timeout: 15000 });
  check('archiving keeps the history and removes the controls', (await page.getByTestId('automation-state').innerText()) === 'Archived' && (await page.getByTestId('run-now').count()) === 0 && (await page.getByTestId('run-row').count()) >= 2);

  // ---- analytics
  const iso = (ms) => new Date(Date.now() - ms).toISOString();
  await ws.api(ws.owner, 'POST', '/v1/telemetry/ingest', { events: [
    { type: 'session.started', timestamp: iso(1000), source: 'app', sessionId: 's1', dimensions: [{ type: 'model', label: 'Claude X', value: 'claude-x' }] },
    { type: 'task.completed', timestamp: iso(2000), source: 'app', sessionId: 's1', durationMs: 2000 },
    { type: 'task.failed', timestamp: iso(3000), source: 'app', sessionId: 's2' },
  ] });
  await ws.api(mia, 'POST', '/v1/telemetry/ingest', { events: [{ type: 'user.active', timestamp: iso(500), source: 'app' }] });
  await page.goto(W + '/dashboard/analytics', { waitUntil: 'networkidle' });
  await page.getByTestId('analytics-summary').waitFor({ timeout: 20000 });
  check('analytics show people, sessions and tasks', (await page.getByTestId('stat-members').innerText()) === '2' && (await page.getByTestId('stat-active').innerText()) === '2 / 2' && (await page.getByTestId('stat-sessions').innerText()) === '2 / 2' && (await page.getByTestId('stat-done').innerText()) === '1 / 1' && (await page.getByTestId('stat-failed').innerText()) === '1 / 1' && /2\.0 s/.test(await page.getByTestId('stat-average').innerText()));
  check('the trend has twelve weeks and models are listed', (await page.getByTestId('week-row').count()) === 12 && /Claude X/.test(await page.getByTestId('models-list').innerText()));
  if (shots) await page.screenshot({ path: shots + '/ui-analytics.png', fullPage: true });
  await op.goto(W + '/dashboard/analytics', { waitUntil: 'networkidle' });
  await op.getByTestId('analytics-denied').waitFor({ timeout: 15000 });
  check('a member without the permission is told so', true);

  await finish(browser, errors);
})().catch((e) => { console.error(e); process.exit(1); });
