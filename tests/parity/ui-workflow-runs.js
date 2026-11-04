// The Workflow runs page in a real browser at den-web's address (/dashboard/analytics/workflow-runs) and its old ones.
//   W=http://localhost:5081 A=http://localhost:5080 node tests/parity/ui-workflow-runs.js [screenshot-dir]
const { chromium } = require('playwright');
const { W, check, workspace, until, signIn, finish } = require('./ui-lib');
const shots = process.argv[2];

const CODE = "const n = input.n ?? 1;\nreturn { doubled: n * 2, name: 'x' }";
const PAYLOAD = { language: 'codemode-js', inputSchema: { type: 'object', properties: { n: { type: 'number' } } }, outputSchema: { type: 'object' }, exampleInput: { n: 2 }, requiredCapabilities: [] };

(async () => {
  const ws = await workspace(`Runs ${Math.floor(Math.random() * 1e6).toString(36)}`);
  const plugin = await ws.api(ws.owner, 'POST', '/v1/plugins', { name: `Doubler plugin ${Date.now()}` });
  const pluginId = plugin.json.item.id;
  const made = await ws.api(ws.owner, 'POST', '/v1/config-objects', { type: 'workflow', sourceMode: 'cloud', pluginIds: [pluginId],
    input: { rawSourceText: CODE, normalizedPayloadJson: PAYLOAD, schemaVersion: 'codemode-script-v1', metadata: { name: 'Doubler', description: 'Doubles' } } });
  const wf = made.json.item;
  const ran = await ws.api(ws.owner, 'POST', `/v1/workflows/${wf.id}/run`, { pluginId, configObjectVersionId: wf.latestVersion.id, input: { n: 4 } });
  check('the Workflow ran', ran.status === 200, `${ran.status}`);

  const browser = await chromium.launch();
  const errors = [];
  const page = await (await browser.newContext({ viewport: { width: 1280, height: 900 } })).newPage();
  page.on('pageerror', (e) => errors.push(String(e).slice(0, 160)));
  await signIn(page, ws.owner.email);

  await page.goto(`${W}/dashboard/analytics/workflow-runs`, { waitUntil: 'networkidle', timeout: 60000 });
  await page.getByTestId('workflow-runs-page').waitFor({ timeout: 30000 });
  await page.getByTestId('run-row').first().waitFor({ timeout: 30000 });
  check('the analytics address lists the run', (await page.getByTestId('run-row').count()) === 1);
  check('the run names its Workflow and succeeded', /Doubler/.test(await page.getByTestId('run-workflow').first().innerText()) && /Succeeded/.test(await page.getByTestId('run-status').first().innerText()));
  if (shots) await page.screenshot({ path: `${shots}/workflow-runs.png`, fullPage: true });

  // A second run appears after "Refresh runs".
  await ws.api(ws.owner, 'POST', `/v1/workflows/${wf.id}/run`, { pluginId, configObjectVersionId: wf.latestVersion.id, input: { n: 5 } });
  await page.getByTestId('runs-refresh').click();
  check('refreshing shows the new run', await until(async () => (await page.getByTestId('run-row').count()) === 2));

  for (const path of ['/dashboard/workflow-runs', '/dashboard/script-runs']) {
    await page.goto(W + path, { waitUntil: 'networkidle', timeout: 60000 });
    await page.getByTestId('run-row').first().waitFor({ timeout: 30000 });
    check(`${path} shows the same page`, (await page.getByTestId('run-row').count()) === 2);
  }

  await page.goto(`${W}/dashboard/analytics`, { waitUntil: 'networkidle', timeout: 60000 });
  await page.getByTestId('analytics-workflow-runs').click();
  await page.waitForURL(/\/dashboard\/analytics\/workflow-runs/, { timeout: 30000 });
  check('Analytics links to the runs page', true);
  await finish(browser, errors);
})();
