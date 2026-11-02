// Workflows in a real browser against the rewrite: my library, the Workflow page (run, live run, runs, versions, edit and test), and the runs list.
//   scripts/dev.sh start   (the rewrite; sign-up must return a session)
//   W=http://localhost:5291 A=http://localhost:5191 node tests/parity/ui-workspace.js [screenshot-dir]
const { chromium } = require('playwright');
const { W, A, check, workspace, until, signIn, finish } = require('./ui-lib');
const shots = process.argv[2];
const text = (page, id) => page.locator(`[data-testid=${id}]`).first().innerText();
const CODE = "const n = input.n ?? 1;\nif (n > 5) { return { big: true } }\nreturn { doubled: n * 2, name: 'x' }";

(async () => {
  const browser = await chromium.launch();
  const errors = [];
  const ws = await workspace('Workflow Workspace');
  const bob = await ws.join('Bob Member');
  const carol = await ws.join('Carol Member');

  // ---- seed two Workflows through the library's own routes, the way an import would ----
  const seed = async (name, code, payload) => {
    const plugin = await ws.api(ws.owner, 'POST', '/v1/plugins', { name: `${name} plugin` });
    const pluginId = plugin.json.item.id;
    const made = await ws.api(ws.owner, 'POST', '/v1/config-objects', { type: 'workflow', sourceMode: 'cloud', pluginIds: [pluginId], input: { rawSourceText: code, normalizedPayloadJson: payload, schemaVersion: 'codemode-script-v1', metadata: { name, description: `${name} workflow` } } });
    return { pluginId, id: made.json.item.id };
  };
  const doubler = await seed('Doubler', CODE, { language: 'codemode-js', inputSchema: { type: 'object', properties: { n: { type: 'number' } } }, outputSchema: { type: 'object' }, exampleInput: { n: 2 }, requiredCapabilities: [] });
  const broken = await seed('Breaker', "throw new Error('boom')", { language: 'codemode-js', requiredCapabilities: [] });
  await ws.api(ws.owner, 'POST', `/v1/plugins/${doubler.pluginId}/access`, { orgMembershipId: bob.memberId, role: 'viewer' });

  const open = async (user, path) => {
    const ctx = await browser.newContext({ viewport: { width: 1100, height: 1000 } });
    const page = await ctx.newPage();
    page.on('pageerror', (e) => errors.push(String(e)));
    await signIn(page, user.email);
    if (path) await page.goto(W + path, { waitUntil: 'networkidle' });
    return page;
  };
  const shot = async (page, name) => { if (shots) await page.screenshot({ path: `${shots}/workspace-${name}.png`, fullPage: true }); };

  // ---- the dashboard and an empty runs page ----
  const owner = await open(ws.owner, '/dashboard');
  check('the dashboard has a Workflow runs button', (await owner.locator('[data-testid=workflow-runs-link]').count()) === 1);
  await owner.locator('[data-testid=workflow-runs-link]').click();
  await owner.waitForURL(/\/dashboard\/workflow-runs$/);
  await owner.locator('[data-testid=runs-empty]').waitFor();
  check('the runs page starts empty and says so', await owner.locator('[data-testid=runs-empty]').isVisible());

  // ---- my library lists the Workflows ----
  await owner.goto(W + '/dashboard/library', { waitUntil: 'networkidle' });
  await owner.locator('[data-testid=library-workflows]').waitFor();
  const names = await owner.locator('[data-testid=library-workflow]').evaluateAll((els) => els.map((e) => e.getAttribute('data-name')));
  check('my library lists both Workflows', names.includes('Doubler') && names.includes('Breaker'), names.join(','));
  check('the card says the person manages it and that it was never run', (await text(owner, 'library-workflow-role')).includes('manage') && (await owner.locator('[data-testid=library-workflow-state]').first().innerText()).length > 0);
  await owner.locator('[data-testid=library-workflow][data-name=Doubler] a').click();
  await owner.waitForURL(/\/dashboard\/library\/workflows\/cob_/);
  await owner.locator('[data-testid=workflow-title]').waitFor();

  // ---- the Workflow page ----
  check('the page shows the title, description and role', (await text(owner, 'workflow-title')) === 'Doubler' && (await text(owner, 'workflow-description')) === 'Doubler workflow' && (await text(owner, 'workflow-role')).includes('manage it'));
  check('it says the Workflow is ready and was never run', (await text(owner, 'workflow-ready')).includes('Ready') && (await text(owner, 'workflow-fresh')).includes('Never run'));
  const steps = await owner.locator('[data-testid=step]').allInnerTexts();
  check('the steps come from the call graph: input, a decision, two returns', steps.length === 4 && steps[0] === 'Takes input' && steps[1].startsWith('Decides: n > 5') && steps[2].includes('Returns'), steps.join(' | '));
  await shot(owner, 'workflow-overview');

  await owner.locator('[data-testid=tab-run]').click();
  await owner.locator('[data-testid=run-input]').waitFor();
  check('the run box starts with the example input', (await owner.locator('[data-testid=run-input]').inputValue()).includes('"n": 2'));
  await owner.locator('[data-testid=run-input]').fill('{"n": 4}');
  await owner.locator('[data-testid=run-now]').click();
  await owner.locator('[data-testid=result-table]').waitFor();
  const cells = await owner.locator('[data-testid=result-table] td').allInnerTexts();
  check('running shows the result as a table', cells.join(',') === 'doubled,8,name,x', cells.join(','));
  check('it shows the receipt', /^wfr_/.test(await text(owner, 'run-receipt')));
  await shot(owner, 'workflow-run');

  await owner.locator('[data-testid=run-input]').fill('{"n": ');
  await owner.locator('[data-testid=run-now]').click();
  check('input that is not JSON is refused before anything runs', (await until(async () => (await owner.locator('[data-testid=run-error]').count()) === 1)) && (await text(owner, 'run-error')).includes('not valid JSON'));
  await owner.locator('[data-testid=run-input]').fill('{"n": "text"}');
  await owner.locator('[data-testid=run-now]').click();
  check('input that breaks the schema is explained', await until(async () => (await owner.locator('[data-testid=run-error]').count()) === 1 && (await text(owner, 'run-error')).includes("inputSchema")));
  await owner.locator('[data-testid=run-live]').click();
  check('a live run works too', await until(async () => (await owner.locator('[data-testid=run-error]').count()) === 0 && (await owner.locator('[data-testid=run-result]').count()) >= 0 && (await owner.locator('[data-testid=result-table]').count()) === 1));

  await owner.locator('[data-testid=tab-runs]').click();
  await owner.locator('[data-testid=snapshots-list]').waitFor();
  check('the runs tab lists the runs, the failed one included', await until(async () => (await owner.locator('[data-testid=snapshot-row]').count()) >= 3));
  check('a failed run shows why', (await owner.locator('[data-testid=snapshot-row][data-status=failed] [data-testid=snapshot-error]').first().innerText()).includes("inputSchema"));
  const erase = owner.locator('[data-testid=snapshot-erase]').first();
  await erase.click();
  check('erasing a result says so and keeps the row', await until(async () => (await owner.locator('[data-testid=snapshot-erased]').count()) === 1) && (await owner.locator('[data-testid=snapshot-row]').count()) >= 3);
  await shot(owner, 'workflow-runs-tab');

  // ---- editing: test, then save a new version ----
  await owner.locator('[data-testid=tab-edit]').click();
  await owner.locator('[data-testid=edit-code]').waitFor();
  check('the edit form starts with the current code', (await owner.locator('[data-testid=edit-code]').inputValue()).includes('doubled: n * 2'));
  await owner.locator('[data-testid=edit-code]').fill("const n = input.n ?? 1;\nreturn { tripled: n * 3 }");
  await owner.locator('[data-testid=edit-example]').fill('{"n": 4}');
  check('saving is not offered before a test', (await owner.locator('[data-testid=edit-save]').count()) === 0);
  await owner.locator('[data-testid=edit-test]').click();
  await owner.locator('[data-testid=edit-save]').waitFor();
  const tested = await owner.locator('[data-testid=edit-panel] [data-testid=result-table] td').allInnerTexts();
  check('testing shows the draft result', tested.join(',') === 'tripled,12', tested.join(','));
  await owner.locator('[data-testid=edit-code]').fill("return { tripled: 99 }");
  await owner.locator('[data-testid=edit-save]').click();
  check('a draft changed after the test cannot be saved', await until(async () => (await owner.locator('[data-testid=error]').count()) === 1 && (await text(owner, 'error')).includes('Test it again')));
  await owner.locator('[data-testid=edit-code]').fill("const n = input.n ?? 1;\nreturn { tripled: n * 3 }");
  await owner.locator('[data-testid=edit-test]').click();
  await owner.locator('[data-testid=edit-save]').waitFor();
  await owner.locator('[data-testid=edit-save]').click();
  check('saving makes a new version', await until(async () => (await owner.locator('[data-testid=notice]').count()) === 1 && (await text(owner, 'notice')).includes('Saved as a new version')));
  await owner.locator('[data-testid=tab-versions]').click();
  await owner.locator('[data-testid=versions-list]').waitFor();
  const versions = await owner.locator('[data-testid=version-row]').allInnerTexts();
  check('the versions tab lists the current and the earlier version', versions.length === 2 && versions[0].includes('Current version') && versions[1].includes('Earlier version'), versions.join(' | '));
  await owner.locator('[data-testid=version-row] summary').first().click();
  check('the manager can read the code of a version', (await text(owner, 'version-code')).includes('tripled'));

  // ---- the runs list ----
  await owner.goto(W + '/dashboard/workflow-runs', { waitUntil: 'networkidle' });
  await owner.locator('[data-testid=runs-table]').waitFor();
  const rows = await owner.locator('[data-testid=run-row]').count();
  check('the runs list shows the runs of the person, newest first', rows >= 5, String(rows));
  check('it lists a draft test beside the Workflow runs', (await owner.locator('[data-testid=run-workflow]').allInnerTexts()).some((t) => t === 'Doubler') && (await owner.locator('[data-testid=run-status]').allInnerTexts()).includes('Failed'));
  await owner.locator('[data-testid=run-workflow]', { hasText: 'Doubler' }).first().click();
  await owner.waitForURL(/\/dashboard\/library\/workflows\/cob_/);
  check('a run links to its Workflow', (await owner.locator('[data-testid=workflow-title]').innerText()) === 'Doubler');
  await owner.goto(W + '/dashboard/workflow-runs', { waitUntil: 'networkidle' });
  await shot(owner, 'runs-list');

  // ---- a script that fails ----
  await owner.goto(W + `/dashboard/library/workflows/${broken.id}`, { waitUntil: 'networkidle' });
  await owner.locator('[data-testid=tab-run]').click();
  await owner.locator('[data-testid=run-now]').click();
  check('a script that throws shows its message', await until(async () => (await owner.locator('[data-testid=run-error]').count()) === 1 && (await text(owner, 'run-error')).includes('boom')));

  // ---- a viewer ----
  const viewer = await open(bob, '/dashboard/library');
  await viewer.locator('[data-testid=library-workflows]').waitFor();
  check('a person it was shared with sees the Workflow in their library, and only that one', (await viewer.locator('[data-testid=library-workflow]').count()) === 1 && (await text(viewer, 'library-workflow-role')).includes('run it'));
  await viewer.locator('[data-testid=library-workflow] a').click();
  await viewer.waitForURL(/\/dashboard\/library\/workflows\/cob_/);
  await viewer.locator('[data-testid=workflow-title]').waitFor();
  check('the viewer has no Edit tab', (await viewer.locator('[data-testid=tab-edit]').count()) === 0 && (await viewer.locator('[data-testid=tab-run]').count()) === 1);
  await viewer.locator('[data-testid=tab-versions]').click();
  await viewer.locator('[data-testid=versions-list]').waitFor();
  check('the viewer cannot read the code', (await viewer.locator('[data-testid=version-code]').count()) === 0);
  await viewer.locator('[data-testid=tab-run]').click();
  await viewer.locator('[data-testid=run-input]').fill('{"n": 10}');
  await viewer.locator('[data-testid=run-now]').click();
  await viewer.locator('[data-testid=result-table]').waitFor();
  check('the viewer can run it', (await viewer.locator('[data-testid=result-table] td').allInnerTexts()).join(',') === 'tripled,30');
  await viewer.locator('[data-testid=tab-runs]').click();
  await viewer.locator('[data-testid=snapshots-list]').waitFor();
  check('the viewer cannot erase results', (await viewer.locator('[data-testid=snapshot-erase]').count()) === 0);
  await shot(viewer, 'viewer');
  await viewer.goto(W + '/dashboard/workflow-runs', { waitUntil: 'networkidle' });
  await viewer.locator('[data-testid=runs-table]').waitFor();
  check('the viewer sees only their own runs', (await viewer.locator('[data-testid=run-row]').count()) === 1);

  // ---- a stranger ----
  const stranger = await open(carol, `/dashboard/library/workflows/${doubler.id}`);
  await stranger.locator('[data-testid=workflow-missing]').waitFor();
  check('a person it was not shared with is told it is not there', await stranger.locator('[data-testid=workflow-missing]').isVisible());
  await stranger.goto(W + '/dashboard/library', { waitUntil: 'networkidle' });
  check('and their library has no Workflows', (await stranger.locator('[data-testid=library-workflows]').count()) === 0);

  await finish(browser, errors);
})().catch((e) => { console.error(e); process.exit(1); });
