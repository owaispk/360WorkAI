// The AI Gateway page in a real browser, against a REAL LiteLLM: add a provider on the deployment's proxy, see its models and grants, prove a
// person's key works at LiteLLM, take access away in the page and see the key stop working. Start the rewrite as in area-gateway.mjs, then:
//   W=http://localhost:5081 A=http://localhost:5080 LITELLM=http://127.0.0.1:4000 node tests/parity/ui-gateway.js [screenshot-dir]
const { chromium } = require('playwright');
const { W, check, workspace, until, signIn, finish } = require('./ui-lib');
const LITELLM = (process.env.LITELLM || 'http://127.0.0.1:4000').replace(/\/+$/, '');
const MODEL = process.env.MODEL || 'fake-small';
const shots = process.argv[2];

async function complete(key) {
  const r = await fetch(`${LITELLM}/v1/chat/completions`, { method: 'POST', headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' }, body: JSON.stringify({ model: MODEL, messages: [{ role: 'user', content: 'ping' }], max_tokens: 5 }) });
  return r.status;
}

(async () => {
  const ws = await workspace(`Gateway UI ${Math.floor(Math.random() * 1e6).toString(36)}`);
  const member = await ws.join('Gina Member');
  const browser = await chromium.launch();
  const errors = [];
  const page = await (await browser.newContext({ viewport: { width: 1280, height: 900 } })).newPage();
  page.on('pageerror', (e) => errors.push(String(e).slice(0, 160)));
  await signIn(page, ws.owner.email);

  await page.goto(`${W}/dashboard`, { waitUntil: 'networkidle', timeout: 60000 });
  await page.getByTestId('ai-gateway-link').click();
  await page.getByTestId('ai-gateway-page').waitFor({ timeout: 30000 });
  await page.getByTestId('create-form').waitFor({ timeout: 30000 });
  check('the dashboard links to the AI Gateway page', page.url().endsWith('/dashboard/ai-gateway'));

  await page.getByTestId('create-provider').click();
  await page.getByTestId('gateway-provider').waitFor({ timeout: 60000 });
  const card = page.getByTestId('gateway-provider').first();
  const groups = await card.getByTestId('model-group').allInnerTexts();
  check('adding a provider shows the synced models in the all-models group', groups.some((g) => g.includes('All LiteLLM models') && g.includes(MODEL)), groups.join(' | '));
  check('everyone in the workspace is allowed', (await card.getByTestId('grant-row').allInnerTexts()).some((t) => t.includes('Everyone')));
  if (shots) await page.screenshot({ path: `${shots}/gateway-provider.png`, fullPage: true });

  const id = await card.getAttribute('data-id');
  const connect = await ws.api(member, 'GET', `/v1/inference-providers/${id}/connect`);
  const key = connect.json?.inferenceProvider?.apiKey;
  check("the member's key answers at LiteLLM", !!key && (await complete(key)) === 200, connect.status);

  await card.getByTestId('remove-grant').first().click();
  await page.getByTestId('notice').filter({ hasText: /Access removed/ }).waitFor({ timeout: 30000 });
  check('removing access in the page deletes the key at LiteLLM', (await until(async () => (await complete(key)) === 401, 15000)) === true);

  await card.getByTestId('grant-audience').selectOption({ label: 'Gina Member' }).catch(async () => card.getByTestId('grant-audience').selectOption({ index: 1 }));
  await card.getByTestId('add-grant').click();
  await page.getByTestId('notice').filter({ hasText: /Access granted/ }).waitFor({ timeout: 30000 });
  const again = await ws.api(member, 'GET', `/v1/inference-providers/${id}/connect`);
  check('allowing the person again gives them a working key', again.status === 200 && (await complete(again.json.inferenceProvider.apiKey)) === 200, again.status);

  await card.getByTestId('delete-provider').click();
  await card.getByTestId('confirm-delete').click();
  await page.getByTestId('no-gateway-providers').waitFor({ timeout: 30000 });
  check('deleting the provider takes the key back at LiteLLM', (await complete(again.json.inferenceProvider.apiKey)) === 401);
  await finish(browser, errors);
})();
