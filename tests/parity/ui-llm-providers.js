// Model providers (/dashboard/custom-llm-providers) in a real browser: add from the catalog, test a custom endpoint and save it, a person's own key,
// blocking it, and deleting. Start the rewrite so it may reach this script's local fake endpoint and uses the bundled catalog:
//   export WORKAI360_API_URL=http://localhost:5192 WORKAI360_WEB_URL=http://localhost:5292 WORKAI360_RUN_DIR=/tmp/workai-llm-run \
//     ConnectionStrings__Default="Data Source=/tmp/workai-llm.db" Connections__AllowPrivateUrls=true LlmProviders__CatalogUrl=
//   rm -f /tmp/workai-llm.db*; scripts/dev.sh start
//   W=$WORKAI360_WEB_URL A=$WORKAI360_API_URL node tests/parity/ui-llm-providers.js [screenshot-dir]
const http = require('http');
const { chromium } = require('playwright');
const { W, check, api, workspace, until, signIn, finish } = require('./ui-lib');
const shots = process.argv[2];
const KEY = 'sk-ui-fake-key';

/** An OpenAI-compatible endpoint that serves two models to the right key. */
function fakeEndpoint() {
  const server = http.createServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    if (req.headers.authorization !== `Bearer ${KEY}`) { res.statusCode = 401; return res.end('{"error":{"message":"bad key"}}'); }
    if (req.url === '/v1/models') return res.end('{"data":[{"id":"house-large"},{"id":"house-small"}]}');
    res.statusCode = 404; res.end('{}');
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, base: `http://127.0.0.1:${server.address().port}/v1` })));
}

(async () => {
  const fake = await fakeEndpoint();
  const ws = await workspace(`Providers ${Math.floor(Math.random() * 1e6).toString(36)}`);
  const member = await ws.join('Morgan Member');
  const browser = await chromium.launch();
  const errors = [];
  const shot = async (page, name) => { if (shots) await page.screenshot({ path: `${shots}/llm-${name}.png`, fullPage: true }); };

  const owner = await (await browser.newContext({ viewport: { width: 1280, height: 900 } })).newPage();
  owner.on('pageerror', (e) => errors.push(String(e).slice(0, 160)));
  await signIn(owner, ws.owner.email);
  await owner.getByTestId('llm-providers-link').click();
  await owner.getByTestId('llm-providers-page').waitFor({ timeout: 30000 });
  check('the dashboard links to model providers', true);
  await owner.getByTestId('no-providers').waitFor({ timeout: 20000 });

  // ---- from the catalog -------------------------------------------------------------------------------------------------------------
  await owner.getByTestId('add-provider').click();
  await owner.getByTestId('provider-form').waitFor({ timeout: 30000 });
  await owner.getByTestId('catalog-select').selectOption('openai');
  await owner.locator('[data-model="gpt-4o"]').waitFor({ timeout: 20000 });
  await owner.locator('[data-model="gpt-4o"]').check();
  await owner.locator('[data-env="OPENAI_API_KEY"]').fill('sk-team-openai');
  await shot(owner, '1-new-catalog');
  await owner.getByTestId('save-provider').click();
  await owner.getByTestId('llm-provider-detail-page').waitFor({ timeout: 30000 });
  await owner.getByTestId('provider-name').waitFor({ timeout: 20000 });
  check('saving goes to the provider page, named after the catalog entry', (await owner.getByTestId('provider-name').innerText()).includes('OpenAI'));
  check('the chosen model is listed', (await owner.getByTestId('models').innerText()).includes('gpt-4o'));
  const list = (await ws.api(member, 'GET', '/v1/llm-providers')).json.llmProviders;
  const openai = list.find((p) => p.providerId === 'openai');
  check('the member can use it (shared with everyone)', Boolean(openai), JSON.stringify(list));
  const connect = (await ws.api(member, 'GET', `/v1/llm-providers/${openai.id}/connect`)).json.llmProvider;
  check('the member\'s desktop receives the key', connect.apiKey === 'sk-team-openai');

  // ---- custom endpoint, tested first ---------------------------------------------------------------------------------------------------
  await owner.goto(`${W}/dashboard/custom-llm-providers/new`, { waitUntil: 'networkidle', timeout: 60000 });
  await owner.getByTestId('provider-form').waitFor({ timeout: 30000 });
  await owner.locator('#lp-name').fill('House Models');
  await owner.getByTestId('source-custom').check();
  await owner.locator('#lp-api').fill(`${fake.base}/chat/completions`);
  await owner.locator('#lp-probe-key').fill('wrong');
  await owner.getByTestId('test-connection').click();
  check('a wrong key is explained', await until(async () => /rejected the key/.test(await owner.getByTestId('probe-result').innerText().catch(() => ''))));
  await owner.locator('#lp-probe-key').fill(KEY);
  await owner.getByTestId('test-connection').click();
  check('the right key lists the endpoint\'s models', await until(async () => /2 models/.test(await owner.getByTestId('probe-result').innerText().catch(() => ''))));
  await owner.getByTestId('use-probe').click();
  check('the configuration is written from the test', await until(async () => /house-large/.test(await owner.getByTestId('custom-config').inputValue())));
  await owner.getByTestId('mode-per-member').check();
  await shot(owner, '2-new-custom');
  await owner.getByTestId('save-provider').click();
  await owner.getByTestId('provider-name').waitFor({ timeout: 30000 });
  const houseId = owner.url().split('/').pop();
  check('the custom provider is saved', (await owner.getByTestId('models').innerText()).includes('house-small'));

  // ---- a person's own key, then blocked ------------------------------------------------------------------------------------------------
  const mem = await (await browser.newContext({ viewport: { width: 1280, height: 900 } })).newPage();
  mem.on('pageerror', (e) => errors.push(String(e).slice(0, 160)));
  await signIn(mem, member.email);
  await mem.goto(`${W}/dashboard/custom-llm-providers/${houseId}`, { waitUntil: 'networkidle', timeout: 60000 });
  await mem.getByTestId('my-credential-form').waitFor({ timeout: 30000 });
  await mem.locator('#lp-mine').fill('sk-morgan-own');
  await mem.getByTestId('save-my-credential').click();
  check('the member saves their own key', await until(async () => /Your key is saved/.test(await mem.getByTestId('my-credential-state').innerText())));
  const mine = (await ws.api(member, 'GET', `/v1/llm-providers/${houseId}/connect`)).json.llmProvider;
  check('their desktop receives their own key', mine.apiKey === 'sk-morgan-own' && mine.memberCredential.state === 'active');
  await shot(mem, '3-my-key');

  await owner.goto(`${W}/dashboard/custom-llm-providers/${houseId}`, { waitUntil: 'networkidle', timeout: 60000 });
  const row = owner.getByTestId('member-credential-row').filter({ hasText: 'Morgan' });
  await row.waitFor({ timeout: 30000 });
  check('the owner sees the member\'s key state, not the key', /Key saved/.test(await row.innerText()) && !(await owner.content()).includes('sk-morgan-own'));
  await row.getByTestId('block-member-credential').click();
  check('blocking shows on the page', await until(async () => /Blocked by an administrator/.test(await row.innerText())));
  await shot(owner, '4-people-keys');
  await mem.locator('#lp-mine').fill('sk-morgan-again');
  await mem.getByTestId('save-my-credential').click();
  check('a blocked member is told why they cannot replace it', await until(async () => /blocked your key/.test(await mem.getByTestId('error').innerText().catch(() => ''))));

  // ---- delete ---------------------------------------------------------------------------------------------------------------------------
  await owner.getByTestId('delete-provider').click();
  await owner.getByTestId('confirm-delete').click();
  await owner.getByTestId('llm-providers-page').waitFor({ timeout: 30000 });
  check('deleting returns to the list without it', await until(async () => !(await owner.getByTestId('provider-list').innerText()).includes('House Models')));
  check('the deleted provider is gone for the member', (await ws.api(member, 'GET', `/v1/llm-providers/${houseId}/connect`)).status === 404);

  fake.server.close();
  await finish(browser, errors);
})();
