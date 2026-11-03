// SAML single sign-on in a real browser against the rewrite, with a local fake SAML identity provider (fake-saml-idp.cjs: real RSA signatures).
//   W=http://localhost:5290 A=http://localhost:5190 node ui-saml.js [screenshot-dir]
// The server must run in Development, where an identity provider on loopback counts as a proven domain (nobody can publish DNS for localhost).
const { chromium } = require('playwright');
const { startFakeSamlIdp } = require('./fake-saml-idp.cjs');
const { W, A, PW, check, api, until, signIn, finish } = require('./ui-lib');
const shots = process.argv[2];

(async () => {
  const idp = await startFakeSamlIdp({ host: '127.0.0.1' });
  const browser = await chromium.launch();
  const errors = [];
  const domain = `ui-saml-${Date.now()}.test`;
  const ownerEmail = `owner@${domain}`;

  const up = await api('POST', '/api/auth/sign-up/email', { name: 'Olive Owner', email: ownerEmail, password: PW });
  const token = up.json.token;
  const org = (await api('POST', '/v1/org', { name: 'SAML Workspace' }, token)).json.organization;
  idp.identity = { nameId: ownerEmail, email: ownerEmail, name: 'Olive Owner' };

  const ctx = await browser.newContext({ viewport: { width: 1280, height: 1300 } });
  const page = await ctx.newPage(); page.on('pageerror', (e) => errors.push(String(e).slice(0, 160)));
  await signIn(page, ownerEmail);

  // ---- Settings: connect, read the addresses for the provider, test, turn on ----
  await page.goto(W + '/dashboard/sso', { waitUntil: 'networkidle' });
  await page.getByTestId('sso-page').waitFor({ timeout: 30000 });
  await page.getByTestId('sso-type').selectOption('saml');
  await page.locator('#sso-entry-point').waitFor({ timeout: 20000 });
  check('choosing SAML swaps the form for the SAML fields', (await page.locator('#sso-entry-point').count()) === 1 && (await page.locator('#sso-cert').count()) === 1 && (await page.locator('#sso-client-secret').count()) === 0);
  await page.locator('#sso-issuer').fill(idp.entityId);
  await page.locator('#sso-domain-input').fill(domain);
  await page.locator('#sso-entry-point').fill(idp.ssoUrl);
  await page.locator('#sso-cert').fill('not a certificate');
  await page.getByTestId('sso-save').click();
  await page.getByTestId('error').waitFor({ timeout: 20000 });
  check('a bad certificate is explained, nothing is saved', /not a valid X\.509 certificate/.test(await page.getByTestId('error').innerText()) && (await page.getByTestId('sso-summary').count()) === 0);
  await page.locator('#sso-cert').fill(idp.certPem);
  await page.getByTestId('sso-save').click();
  await page.getByTestId('sso-summary').waitFor({ timeout: 20000 });
  check('saving shows a SAML connection, turned off', (await page.getByTestId('sso-kind').innerText()) === 'SAML 2.0' && (await page.getByTestId('sso-status').innerText()) === 'disabled');
  const acs = await page.getByTestId('sso-acs-url').innerText();
  check('the page shows the ACS address, the entity id and the metadata link for the provider', /\/api\/auth\/sso\/saml2\/sp\/acs\/openwork-sso-/.test(acs) && (await page.getByTestId('sso-entity-id').innerText()).startsWith('http') && /sp\/metadata\?providerId=/.test(await page.getByTestId('sso-metadata-url').innerText()));
  check('there is no OpenID Connect redirect URL on a SAML connection', (await page.getByTestId('sso-redirect-url').count()) === 0);
  check('the certificate text is not shown back', !(await page.locator('body').innerText()).includes('BEGIN CERTIFICATE'));
  const metadata = await (await fetch(await page.getByTestId('sso-metadata-url').getAttribute('href'))).text();
  check('the metadata link serves the service provider description', /<md:EntityDescriptor/.test(metadata) && metadata.includes(acs) && /WantAssertionsSigned="true"/.test(metadata));
  check('on a development server a loopback identity provider is proven, so no DNS step is shown', (await page.getByTestId('sso-domain-verified').innerText()) === 'Verified');
  if (shots) await page.screenshot({ path: shots + '/ui-saml-settings.png' });

  check('turning SSO on is not possible before a test', await page.getByTestId('sso-enable').isDisabled());
  const popupPromise = ctx.waitForEvent('page', { timeout: 30000 });
  await page.getByTestId('sso-test').click();
  const popup = await popupPromise;
  popup.on('pageerror', (e) => errors.push('popup: ' + String(e).slice(0, 160)));
  const tested = await until(async () => (await page.getByTestId('sso-test-state').innerText().catch(() => '')) === 'succeeded', 40000);
  check('the test opens the provider in a window and reports success here', !!tested);
  check('the provider got a real AuthnRequest: id, ACS address and the service provider as issuer', idp.requests.length === 1 && /^_[0-9a-f]{32}$/.test(idp.requests[0].id) && idp.requests[0].acs === acs && idp.requests[0].method === 'GET' && !!idp.requests[0].relayState);
  await page.getByTestId('sso-enable').click();
  await page.getByTestId('sso-status').filter({ hasText: 'enabled' }).waitFor({ timeout: 20000 });
  check('after a successful test SSO can be turned on', (await page.getByTestId('sso-status').innerText()) === 'enabled');

  // ---- Someone else signs in: the form sends their domain to SSO, the provider answers, the same browser comes back ----
  const fresh = await browser.newContext({ viewport: { width: 1000, height: 800 } });
  const p2 = await fresh.newPage(); p2.on('pageerror', (e) => errors.push(String(e).slice(0, 160)));
  idp.identity = { nameId: `newbie@${domain}`, email: `newbie@${domain}`, name: 'Newbie Person' };
  await p2.goto(W + '/', { waitUntil: 'networkidle', timeout: 120000 });
  await p2.locator('input[type="email"]').fill(`newbie@${domain}`);
  await p2.getByRole('button', { name: /^next$/i }).click();
  await p2.waitForURL(/\/dashboard/, { timeout: 60000 });
  const me = await p2.evaluate(async () => (await (await fetch('/api/browser/v1/me', { credentials: 'include' })).json()));
  check('typing an address on a SAML domain leads through the provider and signs the person in', me.user?.email === `newbie@${domain}`);
  const joined = await p2.evaluate(async () => (await (await fetch('/api/browser/v1/org', { credentials: 'include' })).json()));
  check('the new person joined the workspace as a plain member', joined.currentMember?.role === 'member' && joined.organization?.id === org.id);
  check('the browser went through the ACS and the same-site last step', idp.requests.length === 2 && idp.requests[1].acs === acs);

  // ---- The same page from the workspace address, after the session ends ----
  const again = await browser.newContext({ viewport: { width: 1000, height: 800 } });
  const p3 = await again.newPage(); p3.on('pageerror', (e) => errors.push(String(e).slice(0, 160)));
  idp.identity = { nameId: `second@${domain}`, email: `second@${domain}`, name: 'Second Person' };
  await p3.goto(`${W}/sso/${org.slug}`, { waitUntil: 'networkidle', timeout: 120000 });
  await p3.waitForURL(/\/dashboard/, { timeout: 60000 });
  check('the workspace sign-in address works on its own', (await p3.evaluate(async () => (await (await fetch('/api/browser/v1/me', { credentials: 'include' })).json()))).user?.email === `second@${domain}`);

  // ---- A bad response explains itself and signs nobody in ----
  idp.fault = 'badsig';
  idp.identity = { nameId: `mallory@${domain}`, email: `mallory@${domain}`, name: 'Mallory' };
  const failing = await browser.newContext({ viewport: { width: 1000, height: 800 } });
  const p4 = await failing.newPage(); p4.on('pageerror', (e) => errors.push(String(e).slice(0, 160)));
  await p4.goto(`${W}/sso/${org.slug}`, { waitUntil: 'networkidle', timeout: 120000 });
  await p4.getByTestId('sso-error').waitFor({ timeout: 60000 });
  const text = await p4.getByTestId('sso-error').innerText();
  check('a response that fails signature validation ends on a clear page with a way back', /refused/.test(text) && /could not be verified/.test(text) && (await p4.getByTestId('sso-retry').count()) === 1);
  const mallory = await p4.evaluate(async () => (await fetch('/api/browser/v1/me', { credentials: 'include' })).status);
  check('nobody was signed in by it', mallory === 401);
  if (shots) await p4.screenshot({ path: shots + '/ui-saml-failed.png' });
  idp.fault = '';

  // ---- A replayed response is refused ----
  const replayCtx = await browser.newContext({ viewport: { width: 1000, height: 800 } });
  const p5 = await replayCtx.newPage();
  idp.identity = { nameId: `third@${domain}`, email: `third@${domain}`, name: 'Third Person' };
  await p5.goto(`${W}/sso/${org.slug}`, { waitUntil: 'networkidle', timeout: 120000 });
  await p5.waitForURL(/\/dashboard/, { timeout: 60000 });
  const sent = idp.responses.at(-1);
  const replay = await fetch(sent.acs, { method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ SAMLResponse: sent.response, RelayState: sent.relayState }) });
  check('posting a captured response a second time is refused', replay.status === 302 && /error=/.test(replay.headers.get('location') ?? ''));

  // ---- Turn it off ----
  await page.goto(W + '/dashboard/sso', { waitUntil: 'networkidle' });
  await page.getByTestId('sso-disable').click();
  await page.getByTestId('sso-status').filter({ hasText: 'disabled' }).waitFor({ timeout: 20000 });
  const back = await api('POST', '/api/auth/sign-in/email', { email: ownerEmail, password: PW });
  check('turning SSO off gives members their password back', back.status === 200);
  if (shots) await page.screenshot({ path: shots + '/ui-saml-off.png' });

  await idp.close();
  await finish(browser, errors);
})().catch((e) => { console.error(e); process.exit(1); });
