// Single sign-on and SCIM in a real browser against the rewrite, with a local fake OpenID Connect provider.
//   W=http://localhost:5240 A=http://localhost:5140 node ui-sso.js [screenshot-dir]
// The server must run in Development, where an issuer on loopback counts as a proven domain (nobody can publish DNS for localhost).
const { chromium } = require('playwright');
const { startFakeOidc } = require('./fake-oidc.cjs');
const { W, A, PW, check, api, until, signIn, finish } = require('./ui-lib');
const shots = process.argv[2];

(async () => {
  const idp = await startFakeOidc({ host: '127.0.0.1' });
  const browser = await chromium.launch();
  const errors = [];
  const domain = `ui-${Date.now()}.test`;
  const ownerEmail = `owner@${domain}`;

  const up = await api('POST', '/api/auth/sign-up/email', { name: 'Olive Owner', email: ownerEmail, password: PW });
  const token = up.json.token;
  const orgId = (await api('POST', '/v1/org', { name: 'SSO Workspace' }, token)).json.organization.id;
  idp.identity = { sub: 'owner-sub', email: ownerEmail, email_verified: true, name: 'Olive Owner' };

  const ctx = await browser.newContext({ viewport: { width: 1280, height: 1100 } });
  const page = await ctx.newPage(); page.on('pageerror', (e) => errors.push(String(e).slice(0, 160)));
  await signIn(page, ownerEmail);

  // ---- Settings: connect, test, turn on ----
  await page.getByTestId('sso-link').click();
  await page.getByTestId('sso-page').waitFor({ timeout: 30000 });
  check('the dashboard offers Single sign-on to someone who may manage it', /\/dashboard\/sso/.test(page.url()));
  await page.locator('#sso-issuer').fill(idp.issuer);
  await page.locator('#sso-domain-input').fill(domain);
  await page.locator('#sso-client-id').fill(idp.clientId);
  await page.locator('#sso-client-secret').fill(idp.clientSecret);
  await page.getByTestId('sso-save').click();
  await page.getByTestId('sso-summary').waitFor({ timeout: 20000 });
  check('saving shows the connection, turned off, with its redirect URL', (await page.getByTestId('sso-status').innerText()) === 'disabled' && /\/api\/auth\/sso\/callback\//.test(await page.getByTestId('sso-redirect-url').innerText()));
  check('the client secret is not on the page after saving', !(await page.locator('body').innerText()).includes(idp.clientSecret) && (await page.locator('#sso-client-secret').inputValue()) === '');
  check('on a development server a loopback issuer is proven, so no DNS step is shown', (await page.getByTestId('sso-domain-verified').innerText()) === 'Verified' && (await page.getByTestId('sso-domain-panel').count()) === 0);
  if (shots) await page.screenshot({ path: shots + '/ui-sso-settings.png' });

  check('turning SSO on is not possible before a test', await page.getByTestId('sso-enable').isDisabled());
  const popupPromise = ctx.waitForEvent('page', { timeout: 30000 });
  await page.getByTestId('sso-test').click();
  const popup = await popupPromise;
  popup.on('pageerror', (e) => errors.push('popup: ' + String(e).slice(0, 160)));
  const tested = await until(async () => (await page.getByTestId('sso-test-state').innerText().catch(() => '')) === 'succeeded', 40000);
  check('the test opens the provider sign-in in a window and reports success here', !!tested);
  check('the test signed nobody in and asked the provider with PKCE, state and nonce', idp.authRequests.length === 1 && idp.authRequests[0].code_challenge_method === 'S256' && !!idp.authRequests[0].nonce && !!idp.authRequests[0].state);
  await page.getByTestId('sso-enable').click();
  await page.getByTestId('sso-status').filter({ hasText: 'enabled' }).waitFor({ timeout: 20000 });
  check('after a successful test SSO can be turned on', (await page.getByTestId('sso-status').innerText()) === 'enabled');
  if (shots) await page.screenshot({ path: shots + '/ui-sso-enabled.png' });

  // ---- Someone else signs in: the form sends their domain to SSO ----
  const fresh = await browser.newContext({ viewport: { width: 1000, height: 800 } });
  const p2 = await fresh.newPage(); p2.on('pageerror', (e) => errors.push(String(e).slice(0, 160)));
  idp.identity = { sub: 'newbie-sub', email: `newbie@${domain}`, email_verified: true, name: 'Newbie Person' };
  await p2.goto(W + '/', { waitUntil: 'networkidle', timeout: 120000 });
  await p2.locator('input[type="email"]').fill(`newbie@${domain}`);
  await p2.getByRole('button', { name: /^next$/i }).click();
  await p2.waitForURL(/\/dashboard/, { timeout: 60000 });
  const me = await p2.evaluate(async () => (await (await fetch('/api/browser/v1/me', { credentials: 'include' })).json()));
  check('typing an address on an SSO domain leads through the provider and signs the person in', me.user?.email === `newbie@${domain}`);
  const org = await p2.evaluate(async () => (await (await fetch('/api/browser/v1/org', { credentials: 'include' })).json()));
  check('the new person joined the workspace as a plain member', org.currentMember?.role === 'member' && org.organization?.id === orgId);

  // A person who is a member can no longer use a password.
  const blocked = await api('POST', '/api/auth/sign-in/email', { email: ownerEmail, password: PW });
  check('members of the workspace cannot sign in with a password any more', blocked.status === 403 && /managed by an organization/.test(blocked.json.message));

  // ---- A failed sign-in explains itself ----
  idp.fault = 'error';
  const failing = await browser.newContext({ viewport: { width: 1000, height: 800 } });
  const p3 = await failing.newPage();
  await p3.goto(W + '/', { waitUntil: 'networkidle', timeout: 120000 });
  await p3.locator('input[type="email"]').fill(`someone@${domain}`);
  await p3.getByRole('button', { name: /^next$/i }).click();
  await p3.getByTestId('sso-error').waitFor({ timeout: 60000 });
  check('a refusal at the provider ends on a clear page with a way back', /access_denied|No/.test(await p3.getByTestId('sso-error').innerText()) && (await p3.getByTestId('sso-retry').count()) === 1);
  if (shots) await p3.screenshot({ path: shots + '/ui-sso-failed.png' });
  idp.fault = '';

  // ---- SCIM ----
  await page.goto(W + '/dashboard/scim', { waitUntil: 'networkidle' });
  await page.getByTestId('scim-page').waitFor({ timeout: 30000 });
  check('SCIM shows the base URL and that single sign-on is on', (await page.getByTestId('scim-sso-ready').innerText()) === 'On' && /\/api\/auth\/scim\/v2$/.test(await page.getByTestId('scim-base-url').innerText()));
  await page.getByTestId('scim-token-button').click();
  await page.getByTestId('scim-token').waitFor({ timeout: 20000 });
  const scimToken = await page.getByTestId('scim-token').inputValue();
  check('creating a token shows it once', scimToken.length > 40 && (await page.getByTestId('scim-connection').innerText()) === 'Created');
  const made = await fetch(`${W}/api/auth/scim/v2/Users`, { method: 'POST', headers: { authorization: `Bearer ${scimToken}`, 'content-type': 'application/scim+json' }, body: JSON.stringify({ userName: `scim.person@${domain}`, externalId: 'ext-ui', name: { givenName: 'Scim', familyName: 'Person' } }) });
  const created = await made.json();
  check('an identity provider can create a person with that token', made.status === 201 && created.userName === `scim.person@${domain}`);
  await page.locator('#scim-mode').selectOption('create_teams');
  await page.getByTestId('notice').filter({ hasText: 'create and manage teams' }).waitFor({ timeout: 20000 });
  const group = await fetch(`${W}/api/auth/scim/v2/Groups`, { method: 'POST', headers: { authorization: `Bearer ${scimToken}`, 'content-type': 'application/scim+json' }, body: JSON.stringify({ displayName: 'Engineering', members: [{ value: created.id }] }) });
  const teams = (await api('GET', '/v1/org', null, token, orgId)).json.teams;
  check('with group mapping on, a group becomes a team with its people', group.status === 201 && teams.some((t) => t.name === 'Engineering' && t.memberIds.length === 1));
  if (shots) await page.screenshot({ path: shots + '/ui-scim.png' });
  const gone = await fetch(`${W}/api/auth/scim/v2/Users/${created.id}`, { method: 'DELETE', headers: { authorization: `Bearer ${scimToken}` } });
  check('deprovisioning through SCIM removes the person', gone.status === 204 && (await fetch(`${W}/api/auth/scim/v2/Users/${created.id}`, { headers: { authorization: `Bearer ${scimToken}` } })).status === 404);

  // ---- Turn it off ----
  await page.goto(W + '/dashboard/sso', { waitUntil: 'networkidle' });
  await page.getByTestId('sso-disable').click();
  await page.getByTestId('sso-status').filter({ hasText: 'disabled' }).waitFor({ timeout: 20000 });
  const back = await api('POST', '/api/auth/sign-in/email', { email: ownerEmail, password: PW });
  check('turning SSO off gives members their password back', back.status === 200);

  await idp.close();
  await finish(browser, errors);
})().catch((e) => { console.error(e); process.exit(1); });
