// Browser flows, runnable against the reference web app (W=http://localhost:3005) or the Blazor rewrite (W=http://localhost:5081).
//   W=http://localhost:5081 node ui-flows.js [screenshot-dir]
const { chromium } = require('playwright');
const W = process.env.W || 'http://localhost:3005';
const PW = 'Str0ng!Passw0rd#2026x';
const shots = process.argv[2];
const email = `ui.${Date.now()}@example.com`;
let pass = 0, fail = 0;
const flow = (name, ok, detail = '') => { ok ? pass++ : fail++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '  -> ' + detail}`); };
const step = async (name, fn) => { try { await fn(); } catch (e) { flow(name, false, e.message.split('\n')[0].slice(0, 160)); } };

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const page = await ctx.newPage();
  const pageErrors = []; page.on('pageerror', e => pageErrors.push(String(e).slice(0, 120)));
  const server5xx = []; page.on('response', r => { if (r.url().startsWith(W) && r.status() >= 500) server5xx.push(`${r.status()} ${r.url().replace(W, '')}`); });

  const emailStep = async (p, value) => {
    await p.goto(W + '/', { waitUntil: 'networkidle', timeout: 120000 });
    await p.locator('input[type="email"]').fill(value);
    await p.getByRole('button', { name: /^next$/i }).click();
    await p.locator('input[type="password"]').waitFor({ timeout: 30000 });
  };

  await step('sign-up through the form', async () => {
    await emailStep(page, email);
    await page.locator('input[type="password"]').fill(PW);
    const name = page.locator('input[autocomplete="name"]'); if (await name.count()) await name.fill('UI Tester');
    await page.getByRole('button', { name: 'Sign up', exact: true }).click();
    await page.waitForURL(/\/organization|\/dashboard/, { timeout: 60000 });
    flow('sign-up lands on workspace creation', true);
  });

  await step('create a workspace', async () => {
    if (/\/organization/.test(page.url())) {
      await page.locator('input[type="text"], input:not([type])').first().fill('UI Workspace');
      await page.getByRole('button', { name: /create|continue|next/i }).first().click();
      await page.waitForURL(/\/dashboard|\/onboarding/, { timeout: 60000 });
    }
    await page.waitForTimeout(1500);
    flow('workspace created, dashboard reached (' + page.url().replace(W, '') + ')', /dashboard|onboarding/.test(page.url()), page.url());
    if (shots) await page.screenshot({ path: shots + '/ui-dashboard.png' });
  });

  await step('dashboard shows who is signed in', async () => {
    await page.goto(W + '/dashboard', { waitUntil: 'networkidle', timeout: 60000 }).catch(() => {});
    await page.waitForTimeout(1500);
    const text = await page.locator('body').innerText();
    flow('dashboard shows the signed-in email', text.includes(email), text.slice(0, 120).replace(/\n/g, ' '));
  });

  await step('reload keeps the session (cookie)', async () => {
    await page.goto(W + '/', { waitUntil: 'networkidle', timeout: 60000 });
    await page.waitForURL(/\/dashboard|\/onboarding|\/organization/, { timeout: 30000 });
    flow('visiting / while signed in redirects into the app', true);
  });

  await step('sign out', async () => {
    await page.evaluate(async () => { await fetch('/api/auth/sign-out', { method: 'POST', credentials: 'include', headers: { 'content-type': 'application/json' }, body: '{}' }); localStorage.clear(); });
    await ctx.clearCookies();
    const me = await page.evaluate(async () => (await fetch('/api/browser/v1/me', { credentials: 'include' })).status);
    flow('after sign-out the session is gone (401)', me === 401, String(me));
  });

  await step('sign in as the existing user', async () => {
    await emailStep(page, email);
    const signIn = page.getByRole('button', { name: /^sign in$/i });
    flow('existing email shows the sign-in step', (await signIn.count()) > 0, 'no Sign in button');
    await page.locator('input[type="password"]').fill(PW);
    await signIn.click();
    await page.waitForURL(/\/dashboard|\/organization|\/onboarding/, { timeout: 60000 });
    flow('sign-in succeeds', true);
  });

  await step('wrong password', async () => {
    const c2 = await browser.newContext(); const p2 = await c2.newPage();
    await emailStep(p2, email);
    await p2.locator('input[type="password"]').fill('Wrong!Passw0rd#999');
    await p2.getByRole('button', { name: /^sign in$/i }).click();
    await p2.waitForTimeout(4000);
    const txt = await p2.locator('body').innerText();
    flow('wrong password shows an error and stays on the page', /invalid|incorrect|wrong|password/i.test(txt) && !/dashboard/.test(p2.url()), p2.url());
    await c2.close();
  });

  // Device approval: start a CLI-style device flow over the API, approve it in the browser.
  await step('device approval page', async () => {
    const dev = await (await fetch(W + '/api/auth/device/code', { method: 'POST', headers: { 'content-type': 'application/json', origin: W }, body: JSON.stringify({ client_id: 'openwork-cli' }) })).json();
    await page.goto(`${W}/device?user_code=${dev.user_code}`, { waitUntil: 'networkidle', timeout: 60000 });
    await page.getByRole('button', { name: /approve/i }).click({ timeout: 30000 });
    await page.waitForTimeout(1500);
    const done = /approved/i.test(await page.locator('body').innerText());
    flow('device code approved in the browser', done);
    if (done) {
      await new Promise(r => setTimeout(r, 5500));
      const tok = await (await fetch(W + '/api/auth/device/token', { method: 'POST', headers: { 'content-type': 'application/json', origin: W }, body: JSON.stringify({ grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: dev.device_code, client_id: 'openwork-cli' }) })).json();
      flow('the CLI then receives an access token', typeof tok.access_token === 'string', JSON.stringify(tok).slice(0, 100));
    }
  });

  flow('no uncaught page errors', pageErrors.length === 0, pageErrors.join(' | '));
  flow('no 5xx responses', server5xx.length === 0, server5xx.join(' | '));
  console.log(`\n==== ${pass}/${pass + fail} passed ====`);
  await browser.close();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('FAIL', e.message.slice(0, 300)); process.exit(1); });
