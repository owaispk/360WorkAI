// A real browser connecting an agent: authorize -> sign in -> consent -> callback -> token -> MCP call.
//   W=http://localhost:5081 A=http://localhost:5080 node ui-mcp.js [screenshot-dir]
const { chromium } = require('playwright');
const http = require('http');
const crypto = require('crypto');
const W = process.env.W || 'http://localhost:5081';
const A = process.env.A || 'http://localhost:5080';
const PW = 'Str0ng!Passw0rd#2026x';
const shots = process.argv[2];
let pass = 0, fail = 0;
const check = (name, ok, detail = '') => { ok ? pass++ : fail++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '  -> ' + detail}`); };
const b64u = (b) => b.toString('base64url');

// The agent's loopback callback: records what the browser is redirected to.
function callbackServer() {
  let resolveHit; const hit = new Promise(r => { resolveHit = r; });
  const server = http.createServer((req, res) => { res.end('You can close this tab.'); resolveHit(new URL(req.url, 'http://127.0.0.1')); });
  return new Promise(r => server.listen(0, '127.0.0.1', () => r({ port: server.address().port, hit, close: () => server.close() })));
}

async function api(path, body, headers = {}) {
  const res = await fetch(path, { method: body ? 'POST' : 'GET', headers: { 'content-type': 'application/json', origin: W, ...headers }, body: body ? JSON.stringify(body) : undefined, redirect: 'manual' });
  const text = await res.text(); let json = null; try { json = JSON.parse(text); } catch {}
  return { status: res.status, json, text };
}

async function register(redirect, name) {
  const r = await api(`${A}/register`, { client_name: name, redirect_uris: [redirect], token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'] });
  return r.json.client_id;
}
const pkce = () => { const verifier = b64u(crypto.randomBytes(32)); return { verifier, challenge: b64u(crypto.createHash('sha256').update(verifier).digest()) }; };
const authorizeUrl = (clientId, redirect, challenge, state, extra = '') =>
  `${W}/api/auth/oauth2/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirect)}&scope=${encodeURIComponent('mcp:read mcp:write offline_access')}&state=${state}&code_challenge=${challenge}&code_challenge_method=S256&resource=${encodeURIComponent(A + '/mcp/agent')}${extra}`;

async function signInThroughForm(page, email) {
  await page.locator('input[type="email"]').fill(email);
  await page.getByRole('button', { name: /^next$/i }).click();
  await page.locator('input[type="password"]').waitFor({ timeout: 30000 });
  await page.locator('input[type="password"]').fill(PW);
  await page.getByRole('button', { name: /^sign in$/i }).click();
}

(async () => {
  const browser = await chromium.launch();

  // ---- Scenario 1: an existing member connects an agent
  const email = `agent.${Date.now()}@example.com`;
  const signup = await api(`${W}/api/auth/sign-up/email`, { name: 'Agent Owner', email, password: PW });
  const bearer = signup.json.token;
  const org = await api(`${A}/v1/org`, { name: 'Agent Workspace' }, { authorization: `Bearer ${bearer}` });
  const orgId = org.json.organization.id;

  const cb = await callbackServer();
  const redirect = `http://127.0.0.1:${cb.port}/callback`;
  const clientId = await register(redirect, 'Test Agent');
  const { verifier, challenge } = pkce();

  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const page = await ctx.newPage();
  const errors = []; page.on('pageerror', e => errors.push(String(e).slice(0, 120)));

  await page.goto(authorizeUrl(clientId, redirect, challenge, 'state-1'), { waitUntil: 'networkidle', timeout: 120000 });
  check('signed-out agent is sent to the sign-in page, request preserved in the URL', /\/\?.*client_id=/.test(page.url().replace(W, '/')) && page.url().includes('sig='), page.url().slice(0, 120));
  await signInThroughForm(page, email);

  await page.waitForURL(/\/mcp\/consent\?/, { timeout: 60000 });
  await page.waitForSelector('[data-testid="mcp-consent"] button', { timeout: 30000 });
  await page.waitForTimeout(500);
  const text = await page.locator('body').innerText();
  check('after sign-in the person lands on the consent page', true);
  check('consent page names the app and the workspace', text.includes('Test Agent') && text.includes('Agent Workspace'), text.slice(0, 160).replace(/\n/g, ' '));
  check('consent page shows where the app returns to', (await page.locator('[data-testid="mcp-redirect-host"]').innerText()).includes(`127.0.0.1:${cb.port}`));
  check('consent page lists what is being granted in plain words', /See what your workspace can do/.test(text) && /Make changes in your workspace/.test(text));
  if (shots) await page.screenshot({ path: shots + '/ui-mcp-consent.png' });

  await page.getByRole('button', { name: 'Allow', exact: true }).click();
  const hit = await Promise.race([cb.hit, new Promise(r => setTimeout(() => r(null), 30000))]);
  check('Allow redirects to the agent callback with a code and the original state', !!hit && !!hit.searchParams.get('code') && hit.searchParams.get('state') === 'state-1', hit ? hit.search : 'no callback');

  const token = await fetch(`${W}/api/auth/oauth2/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', code: hit.searchParams.get('code'), redirect_uri: redirect, client_id: clientId, code_verifier: verifier, resource: A + '/mcp/agent' }) });
  const tokens = await token.json();
  check('the agent exchanges the code for tokens', token.status === 200 && !!tokens.access_token && !!tokens.refresh_token, JSON.stringify(tokens).slice(0, 100));

  const call = await fetch(`${A}/mcp/agent`, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', authorization: `Bearer ${tokens.access_token}` }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'execute_capability', arguments: { capability_id: 'openwork.whoami' } } }) });
  const who = (await call.json()).result?.structuredContent;
  check('the agent can then act in that workspace as that person', who?.user?.email === email && who?.organization?.id === orgId && who?.role === 'owner', JSON.stringify(who).slice(0, 120));
  cb.close();

  // ---- Scenario 2: already signed in, previously allowed: no consent screen the second time; prompt=consent forces it; Deny reports back
  const cb2 = await callbackServer();
  const redirect2 = `http://127.0.0.1:${cb2.port}/callback`;
  const client2 = await register(redirect2, 'Second Agent');
  const p2 = pkce();
  await page.goto(authorizeUrl(client2, redirect2, p2.challenge, 'state-2'), { waitUntil: 'domcontentloaded' }).catch(() => {});
  await page.waitForURL(/\/mcp\/consent\?/, { timeout: 60000 });
  await page.waitForSelector('[data-testid="mcp-consent"] button', { timeout: 30000 });
  check('a signed-in person is taken straight to the consent page', true);
  await page.getByRole('button', { name: 'Deny', exact: true }).click();
  const denied = await Promise.race([cb2.hit, new Promise(r => setTimeout(() => r(null), 30000))]);
  check('Deny reports access_denied with the state, and no code', !!denied && denied.searchParams.get('error') === 'access_denied' && denied.searchParams.get('state') === 'state-2' && !denied.searchParams.get('code'), denied ? denied.search : 'no callback');
  cb2.close();

  // The first agent was allowed earlier, so asking again does not show the screen again.
  const cb3 = await callbackServer();
  const redirect3 = `http://127.0.0.1:${cb3.port}/callback`;
  const client3 = await register(redirect3, 'Repeat Agent');
  const p3 = pkce();
  await page.goto(authorizeUrl(client3, redirect3, p3.challenge, 'state-3'), { waitUntil: 'domcontentloaded' }).catch(() => {});
  await page.waitForURL(/\/mcp\/consent\?/, { timeout: 60000 });
  await page.waitForSelector('[data-testid="mcp-consent"] button', { timeout: 30000 });
  await page.getByRole('button', { name: 'Allow', exact: true }).click();
  await Promise.race([cb3.hit, new Promise(r => setTimeout(r, 30000))]);
  await page.waitForURL(/127\.0\.0\.1/, { timeout: 30000 });
  await page.goto(W + '/dashboard', { waitUntil: 'networkidle' });
  const again = await page.evaluate(async (u) => { const r = await fetch(u, { redirect: 'manual' }); return { type: r.type, status: r.status }; }, authorizeUrl(client3, redirect3, pkce().challenge, 'state-4'));
  check('a repeat authorization for an allowed app skips the consent screen (redirects straight out)', again.type === 'opaqueredirect', JSON.stringify(again));
  cb3.close();

  // ---- Scenario 3: a brand-new person with no workspace connects an agent
  const fresh = `fresh.${Date.now()}@example.com`;
  await api(`${W}/api/auth/sign-up/email`, { name: 'Fresh Person', email: fresh, password: PW });
  const cb4 = await callbackServer();
  const redirect4 = `http://127.0.0.1:${cb4.port}/callback`;
  const client4 = await register(redirect4, 'Fresh Agent');
  const p4 = pkce();
  const ctx2 = await browser.newContext(); const page2 = await ctx2.newPage();
  await page2.goto(authorizeUrl(client4, redirect4, p4.challenge, 'state-5'), { waitUntil: 'networkidle', timeout: 120000 });
  await signInThroughForm(page2, fresh);
  await page2.waitForURL(/\/mcp\/(select-organization|consent)\?/, { timeout: 60000 });
  await page2.locator('#workspace').waitFor({ timeout: 30000 });
  check('a person with no workspace is asked to create one first', /Create a workspace/i.test(await page2.locator('body').innerText()));
  await page2.locator('#workspace').fill('Fresh Workspace');
  await page2.getByRole('button', { name: /create workspace/i }).click();
  await page2.getByRole('button', { name: 'Allow', exact: true }).waitFor({ timeout: 30000 });
  await page2.getByRole('button', { name: 'Allow', exact: true }).click();
  const hit4 = await Promise.race([cb4.hit, new Promise(r => setTimeout(() => r(null), 30000))]);
  check('after creating the workspace the same authorization completes with a code', !!hit4 && !!hit4.searchParams.get('code') && hit4.searchParams.get('state') === 'state-5', hit4 ? hit4.search : 'no callback');
  cb4.close();

  // ---- Scenario 4: a tampered link is refused
  const page3 = await (await browser.newContext()).newPage();
  const bad = authorizeUrl(clientId, redirect, challenge, 'x').replace('client_id=', 'client_id=') + '&sig=forged&exp=9999999999';
  const res = await page3.goto(bad, { waitUntil: 'domcontentloaded' });
  check('an authorize link with a forged signature is rejected (400)', res.status() === 400, String(res.status()));

  check('no uncaught page errors', errors.length === 0, errors.join(' | '));
  console.log(`\n==== ${pass}/${pass + fail} passed ====`);
  await browser.close();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('FAIL', e.message.slice(0, 400)); process.exit(1); });
