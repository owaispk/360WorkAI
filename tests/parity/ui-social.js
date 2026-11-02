// Sign-in with Google and GitHub in a real browser against the rewrite, with local fake providers (fake-social.cjs, on 127.0.0.1:5391).
//   Start the rewrite with the fake providers' settings (see the header of area-social.mjs or run `node fake-social.cjs` to print them), then:
//   W=http://localhost:5290 A=http://localhost:5190 node ui-social.js [screenshot-dir]
const { chromium } = require('playwright');
const { startFakeSocial } = require('./fake-social.cjs');
const { W, A, PW, check, api, uniq, until, finish } = require('./ui-lib');
const shots = process.argv[2];

(async () => {
  const fake = await startFakeSocial({ port: Number(process.env.FAKE_SOCIAL_PORT ?? 5391) });
  const browser = await chromium.launch();
  const errors = [];
  const newPage = async () => { const ctx = await browser.newContext({ viewport: { width: 1100, height: 900 } }); const page = await ctx.newPage(); page.on('pageerror', (e) => errors.push(String(e).slice(0, 160))); return { ctx, page }; };

  // ---- the buttons ----
  let { ctx, page } = await newPage();
  await page.goto(W + '/', { waitUntil: 'networkidle', timeout: 120000 });
  await page.getByTestId('auth-card').waitFor({ timeout: 30000 });
  await page.getByTestId('social-buttons').waitFor({ timeout: 20000 });
  check('the sign-in form offers Google and GitHub when both are configured', (await page.getByTestId('social-google').innerText()) === 'Continue with Google' && (await page.getByTestId('social-github').innerText()) === 'Continue with GitHub');
  if (shots) await page.screenshot({ path: shots + '/ui-social-form.png' });

  // ---- Google: a new person ----
  const gEmail = uniq('google.person');
  fake.google = { ...fake.google, email: gEmail, sub: 'g-ui-' + Date.now(), name: 'Gee Person', email_verified: true, fault: '' };
  await page.getByTestId('social-google').click();
  await page.waitForURL(/\/organization|\/dashboard/, { timeout: 60000 });
  check('Continue with Google signs a new person in through the provider and lands in the app', /\/organization|\/dashboard/.test(page.url()));
  const me = await page.evaluate(async () => (await fetch('/api/browser/v1/me')).json());
  check('the new account has the provider\'s verified email and name', me.user?.email === gEmail && me.user?.name === 'Gee Person' && me.user?.emailVerified === true, JSON.stringify(me).slice(0, 200));
  check('the provider was asked with PKCE, a state and a nonce, and the code exchange used the secret server to server', fake.authRequests.at(-1)?.code_challenge_method === 'S256' && !!fake.authRequests.at(-1)?.nonce && fake.tokenRequests.at(-1)?.client_secret === 'g-secret');
  if (shots) await page.screenshot({ path: shots + '/ui-social-signed-in.png' });
  await ctx.close();

  // ---- GitHub: a new person, with the verified primary email ----
  ({ ctx, page } = await newPage());
  const hEmail = uniq('octo.person');
  fake.github = { ...fake.github, id: 70000 + Math.floor(Math.random() * 9000), name: 'Octo Person', profileEmail: 'public@example.test', emails: [{ email: 'secondary@example.test', primary: false, verified: true }, { email: hEmail, primary: true, verified: true }], fault: '' };
  await page.goto(W + '/', { waitUntil: 'networkidle', timeout: 120000 });
  await page.getByTestId('social-github').waitFor({ timeout: 20000 });
  await page.getByTestId('social-github').click();
  await page.waitForURL(/\/organization|\/dashboard/, { timeout: 60000 });
  const meH = await page.evaluate(async () => (await fetch('/api/browser/v1/me')).json());
  check('Continue with GitHub uses the primary verified email', meH.user?.email === hEmail, JSON.stringify(meH).slice(0, 200));
  await ctx.close();

  // ---- the provider refuses: the sign-in form explains, and nobody is signed in ----
  ({ ctx, page } = await newPage());
  fake.google = { ...fake.google, fault: 'error' };
  await page.goto(W + '/', { waitUntil: 'networkidle', timeout: 120000 });
  await page.getByTestId('social-google').waitFor({ timeout: 20000 });
  await page.getByTestId('social-google').click();
  const shown = await until(async () => (await page.getByRole('alert').first().innerText().catch(() => '')) || '', 30000);
  check('when the person says no at the provider the form says sign-in was cancelled and stays signed out', /cancelled/i.test(shown) && /\/\?/.test(page.url()) && new URL(page.url()).searchParams.get('error') === 'access_denied', `${shown} ${page.url()}`);
  const meOut = await page.evaluate(async () => (await fetch('/api/browser/v1/me')).status);
  check('nobody was signed in', meOut === 401, String(meOut));
  if (shots) await page.screenshot({ path: shots + '/ui-social-refused.png' });
  fake.google = { ...fake.google, fault: '' };

  // ---- an unverified email at the provider: the form explains ----
  fake.google = { ...fake.google, email: uniq('unverified'), sub: 'g-unv-' + Date.now(), email_verified: false };
  await page.goto(W + '/', { waitUntil: 'networkidle', timeout: 120000 });
  await page.getByTestId('social-google').waitFor({ timeout: 20000 });
  await page.getByTestId('social-google').click();
  const unv = await until(async () => (await page.getByRole('alert').first().innerText().catch(() => '')) || '', 30000);
  check('an email the provider has not verified is refused, with an explanation', /not verified/i.test(unv), unv);
  fake.google = { ...fake.google, email_verified: true };
  await ctx.close();

  // ---- a link that was not started in this browser ----
  ({ ctx, page } = await newPage());
  await page.goto(W + '/api/auth/callback/google?code=x&state=forged', { waitUntil: 'networkidle', timeout: 60000 });
  check('a callback with a forged state lands on the connect-error page, not in the app', /\/connect\/error\?error=state_mismatch/.test(page.url()), page.url());
  await ctx.close();

  fake.close();
  await finish(browser, errors);
})().catch((e) => { console.error(e); process.exit(1); });
