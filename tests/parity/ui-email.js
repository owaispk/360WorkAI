// Email verification and password reset in a real browser. Needs the rewrite running with Auth__RequireEmailVerification=true
// (the dev outbox at A/dev/outbox is how this script reads the "emailed" codes and links).
//   W=http://localhost:5081 A=http://localhost:5080 node ui-email.js [screenshot-dir]
const { chromium } = require('playwright');
const W = process.env.W || 'http://localhost:5081';
const A = process.env.A || 'http://localhost:5080';
const PW = 'Str0ng!Passw0rd#2026x';
const NEW_PW = 'N3w!Passw0rd#2026y';
const shots = process.argv[2];
let pass = 0, fail = 0;
const check = (name, ok, detail = '') => { ok ? pass++ : fail++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : '  -> ' + detail}`); };
const mails = async (to) => (await (await fetch(`${A}/dev/outbox?to=${encodeURIComponent(to)}`)).json());
const lastCode = async (to) => { const m = (await mails(to)).filter(x => /verification code/.test(x.subject)); return m.length ? m[m.length - 1].subject.match(/(\d{6})$/)[1] : null; };
const lastLink = async (to) => { const m = (await mails(to)).filter(x => /Reset your/.test(x.subject)); return m.length ? m[m.length - 1].text.match(/(http\S+\/api\/auth\/reset-password\/\S+)/)[1] : null; };
const uniq = (p) => `${p}.${Date.now()}.${Math.floor(Math.random() * 1e4)}@example.com`;
const api = async (path, body) => { const r = await fetch(A + path, { method: 'POST', headers: { 'content-type': 'application/json', origin: W }, body: JSON.stringify(body) }); return { status: r.status, json: await r.json().catch(() => null) }; };

async function toPasswordStep(page, email) {
  await page.goto(W + '/', { waitUntil: 'networkidle', timeout: 120000 });
  await page.locator('input[type="email"]').fill(email);
  await page.getByRole('button', { name: /^next$/i }).click();
  await page.locator('input[type="password"]').waitFor({ timeout: 30000 });
}
const bodyText = (page) => page.locator('body').innerText();

(async () => {
  const browser = await chromium.launch();
  const errors = [];

  // ---------- 1. Sign up -> verify (wrong code, then right code)
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const page = await ctx.newPage(); page.on('pageerror', e => errors.push(String(e).slice(0, 120)));
  const email1 = uniq('verify');
  await toPasswordStep(page, email1);
  await page.locator('input[type="password"]').fill(PW);
  await page.getByRole('button', { name: 'Sign up', exact: true }).click();
  await page.locator('#code').waitFor({ timeout: 30000 });
  check('sign-up stops at the verification step', /Verify your email/i.test(await bodyText(page)));
  check('it says which address the code went to', (await page.locator('[data-testid="verify-info"]').innerText()).includes(email1));
  const meBefore = await page.evaluate(async () => (await fetch('/api/browser/v1/me', { credentials: 'include' })).status);
  check('no session exists yet (not signed in)', meBefore === 401, String(meBefore));
  if (shots) await page.screenshot({ path: shots + '/ui-verify.png' });

  const code1 = await lastCode(email1);
  check('a 6-digit code was emailed', /^\d{6}$/.test(code1 ?? ''), String(code1));
  await page.locator('#code').fill(code1 === '000000' ? '111111' : '000000');
  await page.getByRole('button', { name: 'Verify email', exact: true }).click();
  await page.locator('[role="alert"]').waitFor({ timeout: 15000 });
  check('a wrong code shows a clear error and stays on the step', /not right/i.test(await page.locator('[role="alert"]').innerText()) && (await page.locator('#code').count()) === 1);
  await page.locator('#code').fill(code1);
  await page.getByRole('button', { name: 'Verify email', exact: true }).click();
  await page.waitForURL(/\/organization|\/dashboard/, { timeout: 60000 });
  check('the right code verifies and signs the person in (no second password prompt)', true);
  const meAfter = await page.evaluate(async () => (await fetch('/api/browser/v1/me', { credentials: 'include' })).status);
  check('the session is real after verifying', meAfter === 200, String(meAfter));

  // ---------- 2. Resend: the new code replaces the old one
  const ctx2 = await browser.newContext(); const page2 = await ctx2.newPage();
  const email2 = uniq('resend');
  await toPasswordStep(page2, email2);
  await page2.locator('input[type="password"]').fill(PW);
  await page2.getByRole('button', { name: 'Sign up', exact: true }).click();
  await page2.locator('#code').waitFor({ timeout: 30000 });
  const first = await lastCode(email2);
  await page2.getByRole('button', { name: /send a new code/i }).click();
  await page2.waitForFunction(() => /fresh code/i.test(document.body.innerText), null, { timeout: 15000 });
  const second = await lastCode(email2);
  check('"Send a new code" emails another code', (await mails(email2)).length === 2 && !!second);
  if (first !== second) {
    await page2.locator('#code').fill(first);
    await page2.getByRole('button', { name: 'Verify email', exact: true }).click();
    await page2.locator('[role="alert"]').waitFor({ timeout: 15000 });
    check('the old code no longer works', /not right/i.test(await page2.locator('[role="alert"]').innerText()));
  }
  await page2.locator('#code').fill(second);
  await page2.getByRole('button', { name: 'Verify email', exact: true }).click();
  await page2.waitForURL(/\/organization|\/dashboard/, { timeout: 60000 });
  check('the new code works', true);

  // ---------- 3. Signing in while unverified leads to verification
  const email3 = uniq('unverified');
  await api('/api/auth/sign-up/email', { name: 'Unverified', email: email3, password: PW });
  const ctx3 = await browser.newContext(); const page3 = await ctx3.newPage();
  await toPasswordStep(page3, email3);
  await page3.locator('input[type="password"]').fill(PW);
  await page3.getByRole('button', { name: /^sign in$/i }).click();
  await page3.locator('#code').waitFor({ timeout: 30000 });
  check('an unverified account that signs in is asked to verify', /not verified/i.test(await page3.locator('[data-testid="verify-info"]').innerText()));
  await page3.locator('#code').fill(await lastCode(email3));
  await page3.getByRole('button', { name: 'Verify email', exact: true }).click();
  await page3.waitForURL(/\/organization|\/dashboard/, { timeout: 60000 });
  check('verifying there completes the sign-in', true);

  // ---------- 4. Forgot password: email -> link -> new password
  // `page` is a signed-in session for email1 on another "device"; the reset must sign it out.
  const email4 = email1;
  const ctx4 = await browser.newContext(); const page4 = await ctx4.newPage(); page4.on('pageerror', e => errors.push(String(e).slice(0, 120)));
  await toPasswordStep(page4, email4);
  await page4.getByRole('button', { name: /forgot your password/i }).click();
  await page4.getByRole('button', { name: /send reset link/i }).click();
  await page4.locator('[data-testid="reset-sent"]').waitFor({ timeout: 15000 });
  check('"Forgot your password?" confirms without revealing whether the account exists', /If an account exists for/.test(await page4.locator('[data-testid="reset-sent"]').innerText()));
  const link = await lastLink(email4);
  check('a reset link was emailed, pointing at this site', !!link && link.startsWith(W + '/api/auth/reset-password/'), String(link));

  await page4.goto(link, { waitUntil: 'networkidle' });
  await page4.locator('#new-password').waitFor({ timeout: 30000 });
  check('the emailed link lands on the reset page with the token in the URL', /\/reset-password\?token=/.test(page4.url()));
  if (shots) await page4.screenshot({ path: shots + '/ui-reset.png' });

  await page4.locator('#new-password').fill(NEW_PW); await page4.locator('#confirm-password').fill(NEW_PW + 'x');
  await page4.getByRole('button', { name: 'Reset password', exact: true }).click();
  check('mismatched passwords are caught', /do not match/i.test(await page4.locator('[role="alert"]').innerText()));
  await page4.locator('#new-password').fill('alllowercase1!'); await page4.locator('#confirm-password').fill('alllowercase1!');
  await page4.getByRole('button', { name: 'Reset password', exact: true }).click();
  await page4.waitForFunction(() => /uppercase/i.test(document.body.innerText), null, { timeout: 15000 });
  check('a weak password gets the server\'s specific rule, and the link still works', /uppercase/i.test(await page4.locator('[role="alert"]').innerText()));
  await page4.locator('#new-password').fill(NEW_PW); await page4.locator('#confirm-password').fill(NEW_PW);
  await page4.getByRole('button', { name: 'Reset password', exact: true }).click();
  await page4.locator('[data-testid="reset-done"]').waitFor({ timeout: 15000 });
  check('a good password completes the reset', true);

  const old = await page.evaluate(async () => (await fetch('/api/browser/v1/me', { credentials: 'include' })).status);
  check('the reset signed out the other signed-in browser', old === 401, String(old));

  await page4.goto(link, { waitUntil: 'networkidle' });
  await page4.locator('[data-testid="reset-invalid"]').waitFor({ timeout: 15000 });
  check('the same link cannot be used twice', true);

  const ctx5 = await browser.newContext(); const page5 = await ctx5.newPage();
  await toPasswordStep(page5, email4);
  await page5.locator('input[type="password"]').fill(PW);
  await page5.getByRole('button', { name: /^sign in$/i }).click();
  await page5.locator('[role="alert"]').waitFor({ timeout: 15000 });
  check('the old password no longer works', /invalid email or password/i.test(await page5.locator('[role="alert"]').innerText()));
  await page5.locator('input[type="password"]').fill(NEW_PW);
  await page5.getByRole('button', { name: /^sign in$/i }).click();
  await page5.waitForURL(/\/organization|\/dashboard/, { timeout: 60000 });
  check('the new password works', true);

  // ---------- 5. Bad links
  const ctx6 = await browser.newContext(); const page6 = await ctx6.newPage();
  await page6.goto(`${W}/api/auth/reset-password/not-a-real-token?callbackURL=${encodeURIComponent(W + '/reset-password')}`, { waitUntil: 'networkidle' });
  await page6.locator('[data-testid="reset-invalid"]').waitFor({ timeout: 15000 });
  check('an unknown link shows a helpful page, not an error', /not valid/i.test(await bodyText(page6)));
  await page6.goto(`${W}/reset-password`, { waitUntil: 'networkidle' });
  check('the reset page with no token shows the same page', (await page6.locator('[data-testid="reset-invalid"]').count()) === 1);

  check('no uncaught page errors', errors.length === 0, errors.join(' | '));
  console.log(`\n==== ${pass}/${pass + fail} passed ====`);
  await browser.close();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('FAIL', e.message.slice(0, 400)); process.exit(1); });
