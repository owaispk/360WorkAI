// SAML extras in a real browser: pasting identity provider metadata, a single logout URL and signed requests on the SSO page, and what the
// service provider metadata then publishes (its key for signing and encryption, the logout endpoints). Uses the fake provider (fake-saml-idp.cjs).
//   W=http://localhost:5294 A=http://localhost:5194 node tests/parity/ui-saml-extras.js [screenshot-dir]
// The server must run in Development (a loopback identity provider counts as a proven domain there).
const { chromium } = require('playwright');
const { startFakeSamlIdp } = require('./fake-saml-idp.cjs');
const { W, PW, check, api, signIn, finish } = require('./ui-lib');
const shots = process.argv[2];

(async () => {
  const idp = await startFakeSamlIdp({ host: '127.0.0.1' });
  const browser = await chromium.launch();
  const errors = [];
  const domain = `ui-saml-x-${Date.now()}.test`;
  const ownerEmail = `owner@${domain}`;
  const up = await api('POST', '/api/auth/sign-up/email', { name: 'Olive Owner', email: ownerEmail, password: PW });
  await api('POST', '/v1/org', { name: 'SAML Extras' }, up.json.token);
  const idpMetadata = await (await fetch(idp.url + '/metadata')).text();

  const ctx = await browser.newContext({ viewport: { width: 1280, height: 1400 } });
  const page = await ctx.newPage();
  page.on('pageerror', (e) => errors.push(String(e).slice(0, 160)));
  await signIn(page, ownerEmail);
  await page.goto(W + '/dashboard/sso', { waitUntil: 'networkidle' });
  await page.getByTestId('sso-page').waitFor({ timeout: 30000 });
  await page.getByTestId('sso-type').selectOption('saml');
  await page.getByTestId('sso-idp-metadata').waitFor({ timeout: 20000 });

  // Metadata alone (no entity id, URL or certificate typed) is enough.
  await page.getByTestId('sso-idp-metadata').fill(idpMetadata);
  await page.locator('#sso-domain-input').fill(domain);
  await page.getByTestId('sso-slo').fill(idp.url + '/slo');
  await page.getByTestId('sso-sign-requests').check();
  if (shots) await page.screenshot({ path: shots + '/ui-saml-extras-form.png', fullPage: true });
  await page.getByTestId('sso-save').click();
  await page.getByTestId('sso-summary').waitFor({ timeout: 20000 });
  check('a connection saved from pasted metadata shows as SAML', (await page.getByTestId('sso-kind').innerText()) === 'SAML 2.0');

  const sp = await (await fetch(await page.getByTestId('sso-metadata-url').getAttribute('href'))).text();
  check('the SP metadata says requests are signed', /AuthnRequestsSigned="true"/.test(sp));
  check('the SP metadata publishes a signing and an encryption key', /use="signing"/.test(sp) && /use="encryption"/.test(sp) && /<ds:X509Certificate>[A-Za-z0-9+/=]{200,}</.test(sp));
  check('the SP metadata lists the single logout endpoints', /SingleLogoutService[^>]+sp\/slo\/openwork-sso-/.test(sp));

  // A bad paste is explained and nothing changes.
  await page.getByTestId('sso-idp-metadata').fill('<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x"/>');
  await page.getByTestId('sso-save').click();
  await page.getByTestId('error').waitFor({ timeout: 20000 });
  check('metadata without an identity provider is refused with a reason', /no identity provider/.test(await page.getByTestId('error').innerText()));

  await idp.close?.();
  await finish(browser, errors);
})();
