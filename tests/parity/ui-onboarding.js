// The way from sign-up to a working workspace, in a real browser against the rewrite: sign up, create a workspace, invite people, add tools, get the
// desktop app, and take over a workspace an agent made (with a code and with a link). Also the settings page, the invitations waiting for a person,
// and the small pages (setup, security check).
//   W=http://localhost:5260 A=http://localhost:5160 node ui-onboarding.js [screenshot-dir]
// The rewrite should run with Onboarding__Bootstrap__LimitPerHour=1000 (this test provisions two workspaces).
const { chromium } = require('playwright');
const { W, A, PW, check, uniq, api, person, until, finish } = require('./ui-lib');
const shots = process.argv[2];

const text = (page) => page.locator('body').innerText();
const shot = async (page, name) => { if (shots) await page.screenshot({ path: `${shots}/onboarding-${name}.png`, fullPage: true }); };

/** Types the address, then either signs in or signs up (the form asks for a name only when the address is new). */
async function enter(page, email, name = 'Onboarding Tester') {
  await page.locator('input[type="email"]').waitFor({ timeout: 30000 });
  await page.locator('input[type="email"]').fill(email);
  await page.getByRole('button', { name: /^next$/i }).click();
  await page.locator('input[type="password"]').waitFor({ timeout: 30000 });
  const nameField = page.locator('input[autocomplete="name"]');
  const signUp = (await nameField.count()) > 0;
  if (signUp) await nameField.fill(name);
  await page.locator('input[type="password"]').fill(PW);
  await page.getByRole('button', { name: signUp ? 'Sign up' : 'Sign in', exact: true }).click();
  return signUp;
}

(async () => {
  const browser = await chromium.launch();
  const errors = [];
  const newPage = async () => {
    const ctx = await browser.newContext({ viewport: { width: 1180, height: 1000 } });
    const page = await ctx.newPage();
    page.on('pageerror', (e) => errors.push(String(e).slice(0, 160)));
    return page;
  };

  // ---- 1. a new person: sign up, create a workspace, invite someone, reach the dashboard ------------------------------------------------------
  const page = await newPage();
  const email = uniq('ob.owner');
  await page.goto(W + '/', { waitUntil: 'networkidle', timeout: 120000 });
  await enter(page, email, 'Olivia Onboard');
  await page.waitForURL(/\/organization/, { timeout: 60000 });
  await page.locator('#workspace').waitFor({ timeout: 30000 });
  let body = await text(page);
  check('sign-up lands on "Create your workspace" with the step header', /Create your workspace/.test(body) && /Invite \(optional\)/.test(body), body.slice(0, 200));
  await shot(page, '1-create-workspace');

  const create = page.getByRole('button', { name: 'Create workspace' });
  await page.locator('#workspace').fill('x');
  check('a one-letter name cannot be submitted', await create.isDisabled());
  await page.locator('summary').click();
  await page.locator('#invitation-link').fill('https://evil.example/join-org?invite=abc');
  await page.getByRole('button', { name: 'Review invitation' }).click();
  check('an invitation link for another site is refused on the page', /Paste the invitation link for this OpenWork Cloud/.test(await page.getByTestId('link-error').innerText()));
  check('...and the page stayed where it was', /\/organization/.test(page.url()));

  await page.locator('#workspace').fill('Onboarding UI Space');
  await create.click();
  await page.waitForURL(/\/dashboard\/onboarding\/people/, { timeout: 60000 });
  await page.getByTestId('invite-form').waitFor({ timeout: 30000 });
  body = await text(page);
  check('creating the workspace goes on to "Invite people to <workspace>"', /Invite people to Onboarding UI Space/.test(body), body.slice(0, 200));
  await shot(page, '2-invite-people');

  const mate = uniq('ob.mate');
  await page.getByLabel('Teammate email 1').fill('x');
  await page.getByRole('button', { name: 'Send invitations' }).click();
  await until(async () => /Enter a valid email address\./.test(await text(page)));
  check('an address that is not an address is flagged', /Enter a valid email address\./.test(await text(page)));
  await page.getByLabel('Teammate email 1').fill(email);
  await page.getByRole('button', { name: 'Send invitations' }).click();
  await until(async () => /You're already in this workspace\./.test(await text(page)));
  check('inviting yourself is flagged', /You're already in this workspace\./.test(await text(page)));
  await page.getByLabel('Teammate email 1').fill(mate);
  await page.getByLabel('Teammate email 2').fill(mate.toUpperCase());
  await page.getByRole('button', { name: 'Send invitations' }).click();
  await until(async () => /Use a different email address for each person\./.test(await text(page)));
  check('the same address twice is flagged', /Use a different email address for each person\./.test(await text(page)));
  await page.getByLabel('Teammate email 2').fill('');
  await page.getByRole('button', { name: 'Send invitations' }).click();
  await until(async () => /Invitation sent/.test(await text(page)));
  check('a valid address is invited', /Invitation sent/.test(await text(page)));
  await shot(page, '3-invitation-sent');
  const ownerToken = (await api('POST', '/api/auth/sign-in/email', { email, password: PW })).json.token;
  const orgId = (await api('GET', '/v1/me/orgs', null, ownerToken)).json.activeOrgId;
  const org = (await api('GET', '/v1/org', null, ownerToken, orgId)).json;
  check('the invitation exists in the workspace, for the address typed', (org.invitations ?? []).some((i) => i.email === mate.toLowerCase() && i.role === 'member'), JSON.stringify(org.invitations));

  await page.getByRole('button', { name: 'Open workspace' }).click();
  await page.waitForURL(/\/dashboard$/, { timeout: 60000 });
  await page.getByTestId('user-email').waitFor({ timeout: 30000 });
  body = await text(page);
  check('"Open workspace" reaches a working dashboard for the new person', body.includes(email) && body.includes('Onboarding UI Space') && /owner/.test(body) && /Manage members/.test(body), body.slice(0, 300));
  await shot(page, '4-dashboard');

  // ---- 2. tools, models and the desktop app ---------------------------------------------------------------------------------------------------
  await page.goto(W + '/dashboard/onboarding/tools', { waitUntil: 'networkidle', timeout: 60000 });
  await page.getByTestId('onboarding-tools').waitFor({ timeout: 30000 });
  await until(async () => (await page.getByTestId('tool').count()) > 0 || (await page.getByTestId('load-error').count()) > 0);
  const tools = await page.getByTestId('tool').count();
  check('the tools page lists the tools that can be added in one click', tools > 0, await text(page));
  let added = 0;
  if (tools > 0) {
    const first = page.getByTestId('tool').first();
    const name = await first.getAttribute('data-name');
    await first.locator('input').check();
    await page.getByTestId('add-tools').click();
    await until(async () => /· added|could not add/.test(await first.innerText()));
    added = /· added/.test(await first.innerText()) ? 1 : 0;
    const reported = added === 1 || (await page.getByTestId('error').count()) > 0;
    check('adding a tool reports its outcome: a connection the team can use, or the server\'s reason', reported, await first.innerText());
    const list = (await api('GET', '/v1/mcp-connections?scope=manageable', null, ownerToken, orgId)).json;
    const present = (list.connections ?? []).some((c) => c.name === name);
    // Presets point at public services, so a machine with no internet cannot reach them: then nothing may have been created.
    check(added === 1 ? 'the connection is in the workspace' : 'a refused tool leaves no connection behind', added === 1 ? present : !present, JSON.stringify(list).slice(0, 200));
  }
  await shot(page, '5-tools');
  await page.getByTestId('continue').click();
  await page.waitForURL(/\/dashboard\/onboarding$/, { timeout: 30000 });
  await page.getByTestId('marketplace-onboarding').waitFor({ timeout: 30000 });
  await page.getByTestId('email-link').click();
  await until(async () => (await page.getByTestId('email-notice').count()) > 0);
  check('"Email me the link" says where it went', new RegExp(`sent the download link to ${email.replace('.', '\\.')}`).test(await page.getByTestId('email-notice').innerText()));
  const outbox = await (await fetch(`${A}/dev/outbox?to=${encodeURIComponent(email)}`)).json();
  check('...and that message is in the outbox for the person\'s own address only', JSON.stringify(outbox).includes('download link') && JSON.stringify(outbox).includes('/install'), JSON.stringify(outbox).slice(0, 200));
  await shot(page, '6-ready');
  await page.getByTestId('complete-setup').click();
  await page.waitForURL(/\/dashboard$/, { timeout: 30000 });
  check('"Complete setup" ends on the dashboard', true);

  // ---- 3. the install page ----------------------------------------------------------------------------------------------------------------------
  await page.goto(W + '/install', { waitUntil: 'networkidle', timeout: 60000 });
  await page.getByTestId('install-page').waitFor({ timeout: 30000 });
  await page.getByTestId('install-mac-arm64').waitFor({ timeout: 30000 });
  body = await text(page);
  check('the install page offers every platform and names the workspace address', ['Apple Silicon', 'Intel', 'x64 app', 'AppImage (x64)', 'AppImage (ARM64)'].every((s) => body.includes(s)) && (await page.getByTestId('install-workspace-address').locator('input').inputValue()) === W, body.slice(0, 300));
  await shot(page, '7-install');
  const href = await page.getByTestId('install-mac-arm64').getAttribute('href');
  const download = await page.request.get(W + href, { maxRedirects: 0 });
  check('a download link redirects to this platform\'s installer', download.status() === 302 && /openwork-cloud-mac-arm64-[\d.]+\.dmg$/.test(download.headers().location ?? ''), `${download.status()} ${download.headers().location}`);
  const signedOut = await (await newPage()).request.get(W + href, { maxRedirects: 0 });
  check('...and is refused to someone who is not signed in', signedOut.status() === 401, String(signedOut.status()));
  const visitor = await newPage();
  await visitor.goto(W + '/install', { waitUntil: 'networkidle', timeout: 60000 });
  await visitor.waitForURL(/\/\?returnTo=/, { timeout: 30000 });
  check('someone who is not signed in is sent to sign in, and back to the install page', /returnTo=%2Finstall/.test(visitor.url()), visitor.url());
  await visitor.close();

  // ---- 4. settings: profile and organizations ----------------------------------------------------------------------------------------------------
  await page.goto(W + '/organization', { waitUntil: 'networkidle', timeout: 60000 });
  await page.getByTestId('tab-organizations').waitFor({ timeout: 30000 });
  check('a person with a workspace sees their organizations, the current one marked', (await page.getByTestId('organization-row').count()) === 1 && /Current/.test(await page.getByTestId('organizations').innerText()));
  await page.getByTestId('tab-profile').click();
  await page.locator('#first-name').fill('Olive');
  await page.locator('#last-name').fill('Renamed');
  await page.getByRole('button', { name: 'Save profile' }).click();
  await until(async () => (await page.getByTestId('notice').count()) > 0);
  const me = (await api('GET', '/v1/me', null, ownerToken)).json;
  check('the profile can be renamed, and the account shows it', me.user.name === 'Olive Renamed', JSON.stringify(me.user));
  await shot(page, '8-settings');
  await page.getByTestId('tab-organizations').click();
  await page.getByTestId('new-organization').click();
  await page.locator('#workspace').fill('A Second Space');
  await page.getByRole('button', { name: 'Create workspace' }).click();
  await page.waitForURL(/\/dashboard\/onboarding\/people/, { timeout: 60000 });
  check('creating another organization starts the same path again', true);

  // ---- 5. an agent made a workspace: take it over with a code -------------------------------------------------------------------------------------
  const made = (await api('POST', '/v1/bootstrap/workspace', { workspaceName: 'Agent Built Space', ownerEmail: uniq('ob.claim'), teammateEmails: [uniq('ob.t1')], claimRoles: ['owner', 'member'] })).json;
  check('the agent can provision a workspace', made.ok === true && made.organization?.status === 'provisional', JSON.stringify(made).slice(0, 200));
  const codeResponse = (await api('POST', `/v1/bootstrap/workspace/${made.setup.id}/claim`, null, made.identity.assertion)).json;
  const userCode = codeResponse.user_code;
  const claimer = await newPage();
  await claimer.goto(`${W}/claim?user_code=${encodeURIComponent(userCode)}`, { waitUntil: 'networkidle', timeout: 60000 });
  await claimer.waitForURL(/\/\?returnTo=/, { timeout: 30000 });
  const claimEmail = uniq('ob.codeperson');
  await enter(claimer, claimEmail, 'Cora Claimer');
  await claimer.getByTestId('claim-workspace').waitFor({ timeout: 60000 });
  body = await text(claimer);
  check('after signing in the person is back at the code, asked to claim the workspace by name', /Claim Agent Built Space\?/.test(body) && body.includes(userCode) && body.includes(claimEmail) && /temporary access ends now/.test(body), body.slice(0, 300));
  await shot(claimer, '9-claim-code');
  await claimer.getByTestId('claim-workspace').click();
  await claimer.getByTestId('claimed').waitFor({ timeout: 30000 });
  check('claiming says the workspace is theirs', /Agent Built Space is yours/.test(await text(claimer)));
  await claimer.getByTestId('open-workspace').click();
  await claimer.getByTestId('user-email').waitFor({ timeout: 30000 });
  body = await text(claimer);
  check('the dashboard shows the claimed workspace with the person as its only owner', body.includes('Agent Built Space') && /owner/.test(body) && (await claimer.getByTestId('members').locator('li').count()) === 1 && body.includes(claimEmail), body.slice(0, 300));
  await shot(claimer, '10-claimed-dashboard');
  const claimerToken = (await api('POST', '/api/auth/sign-in/email', { email: claimEmail, password: PW })).json.token;
  const claimed = (await api('GET', '/v1/org', null, claimerToken, made.organization.id)).json;
  check('the workspace has one member, the owner, and the starter skill', claimed.members.length === 1 && claimed.members[0].role === 'owner'
    && (await api('GET', '/v1/plugins', null, claimerToken, made.organization.id)).json.items.some((p) => p.name === 'First OpenWork Skill'));
  const stale = await claimer.goto(`${W}/claim?user_code=${encodeURIComponent(userCode)}`, { waitUntil: 'networkidle', timeout: 60000 });
  await claimer.getByTestId('code-invalid').waitFor({ timeout: 30000 });
  check('a used code says so', /invalid or has expired/.test(await text(claimer)) && stale.status() < 400);
  await claimer.getByRole('button', { name: 'Enter a different code' }).click();
  await claimer.locator('#code').fill('abcd efgh');
  await claimer.getByRole('button', { name: 'Continue' }).click();
  await claimer.getByTestId('code-invalid').waitFor({ timeout: 30000 });
  check('a wrong code typed in the box is refused the same way', true);

  // ---- 6. ...and with a link, signing up on the way, with teammates invited ----------------------------------------------------------------------------
  const linkOwnerEmail = uniq('ob.linkperson');
  const mateEmail = uniq('ob.linkmate');
  const made2 = (await api('POST', '/v1/bootstrap/workspace', { workspaceName: 'Linked Space', ownerEmail: linkOwnerEmail, teammateEmails: [mateEmail], claimRoles: ['owner'] })).json;
  const link = made2.claimLinks[0].url.replace(/^https?:\/\/[^/]+/, W);
  const taker = await newPage();
  await taker.goto(link, { waitUntil: 'networkidle', timeout: 60000 });
  await taker.waitForURL(/\/\?returnTo=/, { timeout: 30000 });
  await taker.locator('input[type="email"]').waitFor({ timeout: 30000 });
  check('the sign-in form offers the address the link was made for', (await taker.locator('input[type="email"]').inputValue()) === linkOwnerEmail.toLowerCase(), await taker.locator('input[type="email"]').inputValue());
  await enter(taker, linkOwnerEmail, 'Lena Linked');
  await taker.getByTestId('claim-workspace').waitFor({ timeout: 60000 });
  check('after signing up the person is back on the claim link, with the teammates to be invited listed', /Claim this workspace/.test(await text(taker)) && (await text(taker)).includes(mateEmail.toLowerCase()));
  await shot(taker, '11-claim-link');
  await taker.getByTestId('claim-workspace').click();
  await taker.getByTestId('invite-summary').waitFor({ timeout: 30000 });
  check('claiming invites the teammates and says so', /Invited 1 teammate\./.test(await text(taker)), await text(taker));
  const linkToken = (await api('POST', '/api/auth/sign-in/email', { email: linkOwnerEmail.toLowerCase(), password: PW })).json.token;
  const linked = (await api('GET', '/v1/org', null, linkToken, made2.organization.id)).json;
  check('...and the invitation is pending in the workspace', (linked.invitations ?? []).some((i) => i.email === mateEmail.toLowerCase()), JSON.stringify(linked.invitations));
  await taker.getByTestId('open-workspace').click();
  await taker.getByTestId('user-email').waitFor({ timeout: 30000 });
  check('the dashboard is the linked workspace', (await text(taker)).includes('Linked Space'));
  const again = await newPage();
  await again.goto(link, { waitUntil: 'networkidle', timeout: 60000 });
  await again.waitForURL(/\/\?returnTo=/, { timeout: 30000 });
  await enter(again, uniq('ob.latecomer'), 'Late Comer');
  await again.getByTestId('claim-workspace').waitFor({ timeout: 60000 });
  await again.getByTestId('claim-workspace').click();
  await again.getByTestId('error').waitFor({ timeout: 30000 });
  check('a link that was used says it is missing, expired or already used', /missing, expired, or already used/.test(await again.getByTestId('error').innerText()));
  const noToken = await newPage();
  await noToken.goto(W + '/workspace-claim', { waitUntil: 'networkidle', timeout: 60000 });
  await noToken.getByTestId('claim-missing').waitFor({ timeout: 30000 });
  check('a claim link without its token says so', /missing its claim token/.test(await text(noToken)));

  // ---- 7. invitations waiting for a person with no workspace -------------------------------------------------------------------------------------------
  const host = await person('Hosting Owner');
  const hostOrg = (await api('POST', '/v1/org', { name: 'Waiting Room Space' }, host.token)).json.organization.id;
  const guestEmail = uniq('ob.guest');
  const inv = (await api('POST', '/v1/invitations', { email: guestEmail, role: 'member' }, host.token, hostOrg)).json;
  // Signing up from the emailed link proves the address; the person then opens the site on their own, with no link.
  await api('POST', `/api/auth/sign-up/email?invite=${encodeURIComponent(inv.inviteToken)}`, { name: 'Gus Guest', email: guestEmail, password: PW });
  const guest = await newPage();
  await guest.goto(W + '/', { waitUntil: 'networkidle', timeout: 60000 });
  await enter(guest, guestEmail);
  await guest.waitForURL(/\/organization/, { timeout: 60000 });
  await guest.getByTestId('my-invitations').waitFor({ timeout: 30000 });
  body = await text(guest);
  check('a person with no workspace is shown the invitation waiting for them', /Invitations waiting for you/.test(body) && /Waiting Room Space/.test(body), body.slice(0, 300));
  await shot(guest, '12-waiting-invitation');
  await guest.getByRole('button', { name: 'Join', exact: true }).click();
  await guest.getByTestId('user-email').waitFor({ timeout: 30000 });
  check('joining from the list lands on that workspace\'s dashboard', (await text(guest)).includes('Waiting Room Space'));

  // ---- 8. the small pages --------------------------------------------------------------------------------------------------------------------------
  const anon = await newPage();
  await anon.goto(W + '/setup', { waitUntil: 'networkidle', timeout: 60000 });
  await anon.getByTestId('setup-state').waitFor({ timeout: 30000 });
  check('/setup says the first-administrator setup is not available here', /not available|permanently disabled/.test(await text(anon)));
  await anon.goto(W + '/reauth/complete?nonce=abc', { waitUntil: 'networkidle', timeout: 60000 });
  check('/reauth/complete says the person is verified', /You're verified/.test(await text(anon)));
  const opener = await anon.context().newPage();
  await opener.goto(W + '/', { waitUntil: 'networkidle' });
  const message = opener.evaluate(() => new Promise((resolve) => { window.addEventListener('message', (e) => resolve(e.data)); const w = window.open('/reauth/complete?nonce=n-1&error=denied'); }));
  const got = await Promise.race([message, new Promise((r) => setTimeout(() => r(null), 15000))]);
  check('/reauth/complete tells the window that opened it, with the nonce and any error', got && got.type === 'openwork:reauth-complete' && got.nonce === 'n-1' && got.error === 'denied', JSON.stringify(got));
  await anon.goto(W + '/reauth/desktop', { waitUntil: 'networkidle', timeout: 60000 });
  await anon.getByTestId('reauth-invalid').waitFor({ timeout: 30000 });
  check('/reauth/desktop without the app\'s request explains how to start one', /Share dialog in OpenWork/.test(await text(anon)));
  await shot(anon, '13-setup');

  await finish(browser, errors);
})().catch((e) => { console.error(e); process.exit(1); });
