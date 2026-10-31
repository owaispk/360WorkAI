// Policy pages in a real browser against the rewrite: agents, prompts and models for everyone and a team, and desktop app policies.
//   W=http://localhost:5250 A=http://localhost:5150 node ui-policy.js [screenshot-dir]
const { chromium } = require('playwright');
const { check, api, workspace, until, signIn, finish, W } = require('./ui-lib.js');
const shots = process.argv[2];

(async () => {
  const browser = await chromium.launch();
  const errors = [];
  const ws = await workspace('Policy Workspace');
  const mia = await ws.join('Mia Member');
  const design = (await ws.api(ws.owner, 'POST', '/v1/teams', { name: 'Design', memberIds: [mia.memberId] })).json.team.id;

  const ctx = await browser.newContext({ viewport: { width: 1280, height: 1100 } });
  const page = await ctx.newPage(); page.on('pageerror', (e) => errors.push(String(e).slice(0, 120)));
  await signIn(page, ws.owner.email);
  await page.getByTestId('policy-link').waitFor({ timeout: 30000 });
  check('the dashboard offers the policy pages', (await page.getByTestId('policy-link').count()) === 1 && (await page.getByTestId('desktop-policies-link').count()) === 1);

  // ---- Agents, prompts and models
  await page.getByTestId('policy-link').click();
  await page.getByTestId('policy-page').waitFor({ timeout: 30000 });
  await page.getByTestId('agent-row').first().waitFor({ timeout: 15000 });
  check('the page starts on Everyone with six agent permissions', /every member/.test(await page.getByTestId('scope-name').innerText()) && (await page.getByTestId('agent-row').count()) === 6);
  await page.getByTestId('prompt-text').fill('Be kind to customers.');
  await page.getByTestId('save-prompt').click();
  await page.getByTestId('notice').filter({ hasText: /Prompt saved/ }).waitFor({ timeout: 15000 });
  check('saving a prompt for everyone reaches a member\'s desktop', await until(async () => ((await ws.api(mia, 'GET', '/v1/me/prompts')).json.prompts[0] || {}).content === 'Be kind to customers.'));

  const commands = page.locator('[data-testid="agent-row"][data-key="commands"]');
  await commands.locator('select').selectOption('ask');
  await commands.locator('textarea').first().fill('git status\nnpm test *');
  await commands.locator('textarea').nth(1).fill('rm *');
  await page.locator('[data-testid="agent-row"][data-key="webSearch"] select').selectOption('deny');
  await page.getByTestId('save-agents').click();
  await page.getByTestId('notice').filter({ hasText: /Agent permissions saved/ }).waitFor({ timeout: 15000 });
  const rules = async () => (await ws.api(mia, 'GET', '/v1/me/desktop-config')).json.agentPermissions.rules.map((r) => `${r.action} ${r.resource} ${r.effect} ${r.source}`).join(' | ');
  check('saving agent permissions turns into rules for members', (await rules()) === 'shell * ask Everyone | shell git status allow Everyone | shell npm test * allow Everyone | shell rm * deny Everyone | websearch * deny Everyone', await rules());

  // A bad pattern is explained, not swallowed.
  await page.locator('[data-testid="agent-row"][data-key="websites"] textarea').first().fill('not a site');
  await page.getByTestId('save-agents').click();
  await page.getByTestId('error').waitFor({ timeout: 15000 });
  check('a pattern that is not a site is refused with the reason', /Enter a site like/.test(await page.getByTestId('error').innerText()), await page.getByTestId('error').innerText());
  await page.locator('[data-testid="agent-row"][data-key="websites"] textarea').first().fill('');

  // A team's own choices.
  await page.getByTestId('scope').selectOption(design);
  await page.getByTestId('scope-name').filter({ hasText: /Design/ }).waitFor({ timeout: 10000 });
  check('choosing a team shows its name and starts empty', await until(async () => (await page.getByTestId('prompt-text').inputValue()) === ''));
  await page.getByTestId('prompt-text').fill('Design team: follow the brand guide.');
  await page.getByTestId('save-prompt').click();
  await page.getByTestId('notice').filter({ hasText: /Prompt saved/ }).waitFor({ timeout: 15000 });
  await page.locator('[data-testid="agent-row"][data-key="commands"] select').selectOption('deny');
  await page.getByTestId('save-agents').click();
  await page.getByTestId('notice').filter({ hasText: /Agent permissions saved/ }).waitFor({ timeout: 15000 });
  const prompts = (await ws.api(mia, 'GET', '/v1/me/prompts')).json.prompts.map((p) => `${p.source}:${p.teamName || ''}:${p.content}`);
  check('a team prompt comes after everyone\'s and a team decision replaces everyone\'s', prompts.join('|') === 'organization::Be kind to customers.|team:Design:Design team: follow the brand guide.' && (await rules()).startsWith('shell * deny Design'), prompts.join('|') + ' // ' + await rules());
  check('there is nothing to choose in the model list yet, and the page says so', /no models to choose from/.test(await page.getByTestId('no-models').innerText()));
  if (shots) await page.screenshot({ path: shots + '/ui-policy-agents.png', fullPage: true });

  await page.getByTestId('remove-prompt').click();
  await page.getByTestId('notice').filter({ hasText: /Prompt removed/ }).waitFor({ timeout: 15000 });
  check('removing the team prompt leaves everyone\'s', await until(async () => (await ws.api(mia, 'GET', '/v1/me/prompts')).json.prompts.length === 1));

  // ---- Desktop app policies
  await page.goto(W + '/dashboard/desktop-policies', { waitUntil: 'networkidle' });
  await page.getByTestId('policy-row').first().waitFor({ timeout: 30000 });
  check('the default policy is listed first and marked', (await page.getByTestId('policy-row').first().getAttribute('data-default')) === 'true');
  await page.getByTestId('new-policy').click();
  await page.locator('#policy-name').fill('Designers');
  await page.locator('[data-key="allowCustomProviders"] select').selectOption('off');
  await page.locator('[data-team="Design"]').check();
  await page.locator('#policy-priority').fill('3');
  await page.getByTestId('save-policy').click();
  await page.getByTestId('notice').filter({ hasText: /Policy Designers created/ }).waitFor({ timeout: 15000 });
  const row = page.locator('[data-testid="policy-row"][data-name="Designers"]');
  check('a new policy is listed with who it applies to', /Design/.test(await row.getByTestId('policy-who').innerText()));
  // "Off" in a plain policy only withholds a grant: the default still turns it on. An access limit would switch it off.
  const cfg = async () => (await ws.api(mia, 'GET', '/v1/me/desktop-config')).json;
  check('turning a setting off in a plain policy does not override the default (grants add up)', (await cfg()).allowCustomProviders === true);
  await row.getByTestId('edit-policy').click();
  await page.locator('[data-key="allowZenModel"] select').selectOption('on');
  await page.getByTestId('save-policy').click();
  await page.getByTestId('notice').filter({ hasText: /Policy Designers saved/ }).waitFor({ timeout: 15000 });
  const saved = (await ws.api(ws.owner, 'GET', '/v1/desktop-policies')).json.desktopPolicies.find((p) => p.policyName === 'Designers');
  check('editing keeps the other settings and the team', saved.policy.allowZenModel === true && saved.policy.allowCustomProviders === false && saved.assignments.length === 1 && saved.priority === 3, JSON.stringify(saved.policy));
  const defRow = page.locator('[data-testid="policy-row"][data-default="true"]');
  await defRow.getByTestId('edit-policy').click();
  await page.getByTestId('editor-title').filter({ hasText: /Default desktop policy/ }).waitFor({ timeout: 10000 });
  check('the default policy has no name, priority or assignment fields', (await page.locator('#policy-name').count()) === 0 && (await page.locator('[data-team="Design"]').count()) === 0);
  await page.locator('[data-key="allowAlphaUpdates"] select').selectOption('off');
  await page.getByTestId('save-policy').click();
  await page.getByTestId('notice').filter({ hasText: /saved/ }).waitFor({ timeout: 15000 });
  check('changing the default reaches members', await until(async () => (await cfg()).allowAlphaUpdates === false));
  if (shots) await page.screenshot({ path: shots + '/ui-policy-desktop.png', fullPage: true });

  await page.locator('#auto-desktop').uncheck();
  await page.getByTestId('save-automations').click();
  await page.getByTestId('notice').filter({ hasText: /Automation settings saved/ }).waitFor({ timeout: 15000 });
  check('turning Desktop Automations off reaches members, and Cloud is explained as unavailable', await until(async () => (await cfg()).desktopAutomationsEnabled === false) && (await page.locator('#auto-cloud').isDisabled()));

  await page.locator('[data-testid="policy-row"][data-name="Designers"]').getByRole('button', { name: 'Delete' }).click();
  await page.getByTestId('confirm-delete').click();
  await page.getByTestId('notice').filter({ hasText: /Policy Designers deleted/ }).waitFor({ timeout: 15000 });
  check('deleting a policy removes it from the list', (await page.locator('[data-testid="policy-row"][data-name="Designers"]').count()) === 0);

  // ---- A member has no access to either page.
  const ctx2 = await browser.newContext({ viewport: { width: 1280, height: 800 } });
  const page2 = await ctx2.newPage(); page2.on('pageerror', (e) => errors.push(String(e).slice(0, 120)));
  await signIn(page2, mia.email);
  check('a member is offered neither page on the dashboard', (await page2.getByTestId('policy-link').count()) === 0 && (await page2.getByTestId('desktop-policies-link').count()) === 0);
  await page2.goto(W + '/dashboard/desktop-policies', { waitUntil: 'networkidle' });
  await page2.getByTestId('no-access').waitFor({ timeout: 30000 });
  check('a member who opens the desktop policy page is told they have no access', /don't have access/.test(await page2.getByTestId('no-access').innerText()));
  await page2.goto(W + '/dashboard/policy', { waitUntil: 'networkidle' });
  await page2.getByTestId('policy-page').waitFor({ timeout: 30000 });
  check('a member sees nothing to edit on the agents page', (await page2.getByTestId('agent-row').count()) === 0 && (await page2.getByTestId('save-prompt').count()) === 0);

  await finish(browser, errors);
})().catch((e) => { console.error('FAIL (exception)', e); process.exit(1); });
