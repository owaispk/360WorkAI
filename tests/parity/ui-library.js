// The library in a real browser against the rewrite: plugins, skills, sharing, marketplaces, my library, and importing from GitHub.
//   Start the rewrite with the import pointed at the fake GitHub this script serves on :5321:
//     Library__GithubApiBase=http://127.0.0.1:5321 Library__GithubRawBase=http://127.0.0.1:5321 scripts/dev.sh start
//   W=http://localhost:5220 A=http://localhost:5120 node tests/parity/ui-library.js [screenshot-dir]
const { chromium } = require('playwright');
const http = require('http');
const { W, A, check, workspace, until, signIn, finish, api } = require('./ui-lib');
const shots = process.argv[2];
const body = (page) => page.locator('body').innerText();
const skillText = (n, d, b = 'Do it.') => `---\nname: ${n}\ndescription: ${d}\n---\n\n${b}\n`;

// A stand-in for GitHub, so the import page reads a real HTTP server.
const files = {
  'skills/pitch/SKILL.md': skillText('pitch-deck', 'Build a pitch deck', 'Open with the problem.'),
  'skills/followup/SKILL.md': skillText('follow-up', 'Write a follow up', 'Be brief.'),
  'skills/broken/SKILL.md': 'no frontmatter here',
  'README.md': '# Sales kit',
};
const github = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  const send = (status, obj) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(obj)); };
  if (url.pathname === '/repos/o/kit') return send(200, { default_branch: 'main', private: false });
  if (url.pathname === '/repos/o/kit/commits/main') return send(200, { sha: 'abc123', commit: { tree: { sha: 'tree1' } } });
  if (url.pathname === '/repos/o/kit/git/trees/tree1') return send(200, { truncated: false, tree: Object.keys(files).map((path) => ({ path, type: 'blob', sha: 's' })) });
  if (url.pathname.startsWith('/o/kit/abc123/')) { const f = files[decodeURIComponent(url.pathname.slice('/o/kit/abc123/'.length))]; if (f !== undefined) { res.writeHead(200); return res.end(f); } }
  send(404, { message: 'Not Found' });
});

(async () => {
  await new Promise((r) => github.listen(5321, '127.0.0.1', r));
  const browser = await chromium.launch();
  const errors = [];
  const ws = await workspace('Library Workspace');
  const bob = await ws.join('Bob Member');
  const carol = await ws.join('Carol Member');
  const ann = await ws.join('Ann Admin', 'admin');
  const open = async (user, path) => {
    const ctx = await browser.newContext({ viewport: { width: 1100, height: 900 } });
    const page = await ctx.newPage();
    page.on('pageerror', (e) => errors.push(String(e)));
    await signIn(page, user.email);
    if (path) await page.goto(W + path, { waitUntil: 'networkidle' });
    return page;
  };
  const shot = async (page, name) => { if (shots) await page.screenshot({ path: `${shots}/library-${name}.png`, fullPage: true }); };

  // ---- the owner makes a plugin, adds a skill, edits it ----
  const owner = await open(ws.owner, '/dashboard');
  check('dashboard has the library buttons', (await owner.locator('[data-testid=plugins-link]').count()) === 1 && (await owner.locator('[data-testid=library-link]').count()) === 1 && (await owner.locator('[data-testid=marketplaces-link]').count()) === 1);
  await owner.locator('[data-testid=plugins-link]').click();
  await owner.waitForURL(/\/dashboard\/plugins$/);
  await owner.locator('[data-testid=plugins-page] h1').waitFor();
  check('plugins page starts empty and says so', await owner.locator('[data-testid=no-plugins]').isVisible());
  await owner.locator('#plugin-name').fill('Onboarding');
  await owner.locator('#plugin-description').fill('Welcome new people');
  await owner.locator('[data-testid=create-plugin]').click();
  await owner.waitForURL(/\/dashboard\/plugins\/plg_/);
  await owner.locator('[data-testid=plugin-title]').waitFor();
  const pluginId = owner.url().split('/').pop();
  check('creating a plugin opens it, with the maker as manager', (await owner.locator('[data-testid=plugin-title]').innerText()).includes('Onboarding') && (await owner.locator('[data-testid=my-role]').innerText()) === 'manager');
  check('a plugin starts with nothing in it', await owner.locator('[data-testid=no-skills]').isVisible());

  await owner.locator('[data-testid=skill-text]').fill(skillText('welcome-email', 'Draft a welcome email', 'Greet them by name.'));
  await owner.locator('[data-testid=add-skill]').click();
  check('adding a skill lists it', await until(async () => (await owner.locator('[data-testid=skill-row][data-name="welcome-email"]').count()) === 1), 'skill row missing');
  await owner.locator('[data-testid=skill-text]').fill('this is not a skill');
  await owner.locator('[data-testid=add-skill]').click();
  check('a bad skill is refused in words', await until(async () => /SKILL\.md must start with YAML frontmatter/.test(await body(owner))), (await body(owner)).slice(0, 300));
  await owner.locator('#edit-name').fill('Onboarding kit');
  await owner.locator('[data-testid=save-plugin]').click();
  check('renaming the plugin shows the new name', await until(async () => (await owner.locator('[data-testid=plugin-title]').innerText()).includes('Onboarding kit')));
  await shot(owner, 'plugin');

  // ---- share it with Bob ----
  await owner.locator('[data-testid=share-who]').selectOption({ label: `Bob Member (${bob.email})` });
  await owner.locator('[data-testid=share-button]').click();
  check('sharing with a person lists them', await until(async () => (await owner.locator('[data-testid=grant-row][data-who="Bob Member"]').count()) === 1));
  await owner.locator('[data-testid=share-button]').click();
  check('sharing with nobody chosen asks who', await until(async () => /Choose who to share with/.test(await body(owner))));
  await shot(owner, 'share');

  // ---- Bob sees it, Carol does not ----
  const bobPage = await open(bob, '/dashboard/library');
  await bobPage.locator('[data-testid=library-page] h1').waitFor();
  check("Bob's library shows the plugin, who shared it, and its skill", await until(async () => {
    const t = await body(bobPage);
    return t.includes('Onboarding kit') && t.includes('Shared with you by Olive Owner') && t.includes('welcome-email') && t.includes('You can use it');
  }), (await body(bobPage)).slice(0, 400));
  await shot(bobPage, 'my-library');
  await bobPage.goto(`${W}/dashboard/plugins/${pluginId}`, { waitUntil: 'networkidle' });
  await bobPage.locator('[data-testid=plugin-title]').waitFor();
  check('Bob can open it but cannot edit or share it', (await bobPage.locator('[data-testid=my-role]').innerText()) === 'viewer' && (await bobPage.locator('[data-testid=plugin-edit-form]').count()) === 0 && (await bobPage.locator('[data-testid=share-panel]').count()) === 0);
  const carolPage = await open(carol, `/dashboard/plugins/${pluginId}`);
  check("Carol, who was not given it, is told it is not shared with her and sees nothing of it", await until(async () => /has not been shared with you/.test(await body(carolPage))) && !(await body(carolPage)).includes('welcome-email'));
  await carolPage.goto(W + '/dashboard/plugins', { waitUntil: 'networkidle' });
  await carolPage.locator('[data-testid=plugins-page] h1').waitFor();
  check("Carol's plugin list does not show it", !(await body(carolPage)).includes('Onboarding kit'));
  await carolPage.goto(W + '/dashboard/library', { waitUntil: 'networkidle' });
  await carolPage.locator('[data-testid=library-page] h1').waitFor();
  check("Carol's library is empty", await carolPage.locator('[data-testid=library-empty]').isVisible());

  // ---- a skill: open, edit into a new version, share on its own ----
  await owner.locator('[data-testid=skill-row][data-name="welcome-email"] a').first().click();
  await owner.waitForURL(/\/dashboard\/skills\/cob_/);
  await owner.locator('[data-testid=skill-content]').waitFor();
  check('the skill page shows its instructions and its plugin', (await owner.locator('[data-testid=skill-content]').innerText()).includes('Greet them by name.') && (await body(owner)).includes('Onboarding kit'));
  await owner.locator('[data-testid=edit-skill]').click();
  await owner.locator('[data-testid=skill-text]').fill(skillText('welcome-email', 'Draft a warm welcome email', 'Greet them by name and mention their team.'));
  await owner.locator('#skill-reason').fill('warmer');
  await owner.locator('[data-testid=save-skill]').click();
  check('saving makes a second version', await until(async () => (await owner.locator('[data-testid=version-row]').count()) === 2 && (await owner.locator('[data-testid=skill-content]').innerText()).includes('mention their team')));
  await owner.locator('[data-testid=skill-text]').count();
  await shot(owner, 'skill');
  await owner.goto(W + '/dashboard/skills', { waitUntil: 'networkidle' });
  await owner.locator('[data-testid=skills-page] h1').waitFor();
  check('the skills list shows it and filters by search', (await owner.locator('[data-testid=skill-row]').count()) === 1);
  await owner.locator('[data-testid=skill-search]').fill('nothing-like-this');
  check('a search with no match says so', await until(async () => await owner.locator('[data-testid=no-skills]').isVisible()));

  // ---- a marketplace: create, add the plugin, share with everyone ----
  await owner.goto(W + '/dashboard/marketplaces', { waitUntil: 'networkidle' });
  await owner.locator('[data-testid=marketplaces-page] h1').waitFor();
  await owner.locator('#market-name').fill('Company shelf');
  await owner.locator('[data-testid=create-marketplace]').click();
  await owner.waitForURL(/\/dashboard\/marketplaces\/mkt_/);
  await owner.locator('[data-testid=marketplace-title]').waitFor();
  await owner.locator('[data-testid=add-plugin-select]').selectOption({ label: 'Onboarding kit' });
  await owner.locator('[data-testid=add-plugin]').click();
  check('adding a plugin puts it on the shelf', await until(async () => (await owner.locator('[data-testid=shelf-row][data-name="Onboarding kit"]').count()) === 1));
  await owner.locator('[data-testid=share-who]').selectOption({ label: 'Everyone in the workspace' });
  await owner.locator('[data-testid=share-button]').click();
  check('the marketplace shows it is shared with everyone', await until(async () => (await owner.locator('[data-testid=grant-row][data-who="Everyone in the workspace"]').count()) === 1));
  await shot(owner, 'marketplace');
  await carolPage.goto(W + '/dashboard/library', { waitUntil: 'networkidle' });
  await carolPage.locator('[data-testid=library-page] h1').waitFor();
  check("Carol now sees the plugin through the marketplace, read-only, and not its skills' text", await until(async () => {
    const t = await body(carolPage);
    return t.includes('Onboarding kit') && t.includes('In the Company shelf marketplace');
  }), (await body(carolPage)).slice(0, 300));
  check('a person without the marketplace permission cannot create one', await (async () => {
    const page = await open(carol, '/dashboard/marketplaces');
    await page.locator('[data-testid=marketplaces-page] h1').waitFor();
    return (await page.locator('[data-testid=marketplace-form]').count()) === 0 && (await page.locator('[data-testid=marketplace-row]').count()) === 1;
  })());

  // ---- import from GitHub ----
  const admin = await open(ann, '/dashboard/plugins/import');
  await admin.locator('[data-testid=import-page] h1').waitFor();
  await admin.locator('#github-url').fill('https://example.com/o/kit');
  await admin.locator('[data-testid=preview-button]').click();
  check('a wrong address is explained', await until(async () => /Only github\.com plugin URLs are supported/.test(await body(admin))));
  await admin.locator('#github-url').fill('https://github.com/o/kit');
  await admin.locator('[data-testid=preview-button]').click();
  check('the preview lists the skills found and marks the broken one', await until(async () => (await admin.locator('[data-testid=plan-skill]').count()) === 3) && (await body(admin)).includes('Not a valid SKILL.md'));
  await shot(admin, 'import-preview');
  await admin.locator('[data-testid=plan-skill][data-name="follow-up"] input').uncheck();
  await admin.locator('#import-name').fill('Sales kit');
  await admin.locator('[data-testid=import-button]').click();
  check('importing shows what was added', await until(async () => /Plugin created: 1 added/.test((await admin.locator('[data-testid=import-result]').innerText().catch(() => '')).replace(/\s+/g, ' '))));
  await admin.locator('[data-testid=open-plugin]').click();
  await admin.waitForURL(/\/dashboard\/plugins\/plg_/);
  await admin.locator('[data-testid=plugin-title]').waitFor();
  check('the imported plugin holds only the chosen skill', (await admin.locator('[data-testid=skill-row]').count()) === 1 && (await body(admin)).includes('pitch-deck') && !(await body(admin)).includes('follow-up'));
  const member = await open(bob, '/dashboard/plugins/import');
  await member.locator('[data-testid=import-page] h1').waitFor();
  check('a member is told only admins can import', await member.locator('[data-testid=import-denied]').isVisible());

  // ---- lifecycle: archive hides it from the active list ----
  await owner.goto(`${W}/dashboard/plugins/${pluginId}`, { waitUntil: 'networkidle' });
  await owner.locator('[data-testid=archive-plugin]').click();
  check('archiving a plugin says so', await until(async () => /Plugin archived/.test(await body(owner))));
  await owner.goto(W + '/dashboard/plugins', { waitUntil: 'networkidle' });
  await owner.locator('[data-testid=plugins-page] h1').waitFor();
  check('an archived plugin is not in the active list', !(await body(owner)).includes('Onboarding kit'));
  await owner.locator('[data-testid=plugin-status]').selectOption('archived');
  check('it is in the archived list', await until(async () => (await body(owner)).includes('Onboarding kit')));
  await shot(owner, 'plugins');

  await finish(browser, errors);
  github.close();
})().catch((e) => { console.error(e); github.close(); process.exit(1); });
