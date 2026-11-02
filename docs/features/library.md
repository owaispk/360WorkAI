# The library: plugins, skills, marketplaces and who may use them

Code: `src/WorkAI360.Api/Features/Library/` (routes, access rules, GitHub import, usage, the agent capability), entities in
`Domain/Library/LibraryEntities.cs`, pages in `src/WorkAI360.Web/Components/Pages/` (`Plugins`, `PluginDetail`, `Skills`, `SkillDetail`,
`Marketplaces`, `MarketplaceDetail`, `MyLibrary`, `PluginImport`) with the shared `Components/Shared/SharePanel.razor` and `wwwroot/library.css`.
Tests: `tests/WorkAI360.Api.Tests/LibraryTests.cs` (23), `tests/parity/area-library.mjs` (56, runs on the reference and the rewrite),
`tests/parity/ui-library.js` (31, browser).

## What it is

A **plugin** is a bundle. A **config object** is one thing in a bundle: a skill (a `SKILL.md`), a command, an agent, and so on. Every
config object keeps **versions** (a new text is a new version, nothing is overwritten). A **marketplace** is a shelf of plugins. Plugins,
marketplaces and skills are **shared** with a person, a team, or everyone, as `viewer`, `editor` or `manager`.

## Who can see and do what

A person's role on a thing is the highest of:

* **manager** on everything, if they hold *Manage everything shared* (`sharing.manage_all`; admins and the owner by default);
* **manager** on a plugin they made (and the maker of a skill, plugin or marketplace gets a manager grant on it);
* any grant to them, to a team they are in, or to everyone;
* otherwise: **viewer** on a plugin that sits in a marketplace shared with them; **viewer** on a skill that sits in a plugin they made or
  were given (marketplace access alone never opens the skills inside).

Removed grants keep their row (`removedAt`) and sharing again brings the same grant back. A thing in another workspace is always `404`;
a thing in this workspace you may not see is `403 "Missing viewer access for …"` (as the reference answers) and it never appears in
a list, in `resolved-plugins`, in "my library", or in what an agent can find. Sharing with everyone needs *Share with everyone*
(`sharing.share_org_wide`) even for a manager. Making a marketplace needs *Create and remove marketplaces* (`marketplaces.manage`).
Importing from GitHub needs *Import plugins from GitHub* (`plugins.import`). Library usage needs *View usage analytics*.

**Agents** (`/mcp/agent`) follow explicit sharing only: a skill is a capability `plugin:<pluginId>:<skillId>` (the reference's id) when
it is active, in an active plugin, and shared with that person, their team, or everyone (on the skill, the plugin, or a marketplace that
holds the plugin). Being an admin shows an agent nothing. `search_capabilities` finds it, `execute_capability` returns
`{kind, plugin, marketplace, name, description, provenance, content}` and records a use.

## Routes built

Plugins: `GET`/`POST /v1/plugins` (list with `status`, `q`, `name`, `teamId`, `memberId`, `ownerId`, `includeAccess`, `includeTotal`,
`includeFacets`, keyset `cursor`/`limit`; create with `components`, `orgWide`, `marketplaceId`), `GET`/`PATCH /v1/plugins/{id}`,
`POST …/archive|restore`, `GET`/`POST …/config-objects`, `DELETE …/config-objects/{id}`, `GET …/resolved`, `GET /v1/resolved-plugins`,
access `GET`/`POST …/access`, `DELETE …/access/{grantId}`.
Config objects (skills): `GET`/`POST /v1/config-objects`, `GET …/{id}`, `POST …/archive|delete|restore`, versions (`GET`, `POST`,
`…/latest`, `…/{versionId}`), `GET`/`POST …/plugins`, `DELETE …/plugins/{id}`, access `GET`/`POST`/`DELETE`.
Marketplaces: `GET`/`POST /v1/marketplaces`, `GET`/`PATCH …/{id}`, `POST …/archive|delete|restore`, `GET`/`POST …/plugins`,
`DELETE …/plugins/{id}`, `GET …/resolved`, access, and the declarative `GET`/`PUT`/`DELETE /v1/marketplaces/by-key/{key}`.
Views: `GET /v1/me/library`, `GET /v1/me/plugin-access`, `GET /v1/teams/{id}/plugin-access`.
Usage: `GET /v1/library-usage/{skills|plugins|connectors}`, `GET /v1/library-usage` (breakdown by item, member, day).
Import: `POST /v1/plugins/import-mcps-from-github-url/preview` and `POST /v1/plugins/import-mcps-from-github-url`.

## Importing from GitHub

The importer really fetches over HTTP: the repository's commit and file tree from the GitHub API, then each file from the raw host
(`Library:GithubApiBase`, `Library:GithubRawBase`; tests and `ui-library.js` point them at a local server). It reads a repository or a
`/tree/<branch>/<folder>` address, recognizes a `.claude-plugin/marketplace.json` repository, plugin folders (`plugin.json`), or infers
plugins from `skills/` folders, lists their `skills/*/SKILL.md` (invalid ones are reported and skipped) and the servers in `.mcp.json`.
Import creates **one** plugin from the chosen skills, shares it (everyone by default, or the people and teams given), optionally puts it
on a marketplace, and on a second import of the same address **updates** changed skills as new versions, leaves unchanged ones, adds new
ones, and archives (never deletes) skills the repository no longer has.

## Differences from the reference (on purpose or not built)

* **Remote MCP servers in a plugin** are bound to connections (`components[].connection` / `connectionId`, `POST /v1/plugins/{id}/mcp-connections`, the
  `cloudReadiness` of marketplace plugins): see `gaps.md`. The GitHub import still lists the servers in `.mcp.json` and says they are not
  imported, and `source` in `GET /v1/marketplaces/{id}/resolved` is always `null`. Connectors, connector accounts, targets, sync events and the
  GitHub App install routes (`/v1/connectors/github/*`, `/v1/connector-*`) are not built; `/v1/me/library` lists plugins only (no
  connections or workflows), and the library-usage `connectors` kind is always empty.
* The reference creates a built-in **"OpenWork Marketplace"** with three built-in plugins the first time marketplaces are listed. The
  rewrite does not seed anything.
* The reference's GitHub discovery is richer (agent-plugin manifests, Claude plugin component declarations, private repositories through
  the connector, rate-limit credentials). The rewrite's is the simpler one described above and rejects private repositories the same way.
* **Races**: the reference lets two identical plugin creations at once both succeed and a double share answer 500 for some requests; the
  rewrite makes exactly one plugin (`409 duplicate_plugin` for the rest), one grant (every share answers 201), one marketplace per key.
  Plugin names are unique per person, ignoring case, while active.
* Usage is recorded as one row per skill read by an agent (source `agent`), not as raw rows plus daily rollups; `sources` is therefore only
  ever `agent`; failures are `0` for plugins and `null` for skills.
* `GET /v1/plugins?teamId=…` / `memberId=…` filter what that team or person could see. A reference quirk is not copied: asking
  `GET /v1/config-objects?pluginId=<plugin you cannot view>` answers 500 there and a plain 403 here.
* Audit events, `x-mcp` search aliases, the OpenAPI contract and `If-Match` preconditions (refused `400` on the by-key `PUT`) are not built.
* Lists load a workspace's plugins and work out access in memory: fine for hundreds of plugins; add indexes/SQL filters when a workspace
  has tens of thousands.
* The skill page offers *Edit* only to people who manage the skill (there is no route that says "you are an editor"): editors can still
  save versions through the API.

## Checks

The access rules are mutation-checked: removing any of these makes at least one `LibraryTests` test fail: revoked grants still applying,
team grants applying to everyone, plugin roles ignoring the workspace, any marketplace opening its plugins, any plugin opening its skills,
everyone being *manage all*, no check on sharing with everyone, no manager check on sharing, agents seeing everything, agents seeing
archived plugins, no editor check. One mutation survives on purpose: skill roles ignoring the workspace (every caller already loads the
skill within the workspace first, so it cannot be reached).
