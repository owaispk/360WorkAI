# Policy: what admins set for people and teams

Code: `src/WorkAI360.Api/Features/Policy/` (rules, routes, delivery), entities in `Domain/Policy/PolicyEntities.cs`, pages
`src/WorkAI360.Web/Components/Pages/Policy.razor` (`/dashboard/policy`) and `DesktopPolicies.razor` (`/dashboard/desktop-policies`), dashboard
buttons in `Components/PolicyDashboardLinks.cs`.
Tests: `tests/WorkAI360.Api.Tests/PolicyRulesTests.cs` (69, the resolution rules as pure functions), `PolicyTests.cs` (44, through the API),
`tests/parity/area-policy.mjs` (38, runs on the reference and the rewrite), `tests/parity/ui-policy.js` (21, browser).

## What it is

Five things an admin sets, for everyone or for one team (and, for desktop policies, for a person or a role), and what a signed-in person's
desktop receives as a result (`GET /v1/me/desktop-config`, `GET /v1/me/prompts`).

### Resolution rules (pure functions, unit-tested)

* **Desktop policies** (`DesktopPolicyRules`). Every workspace has one default policy (always on, cannot be deleted or disabled). A person gets
  the default plus every enabled policy assigned to them: by id, by a team they are in, or by a role (an owner matches `owner`, `admin` and
  `member`; an admin, or anyone in an Admin team, matches `admin` and `member`; everyone matches `member`).
  * *Grants add up.* A setting is on when the default (a missing key counts as the catalog default, on) or any assigned policy turns it on. A
    policy that only says "off" withholds a grant; it does not switch anything off.
  * *Access limits switch off.* A policy with `access` (`custom`: the listed capabilities, `locked`: every restrictable setting off) then turns the
    named settings off whatever the grants said. Display preferences (the welcome page) are never locked.
  * *Execution limits intersect.* `commands: deny` wins, blocked commands add up, uploads are blocked if any policy blocks them, and browser origins
    narrow to the sites every policy that lists origins allows (a list that is absent is no limit; an empty list allows nothing).
  * *Onboarding suggestions.* The assigned policy with the highest priority that has valid suggestions (2 or 3 prompts) wins, ties go to the older
    policy and then the smaller id; with none the default's apply.
  * A policy that is deleted, disabled or whose team or person is gone does not apply.
* **Agent permissions** (`AgentPermissionRules`). Per permission (commands, file edits, websites, web search, local skills, local MCP servers) a
  decision (allow, ask first, block; the last three are switches without "ask") and for commands and websites lists of always-allowed and
  always-blocked patterns. For one person: each of their teams has its own decision, else everyone's; the strictest decision of their teams
  applies; an allowed pattern stays an exception only if every restricting team allows it (everyone's allowed patterns count in each team); blocked
  patterns add up, everyone's first; blocking file edits also blocks every command. The result is the ordered rule list the desktop gets (last
  match wins). Patterns are normalized (sites lower-cased, `/*` and trailing dots dropped, ports normalized) and matched by host, subdomain, port,
  scheme and canonical path (encoded letters and separators, dot segments, repeated slashes).
* **Prompts** (`PromptRules`). Everyone's first, then each of the person's teams' by team name, then prompts for the person; a prompt that applies twice
  counts once, an empty one never.
* **Default model** (`DefaultModelRules`). The model new chats start with: the person's teams' override (by team name) if they all agree, the
  organization default if two teams disagree (a conflict never picks a team), else the organization default, else the desktop's own. The listing
  counts, per team, the members who are also on a team that overrides differently.

## Routes built

Desktop policies: `GET`/`POST /v1/desktop-policies`, `GET`/`PATCH`/`DELETE /v1/desktop-policies/{id}`, `GET`/`PUT`/`DELETE /v1/desktop-policies/by-key/{key}`
(`desktop_policies.view` / `.manage`). Agent permissions: `GET /v1/agent-permissions`, `PUT /v1/agent-permissions/everyone`, `PUT`/`DELETE
/v1/agent-permissions/teams/{id}` (`agent_permissions.view` / `.manage`). Prompts: `GET /v1/org/prompts`, `PUT`/`DELETE /v1/org/prompts/everyone`,
`PUT`/`DELETE /v1/org/prompts/teams/{id}` (`prompts.view` / `.manage`). Default model: `GET /v1/org/default-model`, `GET .../options`, `PUT
.../everyone`, `PUT .../teams/{id}` (`inference.view` / `.manage`). Settings: `GET`/`PUT /v1/org/automation-settings` (any member / `organization.update`),
`GET /v1/org/workbot-readiness` (any member), `GET`/`PUT /v1/org/workbot-settings` (`inference.view` or `.manage` / `.manage`). Delivery: `GET /v1/me/desktop-config`,
`GET /v1/me/prompts` (any member). The Auto Router routes and Workbot's proactive-agent routes answer `404 feature_disabled`, as the reference does with those
features off. Writes of sensitive permissions need a recent sign-in (`403 reauth`).

Pages: **Agents, prompts and models** (choose Everyone or a team; prompt, the six agent permissions with their lists, the starting model) and **Desktop app
policies** (list, create, edit, delete, who it applies to, Automation switches).

## Differences from the reference

* **The default policy is made when first needed** (listing, writing, or a person's desktop config), not when the workspace is made; two requests at once
  end with one (a plain unique key). The answers are the same.
* **No plan check.** The reference refuses policy writes on workspaces without the Enterprise entitlement (`402`); there are no plans here.
* **Cleanup is the database's.** Deleting a team or removing a person removes the policy assignments, agent permissions, prompt and default model set
  for them through foreign keys with `ON DELETE CASCADE` (the reference does it in code in the same transaction). Because the cascade is by foreign key,
  `TeamEndpoints` and the member routes needed no change.
* **Prompts are one row per scope** (everyone, or a team) instead of a prompt plus an access list; the wire shape (`assignment`) is the same. The reference's
  schema can also hold a prompt assigned to a person or several teams, but no route makes one, and the resolver still handles them (unit-tested).
* **Agent permission settings are one JSON document per scope**, normalized on read as the reference does; saving nothing removes the row.
* **Models come from a catalog interface** (`IDefaultModelCatalog`). The reference lists the AI Gateway's, OpenWork Models' and the organization's providers;
  none exist here, so the built-in catalog is empty, exactly as the reference's is for a workspace with nothing set up. That means a model can only be cleared
  (`null`), never chosen, until another catalog is registered; the full path (options, validation, the person's own model reference, conflicts) is tested
  with a fake catalog.
* **Workbot settings** can only be saved as "the default" (`null`): choosing a model needs Workbot's runner, which the reference also reports as unavailable
  (`503 workbot_runner_unavailable`) when it cannot be reached. Readiness always says the Gateway is required and has no provider. The value shown is the
  reference's static default model name.
* **Automations**: `cloud` can never be turned on (`409 headless_runner_required`) because nothing provides a headless runner; `Policy:HeadlessRunnerConfigured` and
  `Policy:AutomationsEnabled` mirror the reference's deployment switches. `GET /v1/me/desktop-config` leaves out the organization branding and allowed desktop
  versions (stored in organization metadata in the reference; nothing here writes them).
* **Validation reports the first problem only** (the reference reports the first and "(and N more)").
* The reference's desktop-policy list sorts by name with the database's collation; here by name ignoring case.

## Not built

The Auto Router (needs AI Gateway providers), Workbot's proactive-agent settings and health, `POST /v1/org/workbot-settings/test-default-model`, the audit events
the reference records for agent-permission changes, SCIM-managed teams' policy projection, and den-web's "Browser", "Models" (providers, spend limits) and Desktop
suggestion editors as separate tabs: the page offers the same settings in one place. Desktop-config `desktopCapabilityConfig` filtering (enforcement of
desktop feature policies is switched off in the reference, `DESKTOP_POLICY_ENFORCEMENT_ENABLED = false`, and the desktop applies it).

## Checks

Mutation checks (one rule removed at a time, each caught by a failing test): strictest decision picks the loosest; allowed patterns survive without every
restricting team's consent; blocking edits stops blocking commands; access limits ignored; grants stop adding up; origins union instead of intersect; lowest
priority wins onboarding; Admin teams stop matching the admin role; team conflict picks a team; a team prompt applies to everyone; policy routes skip the
permission check; a policy of another workspace can be updated; the default policy can be deleted; assignments survive a team's deletion.
