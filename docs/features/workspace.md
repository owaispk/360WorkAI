# Workspace: Workflows, apps, the Apps catalog, webhooks, memory answers

Six reference features that had no home yet, built as one area. Code: `src/WorkAI360.Api/Features/Workspace/`, entities in
`Domain/Workspace/`, pages `Components/Pages/WorkflowDetail.razor` and `WorkflowRuns.razor` (plus Workflow cards on `MyLibrary.razor`).
Tests: `tests/WorkAI360.Api.Tests/WorkspaceUnitTests.cs`, `CodeModeRunnerTests.cs`, `WorkflowTests.cs`, `WorkspaceViewTests.cs`;
`tests/parity/area-workspace.mjs` (82 checks, runs on the reference and the rewrite); `tests/parity/ui-workspace.js` (36 checks, browser).

| Feature | Built |
|---|---|
| Memory (`/v1/memory*`) | yes: the reference's answers for the removed Memory Bank |
| Workflows and run receipts | yes, with a real script runner |
| Artifact views and saved apps | yes, serving what exists; the builder that writes new revisions is **not** built |
| Direct uploads | **no** (needs Google Workspace or Microsoft 365); the routes answer 401 / 501 |
| MCP apps | the catalog (`GET /v1/mcp-apps`); the apps' own MCP servers and the builder are **not** built |
| Webhooks | yes for the wire (signatures, answers); no GitHub App installations or billing behind them |

## Memory

`GET /v1/memory` is `{memories: []}`, `GET /v1/memory/search` is `{results: []}`, `DELETE /v1/memory/{id}` is `404 {error: "memory_not_found"}`,
`POST /v1/memory` is `410 {error: "deprecated", message}` and needs no sign-in; the three others answer `401` without one. Published desktop
builds still call these, so the shapes are the reference's, and nothing is stored.

## Workflows

A Workflow is a Code Mode script: JavaScript with top-level `await` and `return`, given `input` and a `tools` tree. It lives as a config object of
type `workflow` (versions with schema `codemode-script-v1`) inside a plugin, so **access is the library's**: viewer reads, editor runs, manager
changes it; a Workflow in another workspace reads as `404 workflow_not_found`, a person with no grant gets `403 forbidden "Missing viewer access
for config object."`. Created through the library's own routes (`POST /v1/config-objects` with `type: "workflow"`, then attach to a plugin) or by
saving a successful run (below).

Routes (all under the signed-in person's workspace; `/v1/codemode-scripts*` and `/v1/programs/*` are the reference's one-release aliases):

| Route | What |
|---|---|
| `GET /v1/workflows` | the Workflows shared with the person (a grant on it, its plugin, or a marketplace holding the plugin: explicit sharing only, as for skills), with the latest version id, schemas and capabilities |
| `POST /v1/workflows` | save a successful run as a Workflow (`code` or `receiptId`, `pluginId`, `currentInput`, schemas); `201 {pluginId, configObjectId, configObjectVersionId, graph, mermaid}`. Without `pluginId` it goes into the person's private "My Workflows" plugin; the same name makes a new version |
| `GET /v1/workflows/{id}` | `{workflow, script, views}`: library card (role, edges, readiness, result freshness, view state, Automation count), detail (versions, latest snapshot, freshness; `?maxAgeMs=` 60 s to 30 days) and views |
| `GET /v1/workflows/{id}/versions`, `POST …/versions` | immutable versions; a new one needs the receipt of a passing test of the exact same draft |
| `POST /v1/workflows/test` | run a draft once (manager); answers a receipt |
| `POST /v1/workflows/{id}/run` | run an exact version (`mode: adhoc` or `live`, `timeZone`); keeps a receipt and the validated result |
| `GET …/snapshots`, `GET …/snapshots/{receiptId}`, `DELETE …/snapshots/{receiptId}/content` | receipts of saved versions (keyset pages), one receipt, erase a run's stored result (the receipt stays) |
| `GET /v1/workflow-runs` (alias `/v1/codemode-runs`) | the person's own receipts, newest first, with the Workflow's title and call graph |
| `GET /v1/workflows/{id}/views` | see views |

### What a script can do

The runner is [Jint](https://github.com/sebastienros/jint) (a JavaScript interpreter in .NET) with no host access: no files, network, modules, timers
or .NET types. Strict mode, time limit (the version's `limits.timeoutMs`, default 120 s, at most 170 s), memory cap, recursion cap, tool-call cap
(1024), output cap (64 KB). Results are plain JSON: `undefined` becomes `null` (also nested); functions, symbols, `NaN`, cycles, dates and maps are
refused. `console.log` is collected. A live run gets a read-only, deep-frozen `input.runtime` (`now`, `today`, `timeZone`, `dayStart`, `dayEnd`).
Failures carry the reference's kinds: `ParseError`, `InvalidDataValue`, `ToolCallLimitExceeded`, `TimeoutExceeded`, `ToolFailure`, `ExecutionFailure`
(an uncaught throw reads `Uncaught: <message>`).

**Tools** are what the person's agents can already do through `/mcp/agent`, so every call is authorized as that person when it runs:
`tools.den.whoami`, `tools.den.workspace_members`, and each connected MCP server they may use as `tools.<connection name>.<tool>` (name lower-cased,
other characters `_`, a number added on collision, `den`/`skills`/`marketplace`/`admin` reserved). A Workflow's `requiredCapabilities` list the tools
it uses (`{capabilityName: "mcp:<connectionId>:<tool>", scriptPath: "tools.docs.search"}`); a run is offered **only** those, and a tool that is
missing, switched off by the connection's tool policy, or no longer shared with the person fails the run before anything is called
(`400 capability_unavailable`, a failed receipt). A live run is offered only tools that need no write scope (today the `den` ones).

### Saving a successful run

`execute_capability_script` is a third tool on `/mcp/agent` (`mcp:write`; live mode needs only `mcp:read`): run a script once as the person, get
`{value, markdown, receiptId, toolCalls, savable}`. The exact source is kept in memory for 15 minutes (as the reference does when no shared store is
configured: after a restart, or on another instance, run it again). `POST /v1/workflows` then checks the receipt belongs to the same person and
workspace, is under 15 minutes old, and that source, input and schema digests match; the tools the run called become `requiredCapabilities` (and must
still be offered). Source holding a literal credential (bearer tokens, API keys, private keys, `user:pass@` URLs, `password = "…"` assignments, also
hidden by `\u` escapes) is refused everywhere: `400 workflow_source_contains_secret`. Agents also find and run saved Workflows with
`search_capabilities` / `execute_capability` (ids `plugin:<pluginId>:<workflowId>`, the reference's).

### Receipts

One row per run (`WorkflowRun`): digests (code, input, input/output schema, result), the names of the tools called, timing and outcome. The result
value and its Markdown are **encrypted at rest** (AES-GCM, as connection secrets are) and cleared when erased; the raw input is never stored, only its
digest. A receipt is readable by the person who made it, and by anyone with access to the Workflow when it was made under the Workflow's standing
source (a manual run of a saved version); a live run or a draft test is its maker's alone. Only the maker of a run, if they manage the Workflow, can
erase its content. A receipt that cannot be written never hides the run's result (it just has none).

Rules checked by tests (and mutation-checked, below): one receipt makes one version even when two requests race (taken under the workspace lock);
a receipt older than 15 minutes, another person's, or of a changed draft is refused; the markdown renderer escapes cell text.

## Views and apps

`GET /v1/workflows/{id}/views`, `POST /v1/artifact-views/{id}/revisions/{revisionId}/activate`, `POST /v1/artifact-views/{id}/retire`,
`GET /v1/apps`, `GET /v1/apps/{id}`, `POST /v1/apps/{id}/share`, `/dashboard`, `/save`. **Off by default**, exactly as in the reference
(`Workspace__GeneratedArtifactViewsEnabled=true` turns them on): then `/v1/apps` says `enabled: false` and every other route is
`404 artifact_view_not_found`. With them on, and Apps as MCP servers on (the default, `Workspace__AppMcpServersEnabled`), Workflow-bound views are
read-only: they open and refresh and can be retired, but activate and save answer `409 legacy_view_read_only`. A view is readable by whoever reads its
Workflow and changed only by its managers (anyone else gets 404, so its existence is not revealed). Activating checks the revision built, is not
retired and was built against the Workflow's current output schema; saving also names the revision it expects to replace (`409 app_changed_since_preview`,
decided under the workspace lock so one of two saves at once loses), puts the app on the person's dashboard and records the title and
`useInWorkflow`. Retiring removes it from every dashboard. Sharing an app gives the teammate viewer access to the **Workflow** (never lowering an
existing grant; result data is never copied) and a dashboard card. Opening a live app runs the Workflow as the person with the time zone given.

**Not built:** the builder that compiles an app's React source and writes revisions (it needs a JavaScript bundler), so no revision is ever made here;
tests write them to the database directly. The reference's `runError.connectionCard` (a card pointing at the connection to fix) is reduced to
`{ok: false, error, message}`.

## MCP apps

`GET /v1/mcp-apps`: the Apps (config objects of type `app` whose newest version is a well-formed authored MCP App) whose plugin is shared with the person,
sorted by title, in the connection-tile shape (`serverName`, `connectionId` = the app id, `toolName: "open_app"`, `projectedToolName`, `resourceUri`
`ui://openwork/apps/{appId}/revisions/{revisionId}/index.html`, title, description, plugin, `requiresInput: false`, `requiresApproval: false`). Empty when
`Workspace__AppMcpServersEnabled` is off. A newest revision that is malformed hides the App. `GET /v1/mcp-connections/{id}/mcp-apps` (an external
server's apps) was already built with connections. **Not built:** each App's own MCP server (`/mcp/agent/connections/{appId}`, with `open_app` and the page
as a resource), and writing Apps (`create_app`, `update_app`).

## Webhooks

* `POST /v1/webhooks/connectors/github`: no secret (`Workspace__GithubWebhookSecret`) is `503` with no body; the `x-hub-signature-256` (HMAC SHA-256 of the
  raw body) is compared in constant time before anything is read (`401 {ok: false, error: "invalid signature"}`); events other than `push`,
  `installation`, `installation_repositories`, `repository`, or without an event or delivery id, answer `200 {ok: true, accepted: false, reason: "event ignored"}`;
  also `missing installation id` and `missing push metadata`. **This build keeps no GitHub App installations, so a verified delivery is never accepted
  (`202`)**: every one is acknowledged and ignored. Difference: a body that is not JSON is `400 {ok: false, error: "invalid payload"}` (the reference throws).
* `POST /v1/webhooks/stripe`: no secret (`Workspace__StripeWebhookSecret`) is `400 stripe_webhook_secret_missing`, no header `400 stripe_signature_missing`;
  the `t=…,v1=…` header is verified over `t.body` with a five-minute tolerance, then `200 {received: true, type}`. Billing is not part of this build, so the event is
  acknowledged and **not applied**. Difference: a bad signature or a stale timestamp are all `400` with Stripe's wording (the reference answers a stale timestamp `500`).

## Direct uploads

Every route is Google Workspace or Microsoft 365 transport (`/v1/direct-uploads/google-workspace/{drive-upload-sessions, drive-files, gmail-drafts}`,
`/v1/direct-uploads/microsoft-365/{mail-drafts, drive-upload-sessions, drive-upload-sessions/content}`), and this build connects to neither. They are
registered so the answers are honest: without a bearer token the reference's `401 {error: "missing_mcp_token", …}`, with one `501 {error: "not_supported"}`.
Nothing is stored or forwarded.

## Differences from the reference (beyond the ones above)

* **Script engine.** The reference runs scripts in its own confined interpreter; this build uses Jint, so the supported JavaScript is Jint's (ES2023-ish)
  rather than the reference's subset, and parse errors read differently (`Failed to parse script: …`). Results are held to the same plain-data rule.
* **Tools.** The tool tree is built from this build's capability providers (the two built-in read operations and connected MCP servers), not the reference's
  catalog of Den operations, native Google/Microsoft providers and skills namespaces. Read-only for live runs is decided by the scope a provider asks for
  (a connection's own hints are not trusted), so no connection tool runs live.
* **JSON Schema.** Validation is this build's own checker (draft 7 / 2020-12 keywords listed in `JsonSchemaCheck.cs`; `format` is not enforced), worded like
  Ajv. A schema it cannot use is `unsupported`, never a pass.
* **Generic library routes** show a Workflow's version without its source and example input, as the reference does, **and** without the source in the object's
  search text (the reference leaves it there until the first new version): a deliberate, small hardening.
* `/v1/workflow-runs` has no plan check (this build has no plan gating); a run list entry carries the Workflow only while the person can still read it.
* The Workflow card's `edges` come from this build's access model (the plugin's doors, the person who made it, grants on the Workflow); a grant's `sharedBy` is `null`.
* Created Workflows have no `currentFileName`/`currentFileExtension` (those columns are not part of this build's config objects).
* Automations: `saved_script` actions are still refused (cloud execution needs a runner), so `automationReferences` is always empty and a receipt is never
  attached to an Automation run.

## Not built

Direct uploads (needs Google/Microsoft); the app builder, each App's own MCP server and app authoring tools; GitHub App installation and sync (so no webhook is
ever accepted) and billing behind the Stripe webhook; a shared store for retained authoring source (it is per process); pages for apps and the Apps catalog
(den-web has none for them under the routes built here). The runner events stream and Automation `saved_script` execution are built in the Automations area
([automations.md](automations.md)); the Workflow runs page answers at den-web's `/dashboard/analytics/workflow-runs` and its old addresses
`/dashboard/workflow-runs` and `/dashboard/script-runs`, with a refresh button, linked from Analytics.

## Switches

| Setting | Meaning |
|---|---|
| `Workspace__GeneratedArtifactViewsEnabled` | generated views and `/v1/apps*` (default off) |
| `Workspace__AppMcpServersEnabled` | Apps as MCP servers; the catalog; views read-only (default on) |
| `Workspace__GithubWebhookSecret`, `Workspace__StripeWebhookSecret` | the secrets the two webhooks verify (unset: refused) |
| `Workspace__DefaultTimeoutMs`, `Workspace__MaxTimeoutMs` | a script's default and ceiling (120000, 170000) |

## Running the checks

```bash
dotnet test --filter "FullyQualifiedName~WorkflowTests|FullyQualifiedName~ViewTests|FullyQualifiedName~ViewsDisabled|FullyQualifiedName~McpAppCatalog|FullyQualifiedName~NoAppServers|FullyQualifiedName~LegacyView|FullyQualifiedName~WorkspaceUnitTests|FullyQualifiedName~CodeModeRunnerTests"
node tests/parity/area-workspace.mjs                                              # reference (defaults: views off, no webhook secrets)
W=http://localhost:5291 A=http://localhost:5191 node tests/parity/area-workspace.mjs   # rewrite
W=http://localhost:5291 A=http://localhost:5191 node tests/parity/ui-workspace.js /tmp/shots
```

## Checks

120 xUnit test methods (196 cases) for this area; the whole suite is 1031 cases and passes on SQLite and on MySQL 8. `area-workspace.mjs` is 82/82 on the
reference and on the rewrite, `ui-workspace.js` 36/36. The added `execute_capability_script` tool changes the tool list `/mcp/agent` answers (an existing
assertion in `OAuthTests` and in `real-mcp-client.mjs` was updated).

Rules were mutation-checked: one rule removed at a time, a test must fail. All were killed (the first attempt at "no workspace filter" survived only because
a second, redundant workspace filter on the plugin also holds; both removed, it is killed):
no role check on a Workflow; no workspace filter; another person's receipt accepted; receipt window unchecked; one receipt usable twice; viewers get the
source / the example input; every receipt readable by everyone; any manager erases anyone's run; results stored in clear; credentials allowed in a new
version / in retained source; running without the Workflow being shared; every tool offered whether declared or not; live runs allowed write tools; GitHub and
Stripe signatures not compared, Stripe timestamp tolerance ignored; library shows the source / search text carries it; a viewer may change a view; save ignores
the expected revision; retire keeps dashboard cards; share lowers an existing grant; legacy views editable; catalog lists unshared apps; retained source not
scoped to its person; script output keeping `undefined`; runner time limit ignored (that test hangs until stopped).
On SQLite the lock around "one receipt, one version" cannot be seen failing (writers are serialized); it matters on MySQL, where the test passes with it.
