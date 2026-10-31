# Connections: external MCP servers and apps, and agents using them

Code: `src/WorkAI360.Api/Features/Connections/` (routes, MCP client, OAuth, SSRF guard, secrets, capability provider, presets), entities in
`Domain/Connections/ConnectionEntities.cs`, pages in `src/WorkAI360.Web/Components/Pages/` (`Connections`, `ConnectionNew`, `ConnectionDetail`,
`YourConnections`, `ConnectMcp`) with `Components/ConnectionsPageBase.cs`, `Components/Shared/ConnectionStyles.razor`, `wwwroot/connections.css`.
Tests: `tests/WorkAI360.Api.Tests/ConnectionTests.cs` (76, with a real fake MCP server and OAuth provider in `FakeMcpServer.cs`),
`tests/parity/area-connections.mjs` (79; runs on the reference and the rewrite, with `tests/parity/fake-mcp.mjs`), `tests/parity/ui-connections.js` (24, browser).

## What it is

A **connection** is an MCP server a workspace has added ("Add any MCP"), by address. It signs in one of three ways: nothing (`none`), an API key
(`apikey`) or OAuth (`oauth`). Its credential is **shared** (one account for everyone) or **per member** (each person signs in or enters their own key).
**Access grants** say who may use it: everyone, one person, or a team. A **tool policy** switches tools off. Agents reach the tools of connections
they may use through `search_capabilities` and `execute_capability` on `/mcp/agent`.

## Who can do what

* Listing every connection, reading one, its tool policy, tools by hand: `connections.view`. Adding any kind of connection, changing access,
  saving a tool policy, running a tool by hand, `check`, `resolve`, connecting a shared OAuth account, entering a shared key: `connections.manage`.
  Editing someone else's: `connections.update`; removing: `connections.delete`; signing everyone out: `connections.disconnect`. Edit, remove and
  disconnect also need a recent sign-in (`403 {error: "reauth"}` otherwise). Giving everyone access needs `sharing.share_org_wide`, even for a manager.
* A plain member may add a connection for themselves only if each person signs in on their own (OAuth per member) or it needs no sign-in, never an
  API key, request headers or an OAuth app, and never for everyone unless they hold `sharing.share_org_wide`. They always keep access to what they
  add and may change who else uses it and remove it.
* **Being an admin grants no use.** A connection nobody granted you is not in your usable list, and its tools are not found or run by you (by hand or
  through an agent), whatever your role. Admins with `connections.view` may still list the tools to inspect them.
* Another workspace's connection, person or team is `404` (`connection_not_found`, `member_not_found`, `team_not_found`), never `403`.

## Routes built

`GET /v1/mcp-connections?scope=usable|manageable`, `POST` (create), `GET`/`PUT`/`DELETE /v1/mcp-connections/{id}`, `PUT …/{id}/access`,
`GET`/`PUT …/{id}/tool-policy`, `GET …/{id}/tools`, `GET …/{id}/mcp-apps`, `POST …/{id}/tools/call`, `POST …/{id}/check`, `POST …/readiness-checks`,
`POST …/{id}/disconnect`, `POST …/{id}/disconnect-my-account`, `POST …/{id}/removal-request`, `PUT …/{id}/my-credential`, `PUT …/{id}/shared-credential`,
`POST …/{id}/credential-prompt`, `PUT`/`DELETE /v1/mcp-connections/by-key/{externalKey}`, `GET …/{id}/connect/start`, `GET /v1/mcp-connections/oauth/callback`,
`GET …/{id}/connect/callback`, `GET /oauth/client-metadata.json`, `POST …/discover`, `POST …/discover/stream` (server-sent events), `POST …/resolve`,
`GET …/presets` (the catalog: the 11 core presets; the 16 extra reviewed ones show with `Connections:ExpandedPresets=true`, the reference's `expandedMcpPresets`).
Wire shapes, status codes, error codes and messages follow the reference (the parity script is the check). Pages: `/dashboard/mcp-connections` (list),
`/new` (catalog, check the server, add), `/{id}` (sign-in, tools and policy, sharing, settings, remove; `?remove=1` opens the confirmation),
`/dashboard/your-connections` (sign in, personal key, disconnect), `/connect/mcp` (the sign-in link an agent hands out).

## Agents

`mcp:<connectionId>:<toolName>` is the capability id (the reference's). Search lists the tools of connections granted to the caller, minus tools the
policy switched off; a per-member connection the person has not signed in to appears once as `mcp:<id>:*` ("needs connection") instead of its tools.
Running a tool needs the **`mcp:write`** scope (a server's own hints cannot prove a tool only reads), a grant, a tool the policy allows, and a usable
credential (the caller's own for per-member). Grant and policy are **checked again at execution**, whatever was seen when searching, and refusals are
`forbidden`, `policy_blocked`, `needs_connection`, `unknown_capability`, `insufficient_scope`, `connection_failed`, `provider_error`,
`invalid_capability_arguments`. The server's own tool result is returned unchanged. `execute_capability` accepts `name` and `body` (the reference's names);
the older `capability_id`/`arguments` still work.

## The MCP client and OAuth

`McpClient` speaks Streamable HTTP: `initialize` (JSON or event-stream replies, session id, negotiated protocol version), `notifications/initialized`,
`tools/list` (all pages), `tools/call`. OAuth for a protected server: protected-resource metadata (RFC 9728, from the 401 challenge or well-known), then
authorization-server metadata (RFC 8414 / OpenID), dynamic client registration (RFC 7591) unless the admin entered a client, PKCE S256, `resource`
(RFC 8707), single-use `state`, response `iss` check (RFC 9207), code exchange, refresh. Tokens are refreshed shortly before they expire and once more
on a `401`; refreshes of one credential run one at a time, so a refresh token that rotates is not spent twice. A refresh the provider rejects signs the
person out (`needsReconnect`).

## Security

* **SSRF**: outbound calls to addresses people type in go through `GuardedHttp`. By default only `https` to public addresses: loopback, private
  (10/8, 172.16/12, 192.168/16), link-local (169.254/16, fe80::/10), shared (100.64/10), unique-local, multicast, reserved, IPv4-mapped and
  NAT64/6to4 forms of these are refused. The address is checked when the socket connects (to the address that was checked, so a name that
  changes its answer cannot reach an internal host), redirects are never followed, proxies are not used, there is a 10 s connect timeout, a 60 s
  limit on a whole exchange (`Connections:ToolTimeoutSeconds`) and a 5 MB limit on any reply (`Connections:MaxResponseBytes`); tool arguments are
  limited to 1 MB. `Connections:AllowPrivateUrls=true` lifts the address and `https` rules for local development and tests only.
  OAuth endpoints a server advertises are checked the same way (a `javascript:` authorization endpoint is refused).
* **Secrets** (API keys, request-header values, OAuth tokens and client secrets, the PKCE verifier) are AES-GCM encrypted at rest (key derived from
  `Auth:Secret`, fresh nonce per value), never returned by any route, and never put in messages (a rejected key is not echoed). Only header names are listed.
* Request headers: the reference's rules (at most 4, reserved names and `authorization` for OpenWork-managed sign-in refused).
* Edits use the version the person opened (`expectedUpdatedAt`, plus a concurrency token), so two edits at once cannot both win.

## Differences from the reference

* **Not built**: Google Workspace, Microsoft 365 and Gmail integrations and every `native_provider` connection (create answers a 400 saying so),
  `GET /v1/oauth-providers/*` (native providers, API checks), GitHub **connector instances** (`/v1/connector-instances/*`), the per-connection MCP
  server (`exposeDirectly` is stored and returned but there is no `/mcp/connections/{id}`), plugin MCP requirement bindings (`requiredBy` is always
  empty and `marketplace_managed` never happens), OAuth issuer review (`…/oauth/issuer-review`), Client ID Metadata Document registration with
  outside servers (only dynamic registration and admin-entered clients; `/oauth/client-metadata.json` is served), the Slack assistant routes, Workbot hand-off,
  readiness fingerprints (a check is reset when settings change instead), MCP App rendering in the host (the `mcp-apps` list is built).
* Agent search keeps this server's existing shape (`capabilities[]` with `id`, `description`, `requiredScope`, `inputSchema`) rather than the
  reference's `matches[]` with scores and `schemaDigest`; there is no advisory schema guidance on arguments.
* A person, team or workspace id in access that does not belong to the workspace is `404` (the reference accepts it silently, and answers `500` for a
  malformed one; here it is `400`).
* Without protected-resource metadata a server is treated as having no OAuth (as the reference), so there is no fallback to the server's own origin.
* The shared-OAuth `connect/start` answers `{status: "connected"}` when already signed in (as the reference); disconnect first to sign in again.
* Diagnostics are simplified: `diagnostic` carries `referenceId`, `phase`, `category`, `code`, `retryable`, `actionOwner`, `operatorAction`,
  `message` (and `httpStatus`, `jsonRpcCode`, `providerErrorMessage` when relevant) but not the outbound path hash or provider excerpt; the manual tool run's
  inspection is rebuilt from what was sent and returned rather than captured from the wire.
* The OAuth `state` is a random value looked up in the database (single use, 10 minutes) instead of the reference's signed token.
* `by-key` replace ignores `If-Match` (the body's version is the current one).

## Running the checks

```bash
dotnet test --filter "FullyQualifiedName~Connection"
# Reference (web :3005, api :8790; allows loopback in dev mode) and rewrite (started with Connections__AllowPrivateUrls=true):
node tests/parity/area-connections.mjs
W=http://localhost:5230 A=http://localhost:5130 node tests/parity/area-connections.mjs
W=http://localhost:5230 A=http://localhost:5130 node tests/parity/ui-connections.js /tmp/shots
```
