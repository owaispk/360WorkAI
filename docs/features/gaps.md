# Gaps closed inside existing areas

Four gaps the library, connections and member areas left open, built after those areas. Code: `src/WorkAI360.Api/Features/PluginConnections/`,
`Features/OAuthProviders/`, entities in `Domain/PluginConnections/` and `Domain/OAuthProviders/`, small edits to `Features/Connections/`,
`Features/Library/`, `Endpoints/InvitationEndpoints.cs`, `Endpoints/TeamEndpoints.cs` and `Domain/Entities.cs`. Pages: the connection panel
`Components/Shared/PluginConnectionsPanel.razor` (on the plugin page) and a team choice on the Members page.
Tests: `tests/WorkAI360.Api.Tests/PluginConnectionTests.cs` (12), `OAuthProviderTests.cs` (4), `TeamInviteTests.cs` (7);
`tests/parity/area-gaps.mjs` (53, sections 1 to 3; runs on the reference and the rewrite); `tests/parity/ui-gaps.js` (11, browser).

## 1. Plugins that need MCP connections

A plugin's MCP object declares remote servers (`mcpServers` / `mcp`). A **binding** (`PluginMcpBinding`) says which connection serves one
declared server of one plugin. Routes (the reference's shapes, probed on it):

* `POST /v1/plugins/{id}/mcp-connections` with `{configObjectId, serverName, authType, credentialMode, apiKey, oauthClient}`: sets up the
  connection for one declared server (or reuses one with the same address, sign-in type and mode, and the same key or OAuth app), checks it
  (a wrong key is `400 credential_rejected` and nothing is kept; an unreachable server `502 connection_validation_failed`), records the binding
  and answers `{ok, item: {binding, connection, links}}`. An API-key server set up without its key waits for it and the answer also carries the
  private `credentialPrompt` (`target.type: plugin_connection_key`) and `nextStep`. The desktop app calls this to save a key typed in chat.
  Errors as the reference: `mcp_requirement_not_found`, `mcp_server_not_found`, `mcp_server_not_remote`, `mcp_auth_type_mismatch` (409),
  `invalid_mcp_auth`, `invalid_mcp_url`, `mcp_requirement_not_synced`, and `secure_entry_required` when a key arrives through an API key.
* `components[].connection` (set up inline) and `components[].connectionId` (use an existing connection) on `POST /v1/plugins`. Inline setup needs
  `connections.manage`; `connectionId` needs the person to have made that connection or hold `connections.manage`. If setup fails the plugin is
  archived and what the attempt made is removed (as the reference does, so the name is free to retry).
* `GET /v1/plugins/{id}/mcp-connections` (**not in the reference**, additive): the plugin's declared servers with the connection each has for the
  caller. The plugin panel uses it.
* `cloudReadiness` on each plugin in `GET /v1/marketplaces/{id}/resolved`: `ready`, `needs_signin`, `needs_admin_setup`, `desktop_only`,
  `not_synced`, with one entry per declared server (`id: null` when none serves it). Matching is the reference's: the binding, else the
  connections the caller may use at the same address; optional servers do not hold a plugin with other pieces back.
* On connections: `requiredBy`, `identityManagedBy`, `requiredAuthType`, `authTypeMismatch`, `oauthClientRequired`, `setupRequired`,
  `authPolicyConfirmed` are now real (they were constants). A connection a plugin needs refuses a changed address / sign-in / key
  (`409 marketplace_managed`, also on `PUT …/shared-credential`) but may be renamed and reshared. A connection a plugin made for itself is
  **retired** (left out of the lists, kept in the database) while every plugin bound to it is archived; deleting a connection removes its bindings.

**Who may use a connection through a plugin** is not stored: it is worked out when asked, from who the plugin is shared with (a grant on the MCP
object, on the plugin, or on an active marketplace that holds it; a person, one of their teams or everyone). Sharing, unsharing, archiving,
taking the object out of the plugin or the plugin off the shelf changes it at once. The connection's own access list (`access`) is unchanged,
so the two never fight. Being an admin adds nothing.

**What a person may learn** (the point of the area): `requiredBy` names only plugins the reader may view (the reference names every plugin in the
admin list; the rewrite filters everywhere); a refusal to edit a managed connection names only the plugins the person may see ("A marketplace
plugin owns …" otherwise); `cloudReadiness` never names a bound connection the person may neither use nor list (`connections.view`), the entry
reads as not set up; configuring a plugin needs `connections.manage` **and** the right to view the plugin (`403` otherwise, nothing created).

Differences from the reference: that viewer check on configuring (the reference only needs `connections.manage`); plugin names are filtered in
the admin list; there is no preset/expanded-preset logic beyond the 27 presets already known; marketplace-declared connections
(`/v1/marketplaces/by-key`, `.mcp.json` imports with `mapsTo`) and the GitHub importer do not create bindings (the importer still lists MCP servers
as "not imported"); `connectionBackedMcpPayload` is built for `connectionId` components but a later edit of the connection's address does not
rewrite old plugin text.

## 2. OAuth apps for providers (`/v1/oauth-providers/*`)

A workspace brings its own OAuth app for Google Workspace or Microsoft 365. Built: `POST …/{providerId}/client` (`oauth_clients.manage`,
re-sign-in), `GET …/{providerId}/client` (`oauth_clients.view` and a sign-in within 24 hours), `GET …/{providerId}/api-check` (Google only),
`GET …/{providerId}/status`, `POST …/{providerId}/disconnect`. The secret is AES-GCM encrypted with the connections `SecretBox`, write-only
(a save without a secret keeps the old one), never returned or echoed. Features are checked against the provider's list (de-duplicated, in
order); Microsoft needs a tenant (GUID or verified domain, lowercased; `common`, `organizations`, `consumers` refused). The saved app is
one row per workspace and provider (`OrgOAuthClient`, unique index); two first saves at once queue behind the workspace row.

**Not built**: `connect/start` and `connect/callback` (the browser sign-in with Google or Microsoft: nothing signs in yet, so `status` is always
`connected: false`, `disconnect` is `404 "Nothing was connected."` and `api-check` lists the APIs as unchecked, exactly the reference's answers
for a person with no sign-in), native-provider connections (`kind: native_provider`), revoking accounts when the client id changes (there are none),
Google API probing. A provider given as a connection id (not a provider key) is `404`.

## 3. Inviting into a team

`POST /v1/invitations` takes `teamId` (string, or `null` to clear; omitted keeps a resent invitation's team). Choosing a team needs
`teams.manage`, a team of this workspace that is not run by SCIM (`400 "Choose a team in this organization …"`), `teams.manage_admin` for an admin
team, and every permission the team grants. The pending person shows in the team at once (their pending member id is in the team's `memberIds`,
as the reference does) and **accepting keeps that id**: the new member is created with the pending id, so the team membership carries over.
Canceling takes them out; resending with another team moves them; deleting a team clears it from pending invitations (they still work, without
a team); editing a team's people accepts a pending person's id. The Members page has a Team select (when the person holds `teams.manage`) and shows
"joins Writers" / "in Writers". `Invitation.TeamId` is a new nullable column.

One difference from before the change: an accepted member's id is now the pending id (it used to be a new one); the reference does this too.

## Not built (and why)

* `GET`/`POST /v1/email/unsubscribe` (the reference's opt-out from lifecycle reminder emails, an HMAC of the address checked and then recorded in its
  `lifecycle_email` ledger). This build sends no lifecycle reminders, so there is nothing to opt out of and no link that would carry a token, and no
  existing table can hold the opt-out without a schema change. It should be built together with the reminders.
* Part 4 small routes (memory, artifact views, direct uploads, MCP apps, webhooks) and part 5 workflows were built afterwards as their own area:
  see [workspace.md](workspace.md). Still not built: `routes/dev` (the development email outbox answers at `GET /dev/outbox` here instead).
* `connect/start`, `connect/callback` for OAuth providers (above).
* Bindings from GitHub imports and declarative marketplace definitions; `If-Match` on connection edits stays unbuilt as before.

## Running the checks

```bash
dotnet test --filter "FullyQualifiedName~PluginConnection|FullyQualifiedName~OAuthProvider|FullyQualifiedName~TeamInvite"
node tests/parity/area-gaps.mjs                                                  # reference (ONLY=1,2,3 for sections)
W=http://localhost:5284 A=http://localhost:5184 node tests/parity/area-gaps.mjs  # rewrite, started with Connections__AllowPrivateUrls=true
W=http://localhost:5284 A=http://localhost:5184 node tests/parity/ui-gaps.js /tmp/shots
```

When last run: whole xUnit suite 764 passed; `area-gaps.mjs` 53/53 on the reference and 53/53 on the rewrite; `ui-gaps.js` 11/11; the existing
`area-connections.mjs` (79), `area-library.mjs` (56), `area-org-admin.mjs` (45) and `area-onboarding.mjs` (26) still pass on the rewrite. MySQL was not run.

## Checks

Access rules are mutation-checked (a change that removes the rule makes at least one test fail):
connections: use ignoring plugin grants, `requiredBy` naming every plugin, readiness naming an unusable connection, configure without the
plugin-visibility check, retired connections not hidden, managed edits allowed, revoked grants still applying, archived marketplace still
opening, archived plugin still opening, object taken out of the plugin still opening, `CanUse` ignoring bindings (11 of 11 killed).
Team invites: no `teams.manage`, other workspaces' teams accepted, no grant check, team delete keeping the invitation's team, cancel keeping the
membership, accept making a new id, resend not moving the person, editing a team refusing pending people (8 of 9; the ninth removes the admin-team
check, which the grant check still covers). OAuth: no manage check, no view check, secret stored plain, no 24 hour window, empty save wiping the
secret (5 of 6; the lock around first saves cannot be seen on SQLite, where writes are serialized anyway: it matters on MySQL).
