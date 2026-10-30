# Building an area of the .NET rewrite

The rewrite (`360workai/`) copies the **wire contract** of the reference Den (`ee/apps/den-api`, `ee/apps/den-web`): routes, JSON shapes,
status codes, error messages. An "area" is one slice of that contract (for example API keys, or SSO). Areas are built to be added without
editing shared files, so several can be built at the same time and merged without conflicts.

## The loop for one area

1. **Read the reference.** Find its routes in `ee/apps/den-api/src/routes/**` (and helpers they call), the schemas, and the permission key each
   route needs (`orgPermissionRoute("...")`, `requireOrgPermission("...")`). Read the matching den-web pages (`ee/apps/den-web/app/**`) to see
   which routes the UI really uses: build those first.
2. **Probe the live reference** (it runs at web `:3005`, API `:8790`; see "Running things"). Send real requests and copy exact status codes, JSON
   keys, error codes and messages. Do not guess.
3. **Build the API** as an `IFeature` (below), reusing `OrgAccess`, `PermissionService`, `TeamRules`, `Responses`, `Ids`.
4. **Write the parity script** `tests/parity/area-<name>.mjs` with `lib.mjs`. Run it against the reference first (it must pass there: that proves
   the test encodes real behavior), then against the rewrite.
5. **Write xUnit tests** (`tests/WorkAI360.Api.Tests/<Area>Tests.cs`, reuse `Workspace`, `Person`, `TeamHelpers`): validation, permission denials,
   cross-workspace isolation (another workspace's ids are 404), concurrency where it matters, anything security-relevant.
6. **Mutation-check** the security rules (remove one rule at a time, compile-safe, confirm a test fails; after restoring a file, `touch` it so
   MSBuild rebuilds).
7. **Build the pages** as Blazor components under `src/WorkAI360.Web/Components/Pages/` and add a browser test `tests/parity/ui-<name>.js`
   with `ui-lib.js`. Check the page in a screenshot.
8. **Write `docs/features/<name>.md`**: routes implemented, differences from the reference (and why), what is not built.
9. Commit on your branch. Do not push. Do not edit `README.md` (the integrator merges the docs files into it).

## Where things go (so areas never collide)

| What | Where |
|---|---|
| Routes and services | `src/WorkAI360.Api/Features/<Area>/` , a class implementing `IFeature` (`AddServices`, `MapEndpoints`). Found automatically. |
| Entities | `src/WorkAI360.Api/Domain/<Area>/` : plain classes, plus an `IEntityTypeConfiguration<T>` in the same file (indexes, collation, filters). Use `db.Set<T>()`. Found automatically; the dev schema creates the tables. Only **nullable** columns can be added to an existing table, so add new tables instead of changing old ones. |
| MCP capabilities (what agents can do) | implement `ICapabilityProvider` (`OAuth/Capabilities.cs`), register it in your feature's `AddServices`. |
| Dashboard buttons | a class implementing `IDashboardLinkSource` (`Components/DashboardLinks.cs`). |
| Pages | `src/WorkAI360.Web/Components/Pages/<Page>.razor`; shared behavior in `Components/ActionPage.cs`, `Components/Shared/ReauthForm.razor`. Styles: component CSS (`Page.razor.css`), not `app.css`. |
| Tests | `tests/WorkAI360.Api.Tests/<Area>Tests.cs`, `tests/parity/area-<name>.mjs`, `tests/parity/ui-<name>.js` |

Shared files you may need to touch (keep the edit minimal and additive; say so in your report): `Auth/OrgAccess.cs`, `Auth/SessionService.cs`
(if you add a credential type), `Endpoints/OrgPayload.cs` (if `GET /v1/org` must show something new), the Web `Proxy/DenProxyExtensions.cs`
(only if a path is not already covered by `/api/browser/v1/{**}` and `/api/auth/{**}`).

## Conventions

* Permission checks: `access.Require(context, "<key>")` answers the reference's 403 (and the re-sign-in prompt for sensitive keys). Resolve the
  workspace with `access.ResolveAsync(ctx)`; ids from other workspaces must read as 404, never 403.
* Ids are TypeID style: `Ids.New("prefix")`; validate path ids with `MemberEndpoints.ValidateTypeId(value, "prefix", "field")`; request-body
  errors use `MemberEndpoints.InvalidRequest(field, message, code)` (the reference's zod format `"field: message"`).
* Secrets (tokens, keys, client secrets) are stored hashed or encrypted, never in plain text, and never logged or returned after creation unless
  the reference does.
* Anything user-visible is behind the reference's behavior, so no new feature flags are needed in the rewrite itself.
* No customer, prospect, partner or outside-person names anywhere (branch names, commits, fixtures, comments). This repository is public.
* Work only inside `360workai/` (and read access to the rest of the repository).
* `TreatWarningsAsErrors` is on: unused parameters and unreachable code break the build.

## Running things

```bash
cd 360workai
dotnet build                                   # fast check
dotnet test --filter "FullyQualifiedName~<Area>"   # your tests
```

Your own copy of the rewrite on ports of your choice (so areas built at the same time do not clash). Pick a port pair no one else uses,
e.g. 5100+N and 5200+N, a private database file, and a private run folder:

```bash
export WORKAI360_API_URL=http://localhost:5100 WORKAI360_WEB_URL=http://localhost:5200 WORKAI360_RUN_DIR=/tmp/workai-<area>-run
# a private database: set the connection string for the API
export ConnectionStrings__Default="Data Source=/tmp/workai-<area>.db"
rm -f /tmp/workai-<area>.db*; scripts/dev.sh start        # builds and starts api + web
W=$WORKAI360_WEB_URL A=$WORKAI360_API_URL node tests/parity/area-<name>.mjs
W=$WORKAI360_WEB_URL A=$WORKAI360_API_URL node tests/parity/ui-<name>.js /tmp/shots
scripts/dev.sh stop
```

The reference is shared and read-mostly (tests create their own workspaces): `node tests/parity/area-<name>.mjs` with no env targets it. If it is
down, `docs/AREA_GUIDE.md` cannot help you start it: say so in your report and carry on from the source code.

Sandbox gotchas: there is no `ss`/`lsof`; never use `pkill -f` or `ps | grep | xargs kill` patterns that can match your own shell (use PID files,
as `dev.sh` does); foreground `sleep` is blocked (poll with an `until` loop); Playwright is installed globally (`require('playwright')`, do not
reinstall it or override `NODE_PATH`); the rewrite runs in the `Development` environment (dev email outbox at `GET /dev/outbox`).
