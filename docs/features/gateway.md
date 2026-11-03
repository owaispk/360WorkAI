# AI Gateway over LiteLLM

Reference: `ee/apps/den-api/src/routes/org/{inference-providers,gateway-usage}.ts`, `src/llm/{litellm,litellm-sync,litellm-issued}.ts`,
`src/gateway-deployment.ts`, the `gateway_*` tables in `ee/packages/den-db/src/schema/inference-providers.ts`, and den-web's
`dashboard/_components/ai-gateway-screen.tsx`. Code: `src/WorkAI360.Api/Features/Gateway/`, entities in `Domain/Gateway/`, page
`Components/Pages/AiGateway.razor` (`/dashboard/ai-gateway`). Tests: `tests/WorkAI360.Api.Tests/GatewayTests.cs` (12, against an in-process fake
LiteLLM, `FakeLiteLlm.cs`), `tests/parity/area-gateway.mjs` (10, against a **real** LiteLLM), `tests/parity/ui-gateway.js` (8, browser, real LiteLLM).

## How it works

In the reference, people's desktops call OpenWork's own gateway app (`ee/apps/gateway`) with an OpenWork key, and that app forwards to upstream
providers, one of which can be a LiteLLM proxy. This build has no gateway app: **LiteLLM is the data plane**. Den is the control plane, as the
reference's LiteLLM provider in "issued" mode:

| Den | LiteLLM |
|---|---|
| A Gateway provider (`GatewayProvider`, `providerId: "litellm"`) | A proxy (the deployment's own, or a workspace's) plus one **team** per provider (`openwork-<providerId>`), whose model list is the synced models |
| Synced models (`GatewayProviderModel`) | `/v1/models` + `/model_group/info` (chat models only; wildcard routes and embedding/image/audio models left out; costs converted to USD per 1M tokens) |
| Model groups and access grants (workspace, team, member) | Nothing: Den decides who may call which model |
| A person's effective models on a provider | The models on **their own virtual key** (`/key/generate` with `user_id` = their member id, the provider's team, `allowed_routes: ["llm_api_routes"]` so the key can never manage LiteLLM, no budget or rate limit) |
| `GET /v1/inference-providers/{id}/connect` | Returns that key, issued on first use (encrypted at rest; LiteLLM's token hash kept to update, delete and attribute usage) and LiteLLM's `/v1` base URL |
| A change of grants, groups, provider status or membership | The key's models are updated in place (`/key/update`), or the key is deleted (`/key/delete`) when the person may call nothing. Immediately, not at the next sync |
| Usage | LiteLLM's request logs (`/spend/logs/v2`, filtered to the provider's team), attributed through the issued keys' token hashes |

## Routes built

| Route | Notes |
|---|---|
| `POST /v1/inference-providers/litellm` | `{name?, useDeploymentProxy: true}` (the operator's proxy; no URL or key) or `{name?, baseUrl, apiKey}` (the workspace's proxy and an admin key; write-only), plus `allMembers`, `memberIds`, `teamIds` and `mode` (only `"issued"`; `org` and `member` answer `400 litellm_mode_unsupported`). Proves the key manages the proxy (`409 litellm_not_admin` otherwise), reads its models (`400 litellm_no_models` when none), creates the team, the "All LiteLLM models" group and the grants. `201 {inferenceProvider, sync}` |
| `GET /v1/inference-providers?scope=usable\|manageable` | Usable (default): active providers with at least one model the caller may call, showing only those models, never a key. Manageable: every provider with groups, grants, LiteLLM status (people's names only to Manage holders) |
| `GET /v1/inference-providers/{id}`, `/models`, `/model-groups`, `/access-grants`, `GET /v1/inference-providers/model-management` | Reads for View Gateway providers |
| `GET /v1/inference-providers/{id}/connect` | The caller's own key (`apiKey`, `apiKeys.LITELLM_API_KEY`), `baseUrl`, and their models. `403 forbidden` without a grant; never to an organization API key; `Cache-Control: no-store` |
| `PATCH /v1/inference-providers/{id}` | `{name?, status: active\|disabled}`. Disabling deletes every key in LiteLLM; enabling lets them be issued again on next use |
| `DELETE /v1/inference-providers/{id}` | Deletes every key and the team in LiteLLM **first**; when LiteLLM cannot confirm, `409 litellm_*` and nothing is removed, so no key outlives its provider |
| `POST /v1/inference-providers/{id}/litellm/sync` | Re-reads the models: new ones join the all-models group, gone ones leave every group, the team follows, every key is brought in line. A failed read keeps the last catalog and records `lastSyncError` |
| `PATCH /v1/inference-providers/{id}/litellm` | `{apiKey}`: a new admin key for a workspace proxy, proven against the same proxy before it replaces the old one, then a sync. `409 litellm_deployment_proxy` for the operator's proxy |
| `POST`/`PATCH`/`DELETE .../model-groups[/{groupId}]` | `{name, description?, modelIds, status?}` (strict); only synced model ids (`400 model_not_found`) |
| `POST .../access-grants`, `DELETE .../access-grants/{grantId}` | `{modelGroupId, audience: {type: organization} \| {type: team, teamId} \| {type: member, memberId}}`; ids from another workspace are 404; a duplicate is `409 access_grant_exists`. The reference changes grants with `PATCH`; here a grant is removed and added |
| `GET /v1/inference-providers/usage?groupBy=model\|person\|team&days=1..366&filterIds=&memberId=` | The reference's usage shape (`requestCount`, `totalTokens`, `totalCostMicroUsd`, `unpricedRequests` = priced at zero by LiteLLM, `unreportedRequests` = no token count, `uncountableRequests.rejected` = failed requests, `series`, `daily` with `values`/`costValues`, `filterOptions`). "model" groups by provider, as the reference. A person may read their own (`memberId` = theirs); anything else needs View Gateway usage. `503 gateway_usage_unavailable` when LiteLLM cannot be read |

All management routes need Gateway management on (`Gateway__Enabled`, else `403 gateway_not_enabled` as the reference) and View / Manage Gateway providers
(Manage is sensitive: a recent sign-in). Keys never arrive through an organization API key (`400 secure_entry_required`).

**Elsewhere**: `GET /v1/admin/dashboard` (platform admin) now reports 30 days of usage across every workspace's providers (a proxy that cannot be read is
left out); the activation checklist's "Share a provider on AI Gateway" step is done once the workspace has an active provider ("LiteLLM on AI Gateway"
for people who may see providers); `GET /v1/org` reports `capabilities.gatewayDashboard` when the gateway is on; removing someone from a workspace
deletes their keys (`CredentialRevocation` calls every `IMemberAccessEnded`).

## Configuration

| Setting | Meaning |
|---|---|
| `Gateway__Enabled` | Gateway management for this deployment (default off) |
| `Gateway__LiteLlm__BaseUrl`, `Gateway__LiteLlm__MasterKey` | The deployment's own LiteLLM proxy and its master (or proxy admin) key. Trusted: called directly, usually on a private network (`http://litellm:4000` in compose). Without them, workspaces bring their own proxy |
| `Gateway__LiteLlm__PublicUrl` | The address desktops use to reach that proxy, when it differs from `BaseUrl` |
| `Gateway__LiteLlm__TimeoutSeconds` | Per call to LiteLLM (default 10). No call follows a redirect; no error echoes a key |

A workspace's own proxy goes through the connections outbound guard: HTTPS and a public address, unless `Connections__AllowPrivateUrls=true`.
`deploy/docker-compose.yml` runs LiteLLM with its own Postgres and points the API at it (`LITELLM_MASTER_KEY`, `LITELLM_PUBLIC_URL`).

## Differences from the reference

* **No OpenWork gateway app**, so no OpenWork gateway keys (`gateway_keys`), no gateway-side pricing, accounting or usage limits; LiteLLM serves the
  requests and its numbers are the usage. Hence also: no non-LiteLLM gateway providers (OpenAI, Anthropic, Bedrock, Vertex, Foundry directly: add them as
  models in LiteLLM instead), no credential sets, no cloud OAuth sign-ins (AWS IAM Identity Center, Google, Microsoft), no `test-connection`.
* **Only the "issued" LiteLLM mode.** `org` mode would hand one shared organization key to every desktop (in the reference the gateway app keeps it
  server-side); `member` mode (people paste their own LiteLLM key) and the `mirror` issue strategy are not built.
* **Usage limits** (`/v1/gateway/usage-limit-policies*`, `/v1/gateway/usage-limits/*`) are not built: the reference enforces day/week/month cost limits
  in its gateway app, and LiteLLM's one budget per key cannot express several windows faithfully.
* Not built either: `/v1/inference/*` (the free hosted tier), the Auto Router (cloud only), provider inventory events, `enable-models`/`available-models`
  (the catalog is whatever the proxy serves), `migrate-from-llm-provider`, pinned models, the provider audit trail.
* **LiteLLM writes request logs in batches**, so usage lags a little; and a key deleted within a batch interval of its last calls may lose those calls'
  logs. Live, Den's usage matches what LiteLLM answered exactly (requests, tokens, unpriced) once the batch is written.

## Testing against a real LiteLLM

The live scripts need a LiteLLM proxy with a database (virtual keys need one) and two chat models. What was used here: `pip install
'litellm[proxy,extra_proxy]' 'prisma==0.11.0'` (LiteLLM 1.106 expects Prisma Client Python 0.11, as its own image pins; with 0.15 the proxy starts but
silently stops writing request logs), `prisma generate` against LiteLLM's `schema.prisma`, Postgres 16, a fake OpenAI-compatible upstream serving `fake-small`
and `fake-large`, and `litellm --config config.yaml --port 4000` with `DATABASE_URL`, `STORE_MODEL_IN_DB=True` and a `master_key`. Then start the rewrite
with `Gateway__Enabled=true Gateway__LiteLlm__BaseUrl=http://127.0.0.1:4000 Gateway__LiteLlm__MasterKey=…` and run `area-gateway.mjs` and `ui-gateway.js`.
The fake upstream must give every response its own `id`: LiteLLM keys its request log on it and drops repeats.
Results: 11/11 and 8/8: keys Den issued answered at LiteLLM, lost a model when their group was narrowed, and were refused (401) at LiteLLM after the
grant was removed, the person left, or the provider was deleted; and Den's usage report counted exactly the calls LiteLLM answered with those keys
(requests and tokens, all unpriced since the fake models have no price).

## Checks

Mutations of the access, secret and attribution rules (14 of 14 killed): grants ignoring the audience, a disabled provider still granting, lost access
keeping the key, narrowed access keeping old models, leaving keeping keys, delete ignoring a LiteLLM failure, a provider found across workspaces, a grant
to another workspace's member, connect without a grant, reading anyone's usage, another key's usage attributed (with a proxy that ignores the team
filter), a workspace URL skipping the outbound guard, the provider name shown to everyone in the checklist, an API key carrying a LiteLLM key.
