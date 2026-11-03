# Model providers ("bring your own keys")

Reference: `ee/apps/den-api/src/routes/org/{llm-providers,llm-provider-access}.ts`, `src/llm/{provider-credentials,models-dev,custom-provider,endpoint-probe,llm-provider-config-redaction}.ts`,
`packages/types/src/managed-provider-config.ts`, the tables in `ee/packages/den-db/src/schema/sharables/llm-providers.ts`, and den-web's
`app/(den)/dashboard/(admin)/custom-llm-providers/**`. Code: `src/WorkAI360.Api/Features/LlmProviders/`, entities in `Domain/LlmProviders/`, pages
`Components/Pages/{LlmProviders,LlmProviderEdit,LlmProviderDetail}.razor`. Tests: `tests/WorkAI360.Api.Tests/LlmProviderTests.cs` (13),
`tests/parity/ui-llm-providers.js` (17, browser; it starts its own fake OpenAI-compatible endpoint, see its header).

A workspace saves model providers with its own keys and decides who may use them; people's desktops fetch what they need through `/connect` and call
the provider directly. The AI Gateway (`/v1/inference-providers`, LiteLLM) is a separate area.

## Routes built

| Route | Notes |
|---|---|
| `GET /v1/llm-provider-catalog`, `GET /v1/llm-provider-catalog/{providerId}` | The models.dev catalog: summaries (`id, name, npm, env, doc, api, modelCount`), and one provider with its config and models. `502 provider_catalog_unavailable` only when the catalog cannot be read and the fallback is off (below) |
| `GET /v1/llm-providers?scope=usable\|manageable` | Usable (default): providers granted to the caller (directly, a team, or everyone), with `hasMyCredential`. Manageable: every provider for holders of View all providers, else the caller's own. Each item has `configRedacted`, `hasApiKey`, `configuredEnvKeys`, `runtimeEnvKeys`, `models`, `access` (`allMembers`, `membersHidden`, `members`, `teams`), `accessibleVia`, `canManage`. Never the credential |
| `GET /v1/llm-providers/{id}`, `GET /v1/llm-providers/by-key/{externalKey}` | View all providers. Same shape, one item |
| `POST /v1/llm-providers` | Any member: `{name, source: models_dev\|custom, providerId + modelIds \| customConfigText \| customConfig, credentialMode: shared\|per_member, apiKey \| apiKeys, memberIds, teamIds, allMembers}`. The creator always keeps direct access. `201 {llmProvider}` |
| `PATCH /v1/llm-providers/{id}` | Replaces config, models and access; an omitted key keeps the stored one; `apiKeys` merges per env name (an empty value clears it). Changing `credentialMode` drops everyone's own keys |
| `PUT /v1/llm-providers/by-key/{externalKey}` | Edit any provider. Create (201) or replace (200); a blank `apiKey` is refused (`invalid_api_keys`), `If-Match` is `400 unsupported_precondition`; two first writes of one key end as one provider |
| `DELETE /v1/llm-providers/{id}` (204), `DELETE /v1/llm-providers/by-key/{externalKey}` (`{ok, deleted}`, idempotent) | Removes models, access and people's keys too |
| `DELETE /v1/llm-providers/{id}/access/{accessId}` | 204; the creator's own row is `409 protected_access` |
| `GET /v1/llm-providers/{id}/connect` | For granted callers only (`403 "You do not have access to this provider."`): the configuration under runtime env names, the credential (`apiKey` for one env name, `apiKeys` for several) and full model configs. Per-member providers add `memberCredential.state` and deliver only the caller's own active key. `Cache-Control: no-store` |
| `PUT`/`DELETE /v1/llm-providers/{id}/my-credential` | A granted person's own key on a per-member provider (`{state, version, updatedAt}`); `400 not_per_member`; a blocked key is `409 credential_blocked` for both |
| `GET /v1/llm-providers/{id}/member-credentials`, `PUT .../member-credentials/{memberId}`, `POST .../{memberId}/block` | Manage people's provider keys: states and external ids for every granted member (no secrets); set a key (`expectedVersion` → `409 version_conflict`; this is also how a block is lifted); block (`404 member_credential_not_found` when there is no key) |
| `POST /v1/llm-providers/test-connection` | `{api, apiKey?, modelIds?}`: normalizes the base URL (strips `/chat/completions`, `/responses`, …; Azure host twins and `/openai/v1`), calls `GET /models` with both `Authorization: Bearer` and `api-key`, and returns the ids served (Azure: the deployments). With `modelIds` (≤ 8) it sends one tiny completion per model to find the request shape (`ok`, or `adjusted` to `@ai-sdk/openai` when the model wants `max_completion_tokens`). Nothing is stored |

## Who may do what

* **Anyone may add a provider**, and its creator may always edit and delete it. Anyone else needs Edit any provider / Delete any provider (both
  sensitive: a sign-in within the privileged window). Workspace admins and owners need the recent sign-in even for their own provider, as in the reference.
* **What a list or read shows**: the stored configuration to people who can edit the provider or are granted it; to everyone else (View all providers
  only) `configRedacted: true` with only the provider's `id`, `name`, `npm` and the models' `id`, `name` and numeric `limit`, no env names and `hasApiKey`
  false. People's names and emails in `access` only to those who can edit it (`membersHidden`).
* **Keys never arrive through an organization API key or an agent** (`400 secure_entry_required`), on every route that takes one.
* Keys are AES-GCM encrypted (the connections `SecretBox`), never returned by a list or read, never written to the audit log.

## Credentials and env names

Stored as in the reference: one env name, the bare value; several, a JSON map. Catalog providers leave Den under names scoped to the row
(`LPR_<last 5 of the id>_OPENAI_API_KEY`), so a workspace provider cannot shadow a person's own `OPENAI_API_KEY` and two rows of one vendor do not share a
slot; for providers with several env names (Bedrock, Azure) each SDK option is bound to its runtime name (`{"region": "{env:LPR_…_AWS_REGION}"}`), never to
the value. Custom providers keep the names their author declared. A Bedrock key needs a valid `AWS_REGION`; `apiKeys` names outside the provider's env list
are refused.

## The catalog

`LlmProviders__CatalogUrl` (default the reference's mirror, `https://models.openworklabs.com/api.json`), cached `LlmProviders__CatalogCacheMinutes` (10),
one refresh at a time. `LlmProviders__CatalogFile` reads a file in the same format instead. An empty URL uses the bundled snapshot
(`Features/LlmProviders/models-catalog-snapshot.json`: OpenAI, Anthropic, Google, Mistral, Groq, DeepSeek, xAI, Azure and 25 Bedrock models, taken from
the same catalog), which is also the fallback when the URL cannot be read (`LlmProviders__CatalogFallbackToSnapshot`, default on; logged). Tests always
use the snapshot.

## Differences from the reference

* **Endpoint probes go through the connections outbound guard**: private and internal addresses are refused unless `Connections__AllowPrivateUrls=true`,
  and plain `http` is refused unless private addresses are allowed. The reference allows private ranges for self-hosted installs and blocks only metadata
  and link-local addresses.
* **No OpenWork-hosted (`source: openwork`) providers**, no managed-models policy, no `migrate-from-llm-provider`, and no Bedrock Mantle / Microsoft
  Foundry catalog entries (those belong to the AI Gateway). The `gateway_only_provider` refusal is kept for them.
* Validation reports the first problem rather than every one (zod lists all; the first message is the same).
* Members are deleted rather than soft-removed, so a removed person's grants and keys go with their membership row's id (they stop matching anyone).

## Activation checklist

"Set up a model provider" is now done by a provider the person added ("OpenAI added"), or any provider in the workspace ("Models from your
organization"), besides the client's report and the desktop policy (see [onboarding.md](onboarding.md)).

## Checks

Mutations of the access and secret rules (16 of 17 killed): workspace scoping of lookups, team grants counted as everyone, connect without the grant
check, no redaction, identities and the `membersHidden` flag shown to all, anyone may edit, admin creators skipping the recent sign-in, permission holders
skipping it, blocked keys still delivered, a member overwriting or deleting a block, the creator's access removable, the credential list without
permission, another workspace's provider found, keys accepted from API keys. The survivor drops the workspace filter from the grant query, which is
redundant: every provider is looked up within the workspace first.

## Not built

The AI Gateway (`/v1/inference-providers*`, usage, limits), hosted OpenWork models, `migrate-from-llm-provider`, models analytics.
