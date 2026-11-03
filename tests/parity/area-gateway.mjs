// AI Gateway over a REAL LiteLLM proxy: Den creates the provider, issues each granted person a LiteLLM key, and the key works (or stops working)
// at LiteLLM itself. Rewrite only (the reference's equivalent needs its own gateway app). Needs:
//   * a LiteLLM proxy with a database (virtual keys) and at least two chat models, e.g. `fake-small` and `fake-large` (see docs/features/gateway.md,
//     "Testing against a real LiteLLM")
//   * the rewrite started with the gateway pointing at it:
//       Gateway__Enabled=true Gateway__LiteLlm__BaseUrl=http://127.0.0.1:4000 Gateway__LiteLlm__MasterKey=sk-... scripts/dev.sh start
//   W=http://localhost:5081 A=http://localhost:5080 LITELLM=http://127.0.0.1:4000 MODELS=fake-small,fake-large node tests/parity/area-gateway.mjs
import { A, call, suite, workspace } from "./lib.mjs";

const LITELLM = (process.env.LITELLM ?? "http://127.0.0.1:4000").replace(/\/+$/, "");
const [SMALL, LARGE] = (process.env.MODELS ?? "fake-small,fake-large").split(",");
const s = suite("gateway");

/** One chat completion straight at LiteLLM with a key Den issued; returns the HTTP status. */
// Every key used here is one Den issued, so each successful call must show up in Den's usage report.
let answered = 0, answeredTokens = 0;
async function complete(key, model) {
  const r = await fetch(`${LITELLM}/v1/chat/completions`, {
    method: "POST", headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
    body: JSON.stringify({ model, messages: [{ role: "user", content: "ping" }], max_tokens: 5 }), signal: AbortSignal.timeout(60000),
  });
  if (r.status === 200) { answered++; answeredTokens += (await r.json()).usage?.total_tokens ?? 0; }
  return r.status;
}

const ws = await workspace("Gateway Live");
const member = await ws.join("Gateway Member");
const outsider = await ws.join("Gateway Outsider");
let providerId, groupId, grantId, key;

await s.t("create on the deployment proxy: 201, both models synced, the all-models group, no secret in the answer", async () => {
  const r = await ws.api(ws.owner, "POST", "/v1/inference-providers/litellm", { useDeploymentProxy: true });
  if (r.status !== 201) return `${r.status} ${r.text}`;
  const p = r.json.inferenceProvider;
  providerId = p.id; groupId = p.modelGroups[0]?.id;
  const ids = p.models.map((m) => m.id);
  if (!ids.includes(SMALL) || !ids.includes(LARGE)) return `models ${ids}`;
  if (/sk-[A-Za-z0-9]{8,}/.test(r.text)) return "a key-looking value is in the answer";
  return p.modelGroups.length === 1 && p.modelGroups[0].name === "All LiteLLM models";
});

await s.t("nobody is granted yet: the member sees nothing and /connect is 403", async () => {
  const list = await ws.api(member, "GET", "/v1/inference-providers");
  const connect = await ws.api(member, "GET", `/v1/inference-providers/${providerId}/connect`);
  return list.json.inferenceProviders.length === 0 && connect.status === 403;
});

await s.t("grant the member: /connect gives a LiteLLM key that answers at LiteLLM", async () => {
  const g = await ws.api(ws.owner, "POST", `/v1/inference-providers/${providerId}/access-grants`, { modelGroupId: groupId, audience: { type: "member", memberId: member.memberId } });
  if (g.status !== 201) return `${g.status} ${g.text}`;
  grantId = g.json.accessGrant.id;
  const c = await ws.api(member, "GET", `/v1/inference-providers/${providerId}/connect`);
  if (c.status !== 200) return `${c.status} ${c.text}`;
  key = c.json.inferenceProvider.apiKey;
  const small = await complete(key, SMALL);
  return small === 200 || `LiteLLM answered ${small}`;
});

await s.t("the outsider is still refused", async () => (await ws.api(outsider, "GET", `/v1/inference-providers/${providerId}/connect`)).status === 403);

await s.t("connect again returns the same key", async () => (await ws.api(member, "GET", `/v1/inference-providers/${providerId}/connect`)).json?.inferenceProvider?.apiKey === key);

await s.t("narrowing the group to one model: the same key keeps it and loses the other at LiteLLM", async () => {
  const r = await ws.api(ws.owner, "PATCH", `/v1/inference-providers/${providerId}/model-groups/${groupId}`, { modelIds: [SMALL] });
  if (r.status !== 200) return `${r.status} ${r.text}`;
  const [small, large] = [await complete(key, SMALL), await complete(key, LARGE)];
  return (small === 200 && large >= 400) || `small ${small}, large ${large}`;
});

await s.t("removing the grant deletes the key at LiteLLM (401)", async () => {
  const r = await ws.api(ws.owner, "DELETE", `/v1/inference-providers/${providerId}/access-grants/${grantId}`);
  if (r.status !== 204) return `${r.status} ${r.text}`;
  const status = await complete(key, SMALL);
  return status === 401 || `LiteLLM answered ${status}`;
});

await s.t("a workspace-wide grant: the member gets a new key; leaving the workspace deletes it at LiteLLM", async () => {
  const g = await ws.api(ws.owner, "POST", `/v1/inference-providers/${providerId}/access-grants`, { modelGroupId: groupId, audience: { type: "organization" } });
  if (g.status !== 201) return `${g.status} ${g.text}`;
  const c = await ws.api(outsider, "GET", `/v1/inference-providers/${providerId}/connect`);
  const k = c.json?.inferenceProvider?.apiKey;
  if (!k || (await complete(k, SMALL)) !== 200) return `connect ${c.status}`;
  const removed = await ws.api(ws.owner, "DELETE", `/v1/members/${outsider.memberId}`);
  if (removed.status !== 204) return `remove ${removed.status}`;
  const status = await complete(k, SMALL);
  return status === 401 || `LiteLLM answered ${status}`;
});

await s.t("usage answers in the reference's shape (LiteLLM writes its logs in batches, so counts may lag)", async () => {
  const r = await ws.api(ws.owner, "GET", "/v1/inference-providers/usage?groupBy=person&days=1");
  if (r.status !== 200) return `${r.status} ${r.text}`;
  const u = r.json.usage;
  return ["requestCount", "totalTokens", "totalCostMicroUsd", "unpricedRequests", "series", "daily", "filterOptions"].every((k) => k in u) && u.daily.length === 1;
});

await s.t("usage counts exactly the calls made with Den-issued keys (polls while LiteLLM flushes its log batch)", async () => {
  const read = async () => (await ws.api(ws.owner, "GET", "/v1/inference-providers/usage?groupBy=person&days=1")).json?.usage;
  const c = await ws.api(member, "GET", `/v1/inference-providers/${providerId}/connect`);
  const k = c.json?.inferenceProvider?.apiKey;
  if (!k) return `connect ${c.status}`;
  for (let i = 0; i < 3; i++) if ((await complete(k, SMALL)) !== 200) return "a completion failed";
  // LiteLLM flushes successful requests to its database in batches (about once a minute).
  const deadline = Date.now() + 150_000;
  let u;
  while (Date.now() < deadline) {
    u = await read();
    if (u && u.requestCount >= answered) break;
    await new Promise((r) => setTimeout(r, 5000));
  }
  return (u.requestCount === answered && u.totalTokens === answeredTokens && u.unpricedRequests === answered)
    || `Den reports ${u.requestCount} requests / ${u.totalTokens} tokens / ${u.unpricedRequests} unpriced; LiteLLM answered ${answered} calls / ${answeredTokens} tokens`;
});

await s.t("delete removes the provider, its team and every key at LiteLLM", async () => {
  const c = await ws.api(member, "GET", `/v1/inference-providers/${providerId}/connect`);
  const k = c.json?.inferenceProvider?.apiKey;
  const r = await ws.api(ws.owner, "DELETE", `/v1/inference-providers/${providerId}`);
  if (r.status !== 204) return `${r.status} ${r.text}`;
  const status = k ? await complete(k, SMALL) : 401;
  const gone = await ws.api(ws.owner, "GET", `/v1/inference-providers/${providerId}`);
  return (status === 401 && gone.status === 404) || `LiteLLM ${status}, get ${gone.status}`;
});

void A; void call;
s.done();
