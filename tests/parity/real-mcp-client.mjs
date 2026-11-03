// A REAL MCP client library (the official TypeScript SDK) connecting to /mcp/agent: discovery (RFC 9728 and 8414), dynamic client registration,
// PKCE, the browser sign-in and consent (driven with Playwright), token exchange, then initialize, tools/list and tool calls. It proves the
// OAuth and MCP surface works for a spec-following client, not just for the scripted ones in ui-mcp.js.
//   W=http://localhost:5081 A=http://localhost:5080 node real-mcp-client.mjs
// On the reference (use A=http://127.0.0.1:8790, the address it advertises) the discovery and registration steps pass; its browser step goes
// through an organization-selection page first, so the sign-in step below is written for the rewrite's consent page.
// Needs the SDK from the reference checkout's node_modules (path below; override with MCP_SDK_DIR) and Playwright (global).
import http from "node:http";
import { createRequire } from "node:module";
const { chromium } = createRequire(import.meta.url)("playwright");   // Playwright is installed globally (CommonJS)
import { person, suite, call, W, A, PW } from "./lib.mjs";

const SDK = process.env.MCP_SDK_DIR ?? (await import("node:child_process")).execSync("ls -d /workspace/openwork/node_modules/.pnpm/@modelcontextprotocol+sdk@*/node_modules/@modelcontextprotocol/sdk/dist/esm").toString().trim().split("\n")[0];
const { Client } = await import(`${SDK}/client/index.js`);
const { StreamableHTTPClientTransport } = await import(`${SDK}/client/streamableHttp.js`);
const { UnauthorizedError } = await import(`${SDK}/client/auth.js`);

const s = suite("real-mcp-client");
const user = await person("Real Client");
await call(A, "/v1/org", { method: "POST", bearer: user.token, body: { name: "Real Client Workspace" } });

// Where the agent's browser is sent back to.
let resolveCode; const codePromise = new Promise((r) => (resolveCode = r));
const callback = http.createServer((req, res) => { const u = new URL(req.url, "http://127.0.0.1"); if (u.searchParams.get("code")) resolveCode({ code: u.searchParams.get("code"), state: u.searchParams.get("state") }); res.end("ok"); });
await new Promise((r) => callback.listen(0, "127.0.0.1", r));
const redirectUrl = `http://127.0.0.1:${callback.address().port}/callback`;

// The state the SDK keeps between its steps, in memory.
const store = { tokens: undefined, client: undefined, verifier: undefined, discovery: undefined, authUrl: undefined };
const authProvider = {
  get redirectUrl() { return redirectUrl; },
  get clientMetadata() { return { client_name: "Real SDK Client", redirect_uris: [redirectUrl], grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none", scope: "mcp:read mcp:write offline_access" }; },
  state: () => "sdk-state-123",
  clientInformation: () => store.client, saveClientInformation: (c) => { store.client = c; },
  tokens: () => store.tokens, saveTokens: (t) => { store.tokens = t; },
  saveCodeVerifier: (v) => { store.verifier = v; }, codeVerifier: () => store.verifier,
  saveDiscoveryState: (d) => { store.discovery = d; }, discoveryState: () => store.discovery,
  invalidateCredentials: (scope) => { if (scope === "all" || scope === "tokens") store.tokens = undefined; },
  redirectToAuthorization: (url) => { store.authUrl = url; },
};

const mcpUrl = new URL(`${A}/mcp/agent`);
let transport = new StreamableHTTPClientTransport(mcpUrl, { authProvider });
let client = new Client({ name: "real-sdk-client", version: "1.0.0" }, { capabilities: {} });

await s.t("an unauthenticated connect makes the SDK discover the server and start the authorization flow", async () => {
  try { await client.connect(transport); return "connected without signing in"; }
  catch (e) { if (!(e instanceof UnauthorizedError)) return `unexpected error: ${e?.message}`; }
  const u = store.authUrl;
  return (!!u && u.pathname.endsWith("/oauth2/authorize") && u.searchParams.get("code_challenge_method") === "S256" && u.searchParams.get("state") === "sdk-state-123"
    && u.searchParams.get("redirect_uri") === redirectUrl && !!store.client?.client_id && u.searchParams.get("resource")?.includes("/mcp/agent")) || `auth url: ${u}`;
});
await s.t("it registered itself dynamically as a public client", async () => !!store.client?.client_id && !store.client?.client_secret);

const browser = await chromium.launch();
const ctx = await browser.newContext(); const page = await ctx.newPage();
await s.t("the person signs in and approves on the consent page, and the browser returns to the client", async () => {
  await page.goto(store.authUrl.toString(), { waitUntil: "networkidle", timeout: 120000 });
  await page.locator('input[type="email"]').fill(user.email); await page.getByRole("button", { name: /^next$/i }).click();
  await page.locator('input[type="password"]').waitFor({ timeout: 30000 }); await page.locator('input[type="password"]').fill(PW);
  await page.getByRole("button", { name: /^sign in$/i }).click();
  await page.waitForURL(/\/mcp\/consent\?/, { timeout: 60000 });
  await page.getByRole("button", { name: "Allow", exact: true }).click();
  const hit = await Promise.race([codePromise, new Promise((r) => setTimeout(() => r(null), 30000))]);
  if (!hit) return "no callback";
  store.hit = hit;
  return hit.state === "sdk-state-123" || `state ${hit.state}`;
});
await s.t("the SDK completes the token exchange (PKCE) and stores tokens", async () => {
  await transport.finishAuth(store.hit.code);
  return (!!store.tokens?.access_token && !!store.tokens?.refresh_token && store.tokens?.token_type?.toLowerCase() === "bearer") || JSON.stringify(Object.keys(store.tokens ?? {}));
});

transport = new StreamableHTTPClientTransport(mcpUrl, { authProvider });
client = new Client({ name: "real-sdk-client", version: "1.0.0" }, { capabilities: {} });
await s.t("a fresh connection with the tokens initializes and reports the server", async () => {
  await client.connect(transport);
  const info = client.getServerVersion();
  return (info?.name === "openwork-agent" && !!client.getServerCapabilities()?.tools) || JSON.stringify(info);
});
await s.t("tools/list shows search_capabilities and execute_capability with input schemas", async () => {
  const { tools } = await client.listTools(); const names = tools.map((t) => t.name).sort().join();
  return ((names === "execute_capability,search_capabilities" || names === "execute_capability,execute_capability_script,search_capabilities") && tools.every((t) => t.inputSchema?.type === "object")) || names;
});
await s.t("search_capabilities finds capabilities and execute_capability runs one", async () => {
  const found = await client.callTool({ name: "search_capabilities", arguments: { query: "who" } });
  const list = found.structuredContent?.capabilities ?? JSON.parse(found.content[0].text).capabilities;
  if (!list.some((c) => c.id === "openwork.whoami")) return `capabilities: ${JSON.stringify(list).slice(0, 200)}`;
  const ran = await client.callTool({ name: "execute_capability", arguments: { capability_id: "openwork.whoami" } });
  const who = ran.structuredContent ?? JSON.parse(ran.content[0].text);
  return (ran.isError !== true && who.user?.email === user.email && who.organization?.name === "Real Client Workspace") || JSON.stringify(who).slice(0, 200);
});
await s.t("an unknown capability is a tool error the client can read, not a protocol failure", async () => {
  const r = await client.callTool({ name: "execute_capability", arguments: { capability_id: "no.such.thing" } });
  return r.isError === true || JSON.stringify(r).slice(0, 160);
});
await s.t("after the access token is discarded the SDK refreshes it with the refresh token and keeps working", async () => {
  const before = store.tokens.access_token; const refreshBefore = store.tokens.refresh_token;
  // Make the stored access token unusable; the SDK must hit 401, refresh, and retry.
  store.tokens = { ...store.tokens, access_token: "ow_mcp_at_not-a-real-token" };
  const t2 = new StreamableHTTPClientTransport(mcpUrl, { authProvider }); const c2 = new Client({ name: "real-sdk-client", version: "1.0.0" }, { capabilities: {} });
  await c2.connect(t2); const { tools } = await c2.listTools();
  await c2.close();
  return (tools.length === 2 && store.tokens.access_token !== before && store.tokens.access_token !== "ow_mcp_at_not-a-real-token" && !!store.tokens.refresh_token && store.tokens.refresh_token !== refreshBefore)
    || `tokens changed? access ${store.tokens.access_token?.slice(0, 12)} refresh rotated ${store.tokens.refresh_token !== refreshBefore}`;
});
await client.close().catch(() => {});
await browser.close(); callback.close();
s.done();
