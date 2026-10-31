// A small fake MCP server plus fake OAuth provider, used by area-connections.mjs (and as a model for the C# fake in the xUnit tests).
// It listens on 127.0.0.1 with a random port and speaks MCP Streamable HTTP with JSON responses:
//   POST /none/mcp    no sign-in
//   POST /key/mcp     needs `Authorization: Bearer <KEY>`
//   POST /oauth/mcp   needs a bearer access token issued by this server's own OAuth provider (RFC 9728 discovery, DCR, PKCE S256)
// Everything it receives is recorded at GET /__calls so a test can prove which credential reached the server.
import { createServer } from "node:http";
import { createHash, randomBytes } from "node:crypto";

export const KEY = "fake-key-0123456789";

const TOOLS = [
  { name: "echo", description: "Echo a message back.", inputSchema: { type: "object", properties: { message: { type: "string" } }, required: ["message"] }, annotations: { readOnlyHint: true } },
  { name: "add", description: "Add two numbers.", inputSchema: { type: "object", properties: { a: { type: "number" }, b: { type: "number" } }, required: ["a", "b"] }, annotations: { readOnlyHint: true } },
  { name: "delete_everything", description: "A dangerous tool a policy should be able to switch off.", inputSchema: { type: "object", properties: {} }, annotations: { destructiveHint: true } },
];

export async function startFake() {
  const calls = [];
  const codes = new Map();      // authorization code -> { challenge, redirectUri, clientId }
  const accessTokens = new Map(); // token -> expiry ms
  const refreshTokens = new Set();
  const clients = new Map();
  let port = 0;
  let tokenCounter = 0;
  const state = { rejectRefresh: false, tokenLifetimeSeconds: 3600, slowMs: 0, bigBody: false };
  const origin = () => `http://127.0.0.1:${port}`;

  const json = (res, status, body, headers = {}) => { res.writeHead(status, { "content-type": "application/json", ...headers }); res.end(JSON.stringify(body)); };
  const readBody = (req) => new Promise((resolve) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => resolve(b)); });
  const newAccess = () => { const t = `at_${++tokenCounter}_${randomBytes(8).toString("hex")}`; accessTokens.set(t, Date.now() + state.tokenLifetimeSeconds * 1000); return t; };

  const server = createServer(async (req, res) => {
    const url = new URL(req.url, origin());
    const path = url.pathname;
    const body = await readBody(req);
    if (path === "/__calls") return json(res, 200, calls);
    if (path === "/__reset") { calls.length = 0; return json(res, 200, { ok: true }); }

    // ---- OAuth provider ----
    if (path === "/.well-known/oauth-protected-resource/oauth/mcp") return json(res, 200, { resource: `${origin()}/oauth/mcp`, authorization_servers: [origin()], scopes_supported: ["mcp"], bearer_methods_supported: ["header"] });
    if (path === "/.well-known/oauth-authorization-server" || path === "/.well-known/openid-configuration") {
      return json(res, 200, {
        issuer: origin(), authorization_endpoint: `${origin()}/authorize`, token_endpoint: `${origin()}/token`, registration_endpoint: `${origin()}/register`,
        response_types_supported: ["code"], grant_types_supported: ["authorization_code", "refresh_token"], code_challenge_methods_supported: ["S256"],
        token_endpoint_auth_methods_supported: ["none", "client_secret_post"], scopes_supported: ["mcp"],
      });
    }
    if (path === "/register" && req.method === "POST") {
      const meta = JSON.parse(body || "{}");
      const clientId = `client_${randomBytes(6).toString("hex")}`;
      clients.set(clientId, meta);
      return json(res, 201, { ...meta, client_id: clientId, client_id_issued_at: Math.floor(Date.now() / 1000), token_endpoint_auth_method: "none" });
    }
    if (path === "/authorize") {
      calls.push({ kind: "authorize", clientId: url.searchParams.get("client_id"), resource: url.searchParams.get("resource"), scope: url.searchParams.get("scope"), method: url.searchParams.get("code_challenge_method") });
      const redirect = url.searchParams.get("redirect_uri");
      if (url.searchParams.get("deny")) { res.writeHead(302, { location: `${redirect}?error=access_denied&state=${encodeURIComponent(url.searchParams.get("state") ?? "")}` }); return res.end(); }
      const code = `code_${randomBytes(8).toString("hex")}`;
      codes.set(code, { challenge: url.searchParams.get("code_challenge"), redirectUri: redirect, clientId: url.searchParams.get("client_id") });
      res.writeHead(302, { location: `${redirect}?code=${code}&state=${encodeURIComponent(url.searchParams.get("state") ?? "")}` });
      return res.end();
    }
    if (path === "/token" && req.method === "POST") {
      const form = new URLSearchParams(body);
      calls.push({ kind: "token", grant: form.get("grant_type"), hasVerifier: Boolean(form.get("code_verifier")) });
      if (form.get("grant_type") === "authorization_code") {
        const issued = codes.get(form.get("code"));
        codes.delete(form.get("code"));
        if (!issued) return json(res, 400, { error: "invalid_grant" });
        const verifier = form.get("code_verifier") ?? "";
        const challenge = createHash("sha256").update(verifier).digest("base64url");
        if (challenge !== issued.challenge) return json(res, 400, { error: "invalid_grant", error_description: "pkce mismatch" });
        const refresh = `rt_${randomBytes(8).toString("hex")}`; refreshTokens.add(refresh);
        return json(res, 200, { access_token: newAccess(), token_type: "Bearer", expires_in: state.tokenLifetimeSeconds, refresh_token: refresh, scope: "mcp" });
      }
      if (form.get("grant_type") === "refresh_token") {
        if (state.rejectRefresh || !refreshTokens.has(form.get("refresh_token"))) return json(res, 400, { error: "invalid_grant" });
        return json(res, 200, { access_token: newAccess(), token_type: "Bearer", expires_in: state.tokenLifetimeSeconds, refresh_token: form.get("refresh_token"), scope: "mcp" });
      }
      return json(res, 400, { error: "unsupported_grant_type" });
    }
    if (path === "/__expire") { for (const t of accessTokens.keys()) accessTokens.set(t, 0); return json(res, 200, { ok: true }); }
    if (path === "/__state") { Object.assign(state, JSON.parse(body || "{}")); return json(res, 200, state); }

    // ---- MCP ----
    const kind = path === "/none/mcp" ? "none" : path === "/key/mcp" ? "key" : path === "/oauth/mcp" ? "oauth" : null;
    if (!kind) return json(res, 404, { error: "not_found" });
    if (req.method === "GET") { res.writeHead(405, { allow: "POST" }); return res.end(); }
    if (req.method === "DELETE") { res.writeHead(200); return res.end(); }
    const auth = req.headers.authorization ?? "";
    let message;
    try { message = JSON.parse(body); } catch { return json(res, 400, { jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }); }
    const extra = Object.entries(req.headers).filter(([k]) => k.startsWith("x-test-")).map(([k, v]) => `${k}=${v}`).join(",");
    calls.push({ kind: "mcp", server: kind, method: message.method, auth, extra, tool: message.params?.name, args: message.params?.arguments });
    if (kind === "key" && auth !== `Bearer ${KEY}`) return json(res, 401, { error: "unauthorized" });
    if (kind === "oauth") {
      const token = auth.replace(/^Bearer /, "");
      const expiry = accessTokens.get(token);
      if (!expiry || expiry < Date.now()) return json(res, 401, { error: "invalid_token" }, { "www-authenticate": `Bearer resource_metadata="${origin()}/.well-known/oauth-protected-resource/oauth/mcp"` });
    }
    if (state.slowMs > 0 && message.method === "tools/call") await new Promise((r) => setTimeout(r, state.slowMs));
    if (message.id === undefined) { res.writeHead(202); return res.end(); }
    const reply = (result) => json(res, 200, { jsonrpc: "2.0", id: message.id, result }, { "mcp-session-id": "fake-session" });
    switch (message.method) {
      case "initialize": return reply({ protocolVersion: message.params?.protocolVersion ?? "2025-06-18", capabilities: { tools: { listChanged: false } }, serverInfo: { name: `fake-${kind}`, version: "1.0.0" } });
      case "ping": return reply({});
      case "tools/list": return reply({ tools: TOOLS });
      case "tools/call": {
        const name = message.params?.name; const args = message.params?.arguments ?? {};
        if (state.bigBody) return reply({ content: [{ type: "text", text: "x".repeat(6 * 1024 * 1024) }] });
        if (name === "echo") return reply({ content: [{ type: "text", text: `echo: ${args.message}` }], structuredContent: { echoed: args.message } });
        if (name === "add") return reply({ content: [{ type: "text", text: String(Number(args.a) + Number(args.b)) }] });
        if (name === "delete_everything") return reply({ content: [{ type: "text", text: "everything deleted" }] });
        return json(res, 200, { jsonrpc: "2.0", id: message.id, error: { code: -32602, message: `Unknown tool: ${name}` } });
      }
      default: return json(res, 200, { jsonrpc: "2.0", id: message.id, error: { code: -32601, message: `Method not found: ${message.method}` } });
    }
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  port = server.address().port;
  return {
    origin: origin(), port, calls, state, key: KEY,
    url: (kind) => `${origin()}/${kind}/mcp`,
    reset: () => { calls.length = 0; },
    mcpCalls: (kind, method) => calls.filter((c) => c.kind === "mcp" && (!kind || c.server === kind) && (!method || c.method === method)),
    close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }),
  };
}
