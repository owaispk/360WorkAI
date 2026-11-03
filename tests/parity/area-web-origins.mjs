// Contract test for approved web origins in use: CORS for approved origins and desktop-handoff web return URLs. Runs unchanged against the
// reference Den and the rewrite (see ../../docs/AREA_GUIDE.md):
//   node area-web-origins.mjs                                                  # reference: web :3005, api :8790
//   W=http://localhost:5081 A=http://localhost:5080 node area-web-origins.mjs  # rewrite
import { workspace, suite, call, A } from "./lib.mjs";

const s = suite("web-origins");
const ws = await workspace("Origins Probe");
const origin = `https://embed-${Date.now()}.example.org`;
const acao = (r) => r.headers.get("access-control-allow-origin");
const preflight = (path, from, extra = {}) => call(A, path, { method: "OPTIONS", origin: from, headers: { "access-control-request-method": "POST", "access-control-request-headers": "content-type", ...extra } });
const handoff = (returnUrl, user = ws.owner) => ws.api(user, "POST", "/v1/auth/desktop-handoff", returnUrl === undefined ? {} : { returnUrl });

await s.t("an origin nobody approved gets no CORS headers on a preflight or a request", async () => {
  const p = await preflight("/v1/org", origin); const g = await call(A, "/health", { origin });
  return (acao(p) === null && acao(g) === null) || `${acao(p)} ${acao(g)}`;
});
await s.t("approving the origin answers 201", async () => { const r = await ws.api(ws.owner, "POST", "/v1/org/web-origins", { origin }); return r.status === 201 || `${r.status} ${r.text}`; });
await s.t("an approved origin passes the preflight with credentials and the documented headers", async () => {
  const p = await preflight("/v1/org", origin, { "access-control-request-headers": "content-type,x-openwork-org-id,x-api-key" });
  const headers = (p.headers.get("access-control-allow-headers") ?? "").toLowerCase(); const methods = p.headers.get("access-control-allow-methods") ?? "";
  return (p.status === 204 && acao(p) === origin && p.headers.get("access-control-allow-credentials") === "true" && headers.includes("x-openwork-org-id") && headers.includes("x-api-key") && headers.includes("content-type")
    && ["GET", "POST", "PUT", "PATCH", "DELETE"].every((m) => methods.includes(m))) || `${p.status} ${acao(p)} ${headers} ${methods}`;
});
await s.t("an approved origin may read responses (ACAO on a real request, Vary: Origin)", async () => {
  const g = await call(A, "/health", { origin }); return (acao(g) === origin && (g.headers.get("vary") ?? "").toLowerCase().includes("origin")) || `${acao(g)} ${g.headers.get("vary")}`;
});
await s.t("look-alike origins never match (other scheme, port, host)", async () => {
  for (const other of [origin.replace("https:", "http:"), origin + ":8443", origin.replace("embed-", "x-embed-")]) {
    const g = await call(A, "/health", { origin: other }); if (acao(g) !== null) return `${other} allowed`;
  }
  return true;
});
await s.t("the desktop-handoff exchange preflight is open to any origin, other routes are not", async () => {
  const stranger = "https://preview-9999.example.net";
  const ex = await preflight("/v1/auth/desktop-handoff/exchange", stranger); const other = await preflight("/v1/auth/desktop-handoff/status", stranger);
  return (acao(ex) === stranger && acao(other) === null) || `${acao(ex)} ${acao(other)}`;
});
await s.t("a handoff with the approved origin answers with the sign-in page of that origin", async () => {
  const r = await handoff(`${origin}/signin`); const bare = await handoff(origin);
  return (r.status === 200 && r.json?.returnUrl === `${origin}/signin` && bare.json?.returnUrl === `${origin}/signin` && /^openwork:\/\/den-auth\?grant=/.test(r.json?.openworkUrl)) || `${r.status} ${r.text} / ${bare.text}`;
});
await s.t("a handoff without a return URL carries none", async () => { const r = await handoff(undefined); return (r.status === 200 && !r.json?.returnUrl) || r.text; });
await s.t("anything not approved or not shaped right is refused with the documented message", async () => {
  for (const bad of ["https://other-origin.example.org/signin", origin.replace("https:", "http:") + "/signin", `${origin}/evil`, `${origin.replace("https://", "https://u:p@")}/signin`, `${origin}/signin#x`, `${origin}/a/../signin`, "javascript:alert(1)"]) {
    const r = await handoff(bad);
    if (!(r.status === 400 && r.json?.error === "invalid_return_url" && r.json?.message === "The Cloud web handoff return URL is not approved for this organization.")) return `${bad} -> ${r.status} ${r.text.slice(0, 160)}`;
  }
  return true;
});
await s.t("another workspace's approval does not count for someone outside it", async () => {
  const other = await workspace("Origins Other"); const theirs = `https://theirs-${Date.now()}.example.org`;
  await other.api(other.owner, "POST", "/v1/org/web-origins", { origin: theirs });
  const r = await handoff(`${theirs}/signin`); return (r.status === 400 && r.json?.error === "invalid_return_url") || `${r.status} ${r.text}`;
});
await s.t("removing the approval closes both doors", async () => {
  const id = (await ws.api(ws.owner, "GET", "/v1/org/web-origins")).json.origins.find((o) => o.origin === origin)?.id;
  const del = await ws.api(ws.owner, "DELETE", `/v1/org/web-origins/${id}`);
  const h = await handoff(`${origin}/signin`);
  // The reference caches CORS answers for up to 30 s on other instances; this instance drops its entry at once.
  const g = await call(A, "/health", { origin });
  return (del.status === 204 && h.status === 400 && acao(g) === null) || `${del.status} ${h.status} ${acao(g)}`;
});
s.done();
