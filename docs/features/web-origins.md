# Approved web origins in use (CORS and web handoff)

Org settings let an owner approve exact HTTPS origins (`/v1/org/web-origins`, built in the org-admin area). This area makes the list *do* something,
as the reference does.

## What it does

* **CORS for browsers on other origins.** A request carrying an `Origin` header gets CORS headers (`Access-Control-Allow-Origin` set to that
  origin, `Allow-Credentials: true`, `Vary: Origin`, exposed headers) only when the origin is this deployment's own web or API origin, one of
  `Cors:Origins` (operator list), or an origin any workspace approved. Other origins are still served, but without CORS headers, so a browser
  will not let their page read the answer. Preflights (`OPTIONS` with `Access-Control-Request-Method`) from allowed origins answer `204` with the
  allowed methods (`GET, POST, PUT, PATCH, DELETE, OPTIONS`), the allowed headers (including `X-Api-Key` and `X-OpenWork-Org-Id`) and
  `Max-Age: 600`.
* **Open exception.** `/v1/auth/desktop-handoff/exchange` answers any origin (methods `POST, OPTIONS`): it is authenticated only by a one-time,
  five-minute grant and never reads cookies or sessions, and preview origins cannot be listed in advance.
* **Cache.** Approvals are cached per process for 30 seconds, positive and negative. Adding or removing an origin drops the entry on that
  instance at once; other instances catch up within 30 seconds. A failing lookup is a refusal (nobody gains access because the database hiccuped).
* **Web handoff return URLs.** `POST /v1/auth/desktop-handoff` accepts `returnUrl`: an `https` URL, no credentials, no fragment, no path tricks
  (`..`, encoded dots or slashes), whose path is `/` or `/signin`. It is honored when the active workspace approved that exact origin or, failing
  that, any workspace the person belongs to did (the session then becomes active in that workspace and the grant belongs to it). The answer
  carries `returnUrl` (always the origin plus `/signin`). Anything else is `400 invalid_return_url` with the reference's message.

## Differences from the reference

* The reference's extra approvals (the configured OpenWork Web gateway origin and signed sandbox preview URLs) need cloud sandboxes and are not built.
* The reference's `corsHandledByEdge` switch (CORS done by a proxy in front) has no counterpart; do not put a second CORS layer in front of this one.

## Tests

`WebOriginEnforcementTests` and `HandoffReturnUrlTests` (xUnit, both databases), `tests/parity/area-web-origins.mjs` (11/11 on the reference and
on the rewrite), and 9 mutations of the rules (7 caught; 2 survivors are redundant layers: the canonical-origin check also rejects `http` and
look-alikes).
