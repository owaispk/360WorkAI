# Operations: running more than one instance

The API keeps its durable state in the database (SQLite for one instance, MySQL 8 for production; see [database.md](database.md)). A few things are
state the instances must *agree on* but that does not belong in the database: rate limits, sign-in lockouts and short-lived caches. By default they live
in each process's memory, which is right for a single instance. With more than one instance, point them all at one Redis.

## Shared store (Redis)

| Setting | Meaning |
|---|---|
| `Cache__Redis__ConnectionString` | A StackExchange.Redis connection string, e.g. `redis:6379` or `redis.internal:6380,password=...,ssl=true`. Unset: in memory, per instance |
| `Cache__Redis__KeyPrefix` | Prefix of every key (default `workai360:`), so one Redis can serve several deployments |

What moves to Redis when it is set (`src/WorkAI360.Api/Auth/SharedStore.cs`):

* **Rate limits** of the email endpoints (sign-up, sign-in, codes, password reset), the OAuth token and introspection endpoints, and per-API-key limits.
  Without Redis, each instance counts on its own, so N instances allow N times the limit.
* **Sign-in lockout** (5 failures in 15 minutes per address): it now holds on every instance.
* **The approved web origin cache**: an origin approved or removed in one workspace takes effect on every instance at once (in memory, other instances
  catch up within 30 seconds).

Counters are fixed windows, each updated by one Lua script (count and expiry together, so a window never loses its expiry; "count only if under the
limit" is a single atomic step, so concurrent requests on different instances cannot go over). Keys are the prefix plus a SHA-256 of the logical key:
no email, address or client id is stored in clear. Redis needs no persistence for this (`--save ''` is fine): losing it only resets the windows.

**If Redis is unreachable** the API keeps serving: limits fail open (nobody is locked out because the cache is down) and caches miss (the database is
asked instead). A warning is logged at most once a minute. The connection is retried in the background; the API also starts while Redis is down.

What stays per instance on purpose: the JWKS cache of `private_key_jwt` clients and MCP discovery caches (they only save fetches), the request log's
write buffer (flushed every two seconds), and the Control Center's lease rows, which are in the database already.

## Other things to know with several instances

* **Database migrations** run once, from a separate step (`--migrate`), before the instances start (`Database__AutoMigrate=false`); the compose file shows it.
* **Background jobs** (housekeeping, Control Center refresh, automation scheduler, request log) run in every instance and are written to be safe that way:
  set-based deletes, lease rows, and conditional updates.
* **`Auth__Secret`** must be the same on every instance (it signs cookies, grants and nonces).
* **DPoP nonces** (`OAuth__DpopNonceRequired`) are stateless, so any instance accepts another's.

## Testing

`tests/WorkAI360.Api.Tests/SharedStoreTests.cs` runs one contract (windows, limits, concurrency, values) against the memory store, and against Redis when
`WORKAI_TEST_REDIS` is set (e.g. `WORKAI_TEST_REDIS=localhost:6379 dotnet test`), plus a test with two API instances sharing one Redis: failures counted
on both lock the address out on both. CI runs them with a Redis service.
