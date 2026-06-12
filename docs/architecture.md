# Architecture

See [doctrine.md](doctrine.md) §3 for the high-level diagram. This document covers
the runtime components, their boundaries, and how they coordinate.

## Layers

1. **Browser SPA** — React + Shadcn, built to static files and served by Nginx
   behind Cloudflare. Stateless: it renders what the API returns.
2. **Rust controller service** — the single service. Auth + 2FA + RBAC, the
   authenticated `/api/` REST API, telemetry ingestion, detection, reroute
   execution, state machine, email alerts, audit. Binds to localhost only.
3. **Providers & data sources** — flow collectors (NetFlow/sFlow/IPFIX), BGP feed
   (ExaBGP/GoBGP/RTBH/FlowSpec), Cloudflare API, scrubbing center.

## Coordination

- **MariaDB** is the system of record. The controller is its only client and
  owns the schema via sqlx migrations.
- **Nginx reverse proxy**: the SPA calls `/api/` with credentialed `fetch`
  (session cookie); Nginx proxies `location /api/` to the controller at
  `http://127.0.0.1:9277`. That proxy is the only path to the API.
- **State publication**: the controller persists current asset status, current
  metrics, rule states, and action states, and serves them back through the
  API for the SPA to render. The browser never reaches routers/providers
  directly.

```text
POST   /api/auth/login          (password; returns TOTP challenge)
POST   /api/auth/totp           (complete 2FA; issues session)
POST   /api/auth/logout
POST   /api/auth/reauth         (fresh password+TOTP before high-safety reroutes)
GET    /api/health              (unauthenticated liveness)
GET    /api/status
CRUD   /api/assets
CRUD   /api/providers
CRUD   /api/rules
POST   /api/assets/{id}/test/telemetry
POST   /api/assets/{id}/rediscover
GET    /api/assets/{id}/live
GET    /api/reroutes
POST   /api/reroutes/manual
POST   /api/reroutes/{id}/cancel
POST   /api/reroutes/{id}/acknowledge-uncertain
GET    /api/alerts
GET    /api/audit
POST   /api/locks/global
DELETE /api/locks/global
GET    /api/settings
PUT    /api/settings
```

The controller binds to `127.0.0.1:9277` only and is never exposed directly —
public access is exclusively through the Nginx `/api/` reverse proxy behind
Cloudflare. Every endpoint except `/api/health` requires an authenticated
session; permissions are enforced per-endpoint via RBAC middleware.

## Why one service

- The controller already needs a long-lived async runtime, raw sockets for
  flow/BGP, and precise state-machine control. Auth, RBAC, and mail fit in the
  same tokio/axum process — there is no separate web tier to coordinate with,
  no second deployment, and no cross-tier failure mode.
- The database remains the system of record, and with a single writer there is
  exactly one source of operational truth and one schema owner (sqlx
  migrations).
- The SPA is stateless static files: it can be rebuilt and redeployed
  independently, and a frontend failure can never affect reroute safety.
- Restart behavior stays simple: one service to recover, one documented
  startup sequence (see [state-recovery.md](state-recovery.md)).

## Controller internal modules

```text
auth/        sessions, Argon2id passwords, TOTP 2FA, recovery codes, RBAC,
             login throttling/lockout
alerts/      async alert dispatcher: recipients, de-dup, rate limits, SMTP
             (lettre), delivery records
telemetry/   ingest + normalize flow/BGP/Cloudflare into per-asset metrics
detection/   stateful rule evaluation, consecutive-sample + duration logic
reroute/     action templates, two-phase state machine, executor, rollback
providers/   cloudflare / bgp_rtbh / flowspec / scrubber adapters (verify-capable)
api/         loopback-bound axum REST API consumed by the SPA via Nginx
db/          sqlx access layer + migrations
scheduler.rs per-asset async tasks with jitter
```

## Polling / ingestion design

Do not build one giant loop. Use per-asset async tasks plus shared collectors:

```text
flow collector (shared) -> normalize -> per-asset metric updates
bgp feed (shared)       -> per-asset/prefix routing state
asset task
  -> reachability / provider health check
  -> metric normalization
  -> detection rule evaluation
  -> reroute scheduling
```

Recommended intervals: metrics rollup 10–30s; reachability/provider health
15–30s; Cloudflare analytics poll 30–60s; capability rediscovery manual or daily.
Use jitter to avoid synchronized polling across many assets.
