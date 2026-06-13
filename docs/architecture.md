# Architecture

See [doctrine.md](doctrine.md) §3 for the high-level diagram. This document covers
the runtime components, their boundaries, and how they coordinate.

## Layers

1. **Browser SPA** — React + Shadcn, built to static files and served by Nginx
   behind Cloudflare. Stateless: it renders what the API returns.
2. **Rust controller service** — the single service. Auth + 2FA + RBAC, the
   authenticated `/api/` REST API, telemetry ingestion, detection, reroute
   execution, state machine, email alerts, audit. Binds to localhost only.
3. **Data sources & actuators** — SNMP interface polling of enrolled devices
   (the v1 telemetry source) and the device-CLI executor that drives reroutes
   over SSH to Cisco IOS. The flow-collector / BGP-feed / Cloudflare-API /
   scrubber providers were de-scoped: there is no `providers/` layer in v1.

## Coordination

- **MariaDB** is the system of record. The controller is its only client and
  owns the schema via sqlx migrations.
- **Nginx reverse proxy**: the SPA calls `/api/` with credentialed `fetch`
  (session cookie); Nginx proxies `location /api/` to the controller at
  `http://127.0.0.1:9277`. That proxy is the only path to the API.
- **State publication**: the controller persists current device/interface
  status, current metrics, rule states, and action states, and serves them back
  through the API for the SPA to render. The browser never reaches routers
  directly.

```text
POST   /api/auth/login          (password; returns TOTP challenge)
POST   /api/auth/totp           (complete 2FA; issues session)
POST   /api/auth/logout
GET    /api/auth/me
GET    /api/health              (unauthenticated liveness)
GET    /api/status
CRUD   /api/devices
POST   /api/devices/{id}/test           (SNMP reachability/identity probe)
POST   /api/devices/{id}/discover       (walk interface tables)
POST   /api/devices/{id}/ssh-test
POST   /api/devices/{id}/ssh-generate-key   (in-app RSA keypair for enrollment)
POST   /api/devices/{id}/ssh-capabilities   (SSH command-access probe)
POST   /api/devices/{id}/discover-bgp
GET    /api/devices/{id}/bgp-peers
GET    /api/devices/{id}/bgp-networks
POST   /api/devices/{id}/discover-prefixes
GET    /api/devices/{id}/interfaces
GET    /api/interfaces/{id}[/metrics]
CRUD   /api/rules               (+ /api/rules/{id}/actions for multi-router actions)
GET    /api/templates[/{id}[/render]]
GET    /api/rtbh-communities    (+ POST/DELETE; global RTBH community catalog)
GET    /api/reroutes
POST   /api/reroutes/manual
POST   /api/reroutes/{id}/cancel
POST   /api/reroutes/{id}/acknowledge-uncertain
POST   /api/reroutes/{id}/rollback
GET    /api/alerts
GET    /api/audit
GET    /api/locks
POST   /api/locks/global
DELETE /api/locks/global
GET    /api/settings
PUT    /api/settings
CRUD   /api/users
```

The controller binds to `127.0.0.1:9277` only and is never exposed directly —
public access is exclusively through the Nginx `/api/` reverse proxy behind
Cloudflare. Every endpoint except `/api/health` requires an authenticated
session; permissions are enforced per-endpoint via RBAC middleware.

## Why one service

- The controller already needs a long-lived async runtime, outbound SNMP/SSH to
  the devices, and precise state-machine control. Auth, RBAC, and mail fit in the
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
telemetry/   SNMP interface polling -> normalized per-interface metrics (v1
             source; snmp.rs). netflow/sflow/bgp/cloudflare are future stubs.
ssh/         device-CLI executor: fail-closed command allowlist, host-key
             pinning, in-app RSA key generation, BGP peer/prefix discovery
detection/   stateful rule evaluation, consecutive-sample + duration logic
reroute/     action templates, two-phase state machine, executor, rollback
api/         loopback-bound axum REST API consumed by the SPA via Nginx
db/          sqlx access layer + migrations
scheduler.rs per-device async tasks with jitter
```

There is no `providers/` layer: the only actuator is the `device_cli` executor
in `ssh/`, the only `provider_type` that runs.

## Polling / ingestion design

Do not build one giant loop. Use per-device async tasks:

```text
device task (one per enabled device)
  -> SNMP poll of monitored interfaces (HC counters)
  -> rate derivation / metric normalization
  -> detection rule evaluation
  -> reroute scheduling (device-CLI over SSH)
```

Recommended intervals: SNMP poll at the device's `poll_interval_seconds`
(default 30); interface discovery / BGP rediscovery manual or daily. Use jitter
to avoid synchronized polling across many devices.
