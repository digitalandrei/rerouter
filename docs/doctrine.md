# Rerouter — Project Doctrine

**Working name:** `Rerouter`
**Short name:** `rrt`
**Date:** 2026-06-12
**Target stack:** Rust (single controller service) + React + Shadcn SPA + MariaDB
**Target platform:** Ubuntu 24.04 server, Nginx origin behind Cloudflare
**Dev URL:** `https://rerouter.cloudcraft.ro` (behind Cloudflare)
**Primary goal:** detect DDoS / abnormal-traffic conditions on protected prefixes
and safely trigger automated or manual **reroute** actions to mitigate them.

---

## 1. Purpose

Rerouter is a small but safety-critical web application for monitoring traffic to
one or more protected network assets (prefixes / IPs / services) and executing
controlled **reroute** actions when traffic conditions cross configured
thresholds — for example during a volumetric flood, SYN flood, or amplification
attack.

The application must:

- let operators log in (with TOTP 2FA) to view live data;
- enroll protected assets (prefixes/IPs/services) and reroute providers
  (Cloudflare account, BGP upstreams, scrubbing centers);
- collect traffic telemetry (NetFlow/sFlow/IPFIX, BGP, and Cloudflare analytics);
- evaluate editable detection conditions and thresholds;
- execute approved reroute actions when conditions match;
- allow manual reroute triggering from the web GUI;
- send email alerts on detection, reroute, failure, and uncertain state;
- recover state after crash/restart;
- show asset/provider reachability and collection/action status;
- provide a drag-and-drop GUI for selecting monitored assets and assigning rules.

The project is not only a dashboard. It is an operations control-plane. Safety,
auditability, and predictable state recovery are core requirements.

---

## 2. Non-goals

The first version should not try to become a full traffic-analytics platform,
a full BGP automation suite, or a managed scrubbing service.

Out of scope for v1:

- replacing FastNetMon, Kentik, Arbor, or a commercial scrubbing provider;
- deep packet inspection or signature-based IDS;
- multi-vendor abstractions beyond clean internal interfaces;
- full route-policy generation;
- full topology discovery;
- distributed high availability;
- automatic destructive reroutes without explicit allowlists and cooldowns.

---

## 3. High-level architecture

One service, one static SPA:

```text
+-----------------------------+
| Browser SPA                 |
| React + Shadcn (static      |
| build served by Nginx)      |
+-------------+---------------+
              |
              | HTTPS via Cloudflare -> Nginx origin
              | /api/ reverse proxy -> 127.0.0.1:9277
              v
+-----------------------------+
| Rust Controller Service     |
| Auth + 2FA + RBAC, REST API,|
| telemetry, detection engine,|
| reroute execution, email    |
| alerts, audit               |
+-------------+---------------+
              |
        +-----+-----+----------------+
        |           |                |
        v           v                v
   NetFlow/     BGP (ExaBGP/      Cloudflare API /
   sFlow taps   GoBGP/RTBH)       Scrubbing center
```

Deployment model:

- The frontend is a React + Shadcn single-page app, built to static files and
  served directly by Nginx behind Cloudflare. It holds no server-side state.
- A single Rust service (`rerouter-controller`) runs as a long-lived systemd
  service and owns everything else: authentication + TOTP 2FA, RBAC, the
  authenticated REST API under `/api/`, telemetry ingestion, rule evaluation,
  the reroute state machine, reroute execution, email alerts, and audit.
- The controller binds its API to `127.0.0.1:9277` only. Public access is
  exclusively through the Nginx reverse proxy (`location /api/`), which sits
  behind Cloudflare. The controller is never exposed directly.
- The controller is the only writer of operational state; **MariaDB** is the
  system of record, and the Rust repo owns the schema via sqlx migrations.
- The SPA talks to the API with credentialed `fetch` (session cookie).

See [architecture.md](architecture.md) for component detail.

---

## 4. Repository layout

```text
rerouter/
├── README.md
├── CLAUDE.md
├── docs/
│   ├── doctrine.md
│   ├── architecture.md
│   ├── deployment.md
│   ├── security.md
│   ├── authentication.md
│   ├── database.md
│   ├── asset-enrollment.md
│   ├── telemetry-model.md
│   ├── detection-engine.md
│   ├── reroute-engine.md
│   ├── state-recovery.md
│   ├── email-alerts.md
│   └── operations-runbook.md
├── backend-rust/
│   ├── Cargo.toml
│   ├── config.example.toml
│   ├── migrations/           (sqlx SQL migrations, e.g. 20260612000100_users_and_auth.sql)
│   ├── src/
│   │   ├── main.rs
│   │   ├── config.rs
│   │   ├── install.rs        (--install: binary, .env, config.toml, systemd unit)
│   │   ├── ui.rs             (embed-ui feature: embedded SPA serving, default off)
│   │   ├── db/
│   │   ├── auth/             (sessions.rs, password.rs, totp.rs, rbac.rs)
│   │   ├── alerts/           (dispatcher.rs, mailer.rs)
│   │   ├── telemetry/        (netflow.rs, sflow.rs, bgp.rs, cloudflare.rs)
│   │   ├── detection/        (condition.rs, cooldown.rs)
│   │   ├── reroute/          (executor.rs, state_machine.rs, templates.rs, rollback.rs)
│   │   ├── providers/        (cloudflare.rs, bgp_rtbh.rs, flowspec.rs, scrubber.rs)
│   │   ├── api/              (health.rs, assets.rs, providers.rs, rules.rs,
│   │   │                      reroutes.rs, alerts.rs, audit.rs, locks.rs,
│   │   │                      settings.rs — the auth router lives in src/auth/)
│   │   └── scheduler.rs
│   └── tests/                (fixtures + integration skeletons)
├── frontend/
│   ├── package.json
│   ├── vite.config.ts
│   ├── tsconfig.json
│   ├── tailwind.config.ts
│   ├── postcss.config.js
│   ├── index.html
│   └── src/
│       ├── main.tsx
│       ├── pages/            (login, dashboard, assets, providers, rules,
│       │                      reroutes, alerts, audit, settings)
│       ├── lib/              (api client, session helpers, types)
│       └── components/ui/    (shadcn/ui components)
├── deploy/
│   ├── nginx/rerouter.conf
│   ├── cloudflare/README.md
│   ├── systemd/rerouter-controller.service
│   └── env/rerouter.example.env
├── agents/
│   ├── controller-agent.md
│   ├── frontend-agent.md
│   ├── traffic-telemetry-agent.md
│   ├── reroute-safety-agent.md
│   └── database-agent.md
└── skills/
    ├── rust-axum-sqlx.md
    ├── rust-auth-2fa.md
    ├── react-shadcn-spa.md
    ├── ddos-mitigation.md
    ├── traffic-telemetry.md
    ├── cloudflare-api.md
    └── bgp-reroute-safety.md
```

---

## 5. Runtime components

### 5.1 Rust controller binary

The operational heart of the system — and the only service. Responsibilities:

- load asset & provider inventory from DB;
- maintain telemetry ingestion (flow collectors, BGP feed, Cloudflare poll);
- normalize per-asset traffic counters and rates;
- calculate bps, pps, new-connections/s, SYN rate, unique-source counts;
- evaluate configured detection rules;
- enforce cooldowns, locks, and safety limits;
- execute approved reroutes via providers (Cloudflare/BGP/FlowSpec/scrubber);
- persist every decision and action;
- serve the authenticated REST API under `/api/` (loopback-only bind);
- run sqlx database migrations (single source of schema truth);
- send email alerts via its internal async alert dispatcher;
- recover incomplete reroutes after restart.

Suggested crates: `tokio`, `axum`, `sqlx` (mysql/mariadb), `serde`, `tracing`,
`clap`, `chrono`/`time`, `uuid`, `anyhow`/`thiserror`, `reqwest` (Cloudflare
API), `argon2` (password hashing), `totp-rs` (TOTP 2FA), `lettre` (SMTP over
rustls), plus a flow collector and a BGP speaker (ExaBGP via subprocess, or a
Rust BGP crate evaluated against the lab).

Build: `cargo build --release`. Installed path: `/srv/rerouter/rerouter-controller` (laid down by `--install`).

### 5.2 Rust API & auth layer

Part of the same binary; owns everything user-facing on the server side:

- **Authentication**: session cookies backed by a DB `sessions` table; Argon2id
  password hashing; TOTP 2FA (RFC 6238, 30s period, 6 digits, issuer
  `Rerouter`); 8 single-use hashed recovery codes; login throttling and account
  lockout keyed by email + real client IP.
- **RBAC**: explicit `roles`/`permissions`/`role_user`/`permission_role` tables,
  enforced via axum middleware/extractors. Roles: `admin`, `operator`,
  `viewer`, `auditor`.
- **REST API** under `/api/`: auth, status, asset/provider/rule CRUD, manual
  reroute triggering, alerts, audit, locks, settings. High-safety reroutes
  require fresh re-auth (`POST /api/auth/reauth`), typed confirmation, and a
  reason — enforced server-side.
- **Email alerts**: an internal async alert dispatcher task reads new `alerts`
  rows, resolves recipients/subscriptions, de-duplicates, rate-limits, sends
  via SMTP, and records deliveries (see §10).
- **Credential encryption**: provider secrets encrypted at rest with
  AES-256-GCM (key from the `SECRETS_KEY` environment variable).
- **Audit**: every authentication event, CRUD change, and reroute decision is
  written to the audit log with the real client IP.

### 5.3 React + Shadcn SPA frontend

A Vite + React 18 + TypeScript + Tailwind + shadcn/ui single-page app, built to
`frontend/dist` and served statically by Nginx. It talks to the API with
credentialed `fetch` (session cookie) and holds no live state of its own.
Clean, operational, explicit. Principles:

- never hide dangerous reroute details;
- show the operating mode prominently — a persistent banner while in `observe`
  (read-only / alert-only) mode;
- show current asset/provider reachability prominently;
- show stale telemetry clearly (live / cached / degraded / unknown);
- require confirmation for manual disruptive reroutes;
- display exactly which reroute will be performed (prefix, provider, method) —
  the SPA renders the exact reroute preview returned by the API;
- show action history near every rule and asset;
- support drag-and-drop monitored-asset configuration;
- show a clear degraded state when the API is unreachable.

Core pages: `/login` (password → TOTP challenge; first-login TOTP enrollment),
`/dashboard`, `/assets`, `/assets/:id`, `/providers`, `/rules`, `/reroutes`,
`/reroutes/manual`, `/alerts`, `/audit`, `/settings`.

---

## 6. Domain model summary

| Concept | Meaning |
| --- | --- |
| **Protected asset** | A prefix / IP / service we monitor and protect. |
| **Reroute provider** | A channel we reroute *through*: Cloudflare account, BGP upstream (RTBH/FlowSpec), or scrubbing center. |
| **Telemetry sample** | A normalized traffic measurement for an asset over an interval. |
| **Detection rule** | A stateful threshold/condition that fires when an asset's traffic matches for a duration. |
| **Reroute template** | An allowlisted, parameterized mitigation (blackhole, FlowSpec drop, Cloudflare under-attack, scrub-divert). |
| **Reroute (action)** | A single, audited execution of a template against an asset/provider, driven by a state machine. |
| **Lock / cooldown** | Safety controls that block actions when state is unsafe or recently changed. |

Detail: [asset-enrollment.md](asset-enrollment.md),
[telemetry-model.md](telemetry-model.md),
[detection-engine.md](detection-engine.md),
[reroute-engine.md](reroute-engine.md).

---

## 7. Reroute methods (simple first)

Start simple. The v1 reroute templates, in increasing blast radius:

1. **Enable Cloudflare "Under Attack" mode** for a zone (exec, easily reversible).
2. **Add a Cloudflare firewall / rate-limit rule** for an attacked path/IP.
3. **RTBH blackhole** a `/32` or `/128` — announce the host route to an upstream
   blackhole community so the edge drops it.
4. **FlowSpec drop / rate-limit** rule for a `{src,dst,proto,port}` tuple.
5. **Divert to scrubbing center** — announce the prefix to the scrubber and accept
   the cleaned return path.
6. **Withdraw / restore** a BGP announcement.

Every method is an action template (see [reroute-engine.md](reroute-engine.md))
with a parameter schema, a safety level, verification, and a rollback template.
Never expose a free-text "run this route command" box in v1.

---

## 8. Safety model (most important)

Safety is the most important part of this project. Full detail in
[reroute-engine.md](reroute-engine.md) and [state-recovery.md](state-recovery.md).

**Operating mode.** The controller has a global operating mode with two values:

- `observe` (**the shipped default**) — safe read-only / alert-only. Telemetry
  and detection run fully, but **no reroute executes — automatic or manual**.
  When a rule fires, the alert and rule event carry the rendered plan of the
  actions that *would* have run, so operators can validate thresholds and
  templates risk-free before ever letting Rerouter act.
- `enforce` — reroutes may execute, still gated by every rule below.

Only an admin can flip the mode (from `/settings`); the change is audited and
alerted. Gate 0 of every execution path checks the mode.

Global safety rules — the app must enforce (in `enforce` mode):

- no automatic reroute unless explicitly enabled (global **and** per-rule);
- no automatic reroute without an action template;
- no automatic reroute if telemetry is stale;
- no automatic reroute if the provider/asset reachability is degraded;
- no automatic reroute if detection confidence is low;
- no action if another action is already running on the same asset;
- no repeated action inside a cooldown window;
- no action under a global maintenance lock;
- no action if the asset is in manual lock mode;
- no action if a previous action is unresolved (`uncertain`);
- no action on newly-discovered/unacknowledged assets.

Cooldown defaults: same rule 15 min; same asset 5 min; same prefix/provider
30 min; global automatic-action rate limit 3 actions / 10 min.

Two-phase action state machine:

```text
planned -> pending -> running -> verifying -> succeeded
                             \-> failed
                             \-> uncertain
```

If the process crashes mid-action, the restarted service marks the action
`uncertain` and locks the asset until verification proves success/failure or an
admin acknowledges. The app prefers doing nothing over doing the wrong thing.

---

## 9. Authentication & access

Users log in to see data. The controller owns the whole flow: session cookies
backed by a DB `sessions` table, Argon2id password hashing, and **TOTP 2FA**
(RFC 6238, enrolled on first login) with 8 single-use hashed recovery codes.
Login throttling and account lockout apply per email + real client IP
(`CF-Connecting-IP`, forwarded by Nginx). Roles: `admin`, `operator`, `viewer`,
`auditor`, enforced via explicit RBAC tables and axum middleware. Dangerous
reroutes require re-authentication (`POST /api/auth/reauth`), typed
confirmation, and a reason. See [authentication.md](authentication.md) and
[security.md](security.md).

---

## 10. Email alerts

Rerouter sends email alerts from the controller itself via SMTP (lettre,
rustls) on: attack detected, reroute planned/started/succeeded/failed, action
`uncertain`, asset unreachable, telemetry stale, and lock created/cleared. An
internal async alert dispatcher task reads new `alerts` rows, resolves
recipients/subscriptions, de-duplicates (10-minute window per
`(event_type, asset, rule)`), rate-limits (20/hr per recipient with digest
fallback), sends, and records `alert_deliveries`. `reroute_uncertain`,
`reroute_failed`, and security events are always sent immediately and never
collapsed. See [email-alerts.md](email-alerts.md).

---

## 11. Database

MariaDB only. The controller (sqlx) is the single owner: it runs the sqlx
migrations in `backend-rust/migrations/` and is the single source of schema
truth. Full schema in [database.md](database.md). Core groups:
users/roles/permissions (+ 2FA, sessions, recovery codes), assets/providers/
credentials/statuses, telemetry samples/current, detection rules/states/events,
reroute templates/actions/steps/outputs/verifications, locks/cooldowns, alerts/
alert_deliveries, audit logs, system settings.

---

## 12. Deployment

Cloudflare fronts `rerouter.cloudcraft.ro`; Nginx is the origin, serving the
static SPA build (`frontend/dist`) and reverse-proxying `/api/` to the
controller on `127.0.0.1:9277`. The Rust controller runs under a dedicated
`rerouter` system user via systemd and binds its API to `127.0.0.1` only.
See [deployment.md](deployment.md).

---

## 13. Implementation milestones

The first production deployment target is a server with access to **Cisco ASR
edge routers** — the ASRs are the NetFlow/IPFIX exporters feeding telemetry,
and are candidates to become RTBH/FlowSpec providers later. Milestones 1–2 run
entirely in `observe` mode (read-only / alert-only — see §8).

1. **Inventory & telemetry (observe mode).** API + SPA login with 2FA,
   asset/provider CRUD, encrypted credentials, flow/BGP/Cloudflare telemetry
   ingestion, per-asset current metrics, dashboard, asset detail,
   monitored-asset selection. **No reroutes executed.**
2. **Detection engine (observe mode).** Rule CRUD, threshold above/below +
   duration/consecutive-sample logic, rule state + events, dashboard active
   matches, email alerts that include the **would-run action plan**.
   **No reroutes.**
3. **Manual reroute engine** (the first milestone that may run in `enforce`
   mode). Reroute templates, command/route preview, manual trigger, provider
   execution, output capture, verification, audit log, locks & cooldowns.
4. **Automatic reroutes.** Explicit global enable, per-rule enable, safety locks,
   cooldown enforcement, state recovery, uncertain-action handling, admin ack.
5. **Hardening.** More providers, FlowSpec, scrubbing-center diversion, richer
   verification.

---

## 14. Open questions for the owner

Answer later; do not block bootstrap.

1. Which upstreams support RTBH communities / FlowSpec, and what community values?
2. Cloudflare plan & which features are available (Magic Transit? rate-limiting?).
3. Is there a scrubbing-center contract, and what is the diversion mechanism?
4. Which prefixes are in scope, and which are never to be auto-rerouted?
5. Flow telemetry source: NetFlow v9, IPFIX, or sFlow? Sampling rate?
6. Are there maintenance windows where automatic reroutes are allowed/forbidden?
7. SMTP relay details for email alerts.
8. Retention: long-term traffic graphs, or current state + short retention only?

---

## 15. Final doctrine

Rerouter must be conservative. Monitoring may be fast. Reroutes must be slow,
explicit, audited, reversible where possible, and blocked whenever state is
uncertain. The app must prefer doing nothing over doing the wrong thing.

Automatic remediation is allowed only when: telemetry is fresh; detection
confidence is high; the rule matched for the configured duration; the reroute
template is approved; the asset/provider is not locked; cooldown allows it; the
exact target is known; verification is possible; and the previous state is
understood.

That is the operating doctrine.
