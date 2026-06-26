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

Rerouter is a small but safety-critical web application for monitoring traffic on
the interfaces of one or more network devices (Cisco IOS edge routers) and
executing controlled **reroute** actions when traffic conditions cross configured
thresholds — for example during a volumetric flood, SYN flood, or amplification
attack.

The application must:

- let operators log in (with TOTP 2FA) to view live data;
- enroll network **devices** (Cisco IOS edge routers) and their monitored
  **interfaces**;
- collect traffic telemetry by **SNMP interface polling** (v1);
- evaluate editable detection conditions and thresholds on interface metrics;
- execute approved reroute actions when conditions match;
- allow manual reroute triggering from the web GUI;
- send email alerts on detection, reroute, failure, and uncertain state;
- recover state after crash/restart;
- show device reachability and collection/action status;
- provide a GUI for selecting monitored interfaces and assigning rules.

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
        +-----+----------------+
        |                       |
        v                       v
   SNMP polling          Device CLI over SSH
   (devices /            (Cisco IOS edge routers:
    interfaces)           Null0 RTBH + BGP shut/no-shut)
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
│   ├── device-enrollment.md
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
│   │   ├── telemetry/        (snmp.rs — v1 interface polling; netflow.rs/
│   │   │                      sflow.rs/bgp.rs/cloudflare.rs are inert stubs)
│   │   ├── detection/        (condition.rs, cooldown.rs, engine.rs)
│   │   ├── reroute/          (executor.rs, state_machine.rs, templates.rs,
│   │   │                      locks.rs, rollback.rs)
│   │   ├── ssh/              (mod.rs — device-CLI execution over SSH, RSA
│   │   │                      keygen, command-access probe, fail-closed
│   │   │                      command allowlist, BGP/prefix discovery)
│   │   │                      (the old providers/ adapter layer was removed)
│   │   ├── api/              (health.rs, devices.rs, interfaces.rs, rules.rs,
│   │   │                      templates.rs, reroutes.rs, rtbh.rs, alerts.rs,
│   │   │                      audit.rs, locks.rs, users.rs, settings.rs —
│   │   │                      the auth router lives in src/auth/)
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
│       ├── pages/            (login, dashboard, devices, device-detail,
│       │                      interface-detail, rules, templates, mitigations,
│       │                      manual-reroute, alerts, audit, settings, users)
│       ├── lib/              (api client, session helpers, types)
│       └── components/ui/    (shadcn/ui components)
├── deploy/
│   ├── nginx/rerouter.conf
│   ├── cloudflare/README.md
│   ├── systemd/rerouter-controller.service
│   └── env/rerouter.example.env
└── .claude/                     (version-controlled; agents/skills live here so
    │                             the Claude Code harness auto-discovers them)
    ├── settings.json
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
        ├── bgp-reroute-safety.md
        └── improve/             (read-only senior-advisor audit skill:
                                  SKILL.md + references/)
```

`.claude/` is intentionally checked into version control (only
`.claude/settings.local.json` is git-ignored) so agents and skills are shared
with the team **and** auto-discovered by the Claude Code harness.

---

## 5. Runtime components

### 5.1 Rust controller binary

The operational heart of the system — and the only service. Responsibilities:

- load device & interface inventory from DB;
- maintain telemetry ingestion (SNMP interface polling);
- normalize per-interface traffic counters and rates;
- calculate per-interface rx/tx bps, rx/tx pps, link utilization %, and
  operational status from SNMP counters;
- evaluate configured detection rules;
- enforce cooldowns, locks, and safety limits;
- execute approved reroutes via device CLI over SSH (Cisco IOS);
- persist every decision and action;
- serve the authenticated REST API under `/api/` (loopback-only bind);
- run sqlx database migrations (single source of schema truth);
- send email alerts via its internal async alert dispatcher;
- recover incomplete reroutes after restart.

Suggested crates: `tokio`, `axum`, `sqlx` (mysql/mariadb), `serde`, `tracing`,
`clap`, `chrono`/`time`, `uuid`, `anyhow`/`thiserror`, an SNMP client for
interface polling, `russh` (device-CLI execution + RSA keygen over SSH),
`argon2` (password hashing), `totp-rs` (TOTP 2FA), and `lettre` (SMTP over
rustls).

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
- **REST API** under `/api/`: auth, status, device/interface/rule/template
  CRUD, manual reroute triggering, RTBH-community catalog, alerts, audit, locks,
  settings, users. Manual reroutes require the `trigger_manual_reroute`
  permission and accept an optional free-text reason for the audit log; there is
  no typed-confirmation or re-auth gate (de-scoped — see §9).
- **Email alerts**: an internal async alert dispatcher task reads new `alerts`
  rows, resolves recipients/subscriptions, de-duplicates, rate-limits, sends
  via SMTP, and records deliveries (see §10).
- **Credential encryption**: device secrets — SNMP community strings and SSH
  credentials (password / private key / passphrase) — and TOTP secrets are
  encrypted at rest with AES-256-GCM (key from the `SECRETS_KEY` environment
  variable).
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
- show current device reachability prominently;
- show stale telemetry clearly (live / cached / degraded / unknown);
- display exactly which reroute will be performed (template, target device, the
  exact CLI commands) — the SPA renders the exact reroute preview returned by
  the API;
- show action history near every rule and device;
- support GUI selection of monitored interfaces and rule assignment;
- show a clear degraded state when the API is unreachable.

Core pages: `/login` (password → TOTP challenge; first-login TOTP enrollment),
`/dashboard`, `/devices`, `/devices/:id`,
`/devices/:deviceId/interfaces/:ifaceId`, `/rules`, `/templates`,
`/mitigations` (reroute history), `/mitigations/manual`, `/alerts`, `/audit`,
`/settings`, `/users`.

---

## 6. Domain model summary

| Concept | Meaning |
| --- | --- |
| **Device** | A network device we manage — a Cisco IOS edge router reached by SNMP (telemetry) and SSH (execution). |
| **Interface** | A monitored interface on a device; telemetry and detection rules target interfaces. |
| **Telemetry sample** | A normalized traffic measurement for an interface over an interval (SNMP poll). |
| **Detection rule** | A stateful threshold/condition that fires when a metric matches for a duration / sample count. The metric is either a single interface's value or the **sum** of a chosen metric (rx/tx bps/pps) across a configured set of interfaces — which may span multiple devices. Conditions may also threshold interface **error rates** (`in_err_rate`/`out_err_rate`). |
| **Reroute template** | An allowlisted, parameterized device-CLI mitigation (Null0 RTBH announce/withdraw, upstream-tagged blackhole, BGP session enable/disable). |
| **Reroute (action)** | A single, audited execution of a template against a target device, driven by a state machine. A rule's actions live in `rule_actions` (template + device + params; one rule may drive several routers). |
| **Lock / cooldown** | Device-scoped safety controls that block actions when state is unsafe or recently changed. |

Detail: [device-enrollment.md](device-enrollment.md),
[telemetry-model.md](telemetry-model.md),
[detection-engine.md](detection-engine.md),
[reroute-engine.md](reroute-engine.md).

---

## 7. Reroute methods

All v1 reroutes execute as **device CLI over SSH** to Cisco IOS edge routers
(`provider_type = device_cli`); it is the only execution path. The template
catalog (the only way a reroute runs) is:

1. **`null_route_prefix`** — install a local `Null0` static route for a prefix
   on the device (local RTBH; drop at this router).
2. **`null_route_withdraw`** — remove that `Null0` static route (rollback of #1).
3. **`blackhole_prefix`** — announce a prefix into BGP tagged for upstream RTBH
   (a route to `Null0` with the blackhole community), so the upstream drops it.
4. **`blackhole_withdraw`** — withdraw that tagged announcement (rollback of #3).
5. **`bgp_session_disable`** — administratively shut a BGP neighbor
   (`neighbor … shutdown`).
6. **`bgp_session_enable`** — bring the neighbor back up (`no … shutdown`;
   rollback of #5).
7. **`bgp_advertise_add`** — start advertising a prefix toward one upstream BGP
   peer by adding the prefix to that peer's **outbound route-map's prefix-list**,
   then `clear ip bgp <neighbor> soft out`. Used for inbound traffic engineering:
   shift an attacked prefix onto a less-saturated upstream.
8. **`bgp_advertise_remove`** — stop advertising the prefix toward that upstream
   (remove the prefix-list entry + soft clear; rollback of #7). "Advertise on
   other peer(s)" is the same `bgp_advertise_add` template fanned out as extra
   `rule_actions` targeting the other neighbor(s).
9. **`iface_tcp_adjust_mss`** — set `ip tcp adjust-mss <mss>` (default 1436) on an
   interface when a rule activates (MSS clamp).
10. **`iface_tcp_adjust_mss_remove`** — remove the MSS clamp (rollback of #9).
11. **`iface_shutdown`** — administratively shut an interface (`shutdown`). A
    **disruptive** action: it black-holes everything on that link. Guarded against
    the controller's own management/transit path (see §8).
12. **`iface_no_shutdown`** — bring the interface back up (`no shutdown`; rollback
    of #11).

A **combination** (e.g. remove-from-saturated-upstream + advertise-on-others +
MSS clamp) is expressed as an ordered set of `rule_actions` on one rule — each
action keeps its own verification and rollback — not a single opaque composite
template. The UI may offer a one-click preset that attaches such a bundle.

Every method is an action template (see [reroute-engine.md](reroute-engine.md))
with a parameter schema, verification, and a rollback template. The earlier
provider-adapter methods (Cloudflare "Under Attack", FlowSpec drop, scrubbing-
center diversion) were **de-scoped** when the project pivoted to device-CLI/SSH;
the per-template "safety level" attribute was removed with them. A free-text
"run this route command" box is never exposed: commands come only from these
templates with typed params, gated by a fail-closed in-app command allowlist
(`ssh::command_allowed`), and the router account is further scoped by a
restricted Cisco parser view (`deploy/cisco/rerouter-view.ios`).

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

Global safety rules — the executor re-checks every gate at execution time, in
order. The live gates are **device-scoped** (in `enforce` mode):

- **GATE 0** — `operating_mode == enforce`. In `observe`, `execute` returns the
  would-run plan and runs nothing;
- not a dry-run;
- no automatic reroute unless explicitly enabled (global **and** per-rule);
- no automatic reroute without an action template;
- no action under a global maintenance lock;
- no action if the device is in manual lock mode;
- no action if another action is already running on the same device;
- no action if a previous action on the device is unresolved (`uncertain`);
- no repeated action inside the per-device cooldown window;
- no repeated action from the same rule inside the per-rule cooldown window;
- no action once the global action rate limit for the window is reached;
- **no interface-level disruptive action (`iface_shutdown`, `iface_tcp_adjust_mss`)
  on a protected interface** — the executor resolves the target interface and
  blocks if it is flagged `protected` (the device's management/transit/SSH path).
  This prevents the controller from black-holing or cutting its own path to the
  device (self-lockout). Returns a `blocked_reason`; the command is never pushed;
- (manual triggers additionally require the `trigger_manual_reroute`
  permission, enforced by the API before `execute` is called).

Interface shutdown is the most destructive template in the catalog. Like every
other action it is blocked entirely in `observe` mode and, in `enforce` mode,
requires the global automatic switch **and** the per-rule switch before it can
fire automatically. Never weaken these defaults.

The per-template "safety level", the provider/asset-reachability gate, the
detection-confidence gate, the telemetry-stale gate, and the
newly-discovered-asset gate were **de-scoped** with the provider abstraction;
the live gates above are the complete set.

Cooldowns / rate limit (all config-driven, `[safety]`, applied to manual and
automatic actions): per-device cooldown (`same_device_cooldown_seconds`, default
300), per-rule cooldown (`same_rule_cooldown_seconds`, default 900, rule-triggered
only), and a global circuit breaker (`global_action_rate_limit_count` actions per
`global_action_rate_limit_window_seconds`, default 3/600). A `0` disables a
throttle.

Two-phase action state machine:

```text
planned -> pending -> running -> verifying -> succeeded
                             \-> failed
                             \-> uncertain
```

If the process crashes mid-action (any reroute left `pending`/`running`/
`verifying`), the restarted service marks the action `uncertain` and locks the
**device** until an admin acknowledges. The app prefers doing nothing over doing
the wrong thing.

---

## 9. Authentication & access

Users log in to see data. The controller owns the whole flow: session cookies
backed by a DB `sessions` table, Argon2id password hashing, and **TOTP 2FA**
(RFC 6238, enrolled on first login) with 8 single-use hashed recovery codes.
Login throttling and account lockout apply per email + real client IP
(`CF-Connecting-IP`, forwarded by Nginx). Roles: `admin`, `operator`, `viewer`,
`auditor`, enforced via explicit RBAC tables and axum middleware. Manual
reroutes require only the `trigger_manual_reroute` permission and accept an
optional free-text reason for the audit log. The earlier re-authentication
gate (`POST /api/auth/reauth`, `sessions.reauth_at`, the
`approve_dangerous_reroute` permission) and typed confirmation were **de-scoped**
and removed; safety now rests on the operating mode, the template/allowlist
controls, and the device-scoped execution gates (§7, §8). See
[authentication.md](authentication.md) and [security.md](security.md).

---

## 10. Email alerts

Rerouter sends alerts from the controller itself on: rule fired (`rule_fired` —
carrying the would-run action plan in observe mode), reroute
started/succeeded/failed, action `uncertain`, device unreachable, telemetry
stale, and lock created/cleared. There are two delivery channels:

- **email** via SMTP (lettre, rustls) — SMTP credentials come from the
  environment (`SMTP_*`); recipients/subscriptions are managed in the DB and via
  the `/settings` notifications UI;
- **Microsoft Teams** via incoming webhook (HTTP POST of a MessageCard) —
  endpoint URLs are stored **encrypted at rest** (AES-256-GCM, `crypto::seal`)
  in `webhook_endpoints`, managed via the same `/settings` notifications UI with
  per-event-type routing and a test-send. Webhook URLs are never logged or echoed.

An internal async alert dispatcher task reads new `alerts` rows, resolves
recipients/subscriptions per channel, de-duplicates (10-minute window, keyed on
the `alerts.dedup_key` — for firing alerts `rule_fired:rule:<id>:iface:<id>`),
rate-limits (20/hr per recipient), sends over each channel, and records
`alert_deliveries` (`channel` ∈ {`email`, `teams`}). `reroute_uncertain`,
`reroute_failed`, and security events are always sent immediately and never
collapsed. No alert payload (email or Teams) ever contains a secret. See
[email-alerts.md](email-alerts.md).

---

## 11. Database

MariaDB only. The controller (sqlx) is the single owner: it runs the sqlx
migrations in `backend-rust/migrations/` and is the single source of schema
truth. Full schema in [database.md](database.md). Core groups:
users/roles/permissions (+ 2FA, sessions, recovery codes), devices/
device_interfaces (+ encrypted SNMP/SSH credentials, device_bgp_networks,
device BGP peers), telemetry samples/current, detection rules/states/events
(+ `rule_actions`), reroute templates/actions/steps/outputs/verifications,
the global `rtbh_communities` catalog, locks/cooldowns, alerts/alert_deliveries,
audit logs, system settings. The asset/provider model (`protected_assets`,
`reroute_providers`, and their `asset_*` satellites) was **dropped** — the model
is devices/interfaces end to end.

---

## 12. Deployment

Cloudflare fronts `rerouter.cloudcraft.ro`; Nginx is the origin, serving the
static SPA build (`frontend/dist`) and reverse-proxying `/api/` to the
controller on `127.0.0.1:9277`. The Rust controller runs under a dedicated
`rerouter` system user via systemd and binds its API to `127.0.0.1` only.
See [deployment.md](deployment.md).

---

## 13. Implementation milestones

The first production deployment target is a server with access to **Cisco IOS
edge routers**, reached by SNMP for telemetry and by SSH for device-CLI
execution. The shipped default is `observe` mode (read-only / alert-only — see
§8); execution paths run only after an admin flips to `enforce`.

1. **Inventory & telemetry (observe mode). [BUILT]** API + SPA login with 2FA,
   device/interface CRUD, encrypted SNMP/SSH credentials, SNMP interface
   polling, per-interface current metrics, dashboard, device & interface detail,
   monitored-interface selection. **No reroutes executed.**
2. **Detection engine (observe mode). [BUILT]** Rule CRUD, threshold above/below
   + duration / consecutive-sample firing logic, hysteresis settle on clear,
   rule state + `rule_fired` events, dashboard active matches, email alerts that
   include the **would-run action plan**. **No reroutes.**
3. **Reroute engine — manual + per-rule automatic. [BUILT]** Device-CLI
   templates over SSH, command preview, manual trigger (`trigger_manual_reroute`
   + optional reason), per-rule automatic execution on the firing edge when the
   global switch (`automatic_actions_enabled`) and the rule's
   `automatic_reroute_enabled` are on (enforce mode only), output capture,
   verification, audit log, device-scoped locks & cooldowns, crash recovery
   (`uncertain` + device lock + admin ack). The full automatic-execution
   machinery — global + per-rule enable, safety locks, cooldown, state recovery,
   uncertain handling, admin ack — is built and active in `enforce` mode; the
   shipped default `observe` mode renders `would_run_actions` and executes
   nothing.
4. **De-scoped.** The original "more providers" milestone (Cloudflare,
   FlowSpec, scrubbing-center diversion, the provider-adapter abstraction) was
   **de-scoped** when the project pivoted to device-CLI/SSH — it is not pending
   work. Future hardening stays within the device-CLI model (richer verification,
   more IOS templates).

---

## 14. Open questions for the owner

Answer later; do not block bootstrap.

1. Which upstreams support RTBH communities, and what community values?
   (Rerouter now ships a global `rtbh_communities` catalog — see
   `/api/rtbh-communities`; this question is now about populating it per
   upstream.)
2. *(Resolved by de-scoping.)* Cloudflare / FlowSpec / scrubbing-center
   diversion were dropped when the project pivoted to device-CLI/SSH.
3. Which prefixes are in scope, and which are never to be auto-rerouted?
4. Are there maintenance windows where automatic reroutes are allowed/forbidden?
5. SMTP relay details for email alerts.
6. Retention: long-term traffic graphs, or current state + short retention only?

---

## 15. Final doctrine

Rerouter must be conservative. Monitoring may be fast. Reroutes must be slow,
explicit, audited, reversible where possible, and blocked whenever state is
uncertain. The app must prefer doing nothing over doing the wrong thing.

Automatic remediation is allowed only when: the controller is in `enforce`
mode, the global automatic switch (`automatic_actions_enabled`) is on, and the
rule's automatic switch is on; the rule matched for its configured
duration / sample count; the action comes from an approved device-CLI template;
the target device is not locked and has no action running or unresolved
(`uncertain`); the per-device cooldown allows it; the exact target is known; and
verification is possible. (Telemetry-freshness and detection-confidence gating
were de-scoped — see §8.)

That is the operating doctrine.
