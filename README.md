# Rerouter

Rerouter is a safety-critical DDoS-mitigation control plane. It watches traffic
telemetry for your protected prefixes, detects attack conditions against editable
thresholds, and executes controlled **reroute** actions — blackhole/RTBH a prefix,
add a FlowSpec drop, enable Cloudflare "Under Attack" mode, or steer traffic to a
scrubbing center — through audited, allowlisted templates.

It is not just a dashboard. It is an operations control-plane for traffic
steering. Safety, auditability, and predictable state recovery are core
requirements: the app prefers doing nothing over doing the wrong thing.

## Components

- **Rust controller binary** (`backend-rust/`) — traffic telemetry collection,
  detection rule engine, reroute execution, state machine, plus the full
  authenticated REST API: session auth with TOTP 2FA, RBAC, email alerting (SMTP
  alert dispatcher), and sqlx database migrations. Binds to localhost only and
  runs as a long-lived systemd service.
- **React + Shadcn SPA** (`frontend/`) — Vite + React + TypeScript + Tailwind +
  shadcn/ui single-page app: login with TOTP 2FA, operational dashboards,
  asset/provider CRUD, detection-rule editor, manual reroute triggers,
  email-alert configuration, and audit views. Built to `frontend/dist` and
  served statically by Nginx.
- **MariaDB** — the controller's database; schema owned by sqlx migrations in
  `backend-rust/migrations/`.
- **Cloudflare + Nginx** — Cloudflare fronts the dev/prod site at
  `rerouter.cloudcraft.ro`; Nginx is the origin, serves the SPA, and
  reverse-proxies `/api/` to the controller on `127.0.0.1:9277`.

## Quick links

- [docs/doctrine.md](docs/doctrine.md) — the operating doctrine (read this first).
- [docs/architecture.md](docs/architecture.md) — layers and runtime components.
- [docs/deployment.md](docs/deployment.md) — Cloudflare + Nginx + systemd.
- [docs/security.md](docs/security.md) — roles, permissions, dangerous actions.
- [docs/authentication.md](docs/authentication.md) — login and TOTP 2FA.
- [docs/database.md](docs/database.md) — MariaDB schema.
- [docs/detection-engine.md](docs/detection-engine.md) — attack-detection rules.
- [docs/reroute-engine.md](docs/reroute-engine.md) — reroute templates & execution.
- [docs/email-alerts.md](docs/email-alerts.md) — alert channel and triggers.
- [docs/operations-runbook.md](docs/operations-runbook.md) — day-2 operations.

## Safety

Rerouter ships in **observe mode** — a safe read-only / alert-only posture in
which **no reroute executes, automatic or manual**. Detection runs fully, and
when a threshold crosses above or below for the configured duration, the email
alert includes the exact actions that *would* have run. An admin must explicitly
flip the operating mode to `enforce` (audited) before Rerouter ever acts.

Beyond that, automatic reroutes are **disabled by default** even in enforce
mode. Every reroute must be defined as an action template and is allowlisted,
rate-limited, cooled down, and audited. Disruptive reroutes require typed
confirmation and a reason, and any action left unresolved by a crash is marked
`uncertain` and locks the affected asset until an admin acknowledges it.

## Status

Bootstrap scaffolding. See [docs/doctrine.md](docs/doctrine.md) section
"Implementation milestones" for the build order. Milestone 1 is monitoring-only:
no reroutes are executed.
