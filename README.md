# Rerouter

Rerouter is a safety-critical DDoS-mitigation control plane. It watches traffic
telemetry for your protected prefixes, detects attack conditions against editable
thresholds, and executes controlled **reroute** actions on Cisco IOS devices:
Null0/RTBH routes, BGP session and advertisement changes, route-map changes, and
bounded interface actions through audited, allowlisted templates.

It is not just a dashboard. It is an operations control-plane for traffic
steering. Safety, auditability, and predictable state recovery are core
requirements: the app prefers doing nothing over doing the wrong thing.

## Components

- **Rust controller binary** (`backend-rust/`) — traffic telemetry collection,
  detection rule engine, reroute execution, state machine, plus the full
  authenticated REST API: session auth with TOTP 2FA, RBAC, email/Teams alert
  delivery, and sqlx database migrations. Binds to localhost only and
  runs as a long-lived systemd service.
- **React + Shadcn SPA** (`frontend/`) — Vite + React + TypeScript + Tailwind +
  shadcn/ui single-page app: login with TOTP 2FA, operational dashboards,
  device/interface management, detection-rule editor, manual reroute triggers,
  notification configuration, and audit views. Built to `frontend/dist` and
  served statically by Nginx.
- **MariaDB** — the controller's database; schema owned by sqlx migrations in
  `backend-rust/migrations/`.
- **Cloudflare + Nginx** — Cloudflare fronts the production site at
  `rerouter.cloudcraft.ro`; Nginx is the origin, serves the SPA, and
  reverse-proxies `/api/` to the controller on `127.0.0.1:9277`.

## Quick start (test deployment)

The released binary contains everything needed — installer, migrations, seeds,
and (optionally) the UI:

```bash
# build — add --features embed-ui for a single-binary UI (after building frontend/dist)
(cd backend-rust && cargo build --release)

scp backend-rust/target/release/rerouter-controller server:/tmp/
ssh server
sudo /tmp/rerouter-controller --install   # binary + .env + config.toml + systemd unit
sudo vi /srv/rerouter/.env                # fill DATABASE_URL + SMTP_* (keys are pre-generated)
# create the MariaDB database + user, then:
sudo systemctl start rerouter-controller
journalctl -fu rerouter-controller        # preflights DB creds, seeds a fresh database itself
```

Create the first superadmin with `--create-admin`; it prints the independent
one-time code required to bind first-login TOTP enrollment. With `embed-ui`, browse the UI
through an SSH tunnel (`ssh -L 9277:127.0.0.1:9277 server`) — the API bind
stays loopback-only. Full details (including the Nginx + Cloudflare production
topology): [docs/deployment.md](docs/deployment.md).

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
rate-limited, cooled down, audited, and verified with a separate read-only SSH
session. Enforce-mode manual actions, rule applies, and rollbacks require a short-lived,
single-use token bound to the exact server-rendered preview. Fresh device
inventory bounds every new target; interface shutdown and route-map changes are
manual-only. Any action left unresolved by a crash is marked `uncertain` and
locks the affected device until an admin acknowledges it.

## Status

Inventory, telemetry, detection, the authenticated UI, alert delivery, manual
and gated automatic execution, rollback, and crash recovery are implemented.
The shipped database default remains `observe`; production arming is always an
explicit, step-up-authenticated operator decision. See the latest
[re-audit](docs/audit-2026-07-10.md) for verified safeguards and residual risks.
