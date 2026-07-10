# Claude instructions for Rerouter

This is a **safety-critical DDoS-mitigation / traffic-rerouting project**. Reroute
actions move production traffic and can black-hole real customers. Treat every
action path as dangerous by default.

## Read first

- [docs/doctrine.md](docs/doctrine.md) is the source of truth. When in doubt,
  follow the doctrine. If a request conflicts with it, surface the conflict.
- Per-area detail lives in `docs/`. Agents and skills live in `.claude/agents/`
  and `.claude/skills/` (version-controlled, so the Claude Code harness
  auto-discovers them).

## Hard rules

- The controller ships in **observe mode** (read-only / alert-only):
  `system_settings.operating_mode = 'observe'`. In observe mode **no reroute
  executes — automatic or manual**; a fired rule alerts with the rendered plan
  of the actions that *would* have run. Mode flips are admin-only and audited.
  Never weaken this default.
- **Never** add arbitrary command/route execution as a first-class feature.
  All reroutes go through validated **action templates** with parameter schemas.
- **Never** enable automatic reroutes by default. Automatic execution requires an
  explicit global enable *and* a per-rule enable (on top of enforce mode). Arming
  the system (enforce, or the global enable) requires step-up re-auth (password + TOTP).
- Every reroute must pass role permissions, the template/allowlist checks,
  cooldowns, locks, and audit logging. In enforce mode, every operator-triggered
  action and rollback must present a short-lived, single-use server token bound
  to the exact preview just rendered. This preview binding is a server-side gate;
  frontend state alone is never sufficient.
- Prefer clear **state machines** over implicit behaviour. Persist runtime state
  before and after every step of an action.
- On controller startup, any reroute left in `planned`/`pending`/`running`/`verifying`
  becomes `uncertain` and **locks** the affected device until an admin
  acknowledges it. Do not assume "nothing happened" after a crash.
- Never treat "command/API call sent" as success. Always verify the resulting
  routing state.
- Telemetry parsers (SNMP and the NetFlow v9 / sFlow v5 flow collector) must
  return structured errors and **never panic**.
  Flow-driven automatic action additionally requires explicit flow-auto config,
  an enrolled source, non-low sampling confidence, and contemporaneous same-
  interface SNMP corroboration. UDP source allowlisting is not cryptographic
  identity; deployments must also enforce management-plane ACL/uRPF controls.

## Conventions

- Rust: `tokio` + `axum` + `sqlx` (MariaDB); `argon2` (Argon2id) + `totp-rs` for
  auth/2FA; `lettre` for email alerts. Structured logging via `tracing`.
- Frontend: Vite + React 19 + TypeScript + Tailwind + shadcn/ui SPA in `frontend/`,
  served statically by Nginx.
- DB: MariaDB only. Migrations are sqlx SQL files in `backend-rust/migrations/`.
- Bootstrap: the installer lives in `src/install.rs`; `.env` is loaded via
  `dotenvy` (`--env-file`); a missing config falls back to built-in defaults
  mirroring `config.example.toml`; the `embed-ui` feature is optional and
  default-off.
- The Rust API binds to `127.0.0.1` only and is never exposed publicly; public
  access goes through the Nginx `/api/` reverse proxy.
- The site sits behind Cloudflare (`rerouter.cloudcraft.ro`); Nginx is the origin.

## When implementing

Treat doctrine, migrations, backend behavior, frontend contracts, deployment
examples, and tests as one change surface. New automatic-capable templates must
be explicitly opted into `automatic_allowed`; interface shutdown and route-map
changes remain manual-only. Preserve the shipped `observe` default and add
failure-path tests whenever a change touches execution, recovery, or identity.
