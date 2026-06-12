---
name: rust-axum-sqlx
description: Patterns for the Rerouter controller — tokio async service, axum app API behind the Nginx proxy, sqlx against MariaDB with sqlx-owned migrations, tracing, and the reroute state machine. Use when writing or reviewing backend-rust/ code.
---

# Skill: Rust + axum + sqlx (Rerouter controller)

## Stack

- `tokio` async runtime; per-asset tasks via the scheduler.
- `axum` for the app's REST API (`127.0.0.1:9277`), reached only through the
  Nginx reverse proxy.
- `sqlx` with the `mysql` feature against MariaDB; compile-time-checked queries
  where practical (`sqlx::query!`), `DATABASE_URL` from the environment.
- `argon2`, `totp-rs`, `lettre` for auth, 2FA, and SMTP alerts
  (see [rust-auth-2fa](rust-auth-2fa.md)).
- `tracing` + `tracing-subscriber` for structured logs to stdout (journald).
- `serde`/`serde_json`, `clap`, `chrono`/`time`, `uuid`, `anyhow`/`thiserror`,
  `reqwest` for the Cloudflare API.

## API conventions

- Bind `127.0.0.1` only; never `0.0.0.0`. Public access is **exclusively** via
  the Nginx reverse proxy (`location /api/ -> http://127.0.0.1:9277`) behind
  Cloudflare — the loopback-bind invariant is unchanged.
- One authenticated REST API under `/api/`; session + RBAC enforced by
  middleware/extractors (see [rust-auth-2fa](rust-auth-2fa.md)).
- JSON in/out; typed request/response structs with `serde`.
- Endpoints per [../docs/architecture.md](../docs/architecture.md): auth
  (`/api/auth/*`), `/api/health` (unauthenticated liveness), `/api/status`,
  asset/provider/rule CRUD and tests, `/api/reroutes/manual`, lock controls.
- Return structured errors (`thiserror`) with stable codes; never panic in a
  handler.

## sqlx patterns

- One `MySqlPool`, shared via app state.
- Persist action state transitions in a transaction with the step output, so a
  crash can never leave "did the step run?" ambiguous.
- Migrations are owned **here**: plain SQL files in `backend-rust/migrations/`
  (e.g. `20260612000100_users_and_auth.sql`), applied with `sqlx migrate run`. The
  Rust repo is the single source of schema truth
  (see [database-agent](../agents/database-agent.md)).

## State machine (reroutes)

Model `planned -> pending -> running -> verifying -> {succeeded|failed|uncertain}`
as an explicit enum with persisted transitions. Write **before** the side effect
(intent) and **after** (outcome). On startup, scan for non-terminal states and
force them to `uncertain` (see [../docs/state-recovery.md](../docs/state-recovery.md)).

## Logging fields

Every operational log carries `asset_id`, `provider_id`, `rule_id`,
`reroute_id`, `event_type`, `status`, and `error` where relevant.

## Testing

Unit-test rate derivation, counter wrap/reset, threshold + duration logic,
cooldown math, template rendering, and state-recovery transitions. Use fixtures
under `tests/fixtures/` for flow/Cloudflare/BGP parsing. Parser failures return
structured errors and are asserted, never panics.
