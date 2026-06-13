# Security

Rerouter can move production traffic and black-hole real hosts. Security and
authorization are first-class. See also [authentication.md](authentication.md)
(login + 2FA) and the safety model in [reroute-engine.md](reroute-engine.md).

## Roles

```text
admin     full control, user management, mode flips, lock management
operator  trigger manual reroutes, manage rules, acknowledge uncertain
viewer    read-only dashboards and data
auditor   read audit logs and configuration, no changes
```

## Permissions

```text
view_dashboard
view_asset
edit_asset
edit_provider
edit_credentials
view_credentials_metadata
edit_rules
trigger_manual_reroute
acknowledge_uncertain_reroute
manage_locks
manage_alerts
view_audit
manage_users
```

RBAC is implemented with explicit `roles` / `permissions` / `role_user` /
`permission_role` tables (see [database.md](database.md)) and enforced by axum
middleware/extractors in the controller. Every `/api/` request is authorized at
the API boundary: a manual reroute request must carry an authenticated,
authorized identity (session + permission check) and a reason.

## Dangerous actions

Reroutes are device-CLI actions over SSH to Cisco IOS — null-route a prefix to
`Null0` (RTBH), tagged-`Null0` upstream RTBH (blackhole), and BGP-neighbor
shut / no-shut. This is an in-house operator tool, so there is **no** typed
confirmation or per-action re-authentication gate; the safety comes from
layered, fail-closed controls rather than per-click friction:

- **observe by default** — the shipped operating mode is `observe`
  (read-only / alert-only); nothing executes, automatic or manual, until an
  admin flips to `enforce`;
- **template-only, allowlisted commands** — actions are rendered from validated
  templates, and the device-CLI layer enforces a fail-closed command allowlist
  (only the exact `Null0` route and `neighbor … shutdown` forms pass);
- **authorized identity** — a manual reroute must carry an authenticated session
  with the `trigger_manual_reroute` permission and an optional free-text reason
  for the audit log;
- **device locks and cooldowns** — a locked or cooling-down device refuses new
  actions;
- **verify, don't assume** — every action confirms the resulting routing state
  with a `show` read-back before it is called succeeded (see
  [state-recovery.md](state-recovery.md) and [reroute-engine.md](reroute-engine.md));
- **full audit** — user / real client IP (`CF-Connecting-IP`) / time on every
  action and lifecycle transition.

Flipping the global operating mode (`observe` → `enforce`, see
[reroute-engine.md](reroute-engine.md) "Operating mode") is itself a dangerous
action: admin-only, audited, and alerted. The shipped default is `observe`
(read-only / alert-only — no reroute executes, automatic or manual).

## Credentials & secrets

- Device secrets — SNMP community strings and SSH credentials (password XOR
  private key + passphrase) — are encrypted at rest by the controller: AES-256-GCM
  with the key from the `SECRETS_KEY` env var; the UI never returns them (only
  presence flags + the non-secret SSH public key). In-app-generated SSH keys are
  stored encrypted the same way.
- File-based keys live under `/etc/rerouter/keys/`, owner `rerouter`, mode `0600`.
- The controller runs as a dedicated `rerouter` system user.
- Better later: HashiCorp Vault, per-provider rotation, never re-expose secrets in
  the UI after creation.

## Network access

- Origin accepts public 443 **only from Cloudflare IP ranges**.
- The Rust controller binds `127.0.0.1:9277` and is never exposed publicly. Its
  `/api/` is the public app API, but **only** through the Nginx reverse proxy
  (`location /api/` -> `http://127.0.0.1:9277`); the SPA is served as static
  files by Nginx.
- The controller must reach the managed devices over **SNMP (UDP 161)** for
  telemetry and **SSH (TCP 22)** for reroute actions/discovery, plus the configured
  SMTP server for alerts. There are no flow-collector / BGP-speaker / Cloudflare /
  scrubber egress paths in v1.

## Authentication hardening

- TOTP 2FA mandatory for all accounts (see [authentication.md](authentication.md)).
- Lock accounts after repeated failed logins; throttle login + 2FA attempts.
- Argon2id password hashing; DB-backed sessions rotated on login (fixation
  protection); secure + httponly + SameSite cookies signed with `SESSION_SECRET`.
- Trust `CF-Connecting-IP` only via the Cloudflare -> Nginx -> loopback path
  (only Cloudflare can reach Nginx; only Nginx can reach the controller).

## Audit

Audit everything: logins, 2FA enrollment/resets, rule edits, reroute lifecycle,
lock changes, credential changes, user management. Audit logs are append-only and
retained per [database.md](database.md) retention policy.
