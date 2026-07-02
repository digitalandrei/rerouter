# Security

Rerouter can move production traffic and black-hole real hosts. Security and
authorization are first-class. See also [authentication.md](authentication.md)
(login + 2FA) and the safety model in [reroute-engine.md](reroute-engine.md).

## Roles

```text
superadmin  everything — a strict superset of admin, plus user management
            and device enrollment (manage_users + manage_devices)
admin       broad control (rules, locks, alerts, manual reroutes, mode flips,
            view everything) EXCEPT user management and device enrollment
operator    trigger manual reroutes, manage rules, acknowledge uncertain
viewer      read-only dashboards and data
auditor     read audit logs and configuration, no changes
```

`superadmin` was added in migration `20260613000100_user_management.sql` and is a
strict superset of `admin`; the controller's `is_admin()` accepts **both** roles
for admin-tier checks (critical-event fan-out, mode flips). The same migration
**downgraded** `admin`: `manage_users` and `manage_devices` are now reserved to
`superadmin` — the bootstrap admin created by `--create-admin` is a `superadmin`,
and any pre-existing `admin` is reduced to the narrower scope.

## Permissions

The `Permission` enum (`src/auth/rbac.rs`) and the seeded `permissions` table list
**14** permissions:

```text
view_dashboard
view_asset                  (compat alias — gates DEVICE read endpoints)
edit_asset                  (compat alias — gates DEVICE write/enroll endpoints)
manage_devices              superadmin-only: device enrollment/management
edit_provider               (compat alias — retained, device-scoped)
edit_credentials
view_credentials_metadata
edit_rules
trigger_manual_reroute
acknowledge_uncertain_reroute
manage_locks
manage_alerts
view_audit
manage_users                superadmin-only: user management
```

`view_asset` / `edit_asset` / `edit_provider` are **retained compatibility
aliases**: the names predate the device/interface model but are still the live
permission strings, and they now gate the **device** endpoints (read / write /
enroll) rather than any "asset" or "provider" abstraction. There is no
asset/provider model in v1.

> **Vestigial seed — `approve_dangerous_reroute`.** Migration
> `20260612000100_users_and_auth.sql` also seeds an `approve_dangerous_reroute`
> permission, but it exists in **neither** the `Permission` enum **nor** any
> handler/extractor — nothing checks it. It is a legacy seed slated for removal;
> do not treat it as a working gate.

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
- Better later: HashiCorp Vault, per-device credential rotation, never re-expose
  secrets in the UI after creation.

## Network access

- Origin accepts public 443 **only from Cloudflare IP ranges**.
- The Rust controller binds `127.0.0.1:9277` and is never exposed publicly. Its
  `/api/` is the public app API, but **only** through the Nginx reverse proxy
  (`location /api/` -> `http://127.0.0.1:9277`); the SPA is served as static
  files by Nginx.
- The controller must reach the managed devices over **SNMP (UDP 161)** for
  telemetry and **SSH (TCP 22)** for reroute actions/discovery, plus the configured
  SMTP server for alerts. The optional **flow collector** additionally *listens*
  for NetFlow v9 / sFlow v5 UDP (off by default; binds a management address, not
  loopback — a deliberate, source-IP-allowlisted ingress). There are no
  BGP-speaker / Cloudflare / scrubber egress paths in v1.

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
