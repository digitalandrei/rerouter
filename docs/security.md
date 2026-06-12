# Security

Rerouter can move production traffic and black-hole real hosts. Security and
authorization are first-class. See also [authentication.md](authentication.md)
(login + 2FA) and the safety model in [reroute-engine.md](reroute-engine.md).

## Roles

```text
admin     full control, user management, dangerous-action approval
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
approve_dangerous_reroute
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

For high-safety-level reroutes (blackhole, withdraw announcement, scrub-divert):

- require **re-authentication** (password + current TOTP);
- require **typed confirmation** of the target (e.g. type the prefix);
- require a **reason** field;
- show the exact reroute preview (prefix, provider, method, communities);
- log user / real client IP (`CF-Connecting-IP`) / time;
- support optional second-approver later.

Flipping the global operating mode (`observe` → `enforce`, see
[reroute-engine.md](reroute-engine.md) "Operating mode") is itself a dangerous
action: admin-only, audited, and alerted. The shipped default is `observe`
(read-only / alert-only — no reroute executes, automatic or manual).

## Credentials & secrets

- Provider API tokens (Cloudflare), BGP TSIG/keys, scrubber creds: encrypted at
  rest by the controller — AES-256-GCM with the key from the `SECRETS_KEY` env
  var; the UI exposes only references/metadata.
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
- The controller must reach: flow collector ports, the BGP speaker, the Cloudflare
  API (HTTPS egress), the scrubbing center as contracted, and the configured
  SMTP server for alerts.

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
