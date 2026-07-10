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
**10** enforced permissions:

```text
view_dashboard
view_asset                  compatibility name for DEVICE read endpoints
manage_devices              superadmin-only: device enrollment/management
edit_rules
trigger_manual_reroute
acknowledge_uncertain_reroute
manage_locks
manage_alerts
view_audit
manage_users                superadmin-only: user management
```

`view_asset` is the one retained compatibility name from the pre-device schema;
it gates device/interface reads. The inert `edit_asset`, `edit_provider`,
`edit_credentials`, and `view_credentials_metadata` rows were removed in
migration `20260710001000_remove_inert_permissions.sql`; device writes use
`manage_devices`. There is no asset/provider model in v1.

RBAC is implemented with explicit `roles` / `permissions` / `role_user` /
`permission_role` tables (see [database.md](database.md)) and enforced by axum
middleware/extractors in the controller. Every `/api/` request is authorized at
the API boundary: a manual reroute request must carry an authenticated,
authorized identity (session + permission check). A reason is optional metadata;
the enforce-mode exact-preview token is the required execution confirmation.

## Dangerous actions

Reroutes are device-CLI actions over SSH to Cisco IOS — null-route a prefix to
`Null0` (RTBH), tagged-`Null0` upstream RTBH (blackhole), and BGP-neighbor
shut / no-shut. This is an in-house operator tool, so there is no typed-text
confirmation or per-action password/TOTP gate; the safety comes from
layered, fail-closed controls rather than per-click friction:

- **observe by default** — the shipped operating mode is `observe`
  (read-only / alert-only); nothing executes, automatic or manual, until an
  admin flips to `enforce`;
- **template-only, allowlisted commands** — actions are rendered from validated
  templates, and the device-CLI layer enforces a fail-closed command allowlist
  covering only the catalogued `show`, Null0 route, BGP neighbor/prefix-list/
  route-map, and interface forms; variable tokens and output-filter syntax are
  independently constrained;
- **authorized identity** — a manual reroute must carry an authenticated session
  with the `trigger_manual_reroute` permission and an optional free-text reason
  for the audit log;
- **server-bound preview** — enforce-mode manual actions and rollbacks consume a
  five-minute, single-use token bound to the exact server-rendered plan, audit
  reason, user, and action scope. Request changes, target drift, expiry, and
  replay are refused;
- **fresh bounded targets** — inventory-backed values are canonicalized against
  recent discovery, Null0/RTBH prefixes must remain inside announced space, RTBH
  tags must be catalogued, and automatic execution requires the template's
  explicit `automatic_allowed` policy;
- **pinned device identity** — first-contact SSH host-key persistence is required
  before config, and every later mismatch fails closed;
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
  loopback — a deliberate, source-IP-allowlisted ingress). Flow auto also needs
  contemporaneous SNMP corroboration, but deployments must enforce ACL/uRPF
  anti-spoofing because UDP source addresses are not cryptographic identity.
- SNMP v2c provides no wire encryption: its community and telemetry traverse the
  management network in cleartext. Restrict UDP/161 by source/destination ACL,
  isolate that network, use a unique read-only community per device, and migrate
  to SNMPv3 before using an untrusted transport.
- Device SSH supports legacy IOS 15.x and therefore retains SHA-1 KEX/MAC,
  `ssh-rsa`, and CBC fallbacks. Isolate the router management network, prefer
  modern router algorithms where available, and treat this compatibility
  profile as migration debt rather than a general-purpose SSH policy.
- There are no BGP-speaker / Cloudflare / scrubber egress paths in v1.

## Authentication hardening

- TOTP 2FA mandatory for all accounts; first enrollment also requires a separate
  one-time enrollment credential (see [authentication.md](authentication.md)).
- Lock accounts after repeated failed logins; throttle login + 2FA attempts.
- Argon2id password hashing; DB-backed sessions rotated on login (fixation
  protection); `Secure` + `HttpOnly` + `SameSite=Strict` cookies signed with
  `SESSION_SECRET`, plus absolute and idle expiry. Unsafe HTTP methods also
  reject cross-origin and sibling-site browser requests using Fetch Metadata
  plus exact `Origin`/`Host` matching; origin-less operational CLI clients remain
  supported.
- Trust `CF-Connecting-IP` only via the Cloudflare -> Nginx -> loopback path
  (only Cloudflare can reach Nginx; only Nginx can reach the controller).

## Audit

Audit everything: logins, 2FA enrollment/resets, rule edits, reroute lifecycle,
lock changes, credential changes, user management. Audit logs are append-only and
retained per [database.md](database.md) retention policy.
