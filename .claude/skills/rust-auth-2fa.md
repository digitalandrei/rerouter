---
name: rust-auth-2fa
description: Patterns for authentication in the Rerouter controller — DB-backed session cookies, Argon2id passwords, enrollment-code-bound TOTP, single-use recovery codes, login throttling/lockout, RBAC, and security alerts. Use for backend-rust/ auth and alert-delivery work.
---

# Skill: Rust auth + 2FA (Rerouter controller)

The controller owns authentication end to end. See
[authentication.md](../../docs/authentication.md) for the flow and
[security.md](../../docs/security.md) for the threat model.

## Sessions

- Session cookies are backed by the DB `sessions` table. The browser receives an
  opaque random token in an `HttpOnly`, `Secure`, `SameSite=Strict` cookie signed
  with `SESSION_SECRET`; the database stores only its SHA-256 hash.
- An axum middleware/extractor resolves the cookie to a session row + user on
  every request. Password-only pre-2FA sessions expire after 10 minutes; normal
  sessions have a configurable 60-minute idle timeout and absolute expiry.

## Passwords (Argon2id)

- Hash with the `argon2` crate, **Argon2id**, a fresh per-user random salt
  (stored in the PHC string); verify via the crate, never by string compare.
- Uniform error for "no such user" vs "wrong password".

## TOTP 2FA (totp-rs)

- RFC 6238: 30s period, 6 digits, issuer **Rerouter** (`TWO_FACTOR_ISSUER`).
- Verify with a **±1 step window** to absorb clock skew; reject code reuse
  within the window.
- Enrollment requires a separate high-entropy, one-use enrollment code generated
  by user creation, an administrator reset, or `--create-admin`. Store only its
  SHA-256 hash. After it is supplied, generate the secret, return the otpauth URL,
  and require one valid TOTP before granting app access.
- **Recovery codes**: 8 random single-use codes, shown once, stored **hashed**;
  mark each consumed on use; regenerating a set invalidates the old one.

## Throttling & lockout

- Key failure counters by **email + real client IP**. The real IP is
  `CF-Connecting-IP`, forwarded by Nginx and trustworthy because the origin is
  locked to Cloudflare ranges and only Nginx can reach the controller.
- Throttle attempts, lock the account after repeated failures, and never leak
  lockout state differently from a wrong password.

## Reroute confirmation

There is no re-auth endpoint. Manual actions, rule applies, and rollbacks use a
server-rendered dry run followed by a short-lived one-use preview token bound to
the user, action identity, and plan hash. The execution endpoint recomputes and
compares the plan before consuming the token.

## RBAC

- Explicit `roles` / `permissions` / `role_user` / `permission_role` tables;
  roles superadmin/admin/operator/viewer/auditor.
- Enforce per-permission via axum extractors/middleware (e.g. a
  `RequirePermission("edit_rules")` layer on the route); deny by default —
  see the permission map in [security.md](../../docs/security.md).

## SMTP mailer (lettre)

- `lettre` with the rustls SMTP transport, configured from
  `SMTP_HOST`/`SMTP_PORT`/`SMTP_USERNAME`/`SMTP_PASSWORD`/`SMTP_FROM`.
- Used by the in-process **alert dispatcher** task: reads new `alerts` rows,
  resolves recipients, de-dups / rate-limits, sends, records `alert_deliveries`
  (see [email-alerts.md](../../docs/email-alerts.md)). `reroute_uncertain`,
  `reroute_failed`, and security events go out immediately, never collapsed.

## Audit everything

Write an `audit_logs` row — actor, real IP, user-agent — for every auth event:
login success/failure, TOTP success/failure, enrollment, recovery-code use,
lockout, logout, password changes, and user/role management.
