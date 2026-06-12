---
name: rust-auth-2fa
description: Patterns for authentication in the Rerouter controller — DB-backed session cookies, Argon2id password hashing, TOTP 2FA with totp-rs, single-use recovery codes, login throttling/lockout, RBAC extractors, the re-auth gate for high-safety reroutes, and the lettre SMTP mailer. Use for backend-rust/ auth and alert-delivery work.
---

# Skill: Rust auth + 2FA (Rerouter controller)

The controller owns authentication end to end. See
[../docs/authentication.md](../docs/authentication.md) for the flow and
[../docs/security.md](../docs/security.md) for the threat model.

## Sessions

- Session cookies backed by the DB `sessions` table (id, user, created/expires,
  IP, user-agent). Opaque random token in an `HttpOnly` + `Secure` + `SameSite`
  cookie, signed with `SESSION_SECRET`.
- An axum middleware/extractor resolves the cookie to a session row + user on
  every request; rotate the session id on login, delete the row on logout,
  expire idle sessions server-side.

## Passwords (Argon2id)

- Hash with the `argon2` crate, **Argon2id**, a fresh per-user random salt
  (stored in the PHC string); verify via the crate, never by string compare.
- Uniform error for "no such user" vs "wrong password".

## TOTP 2FA (totp-rs)

- RFC 6238: 30s period, 6 digits, issuer **Rerouter** (`TWO_FACTOR_ISSUER`).
- Verify with a **±1 step window** to absorb clock skew; reject code reuse
  within the window.
- Enrollment on first login: generate the secret, return the otpauth URL for the
  QR, require one valid code to confirm — block all app access until enrolled
  and confirmed. 2FA is mandatory for every user.
- **Recovery codes**: 8 random single-use codes, shown once, stored **hashed**;
  mark each consumed on use; regenerating a set invalidates the old one.

## Throttling & lockout

- Key failure counters by **email + real client IP**. The real IP is
  `CF-Connecting-IP`, forwarded by Nginx and trustworthy because the origin is
  locked to Cloudflare ranges and only Nginx can reach the controller.
- Throttle attempts, lock the account after repeated failures, and never leak
  lockout state differently from a wrong password.

## Re-auth for high-safety reroutes

`POST /api/auth/reauth` takes password + current TOTP and grants a short-lived
re-auth mark on the session. The reroute engine requires it (plus typed
confirmation + reason) immediately before executing a high-safety-level manual
reroute, and records it in the audit log.

## RBAC

- Explicit `roles` / `permissions` / `role_user` / `permission_role` tables;
  roles admin/operator/viewer/auditor.
- Enforce per-permission via axum extractors/middleware (e.g. a
  `RequirePermission("edit_rules")` layer on the route); deny by default —
  see the permission map in [../docs/security.md](../docs/security.md).

## SMTP mailer (lettre)

- `lettre` with the rustls SMTP transport, configured from
  `SMTP_HOST`/`SMTP_PORT`/`SMTP_USERNAME`/`SMTP_PASSWORD`/`SMTP_FROM`.
- Used by the in-process **alert dispatcher** task: reads new `alerts` rows,
  resolves recipients, de-dups / rate-limits, sends, records `alert_deliveries`
  (see [../docs/email-alerts.md](../docs/email-alerts.md)). `reroute_uncertain`,
  `reroute_failed`, and security events go out immediately, never collapsed.

## Audit everything

Write an `audit_logs` row — actor, real IP, user-agent — for every auth event:
login success/failure, TOTP success/failure, enrollment, recovery-code use,
lockout, logout, re-auth, password changes, and user/role management.
