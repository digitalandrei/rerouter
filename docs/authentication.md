# Authentication & Two-Factor (2FA)

Users must log in to view data. Login is **password + TOTP 2FA**. This document
covers the login flow, TOTP enrollment, recovery codes, and lockout.

## Stack

- Authentication lives in the Rust controller (`rerouter-controller`, axum):
  session auth backed by a DB `sessions` table, with secure + httponly + SameSite
  cookies signed with `SESSION_SECRET`.
- Password hashing with **Argon2id**.
- TOTP via `totp-rs` — RFC 6238, 30s step, SHA-1, 6 digits, issuer "Rerouter",
  compatible with Google Authenticator / Authy / 1Password.
- MariaDB stores users, sessions, and 2FA material (encrypted secret + hashed
  recovery codes). The schema is owned by sqlx migrations in
  `backend-rust/migrations/`.
- The SPA (see [architecture.md](architecture.md)) talks to the auth endpoints
  (`/api/auth/login`, `/api/auth/totp`, `/api/auth/logout`, `/api/auth/me`)
  with credentialed fetch; the session cookie is the only client-side state.

## User table additions

On top of the standard `users` columns:

```text
two_factor_secret            (encrypted, nullable)
two_factor_recovery_codes    (encrypted JSON array, nullable)
two_factor_confirmed_at      (timestamp, nullable)
two_factor_enforced          (bool, default true)
failed_login_attempts        (int, default 0)
locked_until                 (timestamp, nullable)
last_login_at                (timestamp, nullable)
last_login_ip                (varchar)   -- CF-Connecting-IP
```

## Login flow

```text
1. POST /api/auth/login (email + password) over HTTPS (Cloudflare -> Nginx -> controller).
2. Throttle by email + real IP. On repeated failure, increment
   failed_login_attempts; lock account when threshold exceeded.
3. If password OK and 2FA confirmed -> respond with a TOTP challenge.
4. POST /api/auth/totp; verify within the allowed window (±1 step). On success,
   create a `sessions` row, issue the session cookie, record
   last_login_at / last_login_ip, reset failed_login_attempts.
5. If 2FA not yet enrolled -> force enrollment before granting access
   (the SPA's /login page runs first-login enrollment).
```

## TOTP enrollment

```text
1. Generate a random base32 secret; store encrypted (unconfirmed).
2. Show otpauth:// QR for issuer "Rerouter" + the user's email.
3. User submits a code from their authenticator.
4. On verify, set two_factor_confirmed_at and generate 8 single-use recovery
   codes (show once, store hashed).
```

## Recovery codes

- 8 codes, single-use, stored hashed (encrypted JSON of hashes).
- Using a recovery code consumes it and should email the user (security event).
- Admins can reset a user's 2FA (audited); reset forces re-enrollment at next login.

## Audit events

`login_success`, `login_failed`, `account_locked`, `2fa_enrolled`,
`2fa_failed`, `2fa_recovery_used`, `2fa_reset_by_admin`, `logout`. Each carries
actor, real client IP, and user-agent.

## Cloudflare note

Because the app is proxied, the real client IP arrives in `CF-Connecting-IP`.
Throttling, lockout, and audit must use that header. The controller trusts it
because the only path to it is Cloudflare -> Nginx (origin locked to Cloudflare
IP ranges) -> loopback proxy to `127.0.0.1:9277`; only Cloudflare can reach
Nginx and only Nginx can reach the controller. See
[deployment.md](deployment.md).
