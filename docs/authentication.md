# Authentication and Two-Factor Authentication

Every UI/API user authenticates with a password and a second factor. The Rust
controller owns password verification, TOTP enrollment, recovery codes, session
revocation, throttling, and audit events.

## Security properties

- Passwords use Argon2id. TOTP secrets and device credentials use AES-256-GCM
  under `SECRETS_KEY`.
- Recovery codes are one-time values stored only as Argon2id hashes in a JSON
  array. They are never recoverable from the database.
- Browser cookies contain only a random session token. The database stores its
  SHA-256 hash; `SESSION_SECRET` signs the cookie. Cookies are `HttpOnly`,
  `Secure` by default, `SameSite=Strict`, and scoped to `/`.
- Unsafe methods reject browser requests marked `same-site` or `cross-site` and
  reject an `Origin` authority that differs from `Host`. This covers hostile
  sibling subdomains in addition to the cookie's cross-site CSRF protection;
  non-browser clients may omit both headers.
- Normal sessions have a 12-hour absolute TTL (7 days with Remember me) and a
  60-minute idle timeout by default. Password-only pre-2FA sessions expire after
  10 minutes. All values are configurable under `[auth]`.
- Login failures are throttled by normalized email and trusted real client IP.
  Account lockout updates are transactional and race-safe.

## Login flow

```text
1. POST /api/auth/login with email, password, and optional Remember me.
2. The controller checks the per-IP throttle and account lock, verifies Argon2id,
   then issues a short-lived pre-2FA session. It never grants API access yet.
3. POST /api/auth/totp with a live six-digit TOTP or an unused recovery code.
4. On success, the same session is promoted to fully authenticated, login state
   is updated, and the normal session cookie lifetime is applied.
5. Logout or an administrator's 2FA reset expires server-side sessions
   immediately; deleting a browser cookie is not the revocation boundary.
```

TOTP uses RFC 6238, SHA-1, six digits, a 30-second period, and a +/-1 step
verification window. An accepted time-step counter is advanced under a user-row
lock, so the same or an older TOTP cannot be replayed concurrently or in another
session. The issuer defaults to `Rerouter`.

## First enrollment

A password alone cannot claim an unconfirmed account's authenticator. User
creation, administrator 2FA reset, and `--create-admin` each generate a separate
high-entropy enrollment code. Only its SHA-256 hash is stored; the plaintext is
shown once and must be delivered out of band.

```text
1. The user signs in with their password and supplies the one-time enrollment code.
2. The controller creates an encrypted, unconfirmed TOTP secret and returns its
   otpauth URI/QR data.
3. The user submits a live authenticator code.
4. The controller confirms TOTP, consumes the enrollment credential, creates
   eight recovery codes, and returns those codes once.
```

Legacy unconfirmed accounts with no enrollment-token hash must be reset by a
superadmin or rotated through `--create-admin` before they can enroll.

## Recovery and reset

- A recovery code is consumed under `SELECT ... FOR UPDATE`, so concurrent
  requests cannot spend the same code twice.
- Successful recovery writes `2fa_recovery_used` to the audit log and queues a
  security alert. Delivery depends on configured alert recipients/channels.
- A superadmin reset clears TOTP and recovery codes, expires all sessions, and
  returns a new one-time enrollment code. The reset and session revocation commit
  atomically with their audit row.

## Step-up for arming

There is no general `/api/auth/reauth` endpoint and reroute previews do not rely
on persisted re-auth state. The two global arming changes, `observe` to `enforce`
and enabling automatic actions, require a fresh password and TOTP in the settings
request itself. Disarming does not. Failed step-up attempts are audited and
rate-limited with the authentication failure controls.

## Audit events

The controller records `login_success`, `login_failed`, `account_locked`,
`2fa_enrolled`, `2fa_enrollment_failed`, `2fa_failed`, `2fa_recovery_used`,
`user_2fa_reset`, `logout`, and persistence-failure variants where applicable.
Events carry the actor/user, trusted client IP, and user-agent when available.

## Proxy trust

Nginx accepts origin traffic only from current Cloudflare ranges while preserving
the connecting proxy in `$remote_addr`. Only after that ACL passes does it forward
Cloudflare's overwritten `CF-Connecting-IP` value to the loopback API. The
controller validates that value as an IP before using it. Never expose the Rust
listener directly or forward the header without the proxy-source ACL. See
[deployment.md](deployment.md).
