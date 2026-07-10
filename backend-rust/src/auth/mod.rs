//! Authentication owned by the controller: session cookies backed by the DB
//! `sessions` table, Argon2id password hashing, TOTP 2FA, single-use recovery
//! codes, and login throttling/lockout. See ../docs/authentication.md.
//!
//! Invariants:
//!   * login is password + TOTP; first login forces TOTP enrollment;
//!   * throttle/lockout by email + real client IP (CF-Connecting-IP, trusted
//!     because only Cloudflare reaches Nginx and only Nginx reaches us);
//!   * recovery codes are single-use and stored hashed;
//!   * every auth event is audited with actor, real IP, and user-agent.

pub mod password;
pub mod rbac;
pub mod sessions;
pub mod totp;

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::{Key, SignedCookieJar};
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;

use crate::api::{client_ip, user_agent, AppState};
use sessions::Session;

/// Router for /api/auth/*, nested by the API route table.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/login", post(login))
        .route("/totp", post(totp_challenge))
        .route("/logout", post(logout))
        .route("/me", get(me))
}

type JsonResp = (StatusCode, Json<Value>);

#[derive(Debug, Deserialize)]
struct LoginBody {
    email: String,
    password: String,
    /// "Remember me" — use the longer remember-me TTL (default 7 days).
    #[serde(default)]
    remember: bool,
    /// Independent one-time code issued by an administrator for first enrollment.
    #[serde(default)]
    enrollment_code: Option<String>,
}

/// POST /api/auth/login — verify email + password (throttled by email + real
/// client IP), create a PRE-2FA session, and return a TOTP challenge. If the
/// user has no confirmed TOTP, return an enrollment challenge and persist the
/// (unconfirmed) secret. Never reveals whether the email exists.
async fn login(
    State(state): State<AppState>,
    jar: SignedCookieJar<Key>,
    headers: HeaderMap,
    ConnectInfo(socket): ConnectInfo<SocketAddr>,
    Json(body): Json<LoginBody>,
) -> (SignedCookieJar<Key>, JsonResp) {
    let pool = &state.pool;
    let ip = client_ip(&headers, Some(&socket));
    let ua = user_agent(&headers);
    let cfg = &state.config.auth;
    let email = body.email.trim().to_lowercase();

    if ip_throttled(pool, &ip, cfg.lockout_threshold, cfg.lockout_minutes as i64).await {
        return (
            jar,
            (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({ "error": "too_many_attempts" })),
            ),
        );
    }

    // Generic failure response — identical for unknown email and bad password.
    let deny = |jar: SignedCookieJar<Key>| {
        (
            jar,
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid_credentials" })),
            ),
        )
    };

    // Load the user (and lock/2FA state) by email. TIMESTAMP columns decode as
    // DateTime<Utc> (sqlx-mysql maps NaiveDateTime only to DATETIME).
    let row = sqlx::query_as::<
        _,
        (
            u64,
            String,
            String,
            Option<chrono::DateTime<chrono::Utc>>,
            Option<chrono::DateTime<chrono::Utc>>,
            Option<String>,
            Option<String>,
        ),
    >(
        "SELECT id, name, password, two_factor_confirmed_at, locked_until, two_factor_secret, \
                two_factor_enrollment_token_hash \
         FROM users WHERE email = ?",
    )
    .bind(&email)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    let Some((
        user_id,
        _name,
        phc,
        totp_confirmed_at,
        locked_until,
        totp_secret_enc,
        enrollment_token_hash,
    )) = row
    else {
        // Unknown email: same shape + timing-ish as a wrong password.
        let _ = password::verify(&body.password, DUMMY_PHC);
        audit(pool, None, "login_failed", &ip, &ua, "unknown email").await;
        return deny(jar);
    };

    // Lockout check (email + IP throttle expressed as a per-account lock window).
    if let Some(until) = locked_until {
        if until > chrono::Utc::now() {
            audit(
                pool,
                Some(user_id),
                "login_failed",
                &ip,
                &ua,
                "account locked",
            )
            .await;
            return (
                jar,
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({ "error": "account_locked" })),
                ),
            );
        }
    }

    // Verify the password.
    if !password::verify(&body.password, &phc).unwrap_or(false) {
        register_failure(
            pool,
            user_id,
            cfg.lockout_threshold,
            cfg.lockout_minutes as i64,
            &ip,
            &ua,
        )
        .await;
        return deny(jar);
    }

    // First TOTP enrollment requires a second high-entropy code delivered by
    // the administrator. This keeps a leaked temporary password from claiming
    // the account and locking out its intended owner.
    if totp_confirmed_at.is_none() {
        let supplied = body.enrollment_code.as_deref().map(str::trim);
        let enrollment_ok =
            supplied
                .zip(enrollment_token_hash.as_deref())
                .is_some_and(|(code, expected)| {
                    !code.is_empty() && sessions::hash_token(code) == expected
                });
        if !enrollment_ok {
            audit(
                pool,
                Some(user_id),
                "2fa_enrollment_failed",
                &ip,
                &ua,
                "missing or invalid enrollment code",
            )
            .await;
            bump_failure_and_maybe_lock(
                pool,
                user_id,
                cfg.lockout_threshold,
                cfg.lockout_minutes as i64,
                &ip,
                &ua,
            )
            .await;
            return (
                jar,
                (
                    StatusCode::FORBIDDEN,
                    Json(json!({ "error": "enrollment_code_required" })),
                ),
            );
        }
    }

    // Password OK — create a pre-2FA session. "Remember me" picks the longer TTL;
    // the chosen lifetime is persisted in the session row (expires_at) so it
    // survives the token rotation at /totp and an app restart.
    let ttl_hours = if body.remember {
        cfg.remember_me_ttl_hours
    } else {
        cfg.session_ttl_hours
    } as i64;
    if sessions::expire_unverified_for_user(pool, user_id)
        .await
        .is_err()
    {
        return (
            jar,
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "session_create_failed" })),
            ),
        );
    }
    let (_session_id, token) = match sessions::create(pool, user_id, &ip, &ua, ttl_hours).await {
        Ok(v) => v,
        Err(_) => {
            return (
                jar,
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "session_create_failed" })),
                ),
            )
        }
    };
    let jar = jar.add(sessions::build_cookie(
        token,
        time::Duration::hours(ttl_hours),
    ));

    let confirmed = totp_confirmed_at.is_some() && totp_secret_enc.is_some();
    if confirmed {
        audit(
            pool,
            Some(user_id),
            "login_success",
            &ip,
            &ua,
            "password ok; awaiting totp",
        )
        .await;
        return (
            jar,
            (StatusCode::OK, Json(json!({ "totp_required": true }))),
        );
    }

    // No confirmed TOTP -> enrollment. Generate + persist an UNCONFIRMED secret
    // (encrypted). The SPA renders otpauth_url as a QR; secret shown for manual
    // entry. two_factor_confirmed_at stays NULL until /totp succeeds.
    let enrollment = totp_secret_enc
        .as_deref()
        .and_then(decrypt_secret)
        .and_then(|secret| {
            totp::enrollment_for_secret(&secret, &email)
                .ok()
                .map(|url| (secret, url, false))
        })
        .or_else(|| {
            totp::enroll(&email)
                .ok()
                .map(|(secret, url)| (secret, url, true))
        });
    match enrollment {
        Some((secret_b32, otpauth_url, is_new)) => {
            if is_new {
                let Ok(enc) = crate::crypto::seal_str(&secret_b32) else {
                    return (
                        jar,
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({ "error": "enrollment_failed" })),
                        ),
                    );
                };
                if sqlx::query("UPDATE users SET two_factor_secret = ? WHERE id = ?")
                    .bind(hex::encode(enc))
                    .bind(user_id)
                    .execute(pool)
                    .await
                    .is_err()
                {
                    return (
                        jar,
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({ "error": "enrollment_failed" })),
                        ),
                    );
                }
            }
            audit(
                pool,
                Some(user_id),
                "login_success",
                &ip,
                &ua,
                "password ok; totp enrollment required",
            )
            .await;
            (
                jar,
                (
                    StatusCode::OK,
                    Json(json!({
                        "totp_required": true,
                        "totp_enrollment": { "otpauth_url": otpauth_url, "secret": secret_b32 }
                    })),
                ),
            )
        }
        None => (
            jar,
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "enrollment_failed" })),
            ),
        ),
    }
}

#[derive(Debug, Deserialize)]
struct TotpBody {
    code: String,
}

/// POST /api/auth/totp — complete 2FA. Verify the TOTP code (±1 step) against the
/// stored secret, OR consume a single-use recovery code. On success: mark the
/// session totp_verified, rotate the session id, set two_factor_confirmed_at on
/// first confirmation, generate recovery codes on first enrollment, and return
/// the SessionUser. Operates on the PRE-2FA session created by /login.
async fn totp_challenge(
    State(state): State<AppState>,
    jar: SignedCookieJar<Key>,
    headers: HeaderMap,
    ConnectInfo(socket): ConnectInfo<SocketAddr>,
    Json(body): Json<TotpBody>,
) -> (SignedCookieJar<Key>, JsonResp) {
    let pool = &state.pool;
    let ip = client_ip(&headers, Some(&socket));
    let ua = user_agent(&headers);
    let cfg = &state.config.auth;

    if ip_throttled(pool, &ip, cfg.lockout_threshold, cfg.lockout_minutes as i64).await {
        return (
            jar,
            (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({ "error": "too_many_attempts" })),
            ),
        );
    }

    // Load the pre-2FA session from the cookie.
    let Some(cookie) = jar.get(sessions::SESSION_COOKIE) else {
        return (
            jar,
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "no_session" })),
            ),
        );
    };
    let session =
        match sessions::validate_pre2fa(pool, cookie.value(), cfg.pre_2fa_ttl_minutes).await {
            Ok(Some(s)) => s,
            _ => {
                return (
                    jar,
                    (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({ "error": "invalid_session" })),
                    ),
                )
            }
        };
    let user_id = session.user_id;

    // Load the user's email + (encrypted) secret + confirmation + lock state.
    let Some((email, secret_hex, confirmed_at, locked_until)) = sqlx::query_as::<
        _,
        (
            String,
            Option<String>,
            Option<chrono::DateTime<chrono::Utc>>,
            Option<chrono::DateTime<chrono::Utc>>,
        ),
    >(
        "SELECT email, two_factor_secret, two_factor_confirmed_at, locked_until FROM users WHERE id = ?",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten() else {
        return (
            jar,
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid_session" })),
            ),
        );
    };

    // Throttle the 2FA step too: a correct password must not buy unlimited TOTP
    // guesses. Failures below bump the SAME per-user counter as the password step
    // and lock the account at the threshold; a locked account is refused here as
    // well, so brute-forcing the 6-digit code locks out like a bad password does.
    if let Some(until) = locked_until {
        if until > chrono::Utc::now() {
            audit(
                pool,
                Some(user_id),
                "2fa_failed",
                &ip,
                &ua,
                "account locked",
            )
            .await;
            return (
                jar,
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({ "error": "account_locked" })),
                ),
            );
        }
    }

    let first_confirmation = confirmed_at.is_none();

    // Try TOTP first, then a recovery code.
    let mut ok = false;
    let mut used_recovery = false;
    if let Some(secret_hex) = secret_hex.as_deref() {
        if let Some(secret_b32) = decrypt_secret(secret_hex) {
            match consume_totp_step(pool, user_id, &secret_b32, &body.code, &email).await {
                Ok(value) => ok = value,
                Err(e) => {
                    tracing::error!(event_type = "totp_replay_state_failed", user_id, error = %e, "could not verify and consume TOTP step");
                    return (
                        jar,
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({ "error": "2fa_verify_failed" })),
                        ),
                    );
                }
            }
        }
    }
    if !ok {
        if let Ok(true) = consume_recovery_code(pool, user_id, &body.code).await {
            ok = true;
            used_recovery = true;
        }
    }

    if !ok {
        audit(
            pool,
            Some(user_id),
            "2fa_failed",
            &ip,
            &ua,
            "invalid totp/recovery code",
        )
        .await;
        bump_failure_and_maybe_lock(
            pool,
            user_id,
            cfg.lockout_threshold,
            cfg.lockout_minutes as i64,
            &ip,
            &ua,
        )
        .await;
        return (
            jar,
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid_code" })),
            ),
        );
    }

    // Success. Rotate the session token and mark it verified.
    let new_token = match sessions::mark_totp_verified_and_rotate(pool, session.id).await {
        Ok(t) => t,
        Err(_) => {
            return (
                jar,
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "session_update_failed" })),
                ),
            )
        }
    };
    // Keep the cookie's lifetime aligned with the session row (which already
    // encodes the remember-me choice made at /login).
    let remaining = (session.expires_at - chrono::Utc::now())
        .num_seconds()
        .max(60);
    let jar = jar.add(sessions::build_cookie(
        new_token,
        time::Duration::seconds(remaining),
    ));

    // First confirmation: stamp two_factor_confirmed_at + issue recovery codes.
    let mut new_recovery_codes: Option<Vec<String>> = None;
    if first_confirmation {
        let codes = totp::generate_recovery_codes();
        let hashes: anyhow::Result<Vec<String>> = codes.iter().map(|c| password::hash(c)).collect();
        let stored = if let Ok(json_hashes) =
            hashes.and_then(|h| serde_json::to_string(&h).map_err(anyhow::Error::from))
        {
            sqlx::query(
                "UPDATE users SET two_factor_confirmed_at = UTC_TIMESTAMP(), \
                 two_factor_enrollment_token_hash = NULL, two_factor_recovery_codes = ?, \
                 failed_login_attempts = 0, locked_until = NULL, \
                 last_login_at = UTC_TIMESTAMP(), last_login_ip = ? WHERE id = ?",
            )
            .bind(json_hashes)
            .bind(&ip)
            .bind(user_id)
            .execute(pool)
            .await
            .is_ok()
        } else {
            false
        };
        if !stored {
            if let Err(e) = sessions::expire(pool, session.id).await {
                tracing::error!(event_type = "failed_session_revoke_failed", session_id = session.id, error = %e, "could not revoke session after 2FA persistence failure");
            }
            return (
                jar.add(sessions::removal_cookie()),
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "2fa_persist_failed" })),
                ),
            );
        }
        new_recovery_codes = Some(codes);
        audit(
            pool,
            Some(user_id),
            "2fa_enrolled",
            &ip,
            &ua,
            "totp confirmed; recovery codes issued",
        )
        .await;
    } else {
        if sqlx::query(
            "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, \
             last_login_at = UTC_TIMESTAMP(), last_login_ip = ? WHERE id = ?",
        )
        .bind(&ip)
        .bind(user_id)
        .execute(pool)
        .await
        .is_err()
        {
            if let Err(e) = sessions::expire(pool, session.id).await {
                tracing::error!(event_type = "failed_session_revoke_failed", session_id = session.id, error = %e, "could not revoke session after login persistence failure");
            }
            return (
                jar.add(sessions::removal_cookie()),
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "login_persist_failed" })),
                ),
            );
        }
    }

    if used_recovery {
        // Security event — always sent immediately (super::alerts ALWAYS_IMMEDIATE).
        audit(
            pool,
            Some(user_id),
            "2fa_recovery_used",
            &ip,
            &ua,
            "recovery code consumed",
        )
        .await;
        if let Err(e) = enqueue_security_alert(
            pool,
            "2fa_recovery_used",
            user_id,
            "a single-use recovery code was used to sign in",
        )
        .await
        {
            tracing::error!(event_type = "security_alert_enqueue_failed", user_id, alert = "2fa_recovery_used", error = %e, "could not enqueue recovery-code-use alert");
        }
    }
    audit(
        pool,
        Some(user_id),
        "login_success",
        &ip,
        &ua,
        "2fa complete",
    )
    .await;

    let user = match rbac::load_session_user(pool, user_id).await {
        Ok(user) => user,
        Err(_) => {
            if let Err(e) = sessions::expire(pool, session.id).await {
                tracing::error!(event_type = "failed_session_revoke_failed", session_id = session.id, error = %e, "could not revoke session after user lookup failure");
            }
            return (
                jar.add(sessions::removal_cookie()),
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "user_lookup_failed" })),
                ),
            );
        }
    };
    let mut resp = json!({ "user": user });
    if let Some(codes) = new_recovery_codes {
        resp["recovery_codes"] = json!(codes); // shown once
    }
    (jar, (StatusCode::OK, Json(resp)))
}

/// POST /api/auth/logout — expire the DB session and clear the cookie.
async fn logout(
    State(state): State<AppState>,
    jar: SignedCookieJar<Key>,
    headers: HeaderMap,
    ConnectInfo(socket): ConnectInfo<SocketAddr>,
) -> (SignedCookieJar<Key>, JsonResp) {
    let pool = &state.pool;
    if let Some(cookie) = jar.get(sessions::SESSION_COOKIE) {
        match sessions::validate(pool, cookie.value(), state.config.auth.idle_timeout_minutes).await
        {
            Ok(Some(session)) => {
                if sessions::expire(pool, session.id).await.is_err() {
                    return (
                        jar.add(sessions::removal_cookie()),
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({ "error": "logout_revoke_failed" })),
                        ),
                    );
                }
                let ip = client_ip(&headers, Some(&socket));
                let ua = user_agent(&headers);
                audit(
                    pool,
                    Some(session.user_id),
                    "logout",
                    &ip,
                    &ua,
                    "session expired",
                )
                .await;
            }
            Ok(None) => {}
            Err(_) => {
                return (
                    jar.add(sessions::removal_cookie()),
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": "logout_revoke_failed" })),
                    ),
                );
            }
        }
    }
    let jar = jar.add(sessions::removal_cookie());
    (jar, (StatusCode::OK, Json(json!({ "ok": true }))))
}

/// GET /api/auth/me — the current SessionUser, or 401. Requires a fully verified
/// session (the Session extractor enforces totp_verified).
async fn me(State(state): State<AppState>, session: Session) -> JsonResp {
    match rbac::load_session_user(&state.pool, session.user_id).await {
        Ok(user) => (StatusCode::OK, Json(user)),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "lookup_failed" })),
        ),
    }
}

// ---- helpers -------------------------------------------------------------------

/// A fixed valid Argon2id PHC string used to spend ~equal CPU when the email is
/// unknown, so login timing does not leak account existence.
const DUMMY_PHC: &str =
    "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";

/// Decrypt a hex-encoded sealed TOTP secret back to base32.
fn decrypt_secret(secret_hex: &str) -> Option<String> {
    let blob = hex::decode(secret_hex).ok()?;
    crate::crypto::open_str(&blob).ok()
}

/// Password-step failure: audit the bad password, then bump the shared lockout
/// counter.
async fn register_failure(
    pool: &sqlx::MySqlPool,
    user_id: u64,
    threshold: u32,
    lock_minutes: i64,
    ip: &str,
    ua: &str,
) {
    audit(pool, Some(user_id), "login_failed", ip, ua, "bad password").await;
    bump_failure_and_maybe_lock(pool, user_id, threshold, lock_minutes, ip, ua).await;
}

/// Increment failed_login_attempts and lock the account once it reaches
/// `threshold`. Shared by the password step AND the TOTP step so a 6-digit code
/// can't be brute-forced behind a known password. The per-attempt audit event
/// (login_failed / 2fa_failed) is logged by the caller; this adds only the
/// account_locked audit + alert on the locking edge.
async fn bump_failure_and_maybe_lock(
    pool: &sqlx::MySqlPool,
    user_id: u64,
    threshold: u32,
    lock_minutes: i64,
    ip: &str,
    ua: &str,
) {
    let result = async {
        let mut tx = pool.begin().await?;
        let Some((current, locked_until)) =
            sqlx::query_as::<_, (u32, Option<chrono::DateTime<chrono::Utc>>)>(
                "SELECT failed_login_attempts, locked_until FROM users WHERE id = ? FOR UPDATE",
            )
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
        else {
            anyhow::bail!("user disappeared while recording auth failure");
        };
        let next = current.saturating_add(1);
        let now = chrono::Utc::now();
        let was_locked = locked_until.is_some_and(|until| until > now);
        let lock_until =
            (next >= threshold).then(|| now + chrono::Duration::minutes(lock_minutes.max(1)));
        sqlx::query("UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?")
            .bind(next)
            .bind(lock_until)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok::<bool, anyhow::Error>(lock_until.is_some() && !was_locked)
    }
    .await;

    let newly_locked = match result {
        Ok(value) => value,
        Err(e) => {
            tracing::error!(event_type = "auth_lockout_persist_failed", user_id, error = %e, "could not persist authentication failure counter; request remains denied");
            return;
        }
    };

    if newly_locked {
        audit(
            pool,
            Some(user_id),
            "account_locked",
            ip,
            ua,
            "failed auth threshold exceeded",
        )
        .await;
        if let Err(e) = enqueue_security_alert(
            pool,
            "account_locked",
            user_id,
            "account locked after repeated failed auth attempts",
        )
        .await
        {
            tracing::error!(event_type = "security_alert_enqueue_failed", user_id, alert = "account_locked", error = %e, "could not enqueue account-lock alert");
        }
    }
}

/// Real-IP throttle shared by password, TOTP, and recovery-code failures. Account
/// lockout remains separate, so distributing guesses across IPs cannot bypass the
/// per-user counter and distributing users across one IP cannot bypass this gate.
pub(crate) async fn ip_throttled(
    pool: &sqlx::MySqlPool,
    ip: &str,
    threshold: u32,
    window_minutes: i64,
) -> bool {
    if threshold == 0 {
        return false;
    }
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM audit_logs \
         WHERE ip_address = ? AND event_type IN \
             ('login_failed','2fa_failed','2fa_enrollment_failed','settings_reauth_failed') \
           AND created_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? MINUTE)",
    )
    .bind(ip)
    .bind(window_minutes)
    .fetch_one(pool)
    .await
    .unwrap_or(i64::MAX)
        >= threshold as i64
}

/// Single-use recovery-code check, made race-safe. Codes are stored as a JSON
/// array of Argon2id hashes; consuming one is a read → match → write-back of that
/// array, which MUST be atomic or two concurrent requests could both spend the
/// same code. We serialize per user with a transaction + `SELECT ... FOR UPDATE`:
/// the second caller blocks until the first commits, then sees the code already
/// removed and fails to match.
async fn consume_recovery_code(
    pool: &sqlx::MySqlPool,
    user_id: u64,
    code: &str,
) -> anyhow::Result<bool> {
    let mut tx = pool.begin().await?;
    let Some(json_hashes): Option<String> =
        sqlx::query_scalar("SELECT two_factor_recovery_codes FROM users WHERE id = ? FOR UPDATE")
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?
            .flatten()
    else {
        tx.rollback().await?;
        return Ok(false);
    };
    let mut hashes: Vec<String> = serde_json::from_str(&json_hashes)
        .map_err(|e| anyhow::anyhow!("stored recovery-code data is invalid: {e}"))?;
    let normalized = code.trim().to_lowercase();
    let mut matched = None;
    for (i, h) in hashes.iter().enumerate() {
        if password::verify(&normalized, h).unwrap_or(false) {
            matched = Some(i);
            break;
        }
    }
    let Some(i) = matched else {
        tx.rollback().await?;
        return Ok(false);
    };
    hashes.remove(i);
    let updated = serde_json::to_string(&hashes)?;
    sqlx::query("UPDATE users SET two_factor_recovery_codes = ? WHERE id = ?")
        .bind(updated)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}

/// Verify and consume a TOTP time step atomically. A valid code from a step at
/// or before the last accepted step is a replay and is rejected.
async fn consume_totp_step(
    pool: &sqlx::MySqlPool,
    user_id: u64,
    secret_base32: &str,
    code: &str,
    account_email: &str,
) -> anyhow::Result<bool> {
    let Some(step) = totp::matched_step(secret_base32, code, account_email)? else {
        return Ok(false);
    };
    let mut tx = pool.begin().await?;
    let last: Option<u64> =
        sqlx::query_scalar("SELECT last_totp_step FROM users WHERE id = ? FOR UPDATE")
            .bind(user_id)
            .fetch_one(&mut *tx)
            .await?;
    if last.is_some_and(|last| step <= last) {
        tx.rollback().await?;
        return Ok(false);
    }
    let updated = sqlx::query("UPDATE users SET last_totp_step = ? WHERE id = ?")
        .bind(step)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    anyhow::ensure!(
        updated.rows_affected() == 1,
        "user disappeared while consuming TOTP step"
    );
    tx.commit().await?;
    Ok(true)
}

/// Step-up re-authentication for a high-risk admin action (arming the system):
/// verify the user's CURRENT password AND a fresh live TOTP code. Both must pass,
/// so a stolen session alone can't satisfy it. Recovery codes are intentionally
/// NOT accepted here — arming can wait until the operator has their authenticator,
/// and a settings toggle shouldn't burn a single-use recovery code.
/// Returns Ok(false) on any missing factor / mismatch; Err only on a DB error.
pub async fn verify_step_up(
    pool: &sqlx::MySqlPool,
    user_id: u64,
    password: &str,
    totp_code: &str,
) -> anyhow::Result<bool> {
    let Some((email, phc, secret_hex)) = sqlx::query_as::<_, (String, String, Option<String>)>(
        "SELECT email, password, two_factor_secret FROM users WHERE id = ?",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await?
    else {
        return Ok(false);
    };
    if !password::verify(password, &phc).unwrap_or(false) {
        return Ok(false);
    }
    let Some(secret_hex) = secret_hex.as_deref() else {
        return Ok(false); // 2FA not enrolled — cannot step up
    };
    let Some(secret_b32) = decrypt_secret(secret_hex) else {
        return Ok(false);
    };
    consume_totp_step(pool, user_id, &secret_b32, totp_code, &email).await
}

/// Insert an audit_logs row (best-effort; auth must not fail because audit did).
async fn audit(
    pool: &sqlx::MySqlPool,
    user_id: Option<u64>,
    event: &str,
    ip: &str,
    ua: &str,
    message: &str,
) {
    if let Err(e) = sqlx::query(
        "INSERT INTO audit_logs (actor_type, actor_user_id, event_type, message, ip_address, user_agent) \
         VALUES ('user', ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(event)
    .bind(message)
    .bind(ip)
    .bind(ua)
    .execute(pool)
    .await
    {
        tracing::error!(event_type = "auth_audit_persist_failed", audited_event = event, actor_user_id = user_id, error = %e, "could not persist authentication audit event");
    }
}

/// Enqueue a security alert (always-immediate event types). Recipient is the
/// user's own email when present; the dispatcher also fans critical events to
/// admins. dedup_key namespaces by event+user.
async fn enqueue_security_alert(
    pool: &sqlx::MySqlPool,
    event_type: &str,
    user_id: u64,
    message: &str,
) -> anyhow::Result<()> {
    let payload = json!({ "message": message, "user_id": user_id });
    let dedup_key = format!("{event_type}:user:{user_id}");
    sqlx::query(
        "INSERT INTO alerts (event_type, severity, payload_json, dedup_key) VALUES (?, 'critical', ?, ?)",
    )
    .bind(event_type)
    .bind(payload)
    .bind(dedup_key)
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::consume_totp_step;

    #[tokio::test]
    async fn accepted_totp_step_cannot_be_replayed() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let pool = sqlx::mysql::MySqlPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .expect("connect to DATABASE_URL");
        crate::db::migrate_test_schema(&pool)
            .await
            .expect("run migrations");

        let email = format!("totp-replay-{}@example.test", uuid::Uuid::new_v4());
        let user_id = sqlx::query(
            "INSERT INTO users (name, email, password) VALUES ('TOTP replay test', ?, 'unused')",
        )
        .bind(&email)
        .execute(&pool)
        .await
        .expect("insert test user")
        .last_insert_id();
        let (secret, _) = super::totp::enroll(&email).expect("create TOTP secret");
        let code = super::totp::current_code(&secret, &email).expect("generate current TOTP");

        assert!(consume_totp_step(&pool, user_id, &secret, &code, &email)
            .await
            .expect("consume first TOTP"));
        assert!(!consume_totp_step(&pool, user_id, &secret, &code, &email)
            .await
            .expect("reject replayed TOTP"));

        sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("remove test user");
    }
}
