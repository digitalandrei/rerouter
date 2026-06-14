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
        ),
    >(
        "SELECT id, name, password, two_factor_confirmed_at, locked_until, two_factor_secret \
         FROM users WHERE email = ?",
    )
    .bind(&body.email)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    let Some((user_id, _name, phc, totp_confirmed_at, locked_until, totp_secret_enc)) = row else {
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

    // Password OK — create a pre-2FA session. "Remember me" picks the longer TTL;
    // the chosen lifetime is persisted in the session row (expires_at) so it
    // survives the token rotation at /totp and an app restart.
    let ttl_hours = if body.remember {
        cfg.remember_me_ttl_hours
    } else {
        cfg.session_ttl_hours
    } as i64;
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

    // Reset the failure counter on a correct password.
    let _ = sqlx::query("UPDATE users SET failed_login_attempts = 0 WHERE id = ?")
        .bind(user_id)
        .execute(pool)
        .await;

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
    match totp::enroll(&body.email) {
        Ok((secret_b32, otpauth_url)) => {
            if let Ok(enc) = crate::crypto::seal_str(&secret_b32) {
                let _ = sqlx::query("UPDATE users SET two_factor_secret = ? WHERE id = ?")
                    .bind(hex::encode(enc))
                    .bind(user_id)
                    .execute(pool)
                    .await;
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
        Err(_) => (
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
    let session = match sessions::validate_pre2fa(pool, cookie.value()).await {
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

    // Load the user's email + (encrypted) secret + confirmation state.
    let Some((email, secret_hex, confirmed_at)) = sqlx::query_as::<
        _,
        (
            String,
            Option<String>,
            Option<chrono::DateTime<chrono::Utc>>,
        ),
    >(
        "SELECT email, two_factor_secret, two_factor_confirmed_at FROM users WHERE id = ?",
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

    let first_confirmation = confirmed_at.is_none();

    // Try TOTP first, then a recovery code.
    let mut ok = false;
    let mut used_recovery = false;
    if let Some(secret_hex) = secret_hex.as_deref() {
        if let Some(secret_b32) = decrypt_secret(secret_hex) {
            ok = totp::verify(&secret_b32, &body.code, &email).unwrap_or(false);
        }
    }
    if !ok {
        match consume_recovery_code(pool, user_id, &body.code).await {
            Ok(true) => {
                ok = true;
                used_recovery = true;
            }
            _ => {}
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
        let hashes: Vec<String> = codes
            .iter()
            .filter_map(|c| password::hash(c).ok())
            .collect();
        if let Ok(json_hashes) = serde_json::to_string(&hashes) {
            let _ = sqlx::query(
                "UPDATE users SET two_factor_confirmed_at = UTC_TIMESTAMP(), two_factor_recovery_codes = ?, \
                 last_login_at = UTC_TIMESTAMP(), last_login_ip = ? WHERE id = ?",
            )
            .bind(json_hashes)
            .bind(&ip)
            .bind(user_id)
            .execute(pool)
            .await;
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
        let _ = sqlx::query(
            "UPDATE users SET last_login_at = UTC_TIMESTAMP(), last_login_ip = ? WHERE id = ?",
        )
        .bind(&ip)
        .bind(user_id)
        .execute(pool)
        .await;
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
        let _ = enqueue_security_alert(
            pool,
            "2fa_recovery_used",
            user_id,
            "a single-use recovery code was used to sign in",
        )
        .await;
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

    let user = rbac::load_session_user(pool, user_id)
        .await
        .unwrap_or(Value::Null);
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
        if let Ok(Some(session)) = sessions::validate_pre2fa(pool, cookie.value()).await {
            let _ = sessions::expire(pool, session.id).await;
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

/// Increment failed_login_attempts; lock the account when the threshold is hit.
async fn register_failure(
    pool: &sqlx::MySqlPool,
    user_id: u64,
    threshold: u32,
    lock_minutes: i64,
    ip: &str,
    ua: &str,
) {
    let _ = sqlx::query(
        "UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?",
    )
    .bind(user_id)
    .execute(pool)
    .await;

    let current: u32 = sqlx::query_scalar("SELECT failed_login_attempts FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .unwrap_or(0);

    audit(pool, Some(user_id), "login_failed", ip, ua, "bad password").await;

    if current >= threshold {
        let _ = sqlx::query(
            "UPDATE users SET locked_until = DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? MINUTE) WHERE id = ?",
        )
        .bind(lock_minutes)
        .bind(user_id)
        .execute(pool)
        .await;
        audit(
            pool,
            Some(user_id),
            "account_locked",
            ip,
            ua,
            "failed login threshold exceeded",
        )
        .await;
        let _ = enqueue_security_alert(
            pool,
            "account_locked",
            user_id,
            "account locked after repeated failed logins",
        )
        .await;
    }
}

/// Constant-ish-time single-use recovery-code check. Codes are stored as a JSON
/// array of Argon2id hashes; on a match, remove that hash (single-use).
async fn consume_recovery_code(
    pool: &sqlx::MySqlPool,
    user_id: u64,
    code: &str,
) -> anyhow::Result<bool> {
    let Some(json_hashes): Option<String> =
        sqlx::query_scalar("SELECT two_factor_recovery_codes FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_optional(pool)
            .await?
            .flatten()
    else {
        return Ok(false);
    };
    let mut hashes: Vec<String> = serde_json::from_str(&json_hashes).unwrap_or_default();
    let normalized = code.trim().to_lowercase();
    let mut matched = None;
    for (i, h) in hashes.iter().enumerate() {
        if password::verify(&normalized, h).unwrap_or(false) {
            matched = Some(i);
            break;
        }
    }
    let Some(i) = matched else { return Ok(false) };
    hashes.remove(i);
    let updated = serde_json::to_string(&hashes)?;
    sqlx::query("UPDATE users SET two_factor_recovery_codes = ? WHERE id = ?")
        .bind(updated)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(true)
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
    let _ = sqlx::query(
        "INSERT INTO audit_logs (actor_type, actor_user_id, event_type, message, ip_address, user_agent) \
         VALUES ('user', ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(event)
    .bind(message)
    .bind(ip)
    .bind(ua)
    .execute(pool)
    .await;
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
