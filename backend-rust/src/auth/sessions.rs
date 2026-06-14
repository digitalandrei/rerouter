//! DB-backed sessions (`sessions` table). The browser cookie carries only a
//! random token (signed with SESSION_SECRET via axum-extra's SignedCookieJar);
//! the DB row holds the SHA-256 hash, the user, TOTP/re-auth state, and the
//! expiry. Server-side revocation is therefore immediate. The SPA talks to
//! /api/ with credentialed fetch; the cookie is HttpOnly + Secure + SameSite=Lax.

use anyhow::{Context, Result};
use axum::extract::FromRequestParts;
use axum::http::{request::Parts, StatusCode};
use axum_extra::extract::cookie::{Cookie, Key, SameSite, SignedCookieJar};
use chrono::{DateTime, Duration, Utc};
use rand::distr::{Alphanumeric, SampleString};
use sqlx::MySqlPool;

use crate::api::AppState;

pub const SESSION_COOKIE: &str = "rerouter_session";

/// An authenticated session, extracted from the cookie on every /api/ request.
#[derive(Debug, Clone)]
pub struct Session {
    pub id: u64,
    pub user_id: u64,
    /// false until the TOTP challenge succeeds — a password-only session may
    /// ONLY call /api/auth/totp.
    pub totp_verified: bool,
    pub expires_at: DateTime<Utc>,
}

/// Generate a session token. Only its hash is persisted; the plaintext goes to
/// the cookie and is never stored or logged.
pub fn generate_token() -> String {
    Alphanumeric.sample_string(&mut rand::rng(), 48)
}

/// SHA-256 of a session token (hex). Hashing means a DB read alone cannot
/// reconstruct a usable cookie.
pub fn hash_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Create a session row for a user. `totp_verified` starts false (pre-2FA); the
/// TTL comes from [auth] session_ttl_hours. Returns (session_id, plaintext token)
/// — the token goes only into the Set-Cookie.
pub async fn create(
    pool: &MySqlPool,
    user_id: u64,
    ip: &str,
    user_agent: &str,
    ttl_hours: i64,
) -> Result<(u64, String)> {
    let token = generate_token();
    let token_hash = hash_token(&token);
    let expires_at = Utc::now() + Duration::hours(ttl_hours);
    let res = sqlx::query(
        "INSERT INTO sessions (token_hash, user_id, ip_address, user_agent, totp_verified, expires_at) \
         VALUES (?, ?, ?, ?, 0, ?)",
    )
    .bind(&token_hash)
    .bind(user_id)
    .bind(ip)
    .bind(user_agent)
    .bind(expires_at.naive_utc())
    .execute(pool)
    .await
    .context("inserting session")?;
    Ok((res.last_insert_id(), token))
}

/// Mark a session as 2FA-complete and rotate its token (defense against fixation).
/// Returns the new plaintext token for a fresh Set-Cookie.
pub async fn mark_totp_verified_and_rotate(pool: &MySqlPool, session_id: u64) -> Result<String> {
    let token = generate_token();
    let token_hash = hash_token(&token);
    sqlx::query(
        "UPDATE sessions SET token_hash = ?, totp_verified = 1, last_activity_at = UTC_TIMESTAMP() \
         WHERE id = ?",
    )
    .bind(&token_hash)
    .bind(session_id)
    .execute(pool)
    .await
    .context("rotating session token")?;
    Ok(token)
}

/// Look up + validate a session by its plaintext token: exists and not expired.
/// `totp_verified` is returned for the caller/extractor to gate on. Bumps
/// last_activity_at.
pub async fn validate(pool: &MySqlPool, token: &str) -> Result<Option<Session>> {
    let token_hash = hash_token(token);
    // TIMESTAMP columns decode as DateTime<Utc> (NaiveDateTime maps only to
    // DATETIME in sqlx-mysql); the pool pins the session tz to UTC.
    let row = sqlx::query_as::<_, (u64, u64, bool, DateTime<Utc>)>(
        "SELECT id, user_id, totp_verified, expires_at FROM sessions \
         WHERE token_hash = ? AND expires_at > UTC_TIMESTAMP()",
    )
    .bind(&token_hash)
    .fetch_optional(pool)
    .await
    .context("looking up session")?;

    let Some((id, user_id, totp_verified, expires_at)) = row else {
        return Ok(None);
    };

    // Best-effort activity bump (cheap, throttled by the 1s timestamp resolution).
    let _ = sqlx::query("UPDATE sessions SET last_activity_at = UTC_TIMESTAMP() WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await;

    Ok(Some(Session {
        id,
        user_id,
        totp_verified,
        expires_at,
    }))
}

/// Like [`validate`] but does NOT require TOTP — used by /api/auth/totp to load
/// the pre-2FA session the login step created.
pub async fn validate_pre2fa(pool: &MySqlPool, token: &str) -> Result<Option<Session>> {
    validate(pool, token).await
}

/// Expire a session immediately (logout / admin revocation).
pub async fn expire(pool: &MySqlPool, session_id: u64) -> Result<()> {
    sqlx::query("UPDATE sessions SET expires_at = UTC_TIMESTAMP() WHERE id = ?")
        .bind(session_id)
        .execute(pool)
        .await
        .context("expiring session")?;
    Ok(())
}

/// Whether to set the `Secure` cookie attribute. Defaults to **true** (a Secure
/// cookie is the correct production posture behind HTTPS/Cloudflare). Set
/// `COOKIE_SECURE=false` ONLY for an HTTP-only origin (e.g. before Let's Encrypt
/// is in place) — a browser silently drops a Secure cookie over plain HTTP, so
/// login would not persist. Flip back to true once the origin serves HTTPS.
fn cookie_secure() -> bool {
    !matches!(
        std::env::var("COOKIE_SECURE").ok().as_deref(),
        Some("false") | Some("0") | Some("no")
    )
}

/// Build the session cookie carrying `token`, with `max_age` matching the session
/// row's lifetime. HttpOnly + SameSite=Lax, path=/, Secure per `cookie_secure()`;
/// the SignedCookieJar adds the SESSION_SECRET signature on the way out.
pub fn build_cookie(token: String, max_age: time::Duration) -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE, token))
        .http_only(true)
        .secure(cookie_secure())
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(max_age)
        .build()
}

/// A removal cookie for logout (expires the browser copy immediately).
pub fn removal_cookie() -> Cookie<'static> {
    Cookie::build((SESSION_COOKIE, ""))
        .http_only(true)
        .secure(cookie_secure())
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(time::Duration::seconds(0))
        .build()
}

/// Axum extractor: every authenticated /api/ handler takes `Session` as an
/// argument; missing/invalid/expired/pre-2FA cookies are rejected with 401
/// before the handler body runs.
impl FromRequestParts<AppState> for Session {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let jar = SignedCookieJar::<Key>::from_request_parts(parts, state)
            .await
            .map_err(|e| match e {})?; // Infallible
        let token = jar
            .get(SESSION_COOKIE)
            .ok_or((StatusCode::UNAUTHORIZED, "missing session"))?;
        match validate(&state.pool, token.value()).await {
            Ok(Some(session)) if session.totp_verified => Ok(session),
            Ok(Some(_)) => Err((StatusCode::UNAUTHORIZED, "2fa required")),
            Ok(None) => Err((StatusCode::UNAUTHORIZED, "invalid session")),
            Err(e) => {
                tracing::error!(event_type = "session_validate_error", error = format!("{e:#}"), "session lookup failed");
                Err((StatusCode::INTERNAL_SERVER_ERROR, "session lookup failed"))
            }
        }
    }
}
