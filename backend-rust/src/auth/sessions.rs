//! DB-backed sessions (`sessions` table). The browser cookie carries only a
//! random token; the DB row holds the hash, the user, TOTP/re-auth state, and
//! the expiry. Server-side revocation is therefore immediate. The SPA talks to
//! /api/ with credentialed fetch; the cookie is HttpOnly + Secure + SameSite.

use anyhow::Result;
use axum::extract::FromRequestParts;
use axum::http::{request::Parts, StatusCode};
use axum_extra::extract::cookie::CookieJar;
use chrono::{DateTime, Utc};
use rand::distr::{Alphanumeric, SampleString};
use sqlx::MySqlPool;

pub const SESSION_COOKIE: &str = "rerouter_session";

/// An authenticated session, extracted from the cookie on every /api/ request.
#[derive(Debug, Clone)]
pub struct Session {
    pub id: u64,
    pub user_id: u64,
    /// false until the TOTP challenge succeeds — a password-only session may
    /// ONLY call /api/auth/totp.
    pub totp_verified: bool,
    /// last fresh password+TOTP confirmation; high-safety reroutes require this
    /// to be recent (see rbac.rs and api/reroutes.rs).
    pub reauth_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
}

/// Generate a session token. Only its hash is persisted; the plaintext goes to
/// the cookie and is never stored or logged.
pub fn generate_token() -> String {
    Alphanumeric.sample_string(&mut rand::rng(), 48)
}

/// Create a session row for a user (pre-2FA: totp_verified = 0).
pub async fn create(_pool: &MySqlPool, _user_id: u64, _ip: &str, _user_agent: &str) -> Result<String> {
    // TODO(milestone 1): INSERT session (token hash, ttl from [auth]
    // session_ttl_hours), return the plaintext token for the Set-Cookie.
    anyhow::bail!("not implemented")
}

/// Look up + validate a session by token: exists, not expired, TOTP verified.
pub async fn validate(_pool: &MySqlPool, _token: &str) -> Result<Option<Session>> {
    // TODO(milestone 1): hash token, SELECT, enforce expires_at, bump
    // last_activity_at (throttled).
    Ok(None)
}

/// Expire a session (logout / admin revocation).
pub async fn expire(_pool: &MySqlPool, _session_id: u64) -> Result<()> {
    // TODO(milestone 1): UPDATE expires_at = NOW(); audit logout.
    Ok(())
}

/// Axum extractor: every authenticated /api/ handler takes `Session` as an
/// argument; missing/invalid/expired cookies are rejected with 401 before the
/// handler body runs.
impl FromRequestParts<MySqlPool> for Session {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, state: &MySqlPool) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_request_parts(parts, state)
            .await
            .map_err(|e| match e {})?; // Infallible
        let token = jar
            .get(SESSION_COOKIE)
            .ok_or((StatusCode::UNAUTHORIZED, "missing session"))?;
        match validate(state, token.value()).await {
            Ok(Some(session)) if session.totp_verified => Ok(session),
            Ok(Some(_)) => Err((StatusCode::UNAUTHORIZED, "2fa required")),
            Ok(None) => Err((StatusCode::UNAUTHORIZED, "invalid session")),
            Err(_) => Err((StatusCode::INTERNAL_SERVER_ERROR, "session lookup failed")),
        }
    }
}
