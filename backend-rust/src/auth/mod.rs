//! Authentication owned by the controller: session cookies backed by the DB
//! `sessions` table, Argon2id password hashing, TOTP 2FA, single-use recovery
//! codes, and login throttling/lockout. See ../docs/authentication.md and
//! ../skills/rust-auth-2fa.md.
//!
//! Invariants:
//!   * login is password + TOTP; first login forces TOTP enrollment;
//!   * throttle/lockout by email + real client IP (CF-Connecting-IP, trusted
//!     because only Cloudflare reaches Nginx and only Nginx reaches us);
//!   * recovery codes are single-use and stored hashed;
//!   * high-safety reroutes require a FRESH password + TOTP re-auth (POST
//!     /api/auth/reauth) regardless of an active session;
//!   * every auth event is audited with actor, real IP, and user-agent.

pub mod password;
pub mod totp;
pub mod sessions;
pub mod rbac;

use axum::{
    http::StatusCode,
    routing::post,
    Json, Router,
};
use serde_json::{json, Value};
use sqlx::MySqlPool;

/// Router for /api/auth/*, nested by the API route table.
pub fn router() -> Router<MySqlPool> {
    Router::new()
        .route("/login", post(login))
        .route("/totp", post(totp_challenge))
        .route("/logout", post(logout))
        .route("/reauth", post(reauth))
}

/// POST /api/auth/login — verify email + password, return a TOTP challenge.
/// Throttle by email + real client IP; increment failed_login_attempts and set
/// locked_until past the threshold. Never reveals whether the email exists.
async fn login() -> (StatusCode, Json<Value>) {
    // TODO(milestone 1): lockout check -> password::verify -> issue a short-lived
    // pre-2FA challenge (sessions::create with totp_verified = 0); if the user
    // has no confirmed TOTP, respond with an enrollment challenge instead.
    (StatusCode::NOT_IMPLEMENTED, Json(json!({ "error": "not_implemented" })))
}

/// POST /api/auth/totp — complete 2FA (TOTP code or single-use recovery code)
/// and issue the real session cookie. Recovery-code use is a security event
/// (alerted immediately, code consumed).
async fn totp_challenge() -> (StatusCode, Json<Value>) {
    // TODO(milestone 1): totp::verify within ±1 step (or consume a recovery
    // code), mark the session totp_verified, record last_login_at/_ip, reset
    // failed_login_attempts, audit login_success.
    (StatusCode::NOT_IMPLEMENTED, Json(json!({ "error": "not_implemented" })))
}

/// POST /api/auth/logout — expire the DB session and clear the cookie.
async fn logout() -> (StatusCode, Json<Value>) {
    // TODO(milestone 1): sessions::expire + audit logout.
    (StatusCode::NOT_IMPLEMENTED, Json(json!({ "error": "not_implemented" })))
}

/// POST /api/auth/reauth — fresh password + current TOTP immediately before a
/// high-safety reroute. Stamps sessions.reauth_at; the reroute endpoints check
/// its freshness. Produces a reauth_for_action audit record.
async fn reauth() -> (StatusCode, Json<Value>) {
    // TODO(milestone 3): password::verify + totp::verify, stamp reauth_at.
    (StatusCode::NOT_IMPLEMENTED, Json(json!({ "error": "not_implemented" })))
}
