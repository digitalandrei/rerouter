//! The authenticated REST API under /api/, consumed by the React SPA via the
//! Nginx /api proxy; binds loopback only (127.0.0.1:9277). Public access is
//! EXCLUSIVELY via Nginx behind Cloudflare. See ../docs/architecture.md for the
//! endpoint list.
//!
//! Every endpoint except GET /api/health requires a valid session (see
//! auth::sessions::Session) and is authorized via RBAC (auth::rbac) — this
//! process IS the security boundary. The real client IP arrives via
//! CF-Connecting-IP, forwarded by Nginx; trusted because only Cloudflare can
//! reach Nginx and only Nginx can reach us.

pub mod health;
pub mod rules;
pub mod templates;
pub mod rtbh;
pub mod reroutes;
pub mod alerts;
pub mod audit;
pub mod locks;
pub mod settings;
pub mod devices;
pub mod interfaces;
pub mod flows;
pub mod users;

use anyhow::{Context, Result};
use axum::extract::FromRef;
use axum::http::StatusCode;
use axum::routing::{delete, get, patch, post, put};
use axum::{Json, Router};
use axum_extra::extract::cookie::Key;
use serde_json::{json, Value};
use sqlx::MySqlPool;
use tower_http::trace::TraceLayer;

use crate::auth;
use crate::config::Config;

/// Shared application state: the DB pool, the signed-cookie key (from
/// SESSION_SECRET), and the loaded config (operating-mode fallback, auth knobs).
#[derive(Clone)]
pub struct AppState {
    pub pool: MySqlPool,
    pub config: Config,
    /// Signing key for the session cookie (axum-extra SignedCookieJar).
    pub cookie_key: Key,
}

// axum-extra's SignedCookieJar extracts the Key from state via FromRef.
impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.cookie_key.clone()
    }
}

// Convenience for handlers that only need the pool via State<MySqlPool>.
impl FromRef<AppState> for MySqlPool {
    fn from_ref(state: &AppState) -> Self {
        state.pool.clone()
    }
}

/// Derive the cookie signing key from SESSION_SECRET (hex, >=32 bytes after
/// decode; falls back to using the raw bytes if not hex). A missing secret is a
/// hard error — we will not sign cookies with a default key.
///
/// axum-extra's `Key` (cookie crate) needs 64 bytes of key material; the
/// installer ships a 32-byte SESSION_SECRET. We HKDF-expand the master secret to
/// the full key via `Key::derive_from`, which is deterministic (stable across
/// restarts, so sessions survive a restart) and accepts any master >= 32 bytes.
/// A secret already >= 64 bytes is used directly.
pub fn cookie_key_from_env() -> Result<Key> {
    let secret = std::env::var("SESSION_SECRET")
        .context("env SESSION_SECRET not set (needed to sign session cookies)")?;
    let bytes = hex::decode(secret.trim()).unwrap_or_else(|_| secret.into_bytes());
    anyhow::ensure!(bytes.len() >= 32, "SESSION_SECRET must be at least 32 bytes");
    if bytes.len() >= 64 {
        Ok(Key::from(&bytes))
    } else {
        // 32..64 bytes: deterministically expand the master secret to the 64
        // bytes the cookie Key needs via SHA-512 (stable across restarts so
        // sessions survive a restart). The cookie crate's own `derive_from`
        // needs an opt-in feature axum-extra doesn't enable, so we expand here.
        use sha2::{Digest, Sha512};
        let expanded = Sha512::digest(&bytes);
        Ok(Key::from(expanded.as_slice()))
    }
}

/// JSON error helper with an explicit status.
pub(crate) fn err(status: StatusCode, msg: &str) -> (StatusCode, Json<Value>) {
    (status, Json(json!({ "error": msg })))
}

pub async fn serve(pool: MySqlPool, cfg: Config) -> Result<()> {
    let cookie_key = cookie_key_from_env()?;
    let bind = cfg.server.bind.clone();
    let state = AppState { pool, config: cfg, cookie_key };

    let app = Router::new()
        // unauthenticated liveness probe — everything else requires a session
        .route("/api/health", get(health::health))
        .route("/api/status", get(health::status))
        // auth: login (password) -> totp (2FA, issues session) -> logout
        .nest("/api/auth", auth::router())
        // devices (SNMP) — telemetry source of record in v1
        .route("/api/devices", get(devices::list).post(devices::create))
        .route("/api/devices/{id}", get(devices::show).put(devices::update).delete(devices::remove))
        .route("/api/devices/{id}/test", post(devices::test))
        .route("/api/devices/{id}/discover", post(devices::discover))
        .route("/api/devices/{id}/ssh-test", post(devices::ssh_test))
        .route("/api/devices/{id}/ssh-generate-key", post(devices::generate_key))
        .route("/api/devices/{id}/ssh-capabilities", post(devices::ssh_capabilities))
        .route("/api/devices/{id}/discover-bgp", post(devices::discover_bgp))
        .route("/api/devices/{id}/bgp-peers", get(devices::bgp_peers))
        .route("/api/devices/{device_id}/bgp-peers/{peer_id}", patch(devices::update_bgp_peer))
        .route("/api/devices/{id}/bgp-networks", get(devices::bgp_networks))
        .route("/api/devices/{id}/discover-prefixes", post(devices::discover_prefixes))
        .route("/api/devices/{id}/interfaces", get(devices::interfaces))
        // flow telemetry (NetFlow/IPFIX) — read-only second source, see flows.rs
        .route("/api/devices/{id}/flows/top", get(flows::top))
        .route("/api/devices/{id}/flow-exporters", get(flows::exporters))
        .route("/api/flows/search", get(flows::search))
        .route("/api/flows/suggest", get(flows::suggest))
        // interfaces
        .route("/api/interfaces/{id}", get(interfaces::show))
        .route("/api/interfaces/{id}/metrics", get(interfaces::metrics))
        // rules
        .route("/api/rules", get(rules::list).post(rules::create))
        .route("/api/rules/{id}", get(rules::show).put(rules::update).delete(rules::remove))
        .route("/api/rules/{id}/clear", post(rules::clear))
        .route("/api/rules/{id}/actions", post(rules::add_action))
        .route("/api/rules/{rule_id}/actions/{action_id}", delete(rules::remove_action))
        // reroute template catalog (read-only) + render/preview
        .route("/api/templates", get(templates::list))
        .route("/api/templates/{id}", get(templates::show))
        .route("/api/templates/{id}/render", post(templates::render))
        // global RTBH community catalog (blackhole tag picker)
        .route("/api/rtbh-communities", get(rtbh::list).post(rtbh::create))
        .route("/api/rtbh-communities/{id}", delete(rtbh::remove))
        // reroutes (authz: session + RBAC — see reroutes.rs)
        .route("/api/reroutes", get(reroutes::list))
        .route("/api/reroutes/manual", post(reroutes::manual))
        .route("/api/reroutes/{id}", get(reroutes::show))
        .route("/api/reroutes/{id}/cancel", post(reroutes::cancel))
        .route("/api/reroutes/{id}/acknowledge-uncertain", post(reroutes::acknowledge_uncertain))
        .route("/api/reroutes/{id}/rollback", post(reroutes::rollback))
        // alerts + audit
        .route("/api/alerts", get(alerts::list))
        .route("/api/audit", get(audit::list))
        // safety locks + global settings
        .route("/api/locks", get(locks::list))
        .route("/api/locks/global", post(locks::create_global).delete(locks::clear_global))
        .route("/api/settings", get(settings::show).put(settings::update))
        // user management (manage_users / superadmin only)
        .route("/api/users", get(users::list).post(users::create))
        .route("/api/users/{id}", put(users::update).delete(users::remove))
        .route("/api/users/{id}/reset-2fa", post(users::reset_2fa))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // OPTIONAL single-binary UI (cargo feature "embed-ui"): the SPA is the
    // router fallback, so every explicit /api route above always wins.
    #[cfg(feature = "embed-ui")]
    let app = app.fallback(crate::ui::serve_spa);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(event_type = "api_listening", bind = %bind, "API up (loopback only; public via Nginx /api proxy)");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// Extract the real client IP: trust CF-Connecting-IP (Nginx forwards it),
/// falling back to the socket peer address. Used for throttling, lockout, and
/// audit. See ../docs/authentication.md "Cloudflare note".
pub fn client_ip(
    headers: &axum::http::HeaderMap,
    socket: Option<&std::net::SocketAddr>,
) -> String {
    headers
        .get("CF-Connecting-IP")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| socket.map(|a| a.ip().to_string()))
        .unwrap_or_else(|| "unknown".to_string())
}

/// Extract the User-Agent header (for audit), truncated to the column width.
pub fn user_agent(headers: &axum::http::HeaderMap) -> String {
    headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .chars()
        .take(512)
        .collect()
}
