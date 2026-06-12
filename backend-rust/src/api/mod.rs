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
pub mod assets;
pub mod providers;
pub mod rules;
pub mod reroutes;
pub mod alerts;
pub mod audit;
pub mod locks;
pub mod settings;

use anyhow::Result;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use sqlx::MySqlPool;
use tower_http::trace::TraceLayer;

use crate::auth;
use crate::config::Config;

/// Shared stub response while handlers are filled in milestone by milestone.
pub(crate) fn not_implemented() -> (StatusCode, Json<Value>) {
    (StatusCode::NOT_IMPLEMENTED, Json(json!({ "error": "not_implemented" })))
}

pub async fn serve(pool: MySqlPool, cfg: Config) -> Result<()> {
    let app = Router::new()
        // unauthenticated liveness probe — everything else requires a session
        .route("/api/health", get(health::health))
        .route("/api/status", get(health::status))
        // auth: login (password) -> totp (2FA, issues session) -> logout;
        // reauth = fresh password+TOTP before high-safety reroutes
        .nest("/api/auth", auth::router())
        // assets
        .route("/api/assets", get(assets::list).post(assets::create))
        .route("/api/assets/{id}", get(assets::show).put(assets::update).delete(assets::remove))
        .route("/api/assets/{id}/test/telemetry", post(assets::test_telemetry))
        .route("/api/assets/{id}/rediscover", post(assets::rediscover))
        .route("/api/assets/{id}/live", get(assets::live))
        // providers
        .route("/api/providers", get(providers::list).post(providers::create))
        .route("/api/providers/{id}", get(providers::show).put(providers::update).delete(providers::remove))
        // rules
        .route("/api/rules", get(rules::list).post(rules::create))
        .route("/api/rules/{id}", get(rules::show).put(rules::update).delete(rules::remove))
        // reroutes (authz: session + RBAC + re-auth — see reroutes.rs)
        .route("/api/reroutes", get(reroutes::list))
        .route("/api/reroutes/manual", post(reroutes::manual))
        .route("/api/reroutes/{id}/cancel", post(reroutes::cancel))
        .route("/api/reroutes/{id}/acknowledge-uncertain", post(reroutes::acknowledge_uncertain))
        // alerts + audit
        .route("/api/alerts", get(alerts::list))
        .route("/api/audit", get(audit::list))
        // safety locks + global settings
        .route("/api/locks/global", post(locks::create_global).delete(locks::clear_global))
        .route("/api/settings", get(settings::show).put(settings::update))
        .layer(TraceLayer::new_for_http())
        .with_state(pool);

    // OPTIONAL single-binary UI (cargo feature "embed-ui"): the SPA is the
    // router fallback, so every explicit /api route above always wins.
    #[cfg(feature = "embed-ui")]
    let app = app.fallback(crate::ui::serve_spa);

    let listener = tokio::net::TcpListener::bind(&cfg.server.bind).await?;
    tracing::info!(event_type = "api_listening", bind = %cfg.server.bind, "API up (loopback only; public via Nginx /api proxy)");
    axum::serve(listener, app).await?;
    Ok(())
}
