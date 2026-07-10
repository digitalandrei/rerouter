//! The authenticated REST API under /api/, consumed by the React SPA via the
//! Nginx /api proxy; binds loopback only (127.0.0.1:9277). Public access is
//! EXCLUSIVELY via Nginx behind Cloudflare. See ../docs/architecture.md for the
//! endpoint list.
//!
//! Every endpoint except GET /api/health and GET /api/ready requires a valid session (see
//! auth::sessions::Session) and is authorized via RBAC (auth::rbac) — this
//! process IS the security boundary. The real client IP arrives via
//! CF-Connecting-IP, forwarded by Nginx; trusted because only Cloudflare can
//! reach Nginx and only Nginx can reach us.

pub mod alerts;
pub mod audit;
pub mod devices;
pub mod flows;
pub mod health;
pub mod interfaces;
pub mod locks;
pub mod notifications;
pub mod reroutes;
pub mod rtbh;
pub mod rules;
pub mod settings;
pub mod templates;
pub mod users;

use anyhow::{Context, Result};
use axum::extract::{FromRef, Request};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
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
/// installer ships a 32-byte SESSION_SECRET. We SHA-512-expand the master secret
/// deterministically so sessions survive a restart.
/// A secret already >= 64 bytes is used directly.
pub fn cookie_key_from_env() -> Result<Key> {
    let secret = std::env::var("SESSION_SECRET")
        .context("env SESSION_SECRET not set (needed to sign session cookies)")?;
    let bytes = hex::decode(secret.trim()).unwrap_or_else(|_| secret.into_bytes());
    anyhow::ensure!(
        bytes.len() >= 32,
        "SESSION_SECRET must be at least 32 bytes"
    );
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

/// Reject browser mutations initiated by another origin. SameSite cookies stop
/// cross-site CSRF, while Sec-Fetch-Site also distinguishes a potentially
/// compromised sibling subdomain ("same-site") from this exact origin. Origin
/// comparison is the fallback for browsers that omit Fetch Metadata headers;
/// non-browser clients may omit both.
async fn require_same_origin_mutation(request: Request, next: Next) -> Response {
    if !matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    ) && mutation_is_cross_origin(request.headers())
    {
        return err(StatusCode::FORBIDDEN, "cross_origin_mutation_refused").into_response();
    }
    next.run(request).await
}

async fn no_store_api_response(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}

fn mutation_is_cross_origin(headers: &HeaderMap) -> bool {
    if let Some(site) = headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok())
    {
        match site {
            "same-origin" | "none" => {}
            "same-site" | "cross-site" => return true,
            _ => return true,
        }
    }

    let Some(origin) = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    let Some(host) = headers
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
    else {
        return true;
    };
    let Some((scheme, authority)) = origin
        .strip_prefix("https://")
        .map(|authority| ("https", authority))
        .or_else(|| {
            origin
                .strip_prefix("http://")
                .map(|authority| ("http", authority))
        })
    else {
        return true;
    };
    if authority.is_empty()
        || authority.contains('/')
        || !authority.eq_ignore_ascii_case(host.trim())
    {
        return true;
    }

    headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .is_some_and(|forwarded| !scheme.eq_ignore_ascii_case(forwarded.trim()))
}

/// Required audit write for persisted configuration mutations. Callers surface an
/// error when this fails; failures are also logged so an incomplete trail is never
/// silent.
pub(crate) async fn audit_mutation(
    pool: &MySqlPool,
    session: &crate::auth::sessions::Session,
    event_type: &str,
    entity_type: &str,
    entity_id: u64,
    message: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO audit_logs \
         (actor_type, actor_user_id, event_type, entity_type, entity_id, message, ip_address, user_agent) \
         VALUES ('user', ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(session.user_id)
    .bind(event_type)
    .bind(entity_type)
    .bind(entity_id)
    .bind(message)
    .bind(&session.ip_address)
    .bind(&session.user_agent)
    .execute(pool)
    .await
    .with_context(|| format!("auditing {event_type} for {entity_type} {entity_id}"))?;
    Ok(())
}

pub(crate) async fn audit_mutation_on(
    conn: &mut sqlx::MySqlConnection,
    session: &crate::auth::sessions::Session,
    event_type: &str,
    entity_type: &str,
    entity_id: u64,
    message: &str,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO audit_logs \
         (actor_type, actor_user_id, event_type, entity_type, entity_id, message, ip_address, user_agent) \
         VALUES ('user', ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(session.user_id)
    .bind(event_type)
    .bind(entity_type)
    .bind(entity_id)
    .bind(message)
    .bind(&session.ip_address)
    .bind(&session.user_agent)
    .execute(conn)
    .await
    .with_context(|| format!("auditing {event_type} for {entity_type} {entity_id}"))?;
    Ok(())
}

fn action_plan_hash(plan: &Value) -> Result<String> {
    use sha2::{Digest, Sha256};
    let encoded = serde_json::to_vec(plan).context("serializing action preview")?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

pub(crate) async fn store_action_preview(
    pool: &MySqlPool,
    user_id: u64,
    scope: &str,
    scope_id: Option<u64>,
    plan: &Value,
) -> Result<String> {
    let token = crate::auth::sessions::generate_token();
    let token_hash = crate::auth::sessions::hash_token(&token);
    let plan_hash = action_plan_hash(plan)?;
    let mut tx = pool.begin().await?;
    sqlx::query(
        "DELETE FROM action_previews WHERE expires_at <= UTC_TIMESTAMP() OR used_at IS NOT NULL",
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO action_previews \
         (token_hash, user_id, scope, scope_id, plan_hash, expires_at) \
         VALUES (?, ?, ?, ?, ?, DATE_ADD(UTC_TIMESTAMP(), INTERVAL 5 MINUTE))",
    )
    .bind(token_hash)
    .bind(user_id)
    .bind(scope)
    .bind(scope_id)
    .bind(plan_hash)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(token)
}

pub(crate) async fn consume_action_preview(
    pool: &MySqlPool,
    token: &str,
    user_id: u64,
    scope: &str,
    scope_id: Option<u64>,
    plan: &Value,
) -> Result<bool> {
    let token_hash = crate::auth::sessions::hash_token(token);
    let plan_hash = action_plan_hash(plan)?;
    let updated = sqlx::query(
        "UPDATE action_previews SET used_at = UTC_TIMESTAMP() \
         WHERE token_hash = ? AND user_id = ? AND scope = ? \
           AND ((scope_id IS NULL AND ? IS NULL) OR scope_id = ?) \
           AND plan_hash = ? AND used_at IS NULL AND expires_at > UTC_TIMESTAMP()",
    )
    .bind(token_hash)
    .bind(user_id)
    .bind(scope)
    .bind(scope_id)
    .bind(scope_id)
    .bind(plan_hash)
    .execute(pool)
    .await?;
    Ok(updated.rows_affected() == 1)
}

pub async fn serve(pool: MySqlPool, cfg: Config) -> Result<()> {
    let cookie_key = cookie_key_from_env()?;
    let bind = cfg.server.bind.clone();
    let state = AppState {
        pool,
        config: cfg,
        cookie_key,
    };

    let app = Router::new()
        // unauthenticated liveness/readiness probes; status requires a session
        .route("/api/health", get(health::health))
        .route("/api/ready", get(health::ready))
        .route("/api/status", get(health::status))
        // auth: login (password) -> totp (2FA, issues session) -> logout
        .nest("/api/auth", auth::router())
        // devices (SNMP) — telemetry source of record in v1
        .route("/api/devices", get(devices::list).post(devices::create))
        .route(
            "/api/devices/{id}",
            get(devices::show)
                .put(devices::update)
                .delete(devices::remove),
        )
        .route("/api/devices/{id}/test", post(devices::test))
        .route("/api/devices/{id}/discover", post(devices::discover))
        .route("/api/devices/{id}/ssh-test", post(devices::ssh_test))
        .route(
            "/api/devices/{id}/ssh-generate-key",
            post(devices::generate_key),
        )
        .route(
            "/api/devices/{id}/ssh-capabilities",
            post(devices::ssh_capabilities),
        )
        .route(
            "/api/devices/{id}/reachability-test",
            post(devices::reachability_test),
        )
        .route(
            "/api/devices/{id}/discover-bgp",
            post(devices::discover_bgp),
        )
        .route("/api/devices/{id}/bgp-peers", get(devices::bgp_peers))
        .route("/api/devices/{id}/route-maps", get(devices::route_maps))
        .route(
            "/api/devices/{device_id}/bgp-peers/{peer_id}",
            patch(devices::update_bgp_peer),
        )
        .route("/api/devices/{id}/bgp-networks", get(devices::bgp_networks))
        .route(
            "/api/devices/{id}/discover-prefixes",
            post(devices::discover_prefixes),
        )
        .route("/api/devices/{id}/interfaces", get(devices::interfaces))
        // flow telemetry (NetFlow v9/sFlow v5) — passive second source, see flows.rs
        .route("/api/devices/{id}/flows/top", get(flows::top))
        .route("/api/devices/{id}/flow-exporters", get(flows::exporters))
        .route("/api/flows/search", get(flows::search))
        .route("/api/flows/detail", get(flows::detail))
        .route("/api/flows/suggest", get(flows::suggest))
        // interfaces
        .route("/api/interfaces/{id}", get(interfaces::show))
        .route("/api/interfaces/{id}/metrics", get(interfaces::metrics))
        .route(
            "/api/interfaces/{id}/protected",
            patch(interfaces::set_protected),
        )
        // rules
        .route("/api/rules", get(rules::list).post(rules::create))
        .route(
            "/api/rules/{id}",
            get(rules::show).put(rules::update).delete(rules::remove),
        )
        .route("/api/rules/{id}/clear", post(rules::clear))
        .route("/api/rules/{id}/apply", post(rules::apply))
        .route("/api/rules/{id}/actions", post(rules::add_action))
        .route(
            "/api/rules/{rule_id}/actions/{action_id}",
            delete(rules::remove_action),
        )
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
        .route(
            "/api/reroutes/{id}/acknowledge-uncertain",
            post(reroutes::acknowledge_uncertain),
        )
        .route("/api/reroutes/{id}/rollback", post(reroutes::rollback))
        // alerts + audit
        .route("/api/alerts", get(alerts::list))
        .route("/api/audit", get(audit::list))
        // notification settings: email recipients + Teams webhooks (manage_alerts)
        .route(
            "/api/notifications/event-types",
            get(notifications::event_types),
        )
        .route(
            "/api/notifications/recipients",
            get(notifications::list_recipients).post(notifications::add_recipient),
        )
        .route(
            "/api/notifications/recipients/{id}",
            axum::routing::delete(notifications::remove_recipient),
        )
        .route(
            "/api/notifications/recipients/{id}/test",
            post(notifications::test_recipient),
        )
        .route(
            "/api/notifications/webhooks",
            get(notifications::list_webhooks).post(notifications::add_webhook),
        )
        .route(
            "/api/notifications/webhooks/{id}",
            axum::routing::delete(notifications::remove_webhook),
        )
        .route(
            "/api/notifications/webhooks/{id}/test",
            post(notifications::test_webhook),
        )
        // safety locks + global settings
        .route("/api/locks", get(locks::list))
        .route(
            "/api/locks/global",
            post(locks::create_global).delete(locks::clear_global),
        )
        .route("/api/settings", get(settings::show).put(settings::update))
        // user management (manage_users / superadmin only)
        .route("/api/users", get(users::list).post(users::create))
        .route("/api/users/{id}", put(users::update).delete(users::remove))
        .route("/api/users/{id}/reset-2fa", post(users::reset_2fa))
        .layer(middleware::from_fn(require_same_origin_mutation))
        .layer(middleware::from_fn(no_store_api_response))
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
pub fn client_ip(headers: &axum::http::HeaderMap, socket: Option<&std::net::SocketAddr>) -> String {
    headers
        .get("CF-Connecting-IP")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        // Only accept a well-formed IP so a garbage/spoofed header can't pollute
        // the audit trail; otherwise fall back to the trusted socket peer.
        .filter(|s| s.parse::<std::net::IpAddr>().is_ok())
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

#[cfg(test)]
mod tests {
    use super::mutation_is_cross_origin;
    use axum::http::{HeaderMap, HeaderValue};

    fn headers(host: &str, origin: Option<&str>, fetch_site: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_str(host).unwrap());
        if let Some(origin) = origin {
            headers.insert("origin", HeaderValue::from_str(origin).unwrap());
        }
        if let Some(fetch_site) = fetch_site {
            headers.insert("sec-fetch-site", HeaderValue::from_str(fetch_site).unwrap());
        }
        headers
    }

    #[test]
    fn mutation_origin_guard_rejects_sibling_and_cross_site_browsers() {
        assert!(mutation_is_cross_origin(&headers(
            "rerouter.example.com",
            Some("https://tools.example.com"),
            Some("same-site"),
        )));
        assert!(mutation_is_cross_origin(&headers(
            "rerouter.example.com",
            Some("https://attacker.test"),
            Some("cross-site"),
        )));
    }

    #[test]
    fn mutation_origin_guard_accepts_exact_origin_and_cli_requests() {
        assert!(!mutation_is_cross_origin(&headers(
            "rerouter.example.com",
            Some("https://rerouter.example.com"),
            Some("same-origin"),
        )));
        assert!(!mutation_is_cross_origin(&headers(
            "127.0.0.1:9277",
            None,
            None,
        )));
    }

    #[test]
    fn mutation_origin_guard_checks_forwarded_scheme() {
        let mut headers = headers(
            "rerouter.example.com",
            Some("http://rerouter.example.com"),
            Some("same-origin"),
        );
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        assert!(mutation_is_cross_origin(&headers));
    }
}
