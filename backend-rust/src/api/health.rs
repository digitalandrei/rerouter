//! Health + status endpoints.
//!
//! `GET /api/health` is the only unauthenticated route (liveness probe).
//! `GET /api/status` requires a session and returns the SystemStatus dashboard
//! summary (field names pinned by ../../frontend/src/lib/api.ts: SystemStatus).

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use super::{settings, AppState};
use crate::auth::rbac::{markers, RequirePermission};

/// Unauthenticated liveness probe.
pub async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

/// GET /api/status — dashboard summary. Counts devices/interfaces, active rule
/// matches (rule_states.current_state = 'firing'), alerts in the last 24h, and
/// stale telemetry (enabled devices not polled within stale_after_seconds, or
/// never polled).
pub async fn status(
    _g: RequirePermission<markers::ViewDashboard>,
    State(state): State<AppState>,
) -> (StatusCode, Json<Value>) {
    let pool = &state.pool;
    let operating_mode = settings::operating_mode(pool, &state.config).await;
    let stale_after = state.config.telemetry.stale_after_seconds as i64;

    let devices_total: i64 = scalar(pool, "SELECT COUNT(*) FROM devices").await;
    let devices_reachable: i64 = scalar(pool, "SELECT COUNT(*) FROM devices WHERE reachable = 1").await;
    // Every discovered interface is polled/charted, so "monitored" == all of them.
    let interfaces_monitored: i64 = scalar(pool, "SELECT COUNT(*) FROM device_interfaces").await;
    let active_rule_matches: i64 =
        scalar(pool, "SELECT COUNT(*) FROM rule_states WHERE current_state = 'firing'").await;
    let alerts_24h: i64 = scalar(
        pool,
        "SELECT COUNT(*) FROM alerts WHERE created_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 24 HOUR)",
    )
    .await;

    // Telemetry stale: an enabled device that has never been polled or whose last
    // poll is older than stale_after_seconds.
    let telemetry_stale_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM devices \
         WHERE enabled = 1 AND (last_poll_at IS NULL \
            OR last_poll_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? SECOND))",
    )
    .bind(stale_after)
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    (
        StatusCode::OK,
        Json(json!({
            "operating_mode": operating_mode,
            "devices_total": devices_total,
            "devices_reachable": devices_reachable,
            "interfaces_monitored": interfaces_monitored,
            "active_rule_matches": active_rule_matches,
            "alerts_24h": alerts_24h,
            "telemetry_stale_count": telemetry_stale_count,
        })),
    )
}

/// COUNT(*)-style scalar with a 0 fallback (a missing table on a partial schema
/// must never 500 the dashboard).
async fn scalar(pool: &sqlx::MySqlPool, sql: &str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(pool).await.unwrap_or(0)
}
