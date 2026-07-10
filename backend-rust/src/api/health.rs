//! Health + status endpoints.
//!
//! `GET /api/health` is a process liveness probe; `GET /api/ready` verifies the
//! database dependency without exposing details. Both are unauthenticated.
//! `GET /api/status` requires a session and returns the SystemStatus dashboard
//! summary (field names pinned by ../../frontend/src/lib/api.ts: SystemStatus).

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use super::AppState;
use crate::auth::rbac::{markers, RequirePermission};
use crate::config::OperatingMode;

/// Unauthenticated liveness probe.
pub async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

/// Unauthenticated readiness probe. A controller without its durable database
/// must not receive operator traffic even though the process itself is alive.
pub async fn ready(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    match sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await
    {
        Ok(1) => (StatusCode::OK, Json(json!({ "status": "ready" }))),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "unavailable" })),
        ),
    }
}

/// GET /api/status — dashboard summary. Counts devices/interfaces, active rule
/// matches (rule_states.current_state = 'firing'), alerts in the last 24h, and
/// stale telemetry (enabled devices not polled within stale_after_seconds, or
/// never polled).
pub async fn status(
    _g: RequirePermission<markers::ViewDashboard>,
    State(state): State<AppState>,
) -> (StatusCode, Json<Value>) {
    let snapshot = async {
        let configured_mode = match state.config.safety.operating_mode {
            OperatingMode::Enforce => "enforce",
            OperatingMode::Observe => "observe",
        };
        let operating_mode = sqlx::query_scalar::<_, String>(
            "SELECT `value` FROM system_settings WHERE `key` = 'operating_mode'",
        )
        .fetch_optional(&state.pool)
        .await?
        .filter(|value| matches!(value.as_str(), "observe" | "enforce"))
        .unwrap_or_else(|| configured_mode.to_string());
        let devices_total = scalar(&state.pool, "SELECT COUNT(*) FROM devices").await?;
        let devices_reachable =
            scalar(&state.pool, "SELECT COUNT(*) FROM devices WHERE reachable = 1").await?;
        let interfaces_monitored =
            scalar(&state.pool, "SELECT COUNT(*) FROM device_interfaces").await?;
        let active_rule_matches = scalar(
            &state.pool,
            "SELECT COUNT(*) FROM rule_states WHERE current_state = 'firing'",
        )
        .await?;
        let alerts_24h = scalar(
            &state.pool,
            "SELECT COUNT(*) FROM alerts WHERE created_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 24 HOUR)",
        )
        .await?;
        let telemetry_stale_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM devices \
             WHERE enabled = 1 AND (reachable = 0 OR last_poll_at IS NULL \
                OR last_poll_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? SECOND))",
        )
        .bind(state.config.telemetry.stale_after_seconds as i64)
        .fetch_one(&state.pool)
        .await?;
        Ok::<Value, sqlx::Error>(json!({
            "operating_mode": operating_mode,
            "devices_total": devices_total,
            "devices_reachable": devices_reachable,
            "interfaces_monitored": interfaces_monitored,
            "active_rule_matches": active_rule_matches,
            "alerts_24h": alerts_24h,
            "telemetry_stale_count": telemetry_stale_count,
        }))
    }
    .await;
    match snapshot {
        Ok(value) => (StatusCode::OK, Json(value)),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "error": "status_unavailable" })),
        ),
    }
}

async fn scalar(pool: &sqlx::MySqlPool, sql: &str) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(sql).fetch_one(pool).await
}
