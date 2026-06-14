//! GET /api/alerts — alert history for the /alerts SPA page (view_dashboard to
//! read). Field names are pinned by the frontend contract
//! (../../frontend/src/lib/api.ts: Alert).

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{err, AppState};
use crate::auth::rbac::{markers, RequirePermission};

type JsonResp = (StatusCode, Json<Value>);

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// Page size (default 50, capped at 200).
    limit: Option<i64>,
    /// Page offset (default 0).
    offset: Option<i64>,
    /// Only alerts from the last N days (default 7, capped at 365).
    days: Option<i64>,
}

/// A row from the `alerts` table, with the device / interface / rule NAMES
/// resolved (LEFT JOINs) so the UI can show "rule X on device Y / iface Z"
/// instead of raw ids.
#[derive(sqlx::FromRow)]
struct AlertRow {
    id: u64,
    event_type: String,
    severity: String,
    device_id: Option<u64>,
    interface_id: Option<u64>,
    rule_id: Option<u64>,
    device_name: Option<String>,
    interface_name: Option<String>,
    rule_name: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
    payload_json: Option<sqlx::types::Json<Value>>,
}

/// GET /api/alerts — most recent first, scoped to the last `days` (default 7),
/// paginated. Returns `{ rows, total, limit, offset }`.
pub async fn list(
    _g: RequirePermission<markers::ViewDashboard>,
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
) -> JsonResp {
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let offset = q.offset.unwrap_or(0).max(0);
    let days = q.days.unwrap_or(7).clamp(1, 365);

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM alerts \
         WHERE created_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? DAY)",
    )
    .bind(days)
    .fetch_one(&state.pool)
    .await
    .unwrap_or(0);

    let rows = sqlx::query_as::<_, AlertRow>(
        "SELECT a.id, a.event_type, a.severity, a.device_id, a.interface_id, a.rule_id, \
                d.name AS device_name, \
                COALESCE(di.if_name, di.if_descr) AS interface_name, \
                r.name AS rule_name, \
                a.created_at, a.payload_json \
         FROM alerts a \
         LEFT JOIN devices d ON d.id = a.device_id \
         LEFT JOIN device_interfaces di ON di.id = a.interface_id \
         LEFT JOIN rules r ON r.id = a.rule_id \
         WHERE a.created_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? DAY) \
         ORDER BY a.id DESC LIMIT ? OFFSET ?",
    )
    .bind(days)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.pool)
    .await;

    match rows {
        Ok(rows) => {
            let out: Vec<Value> = rows
                .into_iter()
                .map(|r| {
                    json!({
                        "id": r.id,
                        "event_type": r.event_type,
                        "severity": r.severity,
                        "device_id": r.device_id,
                        "interface_id": r.interface_id,
                        "rule_id": r.rule_id,
                        "device_name": r.device_name,
                        "interface_name": r.interface_name,
                        "rule_name": r.rule_name,
                        "created_at": r.created_at.to_rfc3339(),
                        "payload": r.payload_json.map(|j| j.0).unwrap_or_else(|| json!({})),
                    })
                })
                .collect();
            (
                StatusCode::OK,
                Json(json!({ "rows": out, "total": total, "limit": limit, "offset": offset })),
            )
        }
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}
