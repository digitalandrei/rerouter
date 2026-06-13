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
    /// Max rows (default 100, capped at 500).
    limit: Option<i64>,
}

/// A row from the `alerts` table in the contract's Alert shape.
#[derive(sqlx::FromRow)]
struct AlertRow {
    id: u64,
    event_type: String,
    severity: String,
    device_id: Option<u64>,
    interface_id: Option<u64>,
    rule_id: Option<u64>,
    created_at: chrono::DateTime<chrono::Utc>,
    payload_json: Option<sqlx::types::Json<Value>>,
}

/// GET /api/alerts — most recent alerts first.
pub async fn list(
    _g: RequirePermission<markers::ViewDashboard>,
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
) -> JsonResp {
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let rows = sqlx::query_as::<_, AlertRow>(
        "SELECT id, event_type, severity, device_id, interface_id, rule_id, \
                created_at, payload_json \
         FROM alerts ORDER BY id DESC LIMIT ?",
    )
    .bind(limit)
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
                        "created_at": r.created_at.to_rfc3339(),
                        "payload": r.payload_json.map(|j| j.0).unwrap_or_else(|| json!({})),
                    })
                })
                .collect();
            (StatusCode::OK, Json(json!(out)))
        }
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}
