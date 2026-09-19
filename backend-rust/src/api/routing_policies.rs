//! Cached routing-policy inventory. Loading this page never opens SSH.

use super::{err, AppState};
use crate::auth::rbac::{markers, RequirePermission};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};

pub async fn get(
    _g: RequirePermission<markers::ViewAsset>,
    State(state): State<AppState>,
    Path(device_id): Path<u64>,
) -> (StatusCode, Json<Value>) {
    let row = sqlx::query_as::<_, (sqlx::types::Json<Value>, String, sqlx::types::Json<Value>, chrono::DateTime<chrono::Utc>)>(
        "SELECT inventory_json, completeness, blockers_json, read_at FROM routing_policy_snapshots WHERE device_id = ?",
    ).bind(device_id).fetch_optional(&state.pool).await;
    match row {
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
        Ok(None) => (
            StatusCode::OK,
            Json(
                json!({"device_id":device_id,"read_at":null,"completeness":"stale","blockers":["routing_policy_inventory_unavailable"],"prefix_lists":[],"route_maps":[],"peer_bindings":[]}),
            ),
        ),
        Ok(Some((inventory, mut completeness, mut blockers, read_at))) => {
            if chrono::Utc::now().signed_duration_since(read_at)
                >= chrono::Duration::hours(
                    crate::reroute::templates::ROUTING_INVENTORY_MAX_AGE_HOURS,
                )
            {
                completeness = "stale".into();
                let mut values = blockers.0.as_array().cloned().unwrap_or_default();
                values.push(json!("routing_policy_inventory_stale"));
                blockers = sqlx::types::Json(json!(values));
            }
            let mut body = inventory.0.as_object().cloned().unwrap_or_default();
            body.insert("device_id".into(), json!(device_id));
            body.insert("read_at".into(), json!(read_at));
            body.insert("completeness".into(), json!(completeness));
            body.insert("blockers".into(), blockers.0);
            (StatusCode::OK, Json(Value::Object(body)))
        }
    }
}
