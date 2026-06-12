//! Health + status endpoints.

use axum::{extract::State, Json};
use serde_json::{json, Value};
use sqlx::MySqlPool;

pub async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

pub async fn status(State(_pool): State<MySqlPool>) -> Json<Value> {
    // TODO: report assets/providers/telemetry freshness, locks, automatic switch.
    Json(json!({ "status": "ok", "automatic_actions_enabled": false }))
}
