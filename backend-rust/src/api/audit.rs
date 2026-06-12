//! GET /api/audit — append-only audit log, filterable (view_audit).
//! TODO(milestone 1): paginated SELECT over audit_logs
//! (event_type + created_at index).

use axum::http::StatusCode;
use axum::Json;
use serde_json::Value;

use super::not_implemented;

pub async fn list() -> (StatusCode, Json<Value>) {
    not_implemented()
}
