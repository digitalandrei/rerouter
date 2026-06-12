//! POST/DELETE /api/locks/global — the global safety lock (manage_locks).
//! While a global lock is active no reroute may start. Creating/clearing is
//! always audited with actor + real client IP. TODO(milestone 3).

use axum::http::StatusCode;
use axum::Json;
use serde_json::Value;

use super::not_implemented;

pub async fn create_global() -> (StatusCode, Json<Value>) {
    not_implemented()
}

pub async fn clear_global() -> (StatusCode, Json<Value>) {
    not_implemented()
}
