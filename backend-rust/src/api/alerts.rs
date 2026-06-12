//! GET /api/alerts — alert history + recipient/subscription management data
//! for the /alerts SPA page (manage_alerts to change, view_dashboard to read).
//! TODO(milestone 2).

use axum::http::StatusCode;
use axum::Json;
use serde_json::Value;

use super::not_implemented;

pub async fn list() -> (StatusCode, Json<Value>) {
    not_implemented()
}
