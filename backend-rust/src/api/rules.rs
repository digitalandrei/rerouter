//! Detection-rule CRUD (edit_rules). automatic_reroute_enabled defaults to off
//! per rule and is additionally gated by the global switch + safety model.
//! TODO(milestone 2): wire to db + detection engine.

use axum::http::StatusCode;
use axum::Json;
use serde_json::Value;

use super::not_implemented;

pub async fn list() -> (StatusCode, Json<Value>) {
    not_implemented()
}

pub async fn create() -> (StatusCode, Json<Value>) {
    not_implemented()
}

pub async fn show() -> (StatusCode, Json<Value>) {
    not_implemented()
}

pub async fn update() -> (StatusCode, Json<Value>) {
    not_implemented()
}

pub async fn remove() -> (StatusCode, Json<Value>) {
    not_implemented()
}
