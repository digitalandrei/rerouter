//! Reroute-provider CRUD. Secrets are encrypted at rest by the controller
//! (AES-256-GCM, key from SECRETS_KEY); responses expose only credential
//! references/metadata (view_credentials_metadata) — never secret material.
//! Writes require edit_provider / edit_credentials. TODO(milestone 1).

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
