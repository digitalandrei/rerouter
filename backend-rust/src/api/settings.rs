//! GET/PUT /api/settings — system_settings key/value (admin only via
//! manage_users/manage_locks-level roles). Flipping
//! automatic_actions_enabled is a high-visibility, audited change; it defaults
//! to false and nothing in the system may flip it implicitly.
//! TODO(milestone 2).

use axum::http::StatusCode;
use axum::Json;
use serde_json::Value;

use super::not_implemented;

pub async fn show() -> (StatusCode, Json<Value>) {
    not_implemented()
}

pub async fn update() -> (StatusCode, Json<Value>) {
    not_implemented()
}
