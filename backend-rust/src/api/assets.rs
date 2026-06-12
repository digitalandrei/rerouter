//! Protected-asset CRUD + live-status/test endpoints (test telemetry,
//! rediscover, live metrics). Reads require view_asset; writes require
//! edit_asset. TODO(milestone 1): wire to db + telemetry.

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

/// POST /api/assets/{id}/test/telemetry — one-shot telemetry probe.
pub async fn test_telemetry() -> (StatusCode, Json<Value>) {
    not_implemented()
}

/// POST /api/assets/{id}/rediscover — re-run provider/zone discovery.
pub async fn rediscover() -> (StatusCode, Json<Value>) {
    not_implemented()
}

/// GET /api/assets/{id}/live — current normalized metrics + staleness flag.
pub async fn live() -> (StatusCode, Json<Value>) {
    not_implemented()
}
