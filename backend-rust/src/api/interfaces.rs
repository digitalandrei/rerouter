//! Interface read + per-interface monitoring toggle + rate history.
//!
//! Reads require `view_asset`; toggling `enabled_for_monitoring` requires
//! `edit_asset`. Field names are pinned by the frontend contract
//! (../../frontend/src/lib/api.ts: Interface / InterfaceMetrics / Sample).

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{err, AppState};
use crate::auth::rbac::{markers, RequirePermission};

type JsonResp = (StatusCode, Json<Value>);

/// A `device_interfaces` row (without metrics).
#[derive(sqlx::FromRow)]
struct InterfaceRow {
    id: u64,
    device_id: u64,
    if_index: u32,
    if_name: Option<String>,
    if_descr: Option<String>,
    if_alias: Option<String>,
    if_speed_bps: Option<u64>,
    admin_status: Option<String>,
    oper_status: Option<String>,
    enabled_for_monitoring: bool,
}

/// The latest `interface_metrics_current` row (InterfaceMetrics shape).
#[derive(sqlx::FromRow)]
struct MetricsRow {
    sampled_at: Option<chrono::DateTime<chrono::Utc>>,
    valid_sample: bool,
    rx_bps: f64,
    tx_bps: f64,
    rx_pps: f64,
    tx_pps: f64,
    rx_util_percent: f64,
    tx_util_percent: f64,
    in_errors: Option<u64>,
    out_errors: Option<u64>,
}

const IFACE_COLS: &str = "id, device_id, if_index, if_name, if_descr, if_alias, if_speed_bps, \
     admin_status, oper_status, enabled_for_monitoring";

const METRIC_COLS: &str = "sampled_at, valid_sample, rx_bps, tx_bps, rx_pps, tx_pps, \
     rx_util_percent, tx_util_percent, in_errors, out_errors";

fn metrics_json(m: &MetricsRow) -> Value {
    json!({
        "sampled_at": m.sampled_at.map(|t| t.to_rfc3339()),
        "valid_sample": m.valid_sample,
        "rx_bps": m.rx_bps,
        "tx_bps": m.tx_bps,
        "rx_pps": m.rx_pps,
        "tx_pps": m.tx_pps,
        "rx_util_percent": m.rx_util_percent,
        "tx_util_percent": m.tx_util_percent,
        "in_errors": m.in_errors.unwrap_or(0),
        "out_errors": m.out_errors.unwrap_or(0),
    })
}

fn interface_json(r: &InterfaceRow, metrics: Option<&MetricsRow>) -> Value {
    json!({
        "id": r.id,
        "device_id": r.device_id,
        "if_index": r.if_index,
        // The contract types if_name as a non-null string; default to "" when the
        // agent only returned ifDescr.
        "if_name": r.if_name.clone().unwrap_or_default(),
        "if_descr": r.if_descr,
        "if_alias": r.if_alias,
        "if_speed_bps": r.if_speed_bps,
        "admin_status": r.admin_status.clone().unwrap_or_default(),
        "oper_status": r.oper_status.clone().unwrap_or_default(),
        "enabled_for_monitoring": r.enabled_for_monitoring,
        "metrics": metrics.map(metrics_json),
    })
}

/// Load every interface on a device with its latest metrics (used by both the
/// device-scoped list and the single-interface fetch).
pub async fn load_interfaces_for_device(pool: &sqlx::MySqlPool, device_id: u64) -> anyhow::Result<Vec<Value>> {
    let rows = sqlx::query_as::<_, InterfaceRow>(&format!(
        "SELECT {IFACE_COLS} FROM device_interfaces WHERE device_id = ? \
         ORDER BY display_order, if_index"
    ))
    .bind(device_id)
    .fetch_all(pool)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        let m = sqlx::query_as::<_, MetricsRow>(&format!(
            "SELECT {METRIC_COLS} FROM interface_metrics_current WHERE interface_id = ?"
        ))
        .bind(r.id)
        .fetch_optional(pool)
        .await?;
        out.push(interface_json(r, m.as_ref()));
    }
    Ok(out)
}

async fn fetch_interface(pool: &sqlx::MySqlPool, id: u64) -> anyhow::Result<Option<Value>> {
    let row = sqlx::query_as::<_, InterfaceRow>(&format!(
        "SELECT {IFACE_COLS} FROM device_interfaces WHERE id = ?"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let m = sqlx::query_as::<_, MetricsRow>(&format!(
        "SELECT {METRIC_COLS} FROM interface_metrics_current WHERE interface_id = ?"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(Some(interface_json(&row, m.as_ref())))
}

/// GET /api/interfaces/{id}.
pub async fn show(
    _g: RequirePermission<markers::ViewAsset>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> JsonResp {
    match fetch_interface(&state.pool, id).await {
        Ok(Some(v)) => (StatusCode::OK, Json(v)),
        Ok(None) => err(StatusCode::NOT_FOUND, "interface not found"),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateInterface {
    enabled_for_monitoring: bool,
}

/// PUT /api/interfaces/{id} — toggle monitoring. Only monitored interfaces are
/// polled and rule-evaluated.
pub async fn update(
    _g: RequirePermission<markers::EditAsset>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
    Json(body): Json<UpdateInterface>,
) -> JsonResp {
    let res = sqlx::query("UPDATE device_interfaces SET enabled_for_monitoring = ? WHERE id = ?")
        .bind(body.enabled_for_monitoring)
        .bind(id)
        .execute(&state.pool)
        .await;
    match res {
        Ok(r) if r.rows_affected() > 0 => match fetch_interface(&state.pool, id).await {
            Ok(Some(v)) => (StatusCode::OK, Json(v)),
            _ => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
        },
        // rows_affected == 0 can also mean the value was unchanged; confirm existence.
        Ok(_) => match fetch_interface(&state.pool, id).await {
            Ok(Some(v)) => (StatusCode::OK, Json(v)),
            Ok(None) => err(StatusCode::NOT_FOUND, "interface not found"),
            Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
        },
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

#[derive(Debug, Deserialize)]
pub struct MetricsQuery {
    /// Window in minutes (default 60). Bounded to the 7-day retention.
    minutes: Option<i64>,
}

/// GET /api/interfaces/{id}/metrics?minutes=N — rate history (Sample[]).
/// Only valid samples are returned; invalid (wrap/reset) rows are gaps.
pub async fn metrics(
    _g: RequirePermission<markers::ViewAsset>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
    Query(q): Query<MetricsQuery>,
) -> JsonResp {
    let exists: Option<u64> = sqlx::query_scalar("SELECT id FROM device_interfaces WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None);
    if exists.is_none() {
        return err(StatusCode::NOT_FOUND, "interface not found");
    }
    let minutes = q.minutes.unwrap_or(60).clamp(1, 7 * 24 * 60);

    let rows = sqlx::query_as::<_, (chrono::DateTime<chrono::Utc>, f64, f64, f64, f64, f64, f64)>(
        "SELECT sampled_at, rx_bps, tx_bps, rx_pps, tx_pps, rx_util_percent, tx_util_percent \
         FROM interface_samples \
         WHERE interface_id = ? AND valid_sample = 1 \
           AND sampled_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? MINUTE) \
         ORDER BY sampled_at ASC",
    )
    .bind(id)
    .bind(minutes)
    .fetch_all(&state.pool)
    .await;

    match rows {
        Ok(rows) => {
            let out: Vec<Value> = rows
                .into_iter()
                .map(|(ts, rx_bps, tx_bps, rx_pps, tx_pps, rx_u, tx_u)| {
                    json!({
                        "sampled_at": ts.to_rfc3339(),
                        "rx_bps": rx_bps,
                        "tx_bps": tx_bps,
                        "rx_pps": rx_pps,
                        "tx_pps": tx_pps,
                        "rx_util_percent": rx_u,
                        "tx_util_percent": tx_u,
                    })
                })
                .collect();
            (StatusCode::OK, Json(json!(out)))
        }
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}
