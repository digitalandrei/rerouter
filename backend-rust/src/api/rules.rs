//! Detection-rule CRUD (edit_rules to write, view_asset to read).
//!
//! A rule targets a monitored interface XOR a protected asset (enforced here).
//! `automatic_reroute_enabled` defaults off per rule and is additionally gated by
//! the global switch + the reroute safety model — in observe mode it never
//! executes. Field names are pinned by the frontend contract
//! (../../frontend/src/lib/api.ts: Rule).

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{err, AppState};
use crate::auth::rbac::{self, markers, RequirePermission};
use crate::reroute::flow_target::{self, PreparedAction};

/// Templates whose `prefix` is a host-route target eligible for flow auto-target.
/// The IPv6 siblings are swapped in automatically, so only the v4 names are listed.
fn template_supports_auto_target(name: &str) -> bool {
    matches!(name, "null_route_prefix" | "blackhole_prefix")
}

type JsonResp = (StatusCode, Json<Value>);

/// Metrics valid for an interface-target rule (docs/telemetry-model.md).
const INTERFACE_METRICS: &[&str] = &[
    "rx_bps",
    "tx_bps",
    "rx_pps",
    "tx_pps",
    "rx_util_percent",
    "tx_util_percent",
    "in_err_rate",
    "out_err_rate",
    "oper_status",
];

/// Metrics that can be SUMMED across interfaces for a `sum` rule (rates only).
const SUMMABLE_METRICS: &[&str] = &[
    "rx_bps",
    "tx_bps",
    "rx_pps",
    "tx_pps",
    "in_err_rate",
    "out_err_rate",
];

/// Flow-derived metrics: evaluated against the latest closed flow bucket for the
/// rule's (interface, direction[, protocol][, port]) selector (docs/flow-telemetry.md).
const FLOW_METRICS: &[&str] = &["flow_pps", "flow_bps"];

fn is_flow_metric(m: &str) -> bool {
    FLOW_METRICS.contains(&m)
}

#[derive(sqlx::FromRow)]
struct RuleRow {
    id: u64,
    actions_revision: u64,
    name: String,
    interface_id: Option<u64>,
    device_id: Option<u64>,
    metric: String,
    metric_aggregation: String,
    flow_direction: Option<String>,
    flow_protocol: Option<u16>,
    flow_port: Option<u16>,
    flow_port_kind: Option<String>,
    operator: String,
    threshold_value: f64,
    duration_seconds: u32,
    consecutive_samples: u32,
    recovery_mode: String,
    recovery_threshold_value: Option<f64>,
    recovery_window_seconds: Option<u32>,
    recovery_consecutive_samples: Option<u32>,
    severity: String,
    enabled: bool,
    automatic_reroute_enabled: bool,
    automatic_revert_enabled: bool,
    manual_apply_enabled: bool,
    reroute_template_id: Option<u64>,
    // Resolved target labels + live evaluation state (for the list UI).
    interface_name: Option<String>,
    device_name: Option<String>,
    current_state: Option<String>,
    last_metric_value: Option<f64>,
    last_evaluated_at: Option<chrono::DateTime<chrono::Utc>>,
    // Live progression toward firing (from rule_states).
    consecutive_match_count: Option<u32>,
    first_matched_at: Option<chrono::DateTime<chrono::Utc>>,
    // Why the drift audit switched automatic execution off. Kept until a human
    // re-arms, so the reason survives a self-heal that clears the action marker.
    auto_disarmed_at: Option<chrono::DateTime<chrono::Utc>>,
    auto_disarmed_reason: Option<String>,
}

/// Rule columns + resolved target names + the latest evaluation snapshot
/// (rule_states). Note the table aliases (`r`/`i`/`d`/`rs`).
const RULE_SELECT: &str =
    "SELECT r.id, r.actions_revision, r.name, r.interface_id, r.device_id, r.metric, \
     r.metric_aggregation, \
     r.flow_direction, r.flow_protocol, r.flow_port, r.flow_port_kind, \
     r.operator, r.threshold_value, r.duration_seconds, r.consecutive_samples, \
     r.recovery_mode, r.recovery_threshold_value, r.recovery_window_seconds, \
     r.recovery_consecutive_samples, r.severity, r.enabled, \
     r.automatic_reroute_enabled, r.automatic_revert_enabled, r.manual_apply_enabled, r.reroute_template_id, \
     r.auto_disarmed_at, r.auto_disarmed_reason, \
     i.if_name AS interface_name, d.name AS device_name, \
     rs.current_state, rs.last_metric_value, rs.last_evaluated_at, \
     rs.consecutive_match_count, rs.first_matched_at \
     FROM rules r \
     LEFT JOIN device_interfaces i ON i.id = r.interface_id \
     LEFT JOIN devices d ON d.id = r.device_id \
     LEFT JOIN rule_states rs ON rs.rule_id = r.id";

fn rule_json(r: &RuleRow, actions: Vec<Value>, member_interface_ids: Vec<u64>) -> Value {
    json!({
        "id": r.id,
        "actions_revision": r.actions_revision,
        "name": r.name,
        "target_kind": if r.metric_aggregation == "sum" { "interface_group" } else { "interface" },
        "interface_id": r.interface_id,
        "device_id": r.device_id,
        "metric": r.metric,
        "metric_aggregation": r.metric_aggregation,
        "member_interface_ids": member_interface_ids,
        "flow_direction": r.flow_direction,
        "flow_protocol": r.flow_protocol,
        "flow_port": r.flow_port,
        "flow_port_kind": r.flow_port_kind,
        "operator": r.operator,
        "threshold_value": r.threshold_value,
        "duration_seconds": r.duration_seconds,
        "consecutive_samples": r.consecutive_samples,
        "recovery_mode": r.recovery_mode,
        "recovery_threshold_value": r.recovery_threshold_value,
        "recovery_window_seconds": r.recovery_window_seconds,
        "recovery_consecutive_samples": r.recovery_consecutive_samples,
        "severity": r.severity,
        "enabled": r.enabled,
        "automatic_reroute_enabled": r.automatic_reroute_enabled,
        "automatic_revert_enabled": r.automatic_revert_enabled,
        "auto_disarmed_at": r.auto_disarmed_at.map(|t| t.to_rfc3339()),
        "auto_disarmed_reason": r.auto_disarmed_reason,
        "manual_apply_enabled": r.manual_apply_enabled,
        "reroute_template_id": r.reroute_template_id,
        "interface_name": r.interface_name,
        "device_name": r.device_name,
        "current_state": r.current_state,
        "current_value": r.last_metric_value,
        "last_evaluated_at": r.last_evaluated_at.map(|t| t.to_rfc3339()),
        "consecutive_match_count": r.consecutive_match_count,
        "first_matched_at": r.first_matched_at.map(|t| t.to_rfc3339()),
        "action_count": actions.len(),
        "actions": actions,
    })
}

/// Load a rule's attached actions (template + target router + params) for the
/// rule JSON. Joins display names so the SPA needn't re-resolve them.
async fn load_actions(pool: &sqlx::MySqlPool, rule_id: u64) -> anyhow::Result<Vec<Value>> {
    let rows = sqlx::query_as::<_, (u64, u64, String, Option<String>, u64, String, Option<sqlx::types::Json<Value>>, bool, u32, Option<String>, String, Option<String>, Option<chrono::DateTime<chrono::Utc>>)>(
        "SELECT ra.id, ra.reroute_template_id, t.name, t.display_name, ra.device_id, d.name, ra.params_json, ra.enabled, ra.position, ra.auto_target, \
                ra.inventory_state, ra.inventory_drift_reason, ra.inventory_checked_at \
         FROM rule_actions ra \
         JOIN reroute_templates t ON t.id = ra.reroute_template_id \
         JOIN devices d ON d.id = ra.device_id \
         WHERE ra.rule_id = ? ORDER BY ra.position, ra.id",
    )
    .bind(rule_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                template_id,
                template_name,
                template_display_name,
                device_id,
                device_name,
                params,
                enabled,
                position,
                auto_target,
                inventory_state,
                inventory_drift_reason,
                inventory_checked_at,
            )| {
                json!({
                    "id": id,
                    "reroute_template_id": template_id,
                    "template_name": template_name,
                    "template_display_name": template_display_name,
                    "device_id": device_id,
                    "device_name": device_name,
                    "params": params.map(|j| j.0).unwrap_or(Value::Null),
                    "enabled": enabled,
                    "position": position,
                    "auto_target": auto_target,
                    // Drift audit (reroute::inventory_audit). Advisory for the UI
                    // only — the executor re-validates at fire time regardless.
                    "inventory_state": inventory_state,
                    "inventory_drift_reason": inventory_drift_reason,
                    "inventory_checked_at": inventory_checked_at.map(|t| t.to_rfc3339()),
                })
            },
        )
        .collect())
}

/// Member interface ids of a `sum` rule (empty for a single-interface rule).
async fn load_member_interfaces(pool: &sqlx::MySqlPool, rule_id: u64) -> anyhow::Result<Vec<u64>> {
    Ok(sqlx::query_scalar::<_, u64>(
        "SELECT interface_id FROM rule_interfaces WHERE rule_id = ? ORDER BY interface_id",
    )
    .bind(rule_id)
    .fetch_all(pool)
    .await?)
}

/// Build the full rule JSON (row + its actions + any aggregation members).
async fn rule_value(pool: &sqlx::MySqlPool, r: &RuleRow) -> anyhow::Result<Value> {
    let actions = load_actions(pool, r.id).await?;
    let members = if r.metric_aggregation == "sum" {
        load_member_interfaces(pool, r.id).await?
    } else {
        Vec::new()
    };
    Ok(rule_json(r, actions, members))
}

async fn fetch_rule(pool: &sqlx::MySqlPool, id: u64) -> anyhow::Result<Option<Value>> {
    let row = sqlx::query_as::<_, RuleRow>(&format!("{RULE_SELECT} WHERE r.id = ?"))
        .bind(id)
        .fetch_optional(pool)
        .await?;
    match row {
        Some(r) => Ok(Some(rule_value(pool, &r).await?)),
        None => Ok(None),
    }
}

/// GET /api/rules.
pub async fn list(
    _g: RequirePermission<markers::ViewAsset>,
    State(state): State<AppState>,
) -> JsonResp {
    match sqlx::query_as::<_, RuleRow>(&format!("{RULE_SELECT} ORDER BY r.name"))
        .fetch_all(&state.pool)
        .await
    {
        Ok(rows) => {
            let mut out = Vec::with_capacity(rows.len());
            for r in &rows {
                match rule_value(&state.pool, r).await {
                    Ok(rule) => out.push(rule),
                    Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
                }
            }
            (StatusCode::OK, Json(json!(out)))
        }
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

#[derive(Debug, Deserialize)]
pub struct RuleBody {
    name: String,
    interface_id: Option<u64>,
    /// 'single' (default, per-interface) or 'sum' (summed across `interface_ids`).
    #[serde(default = "default_aggregation")]
    metric_aggregation: String,
    /// Member interfaces for a `sum` rule (may span devices). Ignored otherwise.
    #[serde(default)]
    interface_ids: Vec<u64>,
    metric: String,
    // Flow-metric selector (ignored / forced NULL for SNMP interface metrics).
    #[serde(default)]
    flow_direction: Option<String>,
    #[serde(default)]
    flow_protocol: Option<u16>,
    #[serde(default)]
    flow_port: Option<u16>,
    #[serde(default)]
    flow_port_kind: Option<String>,
    operator: String,
    threshold_value: f64,
    #[serde(default)]
    duration_seconds: Option<u32>,
    #[serde(default)]
    consecutive_samples: Option<u32>,
    #[serde(default = "default_recovery_mode")]
    recovery_mode: String,
    #[serde(default)]
    recovery_threshold_value: Option<f64>,
    #[serde(default)]
    recovery_window_seconds: Option<u32>,
    #[serde(default)]
    recovery_consecutive_samples: Option<u32>,
    #[serde(default = "default_severity")]
    severity: String,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    automatic_reroute_enabled: bool,
    #[serde(default)]
    automatic_revert_enabled: bool,
    /// Opt-in: allow operators to manually apply this rule's actions from a
    /// firing alert. Off by default. Gated like any manual reroute at apply time.
    #[serde(default)]
    manual_apply_enabled: bool,
    reroute_template_id: Option<u64>,
}

fn default_severity() -> String {
    "warning".to_string()
}
fn default_recovery_mode() -> String {
    "auto".to_string()
}
fn default_aggregation() -> String {
    "single".to_string()
}

fn valid_recovery_mode(m: &str) -> bool {
    matches!(m, "auto" | "threshold" | "manual")
}
fn default_true() -> bool {
    true
}

/// Validate operator + metric + target. Returns the resolved device_id for an
/// interface rule (looked up from the interface) on success.
async fn validate(
    pool: &sqlx::MySqlPool,
    body: &RuleBody,
) -> Result<Option<u64>, (StatusCode, String)> {
    if body.name.trim().is_empty() {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "name is required".into()));
    }
    // Operators: the contract pins > and < for interface rules.
    if !matches!(
        body.operator.as_str(),
        ">" | "<" | ">=" | "<=" | "==" | "!="
    ) {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "unsupported operator".into(),
        ));
    }
    // Aggregation (`sum`) rules target a SET of interfaces (possibly across
    // devices) rather than one. They have no single owning device (device_id NULL)
    // and list members in rule_interfaces.
    if body.metric_aggregation == "sum" {
        if !SUMMABLE_METRICS.contains(&body.metric.as_str()) {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                format!(
                    "a summed rule's metric must be one of: {}",
                    SUMMABLE_METRICS.join(", ")
                ),
            ));
        }
        if body.interface_ids.is_empty() {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                "a summed rule needs at least one interface in interface_ids".into(),
            ));
        }
        // Every member must exist.
        for iid in &body.interface_ids {
            let exists: Option<u64> =
                sqlx::query_scalar("SELECT id FROM device_interfaces WHERE id = ?")
                    .bind(iid)
                    .fetch_optional(pool)
                    .await
                    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db_error".into()))?;
            if exists.is_none() {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!("interface_id {iid} does not exist"),
                ));
            }
        }
        if !valid_recovery_mode(&body.recovery_mode) {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                "recovery_mode must be auto, threshold, or manual".into(),
            ));
        }
        return Ok(None); // no single owning device
    }

    // A single rule targets one interface (v1 detection is interface-scoped).
    let Some(iface_id) = body.interface_id else {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "interface_id is required".into(),
        ));
    };
    if is_flow_metric(&body.metric) {
        // Flow rule: a direction is required; protocol/port are optional selectors.
        if !matches!(
            body.flow_direction.as_deref(),
            Some("ingress") | Some("egress")
        ) {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                "flow_direction must be ingress or egress".into(),
            ));
        }
        if let Some(pk) = body.flow_port_kind.as_deref() {
            if !matches!(pk, "src" | "dst") {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "flow_port_kind must be src or dst".into(),
                ));
            }
        }
        if body.flow_protocol.is_some() && body.flow_port.is_none() {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                "flow_protocol currently requires a flow_port selector".into(),
            ));
        }
        // Flow rules use time-window persistence (duration_seconds); each tick
        // re-reads the same latest closed bucket, so consecutive_samples would
        // count poll ticks against unchanged evidence. Reject it here — the
        // consecutive-samples gate is SNMP-only.
        if body.consecutive_samples.is_some_and(|n| n > 0) {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                "flow rules use duration_seconds persistence; consecutive_samples must be 0 or omitted".into(),
            ));
        }
    } else if !INTERFACE_METRICS.contains(&body.metric.as_str()) {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!(
                "metric must be one of: {}, or flow_pps / flow_bps",
                INTERFACE_METRICS.join(", ")
            ),
        ));
    }
    if !valid_recovery_mode(&body.recovery_mode) {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "recovery_mode must be auto, threshold, or manual".into(),
        ));
    }
    // Resolve the owning device; also validates the interface exists.
    let device_id: Option<u64> =
        sqlx::query_scalar("SELECT device_id FROM device_interfaces WHERE id = ?")
            .bind(iface_id)
            .fetch_optional(pool)
            .await
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db_error".into()))?;
    match device_id {
        Some(d) => Ok(Some(d)),
        None => Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "interface_id does not exist".into(),
        )),
    }
}

/// POST /api/rules.
pub async fn create(
    g: RequirePermission<markers::EditRules>,
    State(state): State<AppState>,
    Json(body): Json<RuleBody>,
) -> JsonResp {
    let device_id = match validate(&state.pool, &body).await {
        Ok(d) => d,
        Err((code, msg)) => return err(code, &msg),
    };

    // Flow selectors only apply to flow metrics; force NULL otherwise. A flow_port
    // without an explicit kind defaults to destination port.
    let (flow_direction, flow_protocol, flow_port, flow_port_kind) = if is_flow_metric(&body.metric)
    {
        let kind = body
            .flow_port_kind
            .clone()
            .or_else(|| body.flow_port.map(|_| "dst".to_string()));
        (
            body.flow_direction.clone(),
            body.flow_protocol,
            body.flow_port,
            kind,
        )
    } else {
        (None, None, None, None)
    };
    let flow_metric = is_flow_metric(&body.metric);
    let duration_seconds = body.duration_seconds.unwrap_or(if flow_metric {
        state.config.detection.default_min_duration_seconds as u32
    } else {
        0
    });
    let consecutive_samples = body.consecutive_samples.unwrap_or(if flow_metric {
        0
    } else {
        state.config.detection.default_consecutive_samples
    });

    // Recovery threshold + persistence overrides only apply to threshold mode.
    let (recovery_threshold_value, recovery_window_seconds, recovery_consecutive_samples) =
        if body.recovery_mode == "threshold" {
            (
                body.recovery_threshold_value,
                body.recovery_window_seconds,
                body.recovery_consecutive_samples,
            )
        } else {
            (None, None, None)
        };

    let is_sum = body.metric_aggregation == "sum";
    // A summed rule owns no single interface/device; its members live in
    // rule_interfaces (inserted below).
    let interface_id = if is_sum { None } else { body.interface_id };

    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };

    let res = sqlx::query(
        "INSERT INTO rules (name, interface_id, device_id, metric, metric_aggregation, \
            flow_direction, flow_protocol, flow_port, flow_port_kind, \
            operator, threshold_value, \
            duration_seconds, consecutive_samples, recovery_mode, recovery_threshold_value, \
            recovery_window_seconds, recovery_consecutive_samples, \
            severity, enabled, automatic_reroute_enabled, automatic_revert_enabled, manual_apply_enabled, \
            reroute_template_id, created_by, updated_by) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&body.name)
    .bind(interface_id)
    .bind(device_id)
    .bind(&body.metric)
    .bind(if is_sum { "sum" } else { "single" })
    .bind(flow_direction)
    .bind(flow_protocol)
    .bind(flow_port)
    .bind(flow_port_kind)
    .bind(&body.operator)
    .bind(body.threshold_value)
    .bind(duration_seconds)
    .bind(consecutive_samples)
    .bind(&body.recovery_mode)
    .bind(recovery_threshold_value)
    .bind(recovery_window_seconds)
    .bind(recovery_consecutive_samples)
    .bind(&body.severity)
    .bind(body.enabled)
    .bind(body.automatic_reroute_enabled)
    .bind(body.automatic_revert_enabled)
    .bind(body.manual_apply_enabled)
    .bind(body.reroute_template_id)
    .bind(g.session.user_id)
    .bind(g.session.user_id)
    .execute(&mut *tx)
    .await;

    let rule_id = match res {
        Ok(r) => r.last_insert_id(),
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };

    // Persist the member set for a summed rule (interface + its owning device).
    if is_sum {
        for iid in &body.interface_ids {
            let dev: Option<u64> =
                sqlx::query_scalar("SELECT device_id FROM device_interfaces WHERE id = ?")
                    .bind(iid)
                    .fetch_optional(&mut *tx)
                    .await
                    .ok()
                    .flatten();
            let Some(dev) = dev else {
                let _ = tx.rollback().await;
                return err(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "sum rule contains an unknown interface",
                );
            };
            if sqlx::query(
                "INSERT IGNORE INTO rule_interfaces (rule_id, device_id, interface_id) \
                 VALUES (?, ?, ?)",
            )
            .bind(rule_id)
            .bind(dev)
            .bind(iid)
            .execute(&mut *tx)
            .await
            .is_err()
            {
                let _ = tx.rollback().await;
                return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error");
            }
        }
    }
    if super::audit_mutation_on(
        &mut tx,
        &g.session,
        "rule_created",
        "rule",
        rule_id,
        "detection rule created",
    )
    .await
    .is_err()
        || tx.commit().await.is_err()
    {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "audit_write_failed");
    }

    match fetch_rule(&state.pool, rule_id).await {
        Ok(Some(v)) => (StatusCode::CREATED, Json(v)),
        _ => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

/// GET /api/rules/{id}.
pub async fn show(
    _g: RequirePermission<markers::ViewAsset>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> JsonResp {
    match fetch_rule(&state.pool, id).await {
        Ok(Some(v)) => (StatusCode::OK, Json(v)),
        Ok(None) => err(StatusCode::NOT_FOUND, "rule not found"),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

#[derive(Debug, Deserialize)]
pub struct RuleUpdate {
    name: Option<String>,
    metric: Option<String>,
    flow_direction: Option<String>,
    #[serde(default, deserialize_with = "present_nullable")]
    flow_protocol: Option<Option<u16>>,
    #[serde(default, deserialize_with = "present_nullable")]
    flow_port: Option<Option<u16>>,
    #[serde(default, deserialize_with = "present_nullable")]
    flow_port_kind: Option<Option<String>>,
    operator: Option<String>,
    threshold_value: Option<f64>,
    duration_seconds: Option<u32>,
    consecutive_samples: Option<u32>,
    recovery_mode: Option<String>,
    #[serde(default, deserialize_with = "present_nullable")]
    recovery_threshold_value: Option<Option<f64>>,
    #[serde(default, deserialize_with = "present_nullable")]
    recovery_window_seconds: Option<Option<u32>>,
    #[serde(default, deserialize_with = "present_nullable")]
    recovery_consecutive_samples: Option<Option<u32>>,
    severity: Option<String>,
    enabled: Option<bool>,
    automatic_reroute_enabled: Option<bool>,
    automatic_revert_enabled: Option<bool>,
    manual_apply_enabled: Option<bool>,
    #[serde(default, deserialize_with = "present_nullable")]
    reroute_template_id: Option<Option<u64>>,
}

fn present_nullable<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

/// PUT /api/rules/{id} — partial update (target is immutable here; recreate to
/// retarget). Re-validates operator/metric when changed.
pub async fn update(
    g: RequirePermission<markers::EditRules>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
    Json(body): Json<RuleUpdate>,
) -> JsonResp {
    let _policy_fence = match crate::reroute::guard::policy_fence(&state.pool).await {
        Ok(fence) => fence,
        Err(_) => {
            return err(
                StatusCode::CONFLICT,
                "safety policy is busy; retry after the active action finishes",
            )
        }
    };

    let Ok(Some(existing)) = sqlx::query_as::<_, RuleRow>(&format!("{RULE_SELECT} WHERE r.id = ?"))
        .bind(id)
        .fetch_optional(&state.pool)
        .await
    else {
        return err(StatusCode::NOT_FOUND, "rule not found");
    };

    if let Some(op) = &body.operator {
        if !matches!(op.as_str(), ">" | "<" | ">=" | "<=" | "==" | "!=") {
            return err(StatusCode::UNPROCESSABLE_ENTITY, "unsupported operator");
        }
    }
    if let Some(metric) = &body.metric {
        if existing.metric_aggregation == "sum" {
            // A summed rule can only change between summable metrics.
            if !SUMMABLE_METRICS.contains(&metric.as_str()) {
                return err(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "a summed rule's metric must be a summable rate metric",
                );
            }
        } else if is_flow_metric(metric) {
            // Changing into a flow metric requires the rule to already be a flow
            // rule (has a selector). Recreate the rule to change metric family.
            if existing.flow_direction.is_none() {
                return err(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "recreate the rule to switch to a flow metric",
                );
            }
        } else if existing.interface_id.is_some() && !INTERFACE_METRICS.contains(&metric.as_str()) {
            return err(
                StatusCode::UNPROCESSABLE_ENTITY,
                "unsupported interface metric",
            );
        }
    }
    if let Some(Some(pk)) = &body.flow_port_kind {
        if !matches!(pk.as_str(), "src" | "dst") {
            return err(
                StatusCode::UNPROCESSABLE_ENTITY,
                "flow_port_kind must be src or dst",
            );
        }
    }
    if let Some(dir) = &body.flow_direction {
        if !matches!(dir.as_str(), "ingress" | "egress") {
            return err(
                StatusCode::UNPROCESSABLE_ENTITY,
                "flow_direction must be ingress or egress",
            );
        }
    }
    let final_protocol = body.flow_protocol.unwrap_or(existing.flow_protocol);
    let final_port = body.flow_port.unwrap_or(existing.flow_port);
    if final_protocol.is_some() && final_port.is_none() {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "flow_protocol currently requires a flow_port selector",
        );
    }
    // Flow rules use time-window persistence; consecutive_samples is the SNMP-only
    // gate. Reject when the EFFECTIVE metric is a flow metric and the EFFECTIVE
    // consecutive_samples (incoming value, else the stored row value) is > 0. This
    // catches setting the field on a flow rule and switching a rule into a flow
    // metric without zeroing consecutive_samples.
    let final_metric = body.metric.as_deref().unwrap_or(&existing.metric);
    let final_consecutive = body
        .consecutive_samples
        .unwrap_or(existing.consecutive_samples);
    if is_flow_metric(final_metric) && final_consecutive > 0 {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "flow rules use duration_seconds persistence; consecutive_samples must be 0 or omitted",
        );
    }
    if let Some(m) = &body.recovery_mode {
        if !valid_recovery_mode(m) {
            return err(
                StatusCode::UNPROCESSABLE_ENTITY,
                "recovery_mode must be auto, threshold, or manual",
            );
        }
    }
    if body.automatic_reroute_enabled == Some(true) {
        let unsafe_actions: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM rule_actions ra \
             JOIN reroute_templates t ON t.id = ra.reroute_template_id \
             WHERE ra.rule_id = ? AND ra.enabled = 1 \
               AND (t.enabled = 0 OR t.automatic_allowed = 0)",
        )
        .bind(id)
        .fetch_one(&state.pool)
        .await
        .unwrap_or(i64::MAX);
        if unsafe_actions > 0 {
            return err(
                StatusCode::UNPROCESSABLE_ENTITY,
                "one or more enabled actions are not allowed for automatic execution",
            );
        }
        // Re-arming into KNOWN-drifted inventory would arm a mitigation the
        // executor will refuse anyway. The drift marker is cleared by the next
        // conclusive discovery run, or immediately by "Discover prefixes".
        let drifted: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM rule_actions              WHERE rule_id = ? AND enabled = 1 AND inventory_state = 'drifted'",
        )
        .bind(id)
        .fetch_one(&state.pool)
        .await
        .unwrap_or(i64::MAX);
        if drifted > 0 {
            return err(
                StatusCode::UNPROCESSABLE_ENTITY,
                "one or more enabled actions no longer match the router's inventory;                  fix the action (or the router) and re-run device inventory discovery first",
            );
        }
    }

    let condition_changed = body.metric.is_some()
        || body.operator.is_some()
        || body.threshold_value.is_some()
        || body.duration_seconds.is_some()
        || body.consecutive_samples.is_some()
        || body.recovery_mode.is_some()
        || body.recovery_threshold_value.is_some()
        || body.recovery_window_seconds.is_some()
        || body.recovery_consecutive_samples.is_some()
        || body.flow_direction.is_some()
        || body.flow_protocol.is_some()
        || body.flow_port.is_some()
        || body.flow_port_kind.is_some();
    if matches!(
        existing.current_state.as_deref(),
        Some("firing" | "recovered_awaiting_revert")
    ) && (condition_changed || body.enabled == Some(false))
    {
        return err(
            StatusCode::CONFLICT,
            "clear the firing rule and complete its rollback before changing its condition or disabling it",
        );
    }

    let mut sets: Vec<&str> = Vec::new();
    if body.name.is_some() {
        sets.push("name = ?");
    }
    if body.metric.is_some() {
        sets.push("metric = ?");
    }
    if body.flow_direction.is_some() {
        sets.push("flow_direction = ?");
    }
    if body.flow_protocol.is_some() {
        sets.push("flow_protocol = ?");
    }
    if body.flow_port.is_some() {
        sets.push("flow_port = ?");
    }
    if body.flow_port_kind.is_some() {
        sets.push("flow_port_kind = ?");
    }
    if body.operator.is_some() {
        sets.push("operator = ?");
    }
    if body.threshold_value.is_some() {
        sets.push("threshold_value = ?");
    }
    if body.duration_seconds.is_some() {
        sets.push("duration_seconds = ?");
    }
    if body.consecutive_samples.is_some() {
        sets.push("consecutive_samples = ?");
    }
    if body.recovery_mode.is_some() {
        sets.push("recovery_mode = ?");
    }
    if body.recovery_threshold_value.is_some() {
        sets.push("recovery_threshold_value = ?");
    }
    if body.recovery_window_seconds.is_some() {
        sets.push("recovery_window_seconds = ?");
    }
    if body.recovery_consecutive_samples.is_some() {
        sets.push("recovery_consecutive_samples = ?");
    }
    if body.severity.is_some() {
        sets.push("severity = ?");
    }
    if body.enabled.is_some() {
        sets.push("enabled = ?");
    }
    if body.automatic_reroute_enabled.is_some() {
        sets.push("automatic_reroute_enabled = ?");
    }
    if body.automatic_revert_enabled.is_some() {
        sets.push("automatic_revert_enabled = ?");
    }
    if body.automatic_reroute_enabled == Some(true) {
        // A human re-armed it through the normal gate, so the auto-disarm record
        // has served its purpose. (The drift audit itself NEVER re-arms.)
        sets.push("auto_disarmed_at = NULL");
        sets.push("auto_disarmed_reason = NULL");
    }
    if body.manual_apply_enabled.is_some() {
        sets.push("manual_apply_enabled = ?");
    }
    if body.reroute_template_id.is_some() {
        sets.push("reroute_template_id = ?");
    }
    if condition_changed {
        sets.push("actions_revision = actions_revision + 1");
        sets.push("automatic_reroute_enabled = 0");
        sets.push("auto_disarmed_at = UTC_TIMESTAMP()");
        sets.push("auto_disarmed_reason = 'rule condition changed; review and explicitly re-arm'");
    }
    sets.push("updated_by = ?");

    let sql = format!("UPDATE rules SET {} WHERE id = ?", sets.join(", "));
    let mut q = sqlx::query(&sql);
    if let Some(v) = &body.name {
        q = q.bind(v);
    }
    if let Some(v) = &body.metric {
        q = q.bind(v);
    }
    if let Some(v) = &body.flow_direction {
        q = q.bind(v);
    }
    if let Some(v) = body.flow_protocol {
        q = q.bind(v);
    }
    if let Some(v) = body.flow_port {
        q = q.bind(v);
    }
    if let Some(v) = &body.flow_port_kind {
        q = q.bind(v);
    }
    if let Some(v) = &body.operator {
        q = q.bind(v);
    }
    if let Some(v) = body.threshold_value {
        q = q.bind(v);
    }
    if let Some(v) = body.duration_seconds {
        q = q.bind(v);
    }
    if let Some(v) = body.consecutive_samples {
        q = q.bind(v);
    }
    if let Some(v) = &body.recovery_mode {
        q = q.bind(v);
    }
    if let Some(v) = &body.recovery_threshold_value {
        q = q.bind(*v);
    }
    if let Some(v) = &body.recovery_window_seconds {
        q = q.bind(*v);
    }
    if let Some(v) = &body.recovery_consecutive_samples {
        q = q.bind(*v);
    }
    if let Some(v) = &body.severity {
        q = q.bind(v);
    }
    if let Some(v) = body.enabled {
        q = q.bind(v);
    }
    if let Some(v) = body.automatic_reroute_enabled {
        q = q.bind(v);
    }
    if let Some(v) = body.automatic_revert_enabled {
        q = q.bind(v);
    }
    if let Some(v) = body.manual_apply_enabled {
        q = q.bind(v);
    }
    if let Some(v) = &body.reroute_template_id {
        q = q.bind(*v);
    }
    q = q.bind(g.session.user_id);
    q = q.bind(id);

    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    if q.execute(&mut *tx).await.is_err() {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error");
    }
    if condition_changed
        && sqlx::query(
            "INSERT INTO rule_states \
             (rule_id, current_state, consecutive_match_count, last_metric_value, \
              last_cleared_at, last_evaluated_at) \
             VALUES (?, 'clear', 0, 0, UTC_TIMESTAMP(), UTC_TIMESTAMP()) \
             ON DUPLICATE KEY UPDATE current_state = 'clear', first_matched_at = NULL, \
              recovery_first_at = NULL, recovery_consecutive = 0, \
              consecutive_match_count = 0, last_metric_value = 0, \
              last_cleared_at = UTC_TIMESTAMP(), last_evaluated_at = UTC_TIMESTAMP()",
        )
        .bind(id)
        .execute(&mut *tx)
        .await
        .is_err()
    {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "rule state reset failed");
    }
    if super::audit_mutation_on(
        &mut tx,
        &g.session,
        "rule_updated",
        "rule",
        id,
        "detection rule updated",
    )
    .await
    .is_err()
        || tx.commit().await.is_err()
    {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "audit_write_failed");
    }

    match fetch_rule(&state.pool, id).await {
        Ok(Some(v)) => (StatusCode::OK, Json(v)),
        _ => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

/// DELETE /api/rules/{id}.
pub async fn remove(
    g: RequirePermission<markers::EditRules>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> JsonResp {
    let _policy_fence = match crate::reroute::guard::policy_fence(&state.pool).await {
        Ok(fence) => fence,
        Err(_) => {
            return err(
                StatusCode::CONFLICT,
                "safety policy is busy; retry after the active action finishes",
            )
        }
    };

    let firing = match sqlx::query_scalar::<_, Option<String>>(
        "SELECT current_state FROM rule_states WHERE rule_id = ?",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(value) => value.flatten(),
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    if matches!(
        firing.as_deref(),
        Some("firing" | "recovered_awaiting_revert")
    ) {
        return err(
            StatusCode::CONFLICT,
            "clear the firing rule and complete its rollback before deleting it",
        );
    }
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    match outstanding_rule_actions(&state.pool, id).await {
        Ok(actions) if actions.is_empty() => {}
        Ok(_) => {
            return err(
                StatusCode::CONFLICT,
                "restore or reconcile this rule's owned mutations before deleting it",
            )
        }
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
    match sqlx::query("DELETE FROM rules WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await
    {
        Ok(r) if r.rows_affected() > 0 => {
            if super::audit_mutation_on(
                &mut tx,
                &g.session,
                "rule_deleted",
                "rule",
                id,
                "detection rule deleted",
            )
            .await
            .is_err()
                || tx.commit().await.is_err()
            {
                return err(StatusCode::INTERNAL_SERVER_ERROR, "audit_write_failed");
            }
            (StatusCode::OK, Json(json!({ "ok": true })))
        }
        Ok(_) => err(StatusCode::NOT_FOUND, "rule not found"),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

/// POST /api/rules/{id}/clear — operator-initiated clear of a firing rule (the
/// recovery path for recovery_mode = manual, or an admin override). Resets the
/// rule's detection state and records a `cleared` event.
///
/// NOT always side-effect-free: in ENFORCE mode, clearing a firing rule whose
/// Auto switch is on ALSO runs the rollback of its actions (a real config push,
/// the inverse of auto-recovery). That case therefore requires
/// `trigger_manual_reroute` on top of `edit_rules`. In observe mode, or for a
/// manual-only rule, nothing executes and `edit_rules` alone suffices.
pub async fn clear(
    g: RequirePermission<markers::EditRules>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
    _headers: HeaderMap,
    ConnectInfo(_socket): ConnectInfo<SocketAddr>,
    Json(body): Json<ApplyBody>,
) -> JsonResp {
    use super::manual_mitigations as manual;
    let name: Option<String> = match sqlx::query_scalar("SELECT name FROM rules WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.pool)
        .await
    {
        Ok(value) => value,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    let Some(name) = name else {
        return err(StatusCode::NOT_FOUND, "rule not found");
    };
    let reason = body
        .reason
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("manual clear of rule '{name}' (#{id})"));
    if body.dry_run {
        let originals = match outstanding_rule_actions(&state.pool, id).await {
            Ok(ids) => ids,
            Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
        };
        if !originals.is_empty()
            && !rbac::has_permission(
                &state.pool,
                &g.session,
                rbac::Permission::TriggerManualReroute,
            )
            .await
            .unwrap_or(false)
        {
            return err(
                StatusCode::FORBIDDEN,
                "trigger_manual_reroute is required to reverse the rule's actions",
            );
        }
        let actions = match crate::reroute::preparation::prepare_rollbacks(
            &state.pool,
            &originals,
            &reason,
            true,
        )
        .await
        {
            Ok(actions) => actions,
            Err(e) => return err(StatusCode::CONFLICT, &format!("{e:#}")),
        };
        let source =
            json!({"kind":"rule_clear","rule_id":id,"name":name,"original_reroute_ids":originals});
        let (status, Json(mut response)) = manual::preview_actions(
            &state,
            &g.session,
            "rule_clear",
            Some(id),
            actions,
            source,
            reason.clone(),
            json!({"rule_id":id,"reason":reason}),
            None,
        )
        .await;
        response["ok"] = json!(status.is_success());
        response["cleared"] = json!(false);
        return (status, Json(response));
    }
    let Some(token) = body.preview_token.as_deref() else {
        return err(StatusCode::CONFLICT, "preview_required");
    };
    let (plan_id, snapshot) = match manual::plan_for_token(
        &state.pool,
        g.session.user_id,
        token,
        "rule_clear",
        Some(id),
    )
    .await
    {
        Ok(value) => value,
        Err(e) => return err(StatusCode::CONFLICT, &e.to_string()),
    };
    if body
        .reason
        .as_deref()
        .is_some_and(|reason| reason.trim() != snapshot.reason)
    {
        return err(StatusCode::CONFLICT, "preview_changed");
    }
    if !snapshot.actions.is_empty()
        && !rbac::has_permission(
            &state.pool,
            &g.session,
            rbac::Permission::TriggerManualReroute,
        )
        .await
        .unwrap_or(false)
    {
        return err(
            StatusCode::FORBIDDEN,
            "trigger_manual_reroute is required to reverse the rule's actions",
        );
    }
    let accepted =
        match manual::accept_plan(&state, &g.session, plan_id, token, "rule_clear", Some(id)).await
        {
            Ok(value) => value,
            Err(e) => return err(StatusCode::CONFLICT, &format!("{e:#}")),
        };
    let bundle_id = accepted.bundle_id;
    if accepted.already_accepted {
        let (status, Json(mut response)) =
            super::reroutes::execution_results(&state.pool, bundle_id).await;
        let cleared = sqlx::query_scalar::<_, String>(
            "SELECT current_state FROM rule_states WHERE rule_id = ?",
        )
        .bind(id)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten()
        .as_deref()
            == Some("clear");
        response["ok"] = json!(status.is_success());
        response["cleared"] = json!(cleared);
        return (status, Json(response));
    }
    let run = manual::run_context(&g.session, &accepted);
    let pool = state.pool.clone();
    let cfg = state.config.clone();
    let actor = g.session.clone();
    let task = tokio::spawn(async move {
        let (success, results) = if accepted.snapshot.actions.is_empty() {
            (true, Vec::new())
        } else {
            let result =
                crate::reroute::bundle::run(&pool, &cfg, run, accepted.snapshot.actions).await;
            (result.state == "succeeded", result.results)
        };
        let cleared = if success {
            complete_manual_clear(&pool, id, bundle_id, &actor).await?
        } else {
            false
        };
        Ok::<_, anyhow::Error>((cleared, results))
    });
    match task.await {
        Ok(Ok((cleared, results))) => (
            StatusCode::OK,
            Json(
                json!({"ok":true,"cleared":cleared,"results":results,"bundle_id":bundle_id,"preview_token":null}),
            ),
        ),
        Ok(Err(e)) => err(
            StatusCode::CONFLICT,
            &format!("clear not confirmed; reconcile bundle #{bundle_id}: {e:#}"),
        ),
        Err(_) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("clear interrupted; reconcile bundle #{bundle_id}"),
        ),
    }
}

pub(crate) async fn outstanding_rule_actions(
    pool: &sqlx::MySqlPool,
    id: u64,
) -> anyhow::Result<Vec<u64>> {
    Ok(sqlx::query_scalar("SELECT r.id FROM reroutes r WHERE r.rule_id = ? AND r.rollback_of_reroute_id IS NULL \
        AND (r.state IN ('planned','pending','running','verifying','uncertain') OR r.mutation_effect IN ('changed','unknown') \
             OR (r.state = 'succeeded' AND r.mutation_effect = 'pending')) \
        AND NOT EXISTS (SELECT 1 FROM reroutes rb WHERE rb.rollback_of_reroute_id=r.id AND rb.state='succeeded') ORDER BY r.id DESC")
        .bind(id).fetch_all(pool).await?)
}

async fn complete_manual_clear(
    pool: &sqlx::MySqlPool,
    id: u64,
    bundle_id: u64,
    actor: &crate::auth::sessions::Session,
) -> anyhow::Result<bool> {
    let mut tx = pool.begin().await?;
    let exists: Option<u64> = sqlx::query_scalar("SELECT id FROM rules WHERE id = ? FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
    anyhow::ensure!(exists.is_some(), "rule was removed");
    let unresolved:i64=sqlx::query_scalar("SELECT COUNT(*) FROM reroutes r WHERE r.rule_id=? AND r.rollback_of_reroute_id IS NULL \
        AND (r.state IN ('planned','pending','running','verifying','uncertain') OR r.mutation_effect IN ('changed','unknown') \
             OR (r.state='succeeded' AND r.mutation_effect='pending')) \
        AND NOT EXISTS(SELECT 1 FROM reroutes rb WHERE rb.rollback_of_reroute_id=r.id AND rb.state='succeeded')")
        .bind(id).fetch_one(&mut *tx).await?;
    anyhow::ensure!(
        unresolved == 0,
        "rule still owns unresolved mutations; it remains firing"
    );
    sqlx::query("INSERT INTO rule_states(rule_id,current_state,consecutive_match_count,last_metric_value,last_cleared_at,last_evaluated_at) \
        VALUES(?,'clear',0,0,UTC_TIMESTAMP(),UTC_TIMESTAMP()) ON DUPLICATE KEY UPDATE current_state='clear',first_matched_at=NULL, \
        recovery_first_at=NULL,recovery_consecutive=0,consecutive_match_count=0,last_cleared_at=UTC_TIMESTAMP(),last_evaluated_at=UTC_TIMESTAMP()")
        .bind(id).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO rule_events(rule_id,event,metric_value,sampled_at) VALUES(?,'cleared',NULL,NULL)").bind(id).execute(&mut *tx).await?;
    super::audit_mutation_on(
        &mut tx,
        actor,
        "rule_cleared_manual",
        "rule",
        id,
        "cleared after verifying all owned mutations were reversed",
    )
    .await?;
    sqlx::query("UPDATE reroute_bundles SET state='succeeded',finished_at=UTC_TIMESTAMP(),source_json=JSON_SET(source_json,'$.clear_completed',true) WHERE id=?")
        .bind(bundle_id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(true)
}

#[derive(Debug, Deserialize)]
pub struct ApplyBody {
    /// Optional operator note for the audit log.
    #[serde(default)]
    reason: Option<String>,
    /// Render-only preview (even in enforce mode); changes nothing.
    #[serde(default)]
    dry_run: bool,
    /// One-time token returned by the immediately preceding enforce-mode preview.
    #[serde(default)]
    preview_token: Option<String>,
}

/// Manual rule application uses the same immutable preview and runner as named
/// manual mitigations. An unresolved sibling refuses the whole activation.
pub async fn apply(
    g: RequirePermission<markers::TriggerManualReroute>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
    _headers: HeaderMap,
    ConnectInfo(_socket): ConnectInfo<SocketAddr>,
    Json(body): Json<ApplyBody>,
) -> JsonResp {
    use super::manual_mitigations as manual;
    if !body.dry_run && body.preview_token.is_some() {
        let Some(token) = body.preview_token.as_deref() else {
            return err(StatusCode::CONFLICT, "preview_required");
        };
        let (plan_id, snapshot) = match manual::plan_for_token(
            &state.pool,
            g.session.user_id,
            token,
            "rule_apply",
            Some(id),
        )
        .await
        {
            Ok(value) => value,
            Err(e) => return err(StatusCode::CONFLICT, &e.to_string()),
        };
        if body
            .reason
            .as_deref()
            .is_some_and(|reason| reason.trim() != snapshot.reason)
        {
            return err(
                StatusCode::CONFLICT,
                "preview_changed; prepare a fresh preview",
            );
        }
        return match manual::accept_plan(&state, &g.session, plan_id, token, "rule_apply", Some(id))
            .await
        {
            Ok(accepted) => {
                let bundle_id = accepted.bundle_id;
                manual::spawn_accepted(&state, &g.session, accepted);
                (
                    StatusCode::ACCEPTED,
                    Json(json!({"bundle_id":bundle_id,"async":true})),
                )
            }
            Err(e) => err(StatusCode::CONFLICT, &format!("{e:#}")),
        };
    }
    #[derive(sqlx::FromRow)]
    struct Context {
        name: String,
        manual_apply_enabled: bool,
        current_state: Option<String>,
        actions_revision: u64,
        interface_id: Option<u64>,
        flow_direction: Option<String>,
        flow_protocol: Option<u16>,
        flow_port: Option<u16>,
        flow_port_kind: Option<String>,
    }
    let context = match sqlx::query_as::<_, Context>(
        "SELECT r.name, r.manual_apply_enabled, rs.current_state, r.actions_revision, \
        r.interface_id, r.flow_direction, r.flow_protocol, r.flow_port, r.flow_port_kind \
        FROM rules r LEFT JOIN rule_states rs ON rs.rule_id = r.id WHERE r.id = ?",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return err(StatusCode::NOT_FOUND, "rule not found"),
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    if !context.manual_apply_enabled || context.current_state.as_deref() != Some("firing") {
        return err(
            StatusCode::CONFLICT,
            "manual apply requires a firing rule with manual apply enabled",
        );
    }
    let reason = body
        .reason
        .unwrap_or_else(|| format!("manual apply of rule '{}' (#{id})", context.name))
        .trim()
        .to_string();
    if reason.is_empty() || reason.chars().count() > 4000 {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "provide an audit reason of 1–4000 characters",
        );
    }
    let selector = flow_target::FlowSelector {
        interface_id: context.interface_id,
        direction: context.flow_direction,
        protocol: context.flow_protocol,
        port: context.flow_port,
        port_kind: context.flow_port_kind,
    };
    type Spec = (u64, u64, Option<sqlx::types::Json<Value>>, Option<String>);
    let specs: Vec<Spec> = match sqlx::query_as("SELECT reroute_template_id, device_id, params_json, auto_target FROM rule_actions WHERE rule_id = ? AND enabled = 1 ORDER BY position,id")
        .bind(id).fetch_all(&state.pool).await {
        Ok(specs) => specs, Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    let mut actions = Vec::with_capacity(specs.len());
    for (position, (template_id, device_id, params, auto_target)) in specs.into_iter().enumerate() {
        match flow_target::prepare_action(
            &state.pool,
            &selector,
            template_id,
            device_id,
            params.map(|p| p.0).unwrap_or(Value::Null),
            auto_target.as_deref(),
        )
        .await
        {
            PreparedAction::Ready {
                template,
                params,
                auto_target: target,
            } => {
                actions.push(crate::reroute::bundle::BundleAction {
                    device_id,
                    template,
                    params,
                    reason: reason.clone(),
                    position: position as u32,
                    auto_target: target.as_ref().map(|t| t.cidr.clone()),
                    auto_target_low_confidence: target.as_ref().map(|t| t.low_confidence),
                    prepared: None,
                    original_reroute_id: None,
                });
            }
            PreparedAction::Skip { reason } => {
                return err(
                    StatusCode::CONFLICT,
                    &format!(
                        "action {} cannot be prepared: {}; entire mitigation refused",
                        position + 1,
                        reason
                    ),
                )
            }
        }
    }
    let source = json!({"kind":"rule","rule_id":id,"name":context.name,"actions_revision":context.actions_revision});
    let request = json!({"rule_id":id,"reason":reason,"actions_revision":context.actions_revision});
    manual::preview_actions(
        &state,
        &g.session,
        "rule_apply",
        Some(id),
        actions,
        source,
        reason,
        request,
        None,
    )
    .await
}

// ---- Rule action targets (template + router + params) --------------------------

#[derive(Debug, Deserialize)]
pub struct RuleActionBody {
    reroute_template_id: u64,
    device_id: u64,
    #[serde(default)]
    params: Value,
    #[serde(default)]
    position: Option<u32>,
    /// "flow_dst_host" to resolve the prefix from the rule's flows at fire/apply
    /// time (only on a flow rule + a host-route template). NULL = static prefix.
    #[serde(default)]
    auto_target: Option<String>,
}

/// POST /api/rules/{id}/actions — attach a device-CLI action to a rule. Validates
/// the template (must be device_cli), the device, and the params against the
/// template schema, so a malformed action can't be saved. Returns the updated rule.
pub async fn add_action(
    g: RequirePermission<markers::EditRules>,
    State(state): State<AppState>,
    Path(rule_id): Path<u64>,
    Json(body): Json<RuleActionBody>,
) -> JsonResp {
    let _policy_fence = match crate::reroute::guard::policy_fence(&state.pool).await {
        Ok(fence) => fence,
        Err(_) => {
            return err(
                StatusCode::CONFLICT,
                "safety policy is busy; retry after the active action finishes",
            )
        }
    };

    let rule_row: Option<(String, Option<String>, bool)> = match sqlx::query_as(
        "SELECT metric, flow_direction, automatic_reroute_enabled FROM rules WHERE id = ?",
    )
    .bind(rule_id)
    .fetch_optional(&state.pool)
    .await
    {
        Ok(row) => row,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    let Some((_rule_metric, rule_flow_direction, rule_automatic)) = rule_row else {
        return err(StatusCode::NOT_FOUND, "rule not found");
    };

    let template =
        match crate::reroute::templates::load(&state.pool, body.reroute_template_id).await {
            Ok(t) => t,
            Err(_) => return err(StatusCode::UNPROCESSABLE_ENTITY, "template not found"),
        };
    if template.provider_type != "device_cli" {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "only device_cli templates can be attached as rule actions",
        );
    }
    if !template.enabled {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "template is disabled");
    }
    if rule_automatic && !template.automatic_allowed {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "template is not allowed for automatic execution",
        );
    }

    // Auto-target: only on a flow rule + a host-route template. The host (prefix)
    // is resolved at fire/apply time, so validate the OTHER params here against a
    // placeholder prefix; a static action validates the params as given.
    let (auto_target, canonical_params) = match body.auto_target.as_deref() {
        None => {
            let canonical = match crate::reroute::templates::canonicalize_inventory_params(
                &state.pool,
                body.device_id,
                &template,
                &body.params,
            )
            .await
            {
                Ok(v) => v,
                Err(e) => return err(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string()),
            };
            (None, canonical)
        }
        Some(flow_target::FLOW_DST_HOST) => {
            if rule_flow_direction.is_none() {
                return err(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "auto-target requires a flow rule (set a flow metric + selector first)",
                );
            }
            if !template_supports_auto_target(&template.name) {
                return err(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "this template does not support auto-target (use a null-route / blackhole template)",
                );
            }
            let mut probe = body.params.as_object().cloned().unwrap_or_default();
            probe.insert("prefix".into(), Value::String("192.0.2.1/32".into()));
            let mut canonical = match crate::reroute::templates::canonicalize_inventory_params(
                &state.pool,
                body.device_id,
                &template,
                &Value::Object(probe),
            )
            .await
            {
                Ok(v) => v,
                Err(e) => return err(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string()),
            };
            if let Value::Object(params) = &mut canonical {
                params.remove("prefix");
            }
            (Some(flow_target::FLOW_DST_HOST), canonical)
        }
        Some(_) => {
            return err(StatusCode::UNPROCESSABLE_ENTITY, "unknown auto_target mode");
        }
    };

    let device_exists: Option<u64> = match sqlx::query_scalar("SELECT id FROM devices WHERE id = ?")
        .bind(body.device_id)
        .fetch_optional(&state.pool)
        .await
    {
        Ok(row) => row,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    if device_exists.is_none() {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "device not found");
    }

    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    if let Err(e) = lock_action_edit(&mut tx, rule_id, None).await {
        return err(StatusCode::CONFLICT, &e.to_string());
    }
    if disarm_action_edit(&mut tx, rule_id).await.is_err() {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not safely disarm changed actions",
        );
    }
    let res = sqlx::query(
        "INSERT INTO rule_actions (rule_id, reroute_template_id, device_id, params_json, position, auto_target) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(rule_id)
    .bind(body.reroute_template_id)
    .bind(body.device_id)
    .bind(sqlx::types::Json(&canonical_params))
    .bind(body.position.unwrap_or(0))
    .bind(auto_target)
    .execute(&mut *tx)
    .await;

    if res.is_err() {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error");
    }
    if super::audit_mutation_on(
        &mut tx,
        &g.session,
        "rule_action_added",
        "rule",
        rule_id,
        "reroute action attached to rule",
    )
    .await
    .is_err()
        || tx.commit().await.is_err()
    {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "audit_write_failed");
    }
    match fetch_rule(&state.pool, rule_id).await {
        Ok(Some(v)) => (StatusCode::CREATED, Json(v)),
        _ => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

/// DELETE /api/rules/{rule_id}/actions/{action_id} — detach an action. Returns
/// the updated rule.
pub async fn remove_action(
    g: RequirePermission<markers::EditRules>,
    State(state): State<AppState>,
    Path((rule_id, action_id)): Path<(u64, u64)>,
) -> JsonResp {
    let _policy_fence = match crate::reroute::guard::policy_fence(&state.pool).await {
        Ok(fence) => fence,
        Err(_) => {
            return err(
                StatusCode::CONFLICT,
                "safety policy is busy; retry after the active action finishes",
            )
        }
    };

    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    if let Err(e) = lock_action_edit(&mut tx, rule_id, None).await {
        return err(StatusCode::CONFLICT, &e.to_string());
    }
    if disarm_action_edit(&mut tx, rule_id).await.is_err() {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not safely disarm changed actions",
        );
    }
    let res = sqlx::query("DELETE FROM rule_actions WHERE id = ? AND rule_id = ?")
        .bind(action_id)
        .bind(rule_id)
        .execute(&mut *tx)
        .await;
    match res {
        Ok(r) if r.rows_affected() > 0 => {
            if super::audit_mutation_on(
                &mut tx,
                &g.session,
                "rule_action_removed",
                "rule",
                rule_id,
                &format!("rule action {action_id} removed"),
            )
            .await
            .is_err()
                || tx.commit().await.is_err()
            {
                return err(StatusCode::INTERNAL_SERVER_ERROR, "audit_write_failed");
            }
            match fetch_rule(&state.pool, rule_id).await {
                Ok(Some(v)) => (StatusCode::OK, Json(v)),
                _ => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
            }
        }
        Ok(_) => err(StatusCode::NOT_FOUND, "action not found"),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

#[derive(Debug, Deserialize)]
pub struct ReorderBody {
    /// Every enabled-or-disabled action id of this rule, in the intended
    /// execution order.
    order: Vec<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaceActionsBody {
    revision: u64,
    actions: Vec<crate::reroute::preparation::ActionDraft>,
    #[serde(default)]
    preset_id: Option<u64>,
    #[serde(default)]
    preset_revision: Option<u64>,
}

/// Lock definition edits against execution admission. A changed definition can
/// never remain armed, and an incident must be resolved before changing its set.
async fn lock_action_edit(
    conn: &mut sqlx::MySqlConnection,
    rule_id: u64,
    revision: Option<u64>,
) -> anyhow::Result<bool> {
    let row: Option<(u64, Option<String>, String)> = sqlx::query_as(
        "SELECT r.actions_revision, rs.current_state, r.metric FROM rules r \
         LEFT JOIN rule_states rs ON rs.rule_id = r.id WHERE r.id = ? FOR UPDATE",
    )
    .bind(rule_id)
    .fetch_optional(&mut *conn)
    .await?;
    let (current_revision, current_state, metric) =
        row.ok_or_else(|| anyhow::anyhow!("rule not found"))?;
    anyhow::ensure!(
        revision.is_none_or(|r| r == current_revision),
        "actions_changed; reload before saving"
    );
    anyhow::ensure!(
        current_state.as_deref().unwrap_or("clear") == "clear",
        "resolve the firing or matching rule before changing its actions"
    );
    let active: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM reroute_bundles WHERE rule_id = ? AND state IN ('planned','running','compensating','compensation_blocked')",
    ).bind(rule_id).fetch_one(&mut *conn).await?;
    anyhow::ensure!(
        active == 0,
        "reconcile the rule's active or interrupted mitigation before changing its actions"
    );
    Ok(is_flow_metric(&metric))
}

async fn disarm_action_edit(conn: &mut sqlx::MySqlConnection, rule_id: u64) -> anyhow::Result<()> {
    sqlx::query("UPDATE rules SET automatic_reroute_enabled = 0, actions_revision = actions_revision + 1, \
        auto_disarmed_at = UTC_TIMESTAMP(), auto_disarmed_reason = 'action set changed; review and explicitly re-arm' WHERE id = ?")
        .bind(rule_id).execute(conn).await?;
    Ok(())
}

/// Replace the complete action set atomically, including imports. Source IDs are
/// provenance only; copied rules have no live dependence on saved presets.
pub async fn replace_actions(
    g: RequirePermission<markers::EditRules>,
    State(state): State<AppState>,
    Path(rule_id): Path<u64>,
    Json(body): Json<ReplaceActionsBody>,
) -> JsonResp {
    let _policy_fence = match crate::reroute::guard::policy_fence(&state.pool).await {
        Ok(fence) => fence,
        Err(_) => {
            return err(
                StatusCode::CONFLICT,
                "safety policy is busy; retry after the active action finishes",
            )
        }
    };

    let flow_rule = match sqlx::query_scalar::<_, String>("SELECT metric FROM rules WHERE id = ?")
        .bind(rule_id)
        .fetch_optional(&state.pool)
        .await
    {
        Ok(Some(metric)) => is_flow_metric(&metric),
        Ok(None) => return err(StatusCode::NOT_FOUND, "rule not found"),
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    let actions = if body.actions.is_empty() {
        Vec::new()
    } else {
        match crate::reroute::preparation::validate_drafts(&state.pool, &body.actions, flow_rule)
            .await
        {
            Ok(rows) => rows.into_iter().map(|(_, a)| a).collect::<Vec<_>>(),
            Err(e) => return err(StatusCode::UNPROCESSABLE_ENTITY, &format!("{e:#}")),
        }
    };
    let Ok(mut tx) = state.pool.begin().await else {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error");
    };
    if let Err(e) = lock_action_edit(&mut tx, rule_id, Some(body.revision)).await {
        return err(StatusCode::CONFLICT, &e.to_string());
    }
    if let Some(preset_id) = body.preset_id {
        let revision: Option<(u64, Option<chrono::DateTime<chrono::Utc>>)> = sqlx::query_as(
            "SELECT revision, archived_at FROM mitigation_presets WHERE id = ? FOR UPDATE",
        )
        .bind(preset_id)
        .fetch_optional(&mut *tx)
        .await
        .unwrap_or(None);
        if !matches!(revision, Some((revision, None)) if Some(revision) == body.preset_revision) {
            return err(
                StatusCode::CONFLICT,
                "template_changed_or_archived; reload before importing",
            );
        }
    } else if body.preset_revision.is_some() {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "preset_revision requires preset_id",
        );
    }
    let saved = async {
        sqlx::query("DELETE FROM rule_actions WHERE rule_id = ?").bind(rule_id).execute(&mut *tx).await?;
        for (position, action) in actions.iter().enumerate() {
            sqlx::query("INSERT INTO rule_actions (rule_id, reroute_template_id, device_id, params_json, position, enabled, auto_target) VALUES (?, ?, ?, ?, ?, ?, ?)")
                .bind(rule_id).bind(action.reroute_template_id).bind(action.device_id)
                .bind(sqlx::types::Json(&action.params)).bind(position as u32).bind(action.enabled).bind(&action.auto_target)
                .execute(&mut *tx).await?;
        }
        disarm_action_edit(&mut tx, rule_id).await?;
        super::audit_mutation_on(&mut tx, &g.session, "rule_actions_replaced", "rule", rule_id,
            &format!("saved {} ordered actions; automatic execution disarmed; imported preset {:?} revision {:?}", actions.len(), body.preset_id, body.preset_revision)).await?;
        tx.commit().await?;
        Ok::<(), anyhow::Error>(())
    }.await;
    if let Err(e) = saved {
        tracing::error!(event_type="rule_actions_save_failed", rule_id, error=%e);
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "save_failed; reload to reconcile",
        );
    }
    match fetch_rule(&state.pool, rule_id).await {
        Ok(Some(rule)) => (StatusCode::OK, Json(rule)),
        _ => err(StatusCode::INTERNAL_SERVER_ERROR, "saved_but_reload_failed"),
    }
}

/// POST /api/rules/{id}/actions/reorder — set `rule_actions.position` for the
/// whole set in one transaction.
///
/// Order is a SAFETY property, not a display preference: a scrubber-diversion
/// bundle must advertise to the scrubber BEFORE it withdraws from the upstream,
/// so that a failure aborts while traffic still has a path. Reordering by
/// deleting and re-adding rows risks losing an action when a re-add is refused
/// (aged-out inventory, a template since disabled), which silently shortens a
/// mitigation. Renumbering in place cannot lose one.
///
/// The submitted list must be exactly this rule's action set — any missing or
/// foreign id is rejected whole, so a stale UI cannot drop actions it never saw.
pub async fn reorder_actions(
    g: RequirePermission<markers::EditRules>,
    State(state): State<AppState>,
    Path(rule_id): Path<u64>,
    Json(body): Json<ReorderBody>,
) -> JsonResp {
    let _policy_fence = match crate::reroute::guard::policy_fence(&state.pool).await {
        Ok(fence) => fence,
        Err(_) => {
            return err(
                StatusCode::CONFLICT,
                "safety policy is busy; retry after the active action finishes",
            )
        }
    };

    let pool = &state.pool;

    let existing: Vec<u64> =
        match sqlx::query_scalar("SELECT id FROM rule_actions WHERE rule_id = ? ORDER BY id")
            .bind(rule_id)
            .fetch_all(pool)
            .await
        {
            Ok(rows) => rows,
            Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
        };
    if existing.is_empty() {
        return err(StatusCode::NOT_FOUND, "rule has no actions to reorder");
    }

    let mut submitted = body.order.clone();
    submitted.sort_unstable();
    submitted.dedup();
    let mut known = existing.clone();
    known.sort_unstable();
    if submitted.len() != body.order.len() {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "duplicate action id");
    }
    if submitted != known {
        return err(
            StatusCode::CONFLICT,
            "the submitted order must list exactly this rule's actions; reload and retry",
        );
    }

    // MySQL cannot prepare START TRANSACTION, so use the pool's begin()/commit()
    // (see docs/database.md — the MySQL 8.x text-protocol transaction rule).
    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    if let Err(e) = lock_action_edit(&mut tx, rule_id, None).await {
        return err(StatusCode::CONFLICT, &e.to_string());
    }
    if disarm_action_edit(&mut tx, rule_id).await.is_err() {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not safely disarm changed actions",
        );
    }
    for (position, action_id) in body.order.iter().enumerate() {
        if sqlx::query("UPDATE rule_actions SET position = ? WHERE id = ? AND rule_id = ?")
            .bind(position as u32)
            .bind(action_id)
            .bind(rule_id)
            .execute(&mut *tx)
            .await
            .is_err()
        {
            return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error");
        }
    }
    if let Err(e) = super::audit_mutation_on(
        &mut tx,
        &g.session,
        "rule_actions_reordered",
        "rule",
        rule_id,
        &format!("reordered {} action(s)", body.order.len()),
    )
    .await
    {
        tracing::error!(event_type = "reorder_audit_failed", rule_id, error = %e, "could not audit action reorder");
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not audit action reorder",
        );
    }
    if tx.commit().await.is_err() {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "save_failed; reload to reconcile",
        );
    }

    match load_actions(pool, rule_id).await {
        Ok(actions) => (StatusCode::OK, Json(json!({ "actions": actions }))),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "saved_but_reload_failed"),
    }
}
