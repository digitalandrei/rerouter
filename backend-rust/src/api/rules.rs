//! Detection-rule CRUD (edit_rules to write, view_asset to read).
//!
//! A rule targets a monitored interface XOR a protected asset (enforced here).
//! `automatic_reroute_enabled` defaults off per rule and is additionally gated by
//! the global switch + the reroute safety model — in observe mode it never
//! executes. Field names are pinned by the frontend contract
//! (../../frontend/src/lib/api.ts: Rule).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{err, AppState};
use crate::auth::rbac::{self, markers, RequirePermission};
use crate::reroute::executor::{self, ActionRequest};
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
}

/// Rule columns + resolved target names + the latest evaluation snapshot
/// (rule_states). Note the table aliases (`r`/`i`/`d`/`rs`).
const RULE_SELECT: &str = "SELECT r.id, r.name, r.interface_id, r.device_id, r.metric, \
     r.metric_aggregation, \
     r.flow_direction, r.flow_protocol, r.flow_port, r.flow_port_kind, \
     r.operator, r.threshold_value, r.duration_seconds, r.consecutive_samples, \
     r.recovery_mode, r.recovery_threshold_value, r.recovery_window_seconds, \
     r.recovery_consecutive_samples, r.severity, r.enabled, \
     r.automatic_reroute_enabled, r.manual_apply_enabled, r.reroute_template_id, \
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
async fn load_actions(pool: &sqlx::MySqlPool, rule_id: u64) -> Vec<Value> {
    let rows = sqlx::query_as::<_, (u64, u64, String, Option<String>, u64, String, Option<sqlx::types::Json<Value>>, bool, u32, Option<String>)>(
        "SELECT ra.id, ra.reroute_template_id, t.name, t.display_name, ra.device_id, d.name, ra.params_json, ra.enabled, ra.position, ra.auto_target \
         FROM rule_actions ra \
         JOIN reroute_templates t ON t.id = ra.reroute_template_id \
         JOIN devices d ON d.id = ra.device_id \
         WHERE ra.rule_id = ? ORDER BY ra.position, ra.id",
    )
    .bind(rule_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    rows.into_iter()
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
                })
            },
        )
        .collect()
}

/// Member interface ids of a `sum` rule (empty for a single-interface rule).
async fn load_member_interfaces(pool: &sqlx::MySqlPool, rule_id: u64) -> Vec<u64> {
    sqlx::query_scalar::<_, u64>(
        "SELECT interface_id FROM rule_interfaces WHERE rule_id = ? ORDER BY interface_id",
    )
    .bind(rule_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default()
}

/// Build the full rule JSON (row + its actions + any aggregation members).
async fn rule_value(pool: &sqlx::MySqlPool, r: &RuleRow) -> Value {
    let actions = load_actions(pool, r.id).await;
    let members = if r.metric_aggregation == "sum" {
        load_member_interfaces(pool, r.id).await
    } else {
        Vec::new()
    };
    rule_json(r, actions, members)
}

async fn fetch_rule(pool: &sqlx::MySqlPool, id: u64) -> anyhow::Result<Option<Value>> {
    let row = sqlx::query_as::<_, RuleRow>(&format!("{RULE_SELECT} WHERE r.id = ?"))
        .bind(id)
        .fetch_optional(pool)
        .await?;
    match row {
        Some(r) => Ok(Some(rule_value(pool, &r).await)),
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
                out.push(rule_value(&state.pool, r).await);
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
    #[serde(default = "default_duration")]
    duration_seconds: u32,
    #[serde(default = "default_consecutive")]
    consecutive_samples: u32,
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
    /// Opt-in: allow operators to manually apply this rule's actions from a
    /// firing alert. Off by default. Gated like any manual reroute at apply time.
    #[serde(default)]
    manual_apply_enabled: bool,
    reroute_template_id: Option<u64>,
}

fn default_duration() -> u32 {
    30
}
fn default_consecutive() -> u32 {
    3
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

    let res = sqlx::query(
        "INSERT INTO rules (name, interface_id, device_id, metric, metric_aggregation, \
            flow_direction, flow_protocol, flow_port, flow_port_kind, \
            operator, threshold_value, \
            duration_seconds, consecutive_samples, recovery_mode, recovery_threshold_value, \
            recovery_window_seconds, recovery_consecutive_samples, \
            severity, enabled, automatic_reroute_enabled, manual_apply_enabled, \
            reroute_template_id, created_by, updated_by) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
    .bind(body.duration_seconds)
    .bind(body.consecutive_samples)
    .bind(&body.recovery_mode)
    .bind(recovery_threshold_value)
    .bind(recovery_window_seconds)
    .bind(recovery_consecutive_samples)
    .bind(&body.severity)
    .bind(body.enabled)
    .bind(body.automatic_reroute_enabled)
    .bind(body.manual_apply_enabled)
    .bind(body.reroute_template_id)
    .bind(g.session.user_id)
    .bind(g.session.user_id)
    .execute(&state.pool)
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
                    .fetch_optional(&state.pool)
                    .await
                    .unwrap_or(None);
            let Some(dev) = dev else { continue };
            let _ = sqlx::query(
                "INSERT IGNORE INTO rule_interfaces (rule_id, device_id, interface_id) \
                 VALUES (?, ?, ?)",
            )
            .bind(rule_id)
            .bind(dev)
            .bind(iid)
            .execute(&state.pool)
            .await;
        }
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
    flow_protocol: Option<u16>,
    flow_port: Option<u16>,
    flow_port_kind: Option<String>,
    operator: Option<String>,
    threshold_value: Option<f64>,
    duration_seconds: Option<u32>,
    consecutive_samples: Option<u32>,
    recovery_mode: Option<String>,
    recovery_threshold_value: Option<Option<f64>>,
    recovery_window_seconds: Option<Option<u32>>,
    recovery_consecutive_samples: Option<Option<u32>>,
    severity: Option<String>,
    enabled: Option<bool>,
    automatic_reroute_enabled: Option<bool>,
    manual_apply_enabled: Option<bool>,
    reroute_template_id: Option<Option<u64>>,
}

/// PUT /api/rules/{id} — partial update (target is immutable here; recreate to
/// retarget). Re-validates operator/metric when changed.
pub async fn update(
    g: RequirePermission<markers::EditRules>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
    Json(body): Json<RuleUpdate>,
) -> JsonResp {
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
    if let Some(pk) = &body.flow_port_kind {
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
    if let Some(m) = &body.recovery_mode {
        if !valid_recovery_mode(m) {
            return err(
                StatusCode::UNPROCESSABLE_ENTITY,
                "recovery_mode must be auto, threshold, or manual",
            );
        }
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
    if body.manual_apply_enabled.is_some() {
        sets.push("manual_apply_enabled = ?");
    }
    if body.reroute_template_id.is_some() {
        sets.push("reroute_template_id = ?");
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
    if let Some(v) = body.manual_apply_enabled {
        q = q.bind(v);
    }
    if let Some(v) = &body.reroute_template_id {
        q = q.bind(*v);
    }
    q = q.bind(g.session.user_id);
    q = q.bind(id);

    if q.execute(&state.pool).await.is_err() {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error");
    }

    // Editing the CONDITION invalidates any in-progress match/firing streak — reset
    // evaluation state so the rule re-evaluates fresh (a pure enable/name change
    // doesn't). The rule then starts counting from zero against the new condition.
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
    if condition_changed {
        let _ = crate::detection::engine::reset_rule_state(&state.pool, id).await;
    }

    match fetch_rule(&state.pool, id).await {
        Ok(Some(v)) => (StatusCode::OK, Json(v)),
        _ => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

/// DELETE /api/rules/{id}.
pub async fn remove(
    _g: RequirePermission<markers::EditRules>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> JsonResp {
    match sqlx::query("DELETE FROM rules WHERE id = ?")
        .bind(id)
        .execute(&state.pool)
        .await
    {
        Ok(r) if r.rows_affected() > 0 => (StatusCode::OK, Json(json!({ "ok": true }))),
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
) -> JsonResp {
    let pool = &state.pool;
    // Existence + (is it firing?, is Auto on?) in one query.
    let row: Option<(Option<String>, bool)> = sqlx::query_as(
        "SELECT rs.current_state, r.automatic_reroute_enabled \
         FROM rules r LEFT JOIN rule_states rs ON rs.rule_id = r.id WHERE r.id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);
    let Some((current_state, auto_enabled)) = row else {
        return err(StatusCode::NOT_FOUND, "rule not found");
    };

    // If clearing would actually roll back actions (firing + Auto + enforce), it
    // is a reroute-triggering operation and needs the reroute permission too.
    let would_roll_back = current_state.as_deref() == Some("firing")
        && auto_enabled
        && crate::api::settings::operating_mode(pool, &state.config).await == "enforce";
    if would_roll_back {
        match rbac::has_permission(pool, &g.session, rbac::Permission::TriggerManualReroute).await {
            Ok(true) => {}
            Ok(false) => return err(
                StatusCode::FORBIDDEN,
                "clearing this rule would roll back its actions; trigger_manual_reroute required",
            ),
            Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "authz check failed"),
        }
    }

    match crate::detection::engine::clear_rule_manual(pool, &state.config, id).await {
        Ok(cleared) => (
            StatusCode::OK,
            Json(json!({ "ok": true, "cleared": cleared })),
        ),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

#[derive(Debug, Deserialize)]
pub struct ApplyBody {
    /// Optional operator note for the audit log.
    #[serde(default)]
    reason: Option<String>,
    /// Render-only preview (even in enforce mode); changes nothing.
    #[serde(default)]
    dry_run: bool,
}

/// POST /api/rules/{id}/apply — operator manually applies a FIRING rule's
/// configured actions: the supervised middle ground between alert-only and
/// unattended automatic execution.
///
/// Refuses unless the rule has `manual_apply_enabled` (the per-rule opt-in) AND is
/// currently `firing` (manual apply only mitigates a live breach). Each enabled
/// action then runs through the SAME gated executor as automatic execution, but as
/// a `manual` trigger attributed to the operator:
///   * GATE 0 still applies — in observe mode nothing executes; the response
///     carries the would-run plan per action (`would_run`).
///   * device locks, the global maintenance lock, per-device/per-rule cooldowns,
///     the global rate limit, and the protected-interface guard all still apply.
///   * the global AUTOMATIC master switch does NOT gate it — this is a deliberate
///     operator action, not unattended automation.
///
/// Requires `trigger_manual_reroute` (enforced here, the security boundary).
pub async fn apply(
    g: RequirePermission<markers::TriggerManualReroute>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
    Json(body): Json<ApplyBody>,
) -> JsonResp {
    let pool = &state.pool;
    // Existence + opt-in flag + live firing state + flow selector in one read.
    #[allow(clippy::type_complexity)]
    let row: Option<(
        bool,
        Option<String>,
        String,
        Option<u64>,
        Option<String>,
        Option<u16>,
        Option<u16>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT r.manual_apply_enabled, rs.current_state, r.name, \
                r.interface_id, r.flow_direction, r.flow_protocol, r.flow_port, r.flow_port_kind \
         FROM rules r LEFT JOIN rule_states rs ON rs.rule_id = r.id WHERE r.id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);
    let Some((
        manual_apply_enabled,
        current_state,
        rule_name,
        interface_id,
        flow_direction,
        flow_protocol,
        flow_port,
        flow_port_kind,
    )) = row
    else {
        return err(StatusCode::NOT_FOUND, "rule not found");
    };
    if !manual_apply_enabled {
        return err(
            StatusCode::CONFLICT,
            "manual apply is not enabled for this rule",
        );
    }
    if current_state.as_deref() != Some("firing") {
        return err(
            StatusCode::CONFLICT,
            "rule is not currently firing; manual apply is only allowed while the threshold is breached",
        );
    }

    // The rule's enabled actions (template + target router + params [+ auto-target])
    // — the same set the firing alert rendered as would-run, in the same order.
    let specs = sqlx::query_as::<_, (u64, u64, Option<sqlx::types::Json<Value>>, Option<String>)>(
        "SELECT reroute_template_id, device_id, params_json, auto_target FROM rule_actions \
         WHERE rule_id = ? AND enabled = 1 ORDER BY position, id",
    )
    .bind(id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    if specs.is_empty() {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "rule has no enabled actions to apply",
        );
    }

    let reason = body
        .reason
        .clone()
        .unwrap_or_else(|| format!("manual apply of rule '{rule_name}' (#{id})"));
    let sel = flow_target::FlowSelector {
        interface_id,
        direction: flow_direction,
        protocol: flow_protocol,
        port: flow_port,
        port_kind: flow_port_kind,
    };

    let mut results = Vec::with_capacity(specs.len());
    for (template_id, device_id, params_json, auto_target) in specs {
        let params = params_json.map(|j| j.0).unwrap_or(Value::Null);
        // Resolve auto-target (flow dst host) here; a manual apply proceeds even on
        // LOW sampling confidence (the operator confirms the resolved IP), unlike
        // automatic execution which suppresses it.
        match flow_target::prepare_action(pool, &sel, template_id, device_id, params, auto_target.as_deref())
            .await
        {
            PreparedAction::Ready {
                template,
                params,
                auto_target: at,
            } => {
                let action_reason = match &at {
                    Some(a) => format!("{reason}; {}", a.note),
                    None => reason.clone(),
                };
                let req = ActionRequest {
                    device_id,
                    template,
                    params,
                    trigger_type: "manual",
                    rule_id: Some(id),
                    user_id: Some(g.session.user_id),
                    reason: Some(action_reason),
                };
                let outcome = executor::execute(pool, &state.config, req, body.dry_run).await;
                let mut v = serde_json::to_value(outcome).unwrap_or_else(|_| json!({}));
                if let (Value::Object(m), Some(a)) = (&mut v, at) {
                    m.insert("auto_target".into(), json!(a.cidr));
                    m.insert("auto_target_low_confidence".into(), json!(a.low_confidence));
                }
                results.push(v);
            }
            PreparedAction::Skip { reason: why } => {
                results.push(json!({
                    "device_id": device_id,
                    "executed": false,
                    "message": why,
                }));
            }
        }
    }
    (StatusCode::OK, Json(json!({ "results": results })))
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
    _g: RequirePermission<markers::EditRules>,
    State(state): State<AppState>,
    Path(rule_id): Path<u64>,
    Json(body): Json<RuleActionBody>,
) -> JsonResp {
    let rule_row: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT metric, flow_direction FROM rules WHERE id = ?")
            .bind(rule_id)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);
    let Some((_rule_metric, rule_flow_direction)) = rule_row else {
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

    // Auto-target: only on a flow rule + a host-route template. The host (prefix)
    // is resolved at fire/apply time, so validate the OTHER params here against a
    // placeholder prefix; a static action validates the params as given.
    let auto_target = match body.auto_target.as_deref() {
        None => None,
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
            if let Err(e) = crate::reroute::templates::validate_and_expand(
                &template.parameter_schema,
                &Value::Object(probe),
            ) {
                return err(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string());
            }
            Some(flow_target::FLOW_DST_HOST)
        }
        Some(_) => {
            return err(StatusCode::UNPROCESSABLE_ENTITY, "unknown auto_target mode");
        }
    };

    if auto_target.is_none() {
        if let Err(e) =
            crate::reroute::templates::validate_and_expand(&template.parameter_schema, &body.params)
        {
            return err(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string());
        }
    }

    let device_exists: Option<u64> = sqlx::query_scalar("SELECT id FROM devices WHERE id = ?")
        .bind(body.device_id)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None);
    if device_exists.is_none() {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "device not found");
    }

    let res = sqlx::query(
        "INSERT INTO rule_actions (rule_id, reroute_template_id, device_id, params_json, position, auto_target) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(rule_id)
    .bind(body.reroute_template_id)
    .bind(body.device_id)
    .bind(sqlx::types::Json(&body.params))
    .bind(body.position.unwrap_or(0))
    .bind(auto_target)
    .execute(&state.pool)
    .await;

    if res.is_err() {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error");
    }
    match fetch_rule(&state.pool, rule_id).await {
        Ok(Some(v)) => (StatusCode::CREATED, Json(v)),
        _ => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

/// DELETE /api/rules/{rule_id}/actions/{action_id} — detach an action. Returns
/// the updated rule.
pub async fn remove_action(
    _g: RequirePermission<markers::EditRules>,
    State(state): State<AppState>,
    Path((rule_id, action_id)): Path<(u64, u64)>,
) -> JsonResp {
    let res = sqlx::query("DELETE FROM rule_actions WHERE id = ? AND rule_id = ?")
        .bind(action_id)
        .bind(rule_id)
        .execute(&state.pool)
        .await;
    match res {
        Ok(r) if r.rows_affected() > 0 => match fetch_rule(&state.pool, rule_id).await {
            Ok(Some(v)) => (StatusCode::OK, Json(v)),
            _ => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
        },
        Ok(_) => err(StatusCode::NOT_FOUND, "action not found"),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}
