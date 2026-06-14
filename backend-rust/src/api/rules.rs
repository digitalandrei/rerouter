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
use crate::auth::rbac::{markers, RequirePermission};

type JsonResp = (StatusCode, Json<Value>);

/// Metrics valid for an interface-target rule (docs/telemetry-model.md).
const INTERFACE_METRICS: &[&str] = &[
    "rx_bps",
    "tx_bps",
    "rx_pps",
    "tx_pps",
    "rx_util_percent",
    "tx_util_percent",
    "oper_status",
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
    flow_direction: Option<String>,
    flow_protocol: Option<u16>,
    flow_port: Option<u16>,
    flow_port_kind: Option<String>,
    operator: String,
    threshold_value: f64,
    duration_seconds: u32,
    consecutive_samples: u32,
    severity: String,
    enabled: bool,
    automatic_reroute_enabled: bool,
    reroute_template_id: Option<u64>,
    // Resolved target labels + live evaluation state (for the list UI).
    interface_name: Option<String>,
    device_name: Option<String>,
    current_state: Option<String>,
    last_metric_value: Option<f64>,
    last_evaluated_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Rule columns + resolved target names + the latest evaluation snapshot
/// (rule_states). Note the table aliases (`r`/`i`/`d`/`rs`).
const RULE_SELECT: &str = "SELECT r.id, r.name, r.interface_id, r.device_id, r.metric, \
     r.flow_direction, r.flow_protocol, r.flow_port, r.flow_port_kind, \
     r.operator, r.threshold_value, r.duration_seconds, r.consecutive_samples, r.severity, r.enabled, \
     r.automatic_reroute_enabled, r.reroute_template_id, \
     i.if_name AS interface_name, d.name AS device_name, \
     rs.current_state, rs.last_metric_value, rs.last_evaluated_at \
     FROM rules r \
     LEFT JOIN device_interfaces i ON i.id = r.interface_id \
     LEFT JOIN devices d ON d.id = r.device_id \
     LEFT JOIN rule_states rs ON rs.rule_id = r.id";

fn rule_json(r: &RuleRow, actions: Vec<Value>) -> Value {
    json!({
        "id": r.id,
        "name": r.name,
        "target_kind": "interface",
        "interface_id": r.interface_id,
        "device_id": r.device_id,
        "metric": r.metric,
        "flow_direction": r.flow_direction,
        "flow_protocol": r.flow_protocol,
        "flow_port": r.flow_port,
        "flow_port_kind": r.flow_port_kind,
        "operator": r.operator,
        "threshold_value": r.threshold_value,
        "duration_seconds": r.duration_seconds,
        "consecutive_samples": r.consecutive_samples,
        "severity": r.severity,
        "enabled": r.enabled,
        "automatic_reroute_enabled": r.automatic_reroute_enabled,
        "reroute_template_id": r.reroute_template_id,
        "interface_name": r.interface_name,
        "device_name": r.device_name,
        "current_state": r.current_state,
        "current_value": r.last_metric_value,
        "last_evaluated_at": r.last_evaluated_at.map(|t| t.to_rfc3339()),
        "action_count": actions.len(),
        "actions": actions,
    })
}

/// Load a rule's attached actions (template + target router + params) for the
/// rule JSON. Joins display names so the SPA needn't re-resolve them.
async fn load_actions(pool: &sqlx::MySqlPool, rule_id: u64) -> Vec<Value> {
    let rows = sqlx::query_as::<_, (u64, u64, String, Option<String>, u64, String, Option<sqlx::types::Json<Value>>, bool, u32)>(
        "SELECT ra.id, ra.reroute_template_id, t.name, t.display_name, ra.device_id, d.name, ra.params_json, ra.enabled, ra.position \
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
        .map(|(id, template_id, template_name, template_display_name, device_id, device_name, params, enabled, position)| {
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
            })
        })
        .collect()
}

/// Build the full rule JSON (row + its actions).
async fn rule_value(pool: &sqlx::MySqlPool, r: &RuleRow) -> Value {
    let actions = load_actions(pool, r.id).await;
    rule_json(r, actions)
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
pub async fn list(_g: RequirePermission<markers::ViewAsset>, State(state): State<AppState>) -> JsonResp {
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
    #[serde(default = "default_severity")]
    severity: String,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    automatic_reroute_enabled: bool,
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
fn default_true() -> bool {
    true
}

/// Validate operator + metric + target. Returns the resolved device_id for an
/// interface rule (looked up from the interface) on success.
async fn validate(pool: &sqlx::MySqlPool, body: &RuleBody) -> Result<Option<u64>, (StatusCode, String)> {
    if body.name.trim().is_empty() {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "name is required".into()));
    }
    // Operators: the contract pins > and < for interface rules.
    if !matches!(body.operator.as_str(), ">" | "<" | ">=" | "<=" | "==" | "!=") {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "unsupported operator".into()));
    }
    // A rule targets an interface (v1 detection is interface-scoped).
    let Some(iface_id) = body.interface_id else {
        return Err((StatusCode::UNPROCESSABLE_ENTITY, "interface_id is required".into()));
    };
    if is_flow_metric(&body.metric) {
        // Flow rule: a direction is required; protocol/port are optional selectors.
        if !matches!(body.flow_direction.as_deref(), Some("ingress") | Some("egress")) {
            return Err((StatusCode::UNPROCESSABLE_ENTITY, "flow_direction must be ingress or egress".into()));
        }
        if let Some(pk) = body.flow_port_kind.as_deref() {
            if !matches!(pk, "src" | "dst") {
                return Err((StatusCode::UNPROCESSABLE_ENTITY, "flow_port_kind must be src or dst".into()));
            }
        }
    } else if !INTERFACE_METRICS.contains(&body.metric.as_str()) {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("metric must be one of: {}, or flow_pps / flow_bps", INTERFACE_METRICS.join(", ")),
        ));
    }
    // Resolve the owning device; also validates the interface exists.
    let device_id: Option<u64> = sqlx::query_scalar("SELECT device_id FROM device_interfaces WHERE id = ?")
        .bind(iface_id)
        .fetch_optional(pool)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "db_error".into()))?;
    match device_id {
        Some(d) => Ok(Some(d)),
        None => Err((StatusCode::UNPROCESSABLE_ENTITY, "interface_id does not exist".into())),
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
    let (flow_direction, flow_protocol, flow_port, flow_port_kind) = if is_flow_metric(&body.metric) {
        let kind = body
            .flow_port_kind
            .clone()
            .or_else(|| body.flow_port.map(|_| "dst".to_string()));
        (body.flow_direction.clone(), body.flow_protocol, body.flow_port, kind)
    } else {
        (None, None, None, None)
    };

    let res = sqlx::query(
        "INSERT INTO rules (name, interface_id, device_id, metric, \
            flow_direction, flow_protocol, flow_port, flow_port_kind, \
            operator, threshold_value, \
            duration_seconds, consecutive_samples, severity, enabled, automatic_reroute_enabled, \
            reroute_template_id, created_by, updated_by) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&body.name)
    .bind(body.interface_id)
    .bind(device_id)
    .bind(&body.metric)
    .bind(flow_direction)
    .bind(flow_protocol)
    .bind(flow_port)
    .bind(flow_port_kind)
    .bind(&body.operator)
    .bind(body.threshold_value)
    .bind(body.duration_seconds)
    .bind(body.consecutive_samples)
    .bind(&body.severity)
    .bind(body.enabled)
    .bind(body.automatic_reroute_enabled)
    .bind(body.reroute_template_id)
    .bind(g.session.user_id)
    .bind(g.session.user_id)
    .execute(&state.pool)
    .await;

    match res {
        Ok(r) => match fetch_rule(&state.pool, r.last_insert_id()).await {
            Ok(Some(v)) => (StatusCode::CREATED, Json(v)),
            _ => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
        },
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
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
    severity: Option<String>,
    enabled: Option<bool>,
    automatic_reroute_enabled: Option<bool>,
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
        if is_flow_metric(metric) {
            // Changing into a flow metric requires the rule to already be a flow
            // rule (has a selector). Recreate the rule to change metric family.
            if existing.flow_direction.is_none() {
                return err(StatusCode::UNPROCESSABLE_ENTITY, "recreate the rule to switch to a flow metric");
            }
        } else if existing.interface_id.is_some() && !INTERFACE_METRICS.contains(&metric.as_str()) {
            return err(StatusCode::UNPROCESSABLE_ENTITY, "unsupported interface metric");
        }
    }
    if let Some(pk) = &body.flow_port_kind {
        if !matches!(pk.as_str(), "src" | "dst") {
            return err(StatusCode::UNPROCESSABLE_ENTITY, "flow_port_kind must be src or dst");
        }
    }
    if let Some(dir) = &body.flow_direction {
        if !matches!(dir.as_str(), "ingress" | "egress") {
            return err(StatusCode::UNPROCESSABLE_ENTITY, "flow_direction must be ingress or egress");
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
    if body.severity.is_some() {
        sets.push("severity = ?");
    }
    if body.enabled.is_some() {
        sets.push("enabled = ?");
    }
    if body.automatic_reroute_enabled.is_some() {
        sets.push("automatic_reroute_enabled = ?");
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
    if let Some(v) = &body.severity {
        q = q.bind(v);
    }
    if let Some(v) = body.enabled {
        q = q.bind(v);
    }
    if let Some(v) = body.automatic_reroute_enabled {
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

// ---- Rule action targets (template + router + params) --------------------------

#[derive(Debug, Deserialize)]
pub struct RuleActionBody {
    reroute_template_id: u64,
    device_id: u64,
    #[serde(default)]
    params: Value,
    #[serde(default)]
    position: Option<u32>,
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
    let rule_exists: Option<u64> = sqlx::query_scalar("SELECT id FROM rules WHERE id = ?")
        .bind(rule_id)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None);
    if rule_exists.is_none() {
        return err(StatusCode::NOT_FOUND, "rule not found");
    }

    let template = match crate::reroute::templates::load(&state.pool, body.reroute_template_id).await {
        Ok(t) => t,
        Err(_) => return err(StatusCode::UNPROCESSABLE_ENTITY, "template not found"),
    };
    if template.provider_type != "device_cli" {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "only device_cli templates can be attached as rule actions");
    }
    if let Err(e) = crate::reroute::templates::validate_and_expand(&template.parameter_schema, &body.params) {
        return err(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string());
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
        "INSERT INTO rule_actions (rule_id, reroute_template_id, device_id, params_json, position) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(rule_id)
    .bind(body.reroute_template_id)
    .bind(body.device_id)
    .bind(sqlx::types::Json(&body.params))
    .bind(body.position.unwrap_or(0))
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
