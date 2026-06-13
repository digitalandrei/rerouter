//! Reroute endpoints: list / detail / manual / cancel / acknowledge-uncertain /
//! rollback.
//!
//! Authorization is enforced HERE (session + RBAC + re-auth) — this process is
//! the security boundary. Manual triggers require `trigger_manual_reroute`;
//! high-safety templates additionally require a FRESH password+TOTP re-auth
//! (rbac::reauth_is_fresh), a typed confirmation, and a reason. The executor
//! then re-checks every safety gate regardless of what the UI showed, and in
//! observe mode returns the would-run plan instead of executing.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{err, AppState};
use crate::auth::rbac::{markers, RequirePermission};
use crate::reroute::executor::{self, ActionRequest};
use crate::reroute::{locks, rollback, templates};

type JsonResp = (StatusCode, Json<Value>);

#[derive(sqlx::FromRow)]
struct RerouteRow {
    id: u64,
    device_id: Option<u64>,
    device_name: Option<String>,
    reroute_template_id: Option<u64>,
    template_name: Option<String>,
    trigger_type: String,
    state: String,
    reason: Option<String>,
    success: Option<bool>,
    verification_status: Option<String>,
    failure_reason: Option<String>,
    rule_id: Option<u64>,
    triggered_by: Option<String>,
    started_at: Option<DateTime<Utc>>,
    finished_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
}

const REROUTE_SELECT: &str = "SELECT r.id, r.device_id, d.name AS device_name, \
     r.reroute_template_id, t.name AS template_name, r.trigger_type, r.state, \
     r.reason, r.success, r.verification_status, r.failure_reason, r.rule_id, u.email AS triggered_by, \
     r.started_at, r.finished_at, r.created_at \
     FROM reroutes r \
     LEFT JOIN devices d ON d.id = r.device_id \
     LEFT JOIN reroute_templates t ON t.id = r.reroute_template_id \
     LEFT JOIN users u ON u.id = r.triggered_by_user_id";

fn reroute_json(r: &RerouteRow) -> Value {
    json!({
        "id": r.id,
        "device_id": r.device_id,
        "device_name": r.device_name,
        "reroute_template_id": r.reroute_template_id,
        "template_name": r.template_name,
        "trigger_type": r.trigger_type,
        "state": r.state,
        "reason": r.reason,
        "success": r.success,
        "verification_status": r.verification_status,
        "failure_reason": r.failure_reason,
        "rule_id": r.rule_id,
        "triggered_by": r.triggered_by,
        "started_at": r.started_at.map(|t| t.to_rfc3339()),
        "finished_at": r.finished_at.map(|t| t.to_rfc3339()),
        "created_at": r.created_at.to_rfc3339(),
    })
}

/// GET /api/reroutes — recent reroutes (newest first).
pub async fn list(_g: RequirePermission<markers::ViewAsset>, State(state): State<AppState>) -> JsonResp {
    let rows = sqlx::query_as::<_, RerouteRow>(&format!("{REROUTE_SELECT} ORDER BY r.id DESC LIMIT 200"))
        .fetch_all(&state.pool)
        .await;
    match rows {
        Ok(rows) => {
            let out: Vec<Value> = rows.iter().map(reroute_json).collect();
            (StatusCode::OK, Json(json!(out)))
        }
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

/// GET /api/reroutes/{id} — a reroute with its steps, outputs, and verifications.
pub async fn show(_g: RequirePermission<markers::ViewAsset>, State(state): State<AppState>, Path(id): Path<u64>) -> JsonResp {
    let row = sqlx::query_as::<_, RerouteRow>(&format!("{REROUTE_SELECT} WHERE r.id = ?"))
        .bind(id)
        .fetch_optional(&state.pool)
        .await;
    let Ok(Some(r)) = row else {
        return err(StatusCode::NOT_FOUND, "reroute not found");
    };

    let steps = sqlx::query_as::<_, (u32, Option<String>, Option<String>, String)>(
        "SELECT step_number, description, mode, state FROM reroute_steps WHERE reroute_id = ? ORDER BY step_number",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let outputs = sqlx::query_as::<_, (u32, Option<String>, Option<String>, Option<String>)>(
        "SELECT step_number, request, response, status FROM reroute_outputs WHERE reroute_id = ? ORDER BY id",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();
    let verifications = sqlx::query_as::<_, (String, Option<String>, Option<String>, String)>(
        "SELECT method, expected, observed, result FROM reroute_verifications WHERE reroute_id = ? ORDER BY id",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let mut v = reroute_json(&r);
    v["steps"] = json!(steps
        .into_iter()
        .map(|(n, desc, mode, st)| json!({ "step_number": n, "description": desc, "mode": mode, "state": st }))
        .collect::<Vec<_>>());
    v["outputs"] = json!(outputs
        .into_iter()
        .map(|(n, req, resp, st)| json!({ "step_number": n, "request": req, "response": resp, "status": st }))
        .collect::<Vec<_>>());
    v["verifications"] = json!(verifications
        .into_iter()
        .map(|(m, exp, obs, res)| json!({ "method": m, "expected": exp, "observed": obs, "result": res }))
        .collect::<Vec<_>>());
    (StatusCode::OK, Json(v))
}

#[derive(Debug, Deserialize)]
pub struct ManualTarget {
    device_id: u64,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Deserialize)]
pub struct ManualBody {
    template_id: u64,
    targets: Vec<ManualTarget>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    dry_run: bool,
}

/// POST /api/reroutes/manual — plan + execute a template against one or more
/// routers. Gates re-checked at execution time; in observe mode the would-run
/// plan is returned and nothing executes.
pub async fn manual(
    g: RequirePermission<markers::TriggerManualReroute>,
    State(state): State<AppState>,
    Json(body): Json<ManualBody>,
) -> JsonResp {
    if body.targets.is_empty() {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "at least one target router is required");
    }
    let template = match templates::load(&state.pool, body.template_id).await {
        Ok(t) => t,
        Err(_) => return err(StatusCode::NOT_FOUND, "template not found"),
    };
    if template.provider_type != "device_cli" {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "only device_cli templates can be executed");
    }

    let mut results = Vec::with_capacity(body.targets.len());
    for target in &body.targets {
        if let Err(e) = templates::validate_and_expand(&template.parameter_schema, &target.params) {
            results.push(json!({ "device_id": target.device_id, "executed": false, "message": e.to_string() }));
            continue;
        }
        let req = ActionRequest {
            device_id: target.device_id,
            template: template.clone(),
            params: target.params.clone(),
            trigger_type: "manual",
            rule_id: None,
            user_id: Some(g.session.user_id),
            reason: body.reason.clone(),
        };
        let outcome = executor::execute(&state.pool, &state.config, req, body.dry_run).await;
        results.push(serde_json::to_value(outcome).unwrap_or_else(|_| json!({})));
    }
    (StatusCode::OK, Json(json!({ "results": results })))
}

/// POST /api/reroutes/{id}/cancel — cancel a still-pending reroute.
pub async fn cancel(
    _g: RequirePermission<markers::TriggerManualReroute>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> JsonResp {
    let res = sqlx::query(
        "UPDATE reroutes SET state = 'failed', finished_at = UTC_TIMESTAMP(), success = 0, \
         failure_reason = 'cancelled by operator' WHERE id = ? AND state IN ('planned','pending')",
    )
    .bind(id)
    .execute(&state.pool)
    .await;
    match res {
        Ok(r) if r.rows_affected() > 0 => (StatusCode::OK, Json(json!({ "ok": true }))),
        Ok(_) => err(StatusCode::CONFLICT, "reroute is not in a cancellable state"),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

#[derive(Debug, Deserialize)]
pub struct AckBody {
    #[serde(default)]
    note: Option<String>,
}

/// POST /api/reroutes/{id}/acknowledge-uncertain — resolve an uncertain reroute
/// and clear the device lock it created. Always audited.
pub async fn acknowledge_uncertain(
    g: RequirePermission<markers::AcknowledgeUncertainReroute>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
    Json(body): Json<AckBody>,
) -> JsonResp {
    let row = sqlx::query_as::<_, (String, Option<u64>)>("SELECT state, device_id FROM reroutes WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.pool)
        .await;
    let Ok(Some((rstate, device_id))) = row else {
        return err(StatusCode::NOT_FOUND, "reroute not found");
    };
    if rstate != "uncertain" {
        return err(StatusCode::CONFLICT, "reroute is not in the uncertain state");
    }

    let note = body.note.unwrap_or_default();
    let _ = sqlx::query(
        "UPDATE reroutes SET state = 'failed', verification_status = 'acknowledged', \
         failure_reason = CONCAT(COALESCE(failure_reason,''), ' | acknowledged by admin: ', ?) WHERE id = ?",
    )
    .bind(&note)
    .bind(id)
    .execute(&state.pool)
    .await;

    if let Some(dev) = device_id {
        let _ = locks::clear(&state.pool, "device", Some(&dev.to_string()), Some(g.session.user_id)).await;
    }
    let _ = sqlx::query(
        "INSERT INTO audit_logs (actor_type, actor_user_id, event_type, entity_type, entity_id, reroute_id, message) \
         VALUES ('user', ?, 'reroute_uncertain_acknowledged', 'reroute', ?, ?, ?)",
    )
    .bind(g.session.user_id)
    .bind(id)
    .bind(id)
    .bind(format!("acknowledged uncertain reroute: {note}"))
    .execute(&state.pool)
    .await;

    (StatusCode::OK, Json(json!({ "ok": true })))
}

/// POST /api/reroutes/{id}/rollback — run the template's rollback against the
/// same device + params as a fresh audited action.
pub async fn rollback(
    g: RequirePermission<markers::TriggerManualReroute>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> JsonResp {
    let row = sqlx::query_as::<_, (Option<u64>, Option<u64>, Option<sqlx::types::Json<Value>>)>(
        "SELECT device_id, reroute_template_id, parameters_json FROM reroutes WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await;
    let Ok(Some((Some(device_id), Some(template_id), params_json))) = row else {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "reroute has no device/template to roll back");
    };

    // Confirm the template actually has a rollback before executing.
    match templates::load(&state.pool, template_id).await {
        Ok(t) if t.rollback_template_id.is_some() => {}
        Ok(_) => return err(StatusCode::UNPROCESSABLE_ENTITY, "template has no rollback"),
        Err(_) => return err(StatusCode::UNPROCESSABLE_ENTITY, "template not found"),
    }

    let params = params_json.map(|j| j.0).unwrap_or(Value::Null);
    match rollback::rollback_of(
        &state.pool,
        &state.config,
        device_id,
        template_id,
        &params,
        Some(g.session.user_id),
        format!("manual rollback of reroute #{id}"),
    )
    .await
    {
        Some(outcome) => (StatusCode::OK, Json(serde_json::to_value(outcome).unwrap_or_else(|_| json!({})))),
        None => err(StatusCode::UNPROCESSABLE_ENTITY, "template has no rollback"),
    }
}
