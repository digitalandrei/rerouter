//! Reroute endpoints: list / detail / manual / cancel / acknowledge-uncertain /
//! rollback.
//!
//! Authorization is enforced HERE (session + RBAC) — this process is the security
//! boundary. Manual triggers require `trigger_manual_reroute` and accept an
//! optional reason for the audit log. The executor then re-checks every safety
//! gate regardless of what the UI showed, and in observe mode returns the
//! would-run plan instead of executing.

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{client_ip, err, user_agent, AppState};
use crate::auth::rbac::{markers, RequirePermission};
use crate::reroute::executor::{self, ActionRequest, ActorContext};
use crate::reroute::{rollback, templates};

type JsonResp = (StatusCode, Json<Value>);

#[derive(sqlx::FromRow)]
struct RerouteRow {
    id: u64,
    device_id: Option<u64>,
    device_name: Option<String>,
    reroute_template_id: Option<u64>,
    template_name: Option<String>,
    template_display_name: Option<String>,
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
     r.reroute_template_id, t.name AS template_name, t.display_name AS template_display_name, \
     r.trigger_type, r.state, \
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
        "template_display_name": r.template_display_name,
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
pub async fn list(
    _g: RequirePermission<markers::ViewAsset>,
    State(state): State<AppState>,
) -> JsonResp {
    let rows =
        sqlx::query_as::<_, RerouteRow>(&format!("{REROUTE_SELECT} ORDER BY r.id DESC LIMIT 200"))
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
pub async fn show(
    _g: RequirePermission<markers::ViewAsset>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> JsonResp {
    let row = sqlx::query_as::<_, RerouteRow>(&format!("{REROUTE_SELECT} WHERE r.id = ?"))
        .bind(id)
        .fetch_optional(&state.pool)
        .await;
    let Ok(Some(r)) = row else {
        return err(StatusCode::NOT_FOUND, "reroute not found");
    };

    let steps = match sqlx::query_as::<_, (u32, Option<String>, Option<String>, String)>(
        "SELECT step_number, description, mode, state FROM reroute_steps WHERE reroute_id = ? ORDER BY step_number",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    let outputs = match sqlx::query_as::<_, (u32, Option<String>, Option<String>, Option<String>)>(
        "SELECT step_number, request, response, status FROM reroute_outputs WHERE reroute_id = ? ORDER BY id",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    let verifications = match sqlx::query_as::<_, (String, Option<String>, Option<String>, String)>(
        "SELECT method, expected, observed, result FROM reroute_verifications WHERE reroute_id = ? ORDER BY id",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await
    {
        Ok(rows) => rows,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };

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
    #[serde(default)]
    preview_token: Option<String>,
}

/// POST /api/reroutes/manual — plan + execute a template against one or more
/// routers. Gates re-checked at execution time; in observe mode the would-run
/// plan is returned and nothing executes.
pub async fn manual(
    g: RequirePermission<markers::TriggerManualReroute>,
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(socket): ConnectInfo<SocketAddr>,
    Json(body): Json<ManualBody>,
) -> JsonResp {
    let actor_context = ActorContext {
        ip_address: client_ip(&headers, Some(&socket)),
        user_agent: user_agent(&headers),
    };
    if body.targets.is_empty() {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "at least one target router is required",
        );
    }
    let template = match templates::load(&state.pool, body.template_id).await {
        Ok(t) => t,
        Err(_) => return err(StatusCode::NOT_FOUND, "template not found"),
    };
    if template.provider_type != "device_cli" {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "only device_cli templates can be executed",
        );
    }

    let mode = crate::api::settings::operating_mode(&state.pool, &state.config).await;
    if mode == "enforce" && !body.dry_run {
        let preview = manual_results(
            &state,
            &template,
            &body.targets,
            &body.reason,
            g.session.user_id,
            &actor_context,
            true,
        )
        .await;
        let Some(token) = body.preview_token.as_deref() else {
            return err(StatusCode::CONFLICT, "preview_required");
        };
        match super::consume_action_preview(
            &state.pool,
            token,
            g.session.user_id,
            "manual_reroute",
            None,
            &json!({ "results": preview, "reason": body.reason }),
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => return err(StatusCode::CONFLICT, "preview_expired_or_changed"),
            Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "preview_check_failed"),
        }
    }

    let results = manual_results(
        &state,
        &template,
        &body.targets,
        &body.reason,
        g.session.user_id,
        &actor_context,
        body.dry_run,
    )
    .await;
    let preview_token = if mode == "enforce" && body.dry_run {
        match super::store_action_preview(
            &state.pool,
            g.session.user_id,
            "manual_reroute",
            None,
            &json!({ "results": results, "reason": body.reason }),
        )
        .await
        {
            Ok(token) => Some(token),
            Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "preview_store_failed"),
        }
    } else {
        None
    };
    (
        StatusCode::OK,
        Json(json!({ "results": results, "preview_token": preview_token })),
    )
}

async fn manual_results(
    state: &AppState,
    template: &templates::Template,
    targets: &[ManualTarget],
    reason: &Option<String>,
    user_id: u64,
    actor_context: &ActorContext,
    dry_run: bool,
) -> Vec<Value> {
    let mut results = Vec::with_capacity(targets.len());
    for target in targets {
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
            rule_event_id: None,
            rollback_of_reroute_id: None,
            user_id: Some(user_id),
            actor_context: Some(actor_context.clone()),
            reason: reason.clone(),
            defer_cooldown: false,
        };
        let outcome = executor::execute(&state.pool, &state.config, req, dry_run).await;
        results.push(serde_json::to_value(outcome).unwrap_or_else(|_| json!({})));
    }
    results
}

/// POST /api/reroutes/{id}/cancel — cancel a still-pending reroute.
pub async fn cancel(
    g: RequirePermission<markers::TriggerManualReroute>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
    headers: HeaderMap,
    ConnectInfo(socket): ConnectInfo<SocketAddr>,
) -> JsonResp {
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    let res = sqlx::query(
        "UPDATE reroutes SET state = 'failed', finished_at = UTC_TIMESTAMP(), success = 0, \
         failure_reason = 'cancelled by operator' WHERE id = ? AND state IN ('planned','pending')",
    )
    .bind(id)
    .execute(&mut *tx)
    .await;
    match res {
        Ok(r) if r.rows_affected() > 0 => {
            if sqlx::query(
                "INSERT INTO audit_logs \
                 (actor_type, actor_user_id, event_type, entity_type, entity_id, reroute_id, \
                  message, ip_address, user_agent) \
                 VALUES ('user', ?, 'reroute_cancelled', 'reroute', ?, ?, \
                         'cancelled before command execution', ?, ?)",
            )
            .bind(g.session.user_id)
            .bind(id)
            .bind(id)
            .bind(client_ip(&headers, Some(&socket)))
            .bind(user_agent(&headers))
            .execute(&mut *tx)
            .await
            .is_err()
                || tx.commit().await.is_err()
            {
                return err(StatusCode::INTERNAL_SERVER_ERROR, "audit_write_failed");
            }
            (StatusCode::OK, Json(json!({ "ok": true })))
        }
        Ok(_) => err(
            StatusCode::CONFLICT,
            "reroute is not in a cancellable state",
        ),
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
    headers: HeaderMap,
    ConnectInfo(socket): ConnectInfo<SocketAddr>,
    Json(body): Json<AckBody>,
) -> JsonResp {
    let note = body.note.unwrap_or_default();
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    let row = sqlx::query_as::<_, (String, Option<u64>)>(
        "SELECT state, device_id FROM reroutes WHERE id = ? FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await;
    let (rstate, _device_id) = match row {
        Ok(Some(row)) => row,
        Ok(None) => return err(StatusCode::NOT_FOUND, "reroute not found"),
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    if rstate != "uncertain" {
        return err(
            StatusCode::CONFLICT,
            "reroute is not in the uncertain state",
        );
    }
    let updated = sqlx::query(
        "UPDATE reroutes SET state = 'failed', verification_status = 'acknowledged', \
         failure_reason = CONCAT(COALESCE(failure_reason,''), ' | acknowledged by admin: ', ?) \
         WHERE id = ? AND state = 'uncertain'",
    )
    .bind(&note)
    .bind(id)
    .execute(&mut *tx)
    .await;
    if !matches!(updated, Ok(ref r) if r.rows_affected() == 1) {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not record acknowledgement",
        );
    }
    if sqlx::query(
        "UPDATE locks SET cleared_at = UTC_TIMESTAMP(), cleared_by = ? \
         WHERE cleared_at IS NULL AND \
           (reroute_id = ? OR (reroute_id IS NULL AND kind IN ('auto_crash','auto_uncertain') \
             AND reason LIKE CONCAT('reroute #', ?, '%')))",
    )
    .bind(g.session.user_id)
    .bind(id)
    .bind(id)
    .execute(&mut *tx)
    .await
    .is_err()
    {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not clear reroute lock",
        );
    }
    if sqlx::query(
        "INSERT INTO audit_logs \
         (actor_type, actor_user_id, event_type, entity_type, entity_id, reroute_id, \
          message, ip_address, user_agent) \
         VALUES ('user', ?, 'reroute_uncertain_acknowledged', 'reroute', ?, ?, ?, ?, ?)",
    )
    .bind(g.session.user_id)
    .bind(id)
    .bind(id)
    .bind(format!("acknowledged uncertain reroute: {note}"))
    .bind(client_ip(&headers, Some(&socket)))
    .bind(user_agent(&headers))
    .execute(&mut *tx)
    .await
    .is_err()
        || tx.commit().await.is_err()
    {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "audit_write_failed");
    }

    (StatusCode::OK, Json(json!({ "ok": true })))
}

/// POST /api/reroutes/{id}/rollback — run the template's rollback against the
/// same device + params as a fresh audited action.
#[derive(Debug, Deserialize)]
pub struct RollbackBody {
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    dry_run: bool,
    #[serde(default)]
    preview_token: Option<String>,
}

pub async fn rollback(
    g: RequirePermission<markers::TriggerManualReroute>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
    headers: HeaderMap,
    ConnectInfo(socket): ConnectInfo<SocketAddr>,
    Json(body): Json<RollbackBody>,
) -> JsonResp {
    type OriginalRow = (
        Option<u64>,
        Option<u64>,
        Option<sqlx::types::Json<Value>>,
        String,
        Option<DateTime<Utc>>,
    );
    let row = sqlx::query_as::<_, OriginalRow>(
        "SELECT device_id, reroute_template_id, parameters_json, state, started_at \
         FROM reroutes WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await;
    let (device_id, template_id, params_json, original_state, started_at) = match row {
        Ok(Some((Some(device_id), Some(template_id), params_json, state, started_at))) => {
            (device_id, template_id, params_json, state, started_at)
        }
        Ok(Some(_)) => {
            return err(
                StatusCode::UNPROCESSABLE_ENTITY,
                "reroute has no device/template to roll back",
            )
        }
        Ok(None) => return err(StatusCode::NOT_FOUND, "reroute not found"),
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    if started_at.is_none()
        || !matches!(
            original_state.as_str(),
            "succeeded" | "failed" | "uncertain"
        )
    {
        return err(
            StatusCode::CONFLICT,
            "the original action never reached execution and must not be rolled back",
        );
    }
    let existing: i64 = match sqlx::query_scalar(
        "SELECT COUNT(*) FROM reroutes WHERE rollback_of_reroute_id = ? \
         AND state IN ('planned','pending','running','verifying','succeeded')",
    )
    .bind(id)
    .fetch_one(&state.pool)
    .await
    {
        Ok(count) => count,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    if existing > 0 {
        return err(
            StatusCode::CONFLICT,
            "this action already has an active or successful rollback",
        );
    }

    let params = params_json.map(|j| j.0).unwrap_or(Value::Null);
    let actor_context = ActorContext {
        ip_address: client_ip(&headers, Some(&socket)),
        user_agent: user_agent(&headers),
    };
    let reason = body
        .reason
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("manual rollback of reroute #{id}"));
    let mode = crate::api::settings::operating_mode(&state.pool, &state.config).await;

    if mode == "enforce" && !body.dry_run {
        let preview = match rollback_attempt(
            &state,
            device_id,
            template_id,
            &params,
            id,
            g.session.user_id,
            &actor_context,
            &reason,
            true,
        )
        .await
        {
            Ok(Some(outcome)) => outcome,
            Ok(None) => return err(StatusCode::UNPROCESSABLE_ENTITY, "template has no rollback"),
            Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "rollback_preview_failed"),
        };
        let Some(token) = body.preview_token.as_deref() else {
            return err(StatusCode::CONFLICT, "preview_required");
        };
        match super::consume_action_preview(
            &state.pool,
            token,
            g.session.user_id,
            "reroute_rollback",
            Some(id),
            &json!({ "result": preview, "reason": reason }),
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => return err(StatusCode::CONFLICT, "preview_expired_or_changed"),
            Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "preview_check_failed"),
        }
    }

    let outcome = match rollback_attempt(
        &state,
        device_id,
        template_id,
        &params,
        id,
        g.session.user_id,
        &actor_context,
        &reason,
        body.dry_run,
    )
    .await
    {
        Ok(Some(outcome)) => outcome,
        Ok(None) => return err(StatusCode::UNPROCESSABLE_ENTITY, "template has no rollback"),
        Err(e) => return err(StatusCode::CONFLICT, &e.to_string()),
    };
    let preview_token = if mode == "enforce" && body.dry_run {
        match super::store_action_preview(
            &state.pool,
            g.session.user_id,
            "reroute_rollback",
            Some(id),
            &json!({ "result": outcome, "reason": reason }),
        )
        .await
        {
            Ok(token) => Some(token),
            Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "preview_store_failed"),
        }
    } else {
        None
    };
    (
        StatusCode::OK,
        Json(json!({ "result": outcome, "preview_token": preview_token })),
    )
}

#[allow(clippy::too_many_arguments)]
async fn rollback_attempt(
    state: &AppState,
    device_id: u64,
    template_id: u64,
    params: &Value,
    original_id: u64,
    user_id: u64,
    actor_context: &ActorContext,
    reason: &str,
    dry_run: bool,
) -> anyhow::Result<Option<executor::ExecOutcome>> {
    rollback::rollback_of(
        &state.pool,
        &state.config,
        rollback::RollbackRequest {
            device_id,
            template_id,
            params,
            original_reroute_id: Some(original_id),
            rule_event_id: None,
            user_id: Some(user_id),
            actor_context: Some(actor_context.clone()),
            reason: reason.to_string(),
            defer_cooldown: false,
            dry_run,
        },
    )
    .await
}
