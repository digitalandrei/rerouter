//! Reroute endpoints: list / detail / manual / cancel / acknowledge-uncertain /
//! rollback.
//!
//! Authorization is enforced HERE (session + RBAC) — this process is the security
//! boundary. Manual triggers require `trigger_manual_reroute` and accept an
//! optional reason for the audit log. The executor then re-checks every safety
//! gate regardless of what the UI showed, and in observe mode returns the
//! would-run plan instead of executing.

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{client_ip, err, user_agent, AppState};
use crate::auth::rbac::{markers, RequirePermission};

type JsonResp = (StatusCode, Json<Value>);

fn pagination_bounds(total: i64, requested: u32, per_page: u32) -> (u64, u64) {
    let pages = (total.max(0) as u64).div_ceil(per_page as u64).max(1);
    let page = (requested.max(1) as u64).min(pages);
    (page, page.saturating_sub(1).saturating_mul(per_page as u64))
}
fn bundle_list_payload(
    items: Vec<Value>,
    page: u64,
    per_page: u32,
    total: i64,
    legacy: bool,
) -> Value {
    if legacy {
        json!(items)
    } else {
        json!({"items":items,"page":page,"per_page":per_page,"total":total})
    }
}

fn parse_created_bound(
    value: &Option<String>,
) -> Result<Option<DateTime<Utc>>, chrono::ParseError> {
    value
        .as_deref()
        .map(|v| DateTime::parse_from_rfc3339(v).map(|d| d.with_timezone(&Utc)))
        .transpose()
}

#[derive(sqlx::FromRow)]
struct RerouteRow {
    id: u64,
    bundle_id: Option<u64>,
    mutation_effect: String,
    rollback_of_reroute_id: Option<u64>,
    source_json: Option<sqlx::types::Json<Value>>,
    planned_steps_json: Option<sqlx::types::Json<Value>>,
    prior_state_json: Option<sqlx::types::Json<Value>>,
    after_state_json: Option<sqlx::types::Json<Value>>,
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

const REROUTE_SELECT: &str = "SELECT r.id, r.bundle_id, r.mutation_effect,r.rollback_of_reroute_id, b.source_json, r.planned_steps_json,r.prior_state_json,r.after_state_json, r.device_id, d.name AS device_name, \
     r.reroute_template_id, t.name AS template_name, t.display_name AS template_display_name, \
     r.trigger_type, r.state, \
     r.reason, r.success, r.verification_status, r.failure_reason, r.rule_id, u.email AS triggered_by, \
     r.started_at, r.finished_at, r.created_at \
     FROM reroutes r \
     LEFT JOIN devices d ON d.id = r.device_id \
     LEFT JOIN reroute_templates t ON t.id = r.reroute_template_id \
     LEFT JOIN reroute_bundles b ON b.id = r.bundle_id \
     LEFT JOIN users u ON u.id = r.triggered_by_user_id";

fn has_snapshot_proof(snapshot: &Option<sqlx::types::Json<Value>>) -> bool {
    snapshot.as_ref().is_some_and(|value| {
        serde_json::from_value::<Vec<crate::reroute::device_plan::DeviceStateSnapshot>>(
            value.0.clone(),
        )
        .is_ok_and(|items| !items.is_empty())
    })
}

fn reroute_json(r: &RerouteRow) -> Value {
    json!({
        "id": r.id,
        "bundle_id": r.bundle_id,
        "mutation_effect": r.mutation_effect,
        "source": r.source_json.as_ref().map(|source| &source.0),
        "verification_mode": r.planned_steps_json.as_ref().and_then(|steps| steps.0.get("verification_mode")).cloned().or_else(||r.source_json.as_ref().and_then(|source| source.0.get("verification_mode")).cloned()).unwrap_or(json!("routing")),
        "routing_verified": r.source_json.as_ref().and_then(|source| source.0.get("routing_verified")).cloned(),
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
        "reconcile_available": r.device_id.is_some() && has_snapshot_proof(&r.prior_state_json) && has_snapshot_proof(&r.after_state_json) && (r.state == "uncertain" || (r.state == "failed" && r.mutation_effect == "changed" && r.rollback_of_reroute_id.is_some())),
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
    _headers: HeaderMap,
    ConnectInfo(_socket): ConnectInfo<SocketAddr>,
    Json(body): Json<ManualBody>,
) -> JsonResp {
    use super::manual_mitigations as manual;
    if body.targets.is_empty() {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "at least one target router is required",
        );
    }
    let reason = body
        .reason
        .as_deref()
        .unwrap_or("manual mitigation")
        .trim()
        .to_string();
    let actions: Vec<_> = body
        .targets
        .iter()
        .map(|target| crate::reroute::preparation::ActionDraft {
            id: None,
            reroute_template_id: body.template_id,
            device_id: target.device_id,
            params: target.params.clone(),
            enabled: true,
            auto_target: None,
        })
        .collect();
    let request = json!({"actions":actions,"preset_id":null,"preset_revision":null,
        "reason":reason,"revert_after_seconds":null});
    if body.dry_run || body.preview_token.is_none() {
        return manual::preview_manual(
            &state,
            &g.session,
            manual::PreviewBody {
                verification_mode: crate::reroute::device_plan::VerificationMode::Routing,
                preset_id: None,
                preset_revision: None,
                actions,
                reason: Some(reason),
                revert_after_seconds: None,
                request_id: None,
            },
            "legacy_manual",
        )
        .await;
    }
    let Some(token) = body.preview_token.as_deref() else {
        return err(StatusCode::CONFLICT, "preview_required");
    };
    let (plan_id, snapshot) =
        match manual::plan_for_token(&state.pool, g.session.user_id, token, "legacy_manual", None)
            .await
        {
            Ok(value) => value,
            Err(e) => return err(StatusCode::CONFLICT, &e.to_string()),
        };
    if snapshot.request != request {
        return err(
            StatusCode::CONFLICT,
            "preview_changed; prepare a fresh preview",
        );
    }
    let accepted = match manual::accept_plan(
        &state,
        &g.session,
        plan_id,
        token,
        "legacy_manual",
        None,
    )
    .await
    {
        Ok(value) => value,
        Err(e) => return err(StatusCode::CONFLICT, &format!("{e:#}")),
    };
    let bundle_id = accepted.bundle_id;
    if accepted.already_accepted {
        return execution_results(&state.pool, bundle_id).await;
    }
    let run = manual::run_context(&g.session, &accepted);
    let pool = state.pool.clone();
    let cfg = state.config.clone();
    // Dropping the HTTP future must not cancel an admitted mitigation.
    let task = tokio::spawn(async move {
        crate::reroute::bundle::run(&pool, &cfg, run, accepted.snapshot.actions).await
    });
    match task.await {
        Ok(result) => (
            StatusCode::OK,
            Json(
                json!({"results":result.results,"bundle_id":bundle_id,"state":result.state,"preview_token":null}),
            ),
        ),
        Err(_) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("execution interrupted; reconcile bundle #{bundle_id} before retrying"),
        ),
    }
}

pub(crate) async fn execution_results(pool: &sqlx::MySqlPool, bundle_id: u64) -> JsonResp {
    let state: Option<String> =
        match sqlx::query_scalar("SELECT state FROM reroute_bundles WHERE id = ?")
            .bind(bundle_id)
            .fetch_optional(pool)
            .await
        {
            Ok(value) => value,
            Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
        };
    if matches!(
        state.as_deref(),
        Some("planned" | "running" | "compensating")
    ) {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error":"execution_in_progress","bundle_id":bundle_id,"async":true})),
        );
    }
    type Row = (u64, u64, String, String, Option<String>, Option<String>);
    let rows: Vec<Row> = match sqlx::query_as("SELECT r.id, r.device_id, r.state, r.mutation_effect, r.failure_reason, d.name \
        FROM reroutes r LEFT JOIN devices d ON d.id = r.device_id WHERE r.bundle_id = ? ORDER BY r.bundle_position, r.id")
        .bind(bundle_id).fetch_all(pool).await {
        Ok(rows) => rows, Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    let results: Vec<_> = rows.into_iter().map(|(id, device, state, effect, reason, name)| json!({
        "reroute_id":id,"device_id":device,"device_name":name,"state":state,"mutation_effect":effect,
        "executed":matches!(effect.as_str(),"changed"|"unknown"),"message":reason.clone().unwrap_or_else(||state.clone()),
        "blocked_reason":reason,
    })).collect();
    (
        StatusCode::OK,
        Json(json!({"results":results,"bundle_id":bundle_id,"state":state,"preview_token":null})),
    )
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
    _headers: HeaderMap,
    ConnectInfo(_socket): ConnectInfo<SocketAddr>,
    Json(body): Json<AckBody>,
) -> JsonResp {
    reconcile_result(
        &state,
        id,
        g.session.user_id,
        body.note.as_deref().unwrap_or("operator reconciliation"),
    )
    .await
}

/// Reconciliation is read-only on the device. A note cannot override conflicting
/// router evidence or clear the uncertainty of another sibling.
pub async fn reconcile(
    g: RequirePermission<markers::AcknowledgeUncertainReroute>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
    Json(body): Json<AckBody>,
) -> JsonResp {
    reconcile_result(
        &state,
        id,
        g.session.user_id,
        body.note.as_deref().unwrap_or("operator reconciliation"),
    )
    .await
}

async fn reconcile_result(state: &AppState, id: u64, actor: u64, note: &str) -> JsonResp {
    let _fence = match crate::reroute::guard::policy_fence(&state.pool).await {
        Ok(fence) => fence,
        Err(e) => return err(StatusCode::CONFLICT, &e.to_string()),
    };
    match crate::reroute::state_machine::reconcile_uncertain(&state.pool, id, actor, note).await {
        Ok(outcome) => {
            use crate::reroute::state_machine::ReconciliationResult;
            let message = match outcome {
                ReconciliationResult::Changed => "The owned change is present. Preview its rollback; bundle ownership remains held until recovery completes.",
                ReconciliationResult::NotApplied => "The original state is proved. This action made no lasting change.",
                ReconciliationResult::Conflict => "The router matches neither recorded state. Quarantine remains; investigate before further changes.",
            };
            (
                StatusCode::OK,
                Json(
                    json!({"ok":outcome!=ReconciliationResult::Conflict,"outcome":outcome,"message":message}),
                ),
            )
        }
        Err(e) => err(
            StatusCode::CONFLICT,
            &format!("reconciliation could not prove a safe state; quarantine retained: {e:#}"),
        ),
    }
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
    _headers: HeaderMap,
    ConnectInfo(_socket): ConnectInfo<SocketAddr>,
    Json(body): Json<RollbackBody>,
) -> JsonResp {
    use super::manual_mitigations as manual;
    let reason = body
        .reason
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("manual rollback of reroute #{id}"));
    if body.dry_run || body.preview_token.is_none() {
        let actions =
            match crate::reroute::preparation::prepare_rollbacks(&state.pool, &[id], &reason, true)
                .await
            {
                Ok(actions) => actions,
                Err(e) => return err(StatusCode::CONFLICT, &format!("{e:#}")),
            };
        if actions.is_empty() {
            return (
                StatusCode::OK,
                Json(
                    json!({"result":{"executed":false,"state":"succeeded","mutation_effect":"noop","message":"Original action changed nothing; no rollback is needed"},"preview_token":null}),
                ),
            );
        }
        let (status, Json(mut response)) = manual::preview_actions(
            &state,
            &g.session,
            "reroute_rollback",
            Some(id),
            actions,
            json!({"kind":"rollback","original_reroute_id":id}),
            reason.clone(),
            json!({"original_reroute_id":id,"reason":reason}),
            None,
        )
        .await;
        if status.is_success() {
            response["result"] = response["results"].get(0).cloned().unwrap_or(Value::Null);
        }
        return (status, Json(response));
    }
    let Some(token) = body.preview_token.as_deref() else {
        return err(StatusCode::CONFLICT, "preview_required");
    };
    let (plan_id, snapshot) = match manual::plan_for_token(
        &state.pool,
        g.session.user_id,
        token,
        "reroute_rollback",
        Some(id),
    )
    .await
    {
        Ok(value) => value,
        Err(e) => return err(StatusCode::CONFLICT, &e.to_string()),
    };
    if snapshot.reason != reason {
        return err(
            StatusCode::CONFLICT,
            "preview_changed; prepare a fresh preview",
        );
    }
    let accepted = match manual::accept_plan(
        &state,
        &g.session,
        plan_id,
        token,
        "reroute_rollback",
        Some(id),
    )
    .await
    {
        Ok(value) => value,
        Err(e) => return err(StatusCode::CONFLICT, &format!("{e:#}")),
    };
    let bundle_id = accepted.bundle_id;
    if accepted.already_accepted {
        let (status, Json(mut response)) = execution_results(&state.pool, bundle_id).await;
        if status.is_success() {
            response["result"] = response["results"].get(0).cloned().unwrap_or(Value::Null);
        }
        return (status, Json(response));
    }
    let run = manual::run_context(&g.session, &accepted);
    let pool = state.pool.clone();
    let cfg = state.config.clone();
    match tokio::spawn(async move {
        crate::reroute::bundle::run(&pool, &cfg, run, accepted.snapshot.actions).await
    })
    .await
    {
        Ok(out) => (
            StatusCode::OK,
            Json(
                json!({"result":out.results.first(),"results":out.results,"bundle_id":bundle_id,"state":out.state,"preview_token":null}),
            ),
        ),
        Err(_) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("rollback interrupted; reconcile bundle #{bundle_id}"),
        ),
    }
}

/// GET /api/reroute-bundles/{id} — progress of one ordered mitigation bundle.
///
/// A confirmed enforce-mode rule apply returns immediately with a bundle id and
/// keeps pushing config in the background, so this is how the SPA follows it. It
/// reports the bundle's terminal state, per-sibling outcomes in execution order,
/// and — the part an operator must not miss — which siblings are STILL APPLIED
/// when compensation could not finish.
/// Include runs that failed before creating any child reroute, so a lost HTTP
/// response can always be reconciled through the shared execution history.
#[derive(Default, Deserialize)]
pub struct BundleListQuery {
    page: Option<u32>,
    per_page: Option<u32>,
    lifecycle: Option<String>,
    trigger_type: Option<String>,
    rule_id: Option<u64>,
    preset_id: Option<u64>,
    #[serde(default, alias = "original_only")]
    logical_only: bool,
    q: Option<String>,
    source_kind: Option<String>,
    device: Option<String>,
    created_from: Option<String>,
    created_to: Option<String>,
}

pub async fn bundle_list(
    _g: RequirePermission<markers::ViewAsset>,
    State(state): State<AppState>,
    Query(query): Query<BundleListQuery>,
) -> JsonResp {
    let legacy = query.page.is_none()
        && query.per_page.is_none()
        && query.lifecycle.is_none()
        && query.trigger_type.is_none()
        && query.rule_id.is_none()
        && query.preset_id.is_none()
        && query.q.is_none()
        && query.source_kind.is_none()
        && query.device.is_none()
        && query.created_from.is_none()
        && query.created_to.is_none()
        && !query.logical_only;
    let requested_page = query.page.unwrap_or(1).max(1);
    let per_page = query
        .per_page
        .unwrap_or(if legacy { 100 } else { 25 })
        .clamp(1, 200);
    let lifecycle = query.lifecycle.as_deref().filter(|v| *v != "all");
    let created_from = match parse_created_bound(&query.created_from) {
        Ok(v) => v,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid created_from"),
    };
    let created_to = match parse_created_bound(&query.created_to) {
        Ok(v) => v,
        Err(_) => return err(StatusCode::BAD_REQUEST, "invalid created_to"),
    };
    let filter = super::run_summaries::RunSummaryFilter {
        lifecycle,
        trigger_type: query.trigger_type.as_deref(),
        rule_id: query.rule_id,
        preset_id: query.preset_id,
        original_only: query.logical_only,
        q: query.q.as_deref(),
        source_kind: query.source_kind.as_deref(),
        device: query.device.as_deref(),
        created_from,
        created_to,
    };
    let total = match super::run_summaries::count(&state.pool, &filter).await {
        Ok(value) => value,
        Err(_) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not count mitigation runs",
            )
        }
    };
    let (page, offset) = pagination_bounds(total, requested_page, per_page);
    match super::run_summaries::list(&state.pool, &filter, per_page, offset).await {
        Ok(items) => (
            StatusCode::OK,
            Json(bundle_list_payload(items, page, per_page, total, legacy)),
        ),
        Err(_) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not load mitigation runs",
        ),
    }
}

pub async fn bundle_show(
    _g: RequirePermission<markers::ViewAsset>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> JsonResp {
    let mut summary = match super::run_summaries::one(&state.pool, id).await {
        Ok(Some(row)) => row,
        Ok(None) => return err(StatusCode::NOT_FOUND, "bundle not found"),
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    #[derive(sqlx::FromRow)]
    struct ActionRow {
        reroute_id: Option<u64>,
        position: Option<u32>,
        device_id: u64,
        device_name: Option<String>,
        state: String,
        mutation_effect: String,
        failure_reason: Option<String>,
        template_snapshot_json: Option<sqlx::types::Json<Value>>,
        params: Option<sqlx::types::Json<Value>>,
        original_reroute_id: Option<u64>,
        prepared_action_json: Option<sqlx::types::Json<Value>>,
        rendered_plan_json: Option<sqlx::types::Json<Value>>,
        rendered_rollback_json: Option<sqlx::types::Json<Value>>,
    }
    let rows=sqlx::query_as::<_,ActionRow>("SELECT a.reroute_id,a.position,a.device_id,d.name AS device_name, \
        COALESCE(r.state,a.state) AS state, COALESCE(r.mutation_effect,a.mutation_effect) AS mutation_effect, \
        COALESCE(r.failure_reason,a.failure_reason) AS failure_reason, a.template_snapshot_json, \
        a.canonical_params_json AS params, COALESCE(r.rollback_of_reroute_id,a.original_reroute_id) AS original_reroute_id, \
        a.prepared_action_json,a.rendered_plan_json,a.rendered_rollback_json \
        FROM reroute_bundle_actions a LEFT JOIN reroutes r ON r.id=a.reroute_id LEFT JOIN devices d ON d.id=a.device_id \
        WHERE a.bundle_id=? ORDER BY a.position,a.id")
        .bind(id).fetch_all(&state.pool).await;
    let mut rows = match rows {
        Ok(rows) => rows,
        Err(_) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not load action ledger",
            )
        }
    };
    if rows.is_empty() && summary["total_actions"].as_u64().unwrap_or(0) > 0 {
        rows=match sqlx::query_as::<_,ActionRow>("SELECT r.id AS reroute_id,r.bundle_position AS position,r.device_id,d.name AS device_name, \
            r.state,r.mutation_effect,r.failure_reason,r.template_snapshot_json,r.parameters_json AS params, \
            r.rollback_of_reroute_id AS original_reroute_id,NULL AS prepared_action_json,NULL AS rendered_plan_json,NULL AS rendered_rollback_json \
            FROM reroutes r LEFT JOIN devices d ON d.id=r.device_id \
            WHERE r.bundle_id=? ORDER BY r.bundle_position,r.id")
            .bind(id).fetch_all(&state.pool).await {Ok(rows)=>rows,Err(_)=>return err(StatusCode::INTERNAL_SERVER_ERROR,"could not load legacy action history")};
    }
    let prepared = match rows
        .iter()
        .filter_map(|action| action.prepared_action_json.as_ref())
        .map(|value| serde_json::from_value(value.0.clone()))
        .collect::<Result<Vec<crate::reroute::device_plan::PreparedDeviceAction>, _>>()
    {
        Ok(value) => value,
        Err(_) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "stored action evidence is invalid",
            )
        }
    };
    let projections = match crate::reroute::projection::project_action_set(&prepared) {
        Ok(value) => value,
        Err(_) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "stored action projection is invalid",
            )
        }
    };
    let terminal = !matches!(
        summary["state"].as_str(),
        Some("planned" | "running" | "compensating")
    );
    let actions:Vec<_>=rows.into_iter().map(|a| {
        let template=a.template_snapshot_json.map(|v|v.0).unwrap_or(Value::Null);
        json!({"reroute_id":a.reroute_id,"position":a.position,"device_id":a.device_id,"device_name":a.device_name,
            "state":if terminal && a.state=="queued" {"not_run"} else {&a.state},"mutation_effect":a.mutation_effect,
            "failure_reason":a.failure_reason,"template_name":template["name"],"template_display_name":template["display_name"],
            "params":a.params.map(|v|v.0),"original_reroute_id":a.original_reroute_id,
            "prepared_evidence":a.prepared_action_json.map(|v|v.0),"rendered_plan":a.rendered_plan_json.map(|v|v.0),
            "rendered_revert":a.rendered_rollback_json.map(|v|v.0)})
    }).collect();
    let source = summary["source"].clone();
    let mut originals: Vec<u64> = source
        .get("original_reroute_ids")
        .and_then(Value::as_array)
        .map(|ids| ids.iter().filter_map(Value::as_u64).collect())
        .unwrap_or_default();
    if let Some(original) = source.get("original_reroute_id").and_then(Value::as_u64) {
        originals.push(original);
    }
    let mut still = Vec::<u64>::new();
    if summary["remaining_mutations"].as_u64().unwrap_or(0) > 0 {
        if originals.is_empty() {
            still=match sqlx::query_scalar("SELECT r.id FROM reroutes r WHERE r.bundle_id=? AND r.rollback_of_reroute_id IS NULL \
                AND (r.mutation_effect IN ('changed','unknown') OR r.state='uncertain') \
                AND NOT EXISTS(SELECT 1 FROM reroutes rb WHERE rb.rollback_of_reroute_id=r.id AND rb.state='succeeded') ORDER BY r.id")
                .bind(id).fetch_all(&state.pool).await {Ok(ids)=>ids,Err(_)=>return err(StatusCode::INTERNAL_SERVER_ERROR,"could not establish remaining mutations")};
        } else {
            for original in originals {
                let remains:i64=match sqlx::query_scalar("SELECT COUNT(*) FROM reroutes r WHERE r.id=? AND r.mutation_effect IN ('changed','unknown') \
                    AND NOT EXISTS(SELECT 1 FROM reroutes rb WHERE rb.rollback_of_reroute_id=r.id AND rb.state='succeeded')")
                    .bind(original).fetch_one(&state.pool).await {Ok(count)=>count,Err(_)=>return err(StatusCode::INTERNAL_SERVER_ERROR,"could not establish remaining mutations")};
                if remains > 0 {
                    still.push(original);
                }
            }
        }
    }
    summary["actions"] = json!(actions);
    summary["projections"] = json!(projections);
    summary["still_applied_reroute_ids"] = json!(still);
    (StatusCode::OK, Json(summary))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleRevertBody {
    #[serde(default)]
    dry_run: bool,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    plan_id: Option<u64>,
    #[serde(default)]
    preview_token: Option<String>,
    /// Publish a durable server-side recovery before router preparation.
    #[serde(default)]
    direct_run: bool,
    #[serde(default)]
    request_id: Option<String>,
}

/// Preview or confirm the inverse of every mutation owned by a run. Originals
/// are loaded from durable snapshots in reverse bundle order; caller input can
/// never select or rewrite individual siblings.
pub async fn bundle_revert(
    g: RequirePermission<markers::TriggerManualReroute>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
    Json(body): Json<BundleRevertBody>,
) -> JsonResp {
    use super::manual_mitigations as manual;
    let reason = body
        .reason
        .unwrap_or_else(|| format!("revert mitigation run #{id}"));
    if body.direct_run {
        if body.dry_run || body.plan_id.is_some() || body.preview_token.is_some() {
            return err(
                StatusCode::UNPROCESSABLE_ENTITY,
                "direct revert cannot include preview authority",
            );
        }
        let Some(request_id) = body.request_id.as_deref() else {
            return err(
                StatusCode::UNPROCESSABLE_ENTITY,
                "direct revert requires request_id",
            );
        };
        return match manual::admit_direct_recovery(
            &state.pool,
            &g.session,
            id,
            reason.trim(),
            request_id,
        )
        .await
        {
            Ok(admission) => {
                manual::spawn_direct_recovery(&state, &g.session, admission);
                (
                    StatusCode::ACCEPTED,
                    Json(json!({
                        "bundle_id":admission.bundle_id,
                        "async":true,
                        "already_admitted":admission.already_admitted
                    })),
                )
            }
            Err(e) => err(StatusCode::CONFLICT, &format!("{e:#}")),
        };
    }
    if body.dry_run || body.preview_token.is_none() {
        let originals = match crate::reroute::recovery::owned_original_ids(&state.pool, id).await {
            Ok(ids) => ids,
            Err(_) => {
                return err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not establish run ownership",
                )
            }
        };
        if originals.is_empty() {
            return (
                StatusCode::OK,
                Json(
                    json!({"results":[],"revert":{"available":false,"block_reasons":[],"noop":true}}),
                ),
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
            Err(e) => {
                return err(
                    StatusCode::CONFLICT,
                    &format!("whole-run revert refused: {e:#}"),
                )
            }
        };
        return manual::preview_actions(
            &state, &g.session, "bundle_revert", Some(id), actions,
            json!({"kind":"bundle_revert","original_bundle_id":id,"original_reroute_ids":originals}),
            reason.clone(), json!({"original_bundle_id":id,"reason":reason}), None,
        ).await;
    }
    let (Some(plan_id), Some(token)) = (body.plan_id, body.preview_token.as_deref()) else {
        return err(StatusCode::CONFLICT, "preview_required");
    };
    let accepted = match manual::accept_plan(
        &state,
        &g.session,
        plan_id,
        token,
        "bundle_revert",
        Some(id),
    )
    .await
    {
        Ok(value) => value,
        Err(e) => return err(StatusCode::CONFLICT, &format!("{e:#}")),
    };
    let recovery_id = accepted.bundle_id;
    if !accepted.already_accepted {
        manual::spawn_accepted(&state, &g.session, accepted);
    }
    (
        StatusCode::ACCEPTED,
        Json(json!({"bundle_id":recovery_id,"async":true})),
    )
}

/// Cancel a future timer/recovery claim. Once recovery is in flight it cannot
/// be converted to manual ownership underneath the runner.
pub async fn bundle_take_control(
    g: RequirePermission<markers::TriggerManualReroute>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> JsonResp {
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    let changed = match sqlx::query("UPDATE reroute_bundles SET automatic_recovery_cancelled_at=UTC_TIMESTAMP(), \
        automatic_recovery_cancelled_by=?, recovery_deadline=NULL, lifecycle_state=IF(remaining_mutations>0,'active','inactive') \
        WHERE id=? AND lifecycle_state IN ('active','recovery_scheduled') AND recovery_claim_token IS NULL \
          AND (recovery_deadline IS NOT NULL OR (trigger_type='automatic' AND EXISTS(\
            SELECT 1 FROM rules recovery_rule WHERE recovery_rule.id=reroute_bundles.rule_id \
            AND recovery_rule.enabled=1 AND recovery_rule.automatic_revert_enabled=1)))")
        .bind(g.session.user_id).bind(id).execute(&mut *tx).await {
            Ok(result) => result.rows_affected(), Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR,"db_error")
        };
    if changed != 1 {
        return err(
            StatusCode::CONFLICT,
            "automatic recovery is absent, disabled, claimed, or already in flight",
        );
    }
    if super::audit_mutation_on(
        &mut tx,
        &g.session,
        "reroute_bundle_manual_takeover",
        "reroute_bundle",
        id,
        "operator cancelled future automatic recovery; existing mutation ownership remains",
    )
    .await
    .is_err()
        || tx.commit().await.is_err()
    {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "takeover_commit_unknown");
    }
    (
        StatusCode::OK,
        Json(json!({"ok":true,"bundle_id":id,"automatic_recovery_cancelled":true})),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DismissRecoveryBody {
    confirmation: String,
}

/// Dismiss a terminal recovery attempt that is durably proven to have made no
/// router write. Immutable actions, associations and history remain intact.
pub async fn dismiss_recovery(
    g: RequirePermission<markers::TriggerManualReroute>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
    Json(body): Json<DismissRecoveryBody>,
) -> JsonResp {
    let expected = format!("DISMISS RECOVERY #{id}");
    if body.confirmation.trim() != expected {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "confirmation phrase does not match",
        );
    }
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    let child: Option<(String, Option<u64>, Option<sqlx::types::Json<Value>>)> =
        match sqlx::query_as(
            "SELECT state,parent_bundle_id,source_json FROM reroute_bundles WHERE id=? FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        {
            Ok(value) => value,
            Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
        };
    let Some((child_state, parent_id, source)) = child else {
        return err(StatusCode::NOT_FOUND, "recovery run not found");
    };
    if parent_id.is_none() {
        return err(
            StatusCode::CONFLICT,
            "only a recovery child can be dismissed",
        );
    }
    if source
        .as_ref()
        .and_then(|value| value.0.get("dismissed_at"))
        .is_some()
    {
        return (
            StatusCode::OK,
            Json(json!({"ok":true,"bundle_id":id,"already_dismissed":true})),
        );
    }
    if !matches!(
        child_state.as_str(),
        "failed" | "aborted" | "compensation_blocked"
    ) {
        return err(
            StatusCode::CONFLICT,
            "recovery is not a dismissible terminal failure",
        );
    }
    let settlements: (i64, i64) = match sqlx::query_as(
        "SELECT COUNT(CASE WHEN settlement='known_no_write' THEN 1 END), \
                COUNT(CASE WHEN settlement IN ('active','blocked') THEN 1 END) \
         FROM recovery_attempt_sources WHERE recovery_bundle_id=?",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(value) => value,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    let unsafe_actions: i64 = match sqlx::query_scalar(
        "SELECT COUNT(*) FROM reroutes WHERE bundle_id=? AND (state IN ('pending','running','verifying','uncertain') \
         OR mutation_effect IN ('changed','unknown'))",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(value) => value,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    let claimed_sources: i64 = match sqlx::query_scalar(
        "SELECT COUNT(*) FROM recovery_attempt_sources ras JOIN reroute_bundles source ON source.id=ras.source_bundle_id \
         WHERE ras.recovery_bundle_id=? AND source.recovery_claim_token IS NOT NULL",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(value) => value,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    if settlements.0 <= 0 || settlements.1 > 0 || unsafe_actions > 0 || claimed_sources > 0 {
        return err(
            StatusCode::CONFLICT,
            "recovery cannot be dismissed because no-write settlement is not proven",
        );
    }
    if sqlx::query(
        "UPDATE reroute_bundles SET source_json=JSON_SET(COALESCE(source_json,JSON_OBJECT()), \
         '$.dismissed_at',DATE_FORMAT(UTC_TIMESTAMP(),'%Y-%m-%dT%H:%i:%sZ'),'$.dismissed_by',?) WHERE id=?",
    )
    .bind(g.session.user_id)
    .bind(id)
    .execute(&mut *tx)
    .await
    .is_err()
        || super::audit_mutation_on(
            &mut tx,
            &g.session,
            "recovery_attempt_dismissed",
            "reroute_bundle",
            id,
            "dismissed proven no-write recovery attempt; immutable evidence preserved",
        )
        .await
        .is_err()
        || tx.commit().await.is_err()
    {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "dismiss_recovery_failed");
    }
    (
        StatusCode::OK,
        Json(json!({"ok":true,"bundle_id":id,"dismissed":true})),
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    #[test]
    fn maximum_page_is_clamped_without_offset_wrap() {
        assert_eq!(super::pagination_bounds(401, u32::MAX, 200), (3, 400));
        assert_eq!(super::pagination_bounds(0, u32::MAX, 200), (1, 0));
    }
    #[test]
    fn bundle_list_keeps_legacy_array_only_without_query_contract() {
        assert!(super::bundle_list_payload(vec![], 1, 100, 0, true).is_array());
        let paged = super::bundle_list_payload(vec![], 1, 50, 0, false);
        assert!(paged.is_object());
        assert_eq!(paged["page"], 1);
    }
    #[test]
    fn reconciliation_requires_typed_nonempty_snapshot_evidence() {
        assert!(!super::has_snapshot_proof(&None));
        assert!(!super::has_snapshot_proof(&Some(sqlx::types::Json(json!(
            []
        )))));
        assert!(!super::has_snapshot_proof(&Some(sqlx::types::Json(
            json!({"bad":true})
        ))));
        let snapshot =
            json!([{"kind":"interface_admin","interface":"GigabitEthernet0/0","shutdown":false}]);
        assert!(super::has_snapshot_proof(&Some(sqlx::types::Json(
            snapshot
        ))));
    }
    #[test]
    fn created_bounds_require_rfc3339_and_normalize_offsets() {
        assert!(super::parse_created_bound(&Some("2026-09-20".into())).is_err());
        assert!(super::parse_created_bound(&Some("not-a-date".into())).is_err());
        let parsed = super::parse_created_bound(&Some("2026-09-20T12:00:00+03:00".into()))
            .unwrap()
            .unwrap();
        assert_eq!(parsed.to_rfc3339(), "2026-09-20T09:00:00+00:00");
    }
}
