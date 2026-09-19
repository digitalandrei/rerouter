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

#[derive(sqlx::FromRow)]
struct RerouteRow {
    id: u64,
    bundle_id: Option<u64>,
    mutation_effect: String,
    source_json: Option<sqlx::types::Json<Value>>,
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

const REROUTE_SELECT: &str = "SELECT r.id, r.bundle_id, r.mutation_effect, b.source_json, r.device_id, d.name AS device_name, \
     r.reroute_template_id, t.name AS template_name, t.display_name AS template_display_name, \
     r.trigger_type, r.state, \
     r.reason, r.success, r.verification_status, r.failure_reason, r.rule_id, u.email AS triggered_by, \
     r.started_at, r.finished_at, r.created_at \
     FROM reroutes r \
     LEFT JOIN devices d ON d.id = r.device_id \
     LEFT JOIN reroute_templates t ON t.id = r.reroute_template_id \
     LEFT JOIN reroute_bundles b ON b.id = r.bundle_id \
     LEFT JOIN users u ON u.id = r.triggered_by_user_id";

fn reroute_json(r: &RerouteRow) -> Value {
    json!({
        "id": r.id,
        "bundle_id": r.bundle_id,
        "mutation_effect": r.mutation_effect,
        "source": r.source_json.as_ref().map(|source| &source.0),
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
                preset_id: None,
                preset_revision: None,
                actions,
                reason: Some(reason),
                revert_after_seconds: None,
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
}

pub async fn bundle_list(
    _g: RequirePermission<markers::ViewAsset>,
    State(state): State<AppState>,
    Query(query): Query<BundleListQuery>,
) -> JsonResp {
    #[derive(sqlx::FromRow)]
    struct Row {
        id: u64,
        rule_id: Option<u64>,
        trigger_type: String,
        state: String,
        reason: Option<String>,
        total_actions: u32,
        completed_actions: u32,
        failure_reason: Option<String>,
        started_at: Option<DateTime<Utc>>,
        finished_at: Option<DateTime<Utc>>,
        created_at: DateTime<Utc>,
        source_json: Option<sqlx::types::Json<Value>>,
        triggered_by: Option<String>,
        lifecycle_state: String,
        remaining_mutations: u32,
        recovery_deadline: Option<DateTime<Utc>>,
    }
    let legacy = query.page.is_none()
        && query.per_page.is_none()
        && query.lifecycle.is_none()
        && query.trigger_type.is_none()
        && query.rule_id.is_none()
        && query.preset_id.is_none();
    let requested_page = query.page.unwrap_or(1).max(1);
    let per_page = query
        .per_page
        .unwrap_or(if legacy { 100 } else { 50 })
        .clamp(1, 200);
    let lifecycle = query.lifecycle.as_deref().filter(|v| *v != "all");
    let total:i64=match sqlx::query_scalar("SELECT COUNT(*) FROM reroute_bundles b WHERE \
        (? IS NULL OR (?='active' AND (b.remaining_mutations>0 OR b.state IN ('planned','running','compensating') OR b.lifecycle_state<>'inactive')) \
          OR (?='inactive' AND b.remaining_mutations=0 AND b.state NOT IN ('planned','running','compensating') AND b.lifecycle_state='inactive') OR b.lifecycle_state=?) \
        AND (? IS NULL OR b.trigger_type=?) AND (? IS NULL OR b.rule_id=?) \
        AND (? IS NULL OR JSON_UNQUOTE(JSON_EXTRACT(b.source_json,'$.preset_id'))=CAST(? AS CHAR))")
        .bind(lifecycle).bind(lifecycle).bind(lifecycle).bind(lifecycle)
        .bind(query.trigger_type.as_deref()).bind(query.trigger_type.as_deref())
        .bind(query.rule_id).bind(query.rule_id).bind(query.preset_id).bind(query.preset_id)
        .fetch_one(&state.pool).await {Ok(v)=>v,Err(_)=>return err(StatusCode::INTERNAL_SERVER_ERROR,"could not count mitigation runs")};
    let (page, offset) = pagination_bounds(total, requested_page, per_page);
    match sqlx::query_as::<_,Row>("SELECT b.id,b.rule_id,b.trigger_type,b.state,b.reason,b.total_actions,b.completed_actions, \
        b.failure_reason,b.started_at,b.finished_at,b.created_at,b.source_json,u.email AS triggered_by, \
        b.lifecycle_state,b.remaining_mutations,b.recovery_deadline \
        FROM reroute_bundles b LEFT JOIN users u ON u.id=b.triggered_by_user_id WHERE \
        (? IS NULL OR (?='active' AND (b.remaining_mutations>0 OR b.state IN ('planned','running','compensating') OR b.lifecycle_state<>'inactive')) \
          OR (?='inactive' AND b.remaining_mutations=0 AND b.state NOT IN ('planned','running','compensating') AND b.lifecycle_state='inactive') OR b.lifecycle_state=?) \
        AND (? IS NULL OR b.trigger_type=?) AND (? IS NULL OR b.rule_id=?) \
        AND (? IS NULL OR JSON_UNQUOTE(JSON_EXTRACT(b.source_json,'$.preset_id'))=CAST(? AS CHAR)) \
        ORDER BY b.id DESC LIMIT ? OFFSET ?")
        .bind(lifecycle).bind(lifecycle).bind(lifecycle).bind(lifecycle)
        .bind(query.trigger_type.as_deref()).bind(query.trigger_type.as_deref())
        .bind(query.rule_id).bind(query.rule_id).bind(query.preset_id).bind(query.preset_id)
        .bind(per_page).bind(offset).fetch_all(&state.pool).await {
        Ok(rows)=>{
            let items=rows.into_iter().map(|r|json!({
            "id":r.id,"rule_id":r.rule_id,"trigger_type":r.trigger_type,"state":r.state.clone(),"execution_state":r.state,"reason":r.reason,
            "total_actions":r.total_actions,"completed_actions":r.completed_actions,"failure_reason":r.failure_reason,
            "started_at":r.started_at,"finished_at":r.finished_at,"created_at":r.created_at,
            "source":r.source_json.map(|s|s.0),"triggered_by":r.triggered_by,
            "lifecycle_state":r.lifecycle_state,"remaining_mutations":r.remaining_mutations,
            "active":r.remaining_mutations>0,"recovery_deadline":r.recovery_deadline,
            })).collect::<Vec<_>>();
            (StatusCode::OK,Json(bundle_list_payload(items,page,per_page,total,legacy)))
        },
        Err(_)=>err(StatusCode::INTERNAL_SERVER_ERROR,"could not load mitigation runs"),
    }
}

pub async fn bundle_show(
    _g: RequirePermission<markers::ViewAsset>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> JsonResp {
    #[derive(sqlx::FromRow)]
    struct BundleRow {
        rule_id: Option<u64>,
        trigger_type: String,
        state: String,
        failure_policy: String,
        total_actions: u32,
        completed_actions: u32,
        failure_reason: Option<String>,
        started_at: Option<DateTime<Utc>>,
        finished_at: Option<DateTime<Utc>>,
        source_json: Option<sqlx::types::Json<Value>>,
        triggered_by_user_id: Option<u64>,
        triggered_by: Option<String>,
        lifecycle_state: String,
        remaining_mutations: u32,
        recovery_deadline: Option<DateTime<Utc>>,
        automatic_recovery_cancelled_at: Option<DateTime<Utc>>,
        automatic_recovery_block_reason: Option<String>,
    }
    let row=match sqlx::query_as::<_,BundleRow>("SELECT b.rule_id,b.trigger_type,b.state,b.failure_policy,b.total_actions,b.completed_actions, \
        b.failure_reason,b.started_at,b.finished_at,b.source_json,b.triggered_by_user_id,u.email AS triggered_by, \
        b.lifecycle_state,b.remaining_mutations,b.recovery_deadline,b.automatic_recovery_cancelled_at,b.automatic_recovery_block_reason \
        FROM reroute_bundles b LEFT JOIN users u ON u.id=b.triggered_by_user_id WHERE b.id=?")
        .bind(id).fetch_optional(&state.pool).await {
        Ok(Some(row))=>row, Ok(None)=>return err(StatusCode::NOT_FOUND,"bundle not found"),
        Err(_)=>return err(StatusCode::INTERNAL_SERVER_ERROR,"db_error"),
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
    if rows.is_empty() && row.total_actions > 0 {
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
    let terminal = !matches!(row.state.as_str(), "planned" | "running" | "compensating");
    let actions:Vec<_>=rows.into_iter().map(|a| {
        let template=a.template_snapshot_json.map(|v|v.0).unwrap_or(Value::Null);
        json!({"reroute_id":a.reroute_id,"position":a.position,"device_id":a.device_id,"device_name":a.device_name,
            "state":if terminal && a.state=="queued" {"not_run"} else {&a.state},"mutation_effect":a.mutation_effect,
            "failure_reason":a.failure_reason,"template_name":template["name"],"template_display_name":template["display_name"],
            "params":a.params.map(|v|v.0),"original_reroute_id":a.original_reroute_id,
            "prepared_evidence":a.prepared_action_json.map(|v|v.0),"rendered_plan":a.rendered_plan_json.map(|v|v.0),
            "rendered_revert":a.rendered_rollback_json.map(|v|v.0)})
    }).collect();
    let source = row.source_json.map(|v| v.0).unwrap_or(Value::Null);
    let mut originals: Vec<u64> = source
        .get("original_reroute_ids")
        .and_then(Value::as_array)
        .map(|ids| ids.iter().filter_map(Value::as_u64).collect())
        .unwrap_or_default();
    if let Some(original) = source.get("original_reroute_id").and_then(Value::as_u64) {
        originals.push(original);
    }
    let mut still = Vec::<u64>::new();
    if matches!(
        row.state.as_str(),
        "aborted" | "compensation_blocked" | "failed"
    ) {
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
    (
        StatusCode::OK,
        Json(
            json!({"id":id,"rule_id":row.rule_id,"trigger_type":row.trigger_type,"state":row.state,
        "failure_policy":row.failure_policy,"total_actions":row.total_actions,"completed_actions":row.completed_actions,
        "failure_reason":row.failure_reason,"started_at":row.started_at,"finished_at":row.finished_at,"source":source,
        "execution_state":row.state,"lifecycle_state":row.lifecycle_state,"remaining_mutations":row.remaining_mutations,
        "active":row.remaining_mutations>0,"recovery_deadline":row.recovery_deadline,
        "automatic_recovery_cancelled_at":row.automatic_recovery_cancelled_at,
        "revert":{"available":row.remaining_mutations>0 && row.automatic_recovery_block_reason.is_none(),
          "block_reasons":row.automatic_recovery_block_reason.into_iter().collect::<Vec<_>>()},
        "triggered_by_user_id":row.triggered_by_user_id,"triggered_by":row.triggered_by,"actions":actions,
        "projections":projections,"still_applied_reroute_ids":still}),
        ),
    )
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
        WHERE id=? AND lifecycle_state IN ('active','recovery_scheduled') AND recovery_claim_token IS NULL")
        .bind(g.session.user_id).bind(id).execute(&mut *tx).await {
            Ok(result) => result.rows_affected(), Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR,"db_error")
        };
    if changed != 1 {
        return err(
            StatusCode::CONFLICT,
            "automatic recovery is absent, claimed, or already in flight",
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

#[cfg(test)]
mod tests {
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
}
