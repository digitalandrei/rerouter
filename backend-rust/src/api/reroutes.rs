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

type JsonResp = (StatusCode, Json<Value>);

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
    let request =
        json!({"actions":actions,"preset_id":null,"preset_revision":null,"reason":reason});
    if body.dry_run
        || crate::api::settings::operating_mode(&state.pool, &state.config).await != "enforce"
    {
        return manual::preview_manual(
            &state,
            &g.session,
            manual::PreviewBody {
                preset_id: None,
                preset_revision: None,
                actions,
                reason: Some(reason),
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
    let enforce =
        crate::api::settings::operating_mode(&state.pool, &state.config).await == "enforce";
    if body.dry_run || !enforce {
        let actions = match crate::reroute::preparation::prepare_rollbacks(
            &state.pool,
            &[id],
            &reason,
            enforce,
        )
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
pub async fn bundle_list(
    _g: RequirePermission<markers::ViewAsset>,
    State(state): State<AppState>,
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
    }
    match sqlx::query_as::<_,Row>("SELECT b.id,b.rule_id,b.trigger_type,b.state,b.reason,b.total_actions,b.completed_actions, \
        b.failure_reason,b.started_at,b.finished_at,b.created_at,b.source_json,u.email AS triggered_by \
        FROM reroute_bundles b LEFT JOIN users u ON u.id=b.triggered_by_user_id ORDER BY b.id DESC LIMIT 200")
        .fetch_all(&state.pool).await {
        Ok(rows)=>(StatusCode::OK,Json(json!(rows.into_iter().map(|r|json!({
            "id":r.id,"rule_id":r.rule_id,"trigger_type":r.trigger_type,"state":r.state,"reason":r.reason,
            "total_actions":r.total_actions,"completed_actions":r.completed_actions,"failure_reason":r.failure_reason,
            "started_at":r.started_at,"finished_at":r.finished_at,"created_at":r.created_at,
            "source":r.source_json.map(|s|s.0),"triggered_by":r.triggered_by,
        })).collect::<Vec<_>>()))),
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
    }
    let row=match sqlx::query_as::<_,BundleRow>("SELECT b.rule_id,b.trigger_type,b.state,b.failure_policy,b.total_actions,b.completed_actions, \
        b.failure_reason,b.started_at,b.finished_at,b.source_json,b.triggered_by_user_id,u.email AS triggered_by \
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
    }
    let rows=sqlx::query_as::<_,ActionRow>("SELECT a.reroute_id,a.position,a.device_id,d.name AS device_name, \
        COALESCE(r.state,a.state) AS state, COALESCE(r.mutation_effect,a.mutation_effect) AS mutation_effect, \
        COALESCE(r.failure_reason,a.failure_reason) AS failure_reason, a.template_snapshot_json, \
        a.canonical_params_json AS params, COALESCE(r.rollback_of_reroute_id,a.original_reroute_id) AS original_reroute_id \
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
            r.rollback_of_reroute_id AS original_reroute_id FROM reroutes r LEFT JOIN devices d ON d.id=r.device_id \
            WHERE r.bundle_id=? ORDER BY r.bundle_position,r.id")
            .bind(id).fetch_all(&state.pool).await {Ok(rows)=>rows,Err(_)=>return err(StatusCode::INTERNAL_SERVER_ERROR,"could not load legacy action history")};
    }
    let terminal = !matches!(row.state.as_str(), "planned" | "running" | "compensating");
    let actions:Vec<_>=rows.into_iter().map(|a| {
        let template=a.template_snapshot_json.map(|v|v.0).unwrap_or(Value::Null);
        json!({"reroute_id":a.reroute_id,"position":a.position,"device_id":a.device_id,"device_name":a.device_name,
            "state":if terminal && a.state=="queued" {"not_run"} else {&a.state},"mutation_effect":a.mutation_effect,
            "failure_reason":a.failure_reason,"template_name":template["name"],"template_display_name":template["display_name"],
            "params":a.params.map(|v|v.0),"original_reroute_id":a.original_reroute_id})
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
        "triggered_by_user_id":row.triggered_by_user_id,"triggered_by":row.triggered_by,"actions":actions,"still_applied_reroute_ids":still}),
        ),
    )
}
