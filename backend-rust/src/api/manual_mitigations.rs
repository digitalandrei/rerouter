//! Immutable preview/confirmation boundary shared by manual mitigation entry
//! points. The token authorizes a durable snapshot, never a re-rendered request.
use anyhow::{ensure, Context};
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{err, AppState};
use crate::auth::rbac::{markers, RequirePermission};
use crate::auth::sessions::Session;
use crate::reroute::bundle::{self, BundleAction, BundleRun, FailurePolicy};
use crate::reroute::device_plan::{PreparedDeviceAction, PreparedEffect};
use crate::reroute::executor::ActorContext;
use crate::reroute::preparation::{self, ActionDraft};
use crate::reroute::{guard, templates};

pub(crate) type JsonResp = (StatusCode, Json<Value>);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RunSnapshot {
    pub actions: Vec<BundleAction>,
    pub device_actions: Vec<PreparedDeviceAction>,
    pub source: Value,
    pub reason: String,
    /// The immutable caller inputs used by compatibility endpoints to reject a
    /// token presented alongside a different request.
    pub request: Value,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewBody {
    #[serde(default)]
    pub preset_id: Option<u64>,
    #[serde(default)]
    pub preset_revision: Option<u64>,
    pub actions: Vec<ActionDraft>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyBody {
    pub plan_id: u64,
    pub preview_token: String,
}

pub async fn preview(
    g: RequirePermission<markers::TriggerManualReroute>,
    State(state): State<AppState>,
    Json(body): Json<PreviewBody>,
) -> JsonResp {
    preview_manual(&state, &g.session, body, "manual_mitigation").await
}

pub(crate) async fn preview_manual(
    state: &AppState,
    actor: &Session,
    body: PreviewBody,
    scope: &str,
) -> JsonResp {
    let reason = body
        .reason
        .as_deref()
        .unwrap_or("manual mitigation")
        .trim()
        .to_string();
    if reason.is_empty() || reason.chars().count() > 4000 {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "provide an audit reason of 1–4000 characters",
        );
    }
    let source = if let Some(id) = body.preset_id {
        let row: Option<(String, u64, Option<DateTime<Utc>>)> = match sqlx::query_as(
            "SELECT name, revision, archived_at FROM mitigation_presets WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&state.pool)
        .await
        {
            Ok(row) => row,
            Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
        };
        let Some((name, revision, None)) = row else {
            return err(StatusCode::CONFLICT, "template_missing_or_archived");
        };
        if Some(revision) != body.preset_revision {
            return err(
                StatusCode::CONFLICT,
                "template_changed; reload before previewing",
            );
        }
        let saved = match super::mitigation_presets::load_actions(&state.pool, id).await {
            Ok(saved) => saved,
            Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
        };
        if let Err(e) = preparation::validate_overrides(&saved, &body.actions) {
            return err(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string());
        }
        json!({"kind":"preset", "preset_id":id, "preset_revision":revision, "preset_name":name, "saved_actions":saved})
    } else {
        if body.preset_revision.is_some() {
            return err(
                StatusCode::UNPROCESSABLE_ENTITY,
                "preset_revision requires preset_id",
            );
        }
        json!({"kind":"manual", "name":"Run once"})
    };
    let validated = match preparation::validate_drafts(&state.pool, &body.actions, false).await {
        Ok(actions) => actions,
        Err(e) => return err(StatusCode::UNPROCESSABLE_ENTITY, &format!("{e:#}")),
    };
    let actions = validated
        .into_iter()
        .filter(|(_, a)| a.enabled)
        .enumerate()
        .map(|(position, (template, a))| BundleAction {
            device_id: a.device_id,
            template,
            params: a.params,
            reason: reason.clone(),
            position: position as u32,
            auto_target: None,
            auto_target_low_confidence: None,
            prepared: None,
            original_reroute_id: None,
        })
        .collect();
    let request = json!({"actions":body.actions,"preset_id":body.preset_id,"preset_revision":body.preset_revision,"reason":reason});
    preview_actions(
        state,
        actor,
        scope,
        body.preset_id,
        actions,
        source,
        reason,
        request,
    )
    .await
}

/// Populate concrete plans in order. No action is omitted if a later read fails.
pub(crate) async fn inspect_actions(
    pool: &sqlx::MySqlPool,
    actions: &mut [BundleAction],
) -> anyhow::Result<()> {
    preparation::inspect_actions(pool, actions, false).await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn preview_actions(
    state: &AppState,
    actor: &Session,
    scope: &str,
    scope_id: Option<u64>,
    mut actions: Vec<BundleAction>,
    mut source: Value,
    reason: String,
    request: Value,
) -> JsonResp {
    let clear_only =
        actions.is_empty() && source.get("kind").and_then(Value::as_str) == Some("rule_clear");
    if actions.is_empty() && !clear_only {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "no enabled actions to prepare",
        );
    }
    let enforce = super::settings::operating_mode(&state.pool, &state.config).await == "enforce";
    let _policy = if enforce {
        match guard::policy_fence(&state.pool).await {
            Ok(fence) => Some(fence),
            Err(e) => return err(StatusCode::CONFLICT, &format!("preview policy busy: {e}")),
        }
    } else {
        None
    };
    if enforce && actions.iter().any(|a| a.prepared.is_none()) {
        if let Err(e) = inspect_actions(&state.pool, &mut actions).await {
            return err(
                StatusCode::CONFLICT,
                &format!("complete mitigation preparation refused; nothing was executed: {e:#}"),
            );
        }
    }
    if enforce {
        let mut concrete: Vec<_> = actions.iter().filter_map(|a| a.prepared.clone()).collect();
        if actions.iter().any(|a| a.original_reroute_id.is_some()) {
            match crate::reroute::device_plan::prepare_inverse_sequence_read_only(
                &state.pool,
                &mut concrete,
            )
            .await
            {
                Ok(()) => {}
                Err(e) => {
                    return err(
                        StatusCode::CONFLICT,
                        &format!("inverse preconditions could not be proved: {e:#}"),
                    )
                }
            }
            for (action, plan) in actions.iter_mut().zip(concrete) {
                action.prepared = Some(plan);
            }
        }
        let ids: Vec<_> = actions.iter().map(|a| a.device_id).collect();
        match crate::ssh::RusshExecutor::new(state.pool.clone())
            .transport_identities(&ids)
            .await
        {
            Ok(identities) => source["transport_identities"] = json!(identities),
            Err(e) => {
                return err(
                    StatusCode::CONFLICT,
                    &format!("router identity could not be pinned: {e:#}"),
                )
            }
        }
    }
    let mut results = Vec::with_capacity(actions.len());
    for action in &actions {
        let name: Option<String> = sqlx::query_scalar("SELECT name FROM devices WHERE id = ?")
            .bind(action.device_id)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);
        let mut plan = match templates::render(&action.template, &action.params) {
            Ok(plan) => plan,
            Err(e) => {
                return err(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    &format!("action {}: {e:#}", action.position + 1),
                )
            }
        };
        let (inverse, before, after, effect) = if let Some(prepared) = &action.prepared {
            plan.commands = prepared.commands.clone();
            plan.sequence_pending = false;
            // Legacy template substrings may describe the opposite direction
            // of a persisted inverse. Display the typed proof actually required.
            plan.verify = None;
            (
                prepared
                    .inverse
                    .as_ref()
                    .map(|i| json!({"commands":i.commands,"verify":null,"sequence_pending":false})),
                json!(prepared.before),
                json!(prepared.after),
                if prepared.effect == PreparedEffect::AlreadySatisfied {
                    "noop"
                } else {
                    "pending"
                },
            )
        } else {
            (None, Value::Null, Value::Null, "pending")
        };
        results.push(json!({
            "executed":false, "reroute_id":null, "state":null, "device_id":action.device_id, "device_name":name,
            "message":if enforce {"Prepared; confirmation required"} else {"Observe mode: nothing will execute"},
            "would_run":plan, "would_run_rollback":inverse, "before_state":before, "after_state":after,
            "mutation_effect":effect, "predicted_noop":effect=="noop", "bundle_position":action.position,
            "verification_states":action.prepared.as_ref().map(|p| &p.verify),
            "template_name":action.template.name, "template_display_name":action.template.display_name,
            "auto_target":action.auto_target, "auto_target_low_confidence":action.auto_target_low_confidence,
        }));
    }
    if !enforce && !clear_only {
        return (
            StatusCode::OK,
            Json(
                json!({"plan_id":null,"preview_token":null,"results":results,"source":source,"operating_mode":"observe"}),
            ),
        );
    }
    let snapshot = RunSnapshot {
        device_actions: actions.iter().filter_map(|a| a.prepared.clone()).collect(),
        actions,
        source: source.clone(),
        reason: reason.clone(),
        request,
    };
    let snapshot_json = match serde_json::to_value(&snapshot) {
        Ok(value) => value,
        Err(_) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "preview_serialization_failed",
            )
        }
    };
    let plan_hash = hash_snapshot(&snapshot_json);
    let token = crate::auth::sessions::generate_token();
    let token_hash = crate::auth::sessions::hash_token(&token);
    let result = sqlx::query("INSERT INTO execution_plans (user_id, scope, scope_id, reason, snapshot_json, plan_hash, token_hash, expires_at) \
        VALUES (?, ?, ?, ?, ?, ?, ?, DATE_ADD(UTC_TIMESTAMP(), INTERVAL 5 MINUTE))")
        .bind(actor.user_id).bind(scope).bind(scope_id).bind(reason).bind(sqlx::types::Json(snapshot_json))
        .bind(plan_hash).bind(token_hash).execute(&state.pool).await;
    match result {
        Ok(row) => (
            StatusCode::OK,
            Json(
                json!({"plan_id":row.last_insert_id(),"preview_token":token,"results":results,
            "source":source,"expires_at":Utc::now()+chrono::Duration::minutes(5),"operating_mode":if enforce {"enforce"} else {"observe"}}),
            ),
        ),
        Err(e) => {
            tracing::error!(event_type="mitigation_preview_store_failed",error=%e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "preview_store_failed")
        }
    }
}

pub(crate) fn hash_snapshot(value: &Value) -> String {
    hex::encode(Sha256::digest(value.to_string().as_bytes()))
}

pub(crate) struct AcceptedPlan {
    pub bundle_id: u64,
    pub plan_id: u64,
    pub snapshot: RunSnapshot,
    pub already_accepted: bool,
}

#[derive(sqlx::FromRow)]
struct PlanRow {
    user_id: u64,
    scope: String,
    scope_id: Option<u64>,
    snapshot_json: sqlx::types::Json<Value>,
    plan_hash: String,
    token_hash: String,
    expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
    bundle_id: Option<u64>,
}

pub(crate) async fn accept_plan(
    state: &AppState,
    actor: &Session,
    plan_id: u64,
    token: &str,
    scope: &str,
    scope_id: Option<u64>,
) -> anyhow::Result<AcceptedPlan> {
    let _policy_fence = guard::policy_fence(&state.pool).await?;
    let mut tx = state.pool.begin().await?;
    let row = sqlx::query_as::<_, PlanRow>(
        "SELECT user_id, scope, scope_id, snapshot_json, plan_hash, token_hash, expires_at, consumed_at, bundle_id \
         FROM execution_plans WHERE id = ? FOR UPDATE",
    ).bind(plan_id).fetch_optional(&mut *tx).await?.context("preview not found")?;
    ensure!(
        row.user_id == actor.user_id
            && row.scope == scope
            && row.scope_id == scope_id
            && row.token_hash == crate::auth::sessions::hash_token(token),
        "preview_actor_or_scope_mismatch"
    );
    ensure!(
        row.plan_hash == hash_snapshot(&row.snapshot_json.0),
        "stored preview integrity check failed"
    );
    let snapshot: RunSnapshot = serde_json::from_value(row.snapshot_json.0)?;
    let source_kind = snapshot.source.get("kind").and_then(Value::as_str);
    let source_id = match (scope, source_kind) {
        ("manual_mitigation", Some("preset")) => {
            snapshot.source.get("preset_id").and_then(Value::as_u64)
        }
        ("manual_mitigation" | "legacy_manual", Some("manual")) => None,
        ("rule_apply", Some("rule")) | ("rule_clear", Some("rule_clear")) => {
            snapshot.source.get("rule_id").and_then(Value::as_u64)
        }
        ("reroute_rollback", Some("rollback")) => snapshot
            .source
            .get("original_reroute_id")
            .and_then(Value::as_u64),
        _ => anyhow::bail!("preview source does not match its authorization scope"),
    };
    ensure!(
        source_id == row.scope_id && (source_kind == Some("manual") || source_id.is_some()),
        "preview source identity does not match its authorization scope"
    );
    if row.consumed_at.is_some() {
        let bundle_id = row
            .bundle_id
            .context("consumed preview has no execution; reconcile before retrying")?;
        return Ok(AcceptedPlan {
            bundle_id,
            plan_id,
            snapshot,
            already_accepted: true,
        });
    }
    ensure!(
        row.expires_at > Utc::now(),
        "preview_expired; prepare a fresh preview"
    );
    // This read is inside the admission transaction; the executor repeats it at
    // the actual write boundary under its safety serialization.
    let mode: Option<String> = sqlx::query_scalar(
        "SELECT `value` FROM system_settings WHERE `key` = 'operating_mode' FOR UPDATE",
    )
    .fetch_optional(&mut *tx)
    .await?;
    ensure!(
        mode.as_deref() == Some("enforce")
            || (snapshot.actions.is_empty() && snapshot.source["kind"] == "rule_clear"),
        "observe mode: execution refused"
    );
    if let Some(preset_id) = snapshot.source.get("preset_id").and_then(Value::as_u64) {
        let source: Option<(u64, Option<DateTime<Utc>>)> = sqlx::query_as(
            "SELECT revision, archived_at FROM mitigation_presets WHERE id = ? FOR UPDATE",
        )
        .bind(preset_id)
        .fetch_optional(&mut *tx)
        .await?;
        ensure!(
            matches!(source, Some((revision, None)) if Some(revision) == snapshot.source.get("preset_revision").and_then(Value::as_u64)),
            "template_changed_or_archived; prepare a fresh preview"
        );
    }
    let rule_id = snapshot.source.get("rule_id").and_then(Value::as_u64);
    if snapshot.source.get("kind").and_then(Value::as_str) == Some("rule") {
        let rule: Option<(bool, u64, Option<String>)> = sqlx::query_as(
            "SELECT r.manual_apply_enabled, r.actions_revision, rs.current_state \
            FROM rules r LEFT JOIN rule_states rs ON rs.rule_id = r.id WHERE r.id = ? FOR UPDATE",
        )
        .bind(rule_id)
        .fetch_optional(&mut *tx)
        .await?;
        ensure!(
            matches!(rule, Some((true, revision, Some(ref current))) if current=="firing" && Some(revision)==snapshot.source.get("actions_revision").and_then(Value::as_u64)),
            "rule_changed; prepare a fresh preview"
        );
    }
    ensure!(
        snapshot.actions.len() == snapshot.device_actions.len()
            && (!snapshot.actions.is_empty() || snapshot.source["kind"] == "rule_clear"),
        "incomplete execution snapshot"
    );
    for (action, prepared) in snapshot.actions.iter().zip(&snapshot.device_actions) {
        let owned = action
            .prepared
            .as_ref()
            .context("missing concrete device action")?;
        owned.validate()?;
        ensure!(
            owned == prepared,
            "execution snapshot order or prepared action changed"
        );
    }
    let row = sqlx::query("INSERT INTO reroute_bundles (rule_id, trigger_type, triggered_by_user_id, reason, state, failure_policy, total_actions, source_json) \
        VALUES (?, 'manual', ?, ?, 'planned', 'abort_and_compensate', ?, ?)")
        .bind(rule_id).bind(actor.user_id).bind(&snapshot.reason).bind(snapshot.actions.len() as u32)
        .bind(sqlx::types::Json(&snapshot.source)).execute(&mut *tx).await?;
    let bundle_id = row.last_insert_id();
    sqlx::query("UPDATE execution_plans SET consumed_at = UTC_TIMESTAMP(), bundle_id = ? WHERE id = ? AND consumed_at IS NULL")
        .bind(bundle_id).bind(plan_id).execute(&mut *tx).await?;
    super::audit_mutation_on(
        &mut tx,
        actor,
        "mitigation_plan_authorized",
        "reroute_bundle",
        bundle_id,
        &format!("authorized immutable plan #{plan_id}: {}", snapshot.reason),
    )
    .await?;
    tx.commit().await?;
    // The complete snapshot is already durable in execution_plans. Materialize
    // the per-action ledger before admission or asynchronous work can start.
    let admitted = async {
        if snapshot.actions.is_empty() {
            return Ok(());
        }
        bundle::persist_actions(&state.pool, bundle_id, &snapshot.actions).await?;
        if snapshot
            .actions
            .iter()
            .any(|action| action.original_reroute_id.is_none())
        {
            guard::admit_bundle(
                &state.pool,
                &state.config,
                bundle_id,
                snapshot.actions.len() as u32,
            )
            .await
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    if let Err(error) = admitted {
        sqlx::query("UPDATE reroute_bundles SET state = 'failed', finished_at = UTC_TIMESTAMP(), failure_reason = ? WHERE id = ? AND state = 'planned'")
            .bind(format!("admission refused before any router write: {error:#}")).bind(bundle_id).execute(&state.pool).await?;
        return Err(error.context(format!(
            "bundle #{bundle_id} was not admitted; no router command was sent"
        )));
    }
    Ok(AcceptedPlan {
        bundle_id,
        plan_id,
        snapshot,
        already_accepted: false,
    })
}

pub(crate) fn spawn_accepted(state: &AppState, actor: &Session, accepted: AcceptedPlan) {
    if accepted.already_accepted {
        return;
    }
    let pool = state.pool.clone();
    let cfg = state.config.clone();
    let run = run_context(actor, &accepted);
    tokio::spawn(async move {
        bundle::run(&pool, &cfg, run, accepted.snapshot.actions).await;
    });
}

pub(crate) fn run_context(actor: &Session, accepted: &AcceptedPlan) -> BundleRun {
    let actor_context = ActorContext {
        ip_address: actor.ip_address.clone(),
        user_agent: actor.user_agent.clone(),
    };
    let run = if accepted
        .snapshot
        .actions
        .iter()
        .all(|a| a.original_reroute_id.is_some())
    {
        BundleRun::rollback(
            accepted.bundle_id,
            FailurePolicy::AbortAndCompensate,
            actor.user_id,
            actor_context,
        )
    } else {
        BundleRun::manual(
            accepted.bundle_id,
            FailurePolicy::AbortAndCompensate,
            accepted
                .snapshot
                .source
                .get("rule_id")
                .and_then(Value::as_u64),
            actor.user_id,
            actor_context,
        )
    };
    run.with_authorization(Some(accepted.plan_id), format!("plan:{}", accepted.plan_id))
}

pub async fn apply(
    g: RequirePermission<markers::TriggerManualReroute>,
    State(state): State<AppState>,
    Json(body): Json<ApplyBody>,
) -> JsonResp {
    // The source preset id is part of the stored preview, never caller-selected
    // at confirmation. Scope and actor still have to match.
    let scope_id = match sqlx::query_scalar::<_, Option<u64>>("SELECT scope_id FROM execution_plans WHERE id = ? AND user_id = ? AND scope = 'manual_mitigation'")
        .bind(body.plan_id).bind(g.session.user_id).fetch_optional(&state.pool).await {
        Ok(Some(id)) => id, _ => return err(StatusCode::CONFLICT, "preview not found"),
    };
    match accept_plan(
        &state,
        &g.session,
        body.plan_id,
        &body.preview_token,
        "manual_mitigation",
        scope_id,
    )
    .await
    {
        Ok(accepted) => {
            let id = accepted.bundle_id;
            spawn_accepted(&state, &g.session, accepted);
            (
                StatusCode::ACCEPTED,
                Json(json!({"bundle_id":id,"async":true})),
            )
        }
        Err(e) => err(StatusCode::CONFLICT, &format!("{e:#}")),
    }
}

pub(crate) async fn plan_for_token(
    pool: &sqlx::MySqlPool,
    actor: u64,
    token: &str,
    scope: &str,
    scope_id: Option<u64>,
) -> anyhow::Result<(u64, RunSnapshot)> {
    let row: Option<(u64, sqlx::types::Json<Value>)> = sqlx::query_as(
        "SELECT id, snapshot_json FROM execution_plans WHERE user_id = ? AND token_hash = ? AND scope = ? AND scope_id <=> ?",
    ).bind(actor).bind(crate::auth::sessions::hash_token(token)).bind(scope).bind(scope_id).fetch_optional(pool).await?;
    let (id, snapshot) = row.context("preview_required_or_changed")?;
    Ok((id, serde_json::from_value(snapshot.0)?))
}
