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
use crate::reroute::device_plan::{PreparedDeviceAction, PreparedEffect, VerificationMode};
use crate::reroute::executor::ActorContext;
use crate::reroute::preparation::{self, ActionDraft};
use crate::reroute::{guard, templates};

pub(crate) type JsonResp = (StatusCode, Json<Value>);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RunSnapshot {
    #[serde(default)]
    pub verification_mode: VerificationMode,
    pub actions: Vec<BundleAction>,
    pub device_actions: Vec<PreparedDeviceAction>,
    pub source: Value,
    pub reason: String,
    /// The immutable caller inputs used by compatibility endpoints to reject a
    /// token presented alongside a different request.
    pub request: Value,
    #[serde(default)]
    pub revert_after_seconds: Option<u32>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewBody {
    #[serde(default)]
    pub verification_mode: VerificationMode,
    #[serde(default)]
    pub preset_id: Option<u64>,
    #[serde(default)]
    pub preset_revision: Option<u64>,
    pub actions: Vec<ActionDraft>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub revert_after_seconds: Option<u32>,
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

pub async fn capabilities(
    _g: RequirePermission<markers::ViewAsset>,
    State(state): State<AppState>,
) -> JsonResp {
    match eligible_configuration_test_device_ids(&state).await {
        Ok(ids) => (
            StatusCode::OK,
            Json(json!({
                "configuration_test_device_ids": ids,
                "configuration_test_templates": ["bgp_export_policy_set", "iface_tcp_adjust_mss"]
            })),
        ),
        Err(e) => err(
            StatusCode::SERVICE_UNAVAILABLE,
            &format!("configuration-test capabilities unavailable: {e:#}"),
        ),
    }
}

async fn eligible_configuration_test_device_ids(state: &AppState) -> anyhow::Result<Vec<u64>> {
    let ids = state
        .config
        .safety
        .configuration_test_devices
        .iter()
        .map(|d| d.device_id)
        .collect::<Vec<_>>();
    let current = crate::ssh::RusshExecutor::new(state.pool.clone())
        .transport_identities(&ids)
        .await?;
    Ok(state
        .config
        .safety
        .configuration_test_devices
        .iter()
        .filter(|expected| {
            current.get(&expected.device_id).is_some_and(|actual| {
                actual.host == expected.host
                    && actual.port == expected.port
                    && actual.pinned_host_fingerprint == expected.pinned_host_fingerprint
            })
        })
        .map(|d| d.device_id)
        .collect())
}

async fn validate_configuration_only_scope(
    state: &AppState,
    actions: &[BundleAction],
) -> anyhow::Result<()> {
    ensure!(
        !actions.is_empty(),
        "configuration-only verification needs enabled actions"
    );
    let device_id = actions[0].device_id;
    ensure!(
        actions.iter().all(|a| a.device_id == device_id),
        "configuration-only verification requires one designated lab device"
    );
    ensure!(
        actions.iter().all(|a| {
            matches!(
                a.template.name.as_str(),
                "bgp_export_policy_set" | "iface_tcp_adjust_mss"
            ) || (a.original_reroute_id.is_some()
                && a.prepared.as_ref().is_some_and(|prepared| {
                    prepared.verification_mode == VerificationMode::ConfigurationOnly
                }))
        }),
        "configuration-only verification supports only bgp_export_policy_set and iface_tcp_adjust_mss"
    );
    ensure!(
        eligible_configuration_test_device_ids(state)
            .await?
            .contains(&device_id),
        "lab device transport identity is not currently designated"
    );
    Ok(())
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
    if body
        .revert_after_seconds
        .is_some_and(|seconds| !(60..=604_800).contains(&seconds))
    {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "revert_after_seconds must be null or 60–604800",
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
    let actions: Vec<BundleAction> = validated
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
    if body.verification_mode == VerificationMode::ConfigurationOnly {
        if body.revert_after_seconds.is_some() {
            return err(
                StatusCode::UNPROCESSABLE_ENTITY,
                "configuration-only verification does not allow timed reverts",
            );
        }
        if let Err(e) = validate_configuration_only_scope(state, &actions).await {
            return err(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string());
        }
        let device_id = actions[0].device_id;
        let lab_limit = state
            .config
            .safety
            .configuration_test_devices
            .iter()
            .find(|device| device.device_id == device_id)
            .map(|device| device.action_rate_limit_count)
            .unwrap_or(0);
        if actions.len() as u32 > lab_limit {
            return err(
                StatusCode::UNPROCESSABLE_ENTITY,
                &format!(
                    "configuration-only action set has {} actions; lab limit is {}",
                    actions.len(),
                    lab_limit
                ),
            );
        }
    }
    let request = json!({"actions":body.actions,"preset_id":body.preset_id,"preset_revision":body.preset_revision,"reason":reason,"revert_after_seconds":body.revert_after_seconds,"verification_mode":body.verification_mode});
    preview_actions_mode(
        state,
        actor,
        scope,
        body.preset_id,
        actions,
        source,
        reason,
        request,
        body.revert_after_seconds,
        body.verification_mode,
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
    actions: Vec<BundleAction>,
    source: Value,
    reason: String,
    request: Value,
    revert_after_seconds: Option<u32>,
) -> JsonResp {
    preview_actions_mode(
        state,
        actor,
        scope,
        scope_id,
        actions,
        source,
        reason,
        request,
        revert_after_seconds,
        VerificationMode::Routing,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn preview_actions_mode(
    state: &AppState,
    actor: &Session,
    scope: &str,
    scope_id: Option<u64>,
    actions: Vec<BundleAction>,
    source: Value,
    reason: String,
    request: Value,
    revert_after_seconds: Option<u32>,
    verification_mode: VerificationMode,
) -> JsonResp {
    preview_actions_core(
        state,
        actor,
        scope,
        scope_id,
        actions,
        source,
        reason,
        request,
        revert_after_seconds,
        false,
        verification_mode,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn preview_actions_core(
    state: &AppState,
    actor: &Session,
    scope: &str,
    scope_id: Option<u64>,
    mut actions: Vec<BundleAction>,
    mut source: Value,
    reason: String,
    request: Value,
    revert_after_seconds: Option<u32>,
    inverse_already_inspected: bool,
    mut verification_mode: VerificationMode,
) -> JsonResp {
    let clear_only =
        actions.is_empty() && source.get("kind").and_then(Value::as_str) == Some("rule_clear");
    if actions.is_empty() && !clear_only {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "no enabled actions to prepare",
        );
    }
    let inherited_configuration_only = actions
        .iter()
        .filter_map(|a| a.prepared.as_ref())
        .any(|p| p.verification_mode == VerificationMode::ConfigurationOnly);
    if inherited_configuration_only {
        if actions
            .iter()
            .filter_map(|a| a.prepared.as_ref())
            .any(|p| p.verification_mode != VerificationMode::ConfigurationOnly)
        {
            return err(
                StatusCode::CONFLICT,
                "mixed verification scopes are not executable",
            );
        }
        verification_mode = VerificationMode::ConfigurationOnly;
    }
    if verification_mode == VerificationMode::ConfigurationOnly {
        if !matches!(
            scope,
            "manual_mitigation" | "bundle_revert" | "reroute_rollback"
        ) || revert_after_seconds.is_some()
        {
            return err(
                StatusCode::UNPROCESSABLE_ENTITY,
                "configuration-only verification is manual and cannot use timed recovery",
            );
        }
        if let Err(e) = validate_configuration_only_scope(state, &actions).await {
            return err(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string());
        }
        source["verification_mode"] = json!(verification_mode);
        source["routing_verified"] = json!(false);
        source["verification_label"] =
            json!("Configuration-only test; routing will not be verified");
    }
    let enforce = super::settings::operating_mode(&state.pool, &state.config).await == "enforce";
    let _policy = match guard::policy_fence(&state.pool).await {
        Ok(fence) => Some(fence),
        Err(e) => return err(StatusCode::CONFLICT, &format!("preview policy busy: {e}")),
    };
    if actions.iter().any(|a| a.prepared.is_none()) {
        let inspected = if verification_mode == VerificationMode::ConfigurationOnly {
            preparation::inspect_actions_for_mode(&state.pool, &mut actions, verification_mode)
                .await
        } else {
            inspect_actions(&state.pool, &mut actions).await
        };
        if let Err(e) = inspected {
            return err(
                StatusCode::CONFLICT,
                &format!("complete mitigation preparation refused; nothing was executed: {e:#}"),
            );
        }
    }
    {
        let mut concrete: Vec<_> = actions.iter().filter_map(|a| a.prepared.clone()).collect();
        if !inverse_already_inspected && actions.iter().any(|a| a.original_reroute_id.is_some()) {
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
    let projections = match crate::reroute::projection::project_action_set(
        &actions
            .iter()
            .filter_map(|action| action.prepared.clone())
            .collect::<Vec<_>>(),
    ) {
        Ok(value) => value,
        Err(e) => {
            return err(
                StatusCode::CONFLICT,
                &format!("complete projection refused: {e:#}"),
            )
        }
    };
    for action in &actions {
        let name: Option<String> = sqlx::query_scalar("SELECT name FROM devices WHERE id = ?")
            .bind(action.device_id)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);
        let mut plan = if let Some(prepared) = &action.prepared {
            crate::reroute::templates::RenderedPlan {
                template_id: prepared.template_id,
                template_name: prepared.template_name.clone(),
                config_mode: false,
                commands: prepared.commands.clone(),
                verify: None,
                sequence_pending: false,
            }
        } else {
            match templates::render(&action.template, &action.params) {
                Ok(plan) => plan,
                Err(e) => {
                    return err(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        &format!("action {}: {e:#}", action.position + 1),
                    )
                }
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
            "message":"Prepared; explicit confirmation required",
            "would_run":plan, "would_run_rollback":inverse, "before_state":before, "after_state":after,
            "mutation_effect":effect, "predicted_noop":effect=="noop", "bundle_position":action.position,
            "verification_states":action.prepared.as_ref().map(|p| &p.verify),
            "template_name":action.template.name, "template_display_name":action.template.display_name,
            "auto_target":action.auto_target, "auto_target_low_confidence":action.auto_target_low_confidence,
        }));
    }
    let snapshot = RunSnapshot {
        verification_mode,
        device_actions: actions.iter().filter_map(|a| a.prepared.clone()).collect(),
        actions,
        source: source.clone(),
        reason: reason.clone(),
        request,
        revert_after_seconds,
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
                json!({"plan_id":row.last_insert_id(),"preview_token":token,"results":results,"projections":projections,"revert_after_seconds":revert_after_seconds,
            "verification_mode":verification_mode,"routing_verified":if verification_mode == VerificationMode::ConfigurationOnly {Some(false)} else {None},
            "verification_label":if verification_mode == VerificationMode::ConfigurationOnly {Some("Configuration-only test; routing will not be verified")} else {None},
            "source":source,"expires_at":Utc::now()+chrono::Duration::minutes(5),"operating_mode":if enforce {"enforce"} else {"observe"}}),
            ),
        ),
        Err(e) => {
            tracing::error!(event_type="mitigation_preview_store_failed",error=%e);
            err(StatusCode::INTERNAL_SERVER_ERROR, "preview_store_failed")
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn preview_actions_with_reader<R: crate::reroute::device_plan::PreparationReader>(
    state: &AppState,
    actor: &Session,
    scope: &str,
    scope_id: Option<u64>,
    actions: Vec<BundleAction>,
    source: Value,
    reason: String,
    request: Value,
    revert_after_seconds: Option<u32>,
    reader: &R,
) -> JsonResp {
    preview_actions_with_reader_mode(
        state,
        actor,
        scope,
        scope_id,
        actions,
        source,
        reason,
        request,
        revert_after_seconds,
        reader,
        VerificationMode::Routing,
    )
    .await
}

#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub async fn preview_actions_with_reader_mode<R: crate::reroute::device_plan::PreparationReader>(
    state: &AppState,
    actor: &Session,
    scope: &str,
    scope_id: Option<u64>,
    mut actions: Vec<BundleAction>,
    source: Value,
    reason: String,
    request: Value,
    revert_after_seconds: Option<u32>,
    reader: &R,
    verification_mode: VerificationMode,
) -> JsonResp {
    if actions.iter().any(|a| a.prepared.is_none())
        && !actions.iter().any(|a| a.original_reroute_id.is_some())
    {
        if let Err(e) = if verification_mode == VerificationMode::ConfigurationOnly {
            preparation::inspect_actions_with_reader_for_mode(
                &state.pool,
                &mut actions,
                false,
                reader,
                verification_mode,
            )
            .await
        } else {
            preparation::inspect_actions_with_reader(&state.pool, &mut actions, false, reader).await
        } {
            return err(
                StatusCode::CONFLICT,
                &format!("complete mitigation preparation refused; nothing was executed: {e:#}"),
            );
        }
    }
    if actions.iter().any(|a| a.original_reroute_id.is_some()) {
        let mut concrete = actions
            .iter()
            .filter_map(|a| a.prepared.clone())
            .collect::<Vec<_>>();
        if let Err(e) = crate::reroute::device_plan::prepare_inverse_sequence_read_only_with_reader(
            reader,
            &mut concrete,
        )
        .await
        {
            return err(
                StatusCode::CONFLICT,
                &format!("inverse preconditions could not be proved: {e:#}"),
            );
        }
        for (action, plan) in actions.iter_mut().zip(concrete) {
            action.prepared = Some(plan);
        }
    }
    preview_actions_core(
        state,
        actor,
        scope,
        scope_id,
        actions,
        source,
        reason,
        request,
        revert_after_seconds,
        true,
        verification_mode,
    )
    .await
}

pub(crate) fn hash_snapshot(value: &Value) -> String {
    hex::encode(Sha256::digest(value.to_string().as_bytes()))
}

#[doc(hidden)]
pub struct AcceptedPlan {
    pub bundle_id: u64,
    pub plan_id: u64,
    pub(crate) snapshot: RunSnapshot,
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

#[doc(hidden)]
pub async fn accept_plan(
    state: &AppState,
    actor: &Session,
    plan_id: u64,
    token: &str,
    scope: &str,
    scope_id: Option<u64>,
) -> anyhow::Result<AcceptedPlan> {
    accept_plan_inner(state, actor, plan_id, token, scope, scope_id, false).await
}

#[doc(hidden)]
pub async fn accept_plan_with_persist_failure_for_test(
    state: &AppState,
    actor: &Session,
    plan_id: u64,
    token: &str,
    scope: &str,
    scope_id: Option<u64>,
) -> anyhow::Result<AcceptedPlan> {
    accept_plan_inner(state, actor, plan_id, token, scope, scope_id, true).await
}

async fn accept_plan_inner(
    state: &AppState,
    actor: &Session,
    plan_id: u64,
    token: &str,
    scope: &str,
    scope_id: Option<u64>,
    force_persist_failure: bool,
) -> anyhow::Result<AcceptedPlan> {
    let policy_fence = guard::policy_fence(&state.pool).await?;
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
    if snapshot.verification_mode == VerificationMode::ConfigurationOnly {
        ensure!(
            matches!(
                scope,
                "manual_mitigation" | "bundle_revert" | "reroute_rollback"
            ),
            "configuration-only scope cannot be automatic or rule-driven"
        );
        ensure!(
            snapshot.revert_after_seconds.is_none(),
            "configuration-only scope cannot schedule a timed revert"
        );
        validate_configuration_only_scope(state, &snapshot.actions).await?;
    }
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
        ("bundle_revert", Some("bundle_revert")) => snapshot
            .source
            .get("original_bundle_id")
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
        let accepted = AcceptedPlan {
            bundle_id,
            plan_id,
            snapshot,
            already_accepted: true,
        };
        policy_fence.release().await?;
        return Ok(accepted);
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
    let _mode = mode;
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
    if scope == "bundle_revert" {
        let original_bundle_id = row.scope_id.context("bundle revert has no source run")?;
        let expected = snapshot
            .source
            .get("original_reroute_ids")
            .and_then(Value::as_array)
            .context("bundle revert snapshot has no original set")?
            .iter()
            .filter_map(Value::as_u64)
            .collect::<Vec<_>>();
        let current =
            crate::reroute::recovery::owned_original_ids(&state.pool, original_bundle_id).await?;
        ensure!(
            current == expected,
            "run ownership changed; prepare a fresh whole-run revert preview"
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
    ensure!(
        snapshot
            .device_actions
            .iter()
            .all(|prepared| prepared.verification_mode == snapshot.verification_mode)
            && snapshot.actions.iter().all(|action| action
                .prepared
                .as_ref()
                .is_some_and(|prepared| prepared.verification_mode == snapshot.verification_mode)),
        "execution snapshot contains a missing or mixed verification scope"
    );
    for (action, prepared) in snapshot.actions.iter().zip(&snapshot.device_actions) {
        let owned = action
            .prepared
            .as_ref()
            .context("missing concrete device action")?;
        owned.validate()?;
        ensure!(
            action.device_id == owned.device_id && action.template.id == owned.template_id,
            "prepared action identity does not match its bundle action"
        );
        ensure!(
            owned == prepared,
            "execution snapshot order or prepared action changed"
        );
    }
    let parent_bundle_id = if scope == "bundle_revert" {
        row.scope_id
    } else {
        None
    };
    if let Some(parent_id) = parent_bundle_id {
        let claimed=sqlx::query("UPDATE reroute_bundles SET recovery_claim_token=?,recovery_claimed_at=UTC_TIMESTAMP(),lifecycle_state='recovery_claimed' \
            WHERE id=? AND recovery_claim_token IS NULL AND lifecycle_state NOT IN ('recovery_claimed','recovery_running')")
            .bind(format!("manual:plan:{plan_id}")).bind(parent_id).execute(&mut *tx).await?;
        ensure!(
            claimed.rows_affected() == 1,
            "run recovery was already claimed or started"
        );
    }
    let row = sqlx::query("INSERT INTO reroute_bundles (parent_bundle_id, rule_id, trigger_type, triggered_by_user_id, reason, state, failure_policy, total_actions, source_json) \
        VALUES (?, ?, 'manual', ?, ?, 'planned', 'abort_and_compensate', ?, ?)")
        .bind(parent_bundle_id)
        .bind(rule_id).bind(actor.user_id).bind(&snapshot.reason).bind(snapshot.actions.len() as u32)
        .bind(sqlx::types::Json(&snapshot.source)).execute(&mut *tx).await?;
    let bundle_id = row.last_insert_id();
    if let Some(seconds) = snapshot.revert_after_seconds {
        sqlx::query("UPDATE reroute_bundles SET source_json = JSON_SET(COALESCE(source_json, JSON_OBJECT()), '$.revert_after_seconds', ?) WHERE id = ?")
            .bind(seconds).bind(bundle_id).execute(&mut *tx).await?;
    }
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
        if force_persist_failure {
            anyhow::bail!("injected action-ledger persistence failure")
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
        if let Some(parent_id) = parent_bundle_id {
            crate::reroute::recovery::release_claim_if_proven_no_write(
                &state.pool,
                parent_id,
                Some(bundle_id),
                &format!("admission refused: {error:#}"),
            )
            .await?;
        }
        return Err(error.context(format!(
            "bundle #{bundle_id} was not admitted; no router command was sent"
        )));
    }
    let accepted = AcceptedPlan {
        bundle_id,
        plan_id,
        snapshot,
        already_accepted: false,
    };
    policy_fence.release().await?;
    Ok(accepted)
}

pub(crate) fn spawn_accepted(state: &AppState, actor: &Session, accepted: AcceptedPlan) {
    if accepted.already_accepted {
        return;
    }
    let pool = state.pool.clone();
    let cfg = state.config.clone();
    let source_bundle_id = accepted
        .snapshot
        .source
        .get("original_bundle_id")
        .and_then(Value::as_u64);
    let run = run_context(actor, &accepted);
    tokio::spawn(async move {
        let outcome = bundle::run(&pool, &cfg, run, accepted.snapshot.actions).await;
        if outcome.state != "succeeded" {
            if let Some(source_id) = source_bundle_id {
                let reason = outcome
                    .failure_reason
                    .unwrap_or_else(|| format!("revert ended {}", outcome.state));
                match crate::reroute::recovery::release_claim_if_proven_no_write(&pool,source_id,Some(outcome.bundle_id),&reason).await {
                    Ok(true)=>{},
                    Ok(false)=>if let Err(e)=sqlx::query("UPDATE reroute_bundles SET lifecycle_state='recovery_blocked',automatic_recovery_block_reason=? WHERE id=?").bind(reason).bind(source_id).execute(&pool).await {tracing::error!(event_type="source_recovery_finalize_failed",source_bundle_id=source_id,error=%e);},
                    Err(e)=>tracing::error!(event_type="source_recovery_finalize_failed",source_bundle_id=source_id,error=%e),
                }
            }
        }
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
