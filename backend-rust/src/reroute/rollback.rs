//! Rollback. Runs a template's rollback (the reverse action) against the same
//! device + params as a fresh audited action, through the same executor + state
//! machine. Used by the manual rollback endpoint (POST /reroutes/{id}/rollback).

use anyhow::Result;
use serde_json::Value;
use sqlx::MySqlPool;

use crate::config::Config;
use crate::reroute::executor::{
    self, ActionRequest, ActorContext, ExecOutcome, ExecutionAuthorization,
};
use crate::reroute::templates::{self, RenderedPlan, Template};
use crate::ssh::{RusshExecutor, SshExecutor};

/// Resolve which template + params a rollback of `template_id` would run against
/// `device_id`'s original params, WITHOUT executing. `None` when the template has
/// no rollback. Shared by [`rollback_of`] (which executes the result) and
/// [`render_rollback_plan`] (which only renders it), so a shown rollback plan is
/// exactly what a rollback would run.
///
/// Route-Map Change reversal restores the PRIOR map when one was snapshotted at
/// apply (`params.prior_route_map`): re-apply `bgp_route_map_set` with the prior
/// name. With no prior, fall through to the standard rollback template (unset),
/// which removes the map we set.
async fn resolve_rollback(
    pool: &MySqlPool,
    template_id: u64,
    params: &Value,
) -> Result<Option<(Template, Value)>> {
    let orig = templates::load(pool, template_id).await?;

    if orig.name == "bgp_route_map_set" {
        if let Some(prior) = params
            .get("prior_route_map")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let mut restore = params.clone();
            if let Value::Object(m) = &mut restore {
                m.insert("route_map".into(), Value::String(prior.to_string()));
            }
            // bgp_route_map_set, now applying the prior map.
            return Ok(Some((orig, restore)));
        }
    }

    let Some(rollback_id) = orig.rollback_template_id else {
        return Ok(None);
    };
    let rollback = templates::load(pool, rollback_id).await?;
    Ok(Some((rollback, params.clone())))
}

/// Run the rollback template of `template_id` against `device_id` with the same
/// params. Returns the executor outcome, or `None` if the template has no
/// rollback. Used by automatic rule recovery and the manual rollback endpoint.
pub struct RollbackRequest<'a> {
    pub device_id: u64,
    pub template_id: u64,
    pub params: &'a Value,
    pub original_reroute_id: Option<u64>,
    pub rule_event_id: Option<u64>,
    pub user_id: Option<u64>,
    pub actor_context: Option<ActorContext>,
    pub reason: String,
    pub defer_cooldown: bool,
    pub dry_run: bool,
    pub authorization: Option<ExecutionAuthorization>,
}

/// Rollback request whose target is derived entirely from the durable original
/// reroute. Callers cannot accidentally pass pre-executor parameters and lose an
/// apply-time prefix-list sequence or route-map prior state.
pub struct PersistedRollbackRequest {
    pub original_reroute_id: Option<u64>,
    pub rule_event_id: Option<u64>,
    pub user_id: Option<u64>,
    pub actor_context: Option<ActorContext>,
    pub reason: String,
    pub defer_cooldown: bool,
    pub dry_run: bool,
    pub authorization: Option<ExecutionAuthorization>,
}

pub async fn rollback_persisted(
    pool: &MySqlPool,
    cfg: &Config,
    req: PersistedRollbackRequest,
) -> Result<Option<ExecOutcome>> {
    let ssh = RusshExecutor::new(pool.clone());
    rollback_persisted_with(pool, cfg, &ssh, req).await
}

pub async fn rollback_persisted_with<S: SshExecutor>(
    pool: &MySqlPool,
    cfg: &Config,
    ssh: &S,
    req: PersistedRollbackRequest,
) -> Result<Option<ExecOutcome>> {
    let original_id = req
        .original_reroute_id
        .ok_or_else(|| anyhow::anyhow!("persisted rollback requires an original reroute id"))?;
    type Original = (
        Option<u64>,
        Option<u64>,
        Option<sqlx::types::Json<Value>>,
        String,
        Option<sqlx::types::Json<Value>>,
    );
    let row: Original = sqlx::query_as(
        "SELECT device_id, reroute_template_id, parameters_json, mutation_effect, \
                template_snapshot_json \
         FROM reroutes WHERE id = ?",
    )
    .bind(original_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| anyhow::anyhow!("original reroute #{original_id} not found"))?;
    let (device_id, template_id, params, effect, template_snapshot) = row;
    let device_id = device_id.ok_or_else(|| anyhow::anyhow!("original reroute has no device"))?;
    let template_id =
        template_id.ok_or_else(|| anyhow::anyhow!("original reroute has no template"))?;

    if effect == "noop" {
        return Ok(Some(ExecOutcome {
            executed: false,
            reroute_id: None,
            state: Some("succeeded".into()),
            mutation_effect: Some("noop".into()),
            message: "original action was a verified no-op; no inverse was executed".into(),
            blocked_reason: None,
            would_run: None,
            would_run_rollback: None,
            device_id,
            device_name: None,
        }));
    }
    anyhow::ensure!(
        effect == "changed",
        "original reroute effect is {effect}; reconcile it before rollback"
    );
    let params = params.map(|value| value.0).unwrap_or(Value::Null);
    let mut prepared_inverse_template: Template = serde_json::from_value(
        template_snapshot
            .ok_or_else(|| anyhow::anyhow!("original reroute has no immutable template snapshot"))?
            .0,
    )?;
    // Commands and exact verification come from the persisted PreparedInverse,
    // loaded by executor authorization. This inert shell only carries identity
    // through the legacy ActionRequest shape and cannot itself render a write.
    prepared_inverse_template.name = format!("prepared_inverse_of_{original_id}");
    prepared_inverse_template.parameter_schema = serde_json::json!({});
    prepared_inverse_template.plan = serde_json::json!({
        "transport": "ios_ssh",
        "config_mode": false,
        "apply": []
    });
    prepared_inverse_template.verification = Value::Null;
    prepared_inverse_template.rollback_template_id = None;
    prepared_inverse_template.enabled = true;
    execute_resolved_rollback_with(
        pool,
        cfg,
        ssh,
        RollbackRequest {
            device_id,
            template_id,
            params: &params,
            original_reroute_id: Some(original_id),
            rule_event_id: req.rule_event_id,
            user_id: req.user_id,
            actor_context: req.actor_context,
            reason: req.reason,
            defer_cooldown: req.defer_cooldown,
            dry_run: req.dry_run,
            authorization: req.authorization,
        },
        prepared_inverse_template,
        Value::Object(Default::default()),
    )
    .await
}

pub async fn rollback_of(
    pool: &MySqlPool,
    cfg: &Config,
    req: RollbackRequest<'_>,
) -> Result<Option<ExecOutcome>> {
    let ssh = RusshExecutor::new(pool.clone());
    rollback_of_with(pool, cfg, &ssh, req).await
}

pub async fn rollback_of_with<S: SshExecutor>(
    pool: &MySqlPool,
    cfg: &Config,
    ssh: &S,
    req: RollbackRequest<'_>,
) -> Result<Option<ExecOutcome>> {
    let Some((template, params)) = resolve_rollback(pool, req.template_id, req.params).await?
    else {
        return Ok(None);
    };

    execute_resolved_rollback_with(pool, cfg, ssh, req, template, params).await
}

async fn execute_resolved_rollback_with<S: SshExecutor>(
    pool: &MySqlPool,
    cfg: &Config,
    ssh: &S,
    req: RollbackRequest<'_>,
    template: Template,
    params: Value,
) -> Result<Option<ExecOutcome>> {
    // A real rollback is serialized by original action. The same original may be
    // retried after a failed rollback, but never while another rollback is active
    // or after one has already succeeded.
    let mut rollback_guard = None;
    if !req.dry_run {
        if let Some(original_id) = req.original_reroute_id {
            let guard =
                crate::db::advisory::acquire(&format!("05:reroute:rollback:{original_id}")).await?;
            let existing: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM reroutes WHERE rollback_of_reroute_id = ? \
                 AND state IN ('planned','pending','running','verifying','succeeded')",
            )
            .bind(original_id)
            .fetch_one(pool)
            .await?;
            if existing > 0 {
                guard.release().await?;
                anyhow::bail!("this action already has an active or successful rollback");
            }
            rollback_guard = Some(guard);
        }
    }

    let action = ActionRequest {
        device_id: req.device_id,
        template,
        params,
        trigger_type: "rollback",
        rule_id: None,
        rule_event_id: req.rule_event_id,
        rollback_of_reroute_id: req.original_reroute_id,
        user_id: req.user_id,
        actor_context: req.actor_context,
        reason: Some(req.reason),
        defer_cooldown: req.defer_cooldown,
        bundle: None,
        authorization: req.authorization,
    };
    let outcome = executor::execute_with(pool, cfg, ssh, action, req.dry_run).await;
    if let Some(guard) = rollback_guard {
        if let Err(e) = guard.release().await {
            tracing::error!(event_type = "rollback_guard_release_failed", error = %e, "failed to release rollback advisory lock");
        }
    }
    Ok(Some(outcome))
}

/// Render (without executing) the command plan a rollback of `template_id` would
/// run against the same `params`. `None` when the template has no rollback (or the
/// rollback template is not a renderable device_cli template). Used by the manual
/// preview, observe-mode "would-run" alerts, and email bodies so operators can see
/// — and, if needed, run by hand — the exact commands that undo an action.
pub async fn render_rollback_plan(
    pool: &MySqlPool,
    template_id: u64,
    params: &Value,
) -> Option<RenderedPlan> {
    let (template, params) = resolve_rollback(pool, template_id, params)
        .await
        .ok()
        .flatten()?;
    templates::render(&template, &params).ok()
}
