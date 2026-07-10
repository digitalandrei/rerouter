//! Rollback. Runs a template's rollback (the reverse action) against the same
//! device + params as a fresh audited action, through the same executor + state
//! machine. Used by the manual rollback endpoint (POST /reroutes/{id}/rollback).

use anyhow::Result;
use serde_json::Value;
use sqlx::MySqlPool;

use crate::config::Config;
use crate::reroute::executor::{self, ActionRequest, ActorContext, ExecOutcome};
use crate::reroute::templates::{self, RenderedPlan, Template};

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
}

pub async fn rollback_of(
    pool: &MySqlPool,
    cfg: &Config,
    req: RollbackRequest<'_>,
) -> Result<Option<ExecOutcome>> {
    let Some((template, params)) = resolve_rollback(pool, req.template_id, req.params).await?
    else {
        return Ok(None);
    };

    // A real rollback is serialized by original action. The same original may be
    // retried after a failed rollback, but never while another rollback is active
    // or after one has already succeeded.
    let mut lock_conn = None;
    let mut lock_name = None;
    if !req.dry_run {
        if let Some(original_id) = req.original_reroute_id {
            let name = format!("reroute_rollback_{original_id}");
            let mut conn = pool.acquire().await?;
            let got: Option<i64> = sqlx::query_scalar("SELECT GET_LOCK(?, 5)")
                .bind(&name)
                .fetch_one(&mut *conn)
                .await?;
            anyhow::ensure!(got == Some(1), "another rollback is being prepared");
            let existing: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM reroutes WHERE rollback_of_reroute_id = ? \
                 AND state IN ('planned','pending','running','verifying','succeeded')",
            )
            .bind(original_id)
            .fetch_one(&mut *conn)
            .await?;
            if existing > 0 {
                let _ = sqlx::query("SELECT RELEASE_LOCK(?)")
                    .bind(&name)
                    .execute(&mut *conn)
                    .await;
                anyhow::bail!("this action already has an active or successful rollback");
            }
            lock_name = Some(name);
            lock_conn = Some(conn);
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
    };
    let outcome = executor::execute(pool, cfg, action, req.dry_run).await;
    if let (Some(mut conn), Some(name)) = (lock_conn, lock_name) {
        if let Err(e) = sqlx::query("SELECT RELEASE_LOCK(?)")
            .bind(name)
            .execute(&mut *conn)
            .await
        {
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
