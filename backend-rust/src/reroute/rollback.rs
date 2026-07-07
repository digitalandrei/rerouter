//! Rollback. Runs a template's rollback (the reverse action) against the same
//! device + params as a fresh audited action, through the same executor + state
//! machine. Used by the manual rollback endpoint (POST /reroutes/{id}/rollback).

use serde_json::Value;
use sqlx::MySqlPool;

use crate::config::Config;
use crate::reroute::executor::{self, ActionRequest, ExecOutcome};
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
) -> Option<(Template, Value)> {
    let orig = templates::load(pool, template_id).await.ok()?;

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
            return Some((orig, restore));
        }
    }

    let rollback = templates::load(pool, orig.rollback_template_id?)
        .await
        .ok()?;
    Some((rollback, params.clone()))
}

/// Run the rollback template of `template_id` against `device_id` with the same
/// params. Returns the executor outcome, or `None` if the template has no
/// rollback. Used by both auto-expiry and the manual rollback endpoint.
pub async fn rollback_of(
    pool: &MySqlPool,
    cfg: &Config,
    device_id: u64,
    template_id: u64,
    params: &Value,
    user_id: Option<u64>,
    reason: String,
) -> Option<ExecOutcome> {
    let (template, params) = resolve_rollback(pool, template_id, params).await?;
    let req = ActionRequest {
        device_id,
        template,
        params,
        trigger_type: "rollback",
        rule_id: None,
        user_id,
        reason: Some(reason),
    };
    Some(executor::execute(pool, cfg, req, false).await)
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
    let (template, params) = resolve_rollback(pool, template_id, params).await?;
    templates::render(&template, &params).ok()
}
