//! Rollback. Runs a template's rollback (the reverse action) against the same
//! device + params as a fresh audited action, through the same executor + state
//! machine. Used by the manual rollback endpoint (POST /reroutes/{id}/rollback).

use serde_json::Value;
use sqlx::MySqlPool;

use crate::config::Config;
use crate::reroute::executor::{self, ActionRequest, ExecOutcome};
use crate::reroute::templates;

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
    let orig = templates::load(pool, template_id).await.ok()?;

    // Route-Map Change reversal restores the PRIOR map when one was snapshotted at
    // apply (params.prior_route_map): re-apply bgp_route_map_set with the prior
    // name. With no prior, fall through to the standard rollback template (unset),
    // which removes the map we set.
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
            let req = ActionRequest {
                device_id,
                template: orig, // bgp_route_map_set, now applying the prior map
                params: restore,
                trigger_type: "rollback",
                rule_id: None,
                user_id,
                reason: Some(reason),
            };
            return Some(executor::execute(pool, cfg, req, false).await);
        }
    }

    let rollback = templates::load(pool, orig.rollback_template_id?)
        .await
        .ok()?;
    let req = ActionRequest {
        device_id,
        template: rollback,
        params: params.clone(),
        trigger_type: "rollback",
        rule_id: None,
        user_id,
        reason: Some(reason),
    };
    Some(executor::execute(pool, cfg, req, false).await)
}
