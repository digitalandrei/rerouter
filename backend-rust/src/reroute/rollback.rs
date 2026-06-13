//! Rollback + auto-expiry. A succeeded reroute that carries an auto-expiry runs
//! its template's rollback when the window elapses, so a forgotten mitigation
//! self-clears. Rollbacks are themselves audited + verified actions (they go
//! through the same executor + state machine). Manual rollback uses the same
//! [`rollback_of`] path from the API.

use serde_json::Value;
use sqlx::MySqlPool;

use crate::config::Config;
use crate::reroute::executor::{self, ActionRequest, ExecOutcome};
use crate::reroute::templates;

/// Run any due auto-expiry rollbacks. Best-effort; called periodically by the
/// scheduler. Returns the number of rollbacks initiated.
pub async fn run_due_expiries(pool: &MySqlPool, cfg: &Config) -> usize {
    let due = sqlx::query_as::<_, (u64, Option<u64>, Option<u64>, Option<sqlx::types::Json<Value>>)>(
        "SELECT id, device_id, reroute_template_id, parameters_json FROM reroutes \
         WHERE state = 'succeeded' AND expires_at IS NOT NULL AND expires_at <= UTC_TIMESTAMP()",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let mut count = 0;
    for (orig_id, device_id, template_id, params_json) in due {
        // Clear the expiry first so a failing rollback isn't retried forever.
        let _ = sqlx::query("UPDATE reroutes SET expires_at = NULL WHERE id = ?")
            .bind(orig_id)
            .execute(pool)
            .await;

        let (Some(device_id), Some(template_id)) = (device_id, template_id) else { continue };
        let params = params_json.map(|j| j.0).unwrap_or(Value::Null);
        let outcome = rollback_of(pool, cfg, device_id, template_id, &params, None,
            format!("auto-expiry rollback of reroute #{orig_id}")).await;
        if outcome.as_ref().map(|o| o.executed).unwrap_or(false) {
            count += 1;
        }
        tracing::info!(
            event_type = "auto_expiry_rollback",
            orig_reroute_id = orig_id,
            device_id,
            "auto-expiry rollback attempted"
        );
    }
    count
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
    let orig = templates::load(pool, template_id).await.ok()?;
    let rollback = templates::load(pool, orig.rollback_template_id?).await.ok()?;
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
