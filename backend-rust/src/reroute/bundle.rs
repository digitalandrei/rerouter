//! Ordered mitigation bundles — one authorized activation of one rule's whole
//! action set. See ../../docs/reroute-engine.md and ../../plans/015-ordered-mitigation-bundles.md.
//!
//! A real mitigation is rarely one command. Diverting an attacked prefix to a
//! scrubbing provider means advertising it to the scrubber on every border router
//! AND withdrawing it from the saturated upstreams — a dozen-plus actions that the
//! operator previewed and confirmed ONCE. Doctrine expresses that as an ordered set
//! of `rule_actions`, never as a composite template, so this module is the runner
//! for that ordered set, not a new kind of action.
//!
//! Three properties make a bundle safe where a plain loop was not:
//!
//!   1. IDENTITY — every sibling records `bundle_id`, so the guard's cooldown
//!      fallback can exclude the bundle's own earlier siblings. Without it the
//!      first action's `started_at` throttles the remaining thirteen (SPEC-13).
//!   2. ORDER + FAILURE POLICY — siblings run sequentially by `position`, and the
//!      default policy STOPS at the first non-success instead of ploughing on.
//!      Ordering additive actions before destructive ones therefore means a
//!      failure aborts before anything is torn down.
//!   3. COMPENSATION — under `abort_and_compensate` the siblings that already
//!      succeeded are rolled back in reverse order, so a half-applied mitigation
//!      does not survive the request that created it.
//!
//! What this module deliberately does NOT do: bypass a device lock. A sibling that
//! ends `uncertain` locks its device pending admin acknowledgement, and compensation
//! honours that lock. The bundle then ends `compensation_blocked` with a critical
//! alert naming every sibling left applied. Reporting an unsafe state loudly beats
//! forcing config onto a device whose state we could not read.

use serde_json::{json, Value};
use sqlx::MySqlPool;

use crate::config::Config;
use crate::reroute::executor::{self, ActionRequest, ActorContext, BundleMembership};
use crate::reroute::rollback;
use crate::reroute::templates::Template;

/// What to do when a sibling does not succeed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailurePolicy {
    /// Stop, then roll back the siblings that already succeeded (default).
    AbortAndCompensate,
    /// Stop, but leave applied siblings in place for the operator to judge.
    Abort,
    /// Historical best-effort fan-out: keep going. Preserved for callers that
    /// genuinely want independent per-device attempts.
    Continue,
}

impl FailurePolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            FailurePolicy::AbortAndCompensate => "abort_and_compensate",
            FailurePolicy::Abort => "abort",
            FailurePolicy::Continue => "continue",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "abort_and_compensate" => Some(FailurePolicy::AbortAndCompensate),
            "abort" => Some(FailurePolicy::Abort),
            "continue" => Some(FailurePolicy::Continue),
            _ => None,
        }
    }
}

/// One sibling, already resolved (template loaded, flow auto-target applied) and
/// ordered. Resolution happens once, before the bundle is admitted, so the plan
/// the operator confirmed is exactly the plan that runs.
pub struct BundleAction {
    pub device_id: u64,
    pub template: Template,
    pub params: Value,
    pub reason: String,
    pub position: u32,
    pub auto_target: Option<String>,
    pub auto_target_low_confidence: Option<bool>,
}

/// A sibling that succeeded, kept so compensation can reverse it.
struct AppliedSibling {
    reroute_id: u64,
    device_id: u64,
    template_id: u64,
    params: Value,
    position: u32,
}

/// Create the bundle row. Returns its id, which every sibling then carries.
#[allow(clippy::too_many_arguments)]
pub async fn create(
    pool: &MySqlPool,
    rule_id: Option<u64>,
    rule_event_id: Option<u64>,
    trigger_type: &str,
    user_id: Option<u64>,
    reason: &str,
    policy: FailurePolicy,
    total_actions: u32,
) -> anyhow::Result<u64> {
    let res = sqlx::query(
        "INSERT INTO reroute_bundles \
            (rule_id, rule_event_id, trigger_type, triggered_by_user_id, reason, \
             state, failure_policy, total_actions) \
         VALUES (?, ?, ?, ?, ?, 'planned', ?, ?)",
    )
    .bind(rule_id)
    .bind(rule_event_id)
    .bind(trigger_type)
    .bind(user_id)
    .bind(reason)
    .bind(policy.as_str())
    .bind(total_actions)
    .execute(pool)
    .await?;
    Ok(res.last_insert_id())
}

/// Terminal summary of a bundle run, also what the progress endpoint serializes.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BundleOutcome {
    pub bundle_id: u64,
    pub state: String,
    pub results: Vec<Value>,
    /// Siblings still applied when the bundle could not fully compensate. Empty
    /// unless `state` is `compensation_blocked` or `aborted`.
    pub still_applied: Vec<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
}

/// Who authorized this bundle and how it must behave — everything the runner
/// needs besides the actions themselves.
pub struct BundleRun {
    pub bundle_id: u64,
    pub policy: FailurePolicy,
    pub rule_id: Option<u64>,
    /// The firing edge, for an automatic activation.
    pub rule_event_id: Option<u64>,
    pub user_id: Option<u64>,
    pub actor_context: Option<ActorContext>,
    /// "manual" | "automatic". SAFETY: this selects which gates apply —
    /// `guard::decide` only enforces the `automatic_actions_enabled` master
    /// switch (and verify-or-refuse) for `"automatic"`. Running an automatic
    /// activation under `"manual"` would silently bypass the master switch, so
    /// this is threaded through explicitly rather than defaulted.
    pub trigger_type: &'static str,
}

impl BundleRun {
    /// An operator-confirmed apply. Binds `trigger_type` so a caller cannot
    /// accidentally run a supervised bundle under automatic gating.
    pub fn manual(
        bundle_id: u64,
        policy: FailurePolicy,
        rule_id: Option<u64>,
        user_id: u64,
        actor_context: ActorContext,
    ) -> Self {
        Self {
            bundle_id,
            policy,
            rule_id,
            rule_event_id: None,
            user_id: Some(user_id),
            actor_context: Some(actor_context),
            trigger_type: "manual",
        }
    }

    /// An unattended rule activation. Binds `trigger_type` to `"automatic"`, which
    /// is what keeps the `automatic_actions_enabled` master switch and
    /// verify-or-refuse in force for every sibling. Passing `"manual"` here would
    /// silently disarm both, so the choice is not left to the call site.
    pub fn automatic(
        bundle_id: u64,
        policy: FailurePolicy,
        rule_id: u64,
        rule_event_id: u64,
    ) -> Self {
        Self {
            bundle_id,
            policy,
            rule_id: Some(rule_id),
            rule_event_id: Some(rule_event_id),
            user_id: None,
            actor_context: None,
            trigger_type: "automatic",
        }
    }
}

/// Run an ordered bundle to completion. `actions` MUST already be in execution
/// order; the caller sorts by `rule_actions.position`.
///
/// Never panics and never returns early on error: a bundle that stops midway must
/// still reach a terminal state and persist why, because the operator's next
/// decision depends on knowing exactly what is applied.
pub async fn run(
    pool: &MySqlPool,
    cfg: &Config,
    run: BundleRun,
    actions: Vec<BundleAction>,
) -> BundleOutcome {
    let BundleRun {
        bundle_id,
        policy,
        rule_id,
        rule_event_id,
        user_id,
        actor_context,
        trigger_type,
    } = run;
    debug_assert!(
        trigger_type == "manual" || trigger_type == "automatic",
        "bundle trigger_type must be manual or automatic, got {trigger_type}"
    );
    let _ = sqlx::query(
        "UPDATE reroute_bundles SET state = 'running', started_at = UTC_TIMESTAMP() \
         WHERE id = ? AND state = 'planned'",
    )
    .bind(bundle_id)
    .execute(pool)
    .await;

    let mut results: Vec<Value> = Vec::with_capacity(actions.len());
    let mut applied: Vec<AppliedSibling> = Vec::new();
    let mut acted_devices: Vec<u64> = Vec::new();
    let mut stopped_at: Option<(u32, String)> = None;

    for action in actions {
        let template_id = action.template.id;
        let device_id = action.device_id;
        let position = action.position;
        let params = action.params.clone();

        let req = ActionRequest {
            device_id,
            template: action.template,
            params: action.params,
            trigger_type,
            rule_id,
            rule_event_id,
            rollback_of_reroute_id: None,
            user_id,
            actor_context: actor_context.clone(),
            reason: Some(action.reason),
            defer_cooldown: true,
            bundle: Some(BundleMembership {
                bundle_id,
                position,
            }),
        };

        let outcome = executor::execute(pool, cfg, req, false).await;
        if outcome.executed {
            acted_devices.push(outcome.device_id);
        }
        let succeeded = outcome.state.as_deref() == Some("succeeded");
        if succeeded {
            if let Some(reroute_id) = outcome.reroute_id {
                applied.push(AppliedSibling {
                    reroute_id,
                    device_id,
                    template_id,
                    params,
                    position,
                });
            }
        }

        let mut value = serde_json::to_value(&outcome).unwrap_or_else(|_| json!({}));
        if let Value::Object(map) = &mut value {
            map.insert("bundle_position".into(), json!(position));
            if let Some(target) = &action.auto_target {
                map.insert("auto_target".into(), json!(target));
            }
            if let Some(low) = action.auto_target_low_confidence {
                map.insert("auto_target_low_confidence".into(), json!(low));
            }
        }
        results.push(value);

        let _ = sqlx::query(
            "UPDATE reroute_bundles SET completed_actions = completed_actions + 1 WHERE id = ?",
        )
        .bind(bundle_id)
        .execute(pool)
        .await;

        if !succeeded && policy != FailurePolicy::Continue {
            let why = outcome
                .blocked_reason
                .clone()
                .unwrap_or_else(|| outcome.message.clone());
            stopped_at = Some((position, why));
            break;
        }
    }

    // Cooldowns are recorded ONCE, after the whole batch, for every device the
    // bundle actually touched — including devices whose sibling failed, because a
    // failed push may still have changed the box.
    if let Err(e) = executor::record_cooldowns(pool, cfg, rule_id, &acted_devices).await {
        tracing::error!(
            event_type = "bundle_cooldown_persist_failed",
            bundle_id,
            error = %e,
            "could not persist bundle cooldown rows; durable reroute history remains the gate fallback"
        );
    }

    let Some((failed_position, why)) = stopped_at else {
        finish(pool, bundle_id, "succeeded", None).await;
        return BundleOutcome {
            bundle_id,
            state: "succeeded".into(),
            results,
            still_applied: Vec::new(),
            failure_reason: None,
        };
    };

    let summary = format!("stopped at action #{failed_position}: {why}");

    // `Abort` leaves applied siblings deliberately; with nothing applied there is
    // nothing to compensate either way.
    if policy == FailurePolicy::Abort || applied.is_empty() {
        finish(pool, bundle_id, "aborted", Some(&summary)).await;
        let still: Vec<u64> = applied.iter().map(|a| a.reroute_id).collect();
        if !still.is_empty() {
            alert_still_applied(pool, bundle_id, &still, &summary).await;
        }
        return BundleOutcome {
            bundle_id,
            state: "aborted".into(),
            results,
            still_applied: still,
            failure_reason: Some(summary),
        };
    }

    // ---- compensation ------------------------------------------------------
    let _ = sqlx::query("UPDATE reroute_bundles SET state = 'compensating' WHERE id = ?")
        .bind(bundle_id)
        .execute(pool)
        .await;

    let mut still_applied: Vec<u64> = Vec::new();
    // Reverse order: undo the most recent change first, so intermediate states
    // mirror the way the bundle was built up.
    for sibling in applied.iter().rev() {
        let req = rollback::RollbackRequest {
            device_id: sibling.device_id,
            template_id: sibling.template_id,
            params: &sibling.params,
            original_reroute_id: Some(sibling.reroute_id),
            rule_event_id,
            user_id,
            actor_context: actor_context.clone(),
            reason: format!(
                "automatic compensation of bundle #{bundle_id} (action #{} of an aborted mitigation)",
                sibling.position
            ),
            defer_cooldown: true,
            dry_run: false,
        };
        match rollback::rollback_of(pool, cfg, req).await {
            Ok(Some(out)) if out.state.as_deref() == Some("succeeded") => {}
            Ok(Some(out)) => {
                tracing::error!(
                    event_type = "bundle_compensation_failed",
                    bundle_id,
                    reroute_id = sibling.reroute_id,
                    state = out.state.as_deref().unwrap_or("unknown"),
                    "a bundle sibling could not be rolled back; it remains applied"
                );
                still_applied.push(sibling.reroute_id);
            }
            // No rollback template: the action has no inverse, so it stays.
            Ok(None) => {
                tracing::error!(
                    event_type = "bundle_compensation_unavailable",
                    bundle_id,
                    reroute_id = sibling.reroute_id,
                    "sibling template has no rollback; it remains applied"
                );
                still_applied.push(sibling.reroute_id);
            }
            Err(e) => {
                tracing::error!(
                    event_type = "bundle_compensation_error",
                    bundle_id,
                    reroute_id = sibling.reroute_id,
                    error = %e,
                    "rollback of a bundle sibling errored; it remains applied"
                );
                still_applied.push(sibling.reroute_id);
            }
        }
    }

    let state = if still_applied.is_empty() {
        "compensated"
    } else {
        "compensation_blocked"
    };
    finish(pool, bundle_id, state, Some(&summary)).await;
    if !still_applied.is_empty() {
        alert_still_applied(pool, bundle_id, &still_applied, &summary).await;
    }

    BundleOutcome {
        bundle_id,
        state: state.into(),
        results,
        still_applied,
        failure_reason: Some(summary),
    }
}

async fn finish(pool: &MySqlPool, bundle_id: u64, state: &str, failure_reason: Option<&str>) {
    if let Err(e) = sqlx::query(
        "UPDATE reroute_bundles SET state = ?, failure_reason = ?, finished_at = UTC_TIMESTAMP() \
         WHERE id = ?",
    )
    .bind(state)
    .bind(failure_reason)
    .bind(bundle_id)
    .execute(pool)
    .await
    {
        tracing::error!(
            event_type = "bundle_finalize_failed",
            bundle_id,
            state,
            error = %e,
            "could not persist terminal bundle state"
        );
    }
}

/// A mitigation is half-applied and the controller could not undo it. This is the
/// state an operator must see immediately, so it is a CRITICAL alert naming the
/// exact reroutes still in force.
async fn alert_still_applied(pool: &MySqlPool, bundle_id: u64, still: &[u64], summary: &str) {
    let payload = json!({
        "bundle_id": bundle_id,
        "still_applied_reroute_ids": still,
        "reason": summary,
        "operator_action": "these actions are STILL APPLIED and could not be rolled back \
    automatically; review each reroute and roll it back by hand once the device is unlocked",
    });
    if let Err(e) = sqlx::query(
        "INSERT INTO alerts (event_type, severity, payload_json, dedup_key) \
         VALUES ('reroute_bundle_partial', 'critical', ?, ?)",
    )
    .bind(sqlx::types::Json(&payload))
    .bind(format!("reroute_bundle_partial:{bundle_id}"))
    .execute(pool)
    .await
    {
        tracing::error!(
            event_type = "bundle_partial_alert_failed",
            bundle_id,
            error = %e,
            "could not raise the partial-bundle alert; the log line above is the floor"
        );
    }
    if let Err(e) = sqlx::query(
        "INSERT INTO audit_logs \
            (actor_type, event_type, entity_type, entity_id, message) \
         VALUES ('system', 'reroute_bundle_partial', 'reroute_bundle', ?, ?)",
    )
    .bind(bundle_id)
    .bind(format!(
        "bundle #{bundle_id} left {} action(s) applied: {summary}",
        still.len()
    ))
    .execute(pool)
    .await
    {
        tracing::error!(event_type = "bundle_partial_audit_failed", bundle_id, error = %e, "could not audit the partial bundle");
    }
}

/// Bundles caught mid-flight by a restart. Their in-flight siblings are already
/// marked `uncertain` (and their devices locked) by
/// [`super::state_machine::recover_on_startup`]; this closes the bundle row so the
/// UI never shows a mitigation as still progressing after a crash.
pub async fn recover_on_startup(pool: &MySqlPool) -> anyhow::Result<()> {
    let res = sqlx::query(
        "UPDATE reroute_bundles \
            SET state = 'aborted', finished_at = UTC_TIMESTAMP(), \
                failure_reason = 'controller restarted mid-bundle; siblings marked uncertain' \
          WHERE state IN ('planned', 'running', 'compensating')",
    )
    .execute(pool)
    .await?;
    if res.rows_affected() > 0 {
        tracing::warn!(
            event_type = "bundle_recovery_aborted",
            count = res.rows_affected(),
            "closed in-flight mitigation bundles after restart"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The trigger type decides which gates bind: `guard::decide` enforces the
    /// `automatic_actions_enabled` master switch and verify-or-refuse ONLY for
    /// `"automatic"`. An automatic activation running under `"manual"` would be
    /// unattended execution with the master switch disarmed, so the constructors
    /// bind it and these tests pin that binding.
    #[test]
    fn automatic_constructor_binds_automatic_gating() {
        let run = BundleRun::automatic(7, FailurePolicy::AbortAndCompensate, 3, 9);
        assert_eq!(run.trigger_type, "automatic");
        assert_eq!(run.rule_id, Some(3));
        assert_eq!(run.rule_event_id, Some(9));
        assert!(
            run.user_id.is_none(),
            "an unattended activation has no operator"
        );
    }

    #[test]
    fn manual_constructor_binds_manual_gating() {
        let actor = ActorContext {
            ip_address: "192.0.2.10".into(),
            user_agent: "test".into(),
        };
        let run = BundleRun::manual(7, FailurePolicy::Abort, Some(3), 42, actor);
        assert_eq!(run.trigger_type, "manual");
        assert_eq!(run.user_id, Some(42));
        assert!(
            run.rule_event_id.is_none(),
            "a supervised apply is not tied to one firing edge"
        );
    }

    #[test]
    fn failure_policy_round_trips() {
        for p in [
            FailurePolicy::AbortAndCompensate,
            FailurePolicy::Abort,
            FailurePolicy::Continue,
        ] {
            assert_eq!(FailurePolicy::parse(p.as_str()), Some(p));
        }
        assert_eq!(FailurePolicy::parse("something-else"), None);
    }
}
