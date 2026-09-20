//! Ordered mitigation bundles — one authorized activation of a complete rule or
//! manual action set. See ../../docs/manual-mitigations.md.
//!
//! A real mitigation is rarely one command. Diverting an attacked prefix to a
//! scrubbing provider means advertising it to the scrubber on every border router
//! AND withdrawing it from the saturated upstreams — a dozen-plus actions that the
//! operator previewed and confirmed ONCE. Presets and rules both expand to explicit
//! ordered actions; this module executes their immutable prepared snapshots.
//!
//! Three properties make a bundle safe where a plain loop was not:
//!
//!   1. IDENTITY — every sibling records `bundle_id`, so the guard's cooldown
//!      fallback can exclude the bundle's own earlier siblings. Without it the
//!      first action's `started_at` throttles the remaining thirteen (SPEC-13).
//!   2. ORDER + FAILURE POLICY — siblings run sequentially by `position`, and the
//!      policy STOPS at the first non-success; best-effort continuation is refused.
//!      Ordering additive actions before destructive ones therefore means a
//!      failure aborts before anything is torn down.
//!   3. COMPENSATION — under `abort_and_compensate` the siblings that already
//!      changed configuration are rolled back in reverse order only when every
//!      remaining effect and inverse is proven safe. No-ops own no inverse.
//!
//! A sibling that ends `uncertain` freezes the entire set, including compensation
//! on other devices. Evidence-bound reconciliation must resolve it before recovery.
//! The bundle ends `compensation_blocked` with a critical
//! alert naming every sibling left applied. Reporting an unsafe state loudly beats
//! forcing config onto a device whose state we could not read.

use serde_json::{json, Value};
use sqlx::MySqlPool;

use crate::config::Config;
use crate::reroute::executor::{
    self, ActionRequest, ActorContext, BundleMembership, ExecutionAuthorization,
};
use crate::reroute::locks;
use crate::reroute::rollback;
use crate::reroute::templates::Template;
use crate::ssh::{RusshExecutor, SshExecutor};

fn requires_replacement_reproof(trigger_type: &str) -> bool {
    matches!(trigger_type, "manual" | "direct_manual" | "automatic")
}

fn requires_corrective_closure(trigger_type: &str) -> bool {
    matches!(trigger_type, "rollback" | "recovery" | "manual_recovery")
}

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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BundleAction {
    pub device_id: u64,
    pub template: Template,
    pub params: Value,
    pub reason: String,
    pub position: u32,
    pub auto_target: Option<String>,
    pub auto_target_low_confidence: Option<bool>,
    /// Typed, read-only device snapshot prepared while every target device is
    /// exclusively locked. Required for real execution.
    pub prepared: Option<crate::reroute::device_plan::PreparedDeviceAction>,
    /// Set for an inverse prepared action. The runner and guard then preserve
    /// the original-action ownership link and apply rollback gates.
    pub original_reroute_id: Option<u64>,
}

pub(crate) fn safety_phase(template_name: &str) -> (&'static str, u8) {
    match template_name {
        "bgp_advertise_add"
        | "bgp_session_enable"
        | "iface_no_shutdown"
        | "iface_tcp_adjust_mss" => ("additive", 0),
        "bgp_advertise_remove"
        | "bgp_session_disable"
        | "iface_shutdown"
        | "iface_tcp_adjust_mss_remove"
        | "null_route_prefix"
        | "null_route_prefix_v6"
        | "blackhole_prefix"
        | "blackhole_prefix_v6" => ("destructive", 2),
        _ => ("neutral", 1),
    }
}

/// Persist the complete intended sibling set before the asynchronous hand-off.
/// Any render/ordering/write failure aborts the transaction, so a runner never
/// discovers a deterministic invalid sibling after earlier router writes.
pub async fn persist_actions(
    pool: &MySqlPool,
    bundle_id: u64,
    actions: &[BundleAction],
) -> anyhow::Result<()> {
    anyhow::ensure!(!actions.is_empty(), "bundle has no prepared actions");
    let mut seen = std::collections::BTreeSet::new();
    let mut last_phase = 0u8;
    let mut prepared = Vec::with_capacity(actions.len());
    for action in actions {
        anyhow::ensure!(
            seen.insert(action.position),
            "duplicate bundle position {}",
            action.position
        );
        anyhow::ensure!(
            action.template.enabled,
            "template '{}' is disabled",
            action.template.name
        );
        let prepared_action = action.prepared.as_ref().ok_or_else(|| {
            anyhow::anyhow!("action {} has no locked prepared snapshot", action.position)
        })?;
        prepared_action.validate()?;
        anyhow::ensure!(
            prepared_action.device_id == action.device_id,
            "prepared device mismatch"
        );
        anyhow::ensure!(
            prepared_action.template_id == action.template.id,
            "prepared template mismatch"
        );
        let rendered = crate::reroute::templates::RenderedPlan {
            template_id: prepared_action.template_id,
            template_name: prepared_action.template_name.clone(),
            config_mode: false,
            commands: prepared_action.commands.clone(),
            verify: None,
            sequence_pending: false,
        };
        let rollback_snapshot = prepared_action
            .inverse
            .as_ref()
            .map(serde_json::to_value)
            .transpose()?;
        let rendered_rollback = prepared_action.inverse.as_ref().map(|inverse| {
            json!({
                "commands": inverse.commands,
                "verify": inverse.verify,
                "sequence_pending": false,
            })
        });
        let (phase, rank) = if action.template.name == "bgp_export_policy_set" {
            use crate::reroute::device_plan::PreparedSafetyEffect::*;
            match crate::reroute::device_plan::prepared_safety_effect(prepared_action)? {
                Additive => ("additive", 0),
                Neutral => ("neutral", 1),
                Noop => ("neutral", last_phase),
                Destructive => ("destructive", 2),
                Mixed | Unproven => {
                    anyhow::bail!("export policy effect is mixed or cannot be proved")
                }
            }
        } else {
            safety_phase(&action.template.name)
        };
        anyhow::ensure!(
            rank >= last_phase,
            "unsafe action order: '{}' appears after a more destructive phase",
            action.template.name
        );
        last_phase = rank;
        prepared.push((
            action,
            serde_json::to_value(&action.template)?,
            serde_json::to_value(&rendered)?,
            rollback_snapshot,
            rendered_rollback,
            serde_json::to_value(prepared_action)?,
            phase,
        ));
    }

    let mut tx = pool.begin().await?;
    let existing: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM reroute_bundle_actions WHERE bundle_id = ?")
            .bind(bundle_id)
            .fetch_one(&mut *tx)
            .await?;
    if existing > 0 {
        anyhow::ensure!(
            existing == actions.len() as i64,
            "bundle snapshot already exists with a different action count"
        );
        tx.commit().await?;
        return Ok(());
    }
    for (
        action,
        template,
        rendered,
        rollback_snapshot,
        rendered_rollback,
        prepared_action,
        phase,
    ) in prepared
    {
        let auto_target = action.auto_target.as_ref().map(|target| {
            json!({
                "target": target,
                "low_confidence": action.auto_target_low_confidence,
            })
        });
        sqlx::query(
            "INSERT INTO reroute_bundle_actions \
                (bundle_id, position, source_rule_action_id, original_reroute_id, device_id, \
                 template_snapshot_json, rollback_snapshot_json, \
                 canonical_params_json, rendered_plan_json, rendered_rollback_json, \
                 prepared_action_json, \
                 auto_target_json, safety_phase) \
             VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(bundle_id)
        .bind(action.position)
        .bind(action.original_reroute_id)
        .bind(action.device_id)
        .bind(sqlx::types::Json(template))
        .bind(rollback_snapshot.map(sqlx::types::Json))
        .bind(sqlx::types::Json(
            action
                .prepared
                .as_ref()
                .expect("prepared above")
                .canonical_params
                .clone(),
        ))
        .bind(sqlx::types::Json(rendered))
        .bind(rendered_rollback.map(sqlx::types::Json))
        .bind(sqlx::types::Json(prepared_action))
        .bind(auto_target.map(sqlx::types::Json))
        .bind(phase)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Original mitigation ownership still active for this bundle. For an apply
/// bundle the originals are its own reroutes; for a rollback/recovery bundle the
/// immutable ledger points back to source originals. Successful inverses close
/// originals and never become new ownership themselves.
pub async fn outstanding_owned_originals(
    pool: &MySqlPool,
    bundle_id: u64,
) -> anyhow::Result<Vec<(u64, u64)>> {
    Ok(sqlx::query_as(
        "SELECT DISTINCT original.id, original.device_id \
           FROM reroutes original \
           LEFT JOIN reroute_bundle_actions ba \
             ON ba.bundle_id = ? AND ba.original_reroute_id = original.id \
          WHERE original.rollback_of_reroute_id IS NULL \
            AND (original.bundle_id = ? OR ba.id IS NOT NULL) \
            AND original.mutation_effect IN ('changed','unknown') \
            AND NOT EXISTS (SELECT 1 FROM reroutes inverse \
                 WHERE inverse.rollback_of_reroute_id = original.id \
                   AND inverse.state = 'succeeded' \
                   AND inverse.mutation_effect IN ('changed','noop')) \
          ORDER BY original.id",
    )
    .bind(bundle_id)
    .bind(bundle_id)
    .fetch_all(pool)
    .await?)
}

/// A sibling that succeeded, kept so compensation can reverse it.
struct AppliedSibling {
    reroute_id: u64,
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

fn finalization_failure_outcome(
    bundle_id: u64,
    results: Vec<Value>,
    still_applied: Vec<u64>,
    error: anyhow::Error,
) -> BundleOutcome {
    let reason = format!(
        "terminal persistence failed; recovery ownership remains quarantined for startup repair: {error:#}"
    );
    tracing::error!(event_type="bundle_finalize_failed", bundle_id, error=%error, "bundle outcome is unproven because terminal persistence failed");
    BundleOutcome {
        bundle_id,
        state: "compensation_blocked".into(),
        results,
        still_applied,
        failure_reason: Some(reason),
    }
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
    pub authorization_plan_id: Option<u64>,
    pub owner_token: String,
    #[doc(hidden)]
    pub force_terminal_persistence_failure: bool,
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
            authorization_plan_id: None,
            owner_token: format!("bundle:{bundle_id}"),
            force_terminal_persistence_failure: false,
        }
    }

    /// A manual run whose durable bundle was published before preparation.
    /// Its prepared action ledger is the authority instead of a browser-held
    /// preview token.
    pub fn direct_manual(
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
            trigger_type: "direct_manual",
            authorization_plan_id: None,
            owner_token: format!("bundle:{bundle_id}"),
            force_terminal_persistence_failure: false,
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
            authorization_plan_id: None,
            owner_token: format!("bundle:{bundle_id}"),
            force_terminal_persistence_failure: false,
        }
    }

    pub fn rollback(
        bundle_id: u64,
        policy: FailurePolicy,
        user_id: u64,
        actor_context: ActorContext,
    ) -> Self {
        Self {
            bundle_id,
            policy,
            rule_id: None,
            rule_event_id: None,
            user_id: Some(user_id),
            actor_context: Some(actor_context),
            trigger_type: "rollback",
            authorization_plan_id: None,
            owner_token: format!("bundle:{bundle_id}"),
            force_terminal_persistence_failure: false,
        }
    }

    pub fn automatic_recovery(bundle_id: u64, policy: FailurePolicy, rule_id: u64) -> Self {
        Self {
            bundle_id,
            policy,
            rule_id: Some(rule_id),
            rule_event_id: None,
            user_id: None,
            actor_context: None,
            trigger_type: "recovery",
            authorization_plan_id: None,
            owner_token: format!("recovery:bundle:{bundle_id}"),
            force_terminal_persistence_failure: false,
        }
    }

    pub fn scheduled_recovery(bundle_id: u64, policy: FailurePolicy) -> Self {
        Self {
            bundle_id,
            policy,
            rule_id: None,
            rule_event_id: None,
            user_id: None,
            actor_context: None,
            trigger_type: "recovery",
            authorization_plan_id: None,
            owner_token: format!("recovery:bundle:{bundle_id}"),
            force_terminal_persistence_failure: false,
        }
    }

    /// An operator-requested recovery published before its router reads begin.
    /// It uses durable recovery authority while retaining user attribution.
    pub fn manual_recovery(
        bundle_id: u64,
        policy: FailurePolicy,
        user_id: u64,
        actor_context: ActorContext,
    ) -> Self {
        Self {
            bundle_id,
            policy,
            rule_id: None,
            rule_event_id: None,
            user_id: Some(user_id),
            actor_context: Some(actor_context),
            trigger_type: "manual_recovery",
            authorization_plan_id: None,
            owner_token: format!("recovery:bundle:{bundle_id}"),
            force_terminal_persistence_failure: false,
        }
    }

    pub fn with_authorization(
        mut self,
        plan_id: Option<u64>,
        owner_token: impl Into<String>,
    ) -> Self {
        self.authorization_plan_id = plan_id;
        self.owner_token = owner_token.into();
        self
    }

    #[doc(hidden)]
    pub fn with_forced_terminal_persistence_failure(mut self) -> Self {
        self.force_terminal_persistence_failure = true;
        self
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
    let ssh = RusshExecutor::new(pool.clone());
    run_with_ssh(pool, cfg, run, actions, &ssh).await
}

/// Testable orchestration seam. Production passes [`RusshExecutor`]; integration
/// tests pass a fake that must explicitly implement native lock ownership and
/// prepared execution, otherwise the trait defaults fail closed.
pub async fn run_with_ssh<S: SshExecutor>(
    pool: &MySqlPool,
    cfg: &Config,
    run: BundleRun,
    actions: Vec<BundleAction>,
    ssh: &S,
) -> BundleOutcome {
    let bundle_id = run.bundle_id;
    let runtime = match cfg.advisory_runtime(pool).await {
        Ok(value) => value,
        Err(error) => {
            return BundleOutcome {
                bundle_id: run.bundle_id,
                state: "failed".into(),
                results: vec![],
                still_applied: vec![],
                failure_reason: Some(format!("lock runtime unavailable: {error}")),
            }
        }
    };
    match crate::db::advisory::foreground_scope(
        runtime,
        Box::pin(run_with_ssh_inner(pool, cfg, run, actions, ssh)),
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => BundleOutcome {
            bundle_id,
            state: "failed".into(),
            results: vec![],
            still_applied: vec![],
            failure_reason: Some(format!("execution capacity unavailable: {error}")),
        },
    }
}

async fn run_with_ssh_inner<S: SshExecutor>(
    pool: &MySqlPool,
    cfg: &Config,
    run: BundleRun,
    actions: Vec<BundleAction>,
    ssh: &S,
) -> BundleOutcome {
    let BundleRun {
        bundle_id,
        policy,
        rule_id,
        rule_event_id,
        user_id,
        actor_context,
        trigger_type,
        authorization_plan_id,
        owner_token,
        force_terminal_persistence_failure,
    } = run;
    debug_assert!(
        matches!(
            trigger_type,
            "manual" | "direct_manual" | "automatic" | "rollback" | "recovery" | "manual_recovery"
        ),
        "bundle trigger_type must be manual, automatic, rollback or recovery, got {trigger_type}"
    );
    if let Err(e) = persist_actions(pool, bundle_id, &actions).await {
        let reason = format!("bundle preparation failed before execution: {e}");
        if let Err(finalize) =
            finish_and_release(pool, bundle_id, "failed", Some(&reason), &owner_token).await
        {
            return finalization_failure_outcome(bundle_id, Vec::new(), Vec::new(), finalize);
        }
        return BundleOutcome {
            bundle_id,
            state: "failed".into(),
            results: Vec::new(),
            still_applied: Vec::new(),
            failure_reason: Some(reason),
        };
    }
    if let Some(plan_id) = authorization_plan_id {
        if let Err(e) = validate_manual_snapshot(pool, plan_id, bundle_id, &actions).await {
            let reason = format!("authorized bundle snapshot mismatch: {e}");
            if let Err(finalize) =
                finish_and_release(pool, bundle_id, "failed", Some(&reason), &owner_token).await
            {
                return finalization_failure_outcome(bundle_id, Vec::new(), Vec::new(), finalize);
            }
            return BundleOutcome {
                bundle_id,
                state: "failed".into(),
                results: Vec::new(),
                still_applied: Vec::new(),
                failure_reason: Some(reason),
            };
        }
    }
    let device_ids: Vec<u64> = actions.iter().map(|action| action.device_id).collect();
    let originals: Option<Vec<u64>> = actions
        .iter()
        .map(|action| action.original_reroute_id)
        .collect();
    if let Some(originals) = originals {
        if let Err(e) =
            locks::claim_change_windows_for_recovery(pool, bundle_id, &owner_token, &originals)
                .await
        {
            let reason = format!("could not claim original action ownership for recovery: {e}");
            if let Err(finalize) =
                finish_and_release(pool, bundle_id, "failed", Some(&reason), &owner_token).await
            {
                return finalization_failure_outcome(bundle_id, Vec::new(), Vec::new(), finalize);
            }
            return BundleOutcome {
                bundle_id,
                state: "failed".into(),
                results: Vec::new(),
                still_applied: Vec::new(),
                failure_reason: Some(reason),
            };
        }
    }
    if let Err(e) =
        locks::acquire_bundle_change_windows(pool, bundle_id, &owner_token, &device_ids).await
    {
        let reason = format!("could not acquire the bundle device change window: {e}");
        if let Err(finalize) =
            finish_and_release(pool, bundle_id, "failed", Some(&reason), &owner_token).await
        {
            return finalization_failure_outcome(bundle_id, Vec::new(), Vec::new(), finalize);
        }
        return BundleOutcome {
            bundle_id,
            state: "failed".into(),
            results: Vec::new(),
            still_applied: Vec::new(),
            failure_reason: Some(reason),
        };
    }
    let _ = locks::set_bundle_change_window_phase(pool, bundle_id, &owner_token, "applying").await;

    let mut native_locks = match ssh.lock_devices(&device_ids).await {
        Ok(locks) => locks,
        Err(e) => {
            let reason = format!("could not acquire native device configuration locks: {e}");
            if let Err(finalize) =
                finish_and_release(pool, bundle_id, "failed", Some(&reason), &owner_token).await
            {
                return finalization_failure_outcome(bundle_id, Vec::new(), Vec::new(), finalize);
            }
            return BundleOutcome {
                bundle_id,
                state: "failed".into(),
                results: Vec::new(),
                still_applied: Vec::new(),
                failure_reason: Some(reason),
            };
        }
    };
    let source: Option<sqlx::types::Json<Value>> =
        sqlx::query_scalar("SELECT source_json FROM reroute_bundles WHERE id = ?")
            .bind(bundle_id)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten();
    let expected_identities = source
        .and_then(|source| source.0.get("transport_identities").cloned())
        .ok_or_else(|| anyhow::anyhow!("bundle has no prepared transport identity map"))
        .and_then(|value| {
            serde_json::from_value::<
                std::collections::BTreeMap<
                    u64,
                    crate::reroute::device_plan::DeviceTransportIdentity,
                >,
            >(value)
            .map_err(Into::into)
        });
    let identities_match = expected_identities.and_then(|expected| {
        crate::reroute::device_plan::verify_transport_identities(native_locks.as_ref(), &expected)
    });
    if !matches!(identities_match, Ok(true)) {
        let reason = match identities_match {
            Ok(false) => "device transport identity changed after preparation".to_string(),
            Err(e) => format!("could not prove prepared device transport identities: {e}"),
            Ok(true) => unreachable!(),
        };
        if let Err(finalize) =
            finish_and_release(pool, bundle_id, "failed", Some(&reason), &owner_token).await
        {
            let _ = native_locks.unlock_all().await;
            return finalization_failure_outcome(bundle_id, Vec::new(), Vec::new(), finalize);
        }
        let _ = native_locks.unlock_all().await;
        return BundleOutcome {
            bundle_id,
            state: "failed".into(),
            results: Vec::new(),
            still_applied: Vec::new(),
            failure_reason: Some(reason),
        };
    }
    // Validate the entire projected sequence while every native lock is retained.
    // Later same-device siblings may legitimately expect an earlier sibling's
    // projected after-state, so the verifier checks first occurrences live and
    // subsequent occurrences against that projection.
    let prepared_sequence: Vec<_> = actions
        .iter()
        .map(|action| {
            action
                .prepared
                .clone()
                .expect("persist_actions checked prepared plans")
        })
        .collect();
    let preflight = crate::reroute::device_plan::verify_prepared_sequence(
        native_locks.as_mut(),
        &prepared_sequence,
    )
    .await;
    if !matches!(preflight, Ok(true)) {
        let reason = match preflight {
            Ok(false) => "prepared bundle sequence no longer matches router state".to_string(),
            Err(e) => format!("could not prove the complete prepared bundle sequence: {e}"),
            Ok(true) => unreachable!(),
        };
        if let Err(finalize) =
            finish_and_release(pool, bundle_id, "failed", Some(&reason), &owner_token).await
        {
            let _ = native_locks.unlock_all().await;
            return finalization_failure_outcome(bundle_id, Vec::new(), Vec::new(), finalize);
        }
        let _ = native_locks.unlock_all().await;
        return BundleOutcome {
            bundle_id,
            state: "failed".into(),
            results: Vec::new(),
            still_applied: Vec::new(),
            failure_reason: Some(reason),
        };
    }
    let locked_ssh = executor::LockedSshExecutor::new(native_locks.as_mut());

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
    let mut freeze_on_ambiguity: Option<u64> = None;
    let mut projected_state_lost = false;
    let mut any_failure = false;
    let mut corrective_failure = false;
    let mut succeeded_prepared: Vec<crate::reroute::device_plan::PreparedDeviceAction> = Vec::new();

    for action in actions {
        let device_id = action.device_id;
        let position = action.position;
        let inverse_action = action.original_reroute_id.is_some();
        let prepared_for_proof = action
            .prepared
            .clone()
            .expect("persist_actions required a prepared action");
        let prepared_rank = if action.template.name == "bgp_export_policy_set" {
            match crate::reroute::device_plan::prepared_safety_effect(&prepared_for_proof) {
                Ok(crate::reroute::device_plan::PreparedSafetyEffect::Destructive) => 2,
                Ok(crate::reroute::device_plan::PreparedSafetyEffect::Additive) => 0,
                _ => 1,
            }
        } else {
            safety_phase(&action.template.name).1
        };
        let destructive_forward = requires_replacement_reproof(trigger_type) && prepared_rank == 2;
        if destructive_forward && !succeeded_prepared.is_empty() {
            match locked_ssh.verify_projected_after(&succeeded_prepared).await {
                Ok(true) => {}
                Ok(false) => {
                    projected_state_lost = true;
                    stopped_at = Some((
                        position,
                        "previously verified replacement state changed before the destructive action"
                            .into(),
                    ));
                    break;
                }
                Err(e) => {
                    projected_state_lost = true;
                    stopped_at = Some((
                        position,
                        format!(
                            "could not re-prove replacement state before the destructive action: {e}"
                        ),
                    ));
                    break;
                }
            }
        }
        let snapshot_action_id: Option<u64> = sqlx::query_scalar(
            "SELECT id FROM reroute_bundle_actions WHERE bundle_id = ? AND position = ?",
        )
        .bind(bundle_id)
        .bind(position)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();
        let authorization = match trigger_type {
            "manual" => authorization_plan_id.map(|plan_id| {
                ExecutionAuthorization::manual(
                    plan_id,
                    Some(bundle_id),
                    owner_token.clone(),
                    snapshot_action_id,
                )
            }),
            "direct_manual" => Some(ExecutionAuthorization::manual_bundle(
                bundle_id,
                owner_token.clone(),
                snapshot_action_id,
            )),
            "automatic" => Some(ExecutionAuthorization::automatic(
                bundle_id,
                owner_token.clone(),
                snapshot_action_id,
            )),
            "rollback" => authorization_plan_id.map(|plan_id| {
                ExecutionAuthorization::manual(
                    plan_id,
                    Some(bundle_id),
                    owner_token.clone(),
                    snapshot_action_id,
                )
            }),
            "recovery" => Some(ExecutionAuthorization::recovery(
                bundle_id,
                owner_token.clone(),
                snapshot_action_id,
            )),
            "manual_recovery" => Some(ExecutionAuthorization::manual_recovery(
                bundle_id,
                owner_token.clone(),
                snapshot_action_id,
            )),
            _ => None,
        };
        let action_trigger_type = match trigger_type {
            "recovery" => "rollback",
            "manual_recovery" => "rollback",
            "direct_manual" => "manual",
            other => other,
        };

        let req = ActionRequest {
            device_id,
            template: action.template,
            params: action.params,
            trigger_type: action_trigger_type,
            rule_id,
            rule_event_id,
            rollback_of_reroute_id: action.original_reroute_id,
            user_id,
            actor_context: actor_context.clone(),
            reason: Some(action.reason),
            defer_cooldown: true,
            bundle: Some(BundleMembership {
                bundle_id,
                position,
            }),
            authorization,
        };

        let outcome = executor::execute_with(pool, cfg, &locked_ssh, req, false).await;
        if outcome.executed {
            acted_devices.push(outcome.device_id);
        }
        let succeeded = outcome.state.as_deref() == Some("succeeded");
        let changed = outcome.mutation_effect.as_deref() == Some("changed");
        let ambiguous = outcome.state.as_deref() == Some("uncertain")
            || outcome.mutation_effect.as_deref() == Some("unknown")
            || (!succeeded && changed);
        if succeeded && changed && !inverse_action {
            if let Some(reroute_id) = outcome.reroute_id {
                applied.push(AppliedSibling {
                    reroute_id,
                    position,
                });
            }
        }
        if succeeded {
            succeeded_prepared.push(prepared_for_proof);
        }
        if ambiguous {
            freeze_on_ambiguity = outcome.reroute_id;
        }
        if !succeeded {
            any_failure = true;
            corrective_failure |= inverse_action;
        }

        if let Some(action_id) = snapshot_action_id {
            let snapshot_state = if outcome.state.as_deref() == Some("uncertain") {
                "uncertain"
            } else if succeeded && outcome.mutation_effect.as_deref() == Some("noop") {
                "noop"
            } else if succeeded {
                "succeeded"
            } else {
                "failed"
            };
            let _ = sqlx::query(
                "UPDATE reroute_bundle_actions SET state = ?, mutation_effect = ?, \
                        reroute_id = ?, failure_reason = ? WHERE id = ?",
            )
            .bind(snapshot_state)
            .bind(outcome.mutation_effect.as_deref().unwrap_or("unknown"))
            .bind(outcome.reroute_id)
            .bind(&outcome.blocked_reason)
            .bind(action_id)
            .execute(pool)
            .await;
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

        if ambiguous || (!succeeded && policy != FailurePolicy::Continue) {
            let why = outcome
                .blocked_reason
                .clone()
                .unwrap_or_else(|| outcome.message.clone());
            stopped_at = Some((position, why));
            break;
        }
    }

    if stopped_at.is_none() && !any_failure && !succeeded_prepared.is_empty() {
        match locked_ssh.verify_projected_after(&succeeded_prepared).await {
            Ok(true) => {}
            Ok(false) => {
                projected_state_lost = true;
                stopped_at = Some((
                    u32::MAX,
                    "final projected bundle state no longer matches the routers".into(),
                ));
            }
            Err(e) => {
                projected_state_lost = true;
                stopped_at = Some((
                    u32::MAX,
                    format!("could not prove final projected bundle state: {e}"),
                ));
            }
        }
    }
    if stopped_at.is_none() && requires_corrective_closure(trigger_type) {
        match outstanding_owned_originals(pool, bundle_id).await {
            Ok(outstanding) if outstanding.is_empty() => {}
            Ok(_) => {
                corrective_failure = true;
                stopped_at = Some((
                    u32::MAX,
                    "corrective bundle finished without closing every original mutation".into(),
                ));
            }
            Err(e) => {
                corrective_failure = true;
                stopped_at = Some((
                    u32::MAX,
                    format!("could not prove corrective ownership closure: {e}"),
                ));
            }
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
        if any_failure {
            let summary = "one or more actions failed under continue policy".to_string();
            let still: Vec<u64> = applied.iter().map(|a| a.reroute_id).collect();
            if let Err(finalize) =
                finish_and_release(pool, bundle_id, "aborted", Some(&summary), &owner_token).await
            {
                let _ = locks::set_bundle_change_window_phase(
                    pool,
                    bundle_id,
                    &owner_token,
                    "uncertain",
                )
                .await;
                drop(locked_ssh);
                let _ = native_locks.unlock_all().await;
                return finalization_failure_outcome(bundle_id, results, still, finalize);
            }
            if !still.is_empty() {
                alert_still_applied(pool, bundle_id, &still, &summary).await;
            }
            drop(locked_ssh);
            let _ = native_locks.unlock_all().await;
            return BundleOutcome {
                bundle_id,
                state: "aborted".into(),
                results,
                still_applied: still,
                failure_reason: Some(summary),
            };
        }
        let finalized = if force_terminal_persistence_failure {
            Err(anyhow::anyhow!("injected terminal persistence failure"))
        } else {
            finish_and_release(pool, bundle_id, "succeeded", None, &owner_token).await
        };
        if let Err(finalize) = finalized {
            let _ =
                locks::set_bundle_change_window_phase(pool, bundle_id, &owner_token, "uncertain")
                    .await;
            drop(locked_ssh);
            let _ = native_locks.unlock_all().await;
            return finalization_failure_outcome(bundle_id, results, Vec::new(), finalize);
        }
        if let Err(e) = super::recovery::schedule_if_eligible(pool, bundle_id).await {
            tracing::error!(event_type="bundle_lifecycle_refresh_failed",bundle_id,error=%e);
        }
        drop(locked_ssh);
        let _ = native_locks.unlock_all().await;
        return BundleOutcome {
            bundle_id,
            state: "succeeded".into(),
            results,
            still_applied: Vec::new(),
            failure_reason: None,
        };
    };

    let summary = format!("stopped at action #{failed_position}: {why}");

    if corrective_failure {
        let outstanding = outstanding_owned_originals(pool, bundle_id)
            .await
            .unwrap_or_default();
        let still: Vec<u64> = outstanding.into_iter().map(|(id, _)| id).collect();
        let _ =
            locks::set_bundle_change_window_phase(pool, bundle_id, &owner_token, "uncertain").await;
        if let Err(e) =
            finish_blocked_with_alert(pool, bundle_id, &still, &summary, &owner_token).await
        {
            let _ =
                locks::set_bundle_change_window_phase(pool, bundle_id, &owner_token, "uncertain")
                    .await;
            drop(locked_ssh);
            let _ = native_locks.unlock_all().await;
            return finalization_failure_outcome(bundle_id, results, still, e);
        }
        drop(locked_ssh);
        let _ = native_locks.unlock_all().await;
        return BundleOutcome {
            bundle_id,
            state: "compensation_blocked".into(),
            results,
            still_applied: still,
            failure_reason: Some(summary),
        };
    }

    // Once any sibling has an unknown or partially-applied effect, NO further
    // router write is safe, including rollback on another device. The uncertain
    // command may have removed the old path already; undoing an earlier additive
    // sibling could remove the last viable path.
    if freeze_on_ambiguity.is_some() || projected_state_lost {
        let mut still: Vec<u64> = applied.iter().map(|a| a.reroute_id).collect();
        if let Some(ambiguous_id) = freeze_on_ambiguity {
            if !still.contains(&ambiguous_id) {
                still.push(ambiguous_id);
            }
        }
        if projected_state_lost {
            if let Err(e) = quarantine_changed_actions(pool, &applied, &summary).await {
                tracing::error!(event_type="bundle_projected_state_quarantine_failed", bundle_id, error=%e, "changed actions remain protected by bundle device windows");
            }
        }
        let _ =
            locks::set_bundle_change_window_phase(pool, bundle_id, &owner_token, "uncertain").await;
        if let Err(e) =
            finish_blocked_with_alert(pool, bundle_id, &still, &summary, &owner_token).await
        {
            let _ =
                locks::set_bundle_change_window_phase(pool, bundle_id, &owner_token, "uncertain")
                    .await;
            drop(locked_ssh);
            let _ = native_locks.unlock_all().await;
            return finalization_failure_outcome(bundle_id, results, still, e);
        }
        drop(locked_ssh);
        let _ = native_locks.unlock_all().await;
        return BundleOutcome {
            bundle_id,
            state: "compensation_blocked".into(),
            results,
            still_applied: still,
            failure_reason: Some(summary),
        };
    }

    // `Abort` leaves applied siblings deliberately; with nothing applied there is
    // nothing to compensate either way.
    if policy == FailurePolicy::Abort || applied.is_empty() {
        if let Err(finalize) =
            finish_and_release(pool, bundle_id, "aborted", Some(&summary), &owner_token).await
        {
            let _ =
                locks::set_bundle_change_window_phase(pool, bundle_id, &owner_token, "uncertain")
                    .await;
            drop(locked_ssh);
            let _ = native_locks.unlock_all().await;
            let still: Vec<u64> = applied.iter().map(|a| a.reroute_id).collect();
            return finalization_failure_outcome(bundle_id, results, still, finalize);
        }
        let still: Vec<u64> = applied.iter().map(|a| a.reroute_id).collect();
        if !still.is_empty() {
            alert_still_applied(pool, bundle_id, &still, &summary).await;
        }
        drop(locked_ssh);
        let _ = native_locks.unlock_all().await;
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
    let _ =
        locks::set_bundle_change_window_phase(pool, bundle_id, &owner_token, "compensating").await;

    let mut still_applied: Vec<u64> = Vec::new();
    // Reverse order: undo the most recent change first, so intermediate states
    // mirror the way the bundle was built up.
    for (reverse_index, sibling) in applied.iter().rev().enumerate() {
        let req = rollback::PersistedRollbackRequest {
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
            authorization: Some(ExecutionAuthorization::compensation(
                bundle_id,
                owner_token.clone(),
            )),
        };
        match rollback::rollback_persisted_with(pool, cfg, &locked_ssh, req).await {
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
                let remaining = applied.len().saturating_sub(reverse_index + 1);
                still_applied.extend(applied[..remaining].iter().map(|item| item.reroute_id));
                break;
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
                let remaining = applied.len().saturating_sub(reverse_index + 1);
                still_applied.extend(applied[..remaining].iter().map(|item| item.reroute_id));
                break;
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
                let remaining = applied.len().saturating_sub(reverse_index + 1);
                still_applied.extend(applied[..remaining].iter().map(|item| item.reroute_id));
                break;
            }
        }
    }

    let state = if still_applied.is_empty() {
        "compensated"
    } else {
        "compensation_blocked"
    };
    if !still_applied.is_empty() {
        if let Err(e) =
            finish_blocked_with_alert(pool, bundle_id, &still_applied, &summary, &owner_token).await
        {
            let _ =
                locks::set_bundle_change_window_phase(pool, bundle_id, &owner_token, "uncertain")
                    .await;
            drop(locked_ssh);
            let _ = native_locks.unlock_all().await;
            return finalization_failure_outcome(bundle_id, results, still_applied, e);
        }
        let _ =
            locks::set_bundle_change_window_phase(pool, bundle_id, &owner_token, "uncertain").await;
    } else {
        if let Err(finalize) =
            finish_and_release(pool, bundle_id, state, Some(&summary), &owner_token).await
        {
            let _ =
                locks::set_bundle_change_window_phase(pool, bundle_id, &owner_token, "uncertain")
                    .await;
            drop(locked_ssh);
            let _ = native_locks.unlock_all().await;
            return finalization_failure_outcome(bundle_id, results, Vec::new(), finalize);
        }
    }
    drop(locked_ssh);
    let _ = native_locks.unlock_all().await;

    BundleOutcome {
        bundle_id,
        state: state.into(),
        results,
        still_applied,
        failure_reason: Some(summary),
    }
}

async fn validate_manual_snapshot(
    pool: &MySqlPool,
    plan_id: u64,
    bundle_id: u64,
    actions: &[BundleAction],
) -> anyhow::Result<()> {
    let snapshot: sqlx::types::Json<Value> = sqlx::query_scalar(
        "SELECT snapshot_json FROM execution_plans \
         WHERE id = ? AND bundle_id = ? AND consumed_at IS NOT NULL",
    )
    .bind(plan_id)
    .bind(bundle_id)
    .fetch_one(pool)
    .await?;
    let expected_actions = snapshot
        .0
        .get("actions")
        .ok_or_else(|| anyhow::anyhow!("plan has no action snapshot"))?;
    anyhow::ensure!(
        serde_json::to_value(actions)? == *expected_actions,
        "runner actions differ from the consumed plan"
    );
    let expected_devices = snapshot
        .0
        .get("device_actions")
        .ok_or_else(|| anyhow::anyhow!("plan has no device action snapshot"))?;
    let actual_devices: Vec<_> = actions
        .iter()
        .map(|action| {
            action
                .prepared
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("action has no prepared device snapshot"))
        })
        .collect::<anyhow::Result<_>>()?;
    anyhow::ensure!(
        serde_json::to_value(actual_devices)? == *expected_devices,
        "prepared device sequence differs from the consumed plan"
    );
    let bundle_source: Option<sqlx::types::Json<Value>> =
        sqlx::query_scalar("SELECT source_json FROM reroute_bundles WHERE id = ?")
            .bind(bundle_id)
            .fetch_optional(pool)
            .await?;
    anyhow::ensure!(
        bundle_source.map(|source| source.0) == snapshot.0.get("source").cloned(),
        "bundle source/revision differs from the consumed plan"
    );
    Ok(())
}

pub(crate) async fn finish_and_release(
    pool: &MySqlPool,
    bundle_id: u64,
    state: &str,
    failure_reason: Option<&str>,
    owner_token: &str,
) -> anyhow::Result<()> {
    let recovery_sources: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM recovery_attempt_sources WHERE recovery_bundle_id=?",
    )
    .bind(bundle_id)
    .fetch_one(pool)
    .await?;
    if recovery_sources > 0 {
        return super::recovery::finalize_recovery_child(
            pool,
            bundle_id,
            state,
            failure_reason,
            owner_token,
        )
        .await;
    }
    let mut tx = pool.begin().await?;
    let updated = sqlx::query(
        "UPDATE reroute_bundles SET state = ?, failure_reason = ?, \
                finished_at = UTC_TIMESTAMP(), rate_reserved_actions = 0 WHERE id = ? \
          AND state IN ('planned','running','compensating')",
    )
    .bind(state)
    .bind(failure_reason)
    .bind(bundle_id)
    .execute(&mut *tx)
    .await?;
    anyhow::ensure!(
        updated.rows_affected() == 1,
        "bundle terminal state conflict"
    );
    sqlx::query("DELETE membership FROM device_change_window_sources membership WHERE membership.source_bundle_id=? AND (?='succeeded' OR NOT EXISTS(SELECT 1 FROM reroutes original WHERE original.bundle_id=? AND original.rollback_of_reroute_id IS NULL AND original.mutation_effect IN ('changed','unknown') AND NOT EXISTS(SELECT 1 FROM reroutes inverse WHERE inverse.rollback_of_reroute_id=original.id AND inverse.state='succeeded' AND inverse.mutation_effect IN ('changed','noop'))))")
        .bind(bundle_id).bind(state).bind(bundle_id).execute(&mut *tx).await?;
    sqlx::query("DELETE w FROM device_change_windows w WHERE w.bundle_id=? AND w.owner_token=? AND NOT EXISTS(SELECT 1 FROM device_change_window_sources membership WHERE membership.device_id=w.device_id)")
        .bind(bundle_id).bind(owner_token).execute(&mut *tx).await?;
    sqlx::query("UPDATE device_change_windows SET bundle_id=NULL,reroute_id=NULL,owner_token=CONCAT('quarantine:device:',device_id),phase='uncertain' WHERE bundle_id=? AND owner_token=?")
        .bind(bundle_id).bind(owner_token).execute(&mut *tx).await?;
    tx.commit().await?;
    super::recovery::refresh(pool, bundle_id).await?;
    Ok(())
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

async fn finish_blocked_with_alert(
    pool: &MySqlPool,
    bundle_id: u64,
    still: &[u64],
    summary: &str,
    owner_token: &str,
) -> anyhow::Result<()> {
    let recovery_sources: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM recovery_attempt_sources WHERE recovery_bundle_id=?",
    )
    .bind(bundle_id)
    .fetch_one(pool)
    .await?;
    if recovery_sources > 0 {
        return super::recovery::finalize_recovery_child(
            pool,
            bundle_id,
            "compensation_blocked",
            Some(summary),
            owner_token,
        )
        .await;
    }
    let payload = json!({
        "bundle_id": bundle_id,
        "still_applied_reroute_ids": still,
        "reason": summary,
        "operator_action": "reconcile ambiguous actions before any recovery write",
    });
    let mut tx = pool.begin().await?;
    let updated = sqlx::query(
        "UPDATE reroute_bundles SET state = 'compensation_blocked', failure_reason = ?, \
                finished_at = UTC_TIMESTAMP(), rate_reserved_actions = 0 \
          WHERE id = ? AND state IN ('planned','running','compensating')",
    )
    .bind(summary)
    .bind(bundle_id)
    .execute(&mut *tx)
    .await?;
    anyhow::ensure!(
        updated.rows_affected() == 1,
        "bundle terminal state conflict"
    );
    sqlx::query(
        "INSERT INTO alerts (event_type, severity, payload_json, dedup_key) \
         VALUES ('reroute_bundle_partial', 'critical', ?, ?)",
    )
    .bind(sqlx::types::Json(payload))
    .bind(format!("reroute_bundle_partial:{bundle_id}"))
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO audit_logs \
            (actor_type, event_type, entity_type, entity_id, message) \
         VALUES ('system', 'reroute_bundle_partial', 'reroute_bundle', ?, ?)",
    )
    .bind(bundle_id)
    .bind(format!(
        "bundle #{bundle_id} left {} changed or ambiguous action(s): {summary}",
        still.len()
    ))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

async fn quarantine_changed_actions(
    pool: &MySqlPool,
    applied: &[AppliedSibling],
    reason: &str,
) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    for sibling in applied {
        let device_id: u64 = sqlx::query_scalar(
            "SELECT device_id FROM reroutes WHERE id = ? AND state = 'succeeded' \
             AND mutation_effect = 'changed' FOR UPDATE",
        )
        .bind(sibling.reroute_id)
        .fetch_one(&mut *tx)
        .await?;
        let updated = sqlx::query(
            "UPDATE reroutes SET state = 'uncertain', success = NULL, \
                    verification_status = 'uncertain', mutation_effect = 'unknown', \
                    failure_reason = ? WHERE id = ? AND state = 'succeeded'",
        )
        .bind(format!(
            "bundle projected state lost after verification: {reason}"
        ))
        .bind(sibling.reroute_id)
        .execute(&mut *tx)
        .await?;
        anyhow::ensure!(
            updated.rows_affected() == 1,
            "changed reroute state conflict"
        );
        sqlx::query(
            "UPDATE reroute_bundle_actions SET state = 'uncertain', mutation_effect = 'unknown', \
                    failure_reason = ? WHERE reroute_id = ?",
        )
        .bind(reason)
        .bind(sibling.reroute_id)
        .execute(&mut *tx)
        .await?;
        crate::reroute::locks::create_on(
            &mut tx,
            "device",
            Some(&device_id.to_string()),
            Some(sibling.reroute_id),
            "auto_uncertain",
            &format!(
                "reroute #{} lost its bundle-level projected-state proof",
                sibling.reroute_id
            ),
            None,
        )
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

#[doc(hidden)]
pub async fn settle_source_activations(
    pool: &MySqlPool,
    recovery_bundle_id: u64,
) -> anyhow::Result<()> {
    let mapped: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM recovery_attempt_sources WHERE recovery_bundle_id=?",
    )
    .bind(recovery_bundle_id)
    .fetch_one(pool)
    .await?;
    if mapped > 0 {
        let owner: Option<String> = sqlx::query_scalar(
            "SELECT owner_token FROM device_change_windows WHERE bundle_id=? LIMIT 1",
        )
        .bind(recovery_bundle_id)
        .fetch_optional(pool)
        .await?;
        return super::recovery::finalize_recovery_child(
            pool,
            recovery_bundle_id,
            "succeeded",
            Some("all original mutations were verified restored"),
            owner.as_deref().unwrap_or("legacy-settlement"),
        )
        .await;
    }
    let source_bundles: Vec<u64> = sqlx::query_scalar(
        "SELECT DISTINCT original.bundle_id \
           FROM reroute_bundle_actions ba \
           JOIN reroutes original ON original.id = ba.original_reroute_id \
          WHERE ba.bundle_id = ? AND original.bundle_id IS NOT NULL",
    )
    .bind(recovery_bundle_id)
    .fetch_all(pool)
    .await?;
    for source_bundle in source_bundles {
        anyhow::ensure!(
            outstanding_owned_originals(pool, source_bundle)
                .await?
                .is_empty(),
            "source bundle #{source_bundle} still owns unresolved mutations"
        );
        let mut tx = pool.begin().await?;
        sqlx::query(
            "UPDATE reroute_bundles SET state = 'compensated', finished_at = UTC_TIMESTAMP(), \
                    failure_reason = CONCAT(COALESCE(failure_reason,''), \
                        ' | all original mutations were verified restored') \
              WHERE id = ? AND state IN ('aborted','compensation_blocked')",
        )
        .bind(source_bundle)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM device_change_windows WHERE bundle_id = ?")
            .bind(source_bundle)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM device_change_window_sources WHERE source_bundle_id=?")
            .bind(source_bundle)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        super::recovery::refresh(pool, source_bundle).await?;
        sqlx::query(
            "UPDATE reroute_bundles SET lifecycle_state='inactive',remaining_mutations=0, \
                recovery_claim_token=NULL,automatic_recovery_block_reason=NULL WHERE id=?",
        )
        .bind(source_bundle)
        .execute(pool)
        .await?;
    }
    Ok(())
}

/// Bundles caught mid-flight by a restart. Their in-flight siblings are already
/// marked `uncertain` (and their devices locked) by
/// [`super::state_machine::recover_on_startup`]; this closes the bundle row so the
/// UI never shows a mitigation as still progressing after a crash.
pub async fn recover_on_startup(pool: &MySqlPool) -> anyhow::Result<()> {
    super::recovery::repair_legacy_associations(pool).await?;
    let recovery_children: Vec<(u64,String)> = sqlx::query_as(
        "SELECT DISTINCT child.id,child.state FROM reroute_bundles child JOIN recovery_attempt_sources ras ON ras.recovery_bundle_id=child.id WHERE ras.settlement='active' ORDER BY child.id",
    ).fetch_all(pool).await?;
    for (child_id, state) in recovery_children {
        let owner_token: Option<String> = sqlx::query_scalar("SELECT owner_token FROM device_change_windows WHERE bundle_id=? ORDER BY device_id LIMIT 1")
            .bind(child_id).fetch_optional(pool).await?;
        let terminal = match state.as_str() {
            "succeeded" => "succeeded",
            "failed" | "aborted" => "failed",
            _ => "compensation_blocked",
        };
        super::recovery::finalize_recovery_child(
            pool,
            child_id,
            terminal,
            Some("startup repaired recovery ownership"),
            owner_token.as_deref().unwrap_or("startup-repair"),
        )
        .await?;
    }
    let bundles: Vec<u64> = sqlx::query_scalar(
        "SELECT id FROM reroute_bundles \
         WHERE state IN ('planned', 'running', 'compensating') ORDER BY id",
    )
    .fetch_all(pool)
    .await?;
    for bundle_id in &bundles {
        let outstanding = outstanding_owned_originals(pool, *bundle_id).await?;
        let mut tx = pool.begin().await?;
        let blocked = !outstanding.is_empty();
        let state = if blocked {
            "compensation_blocked"
        } else {
            "aborted"
        };
        let reason = if blocked {
            "controller restarted mid-bundle; changed or ambiguous siblings require reconciliation"
        } else {
            "controller restarted before any owned router mutation remained"
        };
        let updated = sqlx::query(
            "UPDATE reroute_bundles SET state = ?, finished_at = UTC_TIMESTAMP(), \
                    interrupted_at = UTC_TIMESTAMP(), failure_reason = ?, \
                    rate_reserved_actions = 0 \
              WHERE id = ? AND state IN ('planned', 'running', 'compensating')",
        )
        .bind(state)
        .bind(reason)
        .bind(bundle_id)
        .execute(&mut *tx)
        .await?;
        anyhow::ensure!(
            updated.rows_affected() == 1,
            "bundle changed during recovery"
        );
        sqlx::query("UPDATE reroute_bundles parent JOIN reroute_bundles child ON child.parent_bundle_id=parent.id \
            SET parent.lifecycle_state='recovery_blocked',parent.automatic_recovery_block_reason=? \
            WHERE child.id=?")
            .bind(reason).bind(bundle_id).execute(&mut *tx).await?;

        if blocked {
            let owner_token = format!("recovery:bundle:{bundle_id}");
            let mut devices: Vec<u64> = outstanding.iter().map(|(_, device)| *device).collect();
            devices.sort_unstable();
            devices.dedup();
            for device_id in devices {
                let owner: Option<(Option<u64>, String)> = sqlx::query_as(
                    "SELECT bundle_id, owner_token FROM device_change_windows \
                     WHERE device_id = ? FOR UPDATE",
                )
                .bind(device_id)
                .fetch_optional(&mut *tx)
                .await?;
                match owner {
                    Some((Some(owner_bundle), _)) if owner_bundle == *bundle_id => {
                        sqlx::query(
                            "UPDATE device_change_windows SET phase = 'uncertain' \
                             WHERE device_id = ? AND bundle_id = ?",
                        )
                        .bind(device_id)
                        .bind(bundle_id)
                        .execute(&mut *tx)
                        .await?;
                    }
                    Some((owner_bundle, token)) => anyhow::bail!(
                        "device {device_id} has foreign change-window owner {owner_bundle:?}/{token}"
                    ),
                    None => {
                        sqlx::query(
                            "INSERT INTO device_change_windows \
                                (device_id, bundle_id, owner_token, phase) \
                             VALUES (?, ?, ?, 'uncertain')",
                        )
                        .bind(device_id)
                        .bind(bundle_id)
                        .bind(&owner_token)
                        .execute(&mut *tx)
                        .await?;
                    }
                }
            }
            let ids: Vec<u64> = outstanding.iter().map(|(id, _)| *id).collect();
            let payload = json!({
                "bundle_id": bundle_id,
                "still_applied_or_ambiguous_reroute_ids": ids,
                "reason": reason,
                "operator_action": "reconcile every listed action before releasing device change windows",
            });
            sqlx::query(
                "INSERT INTO alerts (event_type, severity, payload_json, dedup_key) \
                 VALUES ('reroute_bundle_partial', 'critical', ?, ?)",
            )
            .bind(sqlx::types::Json(payload))
            .bind(format!("reroute_bundle_interrupted:{bundle_id}"))
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO audit_logs \
                    (actor_type, event_type, entity_type, entity_id, message) \
                 VALUES ('system', 'reroute_bundle_interrupted', 'reroute_bundle', ?, ?)",
            )
            .bind(bundle_id)
            .bind(format!(
                "bundle #{bundle_id} interrupted with {} changed or ambiguous action(s)",
                outstanding.len()
            ))
            .execute(&mut *tx)
            .await?;
        } else {
            sqlx::query("DELETE FROM device_change_windows WHERE bundle_id = ?")
                .bind(bundle_id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
    }
    if !bundles.is_empty() {
        tracing::warn!(
            event_type = "bundle_recovery_aborted",
            count = bundles.len(),
            "closed in-flight mitigation bundles after restart"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn verified_success_releases_only_its_membership_for_serial_activation() {
        let database = crate::db::connect_test_database().await;
        let pool = (*database).clone();
        let device =
            sqlx::query("INSERT INTO devices(name,hostname,enabled) VALUES(?, '127.0.0.1', 0)")
                .bind(format!("serial-success-{}", uuid::Uuid::new_v4()))
                .execute(&pool)
                .await
                .unwrap()
                .last_insert_id();
        let first = sqlx::query("INSERT INTO reroute_bundles(trigger_type,state,total_actions,lifecycle_state) VALUES('manual','running',1,'active')")
            .execute(&pool).await.unwrap().last_insert_id();
        let first_owner = format!("test:first:{first}");
        locks::acquire_bundle_change_windows(&pool, first, &first_owner, &[device])
            .await
            .unwrap();
        sqlx::query("INSERT INTO reroutes(device_id,bundle_id,bundle_position,trigger_type,state,mutation_effect) VALUES(?,?,0,'manual','succeeded','changed')")
            .bind(device).bind(first).execute(&pool).await.unwrap();
        finish_and_release(&pool, first, "succeeded", None, &first_owner)
            .await
            .unwrap();

        let second = sqlx::query("INSERT INTO reroute_bundles(trigger_type,state,total_actions,lifecycle_state) VALUES('manual','running',0,'active')")
            .execute(&pool).await.unwrap().last_insert_id();
        let second_owner = format!("test:second:{second}");
        locks::acquire_bundle_change_windows(&pool, second, &second_owner, &[device])
            .await
            .expect("a fully verified prior activation must not quarantine the device");

        let foreign = sqlx::query("INSERT INTO reroute_bundles(trigger_type,state,total_actions,lifecycle_state) VALUES('manual','compensation_blocked',1,'recovery_blocked')")
            .execute(&pool).await.unwrap().last_insert_id();
        sqlx::query(
            "INSERT INTO device_change_window_sources(device_id,source_bundle_id) VALUES(?,?)",
        )
        .bind(device)
        .bind(foreign)
        .execute(&pool)
        .await
        .unwrap();
        finish_and_release(&pool, second, "succeeded", None, &second_owner)
            .await
            .unwrap();
        let window: (Option<u64>, String, String) = sqlx::query_as(
            "SELECT bundle_id,owner_token,phase FROM device_change_windows WHERE device_id=?",
        )
        .bind(device)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            window,
            (
                None,
                format!("quarantine:device:{device}"),
                "uncertain".into()
            )
        );
        let third = sqlx::query("INSERT INTO reroute_bundles(trigger_type,state,total_actions,lifecycle_state) VALUES('manual','planned',0,'active')")
            .execute(&pool).await.unwrap().last_insert_id();
        let blocked = locks::acquire_bundle_change_windows(
            &pool,
            third,
            &format!("test:third:{third}"),
            &[device],
        )
        .await;
        assert!(
            blocked
                .unwrap_err()
                .to_string()
                .contains("retains recovery ownership"),
            "releasing one successful source must preserve a foreign quarantine"
        );
        sqlx::query("DELETE FROM device_change_windows WHERE device_id=?")
            .bind(device)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM device_change_window_sources WHERE device_id=?")
            .bind(device)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM reroutes WHERE bundle_id=?")
            .bind(first)
            .execute(&pool)
            .await
            .unwrap();
        for id in [first, second, third, foreign] {
            sqlx::query("DELETE FROM reroute_bundles WHERE id=?")
                .bind(id)
                .execute(&pool)
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM devices WHERE id=?")
            .bind(device)
            .execute(&pool)
            .await
            .unwrap();
    }

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

    #[test]
    fn recovery_constructor_binds_corrective_authority() {
        let run = BundleRun::automatic_recovery(11, FailurePolicy::AbortAndCompensate, 7);
        assert_eq!(run.trigger_type, "recovery");
        assert_eq!(run.rule_id, Some(7));
        assert!(run.user_id.is_none());
        assert!(run.authorization_plan_id.is_none());
    }

    #[test]
    fn mss_phases_allow_multi_router_add_and_cleanup_ordering() {
        assert_eq!(safety_phase("iface_tcp_adjust_mss").1, 0);
        assert_eq!(safety_phase("bgp_advertise_add").1, 0);
        assert_eq!(safety_phase("bgp_advertise_remove").1, 2);
        assert_eq!(safety_phase("iface_tcp_adjust_mss_remove").1, 2);
    }

    #[test]
    fn direct_workflows_keep_reviewed_bundle_level_proofs() {
        assert!(requires_replacement_reproof("manual"));
        assert!(requires_replacement_reproof("direct_manual"));
        assert!(requires_replacement_reproof("automatic"));
        assert!(!requires_replacement_reproof("manual_recovery"));

        assert!(requires_corrective_closure("rollback"));
        assert!(requires_corrective_closure("recovery"));
        assert!(requires_corrective_closure("manual_recovery"));
        assert!(!requires_corrective_closure("direct_manual"));
    }
}
