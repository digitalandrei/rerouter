//! Reroute executor. Re-checks EVERY safety gate at execution time, drives the
//! two-phase state machine, persists each step's output, and runs verification.
//! See ../docs/reroute-engine.md.
//!
//! Gate order (device_cli, device-scoped — any failure aborts and is logged):
//!   GATE 0 — unattended execution requires operating_mode == enforce. Manual
//!   reviewed apply/revert uses an actor-bound preview token; direct operator
//!   actions use a durable actor-bound bundle published before preparation.
//!   `execute` returns the would-run plan instead. Then: not dry-run | no global
//!   maintenance lock | device not locked | no action already running on the
//!   device | no unresolved `uncertain` on the device | not in cooldown. The
//!   caller (api/reroutes.rs) additionally enforces the `trigger_manual_reroute`
//!   permission and records the operator's reason BEFORE calling execute.
//!
//! Verify, don't assume: after pushing config we open a separate read-only
//! session and run the template's `show` check. The FINAL state is decided from
//! that read, not from "the commands were sent". Ambiguity => `uncertain` + a
//! device lock that an admin must acknowledge.

use serde_json::{json, Value};
use sqlx::MySqlPool;

use crate::config::Config;
use crate::detection::cooldown;
use crate::reroute::guard;
use crate::reroute::locks;
use crate::reroute::templates::{RenderedPlan, Template, VerifyStep};
use crate::ssh::{
    LockedDeviceSetPort, ResolvedApply, RusshExecutor, SessionPlan, SshExecutor, SshOutcome,
};

/// Adapter that runs the existing state machine through a retained set of native
/// IOS configuration-lock sessions. Bundle orchestration owns the lock set; this
/// adapter only serializes mutable access to it.
pub struct LockedSshExecutor<'a> {
    locked: tokio::sync::Mutex<&'a mut dyn LockedDeviceSetPort>,
}

impl<'a> LockedSshExecutor<'a> {
    pub fn new(locked: &'a mut dyn LockedDeviceSetPort) -> Self {
        Self {
            locked: tokio::sync::Mutex::new(locked),
        }
    }

    pub async fn verify_projected_after(
        &self,
        actions: &[crate::reroute::device_plan::PreparedDeviceAction],
    ) -> anyhow::Result<bool> {
        let mut locked = self.locked.lock().await;
        crate::reroute::device_plan::verify_projected_after(&mut **locked, actions).await
    }
}

// An explicit Drop impl makes the retained mutable-session borrow boundary
// visible to orchestration before it consumes the underlying lock set.
impl Drop for LockedSshExecutor<'_> {
    fn drop(&mut self) {}
}

impl SshExecutor for LockedSshExecutor<'_> {
    async fn apply(&self, device_id: u64, commands: &[String]) -> anyhow::Result<SshOutcome> {
        self.locked.lock().await.execute(device_id, commands).await
    }

    async fn verify_read(&self, device_id: u64, command: &str) -> anyhow::Result<String> {
        let result = self.locked.lock().await.read(device_id, command).await?;
        Ok(result.output)
    }

    async fn apply_resolved<'a>(
        &'a self,
        device_id: u64,
        read_command: &'a str,
        resolve: crate::ssh::SessionResolver<'a>,
    ) -> anyhow::Result<ResolvedApply> {
        let mut locked = self.locked.lock().await;
        let read = locked.read(device_id, read_command).await?;
        let decision = resolve(read.output.clone()).await?;
        let mut results = vec![read];
        if let SessionPlan::Push(commands) = &decision {
            let pushed = locked.execute(device_id, commands).await?;
            results.extend(pushed.results);
        }
        Ok(ResolvedApply {
            outcome: SshOutcome {
                results,
                fingerprint: String::new(),
                pinned_now: false,
            },
            decision,
        })
    }

    fn execute_prepared<'a>(
        &'a self,
        action: &'a crate::reroute::device_plan::PreparedDeviceAction,
    ) -> crate::ssh::BoxFuture<'a, anyhow::Result<SshOutcome>> {
        Box::pin(async move {
            let mut locked = self.locked.lock().await;
            crate::reroute::device_plan::execute_prepared(&mut **locked, action).await
        })
    }

    fn execute_prepared_inverse<'a>(
        &'a self,
        device_id: u64,
        inverse: &'a crate::reroute::device_plan::PreparedInverse,
    ) -> crate::ssh::BoxFuture<'a, anyhow::Result<SshOutcome>> {
        Box::pin(async move {
            let mut locked = self.locked.lock().await;
            crate::reroute::device_plan::execute_inverse(&mut **locked, device_id, inverse).await
        })
    }
}

/// What to run and on whose behalf.
#[derive(Clone)]
pub struct ActionRequest {
    pub device_id: u64,
    pub template: Template,
    pub params: Value,
    /// "manual" | "rollback" | "automatic".
    pub trigger_type: &'static str,
    pub rule_id: Option<u64>,
    /// The exact `rule_events.id` firing edge that created this action.
    pub rule_event_id: Option<u64>,
    /// The original reroute this corrective action reverses.
    pub rollback_of_reroute_id: Option<u64>,
    pub user_id: Option<u64>,
    pub actor_context: Option<ActorContext>,
    pub reason: Option<String>,
    /// Rule action bundles record cooldowns once after the whole ordered batch.
    pub defer_cooldown: bool,
    /// Set when this action is one sibling of an ordered bundle — one authorized
    /// activation of a rule's whole action set. The guard excludes the bundle's
    /// own earlier siblings from cooldown history so a 14-action mitigation does
    /// not block itself after the first action (plan 015 / audit SPEC-13).
    pub bundle: Option<BundleMembership>,
    /// Durable authority for a real write. Manual writes name the consumed
    /// execution plan; unattended and compensating writes name their internal
    /// bundle authority. `None` is accepted only for previews.
    pub authorization: Option<ExecutionAuthorization>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionAuthorityKind {
    Manual,
    ManualBundle,
    ManualRecovery,
    Automatic,
    Compensation,
    Recovery,
}

/// Capability threaded from preview/activation admission to the executor.
/// `owner_token` is also the ownership key for device change windows.
#[derive(Debug, Clone)]
pub struct ExecutionAuthorization {
    pub kind: ExecutionAuthorityKind,
    pub plan_id: Option<u64>,
    pub bundle_id: Option<u64>,
    pub owner_token: String,
    pub snapshot_action_id: Option<u64>,
}

impl ExecutionAuthorization {
    pub fn manual(
        plan_id: u64,
        bundle_id: Option<u64>,
        owner_token: impl Into<String>,
        snapshot_action_id: Option<u64>,
    ) -> Self {
        Self {
            kind: ExecutionAuthorityKind::Manual,
            plan_id: Some(plan_id),
            bundle_id,
            owner_token: owner_token.into(),
            snapshot_action_id,
        }
    }

    pub fn automatic(
        bundle_id: u64,
        owner_token: impl Into<String>,
        snapshot_action_id: Option<u64>,
    ) -> Self {
        Self {
            kind: ExecutionAuthorityKind::Automatic,
            plan_id: None,
            bundle_id: Some(bundle_id),
            owner_token: owner_token.into(),
            snapshot_action_id,
        }
    }

    pub fn manual_bundle(
        bundle_id: u64,
        owner_token: impl Into<String>,
        snapshot_action_id: Option<u64>,
    ) -> Self {
        Self {
            kind: ExecutionAuthorityKind::ManualBundle,
            plan_id: None,
            bundle_id: Some(bundle_id),
            owner_token: owner_token.into(),
            snapshot_action_id,
        }
    }

    pub fn compensation(bundle_id: u64, owner_token: impl Into<String>) -> Self {
        Self {
            kind: ExecutionAuthorityKind::Compensation,
            plan_id: None,
            bundle_id: Some(bundle_id),
            owner_token: owner_token.into(),
            snapshot_action_id: None,
        }
    }

    pub fn manual_recovery(
        bundle_id: u64,
        owner_token: impl Into<String>,
        snapshot_action_id: Option<u64>,
    ) -> Self {
        Self {
            kind: ExecutionAuthorityKind::ManualRecovery,
            plan_id: None,
            bundle_id: Some(bundle_id),
            owner_token: owner_token.into(),
            snapshot_action_id,
        }
    }

    pub fn recovery(
        bundle_id: u64,
        owner_token: impl Into<String>,
        snapshot_action_id: Option<u64>,
    ) -> Self {
        Self {
            kind: ExecutionAuthorityKind::Recovery,
            plan_id: None,
            bundle_id: Some(bundle_id),
            owner_token: owner_token.into(),
            snapshot_action_id,
        }
    }
}

/// This action's place in an ordered bundle.
#[derive(Debug, Clone, Copy)]
pub struct BundleMembership {
    pub bundle_id: u64,
    /// Mirrors the originating `rule_actions.position`, so durable history keeps
    /// the order actually used even if the rule is edited later.
    pub position: u32,
}

#[derive(Debug, Clone)]
pub struct ActorContext {
    pub ip_address: String,
    pub user_agent: String,
}

/// Outcome of an `execute` attempt (serialized to the API caller).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ExecOutcome {
    pub executed: bool,
    pub reroute_id: Option<u64>,
    pub state: Option<String>,
    /// Whether this activation changed router configuration. A verified no-op is
    /// successful but is not owned state and therefore must never be inverted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mutation_effect: Option<String>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub would_run: Option<RenderedPlan>,
    /// The rollback (undo) command set for `would_run`, so an observe/dry-run
    /// preview can show how to reverse the action by hand. `None` when the
    /// template has no paired rollback.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub would_run_rollback: Option<RenderedPlan>,
    pub device_id: u64,
    pub device_name: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MutationEffect {
    Changed,
    Noop,
    Unknown,
}

impl MutationEffect {
    fn as_str(self) -> &'static str {
        match self {
            Self::Changed => "changed",
            Self::Noop => "noop",
            Self::Unknown => "unknown",
        }
    }
}

/// The reroute engine. Holds its SSH transport behind the [`SshExecutor`] seam
/// (real russh in prod, a fake in tests) plus the pool and config. Exposes one
/// public method, `execute`; the `ExecOutcome` contract is unchanged.
pub struct Rerouter<'a, S: SshExecutor> {
    pool: &'a MySqlPool,
    cfg: &'a Config,
    ssh: S,
}

impl<'a> Rerouter<'a, RusshExecutor> {
    /// Production constructor — builds the real russh adapter.
    pub fn new(pool: &'a MySqlPool, cfg: &'a Config) -> Self {
        Self {
            pool,
            cfg,
            ssh: RusshExecutor::new(pool.clone()),
        }
    }
}

impl<'a, S: SshExecutor> Rerouter<'a, S> {
    /// Inject a custom SSH executor (tests pass a fake).
    pub fn with_ssh(pool: &'a MySqlPool, cfg: &'a Config, ssh: S) -> Self {
        Self { pool, cfg, ssh }
    }

    /// Execute (or render/observe/dry-run) one action against one device.
    pub async fn execute(&self, req: ActionRequest, dry_run: bool) -> ExecOutcome {
        execute_with(self.pool, self.cfg, &self.ssh, req, dry_run).await
    }
}

/// Back-compat free function: build the real `Rerouter` and run it. Keeps the
/// existing call sites (manual API, detection engine, rollback) unchanged.
pub async fn execute(
    pool: &MySqlPool,
    cfg: &Config,
    req: ActionRequest,
    dry_run: bool,
) -> ExecOutcome {
    Rerouter::new(pool, cfg).execute(req, dry_run).await
}

/// Core orchestration, generic over the [`SshExecutor`] seam.
pub(crate) async fn execute_with<S: SshExecutor>(
    pool: &MySqlPool,
    cfg: &Config,
    ssh: &S,
    req: ActionRequest,
    dry_run: bool,
) -> ExecOutcome {
    let refused = req.clone();
    let runtime = match cfg.advisory_runtime(pool).await {
        Ok(value) => value,
        Err(error) => return blocked(&req, None, format!("lock runtime unavailable: {error}")),
    };
    match crate::db::advisory::foreground_scope(
        runtime,
        Box::pin(execute_with_inner(pool, cfg, ssh, req, dry_run)),
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) => blocked(
            &refused,
            None,
            format!("execution capacity unavailable: {error}"),
        ),
    }
}

async fn execute_with_inner<S: SshExecutor>(
    pool: &MySqlPool,
    cfg: &Config,
    ssh: &S,
    mut req: ActionRequest,
    dry_run: bool,
) -> ExecOutcome {
    let device_name = device_name(pool, req.device_id).await;

    if !req.template.enabled {
        return blocked(&req, device_name, "template is disabled".into());
    }
    if req.trigger_type == "automatic" && !req.template.automatic_allowed {
        return blocked(
            &req,
            device_name,
            "template is not allowed for automatic execution".into(),
        );
    }
    let mode = crate::api::settings::operating_mode(pool, cfg).await;
    let unattended = authority_is_unattended(pool, req.authorization.as_ref()).await;
    if dry_run || (mode != "enforce" && unattended) {
        // Preview-only compatibility path. Real execution below never re-renders
        // or mutates parameters; it consumes the authorized prepared snapshot.
        if req.trigger_type != "rollback" {
            req.params = match crate::reroute::templates::canonicalize_inventory_params(
                pool,
                req.device_id,
                &req.template,
                &req.params,
            )
            .await
            {
                Ok(params) => params,
                Err(e) => {
                    return blocked(
                        &req,
                        device_name,
                        format!("inventory validation failed: {e}"),
                    )
                }
            };
        }
        let plan = match crate::reroute::templates::render(&req.template, &req.params) {
            Ok(plan) => plan,
            Err(e) => return blocked(&req, device_name, format!("invalid parameters: {e}")),
        };
        let would_run_rollback =
            crate::reroute::rollback::render_rollback_plan(pool, req.template.id, &req.params)
                .await;
        let message = if dry_run {
            "dry run: rendered plan only, nothing executed"
        } else {
            "observe mode blocks unattended execution"
        };
        return ExecOutcome {
            executed: false,
            reroute_id: None,
            state: None,
            mutation_effect: None,
            message: message.into(),
            blocked_reason: None,
            would_run: Some(plan),
            would_run_rollback,
            device_id: req.device_id,
            device_name,
        };
    }

    // Serialize authorization, the final mutable policy reads, reservation and
    // device execution with every policy mutation. Held through exact verify.
    let policy_fence = match guard::policy_fence(pool).await {
        Ok(fence) => fence,
        Err(e) => {
            return blocked(
                &req,
                device_name,
                format!("execution policy fence unavailable: {e}"),
            )
        }
    };
    if unattended && crate::api::settings::operating_mode(pool, cfg).await != "enforce" {
        return blocked(
            &req,
            device_name,
            "operating mode changed to observe before execution".into(),
        );
    }
    if unattended
        && !crate::api::settings::bool_setting(
            pool,
            "automatic_actions_enabled",
            cfg.safety.automatic_actions_enabled,
        )
        .await
    {
        return blocked(
            &req,
            device_name,
            "automatic actions are globally disabled".into(),
        );
    }
    if let Err(e) = validate_execution_authorization(pool, cfg, &req).await {
        return blocked(
            &req,
            device_name,
            format!("execution authorization refused: {e}"),
        );
    }
    let prepared_action = match load_prepared_action(pool, &req).await {
        Ok(prepared) => {
            req.params = prepared.canonical_params.clone();
            prepared
        }
        Err(e) => {
            return blocked(
                &req,
                device_name,
                format!("prepared action snapshot refused: {e}"),
            )
        }
    };
    if prepared_action.verification_mode
        == crate::reroute::device_plan::VerificationMode::ConfigurationOnly
    {
        if !configuration_only_authority_allowed(unattended, req.rule_id) {
            return blocked(
                &req,
                device_name,
                "configuration-only verification cannot run through automatic authority, recovery, or rules".into(),
            );
        }
        let identity_allowed =
            self::configuration_test_identity_matches(pool, cfg, req.device_id).await;
        if !identity_allowed {
            return blocked(
                &req,
                device_name,
                "configuration-only device identity changed before execution".into(),
            );
        }
    }
    let plan = RenderedPlan {
        template_id: prepared_action.template_id,
        template_name: prepared_action.template_name.clone(),
        config_mode: false,
        commands: prepared_action.commands.clone(),
        verify: None,
        sequence_pending: false,
    };

    // Safety gates — gather the facts from the DB, then a PURE decision over them
    // (see reroute::guard). Order and semantics match the historical gates, so a
    // blocked action reports the same reason it always did.
    if let Err(reason) = guard::can_execute(pool, cfg, &req, &plan).await {
        return blocked(&req, device_name, reason.to_string());
    }

    // Reachability preflight (hard gate, every trigger type): a reroute pushes
    // config over SSH, so a device that does not answer SSH cannot be mitigated.
    // Refuse up front with a clear reason instead of reserving a slot and failing
    // mid-push. The 60s recency short-circuit inside `reachable_for_mitigation`
    // means bursts don't re-probe (and don't trip the device's SSH throttle).
    let reach = crate::reroute::reachability::reachable_for_mitigation(pool, req.device_id).await;
    if !reach.ssh_ok {
        let detail = reach.ssh_error.as_deref().unwrap_or("no SSH response");
        return blocked(
            &req,
            device_name,
            guard::BlockReason::DeviceUnreachable(detail.to_string()).to_string(),
        );
    }
    // Stability gate — AUTOMATIC triggers only. A device that is reachable but has
    // not been continuously so for the stability window (just recovered / flapping)
    // does not get auto-mitigated. Manual and rollback triggers bypass this (the
    // operator may act during the window; a manual rollback is corrective).
    if req.trigger_type == "automatic" && !reach.stable {
        return blocked(
            &req,
            device_name,
            guard::BlockReason::DeviceStabilizing.to_string(),
        );
    }

    // Reserve a slot under a per-device advisory lock (atomic re-check + INSERT).
    let reroute_id = match guard::reserve_and_persist(pool, cfg, &req, &plan).await {
        Ok(id) => id,
        Err(reason) => return blocked(&req, device_name, reason.to_string()),
    };
    if let Err(e) = audit(
        pool,
        &req,
        reroute_id,
        "reroute_planned",
        &format!(
            "planned '{}' on device {}",
            req.template.name, req.device_id
        ),
    )
    .await
    {
        return abort_reserved(
            pool,
            &req,
            reroute_id,
            device_name,
            format!("required pre-action audit could not be persisted: {e}"),
        )
        .await;
    }
    if let Err(e) =
        enqueue_alert(pool, &req, reroute_id, "reroute_started", "info", json!({})).await
    {
        return abort_reserved(
            pool,
            &req,
            reroute_id,
            device_name,
            format!("required pre-action alert could not be persisted: {e}"),
        )
        .await;
    }

    let outcome = match run_state_machine(
        pool,
        ssh,
        &req,
        reroute_id,
        &plan,
        cfg.reroute.require_verification,
        Some(&prepared_action),
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            // No SSH side effect occurs before run_state_machine's checked
            // planned->pending->running transitions complete.
            let aborted = sqlx::query(
                "UPDATE reroutes SET state = 'failed', finished_at = UTC_TIMESTAMP(), success = 0, \
                 mutation_effect = 'noop', failure_reason = ? \
                 WHERE id = ? AND state IN ('planned','pending')",
            )
            .bind(format!("aborted before command execution: {e}"))
            .bind(reroute_id)
            .execute(pool)
            .await;
            let persisted = matches!(aborted, Ok(ref r) if r.rows_affected() == 1);
            if !persisted {
                tracing::error!(event_type = "reroute_abort_persist_failed", reroute_id, error = ?aborted.err(), "could not persist pre-command abort");
            }
            if let Err(audit_err) = audit(
                pool,
                &req,
                reroute_id,
                "reroute_aborted",
                &format!("reroute #{reroute_id} aborted before SSH: {e}"),
            )
            .await
            {
                tracing::error!(event_type = "reroute_abort_audit_failed", reroute_id, error = %audit_err, "could not audit the pre-command abort");
            }
            return ExecOutcome {
                executed: false,
                reroute_id: Some(reroute_id),
                state: Some(if persisted { "failed" } else { "uncertain" }.into()),
                mutation_effect: Some(if persisted { "noop" } else { "unknown" }.into()),
                message: "reroute aborted before command execution".into(),
                blocked_reason: Some(e.to_string()),
                would_run: None,
                would_run_rollback: None,
                device_id: req.device_id,
                device_name,
            };
        }
    };

    // Standalone actions record their cooldown immediately. Ordered rule bundles
    // defer this until every sibling has had a chance to run.
    if !req.defer_cooldown {
        if let Err(e) = record_cooldowns(pool, cfg, req.rule_id, &[req.device_id]).await {
            tracing::error!(event_type = "reroute_cooldown_persist_failed", reroute_id, error = %e, "could not persist cooldown rows; durable reroute history remains the gate fallback");
        }
    }

    let MachineResult {
        state: final_state,
        note,
        refused,
        mutation_effect,
    } = outcome;
    // A refusal from the fresh in-session read pushed NOTHING: report it the way
    // every other fail-closed refusal is reported, with the actionable reason.
    if refused {
        return ExecOutcome {
            executed: false,
            reroute_id: Some(reroute_id),
            state: Some(final_state),
            mutation_effect: Some(mutation_effect.as_str().into()),
            message: note.clone().unwrap_or_else(|| {
                "reroute refused after reading the device's current state".into()
            }),
            blocked_reason: note,
            would_run: None,
            would_run_rollback: None,
            device_id: req.device_id,
            device_name,
        };
    }
    let message = match final_state.as_str() {
        // A no-op is a real success: the router was already in the requested
        // state, so nothing was pushed and verification still had to confirm it.
        "succeeded" => note
            .clone()
            .map(|n| format!("reroute verified — {n}"))
            .unwrap_or_else(|| "reroute executed and verified".to_string()),
        "failed" => "reroute failed — verification did not confirm the change".to_string(),
        "uncertain" => {
            "reroute UNCERTAIN — device locked pending admin acknowledgement".to_string()
        }
        other => format!("reroute ended in state {other}"),
    };
    if let Err(e) = policy_fence.release().await {
        tracing::error!(event_type = "execution_policy_fence_release_failed", reroute_id, error = %e, "policy fence connection will close rather than return locked to the pool");
    }
    ExecOutcome {
        executed: mutation_effect != MutationEffect::Noop,
        reroute_id: Some(reroute_id),
        state: Some(final_state),
        mutation_effect: Some(mutation_effect.as_str().into()),
        message,
        blocked_reason: None,
        would_run: None,
        would_run_rollback: None,
        device_id: req.device_id,
        device_name,
    }
}

fn configuration_only_authority_allowed(unattended: bool, rule_id: Option<u64>) -> bool {
    !unattended && rule_id.is_none()
}

#[cfg(test)]
mod configuration_only_tests {
    use super::configuration_only_authority_allowed;

    #[test]
    fn only_direct_manual_authority_can_use_configuration_only_scope() {
        assert!(configuration_only_authority_allowed(false, None));
        assert!(!configuration_only_authority_allowed(true, None));
        assert!(!configuration_only_authority_allowed(false, Some(7)));
        assert!(!configuration_only_authority_allowed(true, Some(7)));
    }
}

async fn configuration_test_identity_matches(
    pool: &MySqlPool,
    cfg: &Config,
    device_id: u64,
) -> bool {
    let expected = cfg
        .safety
        .configuration_test_devices
        .iter()
        .find(|device| device.device_id == device_id);
    let actual = RusshExecutor::new(pool.clone())
        .transport_identities(&[device_id])
        .await;
    actual
        .ok()
        .and_then(|ids| ids.get(&device_id).cloned())
        .is_some_and(|actual| {
            expected.is_none_or(|expected| {
                actual.host == expected.host
                    && actual.port == expected.port
                    && actual.pinned_host_fingerprint == expected.pinned_host_fingerprint
            })
        })
}

async fn validate_execution_authorization(
    pool: &MySqlPool,
    cfg: &Config,
    req: &ActionRequest,
) -> anyhow::Result<()> {
    let auth = req
        .authorization
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("a durable prepared-action authority is required"))?;
    anyhow::ensure!(
        !auth.owner_token.trim().is_empty(),
        "empty device-window owner"
    );
    match auth.kind {
        ExecutionAuthorityKind::Manual => {
            anyhow::ensure!(req.trigger_type == "manual" || req.trigger_type == "rollback");
            let plan_id = auth
                .plan_id
                .ok_or_else(|| anyhow::anyhow!("manual execution has no consumed plan"))?;
            let user_id = req
                .user_id
                .ok_or_else(|| anyhow::anyhow!("manual execution has no actor"))?;
            let valid: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM execution_plans \
                 WHERE id = ? AND user_id = ? AND consumed_at IS NOT NULL \
                   AND consumed_at <= expires_at \
                   AND ((? IS NULL AND bundle_id IS NULL) OR bundle_id = ?)",
            )
            .bind(plan_id)
            .bind(user_id)
            .bind(auth.bundle_id)
            .bind(auth.bundle_id)
            .fetch_one(pool)
            .await?;
            anyhow::ensure!(
                valid == 1,
                "plan is missing, unconsumed, expired, or actor-mismatched"
            );
            if req.trigger_type == "manual" {
                if let Some(rule_id) = req.rule_id {
                    let current: i64 = sqlx::query_scalar(
                        "SELECT COUNT(*) \
                           FROM reroute_bundles b \
                           JOIN rules r ON r.id = b.rule_id \
                          WHERE b.id = ? AND b.rule_id = ? \
                            AND JSON_UNQUOTE(JSON_EXTRACT(b.source_json, '$.kind')) = 'rule' \
                            AND CAST(JSON_UNQUOTE(JSON_EXTRACT(b.source_json, '$.actions_revision')) AS UNSIGNED) = r.actions_revision \
                            AND r.manual_apply_enabled = 1",
                    )
                    .bind(auth.bundle_id)
                    .bind(rule_id)
                    .fetch_one(pool)
                    .await?;
                    anyhow::ensure!(
                        current == 1,
                        "rule actions changed or manual apply was disabled after authorization"
                    );
                }
            }
            if req.trigger_type == "rollback" {
                let original_id = req
                    .rollback_of_reroute_id
                    .ok_or_else(|| anyhow::anyhow!("manual rollback has no original action"))?;
                let owned: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM reroutes original \
                     WHERE original.id = ? AND original.state IN ('succeeded','failed') \
                       AND original.mutation_effect = 'changed' \
                       AND original.template_snapshot_json IS NOT NULL \
                       AND original.rollback_snapshot_json IS NOT NULL \
                       AND NOT EXISTS (SELECT 1 FROM reroutes inverse \
                         WHERE inverse.rollback_of_reroute_id = original.id \
                           AND inverse.state IN ('planned','pending','running','verifying','succeeded'))",
                )
                .bind(original_id)
                .fetch_one(pool)
                .await?;
                anyhow::ensure!(owned == 1, "original action is not safely invertible");
            }
        }
        ExecutionAuthorityKind::ManualBundle => {
            anyhow::ensure!(req.trigger_type == "manual");
            let bundle_id = auth
                .bundle_id
                .ok_or_else(|| anyhow::anyhow!("direct manual execution has no bundle"))?;
            let user_id = req
                .user_id
                .ok_or_else(|| anyhow::anyhow!("direct manual execution has no actor"))?;
            let valid: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM reroute_bundles b \
                 WHERE b.id=? AND b.trigger_type='manual' AND b.triggered_by_user_id=? \
                   AND b.state IN ('planned','running') \
                   AND JSON_UNQUOTE(JSON_EXTRACT(b.source_json,'$.admission_kind'))='direct' \
                   AND JSON_UNQUOTE(JSON_EXTRACT(b.source_json,'$.preparation_phase'))='prepared'",
            )
            .bind(bundle_id)
            .bind(user_id)
            .fetch_one(pool)
            .await?;
            anyhow::ensure!(valid == 1, "direct manual bundle is not runnable");
            if let Some(rule_id) = req.rule_id {
                let current: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM reroute_bundles b JOIN rules r ON r.id=b.rule_id \
                     WHERE b.id=? AND b.rule_id=? AND r.manual_apply_enabled=1 \
                       AND CAST(JSON_UNQUOTE(JSON_EXTRACT(b.source_json,'$.actions_revision')) AS UNSIGNED)=r.actions_revision",
                )
                .bind(bundle_id)
                .bind(rule_id)
                .fetch_one(pool)
                .await?;
                anyhow::ensure!(
                    current == 1,
                    "rule actions changed or manual apply was disabled after admission"
                );
            }
        }
        ExecutionAuthorityKind::Automatic => {
            anyhow::ensure!(req.trigger_type == "automatic");
            let bundle_id = auth
                .bundle_id
                .ok_or_else(|| anyhow::anyhow!("automatic execution has no activation"))?;
            let valid: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) \
                   FROM reroute_bundles b \
                   JOIN rules r ON r.id = b.rule_id \
                   JOIN rule_states rs ON rs.rule_id = r.id \
                  WHERE b.id = ? AND b.trigger_type = 'automatic' \
                    AND b.state IN ('planned','running') \
                    AND r.enabled = 1 AND r.automatic_reroute_enabled = 1 \
                    AND rs.current_state = 'firing' \
                    AND JSON_EXTRACT(b.source_json, '$.actions_revision') IS NOT NULL \
                    AND CAST(JSON_UNQUOTE(JSON_EXTRACT(b.source_json, '$.actions_revision')) AS UNSIGNED) = r.actions_revision",
            )
            .bind(bundle_id)
            .fetch_one(pool)
            .await?;
            anyhow::ensure!(valid == 1, "automatic activation is not runnable");
            if let Some(rule_id) = req.rule_id {
                anyhow::ensure!(
                    crate::detection::engine::automatic_flow_evidence_qualified(pool, cfg, rule_id)
                        .await?,
                    "flow evidence is stale, incomplete, or no longer SNMP-corroborated"
                );
            }
        }
        ExecutionAuthorityKind::Compensation => {
            anyhow::ensure!(req.trigger_type == "rollback");
            let bundle_id = auth
                .bundle_id
                .ok_or_else(|| anyhow::anyhow!("compensation has no bundle"))?;
            let original_id = req
                .rollback_of_reroute_id
                .ok_or_else(|| anyhow::anyhow!("compensation has no original reroute"))?;
            let valid: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM reroutes \
                 WHERE id = ? AND bundle_id = ? AND mutation_effect = 'changed'",
            )
            .bind(original_id)
            .bind(bundle_id)
            .fetch_one(pool)
            .await?;
            anyhow::ensure!(
                valid == 1,
                "original action is not an owned mutation of this bundle"
            );
        }
        ExecutionAuthorityKind::Recovery => {
            anyhow::ensure!(req.trigger_type == "rollback");
            let bundle_id = auth
                .bundle_id
                .ok_or_else(|| anyhow::anyhow!("recovery has no bundle"))?;
            let original_id = req
                .rollback_of_reroute_id
                .ok_or_else(|| anyhow::anyhow!("recovery has no original reroute"))?;
            let valid: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM reroute_bundles b \
                   JOIN reroute_bundle_actions ba ON ba.bundle_id=b.id AND ba.original_reroute_id=? \
                   JOIN reroutes original ON original.id=ba.original_reroute_id \
                   JOIN reroute_bundles source_owner ON source_owner.id=original.bundle_id \
                   LEFT JOIN rules rule_row ON rule_row.id=b.rule_id \
                   LEFT JOIN rule_states rs ON rs.rule_id=rule_row.id \
                  WHERE b.id=? AND b.trigger_type='automatic' AND b.state IN ('planned','running') \
                    AND JSON_UNQUOTE(JSON_EXTRACT(b.source_json,'$.kind'))='recovery' \
                    AND original.mutation_effect='changed' \
                    AND source_owner.automatic_recovery_cancelled_at IS NULL \
                    AND source_owner.recovery_claim_token IS NOT NULL \
                    AND source_owner.recovery_bundle_id=b.id \
                    AND (b.rule_id IS NULL OR (original.rule_id=b.rule_id \
                         AND rule_row.automatic_revert_enabled=1 AND rs.current_state='recovered_awaiting_revert')) \
                    AND NOT EXISTS (SELECT 1 FROM reroutes inverse WHERE inverse.rollback_of_reroute_id=original.id \
                         AND inverse.state IN ('planned','pending','running','verifying','succeeded'))",
            )
            .bind(original_id)
            .bind(bundle_id)
            .fetch_one(pool)
            .await?;
            anyhow::ensure!(valid == 1, "automatic recovery ownership check failed");
            if let Some(rule_id) = req.rule_id {
                anyhow::ensure!(
                    crate::detection::engine::automatic_condition_recovery_qualified(
                        pool, cfg, rule_id
                    )
                    .await?,
                    "condition recovery evidence is stale or no longer recovered"
                );
            }
        }
        ExecutionAuthorityKind::ManualRecovery => {
            anyhow::ensure!(req.trigger_type == "rollback");
            let bundle_id = auth
                .bundle_id
                .ok_or_else(|| anyhow::anyhow!("manual recovery has no bundle"))?;
            let original_id = req
                .rollback_of_reroute_id
                .ok_or_else(|| anyhow::anyhow!("manual recovery has no original reroute"))?;
            let user_id = req
                .user_id
                .ok_or_else(|| anyhow::anyhow!("manual recovery has no actor"))?;
            let valid: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM reroute_bundles b \
                 JOIN reroute_bundle_actions ba ON ba.bundle_id=b.id AND ba.original_reroute_id=? \
                 JOIN reroutes original ON original.id=ba.original_reroute_id \
                 JOIN reroute_bundles source_owner ON source_owner.id=original.bundle_id \
                 JOIN recovery_attempt_sources ras ON ras.recovery_bundle_id=b.id \
                   AND ras.source_bundle_id=source_owner.id AND ras.settlement='active' \
                 WHERE b.id=? AND b.trigger_type='manual' AND b.triggered_by_user_id=? \
                   AND b.state IN ('planned','running') \
                   AND JSON_UNQUOTE(JSON_EXTRACT(b.source_json,'$.kind'))='recovery' \
                   AND JSON_UNQUOTE(JSON_EXTRACT(b.source_json,'$.admission_kind'))='direct' \
                   AND original.mutation_effect='changed' \
                   AND source_owner.recovery_claim_token=ras.claim_token \
                   AND NOT EXISTS (SELECT 1 FROM reroutes inverse WHERE inverse.rollback_of_reroute_id=original.id \
                     AND inverse.state IN ('planned','pending','running','verifying','succeeded'))",
            )
            .bind(original_id)
            .bind(bundle_id)
            .bind(user_id)
            .fetch_one(pool)
            .await?;
            anyhow::ensure!(valid == 1, "manual recovery ownership check failed");
        }
    }
    if req.rollback_of_reroute_id.is_none() {
        let current = crate::reroute::templates::load(pool, req.template.id).await?;
        anyhow::ensure!(
            current.enabled,
            "action template was disabled after preparation"
        );
        if req.trigger_type == "automatic" {
            anyhow::ensure!(
                current.automatic_allowed,
                "action template is no longer allowed for automatic execution"
            );
        }
        anyhow::ensure!(
            serde_json::to_value(&current)? == serde_json::to_value(&req.template)?,
            "action template changed after preparation"
        );
    }
    if let Some(action_id) = auth.snapshot_action_id {
        let valid: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM reroute_bundle_actions \
             WHERE id = ? AND device_id = ? AND prepared_action_json IS NOT NULL \
               AND (? IS NULL OR bundle_id = ?)",
        )
        .bind(action_id)
        .bind(req.device_id)
        .bind(auth.bundle_id)
        .bind(auth.bundle_id)
        .fetch_one(pool)
        .await?;
        anyhow::ensure!(
            valid == 1,
            "prepared sibling does not match this device/bundle"
        );
        if auth.kind == ExecutionAuthorityKind::Manual {
            let plan_id = auth.plan_id.expect("manual plan checked above");
            let bound: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) \
                   FROM execution_plans ep \
                   JOIN reroute_bundle_actions ba ON ba.id = ? \
                  WHERE ep.id = ? \
                    AND JSON_CONTAINS(ep.snapshot_json, ba.prepared_action_json, '$.device_actions')",
            )
            .bind(action_id)
            .bind(plan_id)
            .fetch_one(pool)
            .await?;
            anyhow::ensure!(
                bound == 1,
                "prepared sibling is not part of the consumed plan snapshot"
            );
        }
    } else if req.bundle.is_some() {
        anyhow::bail!("bundle execution is missing its prepared sibling id");
    }
    anyhow::ensure!(
        locks::change_window_allows(pool, req.device_id, Some(&auth.owner_token)).await?,
        "device change window belongs to another activation"
    );
    Ok(())
}

#[doc(hidden)]
pub async fn validate_execution_authorization_for_test(
    pool: &MySqlPool,
    cfg: &Config,
    req: &ActionRequest,
) -> anyhow::Result<()> {
    validate_execution_authorization(pool, cfg, req).await
}

#[doc(hidden)]
pub async fn authority_is_unattended(
    pool: &MySqlPool,
    auth: Option<&ExecutionAuthorization>,
) -> bool {
    match auth {
        Some(auth)
            if matches!(
                auth.kind,
                ExecutionAuthorityKind::Automatic | ExecutionAuthorityKind::Recovery
            ) =>
        {
            true
        }
        Some(auth) if auth.kind == ExecutionAuthorityKind::Compensation => match auth.bundle_id {
            Some(id) => {
                sqlx::query_scalar::<_, String>(
                    "SELECT trigger_type FROM reroute_bundles WHERE id=?",
                )
                .bind(id)
                .fetch_optional(pool)
                .await
                .ok()
                .flatten()
                .as_deref()
                    == Some("automatic")
            }
            None => true,
        },
        _ => false,
    }
}

async fn load_prepared_action(
    pool: &MySqlPool,
    req: &ActionRequest,
) -> anyhow::Result<crate::reroute::device_plan::PreparedDeviceAction> {
    let auth = req
        .authorization
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing execution authority"))?;
    if auth.kind == ExecutionAuthorityKind::Compensation {
        let original_id = req
            .rollback_of_reroute_id
            .ok_or_else(|| anyhow::anyhow!("compensation has no original reroute"))?;
        type OriginalSnapshot = (
            u64,
            Option<sqlx::types::Json<Value>>,
            Option<sqlx::types::Json<Value>>,
        );
        let (template_id, params, inverse): OriginalSnapshot = sqlx::query_as(
            "SELECT reroute_template_id, parameters_json, rollback_snapshot_json \
             FROM reroutes WHERE id = ?",
        )
        .bind(original_id)
        .fetch_one(pool)
        .await?;
        let inverse: crate::reroute::device_plan::PreparedInverse = serde_json::from_value(
            inverse
                .ok_or_else(|| anyhow::anyhow!("original reroute has no prepared inverse"))?
                .0,
        )?;
        let prepared = crate::reroute::device_plan::PreparedDeviceAction {
            schema_version: crate::reroute::device_plan::PREPARED_DEVICE_ACTION_SCHEMA_VERSION,
            device_id: req.device_id,
            template_id,
            template_name: format!("inverse-of-{original_id}"),
            canonical_params: params.map(|value| value.0).unwrap_or(Value::Null),
            verification_mode: inverse.verification_mode,
            commands: inverse.commands,
            before: inverse.expected_current,
            after: inverse.restore,
            verify: inverse.verify,
            effect: crate::reroute::device_plan::PreparedEffect::Change,
            inverse: None,
            prepared_at: chrono::Utc::now(),
        };
        prepared.validate()?;
        return Ok(prepared);
    }
    let action_id = auth
        .snapshot_action_id
        .ok_or_else(|| anyhow::anyhow!("missing prepared sibling id"))?;
    let value: sqlx::types::Json<Value> =
        sqlx::query_scalar("SELECT prepared_action_json FROM reroute_bundle_actions WHERE id = ?")
            .bind(action_id)
            .fetch_one(pool)
            .await?;
    let prepared: crate::reroute::device_plan::PreparedDeviceAction =
        serde_json::from_value(value.0)?;
    prepared.validate()?;
    anyhow::ensure!(
        prepared.device_id == req.device_id,
        "prepared device mismatch"
    );
    anyhow::ensure!(
        prepared.template_id == req.template.id,
        "prepared template mismatch"
    );
    Ok(prepared)
}

/// Record post-action cooldowns once for an ordered action bundle. Callers pass
/// only devices on which an executor outcome actually attempted the action.
pub async fn record_cooldowns(
    pool: &MySqlPool,
    cfg: &Config,
    rule_id: Option<u64>,
    device_ids: &[u64],
) -> anyhow::Result<()> {
    let mut unique = std::collections::BTreeSet::new();
    for device_id in device_ids {
        if unique.insert(*device_id) {
            cooldown::record(
                pool,
                "device",
                &device_id.to_string(),
                cfg.safety.same_device_cooldown_seconds as i64,
                "post-action device cooldown",
            )
            .await?;
        }
    }
    if !unique.is_empty() {
        if let Some(rule_id) = rule_id {
            cooldown::record(
                pool,
                "rule",
                &rule_id.to_string(),
                cfg.safety.same_rule_cooldown_seconds as i64,
                "post-action rule cooldown",
            )
            .await?;
        }
    }
    Ok(())
}

/// What one run of the state machine concluded.
struct MachineResult {
    /// The terminal reroute state.
    state: String,
    /// Operator-facing detail: the refusal reason, or the "already in the
    /// requested state, nothing pushed" note.
    note: Option<String>,
    /// True when a fresh in-session read refused the write. Nothing was pushed.
    refused: bool,
    mutation_effect: MutationEffect,
}

/// Push the apply commands, verify the result, finalize the state. Persists
/// before/after each phase.
async fn run_state_machine<S: SshExecutor>(
    pool: &MySqlPool,
    ssh: &S,
    req: &ActionRequest,
    reroute_id: u64,
    plan: &RenderedPlan,
    require_verification: bool,
    prepared_action: Option<&crate::reroute::device_plan::PreparedDeviceAction>,
) -> anyhow::Result<MachineResult> {
    let mut timing = crate::timing::Stage::start("router_execution", reroute_id);
    // -> pending: committed to act, persisted BEFORE any side effect. Crash
    // recovery treats pending/running/verifying as in-flight (=> uncertain), so
    // a crash from here on locks the device rather than being assumed harmless.
    let pending =
        sqlx::query("UPDATE reroutes SET state = 'pending' WHERE id = ? AND state = 'planned'")
            .bind(reroute_id)
            .execute(pool)
            .await?;
    anyhow::ensure!(
        pending.rows_affected() == 1,
        "planned state was cancelled or changed before execution"
    );

    // -> running: the SSH session is about to push config (the side effect).
    let running = sqlx::query(
        "UPDATE reroutes SET state = 'running', started_at = UTC_TIMESTAMP() \
         WHERE id = ? AND state = 'pending'",
    )
    .bind(reroute_id)
    .execute(pool)
    .await?;
    anyhow::ensure!(
        running.rows_affected() == 1,
        "pending state was cancelled or changed before execution"
    );

    let mut persistence_ok = true;

    // Apply over a single SSH session (config mode state must persist across the
    // command sequence, so this cannot be split into per-command sessions).
    //
    // A plan whose prefix-list sequence is still deferred takes the resolving
    // path: the SAME session first reads the target list, the sequence is chosen
    // and PERSISTED, and only then is the config pushed. See
    // `apply_with_sequence_resolution`.
    let prepared_effect = prepared_action.map(|prepared| prepared.effect);
    let (apply, refusal, skip) = if let Some(prepared) = prepared_action {
        match ssh.execute_prepared(prepared).await {
            Ok(outcome) => (
                Ok(outcome),
                None,
                (prepared.effect == crate::reroute::device_plan::PreparedEffect::AlreadySatisfied)
                    .then(|| {
                        "prepared state was already satisfied; no configuration was pushed".into()
                    }),
            ),
            Err(e) => {
                let proven_no_effect = e
                    .downcast_ref::<crate::reroute::device_plan::PreparedExecutionError>()
                    .is_some_and(|failure| {
                        failure.certainty
                            == crate::reroute::device_plan::EffectCertainty::ProvenNoEffect
                    })
                    || e.downcast_ref::<crate::ssh::SshPlanFailure>()
                        .is_some_and(|failure| {
                            failure.certainty
                                == crate::reroute::device_plan::EffectCertainty::ProvenNoEffect
                        });
                if proven_no_effect {
                    if let Some(failure) = e.downcast_ref::<crate::ssh::SshPlanFailure>() {
                        for (index, completed) in failure.completed.iter().enumerate() {
                            if persist_output(
                                pool,
                                reroute_id,
                                (index + 1) as u32,
                                &completed.command,
                                &completed.output,
                                "ok",
                            )
                            .await
                            .is_err()
                            {
                                persistence_ok = false;
                            }
                        }
                        if persist_output(
                            pool,
                            reroute_id,
                            (failure.completed.len() + 1) as u32,
                            &failure.failed_command,
                            &failure.failed_output,
                            "error",
                        )
                        .await
                        .is_err()
                        {
                            persistence_ok = false;
                        }
                    }
                    (
                        Ok(SshOutcome {
                            results: Vec::new(),
                            fingerprint: String::new(),
                            pinned_now: false,
                        }),
                        Some(e.to_string()),
                        None,
                    )
                } else {
                    (Err(e), None, None)
                }
            }
        }
    } else if plan.sequence_pending {
        match apply_with_sequence_resolution(pool, ssh, req, reroute_id, plan).await {
            Ok((outcome, decision)) => match decision {
                crate::ssh::SessionPlan::Refuse(reason) => (Ok(outcome), Some(reason), None),
                crate::ssh::SessionPlan::Skip(note) => (Ok(outcome), None, Some(note)),
                crate::ssh::SessionPlan::Push(_) => (Ok(outcome), None, None),
            },
            Err(e) => (Err(e), None, None),
        }
    } else {
        (ssh.apply(req.device_id, &plan.commands).await, None, None)
    };
    if let Some(note) = &skip {
        tracing::info!(
            event_type = "reroute_no_config_change_needed",
            reroute_id,
            device_id = req.device_id,
            note = %note,
            "the router was already in the requested state; no configuration was pushed"
        );
    }
    let applied_ok = match &apply {
        Ok(out) => {
            for (i, r) in out.results.iter().enumerate() {
                if let Err(e) = persist_output(
                    pool,
                    reroute_id,
                    (i + 1) as u32,
                    &r.command,
                    &r.output,
                    "ok",
                )
                .await
                {
                    persistence_ok = false;
                    tracing::error!(event_type = "reroute_output_persist_failed", reroute_id, error = %e, "could not persist command output");
                }
            }
            if let Err(e) =
                sqlx::query("UPDATE reroute_steps SET state = 'done' WHERE reroute_id = ?")
                    .bind(reroute_id)
                    .execute(pool)
                    .await
            {
                persistence_ok = false;
                tracing::error!(event_type = "reroute_step_persist_failed", reroute_id, error = %e, "could not persist completed steps");
            }
            // SSH just answered — keep the reachability recency window warm so a
            // follow-up reroute in the same storm skips the preflight probe.
            if let Err(e) = crate::reroute::reachability::stamp_ssh_ok(pool, req.device_id).await {
                persistence_ok = false;
                tracing::error!(event_type = "reroute_reachability_persist_failed", reroute_id, error = %e, "could not persist successful SSH contact");
            }
            true
        }
        Err(e) => {
            if let Some(failure) = e.downcast_ref::<crate::ssh::SshPlanFailure>() {
                for (index, completed) in failure.completed.iter().enumerate() {
                    if persist_output(
                        pool,
                        reroute_id,
                        (index + 1) as u32,
                        &completed.command,
                        &completed.output,
                        "ok",
                    )
                    .await
                    .is_err()
                    {
                        persistence_ok = false;
                    }
                }
                if persist_output(
                    pool,
                    reroute_id,
                    (failure.completed.len() + 1) as u32,
                    &failure.failed_command,
                    &failure.failed_output,
                    "error",
                )
                .await
                .is_err()
                {
                    persistence_ok = false;
                }
            } else if persist_output(pool, reroute_id, 0, "<apply>", &e.to_string(), "error")
                .await
                .is_err()
            {
                persistence_ok = false;
            }
            if let Err(err) =
                sqlx::query("UPDATE reroute_steps SET state = 'failed' WHERE reroute_id = ?")
                    .bind(reroute_id)
                    .execute(pool)
                    .await
            {
                persistence_ok = false;
                tracing::error!(event_type = "reroute_step_persist_failed", reroute_id, error = %err, "could not persist failed steps");
            }
            false
        }
    };

    // Fail closed. The fresh in-session read PROVED the planned write must not
    // happen (no free sequence in the gap, an unreadable list, a broader entry
    // that would take other prefixes with it). Nothing was pushed, so this is a
    // known, side-effect-free outcome: `failed` with an actionable reason, NOT
    // `uncertain` — an operator-fixable configuration problem must not lock the
    // device. Verification is skipped because there is nothing new to confirm.
    if let Some(reason) = refusal {
        // The planned steps never ran; do not leave them marked done.
        if let Err(e) = sqlx::query(
            "UPDATE reroute_steps SET state = 'failed' WHERE reroute_id = ? AND step_number > 0",
        )
        .bind(reroute_id)
        .execute(pool)
        .await
        {
            persistence_ok = false;
            tracing::error!(event_type = "reroute_step_persist_failed", reroute_id, error = %e, "could not mark refused steps");
        }
        let state = if persistence_ok {
            "failed"
        } else {
            "uncertain"
        };
        let state = finalize(
            pool,
            req,
            reroute_id,
            state,
            true,
            Verdict::None,
            if persistence_ok {
                MutationEffect::Noop
            } else {
                MutationEffect::Unknown
            },
            Some(reason.clone()),
        )
        .await;
        return Ok(MachineResult {
            state,
            note: Some(reason),
            refused: true,
            mutation_effect: if persistence_ok {
                MutationEffect::Noop
            } else {
                MutationEffect::Unknown
            },
        });
    }

    // -> verifying (read-only confirmation in a separate session)
    let verifying =
        sqlx::query("UPDATE reroutes SET state = 'verifying' WHERE id = ? AND state = 'running'")
            .bind(reroute_id)
            .execute(pool)
            .await;
    if !matches!(verifying, Ok(ref r) if r.rows_affected() == 1) {
        persistence_ok = false;
        tracing::error!(
            event_type = "reroute_transition_persist_failed",
            reroute_id,
            "could not persist running->verifying transition"
        );
    }
    let (verdict, verification_persisted) = if prepared_action.is_some() {
        // `execute_prepared` performs exact typed after-state verification under
        // the retained native lock before returning success.
        (Verdict::Pass, true)
    } else {
        verify(pool, ssh, req, reroute_id, plan).await
    };
    persistence_ok &= verification_persisted;

    let mut final_state = final_state_for(applied_ok, verdict, require_verification);
    if !persistence_ok {
        final_state = "uncertain";
    }

    let mutation_effect = if !persistence_ok || !applied_ok {
        MutationEffect::Unknown
    } else if skip.is_some()
        || prepared_effect == Some(crate::reroute::device_plan::PreparedEffect::AlreadySatisfied)
    {
        MutationEffect::Noop
    } else {
        MutationEffect::Changed
    };
    let state = finalize(
        pool,
        req,
        reroute_id,
        final_state,
        applied_ok,
        verdict,
        mutation_effect,
        None,
    )
    .await;
    timing.complete(match state.as_str() {
        "succeeded" => "succeeded",
        "failed" => "failed",
        _ => "uncertain",
    });
    Ok(MachineResult {
        state,
        note: skip,
        refused: false,
        mutation_effect,
    })
}

/// Resolve a deferred prefix-list sequence and push, all inside ONE SSH session.
///
/// The session runs `show ip prefix-list <name>` first, [`prefix_list`] decides
/// where the entry belongs from THAT text, the choice is PERSISTED, and only
/// then does the config go out. The order matters twice over:
///
/// * **Freshness.** IOS REPLACES an entry when a write reuses its sequence
///   number, so the decision may only rest on a read taken moments earlier.
///   Cached inventory (up to `ROUTING_INVENTORY_MAX_AGE_HOURS` old) could name a
///   sequence another operator has since used, and the write would silently
///   overwrite a live filter entry.
/// * **Persist before the side effect.** The chosen sequence reaches
///   `reroutes.parameters_json` before the command reaches the router, so a
///   crash in between leaves an `uncertain` reroute that still names the exact
///   entry — and the rollback removes exactly that entry, not a content match.
///
/// This is ONE extra `show` in a session the executor already opened. It is not
/// [`crate::ssh::discover_prefixes_and_store`] and it does not run the drift
/// audit: no second connection, no inventory reconcile, no audit pass. The
/// prohibition on inline discovery from a trigger path is unchanged.
async fn apply_with_sequence_resolution<S: SshExecutor>(
    pool: &MySqlPool,
    ssh: &S,
    req: &ActionRequest,
    reroute_id: u64,
    plan: &RenderedPlan,
) -> anyhow::Result<(crate::ssh::SshOutcome, crate::ssh::SessionPlan)> {
    use crate::reroute::prefix_list;

    // Take the VALIDATED, normalized values — the same ones `render` substituted
    // into the plan — so the decision and the command can never disagree about
    // which prefix is being placed.
    let subst = crate::reroute::templates::validate_and_expand(
        &req.template.parameter_schema,
        &req.params,
    )?;
    let list = subst
        .get("prefix_list_name")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("sequenced prefix-list action has no prefix_list_name"))?
        .to_string();
    let prefix = subst
        .get("prefix")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("sequenced prefix-list action has no prefix"))?
        .to_string();
    // Which direction the template moves the entry in decides which reachability
    // question we ask of the list.
    //
    // The errors in this preamble are internal inconsistencies, not operator
    // mistakes: `render` already validated the parameters, and only these two
    // templates can produce a deferred sequence. They surface as an ambiguous
    // apply (=> `uncertain` + device lock), which is the conservative reading of
    // "the engine does not understand its own plan" — nothing is pushed either way.
    let adding = match req.template.name.as_str() {
        "bgp_advertise_add" => true,
        "bgp_advertise_remove" => false,
        other => anyhow::bail!("template '{other}' has no prefix-list sequence resolver"),
    };
    let read_command = format!("show ip prefix-list {list}");
    let (list, prefix) = (list.as_str(), prefix.as_str());

    debug_assert!(plan.sequence_pending, "resolver called on a concrete plan");

    let resolve: crate::ssh::SessionResolver<'_> = Box::new(move |output: String| {
        Box::pin(async move {
            let decision = if adding {
                prefix_list::plan_add(&output, list, prefix)
            } else {
                prefix_list::plan_remove(&output, list, prefix)
            };
            let (session_plan, concrete) = session_plan_for(decision, &req.template, &req.params)?;
            // PERSIST BEFORE THE SIDE EFFECT. A failure here aborts the push: an
            // action whose exact entry we could not record is one we could not
            // roll back.
            if let Some((sequence, plan)) = concrete {
                persist_resolved_sequence(pool, req, reroute_id, sequence, plan.as_ref()).await?;
            }
            Ok(session_plan)
        })
    });
    let resolved = ssh
        .apply_resolved(req.device_id, &read_command, resolve)
        .await?;
    Ok((resolved.outcome, resolved.decision))
}

/// PURE: turn a prefix-list decision into what the open session should do, plus
/// what has to be persisted before it does.
///
/// The second element is `Some((sequence, plan))` when a sequence must be written
/// to `reroutes.parameters_json`; the inner `plan` is `Some` only when config is
/// actually being pushed (a no-op records the entry a rollback may name, but has
/// no new command list). `None` means nothing is persisted and nothing is pushed.
#[allow(clippy::type_complexity)]
fn session_plan_for(
    decision: crate::reroute::prefix_list::SequencePlan,
    template: &Template,
    params: &Value,
) -> anyhow::Result<(crate::ssh::SessionPlan, Option<(u32, Option<RenderedPlan>)>)> {
    use crate::reroute::prefix_list::SequencePlan;
    use crate::ssh::SessionPlan;

    match decision {
        SequencePlan::Refuse(reason) => Ok((SessionPlan::Refuse(reason), None)),
        SequencePlan::AlreadySatisfied { sequence, note } => {
            // Nothing to push. When the satisfying entry IS this prefix, record
            // its sequence so a later rollback removes exactly that entry.
            Ok((SessionPlan::Skip(note), sequence.map(|s| (s, None))))
        }
        SequencePlan::Use(sequence) => {
            // Re-render through the template so the resolved sequence goes through
            // the same typed `seq` validation as any other parameter.
            let (concrete, _) =
                crate::reroute::templates::render_with_sequence(template, params, sequence)?;
            Ok((
                SessionPlan::Push(concrete.commands.clone()),
                Some((sequence, Some(concrete))),
            ))
        }
    }
}

/// Write the apply-time sequence (and, when the plan was re-rendered with it,
/// the concrete command list) into the durable record — BEFORE the commands are
/// sent. A failure here aborts the push: an action whose exact entry we could
/// not record is an action we could not roll back.
async fn persist_resolved_sequence(
    pool: &MySqlPool,
    req: &ActionRequest,
    reroute_id: u64,
    sequence: u32,
    plan: Option<&RenderedPlan>,
) -> anyhow::Result<()> {
    let mut params = req.params.as_object().cloned().unwrap_or_default();
    params.insert(
        crate::reroute::templates::SEQUENCE_PARAM.into(),
        Value::String(sequence.to_string()),
    );
    let params = Value::Object(params);

    match plan {
        Some(plan) => {
            let steps = json!({ "commands": plan.commands, "verify": plan.verify });
            let updated = sqlx::query(
                "UPDATE reroutes SET parameters_json = ?, planned_steps_json = ? \
                 WHERE id = ? AND state = 'running'",
            )
            .bind(sqlx::types::Json(&params))
            .bind(sqlx::types::Json(&steps))
            .bind(reroute_id)
            .execute(pool)
            .await?;
            anyhow::ensure!(
                updated.rows_affected() == 1,
                "reroute #{reroute_id} was no longer running when its prefix-list sequence \
                 was resolved"
            );
            for (i, cmd) in plan.commands.iter().enumerate() {
                sqlx::query(
                    "UPDATE reroute_steps SET description = ? \
                     WHERE reroute_id = ? AND step_number = ?",
                )
                .bind(cmd)
                .bind(reroute_id)
                .bind((i + 1) as u32)
                .execute(pool)
                .await?;
            }
        }
        None => {
            let updated = sqlx::query(
                "UPDATE reroutes SET parameters_json = ? WHERE id = ? AND state = 'running'",
            )
            .bind(sqlx::types::Json(&params))
            .bind(reroute_id)
            .execute(pool)
            .await?;
            anyhow::ensure!(
                updated.rows_affected() == 1,
                "reroute #{reroute_id} was no longer running when its prefix-list entry \
                 was identified"
            );
        }
    }
    tracing::info!(
        event_type = "reroute_prefix_list_sequence_resolved",
        reroute_id,
        device_id = req.device_id,
        template = %req.template.name,
        sequence,
        pushed = plan.is_some(),
        "chose the prefix-list sequence from a fresh in-session read"
    );
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Pass,
    Fail,
    Uncertain,
    None,
}

/// Pure terminal-state decision. Any apply error is uncertain because the SSH
/// transport can fail after a prefix of the command sequence reached the router;
/// a later text check cannot prove every side effect (such as a soft clear) ran.
fn final_state_for(applied_ok: bool, verdict: Verdict, require_verification: bool) -> &'static str {
    if !applied_ok {
        return "uncertain";
    }
    match verdict {
        Verdict::Pass => "succeeded",
        Verdict::Fail => "failed",
        Verdict::Uncertain => "uncertain",
        Verdict::None if require_verification => "uncertain",
        Verdict::None => "succeeded",
    }
}

/// Run the verification `show` read and judge it (substring expect/reject).
async fn verify<S: SshExecutor>(
    pool: &MySqlPool,
    ssh: &S,
    req: &ActionRequest,
    reroute_id: u64,
    plan: &RenderedPlan,
) -> (Verdict, bool) {
    let Some(vstep) = plan.verify.as_ref() else {
        return (Verdict::None, true);
    };
    match ssh.verify_read(req.device_id, &vstep.command).await {
        Ok(output) => {
            let verdict = legacy_verdict(&output, vstep);
            let persisted = persist_verification(
                pool,
                reroute_id,
                vstep,
                &output,
                match verdict {
                    Verdict::Pass => "pass",
                    Verdict::Fail => "fail",
                    _ => "uncertain",
                },
            )
            .await
            .is_ok();
            (verdict, persisted)
        }
        Err(e) => {
            let persisted = persist_verification(
                pool,
                reroute_id,
                vstep,
                &format!("verify read failed: {e}"),
                "uncertain",
            )
            .await
            .is_ok();
            (Verdict::Uncertain, persisted)
        }
    }
}

/// expect-present AND reject-absent (case-insensitive substring).
fn judge(output: &str, v: &VerifyStep) -> bool {
    let hay = output.to_lowercase();
    let expect_ok = v
        .expect
        .as_ref()
        .map(|s| hay.contains(&s.to_lowercase()))
        .unwrap_or(true);
    let reject_ok = v
        .reject
        .as_ref()
        .map(|s| !hay.contains(&s.to_lowercase()))
        .unwrap_or(true);
    expect_ok && reject_ok
}

fn legacy_static_filter_matches(command: &str, output: &str) -> bool {
    let Some(pattern) = command
        .strip_prefix("show running-config | include ^")
        .and_then(|value| value.strip_suffix('$'))
    else {
        return false;
    };
    let wanted = pattern.split_whitespace().collect::<Vec<_>>();
    let supported = match wanted.as_slice() {
        ["ip", "route", network, mask, _] => {
            network.parse::<std::net::Ipv4Addr>().is_ok()
                && mask.parse::<std::net::Ipv4Addr>().is_ok()
        }
        ["ip", "route", network, mask, _, "tag", tag] => {
            network.parse::<std::net::Ipv4Addr>().is_ok()
                && mask.parse::<std::net::Ipv4Addr>().is_ok()
                && tag.parse::<u32>().is_ok()
        }
        ["ipv6", "route", prefix, _] => {
            crate::reroute::device_plan::normalize_cidr(prefix).is_some_and(|p| p.contains(':'))
        }
        ["ipv6", "route", prefix, _, "tag", tag] => {
            crate::reroute::device_plan::normalize_cidr(prefix).is_some_and(|p| p.contains(':'))
                && tag.parse::<u32>().is_ok()
        }
        _ => false,
    };
    if !supported {
        return false;
    }
    output.lines().all(|line| {
        let actual = line.split_whitespace().collect::<Vec<_>>();
        match (wanted.as_slice(), actual.as_slice()) {
            (["ip", "route", wn, wm, wh], ["ip", "route", an, am, ah]) => {
                wn.parse::<std::net::Ipv4Addr>().ok() == an.parse().ok()
                    && wm.parse::<std::net::Ipv4Addr>().ok() == am.parse().ok()
                    && wh == ah
            }
            (["ip", "route", wn, wm, wh, "tag", wt], ["ip", "route", an, am, ah, "tag", at]) => {
                wn.parse::<std::net::Ipv4Addr>().ok() == an.parse().ok()
                    && wm.parse::<std::net::Ipv4Addr>().ok() == am.parse().ok()
                    && wh == ah
                    && wt.parse::<u32>().ok() == at.parse().ok()
            }
            (["ipv6", "route", wp, wh], ["ipv6", "route", ap, ah]) => {
                crate::reroute::device_plan::normalize_cidr(wp)
                    == crate::reroute::device_plan::normalize_cidr(ap)
                    && wh == ah
            }
            (["ipv6", "route", wp, wh, "tag", wt], ["ipv6", "route", ap, ah, "tag", at]) => {
                crate::reroute::device_plan::normalize_cidr(wp)
                    == crate::reroute::device_plan::normalize_cidr(ap)
                    && wh == ah
                    && wt.parse::<u32>().ok() == at.parse().ok()
            }
            _ => false,
        }
    })
}

fn legacy_mss_filter_matches(command: &str, output: &str) -> bool {
    let Some(_interface) = command
        .strip_prefix("show running-config interface ")
        .and_then(|rest| rest.strip_suffix(" | include ip tcp adjust-mss"))
        .map(str::trim)
        .filter(|name| !name.is_empty() && !name.chars().any(char::is_whitespace))
    else {
        return false;
    };
    output.lines().all(|line| {
        let words = line.split_whitespace().collect::<Vec<_>>();
        matches!(words.as_slice(), ["ip", "tcp", "adjust-mss", value] if value.parse::<u32>().is_ok())
    })
}

fn legacy_verdict(output: &str, v: &VerifyStep) -> Verdict {
    let command = v.command.trim();
    let filtered_static = legacy_static_filter_matches(command, "");
    let filtered_mss = legacy_mss_filter_matches(command, "");
    let supported_filtered = filtered_static || filtered_mss;
    let empty_filtered_config = supported_filtered && output.trim().is_empty();
    if output.trim().is_empty() && !empty_filtered_config {
        return Verdict::Uncertain;
    }
    let structured = if command.starts_with("show interfaces ") {
        let interface = command.trim_start_matches("show interfaces ").trim();
        output
            .lines()
            .any(|line| line.trim_start().starts_with(&format!("{interface} is ")))
    } else if command.starts_with("show ip bgp neighbors ")
        && command.ends_with(" advertised-routes")
    {
        let exact_expected = v
            .expect
            .as_deref()
            .is_some_and(|prefix| crate::reroute::device_plan::has_exact_cidr(output, prefix));
        exact_expected || crate::reroute::device_plan::complete_advertisement_table(output)
    } else if command.starts_with("show ip route ") || command.starts_with("show ipv6 route ") {
        let requested = command.split_whitespace().last().unwrap_or("");
        let route_headers = output
            .lines()
            .filter_map(|line| line.trim().strip_prefix("Routing entry for "))
            .collect::<Vec<_>>();
        (!route_headers.is_empty()
            && route_headers.iter().all(|rest| {
                let observed = rest
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_end_matches(',');
                observed == requested || observed.starts_with(&format!("{requested}/"))
            }))
            || output.lines().any(|line| {
                matches!(
                    line.trim().to_ascii_lowercase().as_str(),
                    "% network not in table"
                        | "network not in table"
                        | "% route not found"
                        | "route not found"
                )
            })
    } else if command.starts_with("show running-config interface ") && !supported_filtered {
        let interface = command
            .trim_start_matches("show running-config interface ")
            .trim();
        let headers = output
            .lines()
            .filter_map(|line| line.trim().strip_prefix("interface "))
            .collect::<Vec<_>>();
        headers.len() == 1 && headers[0] == interface
    } else if filtered_static {
        legacy_static_filter_matches(command, output)
    } else if filtered_mss {
        legacy_mss_filter_matches(command, output)
    } else {
        false
    };
    if !structured {
        Verdict::Uncertain
    } else if judge(output, v) {
        Verdict::Pass
    } else {
        Verdict::Fail
    }
}

/// Write the terminal state + side effects (lock on uncertain, alerts, audit).
#[allow(clippy::too_many_arguments)]
async fn finalize(
    pool: &MySqlPool,
    req: &ActionRequest,
    reroute_id: u64,
    state: &str,
    applied_ok: bool,
    verdict: Verdict,
    mutation_effect: MutationEffect,
    // Overrides the generic failure text with an explicit, actionable reason —
    // used when a fresh in-session read refused the write outright.
    refusal: Option<String>,
) -> String {
    let success: Option<bool> = match state {
        "succeeded" => Some(true),
        "failed" => Some(false),
        _ => None,
    };
    let verification_status = match verdict {
        Verdict::Pass => "pass",
        Verdict::Fail => "fail",
        Verdict::Uncertain => "uncertain",
        Verdict::None => "none",
    };
    let failure_reason: Option<String> = match state {
        _ if refusal.is_some() => refusal,
        "failed" => Some(if applied_ok {
            "commands ran but verification did not confirm the intended state".into()
        } else {
            "command push failed and verification did not confirm the change".into()
        }),
        "uncertain" => Some(if applied_ok {
            "could not verify the resulting state after pushing config".into()
        } else {
            "the SSH apply ended ambiguously and may have applied only part of the command plan"
                .into()
        }),
        _ => None,
    };

    // Terminal state, required device lock, alert/outbox intent and audit form one
    // transaction. A restart can therefore never observe a terminal row whose
    // safety trail was only partly committed.
    let severity = match state {
        "succeeded" => "info",
        "failed" => "critical",
        "uncertain" => "critical",
        _ => "info",
    };
    let actor = crate::alerts::actor_json(pool, req.user_id).await;
    let payload = json!({
        "reroute_id": reroute_id,
        "template": req.template.name,
        "template_display_name": req.template.display_name,
        "device_id": req.device_id,
        "device_name": device_name(pool, req.device_id).await,
        "trigger_type": req.trigger_type,
        "actor": actor,
        "reason": req.reason,
        "detail": { "verification": verification_status, "failure_reason": failure_reason },
    });
    let event = format!("reroute_{state}");
    let actor_type = if req.user_id.is_some() {
        "user"
    } else {
        "controller"
    };
    let finalized = async {
        let mut tx = pool.begin().await?;
        let updated = sqlx::query(
            "UPDATE reroutes SET state = ?, finished_at = UTC_TIMESTAMP(), success = ?, \
             verification_status = ?, mutation_effect = ?, failure_reason = ? \
             WHERE id = ? AND state IN ('running','verifying')",
        )
        .bind(state)
        .bind(success)
        .bind(verification_status)
        .bind(mutation_effect.as_str())
        .bind(&failure_reason)
        .bind(reroute_id)
        .execute(&mut *tx)
        .await?;
        anyhow::ensure!(updated.rows_affected() == 1, "terminal state conflict");
        if state == "uncertain" {
            locks::create_on(
                &mut tx,
                "device",
                Some(&req.device_id.to_string()),
                Some(reroute_id),
                "auto_uncertain",
                &format!("reroute #{reroute_id} could not be verified"),
                None,
            )
            .await?;
        }
        sqlx::query(
            "INSERT INTO alerts (event_type, severity, device_id, rule_id, payload_json, dedup_key) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&event)
        .bind(severity)
        .bind(req.device_id)
        .bind(req.rule_id)
        .bind(sqlx::types::Json(&payload))
        .bind(format!("{event}:reroute:{reroute_id}"))
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO audit_logs (actor_type, actor_user_id, event_type, entity_type, \
                 entity_id, reroute_id, message, ip_address, user_agent) \
             VALUES (?, ?, ?, 'reroute', ?, ?, ?, ?, ?)",
        )
        .bind(actor_type)
        .bind(req.user_id)
        .bind(&event)
        .bind(reroute_id)
        .bind(reroute_id)
        .bind(format!("reroute #{reroute_id} {state}"))
        .bind(req.actor_context.as_ref().map(|c| c.ip_address.as_str()))
        .bind(req.actor_context.as_ref().map(|c| c.user_agent.as_str()))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;

    let effective_state = if finalized.is_ok() {
        state
    } else {
        "uncertain"
    };
    if let Err(e) = finalized {
        tracing::error!(event_type = "reroute_finalize_transaction_failed", reroute_id, error = %e, "terminal transaction failed; leaving in-flight state for startup recovery");
    }

    tracing::info!(
        event_type = "reroute_finalized",
        reroute_id,
        device_id = req.device_id,
        state = effective_state,
        template = %req.template.name,
        "reroute finalized"
    );
    effective_state.to_string()
}

// ---- persistence helpers -------------------------------------------------------

async fn persist_output(
    pool: &MySqlPool,
    reroute_id: u64,
    step: u32,
    request: &str,
    response: &str,
    status: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO reroute_outputs (reroute_id, step_number, request, response, status, started_at, finished_at) \
         VALUES (?, ?, ?, ?, ?, UTC_TIMESTAMP(), UTC_TIMESTAMP())",
    )
    .bind(reroute_id)
    .bind(step)
    .bind(request)
    .bind(response)
    .bind(status)
    .execute(pool)
    .await?;
    Ok(())
}

async fn persist_verification(
    pool: &MySqlPool,
    reroute_id: u64,
    v: &VerifyStep,
    observed: &str,
    result: &str,
) -> anyhow::Result<()> {
    let expected = format!(
        "expect={} reject={}",
        v.expect.as_deref().unwrap_or("-"),
        v.reject.as_deref().unwrap_or("-")
    );
    sqlx::query(
        "INSERT INTO reroute_verifications (reroute_id, method, expected, observed, result, checked_at) \
         VALUES (?, 'ios_show', ?, ?, ?, UTC_TIMESTAMP())",
    )
    .bind(reroute_id)
    .bind(expected)
    .bind(observed)
    .bind(result)
    .execute(pool)
    .await?;
    Ok(())
}

async fn enqueue_alert(
    pool: &MySqlPool,
    req: &ActionRequest,
    reroute_id: u64,
    event_type: &str,
    severity: &str,
    extra: Value,
) -> anyhow::Result<()> {
    // Enrich the payload so the email can render the full picture: WHO acted (for
    // manual/rollback), the exact commands run, and the rollback commands to undo
    // it by hand. Rendering is best-effort (params already validated at execution).
    let actor = crate::alerts::actor_json(pool, req.user_id).await;
    let (commands, rollback_commands) =
        match crate::reroute::templates::render(&req.template, &req.params) {
            Ok(plan) => {
                let rb = crate::reroute::rollback::render_rollback_plan(
                    pool,
                    req.template.id,
                    &req.params,
                )
                .await
                .map(|p| p.commands);
                (Some(plan.commands), rb)
            }
            Err(_) => (None, None),
        };
    let payload = json!({
        "reroute_id": reroute_id,
        "template": req.template.name,
        "template_display_name": req.template.display_name,
        "device_id": req.device_id,
        "device_name": device_name(pool, req.device_id).await,
        "trigger_type": req.trigger_type,
        "actor": actor,
        "reason": req.reason,
        "commands": commands,
        "rollback_commands": rollback_commands,
        "detail": extra,
    });
    let dedup_key = format!("{event_type}:reroute:{reroute_id}");
    sqlx::query(
        "INSERT INTO alerts (event_type, severity, device_id, rule_id, payload_json, dedup_key) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(event_type)
    .bind(severity)
    .bind(req.device_id)
    .bind(req.rule_id)
    .bind(sqlx::types::Json(&payload))
    .bind(&dedup_key)
    .execute(pool)
    .await?;
    Ok(())
}

async fn audit(
    pool: &MySqlPool,
    req: &ActionRequest,
    reroute_id: u64,
    event: &str,
    message: &str,
) -> anyhow::Result<()> {
    let actor_type = if req.user_id.is_some() {
        "user"
    } else {
        "controller"
    };
    sqlx::query(
        "INSERT INTO audit_logs (actor_type, actor_user_id, event_type, entity_type, entity_id, reroute_id, message, ip_address, user_agent) \
         VALUES (?, ?, ?, 'reroute', ?, ?, ?, ?, ?)",
    )
    .bind(actor_type)
    .bind(req.user_id)
    .bind(event)
    .bind(reroute_id)
    .bind(reroute_id)
    .bind(message)
    .bind(req.actor_context.as_ref().map(|c| c.ip_address.as_str()))
    .bind(req.actor_context.as_ref().map(|c| c.user_agent.as_str()))
    .execute(pool)
    .await?;
    Ok(())
}

/// A reservation exists but a required pre-action record could not be written.
/// No SSH has been attempted, so terminate the row and return without executing.
async fn abort_reserved(
    pool: &MySqlPool,
    req: &ActionRequest,
    reroute_id: u64,
    device_name: Option<String>,
    reason: String,
) -> ExecOutcome {
    let persisted = sqlx::query(
        "UPDATE reroutes SET state = 'failed', finished_at = UTC_TIMESTAMP(), success = 0, \
         mutation_effect = 'noop', failure_reason = ? WHERE id = ? AND state = 'planned'",
    )
    .bind(&reason)
    .bind(reroute_id)
    .execute(pool)
    .await
    .is_ok_and(|result| result.rows_affected() == 1);
    tracing::error!(event_type = "reroute_preaction_record_failed", reroute_id, device_id = req.device_id, persisted, reason = %reason, "reroute aborted before SSH because its durable trail was incomplete");
    ExecOutcome {
        executed: false,
        reroute_id: Some(reroute_id),
        state: Some(if persisted { "failed" } else { "uncertain" }.into()),
        mutation_effect: Some(if persisted { "noop" } else { "unknown" }.into()),
        message: "reroute aborted before command execution".into(),
        blocked_reason: Some(reason),
        would_run: None,
        would_run_rollback: None,
        device_id: req.device_id,
        device_name,
    }
}

async fn device_name(pool: &MySqlPool, device_id: u64) -> Option<String> {
    sqlx::query_scalar::<_, String>("SELECT name FROM devices WHERE id = ?")
        .bind(device_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
}

fn blocked(req: &ActionRequest, device_name: Option<String>, reason: String) -> ExecOutcome {
    ExecOutcome {
        executed: false,
        reroute_id: None,
        state: None,
        mutation_effect: None,
        message: reason.clone(),
        blocked_reason: Some(reason),
        would_run: None,
        would_run_rollback: None,
        device_id: req.device_id,
        device_name,
    }
}

#[cfg(test)]
mod tests {
    use super::{final_state_for, legacy_verdict, session_plan_for, Verdict};
    use crate::reroute::prefix_list::SequencePlan;
    use crate::reroute::templates::{Template, VerifyStep};
    use crate::ssh::SessionPlan;
    use serde_json::{json, Value};

    /// `bgp_advertise_add` as migration 20260916000400 seeds it.
    fn advertise_add() -> Template {
        Template {
            id: 1,
            name: "bgp_advertise_add".into(),
            display_name: None,
            description: None,
            provider_type: "device_cli".into(),
            mode: "ios_ssh".into(),
            automatic_allowed: false,
            parameter_schema: json!({
                "neighbor_ip": {"type": "ip", "required": true},
                "prefix": {"type": "cidr", "required": true},
                "prefix_list_name": {"type": "string", "required": true},
                "sequence": {"type": "seq", "required": false, "deferred": true},
            }),
            plan: json!({
                "transport": "ios_ssh", "config_mode": true,
                "apply": ["ip prefix-list {prefix_list_name} seq {sequence} permit {prefix}"],
                "exec_after": ["clear ip bgp {neighbor_ip} soft out"],
            }),
            verification: json!({
                "command": "show ip bgp neighbors {neighbor_ip} advertised-routes",
                "expect": "{prefix_net}",
            }),
            rollback_template_id: Some(2),
            v6_sibling_template_id: None,
            enabled: true,
        }
    }

    fn params() -> Value {
        json!({
            "neighbor_ip": "23.45.23.197",
            "prefix": "194.105.143.0/24",
            "prefix_list_name": "pfx-to-viva",
        })
    }

    #[test]
    fn a_chosen_sequence_is_pushed_and_persisted_before_the_write() {
        let (plan, persist) =
            session_plan_for(SequencePlan::Use(7), &advertise_add(), &params()).expect("maps");
        let SessionPlan::Push(commands) = plan else {
            panic!("expected a push");
        };
        assert_eq!(
            commands,
            vec![
                "configure terminal",
                "ip prefix-list pfx-to-viva seq 7 permit 194.105.143.0/24",
                "end",
                "clear ip bgp 23.45.23.197 soft out",
            ]
        );
        // The sequence AND the concrete plan are handed back for persistence,
        // which the caller performs before any command leaves the process.
        let (sequence, concrete) = persist.expect("must persist the chosen sequence");
        assert_eq!(sequence, 7);
        assert_eq!(concrete.expect("concrete plan").commands, commands);
    }

    #[test]
    fn an_already_satisfied_router_pushes_nothing() {
        let (plan, persist) = session_plan_for(
            SequencePlan::AlreadySatisfied {
                sequence: Some(5),
                note: "already permitted by seq 5".into(),
            },
            &advertise_add(),
            &params(),
        )
        .expect("maps");
        assert!(matches!(plan, SessionPlan::Skip(_)), "{plan:?}");
        // The entry that satisfies the intent is recorded (so a rollback removes
        // exactly it) but there is no new command list.
        let (sequence, concrete) = persist.expect("records the entry");
        assert_eq!(sequence, 5);
        assert!(concrete.is_none(), "a no-op must not claim a command list");
    }

    #[test]
    fn an_already_satisfied_router_with_no_nameable_entry_persists_nothing() {
        let (plan, persist) = session_plan_for(
            SequencePlan::AlreadySatisfied {
                sequence: None,
                note: "a broader entry already covers it".into(),
            },
            &advertise_add(),
            &params(),
        )
        .expect("maps");
        assert!(matches!(plan, SessionPlan::Skip(_)));
        // Naming someone else's broader entry would have a rollback delete it.
        assert!(persist.is_none());
    }

    #[test]
    fn a_refusal_pushes_nothing_persists_nothing_and_keeps_its_reason() {
        let reason = "prefix-list 'pfx-to-viva' has no free sequence number between 5 and 6";
        let (plan, persist) = session_plan_for(
            SequencePlan::Refuse(reason.into()),
            &advertise_add(),
            &params(),
        )
        .expect("maps");
        match plan {
            SessionPlan::Refuse(r) => assert_eq!(r, reason),
            other => panic!("expected a refusal, got {other:?}"),
        }
        assert!(persist.is_none());
    }

    #[test]
    fn a_sequence_the_template_rejects_aborts_instead_of_pushing() {
        // 0 is outside the IOS range; the typed `seq` parameter refuses it, so no
        // command is produced at all (the allowlist would be the last line of
        // defence, but it is never reached).
        assert!(session_plan_for(SequencePlan::Use(0), &advertise_add(), &params()).is_err());
    }

    #[test]
    fn no_verify_step_is_uncertain_when_verification_required() {
        // Commands applied but the template carries no verify step: with
        // verification required we must not claim success (doctrine).
        assert_eq!(final_state_for(true, Verdict::None, true), "uncertain");
    }

    #[test]
    fn no_verify_step_is_success_when_verification_not_required() {
        assert_eq!(final_state_for(true, Verdict::None, false), "succeeded");
    }

    #[test]
    fn legacy_verification_keeps_empty_filtered_absence_but_rejects_empty_router_state() {
        let filtered = VerifyStep {
            command: "show running-config | include ^ip route 203.0.113.0 255.255.255.0 Null0$"
                .into(),
            expect: None,
            reject: Some("ip route 203.0.113.0 255.255.255.0 Null0".into()),
        };
        assert_eq!(legacy_verdict("", &filtered), Verdict::Pass);
        let advertisement = VerifyStep {
            command: "show ip bgp neighbors 192.0.2.1 advertised-routes".into(),
            expect: Some("203.0.113.0/24".into()),
            reject: None,
        };
        assert_eq!(legacy_verdict("", &advertisement), Verdict::Uncertain);
        assert_eq!(
            legacy_verdict(
                "Network Next Hop\nTotal number of prefixes 0",
                &advertisement
            ),
            Verdict::Fail
        );
    }

    #[test]
    fn legacy_reject_only_evidence_is_bound_to_the_supported_command_target() {
        let static_absent = VerifyStep {
            command: "show running-config | include ^ip route 203.0.113.0 255.255.255.0 Null0$"
                .into(),
            expect: None,
            reject: Some("ip route 203.0.113.0 255.255.255.0 Null0".into()),
        };
        assert_eq!(
            legacy_verdict("ip route 198.51.100.0 255.255.255.0 Null0", &static_absent),
            Verdict::Uncertain
        );

        let unsupported = VerifyStep {
            command: "show running-config | include ^arbitrary operator text$".into(),
            expect: None,
            reject: Some("arbitrary operator text".into()),
        };
        assert_eq!(legacy_verdict("", &unsupported), Verdict::Uncertain);

        let mss_absent = VerifyStep {
            command: "show running-config interface GigabitEthernet0/0 | include ip tcp adjust-mss"
                .into(),
            expect: None,
            reject: Some("ip tcp adjust-mss".into()),
        };
        assert_eq!(legacy_verdict("", &mss_absent), Verdict::Pass);
        assert_eq!(
            legacy_verdict(
                "interface GigabitEthernet0/1\n ip tcp adjust-mss 1400",
                &mss_absent
            ),
            Verdict::Uncertain
        );
    }

    #[test]
    fn legacy_advertisement_reject_needs_a_complete_table() {
        let absent = VerifyStep {
            command: "show ip bgp neighbors 192.0.2.1 advertised-routes".into(),
            expect: None,
            reject: Some("203.0.113.0/24".into()),
        };
        assert_eq!(
            legacy_verdict("Network Next Hop\n*> 198.51.100.0/24 0.0.0.0", &absent),
            Verdict::Uncertain
        );
        assert_eq!(
            legacy_verdict(
                "Network Next Hop\n*> 198.51.100.0/24 0.0.0.0\nTotal number of prefixes 1",
                &absent
            ),
            Verdict::Pass
        );
    }

    #[test]
    fn failed_apply_is_uncertain_regardless_of_verification_result() {
        assert_eq!(final_state_for(false, Verdict::Pass, true), "uncertain");
        assert_eq!(final_state_for(false, Verdict::Fail, true), "uncertain");
        assert_eq!(
            final_state_for(false, Verdict::Uncertain, true),
            "uncertain"
        );
        assert_eq!(final_state_for(false, Verdict::None, false), "uncertain");
    }
}
