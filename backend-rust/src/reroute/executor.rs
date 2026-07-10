//! Reroute executor. Re-checks EVERY safety gate at execution time, drives the
//! two-phase state machine, persists each step's output, and runs verification.
//! See ../docs/reroute-engine.md.
//!
//! Gate order (device_cli, device-scoped — any failure aborts and is logged):
//!   GATE 0 — operating_mode == enforce. In `observe` mode NOTHING executes;
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
use crate::ssh::{RusshExecutor, SshExecutor};

/// What to run and on whose behalf.
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
async fn execute_with<S: SshExecutor>(
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
    // Rollbacks use the exact typed parameters persisted with the original
    // action. Fresh inventory may legitimately have changed and must not block
    // corrective work; every new manual/automatic action is canonicalized.
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
        match crate::reroute::templates::prefix_target_is_contained(
            pool,
            req.device_id,
            &req.template,
            &req.params,
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => {
                return blocked(
                    &req,
                    device_name,
                    "prefix target is outside the device's announced space".into(),
                )
            }
            Err(e) => {
                return blocked(
                    &req,
                    device_name,
                    format!("could not validate prefix containment: {e}"),
                )
            }
        }
    }
    if let Err(e) = snapshot_prior_route_map(pool, &mut req).await {
        return blocked(
            &req,
            device_name,
            format!("could not snapshot rollback state: {e}"),
        );
    }

    // 1. Render the exact plan (also validates params).
    let plan = match crate::reroute::templates::render(&req.template, &req.params) {
        Ok(p) => p,
        Err(e) => return blocked(&req, device_name, format!("invalid parameters: {e}")),
    };

    // GATE 0 — operating mode. In observe (or an enforce-mode dry-run) NOTHING
    // runs; return the would-run plan plus its rollback (undo) commands so the
    // preview shows how to reverse the action by hand. The rollback is rendered
    // only here, never on the executing path.
    let mode = crate::api::settings::operating_mode(pool, cfg).await;
    if mode != "enforce" || dry_run {
        let would_run_rollback =
            crate::reroute::rollback::render_rollback_plan(pool, req.template.id, &req.params)
                .await;
        let message = if mode != "enforce" {
            "observe mode: NOT executed — this is the plan that would run"
        } else {
            "dry run: rendered plan only, nothing executed"
        };
        return ExecOutcome {
            executed: false,
            reroute_id: None,
            state: None,
            message: message.into(),
            blocked_reason: None,
            would_run: Some(plan),
            would_run_rollback,
            device_id: req.device_id,
            device_name,
        };
    }

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

    let final_state = match run_state_machine(
        pool,
        ssh,
        &req,
        reroute_id,
        &plan,
        cfg.reroute.require_verification,
    )
    .await
    {
        Ok(state) => state,
        Err(e) => {
            // No SSH side effect occurs before run_state_machine's checked
            // planned->pending->running transitions complete.
            let aborted = sqlx::query(
                "UPDATE reroutes SET state = 'failed', finished_at = UTC_TIMESTAMP(), success = 0, \
                 failure_reason = ? WHERE id = ? AND state IN ('planned','pending')",
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

    let message = match final_state.as_str() {
        "succeeded" => "reroute executed and verified".to_string(),
        "failed" => "reroute failed — verification did not confirm the change".to_string(),
        "uncertain" => {
            "reroute UNCERTAIN — device locked pending admin acknowledgement".to_string()
        }
        other => format!("reroute ended in state {other}"),
    };
    ExecOutcome {
        executed: true,
        reroute_id: Some(reroute_id),
        state: Some(final_state),
        message,
        blocked_reason: None,
        would_run: None,
        would_run_rollback: None,
        device_id: req.device_id,
        device_name,
    }
}

/// Snapshot a Route-Map Change's current assignment in the request that is
/// persisted with the reroute. Every execution path then restores the exact prior
/// map rather than only the standalone manual endpoint doing so.
async fn snapshot_prior_route_map(pool: &MySqlPool, req: &mut ActionRequest) -> anyhow::Result<()> {
    if req.template.name != "bgp_route_map_set" || req.params.get("prior_route_map").is_some() {
        return Ok(());
    }
    let Some(neighbor) = req.params.get("neighbor_ip").and_then(Value::as_str) else {
        anyhow::bail!("route-map action has no neighbor_ip");
    };
    let direction = req
        .params
        .get("direction")
        .and_then(Value::as_str)
        .unwrap_or("out");
    let prior: Option<Option<String>> = sqlx::query_scalar(
        "SELECT CASE WHEN ? = 'in' THEN in_route_map ELSE out_route_map END \
         FROM device_bgp_peers p WHERE device_id = ? AND peer_remote_addr = ? \
           AND EXISTS (SELECT 1 FROM device_route_maps r WHERE r.device_id = p.device_id \
                       AND r.last_discovered_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? HOUR)) \
         LIMIT 1",
    )
    .bind(direction)
    .bind(req.device_id)
    .bind(neighbor)
    .bind(crate::reroute::templates::ROUTING_INVENTORY_MAX_AGE_HOURS)
    .fetch_optional(pool)
    .await?;
    let prior = prior.ok_or_else(|| anyhow::anyhow!("BGP peer is no longer in inventory"))?;
    if let Value::Object(params) = &mut req.params {
        params.insert(
            "prior_route_map".into(),
            Value::String(prior.unwrap_or_default()),
        );
    }
    Ok(())
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

/// Push the apply commands, verify the result, finalize the state. Returns the
/// final state string. Persists before/after each phase.
async fn run_state_machine<S: SshExecutor>(
    pool: &MySqlPool,
    ssh: &S,
    req: &ActionRequest,
    reroute_id: u64,
    plan: &RenderedPlan,
    require_verification: bool,
) -> anyhow::Result<String> {
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
    let apply = ssh.apply(req.device_id, &plan.commands).await;
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
            if persist_output(pool, reroute_id, 0, "<apply>", &e.to_string(), "error")
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
    let (verdict, verification_persisted) = verify(pool, ssh, req, reroute_id, plan).await;
    persistence_ok &= verification_persisted;

    let mut final_state = final_state_for(applied_ok, verdict, require_verification);
    if !persistence_ok {
        final_state = "uncertain";
    }

    Ok(finalize(pool, req, reroute_id, final_state, applied_ok, verdict).await)
}

#[derive(Clone, Copy)]
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
            let pass = judge(&output, vstep);
            let persisted = persist_verification(
                pool,
                reroute_id,
                vstep,
                &output,
                if pass { "pass" } else { "fail" },
            )
            .await
            .is_ok();
            if pass {
                (Verdict::Pass, persisted)
            } else {
                (Verdict::Fail, persisted)
            }
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

/// Write the terminal state + side effects (lock on uncertain, alerts, audit).
async fn finalize(
    pool: &MySqlPool,
    req: &ActionRequest,
    reroute_id: u64,
    state: &str,
    applied_ok: bool,
    verdict: Verdict,
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

    let finalized = match sqlx::query(
        "UPDATE reroutes SET state = ?, finished_at = UTC_TIMESTAMP(), success = ?, \
         verification_status = ?, failure_reason = ? \
         WHERE id = ? AND state IN ('running','verifying')",
    )
    .bind(state)
    .bind(success)
    .bind(verification_status)
    .bind(&failure_reason)
    .bind(reroute_id)
    .execute(pool)
    .await
    {
        Ok(r) if r.rows_affected() == 1 => true,
        Ok(_) => {
            tracing::error!(
                event_type = "reroute_finalize_state_conflict",
                reroute_id,
                state,
                "terminal transition did not match an in-flight reroute"
            );
            false
        }
        Err(e) => {
            tracing::error!(
            event_type = "reroute_finalize_persist_failed",
            reroute_id,
            device_id = req.device_id,
            state,
            error = %e,
            "failed to persist final reroute state — runtime state may be inconsistent"
            );
            false
        }
    };

    let effective_state = if finalized { state } else { "uncertain" };
    if !finalized {
        // A second, conservative transition may succeed after a transient error.
        // It never claims success; an in-flight row is forced to uncertain.
        if let Err(e) = sqlx::query(
            "UPDATE reroutes SET state = 'uncertain', finished_at = UTC_TIMESTAMP(), \
             success = NULL, verification_status = 'uncertain', \
             failure_reason = 'could not durably persist the terminal execution state' \
             WHERE id = ? AND state IN ('running','verifying')",
        )
        .bind(reroute_id)
        .execute(pool)
        .await
        {
            tracing::error!(event_type = "reroute_uncertain_fallback_failed", reroute_id, error = %e, "could not persist conservative uncertain fallback");
        }
    }

    if effective_state == "uncertain" {
        // Lock the device; an admin must acknowledge before reroutes resume. If
        // this write fails the device is NOT actually locked, so make it LOUD:
        // a silently-unlocked device after an unverifiable reroute is exactly the
        // failure mode the doctrine forbids (mirrors recover_on_startup).
        if let Err(e) = locks::create(
            pool,
            "device",
            Some(&req.device_id.to_string()),
            Some(reroute_id),
            "auto_uncertain",
            &format!("reroute #{reroute_id} could not be verified"),
            None,
        )
        .await
        {
            tracing::error!(
                event_type = "reroute_lock_persist_failed",
                reroute_id,
                device_id = req.device_id,
                error = %e,
                "CRITICAL: could not lock device after an uncertain reroute — manual lock required"
            );
        }
    }

    // `failed` and `uncertain` are both doctrine-critical (docs/email-alerts.md:
    // they always fan out to the admin tier). Severity drives that fan-out, so
    // `failed` must be `critical`, not `warning`.
    let severity = match effective_state {
        "succeeded" => "info",
        "failed" => "critical",
        "uncertain" => "critical",
        _ => "info",
    };
    if let Err(e) = enqueue_alert(
        pool,
        req,
        reroute_id,
        &format!("reroute_{effective_state}"),
        severity,
        json!({ "verification": verification_status, "failure_reason": failure_reason }),
    )
    .await
    {
        tracing::error!(event_type = "reroute_alert_enqueue_failed", reroute_id, alert = %format!("reroute_{effective_state}"), error = %e, "failed to enqueue terminal reroute alert");
    }
    if let Err(e) = audit(
        pool,
        req,
        reroute_id,
        &format!("reroute_{effective_state}"),
        &format!("reroute #{reroute_id} {effective_state}"),
    )
    .await
    {
        tracing::error!(event_type = "reroute_audit_persist_failed", reroute_id, audited = %format!("reroute_{effective_state}"), error = %e, "failed to write terminal reroute audit row");
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
         failure_reason = ? WHERE id = ? AND state = 'planned'",
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
    use super::{final_state_for, Verdict};

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
