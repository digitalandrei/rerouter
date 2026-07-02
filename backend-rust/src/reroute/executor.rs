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
    pub user_id: Option<u64>,
    pub reason: Option<String>,
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
    req: ActionRequest,
    dry_run: bool,
) -> ExecOutcome {
    let device_name = device_name(pool, req.device_id).await;
    let device_ref = req.device_id.to_string();

    // 1. Render the exact plan (also validates params).
    let plan = match crate::reroute::templates::render(&req.template, &req.params) {
        Ok(p) => p,
        Err(e) => return blocked(&req, device_name, format!("invalid parameters: {e}")),
    };

    // GATE 0 — operating mode. In observe, return the would-run plan, never run.
    let mode = crate::api::settings::operating_mode(pool, cfg).await;
    if mode != "enforce" {
        return ExecOutcome {
            executed: false,
            reroute_id: None,
            state: None,
            message: "observe mode: NOT executed — this is the plan that would run".into(),
            blocked_reason: None,
            would_run: Some(plan),
            device_id: req.device_id,
            device_name,
        };
    }

    // Dry-run: render only, change nothing (even in enforce mode).
    if dry_run {
        return ExecOutcome {
            executed: false,
            reroute_id: None,
            state: None,
            message: "dry run: rendered plan only, nothing executed".into(),
            blocked_reason: None,
            would_run: Some(plan),
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

    // Reserve a slot under a per-device advisory lock (atomic re-check + INSERT).
    let reroute_id = match guard::reserve_and_persist(pool, &req, &plan).await {
        Ok(id) => id,
        Err(reason) => return blocked(&req, device_name, reason.to_string()),
    };
    audit(
        pool,
        &req,
        reroute_id,
        "reroute_planned",
        &format!(
            "planned '{}' on device {}",
            req.template.name, req.device_id
        ),
    )
    .await;
    enqueue_alert(
        pool,
        &req,
        reroute_id,
        "reroute_started",
        "info",
        json!({ "commands": plan.commands }),
    )
    .await;

    let final_state = run_state_machine(
        pool,
        ssh,
        &req,
        reroute_id,
        &plan,
        cfg.reroute.require_verification,
    )
    .await;

    // Post-action cooldowns: per-device always, per-rule when rule-triggered.
    let _ = cooldown::record(
        pool,
        "device",
        &device_ref,
        cfg.safety.same_device_cooldown_seconds as i64,
        "post-action device cooldown",
    )
    .await;
    if let Some(rule_id) = req.rule_id {
        let _ = cooldown::record(
            pool,
            "rule",
            &rule_id.to_string(),
            cfg.safety.same_rule_cooldown_seconds as i64,
            "post-action rule cooldown",
        )
        .await;
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
        device_id: req.device_id,
        device_name,
    }
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
) -> String {
    // -> pending: committed to act, persisted BEFORE any side effect. Crash
    // recovery treats pending/running/verifying as in-flight (=> uncertain), so
    // a crash from here on locks the device rather than being assumed harmless.
    let _ = sqlx::query("UPDATE reroutes SET state = 'pending' WHERE id = ?")
        .bind(reroute_id)
        .execute(pool)
        .await;

    // -> running: the SSH session is about to push config (the side effect).
    let _ = sqlx::query(
        "UPDATE reroutes SET state = 'running', started_at = UTC_TIMESTAMP() WHERE id = ?",
    )
    .bind(reroute_id)
    .execute(pool)
    .await;

    // Apply over a single SSH session (config mode state must persist across the
    // command sequence, so this cannot be split into per-command sessions).
    let apply = ssh.apply(req.device_id, &plan.commands).await;
    let applied_ok = match &apply {
        Ok(out) => {
            for (i, r) in out.results.iter().enumerate() {
                persist_output(
                    pool,
                    reroute_id,
                    (i + 1) as u32,
                    &r.command,
                    &r.output,
                    "ok",
                )
                .await;
            }
            let _ = sqlx::query("UPDATE reroute_steps SET state = 'done' WHERE reroute_id = ?")
                .bind(reroute_id)
                .execute(pool)
                .await;
            true
        }
        Err(e) => {
            persist_output(pool, reroute_id, 0, "<apply>", &e.to_string(), "error").await;
            let _ = sqlx::query("UPDATE reroute_steps SET state = 'failed' WHERE reroute_id = ?")
                .bind(reroute_id)
                .execute(pool)
                .await;
            false
        }
    };

    // -> verifying (read-only confirmation in a separate session)
    let _ = sqlx::query("UPDATE reroutes SET state = 'verifying' WHERE id = ?")
        .bind(reroute_id)
        .execute(pool)
        .await;
    let verdict = verify(pool, ssh, req, reroute_id, plan).await;

    let final_state = match verdict {
        Verdict::Pass => "succeeded",
        Verdict::Fail => "failed",
        Verdict::Uncertain => "uncertain",
        // Template had no verify step. If verification is required we must NOT
        // claim success — mark uncertain (which locks the device) instead.
        Verdict::None => final_state_without_verification(applied_ok, require_verification),
    };

    finalize(pool, req, reroute_id, final_state, applied_ok, verdict).await;
    final_state.to_string()
}

enum Verdict {
    Pass,
    Fail,
    Uncertain,
    None,
}

/// Pure decision for the no-verify-step case: when verification is required we
/// must NEVER report success (doctrine: "verify, don't assume") — mark the action
/// `uncertain` (which locks the device) instead. Unit-tested below.
fn final_state_without_verification(applied_ok: bool, require_verification: bool) -> &'static str {
    if !applied_ok {
        "failed"
    } else if require_verification {
        "uncertain"
    } else {
        "succeeded"
    }
}

/// Run the verification `show` read and judge it (substring expect/reject).
async fn verify<S: SshExecutor>(
    pool: &MySqlPool,
    ssh: &S,
    req: &ActionRequest,
    reroute_id: u64,
    plan: &RenderedPlan,
) -> Verdict {
    let Some(vstep) = plan.verify.as_ref() else {
        return Verdict::None;
    };
    match ssh.verify_read(req.device_id, &vstep.command).await {
        Ok(output) => {
            let pass = judge(&output, vstep);
            persist_verification(
                pool,
                reroute_id,
                vstep,
                &output,
                if pass { "pass" } else { "fail" },
            )
            .await;
            if pass {
                Verdict::Pass
            } else {
                Verdict::Fail
            }
        }
        Err(e) => {
            persist_verification(
                pool,
                reroute_id,
                vstep,
                &format!("verify read failed: {e}"),
                "uncertain",
            )
            .await;
            Verdict::Uncertain
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
) {
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
        "uncertain" => Some("could not verify the resulting state after pushing config".into()),
        _ => None,
    };

    if let Err(e) = sqlx::query(
        "UPDATE reroutes SET state = ?, finished_at = UTC_TIMESTAMP(), success = ?, \
         verification_status = ?, failure_reason = ? WHERE id = ?",
    )
    .bind(state)
    .bind(success)
    .bind(verification_status)
    .bind(&failure_reason)
    .bind(reroute_id)
    .execute(pool)
    .await
    {
        tracing::error!(
            event_type = "reroute_finalize_persist_failed",
            reroute_id,
            device_id = req.device_id,
            state,
            error = %e,
            "failed to persist final reroute state — runtime state may be inconsistent"
        );
    }

    if state == "uncertain" {
        // Lock the device; an admin must acknowledge before reroutes resume. If
        // this write fails the device is NOT actually locked, so make it LOUD:
        // a silently-unlocked device after an unverifiable reroute is exactly the
        // failure mode the doctrine forbids (mirrors recover_on_startup).
        if let Err(e) = locks::create(
            pool,
            "device",
            Some(&req.device_id.to_string()),
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
    let severity = match state {
        "succeeded" => "info",
        "failed" => "critical",
        "uncertain" => "critical",
        _ => "info",
    };
    enqueue_alert(
        pool,
        req,
        reroute_id,
        &format!("reroute_{state}"),
        severity,
        json!({ "verification": verification_status, "failure_reason": failure_reason }),
    )
    .await;
    audit(
        pool,
        req,
        reroute_id,
        &format!("reroute_{state}"),
        &format!("reroute #{reroute_id} {state}"),
    )
    .await;

    tracing::info!(
        event_type = "reroute_finalized",
        reroute_id,
        device_id = req.device_id,
        state,
        template = %req.template.name,
        "reroute finalized"
    );
}

// ---- persistence helpers -------------------------------------------------------

async fn persist_output(
    pool: &MySqlPool,
    reroute_id: u64,
    step: u32,
    request: &str,
    response: &str,
    status: &str,
) {
    let _ = sqlx::query(
        "INSERT INTO reroute_outputs (reroute_id, step_number, request, response, status, started_at, finished_at) \
         VALUES (?, ?, ?, ?, ?, UTC_TIMESTAMP(), UTC_TIMESTAMP())",
    )
    .bind(reroute_id)
    .bind(step)
    .bind(request)
    .bind(response)
    .bind(status)
    .execute(pool)
    .await;
}

async fn persist_verification(
    pool: &MySqlPool,
    reroute_id: u64,
    v: &VerifyStep,
    observed: &str,
    result: &str,
) {
    let expected = format!(
        "expect={} reject={}",
        v.expect.as_deref().unwrap_or("-"),
        v.reject.as_deref().unwrap_or("-")
    );
    let _ = sqlx::query(
        "INSERT INTO reroute_verifications (reroute_id, method, expected, observed, result, checked_at) \
         VALUES (?, 'ios_show', ?, ?, ?, UTC_TIMESTAMP())",
    )
    .bind(reroute_id)
    .bind(expected)
    .bind(observed)
    .bind(result)
    .execute(pool)
    .await;
}

async fn enqueue_alert(
    pool: &MySqlPool,
    req: &ActionRequest,
    reroute_id: u64,
    event_type: &str,
    severity: &str,
    extra: Value,
) {
    let payload = json!({
        "reroute_id": reroute_id,
        "template": req.template.name,
        "device_id": req.device_id,
        "trigger_type": req.trigger_type,
        "detail": extra,
    });
    let dedup_key = format!("{event_type}:reroute:{reroute_id}");
    if let Err(e) = sqlx::query(
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
    .await
    {
        tracing::error!(
            event_type = "reroute_alert_enqueue_failed",
            reroute_id,
            alert = %event_type,
            error = %e,
            "failed to enqueue reroute alert — operators may not be notified"
        );
    }
}

async fn audit(pool: &MySqlPool, req: &ActionRequest, reroute_id: u64, event: &str, message: &str) {
    let actor_type = if req.user_id.is_some() {
        "user"
    } else {
        "controller"
    };
    if let Err(e) = sqlx::query(
        "INSERT INTO audit_logs (actor_type, actor_user_id, event_type, entity_type, entity_id, reroute_id, message) \
         VALUES (?, ?, ?, 'reroute', ?, ?, ?)",
    )
    .bind(actor_type)
    .bind(req.user_id)
    .bind(event)
    .bind(reroute_id)
    .bind(reroute_id)
    .bind(message)
    .execute(pool)
    .await
    {
        tracing::error!(
            event_type = "reroute_audit_persist_failed",
            reroute_id,
            audited = %event,
            error = %e,
            "failed to write reroute audit row"
        );
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
        device_id: req.device_id,
        device_name,
    }
}

#[cfg(test)]
mod tests {
    use super::final_state_without_verification;

    #[test]
    fn no_verify_step_is_uncertain_when_verification_required() {
        // Commands applied but the template carries no verify step: with
        // verification required we must not claim success (doctrine).
        assert_eq!(final_state_without_verification(true, true), "uncertain");
    }

    #[test]
    fn no_verify_step_is_success_when_verification_not_required() {
        assert_eq!(final_state_without_verification(true, false), "succeeded");
    }

    #[test]
    fn failed_apply_is_failed_regardless_of_verification_flag() {
        assert_eq!(final_state_without_verification(false, true), "failed");
        assert_eq!(final_state_without_verification(false, false), "failed");
    }
}
