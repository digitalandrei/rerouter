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
use crate::reroute::locks;
use crate::reroute::templates::{RenderedPlan, Template, VerifyStep};
use crate::ssh;

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

/// Execute (or render/observe/dry-run) one action against one device.
pub async fn execute(
    pool: &MySqlPool,
    cfg: &Config,
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

    // Protected-interface guard — refuse a disruptive interface action
    // (shutdown / MSS clamp) on the device's management/transit path, so the
    // controller cannot black-hole or cut its own path to the device. Applies to
    // manual, automatic, and rollback triggers alike. (Observe mode and dry-run
    // returned above, so this only blocks real executions.)
    if let Some(reason) =
        protected_interface_block(pool, req.device_id, &req.template, &req.params).await
    {
        return blocked(&req, device_name, reason);
    }

    // Global automatic master switch — gates AUTOMATIC triggers ONLY (manual and
    // rollback have their own upstream permission checks and must not be disabled
    // by this switch). Doctrine: automatic execution needs enforce mode AND this
    // global enable AND the per-rule enable. The runtime value lives in
    // system_settings; config is only the startup fallback.
    if req.trigger_type == "automatic"
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
            "automatic actions are globally disabled (automatic_actions_enabled = false)".into(),
        );
    }

    // Verify-or-refuse: when verification is required, an action whose template
    // has NO verification step can never be confirmed. Never auto-run such a
    // template; for manual/rollback it still runs but the state machine forces an
    // `uncertain` outcome instead of reporting success (see run_state_machine).
    if cfg.reroute.require_verification && plan.verify.is_none() && req.trigger_type == "automatic"
    {
        return blocked(
            &req,
            device_name,
            "template has no verification step and reroute.require_verification is enabled".into(),
        );
    }

    // Safety gates (device-scoped).
    if crate::api::settings::bool_setting(pool, "global_maintenance_lock", false).await {
        return blocked(
            &req,
            device_name,
            "global maintenance lock is active".into(),
        );
    }
    if locks::is_blocked(pool, "device", &device_ref)
        .await
        .unwrap_or(true)
    {
        return blocked(
            &req,
            device_name,
            "device is locked (a prior action needs admin acknowledgement)".into(),
        );
    }
    // NOTE: the "already running on this device" and "unresolved uncertain"
    // guards are re-checked atomically with the INSERT under a per-device
    // advisory lock below (see reserve_reroute_slot), so two concurrent triggers
    // cannot both pass them and double-apply config to one device.
    if let Ok(Some(until)) = cooldown::active_until(pool, "device", &device_ref).await {
        return blocked(
            &req,
            device_name,
            format!("device is in cooldown until {}", until.to_rfc3339()),
        );
    }
    // Per-rule re-fire throttle (only for rule-triggered actions).
    if let Some(rule_id) = req.rule_id {
        if let Ok(Some(until)) = cooldown::active_until(pool, "rule", &rule_id.to_string()).await {
            return blocked(
                &req,
                device_name,
                format!("rule {rule_id} is in cooldown until {}", until.to_rfc3339()),
            );
        }
    }
    // Global circuit breaker: cap executed actions per rolling window across all
    // devices. Counts real reroute rows (manual + automatic + rollback).
    let rl_count = cfg.safety.global_action_rate_limit_count;
    if rl_count > 0 {
        let recent =
            recent_reroute_count(pool, cfg.safety.global_action_rate_limit_window_seconds).await;
        if recent >= rl_count as i64 {
            return blocked(
                &req,
                device_name,
                format!(
                    "global action rate limit reached ({recent} in {}s; max {rl_count})",
                    cfg.safety.global_action_rate_limit_window_seconds
                ),
            );
        }
    }

    // Reserve a slot under a per-device advisory lock: the already-running /
    // uncertain re-checks and the INSERT happen atomically, so two concurrent
    // triggers cannot both pass the guard and push config to the same device.
    let lock_name = format!("reroute_dev_{}", req.device_id);
    let mut guard = match pool.acquire().await {
        Ok(c) => c,
        Err(e) => {
            return blocked(
                &req,
                device_name,
                format!("could not acquire device guard: {e}"),
            )
        }
    };
    let got: Option<i64> = sqlx::query_scalar::<_, Option<i64>>("SELECT GET_LOCK(?, 5)")
        .bind(&lock_name)
        .fetch_one(&mut *guard)
        .await
        .ok()
        .flatten();
    if got != Some(1) {
        return blocked(
            &req,
            device_name,
            "could not acquire the per-device reroute guard (another action is being set up)"
                .into(),
        );
    }
    let reserved = reserve_reroute_slot(pool, &req, &plan).await;
    let _ = sqlx::query("SELECT RELEASE_LOCK(?)")
        .bind(&lock_name)
        .execute(&mut *guard)
        .await;
    drop(guard);
    let reroute_id = match reserved {
        Ok(id) => id,
        Err(reason) => return blocked(&req, device_name, reason),
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
async fn run_state_machine(
    pool: &MySqlPool,
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
    let apply = ssh::run_commands(pool, req.device_id, &plan.commands).await;
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
    let verdict = verify(pool, req, reroute_id, plan).await;

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

/// Reserve a reroute row for this device while the caller holds the per-device
/// advisory lock: re-check the device-scoped guards (already-running / uncertain)
/// and INSERT atomically. `Err(reason)` means blocked. Pairing the checks with
/// the INSERT under one lock is what closes the concurrent double-apply race.
async fn reserve_reroute_slot(
    pool: &MySqlPool,
    req: &ActionRequest,
    plan: &RenderedPlan,
) -> Result<u64, String> {
    if running_on_device(pool, req.device_id).await {
        return Err("another reroute is already running on this device".into());
    }
    if has_uncertain(pool, req.device_id).await {
        return Err("an unresolved uncertain action exists on this device".into());
    }
    insert_reroute(pool, req, plan)
        .await
        .map_err(|e| format!("could not persist reroute: {e}"))
}

/// Run the verification `show` read and judge it (substring expect/reject).
async fn verify(
    pool: &MySqlPool,
    req: &ActionRequest,
    reroute_id: u64,
    plan: &RenderedPlan,
) -> Verdict {
    let Some(vstep) = plan.verify.as_ref() else {
        return Verdict::None;
    };
    match ssh::run_commands(pool, req.device_id, std::slice::from_ref(&vstep.command)).await {
        Ok(out) => {
            let output = out
                .results
                .first()
                .map(|r| r.output.clone())
                .unwrap_or_default();
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

    let _ = sqlx::query(
        "UPDATE reroutes SET state = ?, finished_at = UTC_TIMESTAMP(), success = ?, \
         verification_status = ?, failure_reason = ? WHERE id = ?",
    )
    .bind(state)
    .bind(success)
    .bind(verification_status)
    .bind(&failure_reason)
    .bind(reroute_id)
    .execute(pool)
    .await;

    if state == "uncertain" {
        // Lock the device; an admin must acknowledge before reroutes resume.
        let _ = locks::create(
            pool,
            "device",
            Some(&req.device_id.to_string()),
            "auto_uncertain",
            &format!("reroute #{reroute_id} could not be verified"),
            None,
        )
        .await;
    }

    let severity = match state {
        "succeeded" => "info",
        "failed" => "warning",
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

async fn insert_reroute(
    pool: &MySqlPool,
    req: &ActionRequest,
    plan: &RenderedPlan,
) -> anyhow::Result<u64> {
    let steps = json!({ "commands": plan.commands, "verify": plan.verify });
    let res = sqlx::query(
        "INSERT INTO reroutes \
            (device_id, rule_id, reroute_template_id, trigger_type, triggered_by_user_id, \
             state, reason, parameters_json, planned_steps_json) \
         VALUES (?, ?, ?, ?, ?, 'planned', ?, ?, ?)",
    )
    .bind(req.device_id)
    .bind(req.rule_id)
    .bind(req.template.id)
    .bind(req.trigger_type)
    .bind(req.user_id)
    .bind(&req.reason)
    .bind(sqlx::types::Json(&req.params))
    .bind(sqlx::types::Json(&steps))
    .execute(pool)
    .await?;
    let reroute_id = res.last_insert_id();

    for (i, cmd) in plan.commands.iter().enumerate() {
        let _ = sqlx::query(
            "INSERT INTO reroute_steps (reroute_id, step_number, description, mode, state) \
             VALUES (?, ?, ?, 'ios_ssh', 'planned')",
        )
        .bind(reroute_id)
        .bind((i + 1) as u32)
        .bind(cmd)
        .execute(pool)
        .await;
    }
    Ok(reroute_id)
}

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
    let _ = sqlx::query(
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
    .await;
}

async fn audit(pool: &MySqlPool, req: &ActionRequest, reroute_id: u64, event: &str, message: &str) {
    let actor_type = if req.user_id.is_some() {
        "user"
    } else {
        "controller"
    };
    let _ = sqlx::query(
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
    .await;
}

async fn device_name(pool: &MySqlPool, device_id: u64) -> Option<String> {
    sqlx::query_scalar::<_, String>("SELECT name FROM devices WHERE id = ?")
        .bind(device_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
}

/// Block disruptive interface actions targeting a `protected` interface (the
/// device's management / transit / SSH path). Returns `Some(reason)` to block,
/// `None` to proceed. A template "targets an interface" when its parameter schema
/// has a param with `source: "interface_name"`; the guard resolves that param's
/// value and matches it against `device_interfaces.if_name`/`if_descr`. Templates
/// without such a param (BGP, null-route, etc.) are never blocked here. An
/// unknown / unmatched interface name proceeds (the command is still gated by the
/// operating mode and the other safety gates).
async fn protected_interface_block(
    pool: &MySqlPool,
    device_id: u64,
    template: &Template,
    params: &Value,
) -> Option<String> {
    // Find the interface-name parameter, if any.
    let schema = template.parameter_schema.as_object()?;
    let iface_param = schema.iter().find_map(|(name, spec)| {
        (spec.get("source").and_then(Value::as_str) == Some("interface_name")).then(|| name.clone())
    })?;
    let iface = params
        .get(&iface_param)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())?;

    let protected: Option<i64> = sqlx::query_scalar(
        "SELECT protected FROM device_interfaces \
         WHERE device_id = ? AND (if_name = ? OR if_descr = ?) ORDER BY protected DESC LIMIT 1",
    )
    .bind(device_id)
    .bind(iface)
    .bind(iface)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    match protected {
        Some(p) if p != 0 => Some(format!(
            "interface '{iface}' is flagged as a protected management/transit path; \
             disruptive interface actions on it are blocked to prevent self-lockout"
        )),
        _ => None,
    }
}

async fn running_on_device(pool: &MySqlPool, device_id: u64) -> bool {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM reroutes WHERE device_id = ? AND state IN ('planned','pending','running','verifying')",
    )
    .bind(device_id)
    .fetch_one(pool)
    .await
    .unwrap_or(1);
    n > 0
}

async fn has_uncertain(pool: &MySqlPool, device_id: u64) -> bool {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM reroutes WHERE device_id = ? AND state = 'uncertain'",
    )
    .bind(device_id)
    .fetch_one(pool)
    .await
    .unwrap_or(1);
    n > 0
}

/// Count reroute rows created within the last `window_secs` (the global
/// rate-limit window). On a DB error, returns the limit's worst case via a large
/// number so the breaker fails safe (blocks).
async fn recent_reroute_count(pool: &MySqlPool, window_secs: u64) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM reroutes WHERE created_at > DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? SECOND)",
    )
    .bind(window_secs as i64)
    .fetch_one(pool)
    .await
    .unwrap_or(i64::MAX)
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
