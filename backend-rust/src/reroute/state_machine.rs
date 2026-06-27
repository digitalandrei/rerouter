//! Two-phase reroute state machine and crash recovery.
//! See ../docs/reroute-engine.md and ../docs/state-recovery.md.
//!
//!   planned -> pending -> running -> verifying -> succeeded
//!                                \-> failed
//!                                \-> uncertain
//!
//! Persist state BEFORE and AFTER every step. Never treat "sent" as "succeeded".

use anyhow::{Context, Result};
use sqlx::MySqlPool;

/// On startup, any reroute in pending/running/verifying becomes `uncertain` and
/// locks the affected device until an admin acknowledges it. Do NOT assume
/// nothing happened after a crash — a config push made milliseconds before the
/// crash may have taken effect.
///
/// SAFETY: this recovery is non-negotiable and has no opt-out. Every persistence
/// step is checked; a failure (e.g. DB unavailable at startup) is logged at
/// `error`, counted, and — if anything failed to persist — raised as a critical
/// `recovery_degraded` alert and returned as an `Err`, so the controller never
/// proceeds while silently believing a crashed reroute "did nothing".
pub async fn recover_on_startup(pool: &MySqlPool) -> Result<()> {
    // Reroutes caught mid-flight by the crash.
    let stuck = sqlx::query_as::<_, (u64, Option<u64>)>(
        "SELECT id, device_id FROM reroutes WHERE state IN ('pending', 'running', 'verifying')",
    )
    .fetch_all(pool)
    .await
    .context("loading in-flight reroutes")?;

    let mut failures = 0usize;

    for (reroute_id, device_id) in &stuck {
        // 1. Mark uncertain (terminal until acknowledged).
        if let Err(e) = sqlx::query(
            "UPDATE reroutes SET state = 'uncertain', finished_at = UTC_TIMESTAMP(), \
             failure_reason = 'controller restarted mid-action; outcome unverified' WHERE id = ?",
        )
        .bind(reroute_id)
        .execute(pool)
        .await
        {
            failures += 1;
            tracing::error!(
                event_type = "recovery_write_failed",
                step = "mark_uncertain",
                reroute_id,
                error = %e,
                "FAILED to mark crashed reroute uncertain — it may stay pending"
            );
        }

        // 2. Lock the affected device (auto_crash) until an admin acknowledges.
        if let Some(dev) = device_id {
            if let Err(e) = crate::reroute::locks::create(
                pool,
                "device",
                Some(&dev.to_string()),
                "auto_crash",
                &format!("reroute #{reroute_id} was in-flight at restart; outcome unknown"),
                None,
            )
            .await
            {
                failures += 1;
                tracing::error!(
                    event_type = "recovery_write_failed",
                    step = "lock_device",
                    reroute_id,
                    device_id = dev,
                    error = %e,
                    "FAILED to lock device after crash — device is NOT protected"
                );
            }
        }

        // 3. Alert (uncertain is always sent, never collapsed).
        let payload = serde_json::json!({
            "reroute_id": reroute_id,
            "device_id": device_id,
            "reason": "controller restart mid-action",
        });
        if let Err(e) = sqlx::query(
            "INSERT INTO alerts (event_type, severity, device_id, payload_json, dedup_key) \
             VALUES ('reroute_uncertain', 'critical', ?, ?, ?)",
        )
        .bind(device_id)
        .bind(sqlx::types::Json(&payload))
        .bind(format!("reroute_uncertain:reroute:{reroute_id}"))
        .execute(pool)
        .await
        {
            failures += 1;
            tracing::error!(
                event_type = "recovery_write_failed",
                step = "alert",
                reroute_id,
                error = %e,
                "FAILED to enqueue uncertain alert"
            );
        }

        // 4. Audit.
        if let Err(e) = sqlx::query(
            "INSERT INTO audit_logs (actor_type, event_type, entity_type, entity_id, reroute_id, message) \
             VALUES ('system', 'reroute_uncertain', 'reroute', ?, ?, 'marked uncertain on startup recovery')",
        )
        .bind(reroute_id)
        .bind(reroute_id)
        .execute(pool)
        .await
        {
            failures += 1;
            tracing::error!(
                event_type = "recovery_write_failed",
                step = "audit",
                reroute_id,
                error = %e,
                "FAILED to write recovery audit row"
            );
        }
    }

    if !stuck.is_empty() {
        tracing::warn!(
            event_type = "recovery_uncertain",
            count = stuck.len(),
            "marked in-flight reroutes uncertain and locked their devices"
        );
    }

    if failures > 0 {
        // Best-effort surfacing — if even this insert fails, the error log above
        // is the floor. Then refuse to continue: an incompletely-recovered
        // controller must not come up believing everything is clean.
        let payload = serde_json::json!({
            "failed_writes": failures,
            "in_flight_reroutes": stuck.len(),
            "reason": "one or more crash-recovery writes failed; affected assets may be UNPROTECTED",
        });
        let _ = sqlx::query(
            "INSERT INTO alerts (event_type, severity, payload_json, dedup_key) \
             VALUES ('recovery_degraded', 'critical', ?, 'recovery_degraded')",
        )
        .bind(sqlx::types::Json(&payload))
        .execute(pool)
        .await;
        anyhow::bail!(
            "startup recovery incomplete: {failures} persistence write(s) failed; \
             refusing to start while crashed reroutes may be unrecovered"
        );
    }

    tracing::info!(
        event_type = "recovery_complete",
        "startup state recovery done"
    );
    Ok(())
}
