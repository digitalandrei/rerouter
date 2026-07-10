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
    // Reroutes caught mid-flight by the crash. `planned` is included: a crash in
    // the narrow window between slot reservation (state=planned) and the first
    // transition to `pending` would otherwise leave an orphan row that blocks the
    // device forever (running_on_device treats `planned` as busy) yet is never
    // reclaimed. Recovering it is fail-closed and consistent with the doctrine.
    let stuck = sqlx::query_as::<_, (u64, Option<u64>)>(
        "SELECT id, device_id FROM reroutes WHERE state IN ('planned', 'pending', 'running', 'verifying')",
    )
    .fetch_all(pool)
    .await
    .context("loading in-flight reroutes")?;

    let mut failures = 0usize;

    for (reroute_id, device_id) in &stuck {
        let recovered = async {
            let mut tx = pool.begin().await?;
            let updated = sqlx::query(
                "UPDATE reroutes SET state = 'uncertain', finished_at = UTC_TIMESTAMP(), \
                 failure_reason = 'controller restarted mid-action; outcome unverified' \
                 WHERE id = ? AND state IN ('planned','pending','running','verifying')",
            )
            .bind(reroute_id)
            .execute(&mut *tx)
            .await?;
            anyhow::ensure!(
                updated.rows_affected() == 1,
                "in-flight state changed during recovery"
            );

            if let Some(dev) = device_id {
                crate::reroute::locks::create_on(
                    &mut tx,
                    "device",
                    Some(&dev.to_string()),
                    Some(*reroute_id),
                    "auto_crash",
                    &format!("reroute #{reroute_id} was in-flight at restart; outcome unknown"),
                    None,
                )
                .await?;
            }

            let payload = serde_json::json!({
                "reroute_id": reroute_id,
                "device_id": device_id,
                "reason": "controller restart mid-action",
            });
            sqlx::query(
                "INSERT INTO alerts (event_type, severity, device_id, payload_json, dedup_key) \
                 VALUES ('reroute_uncertain', 'critical', ?, ?, ?)",
            )
            .bind(device_id)
            .bind(sqlx::types::Json(&payload))
            .bind(format!("reroute_uncertain:reroute:{reroute_id}"))
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO audit_logs \
                 (actor_type, event_type, entity_type, entity_id, reroute_id, message) \
                 VALUES ('system', 'reroute_uncertain', 'reroute', ?, ?, \
                         'marked uncertain on startup recovery')",
            )
            .bind(reroute_id)
            .bind(reroute_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;

        if let Err(e) = recovered {
            failures += 1;
            tracing::error!(event_type = "recovery_transaction_failed", reroute_id, error = %e, "FAILED to atomically recover in-flight reroute; startup will abort and retry next time");
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
