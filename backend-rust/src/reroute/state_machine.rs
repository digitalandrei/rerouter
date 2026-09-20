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

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconciliationResult {
    Changed,
    NotApplied,
    Conflict,
}

/// Read-only exact reconciliation for an uncertain action. Only an exact match
/// with the persisted owned before/after snapshot resolves quarantine. A
/// conflict or inconclusive read leaves every state and lock in place.
pub async fn reconcile_uncertain(
    pool: &MySqlPool,
    reroute_id: u64,
    actor_user_id: u64,
    note: &str,
) -> Result<ReconciliationResult> {
    type Row = (
        String,
        Option<u64>,
        Option<u64>,
        Option<u64>,
        String,
        Option<sqlx::types::Json<serde_json::Value>>,
        Option<sqlx::types::Json<serde_json::Value>>,
    );
    let row: Row = sqlx::query_as(
        "SELECT state, device_id, bundle_id, rollback_of_reroute_id,mutation_effect,prior_state_json, after_state_json \
         FROM reroutes WHERE id = ?",
    )
    .bind(reroute_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| anyhow::anyhow!("reroute not found"))?;
    let failed_changed_inverse = row.0 == "failed" && row.3.is_some() && row.4 == "changed";
    anyhow::ensure!(
        row.0 == "uncertain" || failed_changed_inverse,
        "reroute is not eligible for evidence-bound reconciliation"
    );
    let device_id = row
        .1
        .ok_or_else(|| anyhow::anyhow!("reroute has no device"))?;
    let before: Vec<crate::reroute::device_plan::DeviceStateSnapshot> = serde_json::from_value(
        row.5
            .ok_or_else(|| anyhow::anyhow!("missing before snapshot"))?
            .0,
    )?;
    let after: Vec<crate::reroute::device_plan::DeviceStateSnapshot> = serde_json::from_value(
        row.6
            .ok_or_else(|| anyhow::anyhow!("missing after snapshot"))?
            .0,
    )?;
    anyhow::ensure!(
        !before.is_empty() && !after.is_empty(),
        "reconciliation requires non-empty before and after evidence"
    );

    let matches_after =
        crate::reroute::device_plan::verify_snapshots_read_only(pool, device_id, &after).await?;
    let matches_before = if before == after {
        matches_after
    } else {
        crate::reroute::device_plan::verify_snapshots_read_only(pool, device_id, &before).await?
    };
    let result = match (matches_after, matches_before, before == after) {
        (true, _, false) => ReconciliationResult::Changed,
        (_, true, _) => ReconciliationResult::NotApplied,
        _ => ReconciliationResult::Conflict,
    };

    let mut tx = pool.begin().await?;
    let locked: Option<(String, String)> =
        sqlx::query_as("SELECT state,mutation_effect FROM reroutes WHERE id = ? FOR UPDATE")
            .bind(reroute_id)
            .fetch_optional(&mut *tx)
            .await?;
    anyhow::ensure!(
        matches!(locked.as_ref(),Some((state,effect)) if state=="uncertain" || (state=="failed" && effect=="changed" && row.3.is_some())),
        "reroute changed during reconciliation"
    );
    match result {
        ReconciliationResult::Changed => {
            sqlx::query(
                "UPDATE reroutes SET state = 'succeeded', success = 1, \
                        verification_status = 'reconciled_after', mutation_effect = 'changed', \
                        failure_reason = CONCAT(COALESCE(failure_reason,''), ?) \
                  WHERE id = ? AND (state = 'uncertain' OR (state='failed' AND mutation_effect='changed'))",
            )
            .bind(format!(" | reconciled exact after-state: {note}"))
            .bind(reroute_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE reroute_bundle_actions SET state = 'succeeded', mutation_effect = 'changed' \
                 WHERE reroute_id = ?",
            )
            .bind(reroute_id)
            .execute(&mut *tx)
            .await?;
        }
        ReconciliationResult::NotApplied => {
            sqlx::query(
                "UPDATE reroutes SET state = 'failed', success = 0, \
                        verification_status = 'reconciled_before', mutation_effect = 'noop', \
                        failure_reason = CONCAT(COALESCE(failure_reason,''), ?) \
                  WHERE id = ? AND (state = 'uncertain' OR (state='failed' AND mutation_effect='changed'))",
            )
            .bind(format!(" | reconciled exact before-state: {note}"))
            .bind(reroute_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE reroute_bundle_actions SET state = 'noop', mutation_effect = 'noop' \
                 WHERE reroute_id = ?",
            )
            .bind(reroute_id)
            .execute(&mut *tx)
            .await?;
        }
        ReconciliationResult::Conflict => {}
    }
    sqlx::query(
        "INSERT INTO audit_logs \
            (actor_type, actor_user_id, event_type, entity_type, entity_id, reroute_id, message) \
         VALUES ('user', ?, 'reroute_reconciled', 'reroute', ?, ?, ?)",
    )
    .bind(actor_user_id)
    .bind(reroute_id)
    .bind(reroute_id)
    .bind(format!("reconciliation result {:?}: {note}", result))
    .execute(&mut *tx)
    .await?;

    if result != ReconciliationResult::Conflict {
        sqlx::query(
            "UPDATE locks SET cleared_at = UTC_TIMESTAMP(), cleared_by = ? \
             WHERE reroute_id = ? AND cleared_at IS NULL \
               AND kind IN ('auto_crash','auto_uncertain')",
        )
        .bind(actor_user_id)
        .bind(reroute_id)
        .execute(&mut *tx)
        .await?;
    }
    let mut mapped_child = None;
    if let Some(bundle_id) = row.2 {
        let mapped: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM recovery_attempt_sources WHERE recovery_bundle_id=?",
        )
        .bind(bundle_id)
        .fetch_one(&mut *tx)
        .await?;
        if mapped > 0 {
            mapped_child = Some(bundle_id);
        }
        let unknown: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM reroutes \
             WHERE bundle_id = ? AND (state = 'uncertain' OR mutation_effect = 'unknown')",
        )
        .bind(bundle_id)
        .fetch_one(&mut *tx)
        .await?;
        let owned: i64 = sqlx::query_scalar(
            "SELECT COUNT(DISTINCT original.id) FROM reroutes original \
             LEFT JOIN reroute_bundle_actions ba \
               ON ba.bundle_id = ? AND ba.original_reroute_id = original.id \
             WHERE original.rollback_of_reroute_id IS NULL \
               AND (original.bundle_id = ? OR ba.id IS NOT NULL) \
               AND original.mutation_effect IN ('changed','unknown') \
               AND NOT EXISTS (SELECT 1 FROM reroutes inverse \
                 WHERE inverse.rollback_of_reroute_id = original.id \
                   AND inverse.state = 'succeeded' \
                   AND inverse.mutation_effect IN ('changed','noop'))",
        )
        .bind(bundle_id)
        .bind(bundle_id)
        .fetch_one(&mut *tx)
        .await?;
        if unknown == 0 && owned == 0 && mapped == 0 {
            sqlx::query("DELETE FROM device_change_windows WHERE bundle_id = ?")
                .bind(bundle_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM device_change_window_sources WHERE source_bundle_id=?")
                .bind(bundle_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query(
                "UPDATE reroute_bundles SET state = 'compensated', finished_at = UTC_TIMESTAMP() \
                 WHERE id = ? AND state = 'compensation_blocked'",
            )
            .bind(bundle_id)
            .execute(&mut *tx)
            .await?;
        }
    } else if result == ReconciliationResult::NotApplied {
        sqlx::query("DELETE FROM device_change_windows WHERE reroute_id = ?")
            .bind(reroute_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    if result != ReconciliationResult::Conflict {
        if let Some(child_id) = mapped_child {
            if crate::reroute::bundle::outstanding_owned_originals(pool, child_id)
                .await?
                .is_empty()
            {
                let owner: Option<String> = sqlx::query_scalar(
                    "SELECT owner_token FROM device_change_windows WHERE bundle_id=? LIMIT 1",
                )
                .bind(child_id)
                .fetch_optional(pool)
                .await?;
                crate::reroute::recovery::finalize_recovery_child(
                    pool,
                    child_id,
                    "succeeded",
                    Some("reconciliation proved recovery completion"),
                    owner.as_deref().unwrap_or("reconcile-repair"),
                )
                .await?;
            }
        }
    }
    Ok(result)
}

/// On startup, any reroute in pending/running/verifying becomes `uncertain` and
/// locks the affected device until evidence-bound reconciliation. Do NOT assume
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
                 mutation_effect = 'unknown', \
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
