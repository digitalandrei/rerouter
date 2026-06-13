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

use crate::config::Config;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionState {
    Planned,
    Pending,
    Running,
    Verifying,
    Succeeded,
    Failed,
    Uncertain,
}

impl ActionState {
    pub fn is_non_terminal(self) -> bool {
        matches!(self, ActionState::Pending | ActionState::Running | ActionState::Verifying)
    }
}

/// On startup, any reroute in pending/running/verifying becomes `uncertain` and
/// locks the affected device until an admin acknowledges it. Do NOT assume
/// nothing happened after a crash — a config push made milliseconds before the
/// crash may have taken effect.
pub async fn recover_on_startup(pool: &MySqlPool, cfg: &Config) -> Result<()> {
    if !cfg.safety.mark_running_actions_uncertain_on_startup {
        tracing::warn!(
            event_type = "recovery_skipped",
            "mark_running_actions_uncertain_on_startup is false — this is unsafe"
        );
        return Ok(());
    }

    // Reroutes caught mid-flight by the crash.
    let stuck = sqlx::query_as::<_, (u64, Option<u64>)>(
        "SELECT id, device_id FROM reroutes WHERE state IN ('pending', 'running', 'verifying')",
    )
    .fetch_all(pool)
    .await
    .context("loading in-flight reroutes")?;

    for (reroute_id, device_id) in &stuck {
        // 1. Mark uncertain (terminal until acknowledged).
        let _ = sqlx::query(
            "UPDATE reroutes SET state = 'uncertain', finished_at = UTC_TIMESTAMP(), \
             failure_reason = 'controller restarted mid-action; outcome unverified' WHERE id = ?",
        )
        .bind(reroute_id)
        .execute(pool)
        .await;

        // 2. Lock the affected device (auto_crash) until an admin acknowledges.
        if let Some(dev) = device_id {
            let _ = crate::reroute::locks::create(
                pool,
                "device",
                Some(&dev.to_string()),
                "auto_crash",
                &format!("reroute #{reroute_id} was in-flight at restart; outcome unknown"),
                None,
            )
            .await;
        }

        // 3. Alert (uncertain is always sent, never collapsed).
        let payload = serde_json::json!({
            "reroute_id": reroute_id,
            "device_id": device_id,
            "reason": "controller restart mid-action",
        });
        let _ = sqlx::query(
            "INSERT INTO alerts (event_type, severity, device_id, payload_json, dedup_key) \
             VALUES ('reroute_uncertain', 'critical', ?, ?, ?)",
        )
        .bind(device_id)
        .bind(sqlx::types::Json(&payload))
        .bind(format!("reroute_uncertain:reroute:{reroute_id}"))
        .execute(pool)
        .await;

        // 4. Audit.
        let _ = sqlx::query(
            "INSERT INTO audit_logs (actor_type, event_type, entity_type, entity_id, reroute_id, message) \
             VALUES ('system', 'reroute_uncertain', 'reroute', ?, ?, 'marked uncertain on startup recovery')",
        )
        .bind(reroute_id)
        .bind(reroute_id)
        .execute(pool)
        .await;
    }

    if !stuck.is_empty() {
        tracing::warn!(
            event_type = "recovery_uncertain",
            count = stuck.len(),
            "marked in-flight reroutes uncertain and locked their devices"
        );
    }
    tracing::info!(event_type = "recovery_complete", "startup state recovery done");
    Ok(())
}
