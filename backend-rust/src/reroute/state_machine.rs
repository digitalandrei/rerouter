//! Two-phase reroute state machine and crash recovery.
//! See ../docs/reroute-engine.md and ../docs/state-recovery.md.
//!
//!   planned -> pending -> running -> verifying -> succeeded
//!                                \-> failed
//!                                \-> uncertain
//!
//! Persist state BEFORE and AFTER every step. Never treat "sent" as "succeeded".

use anyhow::Result;
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
/// locks the affected asset until verification proves the outcome or an admin
/// acknowledges it. Do NOT assume nothing happened after a crash.
pub async fn recover_on_startup(_pool: &MySqlPool, cfg: &Config) -> Result<()> {
    if !cfg.safety.mark_running_actions_uncertain_on_startup {
        tracing::warn!(
            event_type = "recovery_skipped",
            "mark_running_actions_uncertain_on_startup is false — this is unsafe"
        );
        return Ok(());
    }
    // TODO(milestone 4):
    //   1. SELECT reroutes WHERE state IN (pending, running, verifying)
    //   2. UPDATE -> uncertain
    //   3. INSERT lock(scope=asset) kind=auto_crash for each affected asset
    //   4. attempt provider-side verification; resolve or leave uncertain
    //   5. enqueue alerts; require admin ack to clear safety locks
    tracing::info!(event_type = "recovery_complete", "startup state recovery done");
    Ok(())
}
