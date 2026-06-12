//! Alert dispatcher — the controller's internal replacement for an external
//! queue worker. Single consumer of the `alerts` table.
//!
//! Loop: poll new alerts -> resolve recipients (roles + per-asset
//! subscriptions) -> de-duplicate -> rate-limit -> send via mailer -> record
//! `alert_deliveries` (sent/failed + error).
//!
//! Rules (docs/email-alerts.md):
//!   * de-dup: collapse repeats of the same (event_type, asset, rule) — the
//!     alerts.dedup_key — within a 10-minute window into one email carrying an
//!     occurrence count;
//!   * rate limit: max 20 emails/hour per recipient, then fall back to a digest;
//!   * EXCEPTIONS: reroute_uncertain, reroute_failed, and security events
//!     (see super::ALWAYS_IMMEDIATE) are always sent immediately, never
//!     collapsed, never digested;
//!   * critical alerts (uncertain/failed) always go to admins;
//!   * delivery outcomes are recorded in alert_deliveries — "sent to SMTP" is
//!     recorded as `sent`, failures as `failed` with the error, for audit.

use anyhow::Result;
use sqlx::MySqlPool;

use crate::config::Config;

pub const DEDUP_WINDOW_SECS: u64 = 600; // 10 minutes per (event_type, asset, rule)
pub const RATE_LIMIT_PER_HOUR: u32 = 20; // per recipient, digest fallback beyond
const POLL_INTERVAL_SECS: u64 = 5;

/// Long-lived dispatcher loop. Spawned from main via super::spawn_dispatcher.
pub async fn run(_pool: MySqlPool, _cfg: Config) -> Result<()> {
    let _mailer = mailer_from();
    tracing::info!(event_type = "alert_dispatcher_started", "alert dispatcher running (skeleton)");
    loop {
        // TODO(milestone 2):
        //   1. SELECT alerts without deliveries (cursor on alerts.id)
        //   2. resolve recipients: verified alert_recipients x enabled
        //      alert_subscriptions (asset/event filters, NULL = all)
        //   3. de-dup: same dedup_key within DEDUP_WINDOW_SECS -> bump
        //      occurrence_count instead of a new email (skip for ALWAYS_IMMEDIATE)
        //   4. rate limit: COUNT(alert_deliveries) per recipient in the last
        //      hour >= RATE_LIMIT_PER_HOUR -> queue into a digest (skip for
        //      ALWAYS_IMMEDIATE)
        //   5. render + mailer.send(); INSERT alert_deliveries
        //      (sent/failed + error). Never include secrets in mail bodies.
        tokio::time::sleep(std::time::Duration::from_secs(POLL_INTERVAL_SECS)).await;
    }
}

fn mailer_from() -> Option<super::mailer::Mailer> {
    match super::mailer::Mailer::from_env() {
        Ok(m) => Some(m),
        Err(e) => {
            // Run degraded rather than crash the control plane: alerts stay
            // queued (no deliveries recorded) until SMTP is configured.
            tracing::warn!(event_type = "smtp_unconfigured", error = %e, "email disabled");
            None
        }
    }
}
