//! Email alerting, owned by the controller. An internal async dispatcher task
//! (no external queue worker) drains new `alerts` rows and sends mail via SMTP.
//! See ../docs/email-alerts.md.
//!
//! Producers (detection, reroute engine, auth) only INSERT alerts rows — they
//! never block on SMTP. The dispatcher is the single consumer.

pub mod body;
pub mod dispatcher;
pub mod mailer;
pub mod webhook;

use sqlx::MySqlPool;

use crate::config::Config;

/// Event types that are always delivered immediately and never collapsed by
/// de-duplication or the per-recipient rate limit.
pub const ALWAYS_IMMEDIATE: &[&str] = &[
    "reroute_uncertain",
    "reroute_failed",
    "2fa_recovery_used",
    "account_locked",
];

/// Spawn the alert dispatcher as a long-lived background task.
pub fn spawn_dispatcher(pool: MySqlPool, cfg: Config) {
    tokio::spawn(async move {
        if let Err(e) = dispatcher::run(pool, cfg).await {
            tracing::error!(event_type = "alert_dispatcher_died", error = %e, "alert dispatcher exited");
        }
    });
}
