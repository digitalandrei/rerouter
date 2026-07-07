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

use serde_json::{json, Value};
use sqlx::MySqlPool;

use crate::config::Config;

/// Event types that are always delivered immediately and never collapsed by
/// de-duplication or the per-recipient rate limit. The arming/mode-flip events are
/// the highest-consequence state changes (they can allow traffic-moving actions),
/// so they always page.
pub const ALWAYS_IMMEDIATE: &[&str] = &[
    "reroute_uncertain",
    "reroute_failed",
    "2fa_recovery_used",
    "account_locked",
    "operating_mode_changed",
    "automatic_actions_changed",
    "global_lock_changed",
];

/// Resolve an acting user id to a compact `{id, email, name}` object for alert
/// payloads, so an email can state WHO made a manual decision. Returns
/// `Value::Null` for a `None` actor (automatic / controller-driven actions) or
/// when the user can't be loaded. Never includes secrets.
pub async fn actor_json(pool: &MySqlPool, user_id: Option<u64>) -> Value {
    let Some(uid) = user_id else {
        return Value::Null;
    };
    match sqlx::query_as::<_, (String, Option<String>)>("SELECT email, name FROM users WHERE id = ?")
        .bind(uid)
        .fetch_optional(pool)
        .await
    {
        Ok(Some((email, name))) => json!({ "id": uid, "email": email, "name": name }),
        _ => json!({ "id": uid }),
    }
}

/// Spawn the alert dispatcher as a long-lived background task.
pub fn spawn_dispatcher(pool: MySqlPool, cfg: Config) {
    tokio::spawn(async move {
        if let Err(e) = dispatcher::run(pool, cfg).await {
            tracing::error!(event_type = "alert_dispatcher_died", error = %e, "alert dispatcher exited");
        }
    });
}
