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
    "reroute_bundle_partial",
    "reroute_failed",
    "2fa_recovery_used",
    "account_locked",
    "operating_mode_changed",
    "automatic_actions_changed",
    "global_lock_changed",
    "automatic_action_failed",
    "recovery_degraded",
    // Automatic mitigation just stopped being armed for a rule: the operator's
    // protection silently shrank, so it pages immediately and is never collapsed.
    "rule_auto_disarmed",
    "alert_delivery_permanently_failed",
];

/// Format an error for logs, API responses, and durable diagnostics without
/// retaining URL credentials or webhook capability tokens. Keep the surrounding
/// cause chain so operators can still distinguish DNS, TLS, HTTP, and policy
/// failures.
pub(crate) fn safe_diagnostic(error: &anyhow::Error) -> String {
    redact_urls(&format!("{error:#}"))
}

fn redact_urls(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some((offset, prefix_len)) = ["https://", "http://"]
        .iter()
        .filter_map(|prefix| rest.find(prefix).map(|offset| (offset, prefix.len())))
        .min_by_key(|(offset, _)| *offset)
    {
        out.push_str(&rest[..offset]);
        out.push_str("[redacted URL]");
        let tail = &rest[offset + prefix_len..];
        let end = tail
            .find(|c: char| c.is_whitespace() || matches!(c, ')' | ']' | '}' | '"' | '\''))
            .unwrap_or(tail.len());
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// Resolve an acting user id to a compact `{id, email, name}` object for alert
/// payloads, so an email can state WHO made a manual decision. Returns
/// `Value::Null` for a `None` actor (automatic / controller-driven actions) or
/// when the user can't be loaded. Never includes secrets.
pub async fn actor_json(pool: &MySqlPool, user_id: Option<u64>) -> Value {
    let Some(uid) = user_id else {
        return Value::Null;
    };
    match sqlx::query_as::<_, (String, Option<String>)>(
        "SELECT email, name FROM users WHERE id = ?",
    )
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
        loop {
            let p = pool.clone();
            let c = cfg.clone();
            match tokio::spawn(async move { dispatcher::run(p, c).await }).await {
                Ok(Ok(())) => tracing::error!(
                    event_type = "alert_dispatcher_exited",
                    "alert dispatcher exited unexpectedly; restarting"
                ),
                Ok(Err(e)) => {
                    tracing::error!(event_type = "alert_dispatcher_died", error = %e, "alert dispatcher failed; restarting")
                }
                Err(e) => {
                    tracing::error!(event_type = "alert_dispatcher_panicked", error = %e, "alert dispatcher panicked; restarting")
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });
}

#[cfg(test)]
mod diagnostic_tests {
    #[test]
    fn diagnostic_redacts_urls_and_preserves_the_cause() {
        let secret = "synthetic-secret-token";
        let error = anyhow::anyhow!("TLS certificate rejected for https://tenant.webhook.office.com/path/{secret}?sig={secret}")
            .context("posting to Teams webhook");
        let detail = super::safe_diagnostic(&error);
        assert!(detail.contains("posting to Teams webhook"));
        assert!(detail.contains("TLS certificate rejected"));
        assert!(detail.contains("[redacted URL]"));
        assert!(!detail.contains(secret));
    }
}
