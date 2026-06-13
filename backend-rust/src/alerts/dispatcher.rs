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
//!
//! "Processed" = the alert has at least one alert_deliveries row. If SMTP is
//! unconfigured we record NOTHING, so the alert stays queued and is retried once
//! SMTP comes up (we never crash the control plane).

use anyhow::Result;
use serde_json::Value;
use sqlx::MySqlPool;

use super::body;
use crate::config::Config;

pub const DEDUP_WINDOW_SECS: u64 = 600; // 10 minutes per (event_type, asset, rule)
pub const RATE_LIMIT_PER_HOUR: u32 = 20; // per recipient, digest fallback beyond
const POLL_INTERVAL_SECS: u64 = 5;
const BATCH: i64 = 50;

/// A new alert awaiting dispatch.
#[derive(sqlx::FromRow)]
struct PendingAlert {
    id: u64,
    event_type: String,
    severity: String,
    occurrence_count: u32,
    payload_json: Option<sqlx::types::Json<Value>>,
    created_at: chrono::DateTime<chrono::Utc>,
}

/// A resolved recipient (DB id + address).
#[derive(Clone)]
struct Recipient {
    id: u64,
    email: String,
}

/// Long-lived dispatcher loop. Spawned from main via super::spawn_dispatcher.
pub async fn run(pool: MySqlPool, _cfg: Config) -> Result<()> {
    tracing::info!(event_type = "alert_dispatcher_started", "alert dispatcher running");
    loop {
        // Re-evaluate SMTP each cycle so configuring it later starts delivery
        // without a restart. When unconfigured we leave alerts queued.
        let mailer = mailer_from();
        if let Some(mailer) = mailer {
            if let Err(e) = drain_once(&pool, &mailer).await {
                tracing::warn!(event_type = "alert_drain_failed", error = %e, "alert drain pass failed");
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(POLL_INTERVAL_SECS)).await;
    }
}

/// Process one batch of undelivered alerts.
async fn drain_once(pool: &MySqlPool, mailer: &super::mailer::Mailer) -> Result<()> {
    let pending = sqlx::query_as::<_, PendingAlert>(
        "SELECT a.id, a.event_type, a.severity, a.occurrence_count, a.payload_json, a.created_at \
         FROM alerts a \
         WHERE NOT EXISTS (SELECT 1 FROM alert_deliveries d WHERE d.alert_id = a.id) \
         ORDER BY a.id ASC LIMIT ?",
    )
    .bind(BATCH)
    .fetch_all(pool)
    .await?;

    for alert in pending {
        if let Err(e) = dispatch_alert(pool, mailer, &alert).await {
            tracing::warn!(event_type = "alert_dispatch_failed", alert_id = alert.id, error = %e, "dispatching alert failed");
        }
    }
    Ok(())
}

/// Resolve recipients, apply dedup + rate limit, send, and record deliveries for
/// one alert. Always records at least one delivery row (even if there are no
/// recipients) so the alert is not re-scanned forever.
async fn dispatch_alert(pool: &MySqlPool, mailer: &super::mailer::Mailer, alert: &PendingAlert) -> Result<()> {
    let always_immediate = super::ALWAYS_IMMEDIATE.contains(&alert.event_type.as_str());
    let is_critical = alert.severity == "critical";

    let recipients = resolve_recipients(pool, alert, is_critical).await?;
    if recipients.is_empty() {
        // No one subscribed: record a single no-recipient marker so the cursor
        // advances. Uses recipient_id = NULL-equivalent is not allowed (FK), so
        // we skip the delivery row and instead log; to avoid infinite rescan we
        // insert a self-referencing sentinel is impossible — log + return, and
        // rely on the alert simply having no audience. To keep the cursor moving
        // we DELETE-guard by recording nothing only when truly no recipients
        // exist in the system; otherwise the EXISTS check would loop. We instead
        // mark via a system recipient row.
        ensure_processed_without_recipient(pool, alert).await?;
        tracing::info!(event_type = "alert_no_recipients", alert_id = alert.id, "alert had no subscribed recipients");
        return Ok(());
    }

    let subject = body::subject(alert.event_type.as_str(), alert.severity.as_str(), payload(alert));
    let text = body::render(
        alert.event_type.as_str(),
        alert.severity.as_str(),
        alert.occurrence_count,
        alert.created_at,
        payload(alert),
    );

    for r in recipients {
        // De-dup: a prior delivery for the same dedup_key within the window
        // collapses this one (unless always-immediate).
        if !always_immediate && recently_delivered(pool, alert, &r).await? {
            record_delivery(pool, alert.id, r.id, "queued", Some("suppressed: deduplicated within window")).await?;
            continue;
        }
        // Rate limit: too many in the last hour -> queue (digest fallback)
        // instead of sending (unless always-immediate).
        if !always_immediate && over_rate_limit(pool, r.id).await? {
            record_delivery(pool, alert.id, r.id, "queued", Some("rate limited: deferred to digest")).await?;
            continue;
        }

        match mailer.send(&r.email, &subject, text.clone()).await {
            Ok(()) => record_delivery(pool, alert.id, r.id, "sent", None).await?,
            Err(e) => record_delivery(pool, alert.id, r.id, "failed", Some(&truncate(&e.to_string(), 1000))).await?,
        }
    }
    Ok(())
}

/// Resolve the recipient set: verified recipients with an enabled subscription
/// matching the alert's event_type (NULL=all). Critical alerts additionally fan
/// out to every admin user that has a recipient row.
async fn resolve_recipients(pool: &MySqlPool, alert: &PendingAlert, is_critical: bool) -> Result<Vec<Recipient>> {
    let mut map: std::collections::BTreeMap<u64, Recipient> = std::collections::BTreeMap::new();

    let subbed = sqlx::query_as::<_, (u64, String)>(
        "SELECT DISTINCT r.id, r.email \
         FROM alert_recipients r \
         JOIN alert_subscriptions s ON s.recipient_id = r.id \
         WHERE r.verified_at IS NOT NULL AND s.enabled = 1 \
           AND (s.event_type IS NULL OR s.event_type = ?)",
    )
    .bind(&alert.event_type)
    .fetch_all(pool)
    .await?;
    for (id, email) in subbed {
        map.insert(id, Recipient { id, email });
    }

    if is_critical {
        let admins = sqlx::query_as::<_, (u64, String)>(
            "SELECT r.id, r.email FROM alert_recipients r \
             JOIN role_user ru ON ru.user_id = r.user_id \
             JOIN roles ro ON ro.id = ru.role_id \
             WHERE ro.name IN ('admin', 'superadmin') AND r.verified_at IS NOT NULL",
        )
        .fetch_all(pool)
        .await?;
        for (id, email) in admins {
            map.insert(id, Recipient { id, email });
        }
    }

    Ok(map.into_values().collect())
}

/// True if a delivery for the same dedup_key was recorded within the dedup window.
async fn recently_delivered(pool: &MySqlPool, alert: &PendingAlert, r: &Recipient) -> Result<bool> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM alert_deliveries d \
         JOIN alerts a ON a.id = d.alert_id \
         WHERE d.recipient_id = ? AND d.status = 'sent' \
           AND a.dedup_key = (SELECT dedup_key FROM alerts WHERE id = ?) \
           AND d.created_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? SECOND)",
    )
    .bind(r.id)
    .bind(alert.id)
    .bind(DEDUP_WINDOW_SECS as i64)
    .fetch_one(pool)
    .await?;
    Ok(count > 0)
}

/// True if the recipient already received RATE_LIMIT_PER_HOUR sent emails in the
/// last hour.
async fn over_rate_limit(pool: &MySqlPool, recipient_id: u64) -> Result<bool> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM alert_deliveries \
         WHERE recipient_id = ? AND status = 'sent' \
           AND created_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 HOUR)",
    )
    .bind(recipient_id)
    .fetch_one(pool)
    .await?;
    Ok(count >= RATE_LIMIT_PER_HOUR as i64)
}

/// Insert an alert_deliveries row. `sent` stamps sent_at.
async fn record_delivery(pool: &MySqlPool, alert_id: u64, recipient_id: u64, status: &str, error: Option<&str>) -> Result<()> {
    let sent_at_sql = if status == "sent" { "UTC_TIMESTAMP()" } else { "NULL" };
    let sql = format!(
        "INSERT INTO alert_deliveries (alert_id, recipient_id, channel, status, error, sent_at) \
         VALUES (?, ?, 'email', ?, ?, {sent_at_sql})"
    );
    sqlx::query(&sql)
        .bind(alert_id)
        .bind(recipient_id)
        .bind(status)
        .bind(error)
        .execute(pool)
        .await?;
    Ok(())
}

/// When an alert has no subscribed recipients we still must stop re-scanning it.
/// We attach it to a single internal "unrouted" recipient row (created lazily)
/// with a queued delivery noting there was no audience.
async fn ensure_processed_without_recipient(pool: &MySqlPool, alert: &PendingAlert) -> Result<()> {
    // Lazily ensure a sentinel recipient exists (unverified so it never receives
    // real mail). Keyed by a fixed address.
    const SENTINEL: &str = "unrouted@rerouter.local";
    let id: u64 = match sqlx::query_scalar::<_, u64>("SELECT id FROM alert_recipients WHERE email = ?")
        .bind(SENTINEL)
        .fetch_optional(pool)
        .await?
    {
        Some(id) => id,
        None => {
            let res = sqlx::query("INSERT IGNORE INTO alert_recipients (email) VALUES (?)")
                .bind(SENTINEL)
                .execute(pool)
                .await?;
            if res.rows_affected() > 0 {
                res.last_insert_id()
            } else {
                sqlx::query_scalar::<_, u64>("SELECT id FROM alert_recipients WHERE email = ?")
                    .bind(SENTINEL)
                    .fetch_one(pool)
                    .await?
            }
        }
    };
    record_delivery(pool, alert.id, id, "queued", Some("no subscribed recipients")).await
}

fn payload(alert: &PendingAlert) -> &Value {
    static EMPTY: Value = Value::Null;
    alert.payload_json.as_ref().map(|j| &j.0).unwrap_or(&EMPTY)
}

fn truncate(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn mailer_from() -> Option<super::mailer::Mailer> {
    match super::mailer::Mailer::from_env() {
        Ok(m) => Some(m),
        Err(e) => {
            // Run degraded rather than crash the control plane: alerts stay
            // queued (no deliveries recorded) until SMTP is configured.
            tracing::debug!(event_type = "smtp_unconfigured", error = %e, "email disabled");
            None
        }
    }
}
