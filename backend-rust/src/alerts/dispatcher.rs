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
/// Delivery retry policy. A transient send failure (SMTP greylisting, a brief
/// network blip) must NOT permanently lose an alert — the doctrine requires
/// uncertain/failed/security alerts to always reach an admin. So a failed
/// (alert, target) is retried up to MAX_DELIVERY_ATTEMPTS times, each separated by
/// at least RETRY_BACKOFF_SECS; alerts older than MAX_RETRY_AGE_SECS stop being
/// re-scanned (a backstop — the per-target attempt cap already bounds retries).
const MAX_DELIVERY_ATTEMPTS: i64 = 5;
const RETRY_BACKOFF_SECS: u64 = 300; // 5 min — covers typical greylisting
const MAX_RETRY_AGE_SECS: u64 = 21_600; // 6 h

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
    tracing::info!(
        event_type = "alert_dispatcher_started",
        "alert dispatcher running"
    );
    loop {
        // Re-evaluate SMTP each cycle so configuring it later starts delivery
        // without a restart. We drain when EITHER email is configured OR at least
        // one Teams webhook exists; otherwise alerts stay queued (so the original
        // "retry email once SMTP comes up" guarantee holds when Teams isn't used).
        let mailer = mailer_from();
        let have_webhooks = any_enabled_webhook(&pool).await;
        if mailer.is_some() || have_webhooks {
            if let Err(e) = drain_once(&pool, mailer.as_ref()).await {
                tracing::warn!(event_type = "alert_drain_failed", error = %e, "alert drain pass failed");
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(POLL_INTERVAL_SECS)).await;
    }
}

/// Process one batch of undelivered alerts. `mailer` is None when SMTP is
/// unconfigured (the Teams channel may still deliver).
async fn drain_once(pool: &MySqlPool, mailer: Option<&super::mailer::Mailer>) -> Result<()> {
    // Select alerts that still have work: never attempted, OR a target whose
    // latest state is a retryable failure (no later success, under the attempt
    // cap, and its last attempt older than the backoff). dispatch_alert re-checks
    // each target precisely; this query is the coarse filter. Ancient alerts drop
    // out via the age backstop.
    let pending = sqlx::query_as::<_, PendingAlert>(
        "SELECT a.id, a.event_type, a.severity, a.occurrence_count, a.payload_json, a.created_at \
         FROM alerts a \
         WHERE a.created_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? SECOND) \
           AND ( \
             NOT EXISTS (SELECT 1 FROM alert_deliveries d WHERE d.alert_id = a.id) \
             OR EXISTS ( \
               SELECT 1 FROM alert_deliveries d \
               WHERE d.alert_id = a.id AND d.status = 'failed' \
                 AND d.created_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? SECOND) \
                 AND NOT EXISTS ( \
                   SELECT 1 FROM alert_deliveries s WHERE s.alert_id = a.id AND s.status = 'sent' \
                     AND ((d.recipient_id IS NOT NULL AND s.recipient_id = d.recipient_id) \
                       OR (d.endpoint_id IS NOT NULL AND s.endpoint_id = d.endpoint_id))) \
                 AND (SELECT COUNT(*) FROM alert_deliveries f WHERE f.alert_id = a.id AND f.status = 'failed' \
                       AND ((d.recipient_id IS NOT NULL AND f.recipient_id = d.recipient_id) \
                         OR (d.endpoint_id IS NOT NULL AND f.endpoint_id = d.endpoint_id))) < ? \
             ) \
           ) \
         ORDER BY a.id ASC LIMIT ?",
    )
    .bind(MAX_RETRY_AGE_SECS as i64)
    .bind(RETRY_BACKOFF_SECS as i64)
    .bind(MAX_DELIVERY_ATTEMPTS)
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

/// True if at least one enabled Teams webhook endpoint exists.
async fn any_enabled_webhook(pool: &MySqlPool) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM webhook_endpoints WHERE enabled = 1")
        .fetch_one(pool)
        .await
        .map(|n| n > 0)
        .unwrap_or(false)
}

/// Per-target delivery state derived from the alert_deliveries rows, used to drive
/// retries: whether it already succeeded, whether it was intentionally queued
/// (dedup / rate-limit / no-audience — treated as settled, not retried), how many
/// times it has failed, and how long since its last attempt.
struct DeliveryState {
    has_sent: bool,
    settled_queued: bool,
    failed_count: i64,
    secs_since_last: Option<i64>,
}

async fn email_delivery_state(
    pool: &MySqlPool,
    alert_id: u64,
    recipient_id: u64,
) -> Result<DeliveryState> {
    delivery_state(pool, alert_id, "email", Some(recipient_id), None).await
}

async fn teams_delivery_state(
    pool: &MySqlPool,
    alert_id: u64,
    endpoint_id: u64,
) -> Result<DeliveryState> {
    delivery_state(pool, alert_id, "teams", None, Some(endpoint_id)).await
}

async fn delivery_state(
    pool: &MySqlPool,
    alert_id: u64,
    channel: &str,
    recipient_id: Option<u64>,
    endpoint_id: Option<u64>,
) -> Result<DeliveryState> {
    // CAST(SUM(..) AS SIGNED) so the boolean sums decode as i64 (raw SUM is DECIMAL);
    // NULL (no rows) -> None -> treated as zero / never-attempted.
    let (sent, queued, failed, secs): (Option<i64>, Option<i64>, Option<i64>, Option<i64>) =
        sqlx::query_as(
            "SELECT CAST(SUM(status = 'sent') AS SIGNED), CAST(SUM(status = 'queued') AS SIGNED), \
                    CAST(SUM(status = 'failed') AS SIGNED), \
                    TIMESTAMPDIFF(SECOND, MAX(created_at), UTC_TIMESTAMP()) \
             FROM alert_deliveries \
             WHERE alert_id = ? AND channel = ? \
               AND ((? IS NOT NULL AND recipient_id = ?) OR (? IS NOT NULL AND endpoint_id = ?))",
        )
        .bind(alert_id)
        .bind(channel)
        .bind(recipient_id)
        .bind(recipient_id)
        .bind(endpoint_id)
        .bind(endpoint_id)
        .fetch_one(pool)
        .await?;
    Ok(DeliveryState {
        has_sent: sent.unwrap_or(0) > 0,
        settled_queued: queued.unwrap_or(0) > 0,
        failed_count: failed.unwrap_or(0),
        secs_since_last: secs,
    })
}

/// Resolve recipients, apply dedup + rate limit, send, and record deliveries for
/// one alert. Always records at least one delivery row (even if there are no
/// recipients) so the alert is not re-scanned forever.
async fn dispatch_alert(
    pool: &MySqlPool,
    mailer: Option<&super::mailer::Mailer>,
    alert: &PendingAlert,
) -> Result<()> {
    let always_immediate = super::ALWAYS_IMMEDIATE.contains(&alert.event_type.as_str());
    let is_critical = alert.severity == "critical";

    let subject = body::subject(
        alert.event_type.as_str(),
        alert.severity.as_str(),
        payload(alert),
    );
    let text = body::render(
        alert.event_type.as_str(),
        alert.severity.as_str(),
        alert.occurrence_count,
        alert.created_at,
        payload(alert),
    );

    // Whether this alert had ANY audience on any channel (suppressed/queued rows
    // still count — they record a delivery row so the cursor advances).
    let mut had_audience = false;

    // --- Email channel (only when SMTP is configured this cycle) ---------------
    if let Some(mailer) = mailer {
        let recipients = resolve_recipients(pool, alert, is_critical).await?;
        if !recipients.is_empty() {
            had_audience = true;
        }
        for r in recipients {
            // Retry gate: skip if already settled (sent, or intentionally queued);
            // give up past the attempt cap; otherwise honor the backoff between
            // retries of a failed send.
            let st = email_delivery_state(pool, alert.id, r.id).await?;
            if st.has_sent || st.settled_queued {
                continue;
            }
            if st.failed_count >= MAX_DELIVERY_ATTEMPTS {
                tracing::error!(event_type = "alert_delivery_gave_up", alert_id = alert.id, recipient_id = r.id, channel = "email", attempts = st.failed_count, "giving up on alert delivery after max attempts");
                continue;
            }
            if st.failed_count > 0 {
                if let Some(since) = st.secs_since_last {
                    if since < RETRY_BACKOFF_SECS as i64 {
                        continue; // backoff not elapsed
                    }
                }
            }
            if !always_immediate && recently_delivered(pool, alert, &r).await? {
                record_delivery(pool, alert.id, r.id, "queued", Some("suppressed: deduplicated within window")).await?;
                continue;
            }
            if !always_immediate && over_rate_limit(pool, r.id).await? {
                record_delivery(pool, alert.id, r.id, "queued", Some("rate limited: deferred to digest")).await?;
                continue;
            }
            match mailer.send(&r.email, &subject, text.clone()).await {
                Ok(()) => record_delivery(pool, alert.id, r.id, "sent", None).await?,
                Err(e) => {
                    record_delivery(pool, alert.id, r.id, "failed", Some(&truncate(&e.to_string(), 1000))).await?
                }
            }
        }
    }

    // --- Teams channel ---------------------------------------------------------
    let endpoints = super::webhook::load_subscribed(pool, &alert.event_type).await?;
    if !endpoints.is_empty() {
        had_audience = true;
    }
    for e in endpoints {
        let st = teams_delivery_state(pool, alert.id, e.id).await?;
        if st.has_sent || st.settled_queued {
            continue;
        }
        if st.failed_count >= MAX_DELIVERY_ATTEMPTS {
            tracing::error!(event_type = "alert_delivery_gave_up", alert_id = alert.id, endpoint_id = e.id, channel = "teams", attempts = st.failed_count, "giving up on alert delivery after max attempts");
            continue;
        }
        if st.failed_count > 0 {
            if let Some(since) = st.secs_since_last {
                if since < RETRY_BACKOFF_SECS as i64 {
                    continue;
                }
            }
        }
        if !always_immediate && webhook_recently_delivered(pool, alert, e.id).await? {
            record_webhook_delivery(pool, alert.id, e.id, "queued", Some("suppressed: deduplicated within window")).await?;
            continue;
        }
        if !always_immediate && webhook_over_rate_limit(pool, e.id).await? {
            record_webhook_delivery(pool, alert.id, e.id, "queued", Some("rate limited")).await?;
            continue;
        }
        match super::webhook::post_teams(&e.url, &subject, alert.severity.as_str(), &text).await {
            Ok(()) => record_webhook_delivery(pool, alert.id, e.id, "sent", None).await?,
            Err(err) => {
                record_webhook_delivery(pool, alert.id, e.id, "failed", Some(&truncate(&err.to_string(), 1000))).await?
            }
        }
    }

    // No audience on any channel. Only mark processed (sentinel) when email was
    // actually available — otherwise leave queued so email retries once SMTP is up.
    if !had_audience && mailer.is_some() {
        ensure_processed_without_recipient(pool, alert).await?;
        tracing::info!(event_type = "alert_no_recipients", alert_id = alert.id, "alert had no subscribed recipients");
    }
    Ok(())
}

/// Resolve the recipient set: verified recipients with an enabled subscription
/// matching the alert's event_type (NULL=all). Critical alerts additionally fan
/// out to every admin user that has a recipient row.
async fn resolve_recipients(
    pool: &MySqlPool,
    alert: &PendingAlert,
    is_critical: bool,
) -> Result<Vec<Recipient>> {
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

/// Teams equivalent of `recently_delivered`, keyed on the endpoint.
async fn webhook_recently_delivered(
    pool: &MySqlPool,
    alert: &PendingAlert,
    endpoint_id: u64,
) -> Result<bool> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM alert_deliveries d \
         JOIN alerts a ON a.id = d.alert_id \
         WHERE d.endpoint_id = ? AND d.channel = 'teams' AND d.status = 'sent' \
           AND a.dedup_key = (SELECT dedup_key FROM alerts WHERE id = ?) \
           AND d.created_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? SECOND)",
    )
    .bind(endpoint_id)
    .bind(alert.id)
    .bind(DEDUP_WINDOW_SECS as i64)
    .fetch_one(pool)
    .await?;
    Ok(count > 0)
}

/// Teams equivalent of `over_rate_limit`, keyed on the endpoint.
async fn webhook_over_rate_limit(pool: &MySqlPool, endpoint_id: u64) -> Result<bool> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM alert_deliveries \
         WHERE endpoint_id = ? AND channel = 'teams' AND status = 'sent' \
           AND created_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 HOUR)",
    )
    .bind(endpoint_id)
    .fetch_one(pool)
    .await?;
    Ok(count >= RATE_LIMIT_PER_HOUR as i64)
}

/// Insert a Teams alert_deliveries row (recipient_id NULL, channel 'teams').
async fn record_webhook_delivery(
    pool: &MySqlPool,
    alert_id: u64,
    endpoint_id: u64,
    status: &str,
    error: Option<&str>,
) -> Result<()> {
    let sent_at_sql = if status == "sent" {
        "UTC_TIMESTAMP()"
    } else {
        "NULL"
    };
    let sql = format!(
        "INSERT INTO alert_deliveries (alert_id, endpoint_id, channel, status, error, sent_at) \
         VALUES (?, ?, 'teams', ?, ?, {sent_at_sql})"
    );
    sqlx::query(&sql)
        .bind(alert_id)
        .bind(endpoint_id)
        .bind(status)
        .bind(error)
        .execute(pool)
        .await?;
    Ok(())
}

/// Insert an alert_deliveries row. `sent` stamps sent_at.
async fn record_delivery(
    pool: &MySqlPool,
    alert_id: u64,
    recipient_id: u64,
    status: &str,
    error: Option<&str>,
) -> Result<()> {
    let sent_at_sql = if status == "sent" {
        "UTC_TIMESTAMP()"
    } else {
        "NULL"
    };
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
    let id: u64 =
        match sqlx::query_scalar::<_, u64>("SELECT id FROM alert_recipients WHERE email = ?")
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
    record_delivery(
        pool,
        alert.id,
        id,
        "queued",
        Some("no subscribed recipients"),
    )
    .await
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
