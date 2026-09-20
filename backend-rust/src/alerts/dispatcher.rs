//! Durable per-target alert dispatcher.

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use serde_json::Value;
use sqlx::MySqlPool;

use super::body;
use crate::config::Config;
use crate::ssh::BoxFuture;

pub const DEDUP_WINDOW_SECS: u64 = 600;
pub const RATE_LIMIT_PER_HOUR: u32 = 20;
const POLL_INTERVAL_SECS: u64 = 5;
const CRITICAL_SLOTS: i64 = 40;
const NORMAL_SLOTS: i64 = 10;
const MAX_DELIVERY_ATTEMPTS: u32 = 5;
const RETRY_BACKOFF_SECS: u64 = 300;
const CLAIM_LEASE_SECS: u64 = 120;

#[derive(Clone, sqlx::FromRow)]
struct PendingAlert {
    id: u64,
    event_type: String,
    severity: String,
}

#[derive(Clone)]
struct Recipient {
    id: u64,
    email: String,
}

struct EndpointTarget {
    id: u64,
    encrypted_url: Vec<u8>,
}

#[derive(sqlx::FromRow)]
struct DueIntent {
    id: u64,
    alert_id: u64,
    channel: String,
    recipient_id: Option<u64>,
    endpoint_id: Option<u64>,
    target_address: Option<String>,
    target_encrypted: Option<Vec<u8>>,
    attempt_count: u32,
    event_type: String,
    severity: String,
    occurrence_count: u32,
    payload_json: Option<sqlx::types::Json<Value>>,
    alert_created_at: chrono::DateTime<chrono::Utc>,
}

trait DeliverySender: Send + Sync {
    fn email_available(&self) -> bool;
    fn send_email<'a>(
        &'a self,
        to: &'a str,
        subject: &'a str,
        text: String,
    ) -> BoxFuture<'a, Result<()>>;
    fn send_teams<'a>(
        &'a self,
        url: &'a str,
        subject: &'a str,
        severity: &'a str,
        text: &'a str,
    ) -> BoxFuture<'a, Result<()>>;
}

struct ProductionSender {
    mailer: Option<Arc<super::mailer::Mailer>>,
}

impl DeliverySender for ProductionSender {
    fn email_available(&self) -> bool {
        self.mailer.is_some()
    }

    fn send_email<'a>(
        &'a self,
        to: &'a str,
        subject: &'a str,
        text: String,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.mailer
                .as_ref()
                .context("SMTP is not configured")?
                .send(to, subject, text)
                .await
        })
    }

    fn send_teams<'a>(
        &'a self,
        url: &'a str,
        subject: &'a str,
        severity: &'a str,
        text: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { super::webhook::post_teams(url, subject, severity, text).await })
    }
}

pub async fn run(pool: MySqlPool, _cfg: Config) -> Result<()> {
    tracing::info!(
        event_type = "alert_dispatcher_started",
        "alert dispatcher running"
    );
    loop {
        let sender = ProductionSender {
            mailer: mailer_from().map(Arc::new),
        };
        if let Err(error) = drain_once(&pool, &sender).await {
            tracing::warn!(event_type = "alert_drain_failed", error = %error, "alert drain pass failed");
        }
        tokio::time::sleep(std::time::Duration::from_secs(POLL_INTERVAL_SECS)).await;
    }
}

async fn drain_once<S: DeliverySender>(pool: &MySqlPool, sender: &S) -> Result<()> {
    materialize_batch(pool).await?;
    let due = sqlx::query_as::<_, DueIntent>(
        "WITH ranked AS ( \
           SELECT i.id, i.alert_id, i.channel, i.recipient_id, i.endpoint_id, \
                  i.target_address, i.target_encrypted, i.attempt_count, i.next_attempt_at, \
                  a.event_type, a.severity, a.occurrence_count, a.payload_json, \
                  a.created_at AS alert_created_at, \
                  ROW_NUMBER() OVER (PARTITION BY (a.severity='critical') \
                                     ORDER BY i.next_attempt_at, a.id, i.id) AS class_rank \
           FROM alert_delivery_intents i JOIN alerts a ON a.id=i.alert_id \
           WHERE i.state IN ('pending','retry') AND i.next_attempt_at <= UTC_TIMESTAMP() \
             AND (i.claimed_at IS NULL OR i.claimed_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? SECOND)) \
         ) \
         SELECT id, alert_id, channel, recipient_id, endpoint_id, target_address, \
                target_encrypted, attempt_count, event_type, severity, occurrence_count, \
                payload_json, alert_created_at \
         FROM ranked \
         WHERE (severity='critical' AND class_rank <= ?) \
            OR (severity<>'critical' AND class_rank <= ?) \
         ORDER BY (severity='critical') DESC, next_attempt_at, alert_id, id",
    )
    .bind(CLAIM_LEASE_SECS as i64)
    .bind(CRITICAL_SLOTS)
    .bind(NORMAL_SLOTS)
    .fetch_all(pool)
    .await?;

    for intent in due {
        let claim = uuid::Uuid::new_v4().simple().to_string();
        let claimed = sqlx::query(
            "UPDATE alert_delivery_intents SET claim_token=?, claimed_at=UTC_TIMESTAMP() \
             WHERE id=? AND state IN ('pending','retry') AND next_attempt_at <= UTC_TIMESTAMP() \
               AND (claimed_at IS NULL OR claimed_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? SECOND))",
        )
        .bind(&claim)
        .bind(intent.id)
        .bind(CLAIM_LEASE_SECS as i64)
        .execute(pool)
        .await?
        .rows_affected();
        if claimed != 1 {
            continue;
        }
        if let Err(error) = process_intent(pool, sender, &intent, &claim).await {
            tracing::warn!(event_type="alert_intent_failed", alert_id=intent.alert_id, intent_id=intent.id, error=%error, "alert delivery intent failed");
            release_claim_after_internal_error(pool, intent.id, &claim, &error).await?;
        }
    }
    Ok(())
}

/// Snapshot the complete current audience transactionally before any send.
async fn materialize_batch(pool: &MySqlPool) -> Result<()> {
    let alerts = sqlx::query_as::<_, PendingAlert>(
        "WITH ranked AS ( \
           SELECT a.id,a.event_type,a.severity, \
                  ROW_NUMBER() OVER (PARTITION BY (a.severity='critical') ORDER BY a.id) AS class_rank \
           FROM alerts a \
           WHERE NOT EXISTS (SELECT 1 FROM alert_delivery_intents i WHERE i.alert_id=a.id) \
         ) \
         SELECT id,event_type,severity FROM ranked \
         WHERE (severity='critical' AND class_rank <= ?) \
            OR (severity<>'critical' AND class_rank <= ?) \
         ORDER BY (severity='critical') DESC,id",
    )
    .bind(CRITICAL_SLOTS)
    .bind(NORMAL_SLOTS)
    .fetch_all(pool)
    .await?;
    for alert in alerts {
        materialize_alert(pool, &alert).await?;
    }
    Ok(())
}

async fn materialize_alert(pool: &MySqlPool, alert: &PendingAlert) -> Result<bool> {
    let mut tx = pool.begin().await?;
    // Audience selection and the complete intent fanout share one repeatable-read
    // transaction. A concurrent subscription edit applies to the next alert, not
    // to only a suffix of this alert's targets.
    let recipients = resolve_recipients(&mut tx, alert, alert.severity == "critical").await?;
    let endpoints = resolve_endpoints(&mut tx, &alert.event_type).await?;
    for recipient in recipients {
        sqlx::query(
            "INSERT IGNORE INTO alert_delivery_intents \
                (alert_id,channel,target_key,recipient_id,target_address) \
             VALUES (?,'email',?,?,?)",
        )
        .bind(alert.id)
        .bind(format!("recipient:{}", recipient.id))
        .bind(recipient.id)
        .bind(recipient.email)
        .execute(&mut *tx)
        .await?;
    }
    for endpoint in endpoints {
        sqlx::query(
            "INSERT IGNORE INTO alert_delivery_intents \
                (alert_id,channel,target_key,endpoint_id,target_encrypted) \
             VALUES (?,'teams',?,?,?)",
        )
        .bind(alert.id)
        .bind(format!("endpoint:{}", endpoint.id))
        .bind(endpoint.id)
        .bind(endpoint.encrypted_url)
        .execute(&mut *tx)
        .await?;
    }
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM alert_delivery_intents WHERE alert_id=?")
            .bind(alert.id)
            .fetch_one(&mut *tx)
            .await?;
    if count == 0 {
        sqlx::query(
            "INSERT IGNORE INTO alert_delivery_intents \
                (alert_id,channel,target_key,state,outcome,settled_at,last_error) \
             VALUES (?,'email','no-audience','settled','no_audience',UTC_TIMESTAMP(), \
                     'no subscribed recipients or endpoints')",
        )
        .bind(alert.id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(true)
}

async fn process_intent<S: DeliverySender>(
    pool: &MySqlPool,
    sender: &S,
    intent: &DueIntent,
    claim: &str,
) -> Result<()> {
    if intent_already_sent(pool, intent.id).await? {
        settle_intent(
            pool,
            intent.id,
            claim,
            "sent",
            "recovered prior sent attempt",
        )
        .await?;
        return Ok(());
    }
    let immediate = super::ALWAYS_IMMEDIATE.contains(&intent.event_type.as_str());
    if !immediate && recently_delivered(pool, intent).await? {
        record_attempt(
            pool,
            intent,
            "queued",
            Some("suppressed: deduplicated within window"),
        )
        .await?;
        settle_intent(
            pool,
            intent.id,
            claim,
            "suppressed",
            "deduplicated within window",
        )
        .await?;
        return Ok(());
    }
    if !immediate && over_rate_limit(pool, intent).await? {
        record_attempt(pool, intent, "queued", Some("rate limited: retry later")).await?;
        retry_intent(pool, intent.id, claim, "rate limited: retry later").await?;
        return Ok(());
    }
    if intent.channel == "email" && !sender.email_available() {
        retry_intent(pool, intent.id, claim, "SMTP is not configured").await?;
        return Ok(());
    }

    let subject = body::subject(
        &intent.event_type,
        &intent.severity,
        payload(intent.payload_json.as_ref()),
    );
    let text = body::render(
        &intent.event_type,
        &intent.severity,
        intent.occurrence_count,
        intent.alert_created_at,
        payload(intent.payload_json.as_ref()),
    );

    start_attempt(pool, intent.id, claim).await?;
    match send_target(sender, intent, &subject, &text).await {
        Ok(()) => {
            record_attempt(pool, intent, "sent", None).await?;
            settle_intent(pool, intent.id, claim, "sent", "sent").await?;
        }
        Err(error) => {
            let detail = truncate(&super::safe_diagnostic(&error), 1000);
            record_attempt(pool, intent, "failed", Some(&detail)).await?;
            if intent.attempt_count + 1 >= MAX_DELIVERY_ATTEMPTS {
                settle_permanent_failure(pool, intent, claim, &detail).await?;
            } else {
                retry_intent(pool, intent.id, claim, &detail).await?;
            }
        }
    }
    Ok(())
}

async fn intent_already_sent(pool: &MySqlPool, intent_id: u64) -> Result<bool> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM alert_deliveries \
         WHERE delivery_intent_id=? AND status='sent'",
    )
    .bind(intent_id)
    .fetch_one(pool)
    .await?;
    Ok(count > 0)
}

async fn send_target<S: DeliverySender>(
    sender: &S,
    intent: &DueIntent,
    subject: &str,
    text: &str,
) -> Result<()> {
    match intent.channel.as_str() {
        "email" => {
            let to = intent
                .target_address
                .as_deref()
                .context("email target missing")?;
            sender.send_email(to, subject, text.to_string()).await
        }
        "teams" => {
            let encrypted = intent
                .target_encrypted
                .as_deref()
                .context("Teams target missing")?;
            let url =
                crate::crypto::open_str(encrypted).context("decrypting Teams intent target")?;
            sender
                .send_teams(&url, subject, &intent.severity, text)
                .await
        }
        other => anyhow::bail!("unsupported alert channel {other:?}"),
    }
}

async fn start_attempt(pool: &MySqlPool, id: u64, claim: &str) -> Result<()> {
    let updated = sqlx::query(
        "UPDATE alert_delivery_intents SET attempt_count=attempt_count+1 \
         WHERE id=? AND claim_token=? AND state IN ('pending','retry')",
    )
    .bind(id)
    .bind(claim)
    .execute(pool)
    .await?
    .rows_affected();
    anyhow::ensure!(updated == 1, "delivery intent claim lost before send");
    Ok(())
}

async fn retry_intent(pool: &MySqlPool, id: u64, claim: &str, error: &str) -> Result<()> {
    sqlx::query(
        "UPDATE alert_delivery_intents SET state='retry', \
             next_attempt_at=DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND), last_error=?, \
             claim_token=NULL, claimed_at=NULL WHERE id=? AND claim_token=?",
    )
    .bind(RETRY_BACKOFF_SECS as i64)
    .bind(error)
    .bind(id)
    .bind(claim)
    .execute(pool)
    .await?;
    Ok(())
}

async fn settle_intent(
    pool: &MySqlPool,
    id: u64,
    claim: &str,
    outcome: &str,
    detail: &str,
) -> Result<()> {
    sqlx::query(
        "UPDATE alert_delivery_intents SET state='settled',outcome=?,settled_at=UTC_TIMESTAMP(), \
             last_error=?,claim_token=NULL,claimed_at=NULL WHERE id=? AND claim_token=?",
    )
    .bind(outcome)
    .bind(detail)
    .bind(id)
    .bind(claim)
    .execute(pool)
    .await?;
    Ok(())
}

async fn release_claim_after_internal_error(
    pool: &MySqlPool,
    id: u64,
    claim: &str,
    error: &anyhow::Error,
) -> Result<()> {
    retry_intent(
        pool,
        id,
        claim,
        &truncate(
            &format!(
                "internal dispatcher error: {}",
                super::safe_diagnostic(error)
            ),
            1000,
        ),
    )
    .await
}

async fn record_attempt(
    pool: &MySqlPool,
    intent: &DueIntent,
    status: &str,
    error: Option<&str>,
) -> Result<()> {
    let sent_at = if status == "sent" {
        "UTC_TIMESTAMP()"
    } else {
        "NULL"
    };
    let sql = format!(
        "INSERT INTO alert_deliveries \
            (alert_id,delivery_intent_id,recipient_id,endpoint_id,channel,status,error,sent_at) \
         VALUES (?,?,?,?,?,?,?,{sent_at})"
    );
    sqlx::query(&sql)
        .bind(intent.alert_id)
        .bind(intent.id)
        .bind(intent.recipient_id)
        .bind(intent.endpoint_id)
        .bind(&intent.channel)
        .bind(status)
        .bind(error)
        .execute(pool)
        .await?;
    Ok(())
}

async fn recently_delivered(pool: &MySqlPool, intent: &DueIntent) -> Result<bool> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM alert_deliveries d JOIN alerts a ON a.id=d.alert_id \
         WHERE d.status='sent' AND d.channel=? \
           AND ((? IS NOT NULL AND d.recipient_id=?) OR (? IS NOT NULL AND d.endpoint_id=?)) \
           AND a.dedup_key=(SELECT dedup_key FROM alerts WHERE id=?) \
           AND d.created_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? SECOND)",
    )
    .bind(&intent.channel)
    .bind(intent.recipient_id)
    .bind(intent.recipient_id)
    .bind(intent.endpoint_id)
    .bind(intent.endpoint_id)
    .bind(intent.alert_id)
    .bind(DEDUP_WINDOW_SECS as i64)
    .fetch_one(pool)
    .await?;
    Ok(count > 0)
}

async fn over_rate_limit(pool: &MySqlPool, intent: &DueIntent) -> Result<bool> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM alert_deliveries WHERE status='sent' AND channel=? \
           AND ((? IS NOT NULL AND recipient_id=?) OR (? IS NOT NULL AND endpoint_id=?)) \
           AND created_at >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 HOUR)",
    )
    .bind(&intent.channel)
    .bind(intent.recipient_id)
    .bind(intent.recipient_id)
    .bind(intent.endpoint_id)
    .bind(intent.endpoint_id)
    .fetch_one(pool)
    .await?;
    Ok(count >= RATE_LIMIT_PER_HOUR as i64)
}

async fn settle_permanent_failure(
    pool: &MySqlPool,
    intent: &DueIntent,
    claim: &str,
    detail: &str,
) -> Result<()> {
    tracing::error!(event_type="alert_delivery_gave_up", alert_id=intent.alert_id, intent_id=intent.id, channel=%intent.channel, attempts=MAX_DELIVERY_ATTEMPTS, "giving up on alert delivery after max attempts");
    let mut tx = pool.begin().await?;
    sqlx::query(
        "UPDATE alert_delivery_intents SET state='settled',outcome='permanent_failure', \
             settled_at=UTC_TIMESTAMP(),last_error=?,claim_token=NULL,claimed_at=NULL \
         WHERE id=? AND claim_token=?",
    )
    .bind(detail)
    .bind(intent.id)
    .bind(claim)
    .execute(&mut *tx)
    .await?;
    if intent.event_type == "alert_delivery_permanently_failed" {
        tx.commit().await?;
        return Ok(());
    }
    let payload = serde_json::json!({
        "original_alert_id": intent.alert_id,
        "original_event_type": intent.event_type,
        "delivery_intent_id": intent.id,
        "channel": intent.channel,
        "recipient_id": intent.recipient_id,
        "endpoint_id": intent.endpoint_id,
        "attempts": MAX_DELIVERY_ATTEMPTS,
    });
    sqlx::query(
        "INSERT INTO alerts (event_type,severity,payload_json,dedup_key) \
         VALUES ('alert_delivery_permanently_failed','critical',?,?)",
    )
    .bind(sqlx::types::Json(payload))
    .bind(format!(
        "alert_delivery_permanently_failed:intent:{}",
        intent.id
    ))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

async fn resolve_recipients(
    conn: &mut sqlx::MySqlConnection,
    alert: &PendingAlert,
    critical: bool,
) -> Result<Vec<Recipient>> {
    let mut recipients = BTreeMap::new();
    let subscribed = sqlx::query_as::<_, (u64, String)>(
        "SELECT DISTINCT r.id,r.email FROM alert_recipients r \
         JOIN alert_subscriptions s ON s.recipient_id=r.id \
         WHERE r.verified_at IS NOT NULL AND s.enabled=1 \
           AND (s.event_type IS NULL OR s.event_type=?)",
    )
    .bind(&alert.event_type)
    .fetch_all(&mut *conn)
    .await?;
    for (id, email) in subscribed {
        recipients.insert(id, Recipient { id, email });
    }
    if critical {
        let admins = sqlx::query_as::<_, (u64, String)>(
            "SELECT DISTINCT r.id,r.email FROM alert_recipients r \
             JOIN role_user ru ON ru.user_id=r.user_id JOIN roles ro ON ro.id=ru.role_id \
             WHERE ro.name IN ('admin','superadmin') AND r.verified_at IS NOT NULL",
        )
        .fetch_all(&mut *conn)
        .await?;
        for (id, email) in admins {
            recipients.insert(id, Recipient { id, email });
        }
    }
    Ok(recipients.into_values().collect())
}

async fn resolve_endpoints(
    conn: &mut sqlx::MySqlConnection,
    event_type: &str,
) -> Result<Vec<EndpointTarget>> {
    let rows = sqlx::query_as::<_, (u64, Vec<u8>)>(
        "SELECT DISTINCT e.id,e.url_encrypted FROM webhook_endpoints e \
         JOIN webhook_subscriptions s ON s.endpoint_id=e.id \
         WHERE e.enabled=1 AND s.enabled=1 AND (s.event_type IS NULL OR s.event_type=?) \
         ORDER BY e.id",
    )
    .bind(event_type)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, encrypted_url)| EndpointTarget { id, encrypted_url })
        .collect())
}

fn payload(value: Option<&sqlx::types::Json<Value>>) -> &Value {
    static EMPTY: Value = Value::Null;
    value.map(|json| &json.0).unwrap_or(&EMPTY)
}

fn truncate(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

fn mailer_from() -> Option<super::mailer::Mailer> {
    match super::mailer::Mailer::from_env() {
        Ok(mailer) => Some(mailer),
        Err(error) => {
            tracing::debug!(event_type="smtp_unconfigured", error=%error, "email disabled");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FakeSender {
        email: AtomicUsize,
        teams: AtomicUsize,
    }

    impl DeliverySender for FakeSender {
        fn email_available(&self) -> bool {
            true
        }
        fn send_email<'a>(
            &'a self,
            _to: &'a str,
            _subject: &'a str,
            _text: String,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                self.email.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        }
        fn send_teams<'a>(
            &'a self,
            _url: &'a str,
            _subject: &'a str,
            _severity: &'a str,
            _text: &'a str,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                self.teams.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        }
    }

    fn email_intent() -> DueIntent {
        DueIntent {
            id: 1,
            alert_id: 2,
            channel: "email".into(),
            recipient_id: Some(3),
            endpoint_id: None,
            target_address: Some("ops@example.test".into()),
            target_encrypted: None,
            attempt_count: 0,
            event_type: "reroute_failed".into(),
            severity: "critical".into(),
            occurrence_count: 1,
            payload_json: None,
            alert_created_at: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn fake_sender_receives_exactly_one_materialized_target() {
        let sender = FakeSender {
            email: AtomicUsize::new(0),
            teams: AtomicUsize::new(0),
        };
        send_target(&sender, &email_intent(), "subject", "body")
            .await
            .unwrap();
        assert_eq!(sender.email.load(Ordering::SeqCst), 1);
        assert_eq!(sender.teams.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn smtp_diagnostics_are_bounded_without_losing_the_cause() {
        assert_eq!(truncate("abcdef", 3), "abc");
        assert_eq!(
            truncate("invalid peer certificate", 100),
            "invalid peer certificate"
        );
    }

    #[tokio::test]
    async fn durable_fanout_keeps_unsent_siblings_runnable() {
        let database = crate::db::connect_test_database().await;
        let pool = database.pool();
        // Remove only fixture rows left by a prior panic in this same test.
        sqlx::query("DELETE FROM alerts WHERE dedup_key LIKE 'intent-test-%'")
            .execute(pool)
            .await
            .unwrap();
        sqlx::query(
            "DELETE FROM alert_recipients \
             WHERE email REGEXP '^[0-9a-f]{32}-[ab]@example\\.test$'",
        )
        .execute(pool)
        .await
        .unwrap();
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let event_type = format!("intent_test_{nonce}");
        let alert_id = sqlx::query(
            "INSERT INTO alerts (event_type,severity,payload_json,dedup_key) \
             VALUES (?,'warning','{}',?)",
        )
        .bind(&event_type)
        .bind(format!("intent-test-{nonce}"))
        .execute(pool)
        .await
        .unwrap()
        .last_insert_id();
        let mut recipients = Vec::new();
        for suffix in ["a", "b"] {
            let id = sqlx::query(
                "INSERT INTO alert_recipients (email,verified_at) VALUES (?,UTC_TIMESTAMP())",
            )
            .bind(format!("{nonce}-{suffix}@example.test"))
            .execute(pool)
            .await
            .unwrap()
            .last_insert_id();
            sqlx::query("INSERT INTO alert_subscriptions (recipient_id,event_type) VALUES (?,?)")
                .bind(id)
                .bind(&event_type)
                .execute(pool)
                .await
                .unwrap();
            recipients.push(id);
        }

        materialize_alert(
            pool,
            &PendingAlert {
                id: alert_id,
                event_type: event_type.clone(),
                severity: "warning".into(),
            },
        )
        .await
        .unwrap();
        let intents: Vec<u64> = sqlx::query_scalar(
            "SELECT id FROM alert_delivery_intents WHERE alert_id=? ORDER BY id",
        )
        .bind(alert_id)
        .fetch_all(pool)
        .await
        .unwrap();
        assert_eq!(intents.len(), 2, "all targets materialize before sends");
        sqlx::query(
            "UPDATE alert_delivery_intents SET state='settled',outcome='sent',settled_at=UTC_TIMESTAMP() WHERE id=?",
        )
        .bind(intents[0])
        .execute(pool)
        .await
        .unwrap();
        let sender = FakeSender {
            email: AtomicUsize::new(0),
            teams: AtomicUsize::new(0),
        };
        let claim = format!("test-{nonce}");
        sqlx::query(
            "UPDATE alert_delivery_intents SET claim_token=?,claimed_at=UTC_TIMESTAMP() WHERE id=?",
        )
        .bind(&claim)
        .bind(intents[1])
        .execute(pool)
        .await
        .unwrap();
        let pending = sqlx::query_as::<_, DueIntent>(
            "SELECT i.id,i.alert_id,i.channel,i.recipient_id,i.endpoint_id, \
                    i.target_address,i.target_encrypted,i.attempt_count, \
                    a.event_type,a.severity,a.occurrence_count,a.payload_json, \
                    a.created_at AS alert_created_at \
             FROM alert_delivery_intents i JOIN alerts a ON a.id=i.alert_id WHERE i.id=?",
        )
        .bind(intents[1])
        .fetch_one(pool)
        .await
        .unwrap();
        process_intent(pool, &sender, &pending, &claim)
            .await
            .unwrap();
        assert_eq!(sender.email.load(Ordering::SeqCst), 1);
        let unsettled: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM alert_delivery_intents WHERE alert_id=? AND state<>'settled'",
        )
        .bind(alert_id)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(unsettled, 0);

        sqlx::query("DELETE FROM alerts WHERE id=?")
            .bind(alert_id)
            .execute(pool)
            .await
            .ok();
        for id in recipients {
            sqlx::query("DELETE FROM alert_recipients WHERE id=?")
                .bind(id)
                .execute(pool)
                .await
                .ok();
        }
    }

    #[tokio::test]
    async fn no_audience_page_cannot_starve_later_routable_alert() {
        let database = crate::db::connect_test_database().await;
        let pool = database.pool();
        sqlx::query("DELETE FROM alerts WHERE dedup_key LIKE 'fairness-test-%'")
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM alert_recipients WHERE email LIKE 'fairness-%@example.test'")
            .execute(pool)
            .await
            .unwrap();

        let backlog: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM alerts a WHERE NOT EXISTS \
             (SELECT 1 FROM alert_delivery_intents i WHERE i.alert_id=a.id)",
        )
        .fetch_one(pool)
        .await
        .unwrap();
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let old_event = format!("fair_old_{nonce}");
        for index in 0..55 {
            sqlx::query(
                "INSERT INTO alerts (event_type,severity,payload_json,dedup_key) \
                 VALUES (?,'warning','{}',?)",
            )
            .bind(&old_event)
            .bind(format!("fairness-test-{nonce}-old-{index}"))
            .execute(pool)
            .await
            .unwrap();
        }
        let new_event = format!("fair_new_{nonce}");
        let recipient_id = sqlx::query(
            "INSERT INTO alert_recipients (email,verified_at) VALUES (?,UTC_TIMESTAMP())",
        )
        .bind(format!("fairness-{nonce}@example.test"))
        .execute(pool)
        .await
        .unwrap()
        .last_insert_id();
        sqlx::query("INSERT INTO alert_subscriptions (recipient_id,event_type) VALUES (?,?)")
            .bind(recipient_id)
            .bind(&new_event)
            .execute(pool)
            .await
            .unwrap();
        let routable_alert = sqlx::query(
            "INSERT INTO alerts (event_type,severity,payload_json,dedup_key) \
             VALUES (?,'warning','{}',?)",
        )
        .bind(&new_event)
        .bind(format!("fairness-test-{nonce}-routable"))
        .execute(pool)
        .await
        .unwrap()
        .last_insert_id();

        let passes = ((backlog + 56 + NORMAL_SLOTS - 1) / NORMAL_SLOTS) + 1;
        for _ in 0..passes {
            materialize_batch(pool).await.unwrap();
        }
        let old_settled: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM alert_delivery_intents i JOIN alerts a ON a.id=i.alert_id \
             WHERE a.dedup_key LIKE ? AND i.state='settled' AND i.outcome='no_audience'",
        )
        .bind(format!("fairness-test-{nonce}-old-%"))
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(old_settled, 55);
        let routable_pending: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM alert_delivery_intents \
             WHERE alert_id=? AND state='pending' AND channel='email' AND recipient_id=?",
        )
        .bind(routable_alert)
        .bind(recipient_id)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(
            routable_pending, 1,
            "later subscribed alert must materialize despite older no-audience pages"
        );

        sqlx::query("DELETE FROM alerts WHERE dedup_key LIKE ?")
            .bind(format!("fairness-test-{nonce}-%"))
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM alert_recipients WHERE id=?")
            .bind(recipient_id)
            .execute(pool)
            .await
            .ok();
    }

    #[tokio::test]
    async fn legacy_repair_preserves_outcomes_and_retry_state() {
        let database = crate::db::connect_test_database().await;
        let pool = database.pool();
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let recipient_id = sqlx::query(
            "INSERT INTO alert_recipients (email,verified_at) VALUES (?,UTC_TIMESTAMP())",
        )
        .bind(format!("repair-{nonce}@example.test"))
        .execute(pool)
        .await
        .unwrap()
        .last_insert_id();

        let mut alerts = Vec::new();
        for label in [
            "sent",
            "suppressed",
            "retry",
            "bounced",
            "existing",
            "combined_budget",
            "legacy_rate_limit",
            "settled_immutable",
            "sent_then_failed",
            "teams_rate_url",
            "settled_failure_with_sent",
        ] {
            let id = sqlx::query(
                "INSERT INTO alerts (event_type,severity,payload_json,dedup_key) \
                 VALUES (?,'warning','{}',?)",
            )
            .bind(format!("repair_{label}"))
            .bind(format!("repair-{nonce}-{label}"))
            .execute(pool)
            .await
            .unwrap()
            .last_insert_id();
            alerts.push(id);
        }
        let attempts = [
            (alerts[0], "sent", None),
            (
                alerts[1],
                "queued",
                Some("suppressed: deduplicated within window"),
            ),
            (alerts[2], "failed", Some("connection refused")),
            (alerts[2], "queued", Some("rate limited: retry later")),
            (alerts[3], "bounced", Some("mailbox unavailable")),
            (alerts[4], "sent", None),
        ];
        for (alert_id, status, error) in attempts {
            sqlx::query(
                "INSERT INTO alert_deliveries \
                    (alert_id,recipient_id,channel,status,error,sent_at) \
                 VALUES (?,?,'email',?,?,IF(?='sent',UTC_TIMESTAMP(),NULL))",
            )
            .bind(alert_id)
            .bind(recipient_id)
            .bind(status)
            .bind(error)
            .bind(status)
            .execute(pool)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO alert_deliveries (alert_id,recipient_id,channel,status,error) \
             VALUES (?,?,'email','failed','fifth disjoint failure'), \
                    (?,?,'email','queued','rate limited')",
        )
        .bind(alerts[5])
        .bind(recipient_id)
        .bind(alerts[6])
        .bind(recipient_id)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO alert_deliveries \
                (alert_id,recipient_id,channel,status,error,sent_at,created_at) \
             VALUES (?,?,'email','sent',NULL,DATE_SUB(UTC_TIMESTAMP(),INTERVAL 9 MINUTE), \
                     DATE_SUB(UTC_TIMESTAMP(),INTERVAL 10 MINUTE)), \
                    (?,?,'email','failed','later failure',NULL,UTC_TIMESTAMP())",
        )
        .bind(alerts[8])
        .bind(recipient_id)
        .bind(alerts[8])
        .bind(recipient_id)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO alert_delivery_intents \
                (alert_id,channel,target_key,recipient_id,target_address,state) \
             VALUES (?,'email',?,?,?,'pending')",
        )
        .bind(alerts[4])
        .bind(format!("recipient:{recipient_id}"))
        .bind(recipient_id)
        .bind(format!("repair-{nonce}@example.test"))
        .execute(pool)
        .await
        .unwrap();
        for (alert_id, state, outcome, attempts) in [
            (alerts[5], "pending", None::<&str>, 4u32),
            (alerts[6], "pending", None::<&str>, 0u32),
        ] {
            sqlx::query(
                "INSERT INTO alert_delivery_intents \
                    (alert_id,channel,target_key,recipient_id,target_address,state,outcome,attempt_count) \
                 VALUES (?,'email',?,?,?, ?, ?, ?)",
            )
            .bind(alert_id)
            .bind(format!("recipient:{recipient_id}"))
            .bind(recipient_id)
            .bind(format!("repair-{nonce}@example.test"))
            .bind(state)
            .bind(outcome)
            .bind(attempts)
            .execute(pool)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO alert_delivery_intents \
                (alert_id,channel,target_key,recipient_id,target_address,state,outcome,attempt_count,settled_at,updated_at) \
             VALUES (?,'email',?,?,?,'settled','suppressed',2,NULL,DATE_SUB(UTC_TIMESTAMP(),INTERVAL 1 DAY))",
        )
        .bind(alerts[7])
        .bind(format!("recipient:{recipient_id}"))
        .bind(recipient_id)
        .bind(format!("repair-{nonce}@example.test"))
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO alert_deliveries (alert_id,recipient_id,channel,status,error) \
             VALUES (?,?,'email','queued','suppressed: already delivered')",
        )
        .bind(alerts[7])
        .bind(recipient_id)
        .execute(pool)
        .await
        .unwrap();
        let immutable_before: (String, Option<String>, u32, Option<chrono::DateTime<chrono::Utc>>, chrono::DateTime<chrono::Utc>) =
            sqlx::query_as("SELECT state,outcome,attempt_count,settled_at,updated_at FROM alert_delivery_intents WHERE alert_id=?")
                .bind(alerts[7]).fetch_one(pool).await.unwrap();
        let endpoint_id =
            sqlx::query("INSERT INTO webhook_endpoints(name,url_encrypted,enabled) VALUES(?,?,1)")
                .bind(format!("repair-{nonce}"))
                .bind(vec![1u8, 2, 3])
                .execute(pool)
                .await
                .unwrap()
                .last_insert_id();
        let teams_delivery_id = sqlx::query(
            "INSERT INTO alert_deliveries(alert_id,endpoint_id,channel,status,error,created_at) \
             VALUES (?,?,'teams','queued',?,DATE_SUB(UTC_TIMESTAMP(),INTERVAL 7 MINUTE))",
        )
        .bind(alerts[9])
        .bind(endpoint_id)
        .bind("rate limited: retry https://example.invalid/webhook?sig=SYNTHETIC_SECRET")
        .execute(pool)
        .await
        .unwrap()
        .last_insert_id();
        let teams_created_before: chrono::DateTime<chrono::Utc> =
            sqlx::query_scalar("SELECT created_at FROM alert_deliveries WHERE id=?")
                .bind(teams_delivery_id)
                .fetch_one(pool)
                .await
                .unwrap();
        sqlx::query(
            "INSERT INTO alert_delivery_intents \
                (alert_id,channel,target_key,recipient_id,target_address,state,outcome,attempt_count,settled_at,updated_at) \
             VALUES (?,'email',?,?,?,'settled','permanent_failure',3,DATE_SUB(UTC_TIMESTAMP(),INTERVAL 1 DAY),DATE_SUB(UTC_TIMESTAMP(),INTERVAL 1 DAY))",
        )
        .bind(alerts[10])
        .bind(format!("recipient:{recipient_id}"))
        .bind(recipient_id)
        .bind(format!("repair-{nonce}@example.test"))
        .execute(pool)
        .await
        .unwrap();
        let winning_delivery = sqlx::query(
            "INSERT INTO alert_deliveries \
                (alert_id,recipient_id,channel,status,sent_at,created_at) \
             VALUES (?,?,'email','sent',DATE_SUB(UTC_TIMESTAMP(),INTERVAL 9 MINUTE),DATE_SUB(UTC_TIMESTAMP(),INTERVAL 10 MINUTE))",
        )
        .bind(alerts[10])
        .bind(recipient_id)
        .execute(pool)
        .await
        .unwrap()
        .last_insert_id();
        let settled_failure_before: (String, u32, chrono::DateTime<chrono::Utc>) = sqlx::query_as(
            "SELECT state,attempt_count,updated_at FROM alert_delivery_intents WHERE alert_id=?",
        )
        .bind(alerts[10])
        .fetch_one(pool)
        .await
        .unwrap();

        sqlx::raw_sql(include_str!(
            "../../migrations/20260921000300_alert_delivery_repair.sql"
        ))
        .execute(pool)
        .await
        .unwrap();

        let summaries: Vec<(String, Option<String>, u32)> = sqlx::query_as(
            "SELECT state,outcome,attempt_count FROM alert_delivery_intents \
             WHERE alert_id=? AND recipient_id=?",
        )
        .bind(alerts[0])
        .bind(recipient_id)
        .fetch_all(pool)
        .await
        .unwrap();
        assert_eq!(summaries, vec![("settled".into(), Some("sent".into()), 0)]);

        let states: Vec<(u64, String, Option<String>, u32)> = sqlx::query_as(
            "SELECT alert_id,state,outcome,attempt_count FROM alert_delivery_intents \
             WHERE alert_id IN (?,?,?,?,?) ORDER BY alert_id",
        )
        .bind(alerts[0])
        .bind(alerts[1])
        .bind(alerts[2])
        .bind(alerts[3])
        .bind(alerts[4])
        .fetch_all(pool)
        .await
        .unwrap();
        assert_eq!(states[1].1, "settled");
        assert_eq!(states[1].2.as_deref(), Some("suppressed"));
        assert_eq!(states[2].1, "retry");
        assert_eq!(states[2].2, None);
        assert_eq!(states[2].3, 1);
        assert_eq!(states[3].2.as_deref(), Some("permanent_failure"));
        assert_eq!(
            states[4].2.as_deref(),
            Some("sent"),
            "historical success settles an existing pending intent"
        );
        let settled_at: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
            "SELECT settled_at FROM alert_delivery_intents WHERE alert_id=? AND recipient_id=?",
        )
        .bind(alerts[4])
        .bind(recipient_id)
        .fetch_one(pool)
        .await
        .unwrap();
        assert!(settled_at.is_some(), "settled success has a timestamp");

        let combined: (String, Option<String>, u32) = sqlx::query_as(
            "SELECT state,outcome,attempt_count FROM alert_delivery_intents WHERE alert_id=?",
        )
        .bind(alerts[5])
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(
            combined,
            ("settled".into(), Some("permanent_failure".into()), 5)
        );
        let legacy_rate: (String, Option<String>, u32) = sqlx::query_as(
            "SELECT state,outcome,attempt_count FROM alert_delivery_intents WHERE alert_id=?",
        )
        .bind(alerts[6])
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(legacy_rate, ("retry".into(), None, 0));
        let teams_repaired: (String, Option<String>, u32, Option<String>, u64) = sqlx::query_as(
            "SELECT state,outcome,attempt_count,last_error,endpoint_id \
             FROM alert_delivery_intents WHERE alert_id=?",
        )
        .bind(alerts[9])
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(teams_repaired.0, "retry");
        assert_eq!(teams_repaired.1, None);
        assert_eq!(teams_repaired.2, 0);
        assert_eq!(teams_repaired.4, endpoint_id);
        let safe_error = teams_repaired.3.expect("retry diagnostic retained");
        assert!(safe_error.starts_with("rate limited:"));
        assert!(!safe_error.contains("http"));
        assert!(!safe_error.contains("SYNTHETIC_SECRET"));
        let (delivery_error, teams_created_after, repaired_endpoint): (
            String,
            chrono::DateTime<chrono::Utc>,
            u64,
        ) = sqlx::query_as("SELECT error,created_at,endpoint_id FROM alert_deliveries WHERE id=?")
            .bind(teams_delivery_id)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(teams_created_after, teams_created_before);
        assert_eq!(repaired_endpoint, endpoint_id);
        assert!(delivery_error.starts_with("rate limited:"));
        assert!(!delivery_error.contains("http"));
        assert!(!delivery_error.contains("SYNTHETIC_SECRET"));
        let immutable_after: (String, Option<String>, u32, Option<chrono::DateTime<chrono::Utc>>, chrono::DateTime<chrono::Utc>) =
            sqlx::query_as("SELECT state,outcome,attempt_count,settled_at,updated_at FROM alert_delivery_intents WHERE alert_id=?")
                .bind(alerts[7]).fetch_one(pool).await.unwrap();
        assert_eq!(
            immutable_after, immutable_before,
            "settled intent is byte-for-byte immutable across repaired fields"
        );
        let (repaired_sent_at, historical_sent_at): (
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
        ) = sqlx::query_as(
            "SELECT i.settled_at, d.sent_at FROM alert_delivery_intents i \
             JOIN alert_deliveries d ON d.alert_id=i.alert_id AND d.status='sent' \
             WHERE i.alert_id=?",
        )
        .bind(alerts[8])
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(
            repaired_sent_at, historical_sent_at,
            "sent winner settles at the sent attempt, not a later failure"
        );
        let settled_failure_after: (
            String,
            Option<String>,
            u32,
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
        ) = sqlx::query_as(
            "SELECT state,outcome,attempt_count,settled_at,updated_at \
             FROM alert_delivery_intents WHERE alert_id=?",
        )
        .bind(alerts[10])
        .fetch_one(pool)
        .await
        .unwrap();
        let winning_sent_at: chrono::DateTime<chrono::Utc> =
            sqlx::query_scalar("SELECT sent_at FROM alert_deliveries WHERE id=?")
                .bind(winning_delivery)
                .fetch_one(pool)
                .await
                .unwrap();
        assert_eq!(settled_failure_after.0, settled_failure_before.0);
        assert_eq!(settled_failure_after.1.as_deref(), Some("sent"));
        assert_eq!(settled_failure_after.2, settled_failure_before.1);
        assert_eq!(settled_failure_after.3, winning_sent_at);
        assert_eq!(settled_failure_after.4, settled_failure_before.2);

        let unlinked: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM alert_deliveries d JOIN alerts a ON a.id=d.alert_id \
             WHERE a.dedup_key LIKE ? AND d.delivery_intent_id IS NULL",
        )
        .bind(format!("repair-{nonce}-%"))
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(
            unlinked, 0,
            "every legacy attempt is linked deterministically"
        );

        sqlx::raw_sql(include_str!(
            "../../migrations/20260921000300_alert_delivery_repair.sql"
        ))
        .execute(pool)
        .await
        .unwrap();
        let replayed: Vec<(u64, String, Option<String>, u32)> = sqlx::query_as(
            "SELECT alert_id,state,outcome,attempt_count FROM alert_delivery_intents \
             WHERE alert_id IN (?,?,?,?,?) ORDER BY alert_id",
        )
        .bind(alerts[0])
        .bind(alerts[1])
        .bind(alerts[2])
        .bind(alerts[3])
        .bind(alerts[4])
        .fetch_all(pool)
        .await
        .unwrap();
        assert_eq!(replayed, states, "repair is idempotent");
        let replayed_budget: (String, Option<String>, u32) = sqlx::query_as(
            "SELECT state,outcome,attempt_count FROM alert_delivery_intents WHERE alert_id=?",
        )
        .bind(alerts[5])
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(
            replayed_budget, combined,
            "linked legacy failures are not charged twice on replay"
        );
        let teams_replayed: (String, Option<String>, u32, Option<String>) = sqlx::query_as(
            "SELECT state,outcome,attempt_count,last_error FROM alert_delivery_intents WHERE alert_id=?",
        )
        .bind(alerts[9])
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(
            teams_replayed,
            ("retry".into(), None, 0, Some(safe_error)),
            "URL scrub and rate-limit classification are idempotent"
        );
        let settled_failure_replayed: (
            String,
            Option<String>,
            u32,
            chrono::DateTime<chrono::Utc>,
            chrono::DateTime<chrono::Utc>,
        ) = sqlx::query_as(
            "SELECT state,outcome,attempt_count,settled_at,updated_at \
             FROM alert_delivery_intents WHERE alert_id=?",
        )
        .bind(alerts[10])
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(settled_failure_replayed, settled_failure_after);

        for alert_id in alerts {
            sqlx::query("DELETE FROM alerts WHERE id=?")
                .bind(alert_id)
                .execute(pool)
                .await
                .ok();
        }
        sqlx::query("DELETE FROM alert_recipients WHERE id=?")
            .bind(recipient_id)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM webhook_endpoints WHERE id=?")
            .bind(endpoint_id)
            .execute(pool)
            .await
            .ok();
    }
}
