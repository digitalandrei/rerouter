-- Reconstruct durable per-target work from the append-only delivery history.
-- Identity and timestamps stay on the historical rows; the new intent is only
-- the resumable summary and every old attempt is linked to it below.

-- Older reqwest diagnostics could contain the complete Teams capability URL.
-- Replace the whole URL-bearing diagnostic: cross-engine URL surgery is more
-- likely to leave a query token behind than this deliberately generic message.
UPDATE alert_deliveries
SET error = CASE
      WHEN error LIKE 'rate limited%' THEN
        'rate limited: Teams delivery deferred (historical URL-bearing diagnostic redacted)'
      ELSE 'Teams delivery failed (historical URL-bearing diagnostic redacted)'
    END
WHERE channel = 'teams' AND error IS NOT NULL
  AND (error LIKE '%http://%' OR error LIKE '%https://%');

UPDATE alert_delivery_intents
SET last_error = CASE
      WHEN last_error LIKE 'rate limited%' THEN
        'rate limited: Teams delivery deferred (historical URL-bearing diagnostic redacted)'
      ELSE 'Teams delivery failed (historical URL-bearing diagnostic redacted)'
    END,
    updated_at = updated_at
WHERE channel = 'teams' AND last_error IS NOT NULL
  AND (last_error LIKE '%http://%' OR last_error LIKE '%https://%');

DROP TEMPORARY TABLE IF EXISTS legacy_alert_delivery_repair;
CREATE TEMPORARY TABLE legacy_alert_delivery_repair AS
SELECT d.alert_id,
       d.channel,
       d.recipient_id,
       d.endpoint_id,
       CASE
         WHEN d.recipient_id IS NOT NULL THEN CONCAT('recipient:', d.recipient_id)
         WHEN d.endpoint_id IS NOT NULL THEN CONCAT('endpoint:', d.endpoint_id)
         ELSE CONCAT('legacy-unresolved:', d.channel)
       END AS target_key,
       MAX(d.status = 'sent') AS has_sent,
       MAX(COALESCE(r.email = 'unrouted@rerouter.local', 0)) AS is_no_audience,
       MAX(d.status = 'bounced') AS has_bounced,
       MAX(d.status = 'queued' AND COALESCE(d.error, '') LIKE 'rate limited%') AS has_rate_limit,
       MAX(d.status = 'queued' AND COALESCE(d.error, '') NOT LIKE 'rate limited%') AS has_settled_queue,
       SUM(d.status IN ('failed', 'bounced')) AS failed_attempts,
       MAX(d.created_at) AS last_attempt_at,
       MAX(CASE WHEN d.status = 'sent' THEN COALESCE(d.sent_at, d.created_at) END) AS sent_at,
       SUBSTRING_INDEX(GROUP_CONCAT(COALESCE(d.error, '') ORDER BY d.created_at DESC, d.id DESC SEPARATOR '\n'), '\n', 1) AS last_error
FROM alert_deliveries d
LEFT JOIN alert_recipients r ON r.id = d.recipient_id
WHERE d.delivery_intent_id IS NULL
GROUP BY d.alert_id, d.channel, d.recipient_id, d.endpoint_id;

-- Snapshot the old intent and compute every repaired field once. This avoids
-- MySQL/MariaDB ON DUPLICATE assignment-order semantics and makes disjoint old
-- attempt_count + still-unlinked legacy failures consume one combined budget.
DROP TEMPORARY TABLE IF EXISTS alert_delivery_repair_summary;
CREATE TEMPORARY TABLE alert_delivery_repair_summary AS
SELECT g.*,
       i.state AS old_state,
       i.outcome AS old_outcome,
       i.attempt_count AS old_attempt_count,
       i.next_attempt_at AS old_next_attempt_at,
       i.last_error AS old_last_error,
       i.settled_at AS old_settled_at,
       i.updated_at AS old_updated_at,
       CASE WHEN i.state = 'settled' THEN i.attempt_count
            ELSE COALESCE(i.attempt_count, 0) + g.failed_attempts
       END AS repaired_attempt_count,
       CASE
         WHEN i.state = 'settled' THEN 'settled'
         WHEN g.has_sent = 1 OR g.is_no_audience = 1
              OR (g.recipient_id IS NULL AND g.endpoint_id IS NULL)
              OR g.has_settled_queue = 1 OR g.has_bounced = 1
              OR COALESCE(i.attempt_count, 0) + g.failed_attempts >= 5 THEN 'settled'
         ELSE 'retry'
       END AS repaired_state,
       CASE
         WHEN g.has_sent = 1 THEN 'sent'
         WHEN i.state = 'settled' THEN i.outcome
         WHEN g.is_no_audience = 1 THEN 'no_audience'
         WHEN g.recipient_id IS NULL AND g.endpoint_id IS NULL THEN 'permanent_failure'
         WHEN g.has_settled_queue = 1 THEN 'suppressed'
         WHEN g.has_bounced = 1 OR COALESCE(i.attempt_count, 0) + g.failed_attempts >= 5
           THEN 'permanent_failure'
         ELSE NULL
       END AS repaired_outcome,
       CASE
         WHEN i.state = 'settled' THEN i.next_attempt_at
         WHEN g.has_sent = 1 OR g.is_no_audience = 1
              OR (g.recipient_id IS NULL AND g.endpoint_id IS NULL)
              OR g.has_settled_queue = 1 OR g.has_bounced = 1
              OR COALESCE(i.attempt_count, 0) + g.failed_attempts >= 5
           THEN g.last_attempt_at
         ELSE GREATEST(COALESCE(i.next_attempt_at, g.last_attempt_at),
                       DATE_ADD(g.last_attempt_at, INTERVAL 300 SECOND))
       END AS repaired_next_attempt_at,
       CASE
         WHEN i.state = 'settled' THEN i.last_error
         WHEN g.recipient_id IS NULL AND g.endpoint_id IS NULL
           THEN CONCAT('legacy target identity unavailable; ', COALESCE(NULLIF(g.last_error, ''), 'diagnostic unavailable'))
         ELSE NULLIF(g.last_error, '')
       END AS repaired_last_error,
       CASE
         WHEN g.has_sent = 1 THEN g.sent_at
         WHEN i.state = 'settled' THEN i.settled_at
         WHEN g.is_no_audience = 1
              OR (g.recipient_id IS NULL AND g.endpoint_id IS NULL)
              OR g.has_settled_queue = 1 OR g.has_bounced = 1
              OR COALESCE(i.attempt_count, 0) + g.failed_attempts >= 5
           THEN g.last_attempt_at
         ELSE NULL
       END AS repaired_settled_at,
       COALESCE(i.updated_at, CURRENT_TIMESTAMP) AS repaired_updated_at
FROM legacy_alert_delivery_repair g
LEFT JOIN alert_delivery_intents i
  ON i.alert_id = g.alert_id AND i.channel = g.channel AND i.target_key = g.target_key;

INSERT INTO alert_delivery_intents
    (alert_id, channel, target_key, recipient_id, endpoint_id,
     target_address, target_encrypted, state, outcome, attempt_count,
     next_attempt_at, last_error, settled_at, updated_at)
SELECT g.alert_id,
       g.channel,
       g.target_key,
       g.recipient_id,
       g.endpoint_id,
       CASE WHEN g.channel = 'email' THEN r.email ELSE NULL END,
       CASE WHEN g.channel = 'teams' THEN e.url_encrypted ELSE NULL END,
       g.repaired_state,
       g.repaired_outcome,
       g.repaired_attempt_count,
       g.repaired_next_attempt_at,
       g.repaired_last_error,
       g.repaired_settled_at,
       g.repaired_updated_at
FROM alert_delivery_repair_summary g
LEFT JOIN alert_recipients r ON r.id = g.recipient_id
LEFT JOIN webhook_endpoints e ON e.id = g.endpoint_id
ON DUPLICATE KEY UPDATE
    state = VALUES(state), outcome = VALUES(outcome), attempt_count = VALUES(attempt_count),
    next_attempt_at = VALUES(next_attempt_at), last_error = VALUES(last_error),
    settled_at = VALUES(settled_at), updated_at = VALUES(updated_at);

UPDATE alert_deliveries d
JOIN legacy_alert_delivery_repair g
  ON g.alert_id = d.alert_id
 AND g.channel = d.channel
 AND g.recipient_id <=> d.recipient_id
 AND g.endpoint_id <=> d.endpoint_id
JOIN alert_delivery_intents i
  ON i.alert_id = g.alert_id AND i.channel = g.channel AND i.target_key = g.target_key
SET d.delivery_intent_id = i.id
WHERE d.delivery_intent_id IS NULL;

DROP TEMPORARY TABLE alert_delivery_repair_summary;
DROP TEMPORARY TABLE legacy_alert_delivery_repair;
