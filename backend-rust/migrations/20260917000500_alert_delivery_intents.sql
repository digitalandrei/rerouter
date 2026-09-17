-- Durable per-target alert work. Delivery attempts remain append-only audit
-- records; this table is the authoritative pending/retry/settled state.

CREATE TABLE IF NOT EXISTS alert_delivery_intents (
    id                      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    alert_id                BIGINT UNSIGNED NOT NULL,
    channel                 ENUM('email','teams') NOT NULL,
    target_key              VARCHAR(255) NOT NULL,
    recipient_id            BIGINT UNSIGNED NULL,
    endpoint_id             BIGINT UNSIGNED NULL,
    target_address          VARCHAR(191) NULL,
    target_encrypted        BLOB NULL,
    state                   ENUM('pending','retry','settled') NOT NULL DEFAULT 'pending',
    outcome                 ENUM('sent','suppressed','permanent_failure','no_audience') NULL,
    attempt_count           INT UNSIGNED NOT NULL DEFAULT 0,
    next_attempt_at         DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    claimed_at              DATETIME NULL,
    claim_token             VARCHAR(64) NULL,
    last_error              TEXT NULL,
    settled_at              DATETIME NULL,
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_alert_delivery_intent_target (alert_id, channel, target_key),
    KEY idx_alert_delivery_intents_due (state, next_attempt_at, id),
    KEY idx_alert_delivery_intents_alert_state (alert_id, state),
    KEY idx_alert_delivery_intents_recipient (recipient_id),
    KEY idx_alert_delivery_intents_endpoint (endpoint_id),
    CONSTRAINT fk_alert_delivery_intents_alert
        FOREIGN KEY (alert_id) REFERENCES alerts (id) ON DELETE CASCADE,
    CONSTRAINT fk_alert_delivery_intents_recipient
        FOREIGN KEY (recipient_id) REFERENCES alert_recipients (id) ON DELETE SET NULL,
    CONSTRAINT fk_alert_delivery_intents_endpoint
        FOREIGN KEY (endpoint_id) REFERENCES webhook_endpoints (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Correlate append-only SMTP/webhook diagnostics with their durable work item.
SET @col := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'alert_deliveries'
      AND column_name = 'delivery_intent_id');
SET @ddl := IF(@col = 0,
    'ALTER TABLE alert_deliveries ADD COLUMN delivery_intent_id BIGINT UNSIGNED NULL AFTER alert_id',
    'DO 0');
PREPARE s FROM @ddl; EXECUTE s; DEALLOCATE PREPARE s;

SET @idx := (SELECT COUNT(*) FROM information_schema.statistics
    WHERE table_schema = DATABASE() AND table_name = 'alert_deliveries'
      AND index_name = 'idx_alert_deliveries_intent');
SET @ddl := IF(@idx = 0,
    'CREATE INDEX idx_alert_deliveries_intent ON alert_deliveries (delivery_intent_id, created_at)',
    'DO 0');
PREPARE s FROM @ddl; EXECUTE s; DEALLOCATE PREPARE s;

SET @fk := (SELECT COUNT(*) FROM information_schema.table_constraints
    WHERE table_schema = DATABASE() AND table_name = 'alert_deliveries'
      AND constraint_name = 'fk_alert_deliveries_intent');
SET @ddl := IF(@fk = 0,
    'ALTER TABLE alert_deliveries ADD CONSTRAINT fk_alert_deliveries_intent FOREIGN KEY (delivery_intent_id) REFERENCES alert_delivery_intents(id) ON DELETE SET NULL',
    'DO 0');
PREPARE s FROM @ddl; EXECUTE s; DEALLOCATE PREPARE s;

-- Existing recipients created by email-only settings lacked the user link, so
-- mandatory admin fanout could not find them. utf8mb4_unicode_ci comparison is
-- case-insensitive; preserve an explicit existing link.
UPDATE alert_recipients r
JOIN users u ON u.email = r.email
SET r.user_id = u.id
WHERE r.user_id IS NULL;
