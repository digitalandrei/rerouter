-- Microsoft Teams (incoming webhook) as a SECOND alert delivery channel beside
-- email. Endpoint URLs are encrypted at rest (AES-256-GCM, crypto::seal) — only
-- ciphertext lands here, never the plaintext webhook URL. Per-event routing
-- mirrors alert_subscriptions.

CREATE TABLE IF NOT EXISTS webhook_endpoints (
    id            BIGINT UNSIGNED  NOT NULL AUTO_INCREMENT,
    kind          ENUM('teams')    NOT NULL DEFAULT 'teams',
    name          VARCHAR(191)     NOT NULL,
    -- AES-256-GCM ciphertext of the incoming-webhook URL (crypto::seal). Never plaintext.
    url_encrypted VARBINARY(2048)  NOT NULL,
    enabled       TINYINT(1)       NOT NULL DEFAULT 1,
    created_by    BIGINT UNSIGNED  NULL,
    created_at    TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMP        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_webhook_endpoints_name (name),
    CONSTRAINT fk_webhook_endpoints_user FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS webhook_subscriptions (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    endpoint_id BIGINT UNSIGNED NOT NULL,
    event_type  VARCHAR(64)     NULL,   -- NULL = all event types
    enabled     TINYINT(1)      NOT NULL DEFAULT 1,
    created_at  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_webhook_subscriptions_endpoint (endpoint_id),
    CONSTRAINT fk_webhook_subscriptions_endpoint FOREIGN KEY (endpoint_id) REFERENCES webhook_endpoints (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Extend deliveries for the Teams channel: recipient_id becomes nullable (a Teams
-- delivery targets an endpoint, not an email recipient) and an endpoint_id is added.
ALTER TABLE alert_deliveries
    MODIFY COLUMN channel ENUM('email', 'teams') NOT NULL DEFAULT 'email',
    MODIFY COLUMN recipient_id BIGINT UNSIGNED NULL,
    ADD COLUMN endpoint_id BIGINT UNSIGNED NULL AFTER recipient_id,
    ADD KEY idx_alert_deliveries_endpoint_created (endpoint_id, created_at),
    ADD CONSTRAINT fk_alert_deliveries_endpoint FOREIGN KEY (endpoint_id) REFERENCES webhook_endpoints (id) ON DELETE CASCADE;
