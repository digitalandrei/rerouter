-- Email alert pipeline tables. The controller's internal alert dispatcher task
-- polls new alerts rows, resolves recipients/subscriptions, de-dups (10-min
-- window per dedup_key = event_type/asset/rule), rate-limits (20/hr per
-- recipient, digest fallback), sends via SMTP, and records alert_deliveries.
-- reroute_uncertain / reroute_failed / security events are always sent
-- immediately and never collapsed. See docs/email-alerts.md.

CREATE TABLE IF NOT EXISTS alerts (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    event_type          VARCHAR(64)     NOT NULL,
    severity            VARCHAR(32)     NOT NULL DEFAULT 'warning',
    asset_id            BIGINT UNSIGNED NULL,
    rule_id             BIGINT UNSIGNED NULL,
    reroute_id          BIGINT UNSIGNED NULL,
    payload_json        JSON            NULL,
    dedup_key           VARCHAR(191)    NOT NULL,
    occurrence_count    INT UNSIGNED    NOT NULL DEFAULT 1,
    created_at          TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_alerts_dedup_key (dedup_key),
    KEY idx_alerts_event_created (event_type, created_at),
    KEY idx_alerts_asset (asset_id),
    CONSTRAINT fk_alerts_asset FOREIGN KEY (asset_id) REFERENCES protected_assets (id) ON DELETE SET NULL,
    CONSTRAINT fk_alerts_rule FOREIGN KEY (rule_id) REFERENCES rules (id) ON DELETE SET NULL,
    CONSTRAINT fk_alerts_reroute FOREIGN KEY (reroute_id) REFERENCES reroutes (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS alert_recipients (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id     BIGINT UNSIGNED NULL,
    email       VARCHAR(191)    NOT NULL,
    verified_at TIMESTAMP       NULL DEFAULT NULL,
    created_at  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_alert_recipients_email (email),
    KEY idx_alert_recipients_user (user_id),
    CONSTRAINT fk_alert_recipients_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS alert_subscriptions (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    recipient_id    BIGINT UNSIGNED NOT NULL,
    asset_id        BIGINT UNSIGNED NULL,  -- NULL = all assets
    event_type      VARCHAR(64)     NULL,  -- NULL = all event types
    enabled         TINYINT(1)      NOT NULL DEFAULT 1,
    created_at      TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_alert_subscriptions_recipient (recipient_id),
    KEY idx_alert_subscriptions_asset (asset_id),
    CONSTRAINT fk_alert_subscriptions_recipient FOREIGN KEY (recipient_id) REFERENCES alert_recipients (id) ON DELETE CASCADE,
    CONSTRAINT fk_alert_subscriptions_asset FOREIGN KEY (asset_id) REFERENCES protected_assets (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS alert_deliveries (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    alert_id        BIGINT UNSIGNED NOT NULL,
    recipient_id    BIGINT UNSIGNED NOT NULL,
    channel         ENUM('email')   NOT NULL DEFAULT 'email',
    status          ENUM('queued', 'sent', 'failed', 'bounced') NOT NULL DEFAULT 'queued',
    error           TEXT            NULL,
    sent_at         TIMESTAMP       NULL DEFAULT NULL,
    created_at      TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_alert_deliveries_alert (alert_id),
    -- supports the per-recipient 20/hr rate-limit query
    KEY idx_alert_deliveries_recipient_created (recipient_id, created_at),
    CONSTRAINT fk_alert_deliveries_alert FOREIGN KEY (alert_id) REFERENCES alerts (id) ON DELETE CASCADE,
    CONSTRAINT fk_alert_deliveries_recipient FOREIGN KEY (recipient_id) REFERENCES alert_recipients (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
