-- Append-only audit log + global key/value settings.
-- Audit everything; never delete audit_logs automatically without an explicit
-- retention decision (see docs/database.md).

CREATE TABLE IF NOT EXISTS audit_logs (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    actor_type      ENUM('user', 'controller', 'system') NOT NULL,
    actor_user_id   BIGINT UNSIGNED NULL,
    event_type      VARCHAR(64)     NOT NULL,
    entity_type     VARCHAR(64)     NULL,
    entity_id       BIGINT UNSIGNED NULL,
    asset_id        BIGINT UNSIGNED NULL,
    reroute_id      BIGINT UNSIGNED NULL,
    message         TEXT            NULL,
    before_json     JSON            NULL,
    after_json      JSON            NULL,
    ip_address      VARCHAR(45)     NULL,   -- real client IP (CF-Connecting-IP)
    user_agent      VARCHAR(512)    NULL,
    created_at      TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_audit_logs_event_created (event_type, created_at),
    KEY idx_audit_logs_actor_user (actor_user_id),
    KEY idx_audit_logs_asset (asset_id),
    KEY idx_audit_logs_reroute (reroute_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS system_settings (
    `key`       VARCHAR(128)    NOT NULL,
    `value`     VARCHAR(512)    NOT NULL,
    updated_by  BIGINT UNSIGNED NULL,
    updated_at  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- SAFETY: the controller ships in 'observe' mode — read-only / alert-only.
-- NO reroute executes (automatic or manual) until an admin flips
-- operating_mode to 'enforce' from /settings (audited). While observing, a
-- fired rule alerts with the rendered plan of the actions that WOULD have run.
-- automatic_actions_enabled additionally gates automatic reroutes in enforce
-- mode. Idempotent — never flips an existing value back.
INSERT IGNORE INTO system_settings (`key`, `value`) VALUES
    ('operating_mode', 'observe'),
    ('automatic_actions_enabled', 'false'),
    ('global_maintenance_lock', 'false');
