-- Safety primitives: locks block actions; cooldowns throttle repeats.
-- A crash leaves uncertain reroutes behind an auto_crash asset lock until
-- verified or acknowledged (see docs/state-recovery.md).

CREATE TABLE IF NOT EXISTS locks (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    scope       ENUM('global', 'asset', 'provider', 'prefix', 'template') NOT NULL,
    scope_ref   VARCHAR(191)    NULL,
    reason      TEXT            NULL,
    kind        ENUM('manual', 'auto_failed', 'auto_crash', 'auto_uncertain') NOT NULL,
    created_by  BIGINT UNSIGNED NULL,
    created_at  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    cleared_by  BIGINT UNSIGNED NULL,
    cleared_at  TIMESTAMP       NULL DEFAULT NULL,
    PRIMARY KEY (id),
    KEY idx_locks_scope_ref_cleared (scope, scope_ref, cleared_at),
    CONSTRAINT fk_locks_created_by FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT fk_locks_cleared_by FOREIGN KEY (cleared_by) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS cooldowns (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    scope       ENUM('rule', 'asset', 'prefix_provider', 'global') NOT NULL,
    scope_ref   VARCHAR(191)    NULL,
    until       TIMESTAMP       NOT NULL,
    reason      TEXT            NULL,
    created_at  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_cooldowns_scope_ref_until (scope, scope_ref, until)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
