-- Ordered mitigation bundles (plan 015; implements roadmap item 14.07 / audit
-- SPEC-13).
--
-- A BUNDLE is one authorized activation of one rule's ordered action set: the
-- operator previewed N actions and confirmed them once, so the N sibling
-- reroutes are one decision, not N independent ones.
--
-- Without a durable bundle identity the guard's cooldown fallback
-- (`MAX(reroutes.started_at)` per rule / per device) counts the bundle's own
-- first sibling as "a recent action" and blocks the rest, so a 14-action
-- mitigation applied roughly one action and stopped. `bundle_id` lets the guard
-- exclude ONLY previously authorized siblings of the same bundle while leaving
-- every unrelated device/rule cooldown intact.
--
-- The bundle row is also the async job record: the apply endpoint returns its id
-- immediately instead of holding an HTTP request open across ~28 SSH sessions.

CREATE TABLE IF NOT EXISTS reroute_bundles (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    rule_id             BIGINT UNSIGNED NULL,
    rule_event_id       BIGINT UNSIGNED NULL,
    -- Who authorized it. 'manual' = operator apply, 'automatic' = rule activation.
    trigger_type        ENUM('automatic', 'manual') NOT NULL,
    triggered_by_user_id BIGINT UNSIGNED NULL,
    reason              TEXT            NULL,
    -- planned  : admitted, nothing executed yet
    -- running  : at least one sibling has started
    -- succeeded: every sibling succeeded
    -- aborted  : stopped at a non-success; applied siblings left in place
    -- compensating / compensated: rolling back / rolled back applied siblings
    -- compensation_blocked: a device lock (uncertain sibling) stopped compensation
    --            — siblings remain applied and an admin must intervene
    -- failed   : refused before any sibling executed
    state               ENUM('planned', 'running', 'succeeded', 'aborted',
                             'compensating', 'compensated',
                             'compensation_blocked', 'failed')
                        NOT NULL DEFAULT 'planned',
    -- What to do at the first non-success. `continue` preserves the historical
    -- best-effort fan-out; `abort_and_compensate` is the safe default for new
    -- operator bundles (see plan 015).
    failure_policy      ENUM('abort_and_compensate', 'abort', 'continue')
                        NOT NULL DEFAULT 'abort_and_compensate',
    total_actions       INT UNSIGNED    NOT NULL DEFAULT 0,
    -- Siblings that reached a terminal state, successful or not.
    completed_actions   INT UNSIGNED    NOT NULL DEFAULT 0,
    -- Free-text summary of why the bundle stopped, shown in the UI and alerts.
    failure_reason      TEXT            NULL,
    started_at          TIMESTAMP       NULL DEFAULT NULL,
    finished_at         TIMESTAMP       NULL DEFAULT NULL,
    created_at          TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_reroute_bundles_state (state),
    KEY idx_reroute_bundles_rule (rule_id, created_at),
    CONSTRAINT fk_reroute_bundles_rule FOREIGN KEY (rule_id) REFERENCES rules (id) ON DELETE SET NULL,
    CONSTRAINT fk_reroute_bundles_user FOREIGN KEY (triggered_by_user_id) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Sibling membership + intended order. `bundle_position` mirrors the originating
-- `rule_actions.position` so the durable history records the order actually used,
-- independently of later edits to the rule.
--
-- Guarded against information_schema: MySQL DDL auto-commits, so a column from a
-- partially-applied run must not be re-added.
SET @col := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'reroutes'
      AND column_name = 'bundle_id');
SET @ddl := IF(@col = 0,
    'ALTER TABLE reroutes ADD COLUMN bundle_id BIGINT UNSIGNED NULL AFTER rule_id',
    'DO 0');
PREPARE s FROM @ddl; EXECUTE s; DEALLOCATE PREPARE s;

SET @col := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'reroutes'
      AND column_name = 'bundle_position');
SET @ddl := IF(@col = 0,
    'ALTER TABLE reroutes ADD COLUMN bundle_position INT UNSIGNED NULL AFTER bundle_id',
    'DO 0');
PREPARE s FROM @ddl; EXECUTE s; DEALLOCATE PREPARE s;

-- The guard's cooldown fallback filters on (rule_id, bundle_id, started_at) and
-- (device_id, bundle_id, started_at); compensation looks siblings up by bundle.
SET @idx := (SELECT COUNT(*) FROM information_schema.statistics
    WHERE table_schema = DATABASE() AND table_name = 'reroutes'
      AND index_name = 'idx_reroutes_bundle');
SET @ddl := IF(@idx = 0,
    'ALTER TABLE reroutes ADD KEY idx_reroutes_bundle (bundle_id, bundle_position)',
    'DO 0');
PREPARE s FROM @ddl; EXECUTE s; DEALLOCATE PREPARE s;

-- FK last, so it applies to the column added above in this same migration.
SET @fk := (SELECT COUNT(*) FROM information_schema.table_constraints
    WHERE table_schema = DATABASE() AND table_name = 'reroutes'
      AND constraint_name = 'fk_reroutes_bundle');
SET @ddl := IF(@fk = 0,
    'ALTER TABLE reroutes ADD CONSTRAINT fk_reroutes_bundle FOREIGN KEY (bundle_id) REFERENCES reroute_bundles (id) ON DELETE SET NULL',
    'DO 0');
PREPARE s FROM @ddl; EXECUTE s; DEALLOCATE PREPARE s;
