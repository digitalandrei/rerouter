-- Inventory DRIFT detection + automatic disarm of automatic execution.
--
-- Why: routing inventory (outbound prefix-lists, route-maps, announced space) is
-- re-read by SSH discovery, but a change made on the router between two runs was
-- only ever noticed by the executor's fire-time re-validation — i.e. DURING an
-- attack, with the rule looking healthy and armed right up to that moment.
--
-- These columns record the result of a read-only post-discovery audit:
--
--   rule_actions.inventory_state       'ok' until a CONCLUSIVE discovery run
--                                      proves the stored parameter no longer
--                                      validates; 'drifted' afterwards.
--   rule_actions.inventory_drift_reason the concrete validator message, shown to
--                                      the operator (never a generic string).
--   rule_actions.inventory_checked_at  when the audit last RAN for this action
--                                      (set on pass and on fail alike), so
--                                      "never audited" is distinguishable from
--                                      "audited and clean".
--   rules.auto_disarmed_at/_reason     why automatic execution was switched off.
--                                      Deliberately NOT cleared by self-heal:
--                                      re-arming is a human act (global enable +
--                                      step-up re-auth), and until it happens the
--                                      operator must still be able to see why the
--                                      rule stopped acting on its own.
--
-- An inconclusive read (denied / failed / empty-but-unproven) never writes any of
-- these: whoever can make a router return an empty read must not be able to
-- disarm the operator's mitigations.
--
-- Guarded against information_schema so the migration is idempotent (MySQL DDL
-- auto-commits, so a column from a partially-applied run is not re-added).
-- Valid on MariaDB and on MySQL 8.4 (the one deployment that runs it).

SET @col := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'rule_actions'
      AND column_name = 'inventory_state');
SET @ddl := IF(@col = 0,
    'ALTER TABLE rule_actions ADD COLUMN inventory_state ENUM(''ok'',''drifted'') NOT NULL DEFAULT ''ok''',
    'DO 0');
PREPARE s FROM @ddl; EXECUTE s; DEALLOCATE PREPARE s;

SET @col := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'rule_actions'
      AND column_name = 'inventory_drift_reason');
SET @ddl := IF(@col = 0,
    'ALTER TABLE rule_actions ADD COLUMN inventory_drift_reason VARCHAR(500) NULL',
    'DO 0');
PREPARE s FROM @ddl; EXECUTE s; DEALLOCATE PREPARE s;

SET @col := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'rule_actions'
      AND column_name = 'inventory_checked_at');
SET @ddl := IF(@col = 0,
    'ALTER TABLE rule_actions ADD COLUMN inventory_checked_at DATETIME NULL',
    'DO 0');
PREPARE s FROM @ddl; EXECUTE s; DEALLOCATE PREPARE s;

SET @col := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'rules'
      AND column_name = 'auto_disarmed_at');
SET @ddl := IF(@col = 0,
    'ALTER TABLE rules ADD COLUMN auto_disarmed_at DATETIME NULL',
    'DO 0');
PREPARE s FROM @ddl; EXECUTE s; DEALLOCATE PREPARE s;

SET @col := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'rules'
      AND column_name = 'auto_disarmed_reason');
SET @ddl := IF(@col = 0,
    'ALTER TABLE rules ADD COLUMN auto_disarmed_reason VARCHAR(500) NULL',
    'DO 0');
PREPARE s FROM @ddl; EXECUTE s; DEALLOCATE PREPARE s;

-- The audit sweeps by device; the existing index is on rule_id only.
SET @idx := (SELECT COUNT(*) FROM information_schema.statistics
    WHERE table_schema = DATABASE() AND table_name = 'rule_actions'
      AND index_name = 'idx_rule_actions_device');
SET @ddl := IF(@idx = 0,
    'CREATE INDEX idx_rule_actions_device ON rule_actions (device_id, enabled)',
    'DO 0');
PREPARE s FROM @ddl; EXECUTE s; DEALLOCATE PREPARE s;
