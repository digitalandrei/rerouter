-- Saved definitions may be incomplete drafts (invalid or missing policy
-- parameters), but their template/device identities remain real foreign keys.
-- Run preparation remains strict and requires the complete set to be ready.

ALTER TABLE reroute_bundles
    ADD COLUMN parent_bundle_id BIGINT UNSIGNED NULL AFTER id,
    ADD COLUMN lifecycle_state ENUM('inactive','active','recovery_scheduled',
        'recovery_claimed','recovery_running','recovery_blocked')
        NOT NULL DEFAULT 'inactive' AFTER state,
    ADD COLUMN remaining_mutations INT UNSIGNED NOT NULL DEFAULT 0 AFTER completed_actions,
    ADD COLUMN recovery_deadline DATETIME NULL AFTER interrupted_at,
    ADD COLUMN recovery_claim_token VARCHAR(64) NULL AFTER recovery_deadline,
    ADD COLUMN recovery_claimed_at DATETIME NULL AFTER recovery_claim_token,
    ADD COLUMN recovery_started_at DATETIME NULL AFTER recovery_claimed_at,
    ADD COLUMN recovery_bundle_id BIGINT UNSIGNED NULL AFTER recovery_started_at,
    ADD COLUMN automatic_recovery_cancelled_at DATETIME NULL AFTER recovery_bundle_id,
    ADD COLUMN automatic_recovery_cancelled_by BIGINT UNSIGNED NULL AFTER automatic_recovery_cancelled_at,
    ADD COLUMN automatic_recovery_block_reason TEXT NULL AFTER automatic_recovery_cancelled_by,
    ADD KEY idx_bundle_lifecycle (lifecycle_state, recovery_deadline),
    ADD KEY idx_bundle_parent (parent_bundle_id),
    ADD CONSTRAINT fk_bundle_parent FOREIGN KEY (parent_bundle_id) REFERENCES reroute_bundles(id) ON DELETE RESTRICT,
    ADD CONSTRAINT fk_bundle_recovery_bundle FOREIGN KEY (recovery_bundle_id) REFERENCES reroute_bundles(id) ON DELETE RESTRICT,
    ADD CONSTRAINT fk_bundle_takeover_actor FOREIGN KEY (automatic_recovery_cancelled_by) REFERENCES users(id) ON DELETE RESTRICT;

-- Preserve existing behaviour while making the recovery action independently
-- controllable from its threshold/condition.
ALTER TABLE rules
    ADD COLUMN automatic_revert_enabled TINYINT(1) NOT NULL DEFAULT 0
        AFTER automatic_reroute_enabled;
UPDATE rules SET automatic_revert_enabled = (recovery_mode IN ('auto','threshold'));

ALTER TABLE rule_states
    MODIFY current_state ENUM('clear','matching','firing','recovered_awaiting_revert')
        NOT NULL DEFAULT 'clear';

-- Derive existing lifecycle from durable ownership rather than terminal result.
UPDATE reroute_bundles b
LEFT JOIN (
    SELECT original.bundle_id, COUNT(*) AS remaining
    FROM reroutes original
    WHERE original.rollback_of_reroute_id IS NULL
      AND original.mutation_effect IN ('changed','unknown')
      AND NOT EXISTS (
          SELECT 1 FROM reroutes inverse
          WHERE inverse.rollback_of_reroute_id = original.id
            AND inverse.state = 'succeeded'
            AND inverse.mutation_effect IN ('changed','noop')
      )
    GROUP BY original.bundle_id
) ownership ON ownership.bundle_id = b.id
SET b.remaining_mutations = COALESCE(ownership.remaining, 0),
    b.lifecycle_state = CASE
        WHEN COALESCE(ownership.remaining, 0) > 0 THEN 'active'
        ELSE 'inactive'
    END;
