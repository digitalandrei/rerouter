-- An evaluator tick is not another telemetry observation. Persist consumed
-- identities across controller restarts and keep aggregate member cursors.
SET @rrt_exists := (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='rule_states' AND column_name='last_observation_json');
SET @rrt_ddl := IF(@rrt_exists=0, 'ALTER TABLE rule_states ADD COLUMN last_observation_json JSON NULL, ADD COLUMN last_observation_at DATETIME(6) NULL', 'DO 0');
PREPARE rrt_migration FROM @rrt_ddl; EXECUTE rrt_migration; DEALLOCATE PREPARE rrt_migration;

-- Old streaks were counted by evaluations and cannot be trusted as evidence.
-- Preserve firing incidents and their mutations, but restart unproven progress.
UPDATE rule_states SET current_state=IF(current_state='matching','clear',current_state),
    first_matched_at=NULL, consecutive_match_count=0,
    recovery_first_at=NULL, recovery_consecutive=0;
