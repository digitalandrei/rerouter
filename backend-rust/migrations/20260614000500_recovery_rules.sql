-- Per-rule recovery policy (how a firing rule clears) + recovery tracking state.
-- See docs/detection-engine.md.
--
-- recovery_mode:
--   'auto'      (default) — clear after the global hysteresis settle window once
--                the firing condition stops matching (the existing behaviour).
--   'threshold' — clear when the metric crosses back to the recovered side of
--                recovery_threshold_value (a hysteresis band: e.g. fire above
--                1 Gbps, recover below 800 Mbps) and holds there for the settle
--                window. recovery_threshold_value defaults to the fire threshold.
--   'manual'    — never auto-clears; an operator clears it (POST /api/rules/{id}/clear).
--
-- ADDITIVE migration (new nullable columns); edits no existing migration.

ALTER TABLE rules
    ADD COLUMN recovery_mode ENUM('auto','threshold','manual') NOT NULL DEFAULT 'auto' AFTER consecutive_samples,
    ADD COLUMN recovery_threshold_value DOUBLE NULL AFTER recovery_mode;

-- Tracks when the recovered-side condition started holding (threshold mode), so
-- the settle window can elapse. NULL = not currently recovering.
ALTER TABLE rule_states
    ADD COLUMN recovery_first_at TIMESTAMP NULL DEFAULT NULL AFTER last_matched_at;
