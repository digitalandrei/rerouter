-- Per-rule recovery settle window. The "clear after settle window" used by
-- recovery_mode = auto (and the hold time for recovery_mode = threshold) was a
-- single global value (detection.hysteresis_seconds). Make it per-rule, with the
-- global value as the fallback when NULL. See docs/detection-engine.md.
--
-- ADDITIVE migration (one nullable column); edits no existing migration.

ALTER TABLE rules
    ADD COLUMN recovery_window_seconds INT UNSIGNED NULL AFTER recovery_threshold_value;
