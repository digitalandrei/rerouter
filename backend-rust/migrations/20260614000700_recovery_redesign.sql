-- Recovery redesign. Recovery persistence now mirrors the FIRING persistence by
-- family: SNMP rules recover after N consecutive samples back under the threshold,
-- flow rules after the metric stays back under for a time window.
--
-- - auto      : mirror the trigger — same consecutive_samples / duration_seconds,
--               staying on the recovered side of the FIRE threshold. No extra config.
-- - threshold : custom — a recovery_threshold_value (hysteresis band) plus an
--               optional recovery persistence override (recovery_consecutive_samples
--               for SNMP, recovery_window_seconds for flow); blank falls back to the
--               firing persistence.
-- - manual    : operator clears.
--
-- recovery_window_seconds already exists (now the flow recovery override). Add the
-- SNMP recovery override + the recovery streak counter on rule_states.
--
-- ADDITIVE migration; edits no existing migration.

ALTER TABLE rules
    ADD COLUMN recovery_consecutive_samples INT UNSIGNED NULL AFTER recovery_window_seconds;

ALTER TABLE rule_states
    ADD COLUMN recovery_consecutive INT UNSIGNED NOT NULL DEFAULT 0 AFTER recovery_first_at;
