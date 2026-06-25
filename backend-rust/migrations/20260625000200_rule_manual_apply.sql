-- Per-rule opt-in: may an operator MANUALLY APPLY this rule's configured actions
-- from a firing alert (the supervised middle ground between alert-only and
-- unattended automatic execution)?
--
-- Independent of `automatic_reroute_enabled` (which is hands-off auto-execution
-- on the firing edge). Manual apply runs through the SAME gated executor as a
-- manual reroute: blocked in observe mode (returns the would-run plan), requires
-- the `trigger_manual_reroute` permission, and respects device locks, cooldowns,
-- the global maintenance lock and the global rate limit. It is NOT gated by the
-- global automatic master switch — it is a deliberate operator action.
--
-- Defaults OFF (opt-in), mirroring `automatic_reroute_enabled`, so the doctrine
-- "prefer doing nothing" default is preserved: a new rule alerts only.

ALTER TABLE rules
    ADD COLUMN manual_apply_enabled TINYINT(1) NOT NULL DEFAULT 0
    AFTER automatic_reroute_enabled;
