-- Remove the safety-level classification entirely. This is an in-house tool;
-- operators know the blast radius. The only behaviour the level still gated — a
-- re-auth + typed-confirmation prompt on manual "high" triggers — is dropped too.
-- Manual triggers now need only the trigger_manual_reroute permission + enforce
-- mode; automatic execution remains the rule's call. Every other guardrail
-- (observe default, allowlisted templates, device locks, cooldowns, audit) stays.
ALTER TABLE reroutes DROP COLUMN safety_level;
ALTER TABLE reroute_templates DROP COLUMN safety_level;
