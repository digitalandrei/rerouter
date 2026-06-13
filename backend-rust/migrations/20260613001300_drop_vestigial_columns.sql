-- Cleanup: remove vestigial schema left behind by earlier de-scoping, and fix a
-- stale template description. No live code reads any of these columns anymore.
--
--  * auto-expiry was removed (templates describe WHAT they do, not self-clearing
--    after N minutes) — drop reroute_templates.auto_expiry_seconds and the
--    reroutes.expires_at / cooldown_until columns it fed.
--  * the manual re-auth + typed-confirmation gate was removed with the safety_level
--    classification — drop reroute_templates.manual_confirmation_required and
--    sessions.reauth_at.
--  * null_route_prefix still carried the "Auto-expires after 30 min" wording that
--    migration 000900 only fixed for blackhole_prefix.

-- Correct the stale description (mirrors what 000900 did for blackhole_prefix).
UPDATE reroute_templates
SET description = 'Null-route (RTBH) a destination prefix on the router: ip route <net> <mask> Null0. Drops ALL traffic to the prefix until withdrawn.'
WHERE name = 'null_route_prefix';

-- Drop the auto-expiry / cooldown-column design on reroutes (cooldowns live in the
-- `cooldowns` table; expiry no longer exists).
ALTER TABLE reroutes DROP INDEX idx_reroutes_expires_at;
ALTER TABLE reroutes DROP COLUMN expires_at;
ALTER TABLE reroutes DROP COLUMN cooldown_until;

-- Drop the vestigial template gating columns (concept removed; always NULL/unused).
ALTER TABLE reroute_templates DROP COLUMN auto_expiry_seconds;
ALTER TABLE reroute_templates DROP COLUMN manual_confirmation_required;

-- Drop the re-auth timestamp (the re-auth gate it backed was removed).
ALTER TABLE sessions DROP COLUMN reauth_at;
