-- Remove template-level auto-expiry entirely. A mitigation's lifecycle is
-- decided by the RULE / operator, not by the command template (no self-clearing
-- after N minutes). Clears the only template that had it (blackhole_prefix) and
-- drops the now-stale "auto-expires after 30 min" wording from its description.
UPDATE reroute_templates SET auto_expiry_seconds = NULL WHERE auto_expiry_seconds IS NOT NULL;

UPDATE reroute_templates
   SET description = 'Remote-triggered black hole (RTBH): add a tagged Null0 static so the router redistributes the prefix into BGP with the blackhole community and UPSTREAM drops it. Requires the router''s RTBH redistribute route-map matching the tag. Drops ALL traffic to the prefix.'
 WHERE name = 'blackhole_prefix';
