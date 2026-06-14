-- Human-friendly display names for templates. `name` stays the stable machine
-- identifier (used in code, the command allowlist, and rule_actions); display_name
-- is what the UI shows. Nullable so a template without one falls back to `name`.

ALTER TABLE reroute_templates ADD COLUMN display_name VARCHAR(128) NULL AFTER name;

UPDATE reroute_templates SET display_name = 'Null-Route Prefix'       WHERE name = 'null_route_prefix';
UPDATE reroute_templates SET display_name = 'Null-Route Withdraw'     WHERE name = 'null_route_withdraw';
UPDATE reroute_templates SET display_name = 'Blackhole Prefix (RTBH)' WHERE name = 'blackhole_prefix';
UPDATE reroute_templates SET display_name = 'Blackhole Withdraw'      WHERE name = 'blackhole_withdraw';
UPDATE reroute_templates SET display_name = 'BGP Session Enable'      WHERE name = 'bgp_session_enable';
UPDATE reroute_templates SET display_name = 'BGP Session Disable'     WHERE name = 'bgp_session_disable';
