-- Friendly display names for the device-CLI templates that were seeded without
-- one (20260614000200 only named the first six). `name` stays the stable machine
-- identifier (code, command allowlist, rule_actions); display_name is what the UI
-- shows. Style matches the existing names: Title Case, plain words, a parenthetical
-- only to flag a disruptive action.

UPDATE reroute_templates SET display_name = 'BGP Advertise to Upstream'    WHERE name = 'bgp_advertise_add';
UPDATE reroute_templates SET display_name = 'BGP Advertise Withdraw'       WHERE name = 'bgp_advertise_remove';
UPDATE reroute_templates SET display_name = 'Interface MSS Clamp'          WHERE name = 'iface_tcp_adjust_mss';
UPDATE reroute_templates SET display_name = 'Interface MSS Clamp Remove'   WHERE name = 'iface_tcp_adjust_mss_remove';
UPDATE reroute_templates SET display_name = 'Interface Shutdown (Disruptive)' WHERE name = 'iface_shutdown';
UPDATE reroute_templates SET display_name = 'Interface No-Shutdown'        WHERE name = 'iface_no_shutdown';
