-- Flow auto-target: derive a null-route/blackhole HOST from flow data at fire /
-- apply time, instead of hard-coding a prefix. For a flow rule (e.g. TCP dport
-- 443) the controller finds the top attacked destination IP in the matching flows
-- and null-routes it as a /32 (IPv4) or /128 (IPv6).
--
-- Safety model (see docs/reroute-engine.md, docs/flow-telemetry.md):
--   * the resolved host MUST sit inside one of the device's announced prefixes
--     (device_bgp_networks) — we only ever black-hole our own space;
--   * LOW flow-sampling confidence blocks AUTOMATIC execution (doctrine); a manual
--     apply still proceeds (the operator sees and confirms the resolved IP);
--   * the resolved host is rendered into the would-run plan before anything runs.

-- 1. rule_actions.auto_target: NULL = static prefix (current behaviour).
--    'flow_dst_host' = resolve the top attacked destination IP from the rule's
--    flows. Only valid on a flow rule + a host-route template (enforced in the API).
ALTER TABLE rule_actions
    ADD COLUMN auto_target VARCHAR(24) NULL AFTER params_json;

-- 2. Family sibling: when an auto-target resolves to an IPv6 victim, the engine
--    swaps the IPv4 host-route template for its IPv6 sibling. Same self-referential
--    pattern as rollback_template_id (plain column, wired by name below).
ALTER TABLE reroute_templates
    ADD COLUMN v6_sibling_template_id BIGINT UNSIGNED NULL AFTER rollback_template_id;

-- 3. IPv6 null-route templates (siblings of null_route_prefix / _withdraw). IPv6
--    uses `ipv6 route <pfx>/<len> Null0` (prefix/len form, no dotted mask), so it
--    needs its own template + the renderer's family-aware cidr handling. The cidr
--    param is pinned to family "v6" so a v4 value can't be rendered here.
INSERT IGNORE INTO reroute_templates
    (name, display_name, description, provider_type, mode, automatic_allowed,
     parameter_schema_json, plan_json, verification_json, enabled)
VALUES
    ('null_route_prefix_v6',
     'Null-Route Prefix (IPv6)',
     'Install a local IPv6 Null0 static route for a prefix or /128 host (local RTBH; drop at this router). IPv6 sibling of null_route_prefix.',
     'device_cli', 'ios_ssh', 0,
     '{"prefix":{"type":"cidr","family":"v6","label":"IPv6 prefix / host","required":true}}',
     '{"transport":"ios_ssh","config_mode":true,"apply":["ipv6 route {prefix} Null0 name RRT-BLACKHOLE"]}',
     '{"method":"ios_show","command":"show ipv6 route {prefix_net}","expect":"Null0"}',
     1),
    ('null_route_withdraw_v6',
     'Null-Route Withdraw (IPv6)',
     'Remove an IPv6 Null0 static route (rollback of null_route_prefix_v6).',
     'device_cli', 'ios_ssh', 0,
     '{"prefix":{"type":"cidr","family":"v6","label":"IPv6 prefix / host","required":true}}',
     '{"transport":"ios_ssh","config_mode":true,"apply":["no ipv6 route {prefix} Null0"]}',
     '{"method":"ios_show","command":"show ipv6 route {prefix_net}","reject":"Null0"}',
     1);

-- 4. Wire rollback (v6 pair) and the v4 -> v6 family sibling links.
UPDATE reroute_templates t JOIN reroute_templates r ON r.name = 'null_route_withdraw_v6'
    SET t.rollback_template_id = r.id WHERE t.name = 'null_route_prefix_v6';
UPDATE reroute_templates t JOIN reroute_templates r ON r.name = 'null_route_prefix_v6'
    SET t.rollback_template_id = r.id WHERE t.name = 'null_route_withdraw_v6';
UPDATE reroute_templates t JOIN reroute_templates r ON r.name = 'null_route_prefix_v6'
    SET t.v6_sibling_template_id = r.id WHERE t.name = 'null_route_prefix';
UPDATE reroute_templates t JOIN reroute_templates r ON r.name = 'null_route_withdraw_v6'
    SET t.v6_sibling_template_id = r.id WHERE t.name = 'null_route_withdraw';
