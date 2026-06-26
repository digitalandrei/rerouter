-- Blackhole / Null-Route become host-targeting mitigations:
--   * auto-detect the victim /32 (v4) or /128 (v6) from a flow rule's traffic
--     (the engine sets auto_target='flow_dst_host' on the action), OR
--   * a MANUAL prefix the operator types, bounded for blast-radius safety to
--     >= /8 (IPv4) and >= /29 (IPv6) via the new "min_len" on the prefix param.
--
-- Also: friendlier names (drop "Prefix"), and an IPv6 sibling for Blackhole so an
-- IPv6 victim swaps templates the same way Null-Route already does.

-- 1. Rename + add min_len bounds on the existing v4/v6 host templates.
UPDATE reroute_templates
   SET display_name = 'Null-Route',
       parameter_schema_json = '{"prefix":{"type":"cidr","label":"Destination (CIDR)","required":true,"min_len":8}}'
 WHERE name = 'null_route_prefix';

UPDATE reroute_templates
   SET display_name = 'Null-Route Withdraw',
       parameter_schema_json = '{"prefix":{"type":"cidr","label":"Destination (CIDR)","required":true,"min_len":8}}'
 WHERE name = 'null_route_withdraw';

UPDATE reroute_templates
   SET display_name = 'Null-Route (IPv6)',
       parameter_schema_json = '{"prefix":{"type":"cidr","family":"v6","label":"Destination (IPv6)","required":true,"min_len":29}}'
 WHERE name = 'null_route_prefix_v6';

UPDATE reroute_templates
   SET display_name = 'Null-Route Withdraw (IPv6)',
       parameter_schema_json = '{"prefix":{"type":"cidr","family":"v6","label":"Destination (IPv6)","required":true,"min_len":29}}'
 WHERE name = 'null_route_withdraw_v6';

UPDATE reroute_templates
   SET display_name = 'Blackhole (RTBH)',
       parameter_schema_json = '{"prefix":{"type":"cidr","label":"Destination (CIDR)","required":true,"min_len":8},"tag":{"type":"asn","label":"RTBH tag","required":false,"default":"666"}}'
 WHERE name = 'blackhole_prefix';

UPDATE reroute_templates
   SET display_name = 'Blackhole Withdraw',
       parameter_schema_json = '{"prefix":{"type":"cidr","label":"Destination (CIDR)","required":true,"min_len":8},"tag":{"type":"asn","label":"RTBH tag","required":false,"default":"666"}}'
 WHERE name = 'blackhole_withdraw';

-- 2. IPv6 Blackhole sibling pair (true RTBH: tagged Null0 -> redistributed into BGP
--    with the blackhole community by the router's pre-configured route-map).
INSERT IGNORE INTO reroute_templates
    (name, display_name, description, provider_type, mode, automatic_allowed,
     parameter_schema_json, plan_json, verification_json, enabled)
VALUES
    ('blackhole_prefix_v6',
     'Blackhole (RTBH, IPv6)',
     'IPv6 remote-triggered black hole (RTBH): add a tagged IPv6 Null0 static so the router redistributes the host into BGP with the blackhole community and UPSTREAM drops it. IPv6 sibling of blackhole_prefix.',
     'device_cli', 'ios_ssh', 0,
     '{"prefix":{"type":"cidr","family":"v6","label":"Destination (IPv6)","required":true,"min_len":29},"tag":{"type":"asn","label":"RTBH tag","required":false,"default":"666"}}',
     '{"transport":"ios_ssh","config_mode":true,"apply":["ipv6 route {prefix} Null0 tag {tag}"]}',
     '{"method":"ios_show","command":"show ipv6 route {prefix_net}","expect":"Null0"}',
     1),
    ('blackhole_withdraw_v6',
     'Blackhole Withdraw (IPv6)',
     'Withdraw an IPv6 RTBH black hole: remove the tagged IPv6 Null0 static. Rollback of blackhole_prefix_v6.',
     'device_cli', 'ios_ssh', 0,
     '{"prefix":{"type":"cidr","family":"v6","label":"Destination (IPv6)","required":true,"min_len":29},"tag":{"type":"asn","label":"RTBH tag","required":false,"default":"666"}}',
     '{"transport":"ios_ssh","config_mode":true,"apply":["no ipv6 route {prefix} Null0 tag {tag}"]}',
     '{"method":"ios_show","command":"show ipv6 route {prefix_net}","reject":"Null0"}',
     1);

-- 3. Wire rollback (v6 pair) + the v4 -> v6 family sibling links for Blackhole.
UPDATE reroute_templates t JOIN reroute_templates r ON r.name = 'blackhole_withdraw_v6'
    SET t.rollback_template_id = r.id WHERE t.name = 'blackhole_prefix_v6';
UPDATE reroute_templates t JOIN reroute_templates r ON r.name = 'blackhole_prefix_v6'
    SET t.rollback_template_id = r.id WHERE t.name = 'blackhole_withdraw_v6';
UPDATE reroute_templates t JOIN reroute_templates r ON r.name = 'blackhole_prefix_v6'
    SET t.v6_sibling_template_id = r.id WHERE t.name = 'blackhole_prefix';
UPDATE reroute_templates t JOIN reroute_templates r ON r.name = 'blackhole_withdraw_v6'
    SET t.v6_sibling_template_id = r.id WHERE t.name = 'blackhole_withdraw';
