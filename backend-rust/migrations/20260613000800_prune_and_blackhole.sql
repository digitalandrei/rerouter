-- De-scope the template catalog and make blackhole functional.
--
-- Drops the unimplemented provider templates (cloudflare_under_attack,
-- flowspec_drop) and the original non-functional blackhole_prefix (bgp_rtbh),
-- then re-seeds blackhole_prefix/blackhole_withdraw as a functional device_cli
-- RTBH pair. Distinct from null_route (local Null0): blackhole adds a *tagged*
-- Null0 static that the router's pre-configured route-map redistributes into BGP
-- with the blackhole community, so UPSTREAM drops the prefix (true RTBH).
--
-- None of the removed templates have been used (rule actions only accept
-- device_cli; no reroutes have executed), so the deletes are safe.

DELETE FROM reroute_templates WHERE name IN ('cloudflare_under_attack', 'flowspec_drop', 'blackhole_prefix');

-- blackhole_prefix (device_cli, high): tagged Null0 static -> upstream RTBH.
INSERT INTO reroute_templates
    (name, description, provider_type, mode, safety_level, automatic_allowed,
     manual_confirmation_required, parameter_schema_json, plan_json, verification_json,
     auto_expiry_seconds, enabled)
VALUES
    ('blackhole_prefix',
     'Remote-triggered black hole (RTBH): add a tagged Null0 static so the router redistributes the prefix into BGP with the blackhole community and UPSTREAM drops it. Requires the router''s RTBH redistribute route-map matching the tag. Drops ALL traffic to the prefix; auto-expires after 30 min unless renewed.',
     'device_cli', 'ios_ssh', 'high', 0, 1,
     '{"prefix":{"type":"cidr","label":"Prefix (CIDR)","required":true},"tag":{"type":"asn","label":"RTBH tag","required":false,"default":"666"}}',
     '{"transport":"ios_ssh","config_mode":true,"apply":["ip route {prefix_net} {prefix_mask} Null0 tag {tag}"]}',
     '{"method":"ios_show","command":"show ip route {prefix_net}","expect":"Null0"}',
     1800, 1);

-- blackhole_withdraw (device_cli, high): remove the tagged Null0 static.
INSERT INTO reroute_templates
    (name, description, provider_type, mode, safety_level, automatic_allowed,
     manual_confirmation_required, parameter_schema_json, plan_json, verification_json,
     auto_expiry_seconds, enabled)
VALUES
    ('blackhole_withdraw',
     'Withdraw an RTBH black hole: remove the tagged Null0 static so the prefix is no longer announced with the blackhole community.',
     'device_cli', 'ios_ssh', 'high', 0, 1,
     '{"prefix":{"type":"cidr","label":"Prefix (CIDR)","required":true},"tag":{"type":"asn","label":"RTBH tag","required":false,"default":"666"}}',
     '{"transport":"ios_ssh","config_mode":true,"apply":["no ip route {prefix_net} {prefix_mask} Null0 tag {tag}"]}',
     '{"method":"ios_show","command":"show ip route {prefix_net}","reject":"Null0"}',
     NULL, 1);

UPDATE reroute_templates t JOIN reroute_templates r ON r.name = 'blackhole_withdraw'
    SET t.rollback_template_id = r.id WHERE t.name = 'blackhole_prefix';
UPDATE reroute_templates t JOIN reroute_templates r ON r.name = 'blackhole_prefix'
    SET t.rollback_template_id = r.id WHERE t.name = 'blackhole_withdraw';
