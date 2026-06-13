-- Device-CLI reroute templates (Cisco IOS over SSH) — the v1 mitigation path.
-- Extends the existing template/reroute engine with a device_cli provider and
-- DEVICE-scoped reroutes/locks/cooldowns (the doctrine's asset paths are
-- unchanged; this adds device targeting for CLI actions). Commands remain
-- parameterized templates — no free-text execution.

-- 1. New provider type for IOS-over-SSH actions.
ALTER TABLE reroute_templates
    MODIFY COLUMN provider_type
        ENUM('cloudflare', 'bgp_rtbh', 'flowspec', 'scrubber', 'device_cli') NOT NULL;

-- 2. Reroutes can target a DEVICE (not just an asset). asset_id becomes optional;
--    device_id is set for device_cli actions.
ALTER TABLE reroutes
    MODIFY COLUMN asset_id BIGINT UNSIGNED NULL,
    ADD COLUMN device_id BIGINT UNSIGNED NULL AFTER asset_id,
    ADD KEY idx_reroutes_device_state (device_id, state),
    ADD CONSTRAINT fk_reroutes_device FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE;

-- 3. Device-scoped safety locks + cooldowns (running action / uncertainty / crash
--    recovery all lock the device; cooldown is per-device).
ALTER TABLE locks
    MODIFY COLUMN scope ENUM('global', 'asset', 'provider', 'prefix', 'template', 'device') NOT NULL;
ALTER TABLE cooldowns
    MODIFY COLUMN scope ENUM('rule', 'asset', 'prefix_provider', 'global', 'device') NOT NULL;

-- 4. Seed the device-CLI templates. Idempotent (INSERT IGNORE on unique name).
--    parameter_schema_json: { "<name>": {"type":"ip|cidr|asn","label":..,"required":..,"source":..} }
--    plan_json:            { "transport":"ios_ssh", "config_mode":true, "apply":[ "<cmd with {param}>" ] }
--    verification_json:    { "method":"ios_show", "command":.., "expect":<substr present>, "reject":<substr absent> }
--    A cidr param `X` also exposes {X_net} and {X_mask} to the renderer.

-- null_route_prefix (medium): blackhole a destination prefix to Null0. Auto-expires.
INSERT IGNORE INTO reroute_templates
    (name, description, provider_type, mode, safety_level, automatic_allowed,
     manual_confirmation_required, parameter_schema_json, plan_json, verification_json,
     auto_expiry_seconds, enabled)
VALUES
    ('null_route_prefix',
     'Null-route (RTBH) a destination prefix on the router: ip route <net> <mask> Null0. Drops ALL traffic to the prefix. Auto-expires after 30 min unless renewed.',
     'device_cli', 'ios_ssh', 'medium', 0, 1,
     '{"prefix":{"type":"cidr","label":"Prefix (CIDR)","required":true}}',
     '{"transport":"ios_ssh","config_mode":true,"apply":["ip route {prefix_net} {prefix_mask} Null0 name RRT-BLACKHOLE"]}',
     '{"method":"ios_show","command":"show ip route {prefix_net}","expect":"Null0"}',
     1800, 1);

-- null_route_withdraw (medium): remove the Null0 route (rollback of the above).
INSERT IGNORE INTO reroute_templates
    (name, description, provider_type, mode, safety_level, automatic_allowed,
     manual_confirmation_required, parameter_schema_json, plan_json, verification_json,
     auto_expiry_seconds, enabled)
VALUES
    ('null_route_withdraw',
     'Withdraw a null-route: no ip route <net> <mask> Null0. Restores normal forwarding to the prefix.',
     'device_cli', 'ios_ssh', 'medium', 0, 1,
     '{"prefix":{"type":"cidr","label":"Prefix (CIDR)","required":true}}',
     '{"transport":"ios_ssh","config_mode":true,"apply":["no ip route {prefix_net} {prefix_mask} Null0"]}',
     '{"method":"ios_show","command":"show ip route {prefix_net}","reject":"Null0"}',
     NULL, 1);

-- bgp_session_enable (high): no shutdown a neighbor — start announcing to a
-- scrubber (divert). High safety: typed confirmation + re-auth.
INSERT IGNORE INTO reroute_templates
    (name, description, provider_type, mode, safety_level, automatic_allowed,
     manual_confirmation_required, parameter_schema_json, plan_json, verification_json,
     auto_expiry_seconds, enabled)
VALUES
    ('bgp_session_enable',
     'Enable (no shutdown) a BGP neighbor — e.g. bring up the GRE scrubber session so routes are announced and traffic diverts.',
     'device_cli', 'ios_ssh', 'high', 0, 1,
     '{"neighbor_ip":{"type":"ip","label":"Neighbor IP","required":true,"source":"bgp_peer"},"local_asn":{"type":"asn","label":"Local AS","required":true,"source":"bgp_local_as"}}',
     '{"transport":"ios_ssh","config_mode":true,"apply":["router bgp {local_asn}","no neighbor {neighbor_ip} shutdown"]}',
     '{"method":"ios_show","command":"show ip bgp neighbors {neighbor_ip}","expect":"BGP state","reject":"Administratively shut"}',
     NULL, 1);

-- bgp_session_disable (high): shutdown a neighbor — stop announcing / stop the
-- diversion (rollback of enable).
INSERT IGNORE INTO reroute_templates
    (name, description, provider_type, mode, safety_level, automatic_allowed,
     manual_confirmation_required, parameter_schema_json, plan_json, verification_json,
     auto_expiry_seconds, enabled)
VALUES
    ('bgp_session_disable',
     'Disable (shutdown) a BGP neighbor — e.g. tear down the GRE scrubber session so the diversion stops.',
     'device_cli', 'ios_ssh', 'high', 0, 1,
     '{"neighbor_ip":{"type":"ip","label":"Neighbor IP","required":true,"source":"bgp_peer"},"local_asn":{"type":"asn","label":"Local AS","required":true,"source":"bgp_local_as"}}',
     '{"transport":"ios_ssh","config_mode":true,"apply":["router bgp {local_asn}","neighbor {neighbor_ip} shutdown"]}',
     '{"method":"ios_show","command":"show ip bgp neighbors {neighbor_ip}","expect":"Administratively shut"}',
     NULL, 1);

-- 5. Wire each disruptive template to its rollback (self-referential).
UPDATE reroute_templates t
    JOIN reroute_templates r ON r.name = 'null_route_withdraw'
    SET t.rollback_template_id = r.id
    WHERE t.name = 'null_route_prefix';
UPDATE reroute_templates t
    JOIN reroute_templates r ON r.name = 'null_route_prefix'
    SET t.rollback_template_id = r.id
    WHERE t.name = 'null_route_withdraw';
UPDATE reroute_templates t
    JOIN reroute_templates r ON r.name = 'bgp_session_disable'
    SET t.rollback_template_id = r.id
    WHERE t.name = 'bgp_session_enable';
UPDATE reroute_templates t
    JOIN reroute_templates r ON r.name = 'bgp_session_enable'
    SET t.rollback_template_id = r.id
    WHERE t.name = 'bgp_session_disable';
