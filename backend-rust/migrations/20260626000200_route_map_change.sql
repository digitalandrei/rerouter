-- Route-Map Change: an advanced, manual, reversible mitigation that swaps the
-- route-map applied to one or more BGP neighbors (in/out) — e.g. withdraw an
-- announcement from peer A and advertise it on peer B by changing route-maps.
--
-- Doctrine stays intact: this is a TEMPLATE with typed params. The route-map name
-- is constrained to maps DISCOVERED on the router (device_route_maps), not free
-- text — "we detect route maps and suggest them". Multiple peers in one mitigation
-- are an ordered bundle of per-peer actions (each verified/reverted on its own).

-- 1. Per-neighbor CURRENT route-map assignments (discovered), so we can suggest
--    and snapshot the prior map for reversal.
ALTER TABLE device_bgp_peers
    ADD COLUMN in_route_map  VARCHAR(191) NULL,
    ADD COLUMN out_route_map VARCHAR(191) NULL;

-- 2. Catalog of route-map names discovered on each device (the picker source).
CREATE TABLE IF NOT EXISTS device_route_maps (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    device_id           BIGINT UNSIGNED NOT NULL,
    name                VARCHAR(191)    NOT NULL,
    last_discovered_at  TIMESTAMP       NULL DEFAULT NULL,
    created_at          TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_device_route_map (device_id, name),
    KEY idx_device_route_maps_device (device_id),
    CONSTRAINT fk_device_route_maps_device FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. Templates. `direction` is constrained to in/out via the new "enum" support in
--    the renderer; `route_map` is a restricted string (no whitespace) further
--    validated against device_route_maps by the API. The soft-clear is in
--    exec_after (privileged EXEC, outside the config block).
INSERT IGNORE INTO reroute_templates
    (name, display_name, description, provider_type, mode, automatic_allowed,
     parameter_schema_json, plan_json, verification_json, enabled)
VALUES
    ('bgp_route_map_set',
     'Route-Map Change',
     'Apply a route-map to a BGP neighbor in a direction (neighbor <ip> route-map <name> in|out), then soft-clear that direction. The route-map is chosen from maps discovered on the router. Advanced/manual; reversible (the prior map is restored on revert). Fan out across several peers in one mitigation to shift policy between upstreams.',
     'device_cli', 'ios_ssh', 0,
     '{"local_asn":{"type":"asn","label":"Local AS","required":true,"source":"bgp_local_as"},"neighbor_ip":{"type":"ip","label":"Neighbor","required":true,"source":"bgp_peer"},"route_map":{"type":"string","label":"Route-map","required":true,"source":"route_map"},"direction":{"type":"string","label":"Direction","required":true,"enum":["in","out"],"default":"out","source":"bgp_direction"}}',
     '{"transport":"ios_ssh","config_mode":true,"apply":["router bgp {local_asn}","neighbor {neighbor_ip} route-map {route_map} {direction}"],"exec_after":["clear ip bgp {neighbor_ip} soft {direction}"]}',
     '{"method":"ios_show","command":"show running-config | include neighbor {neighbor_ip} route-map","expect":"{route_map} {direction}"}',
     1),
    ('bgp_route_map_unset',
     'Route-Map Change (Remove)',
     'Remove a route-map from a BGP neighbor in a direction (no neighbor <ip> route-map <name> in|out), then soft-clear. Used to revert a Route-Map Change when the neighbor had no prior map.',
     'device_cli', 'ios_ssh', 0,
     '{"local_asn":{"type":"asn","label":"Local AS","required":true,"source":"bgp_local_as"},"neighbor_ip":{"type":"ip","label":"Neighbor","required":true,"source":"bgp_peer"},"route_map":{"type":"string","label":"Route-map","required":true,"source":"route_map"},"direction":{"type":"string","label":"Direction","required":true,"enum":["in","out"],"default":"out","source":"bgp_direction"}}',
     '{"transport":"ios_ssh","config_mode":true,"apply":["router bgp {local_asn}","no neighbor {neighbor_ip} route-map {route_map} {direction}"],"exec_after":["clear ip bgp {neighbor_ip} soft {direction}"]}',
     '{"method":"ios_show","command":"show running-config | include neighbor {neighbor_ip} route-map","reject":"{route_map} {direction}"}',
     1);

-- 4. Basic rollback link (set <-> unset). The prior-route-map RESTORE on revert is
--    layered on top in the API (it snapshots the neighbor's current map at apply);
--    this link is the fallback "remove the applied map" reverse.
UPDATE reroute_templates t JOIN reroute_templates r ON r.name = 'bgp_route_map_unset'
    SET t.rollback_template_id = r.id WHERE t.name = 'bgp_route_map_set';
UPDATE reroute_templates t JOIN reroute_templates r ON r.name = 'bgp_route_map_set'
    SET t.rollback_template_id = r.id WHERE t.name = 'bgp_route_map_unset';
