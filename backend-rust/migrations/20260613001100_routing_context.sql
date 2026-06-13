-- Routing context for guided action parameters. BGP ASN + neighbors are already
-- cached in device_bgp_peers (SNMP, refreshed each poll). This adds:
--   * rtbh_communities: a GLOBAL list of blackhole communities (standard X:Y or
--     large X:Y:Z) + the route tag the routers' RTBH redistribute route-map
--     matches to set that community.
--   * device_bgp_networks: per-device announced prefixes (BGP network
--     statements), discovered from config over SSH and revalidated daily/manually.

CREATE TABLE IF NOT EXISTS rtbh_communities (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    label       VARCHAR(191)    NOT NULL,
    kind        ENUM('standard', 'large') NOT NULL DEFAULT 'standard',
    community   VARCHAR(64)     NOT NULL,
    tag         INT UNSIGNED    NOT NULL,
    created_by  BIGINT UNSIGNED NULL,
    created_at  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_rtbh_tag (tag),
    CONSTRAINT fk_rtbh_created_by FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS device_bgp_networks (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    device_id           BIGINT UNSIGNED NOT NULL,
    prefix              VARCHAR(49)     NOT NULL, -- CIDR a.b.c.d/len
    first_seen_at       TIMESTAMP       NULL DEFAULT NULL,
    last_seen_at        TIMESTAMP       NULL DEFAULT NULL,
    last_discovered_at  TIMESTAMP       NULL DEFAULT NULL,
    created_at          TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_device_network (device_id, prefix),
    KEY idx_device_networks_device (device_id),
    CONSTRAINT fk_device_networks_device FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Re-point the template parameter schemas at the guided sources.
-- bgp_session_*: local AS (asn dropdown) + neighbor (peer dropdown).
UPDATE reroute_templates
   SET parameter_schema_json = '{"local_asn":{"type":"asn","label":"Local AS","required":true,"source":"bgp_local_as"},"neighbor_ip":{"type":"ip","label":"Neighbor","required":true,"source":"bgp_peer"}}'
 WHERE name IN ('bgp_session_enable', 'bgp_session_disable');

-- blackhole_*: announced prefix (whole) + RTBH community (-> route tag).
UPDATE reroute_templates
   SET parameter_schema_json = '{"prefix":{"type":"cidr","label":"Announced prefix","required":true,"source":"announced_prefix"},"tag":{"type":"int","label":"RTBH community","required":true,"source":"rtbh_tag"}}'
 WHERE name IN ('blackhole_prefix', 'blackhole_withdraw');

-- null_route_*: parent = announced prefix; target = any subprefix of it. The
-- command operates on the TARGET (which may equal the parent).
UPDATE reroute_templates
   SET parameter_schema_json = '{"parent":{"type":"cidr","label":"Prefix","required":true,"source":"announced_prefix"},"target":{"type":"cidr","label":"Destination (subprefix)","required":true,"subprefix_of":"parent"}}',
       plan_json = '{"transport":"ios_ssh","config_mode":true,"apply":["ip route {target_net} {target_mask} Null0"]}',
       verification_json = '{"method":"ios_show","command":"show ip route {target_net}","expect":"Null0"}'
 WHERE name = 'null_route_prefix';
UPDATE reroute_templates
   SET parameter_schema_json = '{"parent":{"type":"cidr","label":"Prefix","required":true,"source":"announced_prefix"},"target":{"type":"cidr","label":"Destination (subprefix)","required":true,"subprefix_of":"parent"}}',
       plan_json = '{"transport":"ios_ssh","config_mode":true,"apply":["no ip route {target_net} {target_mask} Null0"]}',
       verification_json = '{"method":"ios_show","command":"show ip route {target_net}","reject":"Null0"}'
 WHERE name = 'null_route_withdraw';
