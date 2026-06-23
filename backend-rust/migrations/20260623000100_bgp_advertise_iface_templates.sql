-- New device-CLI reroute templates + supporting columns:
--   * BGP per-peer advertisement control via the peer's OUTBOUND route-map's
--     prefix-list (add/remove a prefix, then `clear ip bgp <peer> soft out`).
--   * Interface TCP MSS clamp (ip tcp adjust-mss) add/remove.
--   * Interface shutdown / no shutdown (DISRUPTIVE).
-- Commands remain parameterized templates — no free-text execution. Each
-- disruptive template is paired with its rollback.
--
-- The two column adds are guarded against information_schema so the migration is
-- idempotent (MySQL DDL auto-commits, so a column from a partially-applied run is
-- not re-added). Template seeds use INSERT IGNORE on the unique name.

-- 1. Per-peer outbound prefix-list, discovered from the peer's outbound
--    route-map (`neighbor X route-map NAME out` -> route-map `match ip address
--    prefix-list PL`). Feeds the `peer_out_prefix_list` guided picker.
SET @col := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'device_bgp_peers'
      AND column_name = 'out_prefix_list');
SET @ddl := IF(@col = 0,
    'ALTER TABLE device_bgp_peers ADD COLUMN out_prefix_list VARCHAR(191) NULL',
    'DO 0');
PREPARE s FROM @ddl; EXECUTE s; DEALLOCATE PREPARE s;

-- 2. Management/transit-path guard flag. The executor refuses a disruptive
--    interface action (shutdown / MSS clamp) on an interface flagged `protected`
--    so the controller cannot black-hole or cut its own path to the device.
SET @col := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'device_interfaces'
      AND column_name = 'protected');
SET @ddl := IF(@col = 0,
    'ALTER TABLE device_interfaces ADD COLUMN protected TINYINT(1) NOT NULL DEFAULT 0',
    'DO 0');
PREPARE s FROM @ddl; EXECUTE s; DEALLOCATE PREPARE s;

-- 3. Seed templates. plan_json gains an optional "exec_after" array: commands run
--    AFTER `end` (privileged EXEC, e.g. `clear ip bgp ... soft out`), never inside
--    the config block. verification expect/reject may reference {params}.

-- bgp_advertise_add (high): start advertising a prefix to ONE upstream peer by
-- adding it to that peer's outbound prefix-list, then soft-clear outbound.
INSERT IGNORE INTO reroute_templates
    (name, description, provider_type, mode, automatic_allowed,
     parameter_schema_json, plan_json, verification_json, enabled)
VALUES
    ('bgp_advertise_add',
     'Advertise a prefix toward one upstream BGP peer: add it to the peer''s outbound route-map prefix-list, then clear ip bgp <peer> soft out. Use to shift an attacked prefix onto a less-saturated upstream. Reversible.',
     'device_cli', 'ios_ssh', 0,
     '{"neighbor_ip":{"type":"ip","label":"Upstream neighbor","required":true,"source":"bgp_peer"},"prefix":{"type":"cidr","label":"Prefix to advertise","required":true,"source":"announced_prefix"},"prefix_list_name":{"type":"string","label":"Outbound prefix-list","required":true,"source":"peer_out_prefix_list"}}',
     '{"transport":"ios_ssh","config_mode":true,"apply":["ip prefix-list {prefix_list_name} permit {prefix}"],"exec_after":["clear ip bgp {neighbor_ip} soft out"]}',
     '{"method":"ios_show","command":"show ip bgp neighbors {neighbor_ip} advertised-routes","expect":"{prefix_net}"}',
     1);

-- bgp_advertise_remove (high): stop advertising the prefix to that peer (rollback
-- of add) — remove the prefix-list entry, soft-clear outbound.
INSERT IGNORE INTO reroute_templates
    (name, description, provider_type, mode, automatic_allowed,
     parameter_schema_json, plan_json, verification_json, enabled)
VALUES
    ('bgp_advertise_remove',
     'Stop advertising a prefix toward one upstream BGP peer: remove it from the peer''s outbound route-map prefix-list, then clear ip bgp <peer> soft out. Rollback of bgp_advertise_add.',
     'device_cli', 'ios_ssh', 0,
     '{"neighbor_ip":{"type":"ip","label":"Upstream neighbor","required":true,"source":"bgp_peer"},"prefix":{"type":"cidr","label":"Prefix to withdraw","required":true,"source":"announced_prefix"},"prefix_list_name":{"type":"string","label":"Outbound prefix-list","required":true,"source":"peer_out_prefix_list"}}',
     '{"transport":"ios_ssh","config_mode":true,"apply":["no ip prefix-list {prefix_list_name} permit {prefix}"],"exec_after":["clear ip bgp {neighbor_ip} soft out"]}',
     '{"method":"ios_show","command":"show ip bgp neighbors {neighbor_ip} advertised-routes","reject":"{prefix_net}"}',
     1);

-- iface_tcp_adjust_mss (medium): clamp TCP MSS on an interface when a rule fires.
INSERT IGNORE INTO reroute_templates
    (name, description, provider_type, mode, automatic_allowed,
     parameter_schema_json, plan_json, verification_json, enabled)
VALUES
    ('iface_tcp_adjust_mss',
     'Set ip tcp adjust-mss on an interface (MSS clamp, default 1436). Applied when a rule activates.',
     'device_cli', 'ios_ssh', 0,
     '{"interface":{"type":"string","label":"Interface","required":true,"source":"interface_name"},"mss":{"type":"int","label":"MSS","required":true,"default":"1436"}}',
     '{"transport":"ios_ssh","config_mode":true,"apply":["interface {interface}","ip tcp adjust-mss {mss}"]}',
     '{"method":"ios_show","command":"show running-config interface {interface}","expect":"ip tcp adjust-mss {mss}"}',
     1);

-- iface_tcp_adjust_mss_remove (medium): remove the MSS clamp (rollback).
INSERT IGNORE INTO reroute_templates
    (name, description, provider_type, mode, automatic_allowed,
     parameter_schema_json, plan_json, verification_json, enabled)
VALUES
    ('iface_tcp_adjust_mss_remove',
     'Remove ip tcp adjust-mss from an interface. Rollback of iface_tcp_adjust_mss.',
     'device_cli', 'ios_ssh', 0,
     '{"interface":{"type":"string","label":"Interface","required":true,"source":"interface_name"}}',
     '{"transport":"ios_ssh","config_mode":true,"apply":["interface {interface}","no ip tcp adjust-mss"]}',
     '{"method":"ios_show","command":"show running-config interface {interface}","reject":"adjust-mss"}',
     1);

-- iface_shutdown (high, DISRUPTIVE): administratively shut an interface. Guarded
-- against the device's protected (management/transit) interfaces by the executor.
INSERT IGNORE INTO reroute_templates
    (name, description, provider_type, mode, automatic_allowed,
     parameter_schema_json, plan_json, verification_json, enabled)
VALUES
    ('iface_shutdown',
     'Administratively shut an interface (shutdown). DISRUPTIVE — black-holes everything on the link. Blocked on interfaces flagged as the management/transit path.',
     'device_cli', 'ios_ssh', 0,
     '{"interface":{"type":"string","label":"Interface","required":true,"source":"interface_name"}}',
     '{"transport":"ios_ssh","config_mode":true,"apply":["interface {interface}","shutdown"]}',
     '{"method":"ios_show","command":"show interfaces {interface}","expect":"administratively down"}',
     1);

-- iface_no_shutdown (high): bring the interface back up (rollback of shutdown).
INSERT IGNORE INTO reroute_templates
    (name, description, provider_type, mode, automatic_allowed,
     parameter_schema_json, plan_json, verification_json, enabled)
VALUES
    ('iface_no_shutdown',
     'Bring an interface back up (no shutdown). Rollback of iface_shutdown.',
     'device_cli', 'ios_ssh', 0,
     '{"interface":{"type":"string","label":"Interface","required":true,"source":"interface_name"}}',
     '{"transport":"ios_ssh","config_mode":true,"apply":["interface {interface}","no shutdown"]}',
     '{"method":"ios_show","command":"show interfaces {interface}","reject":"administratively down"}',
     1);

-- 4. Wire each template to its rollback (self-referential, by name).
UPDATE reroute_templates t JOIN reroute_templates r ON r.name = 'bgp_advertise_remove'
    SET t.rollback_template_id = r.id WHERE t.name = 'bgp_advertise_add';
UPDATE reroute_templates t JOIN reroute_templates r ON r.name = 'bgp_advertise_add'
    SET t.rollback_template_id = r.id WHERE t.name = 'bgp_advertise_remove';
UPDATE reroute_templates t JOIN reroute_templates r ON r.name = 'iface_tcp_adjust_mss_remove'
    SET t.rollback_template_id = r.id WHERE t.name = 'iface_tcp_adjust_mss';
UPDATE reroute_templates t JOIN reroute_templates r ON r.name = 'iface_tcp_adjust_mss'
    SET t.rollback_template_id = r.id WHERE t.name = 'iface_tcp_adjust_mss_remove';
UPDATE reroute_templates t JOIN reroute_templates r ON r.name = 'iface_no_shutdown'
    SET t.rollback_template_id = r.id WHERE t.name = 'iface_shutdown';
UPDATE reroute_templates t JOIN reroute_templates r ON r.name = 'iface_shutdown'
    SET t.rollback_template_id = r.id WHERE t.name = 'iface_no_shutdown';
