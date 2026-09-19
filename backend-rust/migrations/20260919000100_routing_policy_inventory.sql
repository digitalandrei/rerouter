-- Complete, typed routing-policy snapshots. Rows are replaced transactionally
-- only after all three bounded configuration reads parse successfully.
CREATE TABLE routing_policy_snapshots (
 device_id BIGINT UNSIGNED NOT NULL PRIMARY KEY,
 inventory_json JSON NOT NULL,
 completeness ENUM('complete','partial','stale') NOT NULL,
 blockers_json JSON NOT NULL,
 read_at TIMESTAMP NOT NULL,
 CONSTRAINT fk_routing_policy_snapshot_device FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT IGNORE INTO reroute_templates
 (name,display_name,description,provider_type,mode,automatic_allowed,parameter_schema_json,plan_json,verification_json,enabled)
VALUES
 ('bgp_export_policy_set','Change BGP export policy',
  'Replace only the selected neighbor direct outbound IPv4 policy attachment. Policy contents are preserved and snapshotted; inherited or ambiguous policy is refused.',
  'device_cli','ios_ssh',0,
  '{"neighbor_ip":{"type":"ip","label":"Neighbor","required":true,"source":"bgp_peer"},"policy_kind":{"type":"string","label":"Policy type","required":true,"enum":["prefix_list","route_map"]},"policy_name":{"type":"string","label":"Policy","required":true,"source":"routing_export_policy"}}',
  '{"transport":"ios_ssh","config_mode":true,"apply":[]}',
  '{"method":"prepared_state"}',1);
