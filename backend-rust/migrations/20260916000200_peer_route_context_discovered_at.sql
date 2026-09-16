-- Per-peer freshness marker for the SSH-discovered ROUTE CONTEXT
-- (out_prefix_list / in_route_map / out_route_map).
--
-- Why: those three columns are written by SSH discovery
-- (`discover_prefixes_and_store`), but the validator gated them on
-- `device_bgp_peers.last_polled_at` — a column only SNMP polling writes — plus an
-- EXISTS over `device_route_maps` as a stand-in for "routing inventory is fresh".
-- Neither says anything about when the prefix-list was read, and the EXISTS is
-- false FOREVER on a device that legitimately has no route-maps (a peer whose
-- outbound filter is `neighbor <ip> prefix-list <NAME> out`), so a freshly
-- discovered, perfectly valid value was rejected permanently.
--
-- This column is set (and the values cleared) inside the SAME reconcile
-- transaction that writes the route context, so the marker can never outlive or
-- lag behind the values it vouches for. NULL = never discovered => fail closed.
-- `last_polled_at` keeps its real meaning: peer liveness for the `bgp_peer` source.
--
-- Guarded against information_schema so the migration is idempotent (MySQL DDL
-- auto-commits, so a column from a partially-applied run is not re-added).
-- Valid on MariaDB and on MySQL 8.4 (the one deployment that runs it).

SET @col := (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'device_bgp_peers'
      AND column_name = 'route_context_discovered_at');
SET @ddl := IF(@col = 0,
    'ALTER TABLE device_bgp_peers ADD COLUMN route_context_discovered_at DATETIME NULL',
    'DO 0');
PREPARE s FROM @ddl; EXECUTE s; DEALLOCATE PREPARE s;
