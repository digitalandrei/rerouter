-- Detection evaluates flow rules against the latest closed interface bucket,
-- optionally narrowed by protocol and port. Index those exact lookups so rule
-- evaluation stays bounded as the 48-hour high-cardinality tables grow.

ALTER TABLE flow_iface_buckets
    ADD KEY idx_flow_iface_rule_latest
        (device_id, if_index, direction, bucket_ts);

ALTER TABLE flow_port_buckets
    ADD KEY idx_flow_port_rule_latest
        (device_id, if_index, direction, bucket_ts, port_kind, port, protocol);

-- Exporter cleanup uses the last packet timestamp, with created_at as the
-- fallback for exporters that never sent a datagram. Keep both predicates
-- index-backed as exporter health rows accumulate.
ALTER TABLE flow_exporters
    ADD KEY idx_flow_exporters_last_packet (last_packet_at),
    ADD KEY idx_flow_exporters_created (created_at);
