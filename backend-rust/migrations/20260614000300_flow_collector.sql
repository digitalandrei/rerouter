-- Flow telemetry (NetFlow v9 / IPFIX) — read-only collector storage. SECOND,
-- additive telemetry source alongside SNMP interface polling; gives per-tuple
-- composition SNMP cannot. See docs/flow-telemetry.md.
--
-- Model: exporter (an enrolled device, by source IP) -> NetFlow datagrams ->
-- decoded FlowRecords -> pre-aggregated into fixed-width time buckets. We NEVER
-- store raw flows (5-tuple cardinality explodes under the very DDoS we detect).
-- Three purpose-built, individually-bounded bucket tables; a single top-K table
-- would miss a spoofed-source flood (per docs/flow-telemetry.md).
--
-- Buckets retain ~the last hour (prune mirrors interface_samples, 70 min).
-- flow_exporters is durable state and is NOT pruned. All flow data is telemetry:
-- it feeds detection but executes nothing — observe mode + reroute gates unchanged.
--
-- ADDITIVE migration (new tables only); edits no existing migration.

-- One row per learned exporter (NetFlow source). Maps the export source IP to an
-- enrolled device and holds the resolved sampling state + collector health.
CREATE TABLE IF NOT EXISTS flow_exporters (
    id                      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    device_id               BIGINT UNSIGNED NULL,        -- NULL until matched to a device
    -- export source address (the router's exporting interface IP).
    source_addr             VARCHAR(45)     NOT NULL,    -- INET6-capable
    -- NetFlow v9 source_id / IPFIX observation domain id.
    observation_domain      INT UNSIGNED    NOT NULL DEFAULT 0,
    version                 SMALLINT UNSIGNED NULL,      -- 9 = NetFlow v9, 10 = IPFIX
    -- SAMPLING: store every input + the resolved effective rate. Counts are kept
    -- raw (sampled); estimates are effective_sampling_rate * raw, re-derivable if
    -- the rate is later corrected. See docs/flow-telemetry.md precedence.
    configured_sampling_rate INT UNSIGNED   NULL,        -- operator override (authoritative when set)
    reported_sampling_rate   INT UNSIGNED   NULL,        -- from the exporter's options template
    snmp_derived_rate        INT UNSIGNED   NULL,        -- back-calculated vs SNMP ifHC counters
    effective_sampling_rate  INT UNSIGNED   NOT NULL DEFAULT 1,
    sampling_source         ENUM('config','reported','snmp_derived','default','unknown')
                                            NOT NULL DEFAULT 'unknown',
    -- SAFETY: low confidence blocks flow-driven automatic actions (doctrine).
    sampling_confidence     ENUM('high','low') NOT NULL DEFAULT 'low',
    -- SNMP cross-calibration: ratio of SNMP-measured to flow-estimated volume over
    -- the last window (~1.0 = agree). Persisted for the exporter-health view.
    snmp_xcal_ratio         DOUBLE          NULL,
    -- collector health / liveness.
    last_packet_at          TIMESTAMP       NULL DEFAULT NULL,
    template_count          INT UNSIGNED    NOT NULL DEFAULT 0,
    last_sequence           BIGINT UNSIGNED NULL,        -- last seen export sequence number
    datagrams_total         BIGINT UNSIGNED NOT NULL DEFAULT 0,
    dropped_not_allowlisted BIGINT UNSIGNED NOT NULL DEFAULT 0,
    dropped_no_template     BIGINT UNSIGNED NOT NULL DEFAULT 0,
    dropped_malformed       BIGINT UNSIGNED NOT NULL DEFAULT 0,
    created_at              TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_flow_exporters_src_domain (source_addr, observation_domain),
    KEY idx_flow_exporters_device (device_id),
    CONSTRAINT fk_flow_exporters_device FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Per (bucket, interface, direction) totals. Tiny; drives per-interface totals
-- and SNMP cross-calibration. flow_count = number of distinct flows folded in
-- (including the tail truncated out of flow_talker_buckets), so the UI can show
-- "top K of N".
CREATE TABLE IF NOT EXISTS flow_iface_buckets (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    exporter_id         BIGINT UNSIGNED NOT NULL,
    device_id           BIGINT UNSIGNED NOT NULL,
    interface_id        BIGINT UNSIGNED NULL,            -- NULL = ifIndex not yet discovered
    if_index            INT UNSIGNED    NOT NULL,
    direction           ENUM('ingress','egress') NOT NULL,
    bucket_ts           TIMESTAMP       NOT NULL,        -- bucket start (UTC)
    -- raw SAMPLED counts; multiply by effective_sampling_rate for an estimate.
    pkts                BIGINT UNSIGNED NOT NULL DEFAULT 0,
    bytes               BIGINT UNSIGNED NOT NULL DEFAULT 0,
    flow_count          BIGINT UNSIGNED NOT NULL DEFAULT 0,
    effective_sampling_rate INT UNSIGNED NOT NULL DEFAULT 1,
    sampling_confidence ENUM('high','low') NOT NULL DEFAULT 'low',
    created_at          TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_flow_iface_bucket (exporter_id, if_index, direction, bucket_ts),
    KEY idx_flow_iface_bucket_ts (bucket_ts),
    KEY idx_flow_iface_iface_ts (interface_id, bucket_ts),
    CONSTRAINT fk_flow_iface_exporter FOREIGN KEY (exporter_id) REFERENCES flow_exporters (id) ON DELETE CASCADE,
    CONSTRAINT fk_flow_iface_device FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE,
    CONSTRAINT fk_flow_iface_interface FOREIGN KEY (interface_id) REFERENCES device_interfaces (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Per (bucket, interface, direction, protocol, port_kind, port). Bounded and in
-- practice small. Aggregates across ALL source IPs, so it is what surfaces a
-- spoofed-source flood (e.g. millions of tiny flows to dst/53). port_kind marks
-- whether `port` is the source or destination port of the flows.
CREATE TABLE IF NOT EXISTS flow_port_buckets (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    exporter_id         BIGINT UNSIGNED NOT NULL,
    device_id           BIGINT UNSIGNED NOT NULL,
    interface_id        BIGINT UNSIGNED NULL,
    if_index            INT UNSIGNED    NOT NULL,
    direction           ENUM('ingress','egress') NOT NULL,
    bucket_ts           TIMESTAMP       NOT NULL,
    protocol            SMALLINT UNSIGNED NOT NULL,       -- IP protocol number (6=TCP, 17=UDP, ...)
    port_kind           ENUM('src','dst') NOT NULL,
    port                SMALLINT UNSIGNED NOT NULL,
    pkts                BIGINT UNSIGNED NOT NULL DEFAULT 0,
    bytes               BIGINT UNSIGNED NOT NULL DEFAULT 0,
    flow_count          BIGINT UNSIGNED NOT NULL DEFAULT 0,
    effective_sampling_rate INT UNSIGNED NOT NULL DEFAULT 1,
    sampling_confidence ENUM('high','low') NOT NULL DEFAULT 'low',
    created_at          TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_flow_port_bucket (exporter_id, if_index, direction, protocol, port_kind, port, bucket_ts),
    KEY idx_flow_port_bucket_ts (bucket_ts),
    KEY idx_flow_port_iface_ts (interface_id, bucket_ts),
    CONSTRAINT fk_flow_port_exporter FOREIGN KEY (exporter_id) REFERENCES flow_exporters (id) ON DELETE CASCADE,
    CONSTRAINT fk_flow_port_device FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE,
    CONSTRAINT fk_flow_port_interface FOREIGN KEY (interface_id) REFERENCES device_interfaces (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Per (bucket, interface, direction) TOP-K 5-tuples only. The tail beyond
-- top_k_talkers is truncated in memory before write (logged, never silent); the
-- count it represents survives in flow_iface_buckets.flow_count. For the "top
-- flows" display, not for aggregate detection.
CREATE TABLE IF NOT EXISTS flow_talker_buckets (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    exporter_id         BIGINT UNSIGNED NOT NULL,
    device_id           BIGINT UNSIGNED NOT NULL,
    interface_id        BIGINT UNSIGNED NULL,
    if_index            INT UNSIGNED    NOT NULL,
    direction           ENUM('ingress','egress') NOT NULL,
    bucket_ts           TIMESTAMP       NOT NULL,
    -- the 5-tuple. Addresses as text for INET6-capable display/grouping.
    src_addr            VARCHAR(45)     NOT NULL,
    dst_addr            VARCHAR(45)     NOT NULL,
    src_port            SMALLINT UNSIGNED NULL,           -- NULL for non-port protocols
    dst_port            SMALLINT UNSIGNED NULL,
    protocol            SMALLINT UNSIGNED NOT NULL,
    pkts                BIGINT UNSIGNED NOT NULL DEFAULT 0,
    bytes               BIGINT UNSIGNED NOT NULL DEFAULT 0,
    effective_sampling_rate INT UNSIGNED NOT NULL DEFAULT 1,
    sampling_confidence ENUM('high','low') NOT NULL DEFAULT 'low',
    created_at          TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_flow_talker_bucket (exporter_id, if_index, direction, bucket_ts, src_addr, dst_addr, src_port, dst_port, protocol),
    KEY idx_flow_talker_bucket_ts (bucket_ts),
    KEY idx_flow_talker_iface_ts (interface_id, bucket_ts),
    CONSTRAINT fk_flow_talker_exporter FOREIGN KEY (exporter_id) REFERENCES flow_exporters (id) ON DELETE CASCADE,
    CONSTRAINT fk_flow_talker_device FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE,
    CONSTRAINT fk_flow_talker_interface FOREIGN KEY (interface_id) REFERENCES device_interfaces (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
