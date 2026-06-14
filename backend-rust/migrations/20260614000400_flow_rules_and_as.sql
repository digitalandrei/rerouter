-- Wire flow telemetry into detection rules + add an AS (autonomous-system)
-- aggregation dimension. See docs/flow-telemetry.md.
--
-- 1. Detection rules can now threshold a FLOW-derived metric (flow_pps /
--    flow_bps) for a specific (interface, direction[, protocol][, port]) selector
--    — the high-pps / low-bps "port-53 from peer A" case. The selector columns
--    are NULL for the existing SNMP interface metrics (rx_bps, …). Flow metrics
--    are evaluated against the latest closed flow bucket; LOW sampling confidence
--    blocks any automatic action (per doctrine), the alert still renders.
-- 2. flow_as_buckets mirrors flow_port_buckets but keys on source/destination AS
--    number, for "top speakers by AS". Only populated when the exporter's flow
--    record collects SRC_AS / DST_AS (Cisco FNF: `collect routing source as` /
--    `collect routing destination as`).
--
-- ADDITIVE migration (new columns + new table); edits no existing migration.

ALTER TABLE rules
    -- ingress/egress the flow metric is measured on (required for a flow rule).
    ADD COLUMN flow_direction  ENUM('ingress','egress') NULL AFTER metric,
    -- IP protocol number to match (NULL = any protocol).
    ADD COLUMN flow_protocol   SMALLINT UNSIGNED NULL AFTER flow_direction,
    -- L4 port to match (NULL = the whole interface, i.e. the iface bucket).
    ADD COLUMN flow_port       SMALLINT UNSIGNED NULL AFTER flow_protocol,
    -- whether flow_port is the source or destination port (default dst when set).
    ADD COLUMN flow_port_kind  ENUM('src','dst') NULL AFTER flow_port;

-- Per (bucket, interface, direction, as_kind, asn). Bounded; aggregates across
-- all flows, so it surfaces a top source/destination AS even under a spoofed-
-- source flood. as_kind marks whether `asn` is the source or destination AS.
CREATE TABLE IF NOT EXISTS flow_as_buckets (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    exporter_id         BIGINT UNSIGNED NOT NULL,
    device_id           BIGINT UNSIGNED NOT NULL,
    interface_id        BIGINT UNSIGNED NULL,
    if_index            INT UNSIGNED    NOT NULL,
    direction           ENUM('ingress','egress') NOT NULL,
    bucket_ts           TIMESTAMP       NOT NULL,
    as_kind             ENUM('src','dst') NOT NULL,
    asn                 INT UNSIGNED    NOT NULL,
    pkts                BIGINT UNSIGNED NOT NULL DEFAULT 0,
    bytes               BIGINT UNSIGNED NOT NULL DEFAULT 0,
    flow_count          BIGINT UNSIGNED NOT NULL DEFAULT 0,
    effective_sampling_rate INT UNSIGNED NOT NULL DEFAULT 1,
    sampling_confidence ENUM('high','low') NOT NULL DEFAULT 'low',
    created_at          TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_flow_as_bucket (exporter_id, if_index, direction, as_kind, asn, bucket_ts),
    KEY idx_flow_as_bucket_ts (bucket_ts),
    KEY idx_flow_as_iface_ts (interface_id, bucket_ts),
    CONSTRAINT fk_flow_as_exporter FOREIGN KEY (exporter_id) REFERENCES flow_exporters (id) ON DELETE CASCADE,
    CONSTRAINT fk_flow_as_device FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE,
    CONSTRAINT fk_flow_as_interface FOREIGN KEY (interface_id) REFERENCES device_interfaces (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
