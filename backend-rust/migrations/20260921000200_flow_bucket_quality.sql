-- Per-bucket flow collection completeness. Quality is independent of sampling
-- confidence and counter presence. Old buckets have no row and are unavailable.
CREATE TABLE flow_bucket_quality (
    exporter_id       BIGINT UNSIGNED NOT NULL,
    bucket_ts         TIMESTAMP NOT NULL,
    iface_complete    TINYINT(1) NOT NULL DEFAULT 0,
    port_complete     TINYINT(1) NOT NULL DEFAULT 0,
    asn_complete      TINYINT(1) NOT NULL DEFAULT 0,
    talker_complete   TINYINT(1) NOT NULL DEFAULT 0,
    iface_dropped     BIGINT UNSIGNED NOT NULL DEFAULT 0,
    port_dropped      BIGINT UNSIGNED NOT NULL DEFAULT 0,
    asn_dropped       BIGINT UNSIGNED NOT NULL DEFAULT 0,
    talker_dropped    BIGINT UNSIGNED NOT NULL DEFAULT 0,
    created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (exporter_id, bucket_ts),
    KEY idx_flow_bucket_quality_ts (bucket_ts),
    CONSTRAINT fk_flow_bucket_quality_exporter
        FOREIGN KEY (exporter_id) REFERENCES flow_exporters (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Durable expected-contributor registry. interface_id restricts membership to
-- enrolled/discovered interfaces; it cannot grow from arbitrary wire ifIndex
-- values. Missing contributors remain expected until their exporter is moved or
-- deleted, so silence can never age into a measured zero.
CREATE TABLE flow_exporter_interfaces (
    exporter_id       BIGINT UNSIGNED NOT NULL,
    device_id         BIGINT UNSIGNED NOT NULL,
    interface_id      BIGINT UNSIGNED NOT NULL,
    if_index          INT UNSIGNED NOT NULL,
    direction         ENUM('ingress','egress') NOT NULL,
    first_seen_at     TIMESTAMP NOT NULL,
    last_seen_at      TIMESTAMP NOT NULL,
    created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (exporter_id, interface_id, direction),
    KEY idx_flow_exporter_interfaces_lookup (device_id, if_index, direction),
    KEY idx_flow_exporter_interfaces_last_seen (last_seen_at),
    CONSTRAINT fk_flow_exporter_interfaces_exporter
        FOREIGN KEY (exporter_id) REFERENCES flow_exporters (id) ON DELETE CASCADE,
    CONSTRAINT fk_flow_exporter_interfaces_device
        FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE,
    CONSTRAINT fk_flow_exporter_interfaces_interface
        FOREIGN KEY (interface_id) REFERENCES device_interfaces (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Backlog loss is cumulative collector health only. It is intentionally absent
-- from flow_bucket_quality and cannot poison later buckets.
ALTER TABLE flow_exporters
    ADD COLUMN dropped_bucket_backlog BIGINT UNSIGNED NOT NULL DEFAULT 0
        AFTER dropped_malformed;
