-- Telemetry: latest normalized metrics per asset + high-volume raw samples.
-- See docs/telemetry-model.md. traffic_samples is retention-controlled
-- (default 7 days; cleanup job honours docs/database.md retention defaults).

CREATE TABLE IF NOT EXISTS asset_metrics_current (
    asset_id            BIGINT UNSIGNED NOT NULL,
    sampled_at          TIMESTAMP       NULL DEFAULT NULL,
    method              VARCHAR(32)     NULL,
    valid_sample        TINYINT(1)      NOT NULL DEFAULT 0,
    sampling_rate       INT UNSIGNED    NOT NULL DEFAULT 1,
    rx_bps              DOUBLE          NOT NULL DEFAULT 0,
    tx_bps              DOUBLE          NOT NULL DEFAULT 0,
    rx_pps              DOUBLE          NOT NULL DEFAULT 0,
    tx_pps              DOUBLE          NOT NULL DEFAULT 0,
    new_conns_per_sec   DOUBLE          NULL,
    syn_rate            DOUBLE          NULL,
    syn_ack_ratio       DOUBLE          NULL,
    unique_src_count    INT UNSIGNED    NULL,
    top_src_asn         INT UNSIGNED    NULL,
    top_dst_port        SMALLINT UNSIGNED NULL,
    -- SAFETY: stale telemetry blocks automatic actions.
    telemetry_stale     TINYINT(1)      NOT NULL DEFAULT 1,
    updated_at          TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (asset_id),
    CONSTRAINT fk_asset_metrics_current_asset FOREIGN KEY (asset_id) REFERENCES protected_assets (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS traffic_samples (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    asset_id            BIGINT UNSIGNED NOT NULL,
    sampled_at          TIMESTAMP       NOT NULL,
    method              VARCHAR(32)     NOT NULL,
    valid_sample        TINYINT(1)      NOT NULL DEFAULT 0,
    sampling_rate       INT UNSIGNED    NOT NULL DEFAULT 1,
    rx_bps              DOUBLE          NOT NULL DEFAULT 0,
    tx_bps              DOUBLE          NOT NULL DEFAULT 0,
    rx_pps              DOUBLE          NOT NULL DEFAULT 0,
    tx_pps              DOUBLE          NOT NULL DEFAULT 0,
    new_conns_per_sec   DOUBLE          NULL,
    syn_rate            DOUBLE          NULL,
    syn_ack_ratio       DOUBLE          NULL,
    unique_src_count    INT UNSIGNED    NULL,
    raw_ref             VARCHAR(255)    NULL,
    created_at          TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_traffic_samples_asset_sampled (asset_id, sampled_at),
    KEY idx_traffic_samples_sampled_at (sampled_at),
    CONSTRAINT fk_traffic_samples_asset FOREIGN KEY (asset_id) REFERENCES protected_assets (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
