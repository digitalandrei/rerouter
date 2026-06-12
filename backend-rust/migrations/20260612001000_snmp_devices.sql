-- SNMP interface-polling telemetry: devices (routers) + their interfaces, the
-- latest derived metrics per interface, and a retained sample history. This is
-- the v1 telemetry source (SNMP v2c interface polling — NOT NetFlow). See
-- docs/telemetry-model.md and docs/device-enrollment.md.
--
-- Model: device (Cisco ASR / any SNMP agent) -> device_interfaces -> per
-- interface { interface_metrics_current (one row, carries the raw counters that
-- form the next delta baseline) + interface_samples (history, 7-day retention) }.
-- SNMP is read-only, which is exactly what observe mode wants.
--
-- This migration is ADDITIVE (new tables + two nullable columns on rules); it
-- never edits an existing migration. Fresh-DB detection in db::migrate keys on
-- _sqlx_migrations and is unaffected.

-- A polled SNMP device (router). Community/v3 key material is encrypted at rest
-- by the controller (AES-256-GCM, key from SECRETS_KEY); only ciphertext lands
-- here. v3 columns are reserved (v1 implements v2c; v3 returns "unsupported").
CREATE TABLE IF NOT EXISTS devices (
    id                      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    name                    VARCHAR(191)    NOT NULL,
    -- management IP or DNS name the controller polls.
    hostname                VARCHAR(255)    NOT NULL,
    snmp_version            ENUM('v2c', 'v3') NOT NULL DEFAULT 'v2c',
    snmp_port               SMALLINT UNSIGNED NOT NULL DEFAULT 161,
    -- v2c: AES-256-GCM ciphertext of the community string (nullable so a device
    -- row can exist before the secret is set). Never the plaintext.
    community_encrypted     VARBINARY(512)  NULL,
    -- v3 (reserved; all nullable). Auth/priv keys encrypted like the community.
    v3_sec_name             VARCHAR(191)    NULL,
    v3_auth_proto           ENUM('none', 'MD5', 'SHA', 'SHA256', 'SHA512') NULL,
    v3_auth_key_encrypted   VARBINARY(512)  NULL,
    v3_priv_proto           ENUM('none', 'DES', 'AES', 'AES256') NULL,
    v3_priv_key_encrypted   VARBINARY(512)  NULL,
    poll_interval_seconds   INT UNSIGNED    NOT NULL DEFAULT 30,
    enabled                 TINYINT(1)      NOT NULL DEFAULT 1,
    -- identity learned from sysDescr at test/discover time.
    vendor                  VARCHAR(191)    NULL,
    model                   VARCHAR(191)    NULL,
    os_version              VARCHAR(191)    NULL,
    -- last poll outcome. reachable defaults 0 (telemetry stale until proven).
    reachable               TINYINT(1)      NOT NULL DEFAULT 0,
    last_poll_at            TIMESTAMP       NULL DEFAULT NULL,
    last_error              TEXT            NULL,
    sys_name                VARCHAR(255)    NULL,
    sys_uptime              BIGINT UNSIGNED NULL,   -- sysUpTime in TimeTicks (1/100 s)
    created_at              TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_devices_name (name),
    KEY idx_devices_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Interfaces discovered on a device (ifXTable + ifTable), reconciled by if_index.
-- Only interfaces with enabled_for_monitoring = 1 are polled and rule-evaluated.
CREATE TABLE IF NOT EXISTS device_interfaces (
    id                      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    device_id               BIGINT UNSIGNED NOT NULL,
    if_index                INT UNSIGNED    NOT NULL,
    if_name                 VARCHAR(191)    NULL,   -- ifName (ifXTable)
    if_descr                VARCHAR(255)    NULL,   -- ifDescr (ifTable)
    if_alias                VARCHAR(255)    NULL,   -- ifAlias (ifXTable) — operator label
    -- bits/sec: ifHighSpeed*1_000_000 when present, else ifSpeed. Drives util%.
    if_speed_bps            BIGINT UNSIGNED NOT NULL DEFAULT 0,
    admin_status            VARCHAR(16)     NULL,   -- up | down | testing
    oper_status             VARCHAR(16)     NULL,   -- up | down | ... (ifOperStatus)
    is_physical             TINYINT(1)      NOT NULL DEFAULT 0,  -- ifType-derived heuristic
    enabled_for_monitoring  TINYINT(1)      NOT NULL DEFAULT 0,
    display_order           INT             NOT NULL DEFAULT 0,
    first_seen_at           TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at            TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_device_interfaces_device_ifindex (device_id, if_index),
    KEY idx_device_interfaces_monitored (device_id, enabled_for_monitoring),
    CONSTRAINT fk_device_interfaces_device FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Latest derived metrics per interface (exactly one row per interface). The
-- raw *_octets / *_pkts columns are the counters from the last valid poll and
-- form the baseline for the NEXT delta — keep raw and derived strictly separate
-- (docs/telemetry-model.md). valid_sample = 0 marks a wrapped/reset/failed read
-- whose rates must not be trusted by detection.
CREATE TABLE IF NOT EXISTS interface_metrics_current (
    interface_id        BIGINT UNSIGNED NOT NULL,
    device_id           BIGINT UNSIGNED NOT NULL,
    sampled_at          TIMESTAMP       NULL DEFAULT NULL,
    valid_sample        TINYINT(1)      NOT NULL DEFAULT 0,
    -- raw counters from the last successful read (next-delta baseline).
    in_octets           BIGINT UNSIGNED NULL,
    out_octets          BIGINT UNSIGNED NULL,
    in_ucast_pkts       BIGINT UNSIGNED NULL,
    out_ucast_pkts      BIGINT UNSIGNED NULL,
    -- derived rates.
    rx_bps              DOUBLE          NOT NULL DEFAULT 0,
    tx_bps              DOUBLE          NOT NULL DEFAULT 0,
    rx_pps              DOUBLE          NOT NULL DEFAULT 0,
    tx_pps              DOUBLE          NOT NULL DEFAULT 0,
    rx_util_percent     DOUBLE          NOT NULL DEFAULT 0,
    tx_util_percent     DOUBLE          NOT NULL DEFAULT 0,
    -- error/discard counters (raw, for display and error-rate rules).
    in_errors           BIGINT UNSIGNED NULL,
    out_errors          BIGINT UNSIGNED NULL,
    in_discards         BIGINT UNSIGNED NULL,
    out_discards        BIGINT UNSIGNED NULL,
    admin_status        VARCHAR(16)     NULL,
    oper_status         VARCHAR(16)     NULL,
    updated_at          TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (interface_id),
    KEY idx_interface_metrics_current_device (device_id),
    CONSTRAINT fk_interface_metrics_current_interface FOREIGN KEY (interface_id) REFERENCES device_interfaces (id) ON DELETE CASCADE,
    CONSTRAINT fk_interface_metrics_current_device FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Retained per-interface rate history (default 7-day retention, like
-- traffic_samples). Only derived rates are kept here; raw counters live in
-- interface_metrics_current.
CREATE TABLE IF NOT EXISTS interface_samples (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    interface_id        BIGINT UNSIGNED NOT NULL,
    device_id           BIGINT UNSIGNED NOT NULL,
    sampled_at          TIMESTAMP       NOT NULL,
    valid_sample        TINYINT(1)      NOT NULL DEFAULT 0,
    rx_bps              DOUBLE          NOT NULL DEFAULT 0,
    tx_bps              DOUBLE          NOT NULL DEFAULT 0,
    rx_pps              DOUBLE          NOT NULL DEFAULT 0,
    tx_pps              DOUBLE          NOT NULL DEFAULT 0,
    rx_util_percent     DOUBLE          NOT NULL DEFAULT 0,
    tx_util_percent     DOUBLE          NOT NULL DEFAULT 0,
    created_at          TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_interface_samples_interface_sampled (interface_id, sampled_at),
    KEY idx_interface_samples_sampled_at (sampled_at),
    CONSTRAINT fk_interface_samples_interface FOREIGN KEY (interface_id) REFERENCES device_interfaces (id) ON DELETE CASCADE,
    CONSTRAINT fk_interface_samples_device FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Extend rules so a rule can target a monitored interface (interface metrics)
-- INSTEAD OF a protected asset. asset_id was NOT NULL; relax it so a rule
-- targets an interface XOR an asset (enforced in application code). Interface
-- metrics: rx_bps, tx_bps, rx_pps, tx_pps, rx_util_percent, tx_util_percent,
-- oper_status. Operators (>,>=,<,<=,==,!=) already exist.
ALTER TABLE rules
    MODIFY COLUMN asset_id BIGINT UNSIGNED NULL,
    ADD COLUMN interface_id BIGINT UNSIGNED NULL AFTER asset_id,
    ADD COLUMN device_id    BIGINT UNSIGNED NULL AFTER interface_id,
    ADD KEY idx_rules_interface (interface_id),
    ADD KEY idx_rules_device (device_id),
    ADD CONSTRAINT fk_rules_interface FOREIGN KEY (interface_id) REFERENCES device_interfaces (id) ON DELETE CASCADE,
    ADD CONSTRAINT fk_rules_device FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE;

-- Let alerts/rule_events reference the device + interface that fired (additive,
-- nullable; the existing asset_id path is unchanged).
ALTER TABLE alerts
    ADD COLUMN device_id    BIGINT UNSIGNED NULL AFTER asset_id,
    ADD COLUMN interface_id BIGINT UNSIGNED NULL AFTER device_id,
    ADD KEY idx_alerts_device (device_id),
    ADD KEY idx_alerts_interface (interface_id),
    ADD CONSTRAINT fk_alerts_device FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE SET NULL,
    ADD CONSTRAINT fk_alerts_interface FOREIGN KEY (interface_id) REFERENCES device_interfaces (id) ON DELETE SET NULL;
