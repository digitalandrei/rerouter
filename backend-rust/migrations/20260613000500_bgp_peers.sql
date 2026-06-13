-- BGP session discovery (read-only telemetry). The v1 mitigation toggles BGP
-- sessions to GRE-tunnelled scrubbers; operators must pick from REAL neighbors,
-- so we discover them over SNMP (BGP4-MIB bgpPeerTable) exactly like interfaces.
--
-- Reconciled by (device_id, peer_remote_addr). `label` is an operator-set
-- friendly name (e.g. "Scrubber-A GRE"); everything else is SNMP-sourced and
-- refreshed every poll. IPv4 peers only in v1 (BGP4-MIB); IPv6/VPNv4 deferred.
CREATE TABLE IF NOT EXISTS device_bgp_peers (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    device_id           BIGINT UNSIGNED NOT NULL,
    peer_remote_addr    VARCHAR(45)     NOT NULL,
    peer_remote_as      INT UNSIGNED    NULL,
    local_as            INT UNSIGNED    NULL,
    -- session FSM state (idle/connect/active/opensent/openconfirm/established)
    peer_state          VARCHAR(32)     NULL,
    -- admin intent: 'start' (no shutdown) or 'stop' (shutdown)
    peer_admin_status   VARCHAR(16)     NULL,
    label               VARCHAR(191)    NULL,
    first_seen_at       TIMESTAMP       NULL DEFAULT NULL,
    last_seen_at        TIMESTAMP       NULL DEFAULT NULL,
    last_polled_at      TIMESTAMP       NULL DEFAULT NULL,
    created_at          TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_device_bgp_peer (device_id, peer_remote_addr),
    KEY idx_device_bgp_peers_device (device_id),
    CONSTRAINT fk_device_bgp_peers_device FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
