-- Protected assets, reroute providers, credentials, and per-asset status.
-- See docs/database.md and docs/asset-enrollment.md.

CREATE TABLE IF NOT EXISTS protected_assets (
    id                      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    name                    VARCHAR(191)    NOT NULL,
    kind                    ENUM('prefix', 'ip', 'service') NOT NULL,
    cidr                    VARCHAR(64)     NOT NULL,
    address_family          ENUM('v4', 'v6') NOT NULL DEFAULT 'v4',
    description             TEXT            NULL,
    owner                   VARCHAR(191)    NULL,
    site                    VARCHAR(191)    NULL,
    criticality             VARCHAR(32)     NULL,
    enabled                 TINYINT(1)      NOT NULL DEFAULT 1,
    flow_enabled            TINYINT(1)      NOT NULL DEFAULT 0,
    bgp_enabled             TINYINT(1)      NOT NULL DEFAULT 0,
    cloudflare_zone_id      VARCHAR(64)     NULL,
    -- SAFETY: assets are NOT eligible for automatic reroutes unless explicitly opted in.
    auto_reroute_eligible   TINYINT(1)      NOT NULL DEFAULT 0,
    created_at              TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_protected_assets_name (name),
    KEY idx_protected_assets_enabled (enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- NOTE: reroute_providers.credential_id <-> provider_credentials.provider_id is
-- intentionally circular; credential_id is therefore an indexed column without a
-- foreign key (validated in application code).
CREATE TABLE IF NOT EXISTS reroute_providers (
    id                      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    name                    VARCHAR(191)    NOT NULL,
    type                    ENUM('cloudflare', 'bgp_rtbh', 'flowspec', 'scrubber') NOT NULL,
    enabled                 TINYINT(1)      NOT NULL DEFAULT 1,
    -- SAFETY: a provider can be visible for telemetry while actions stay disabled.
    actions_enabled         TINYINT(1)      NOT NULL DEFAULT 0,
    endpoint                VARCHAR(255)    NULL,
    peer_ip                 VARCHAR(45)     NULL,
    local_asn               INT UNSIGNED    NULL,
    remote_asn              INT UNSIGNED    NULL,
    blackhole_community     VARCHAR(64)     NULL,
    permitted_prefixes_json JSON            NULL,
    credential_id           BIGINT UNSIGNED NULL,
    health_status           VARCHAR(32)     NULL,
    last_success_at         TIMESTAMP       NULL DEFAULT NULL,
    last_failure_reason     TEXT            NULL,
    created_at              TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_reroute_providers_name (name),
    KEY idx_reroute_providers_credential (credential_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Secret material is encrypted by the controller (AES-256-GCM, key from the
-- SECRETS_KEY env var); the API exposes only references/metadata.
CREATE TABLE IF NOT EXISTS provider_credentials (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    provider_id     BIGINT UNSIGNED NOT NULL,
    name            VARCHAR(191)    NOT NULL,
    kind            ENUM('api_token', 'bgp_key', 'ssh_key', 'password') NOT NULL,
    encrypted_value BLOB            NULL,
    key_path        VARCHAR(255)    NULL,
    created_at      TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_provider_credentials_provider (provider_id),
    CONSTRAINT fk_provider_credentials_provider FOREIGN KEY (provider_id) REFERENCES reroute_providers (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Which providers can mitigate which assets.
CREATE TABLE IF NOT EXISTS asset_provider (
    asset_id    BIGINT UNSIGNED NOT NULL,
    provider_id BIGINT UNSIGNED NOT NULL,
    created_at  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (asset_id, provider_id),
    KEY idx_asset_provider_provider (provider_id),
    CONSTRAINT fk_asset_provider_asset FOREIGN KEY (asset_id) REFERENCES protected_assets (id) ON DELETE CASCADE,
    CONSTRAINT fk_asset_provider_provider FOREIGN KEY (provider_id) REFERENCES reroute_providers (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS asset_statuses (
    asset_id                  BIGINT UNSIGNED NOT NULL,
    overall_status            VARCHAR(32)     NOT NULL DEFAULT 'unknown',
    network_status            VARCHAR(32)     NOT NULL DEFAULT 'unknown',
    telemetry_status          VARCHAR(32)     NOT NULL DEFAULT 'unknown',
    provider_status           VARCHAR(32)     NOT NULL DEFAULT 'unknown',
    last_successful_sample_at TIMESTAMP       NULL DEFAULT NULL,
    last_failed_sample_at     TIMESTAMP       NULL DEFAULT NULL,
    last_failure_reason       TEXT            NULL,
    last_seen_at              TIMESTAMP       NULL DEFAULT NULL,
    telemetry_stale           TINYINT(1)      NOT NULL DEFAULT 1,
    updated_at                TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (asset_id),
    CONSTRAINT fk_asset_statuses_asset FOREIGN KEY (asset_id) REFERENCES protected_assets (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
