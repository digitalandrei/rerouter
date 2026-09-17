-- Durable execution ownership for ordered reroute bundles.
--
-- A successful verification does not by itself prove that this activation
-- changed the router: an already-satisfied action is a verified no-op and must
-- never be inverted.  The state snapshots below keep that distinction and make
-- rollback use the exact template/parameters that actually ran.
ALTER TABLE reroutes
    ADD COLUMN mutation_effect ENUM('pending', 'changed', 'noop', 'unknown')
        NOT NULL DEFAULT 'pending' AFTER verification_status,
    ADD COLUMN prior_state_json JSON NULL AFTER mutation_effect,
    ADD COLUMN after_state_json JSON NULL AFTER prior_state_json,
    ADD COLUMN template_snapshot_json JSON NULL AFTER after_state_json,
    ADD COLUMN rollback_snapshot_json JSON NULL AFTER template_snapshot_json;

-- Operational history is part of the recovery boundary.  A device with any
-- reroute history must be disabled rather than hard-deleted.
ALTER TABLE reroutes
    DROP FOREIGN KEY fk_reroutes_device;
ALTER TABLE reroutes
    ADD CONSTRAINT fk_reroutes_device FOREIGN KEY (device_id)
        REFERENCES devices (id) ON DELETE RESTRICT;

-- Rate capacity is a reservation, not merely a count of child reroute rows.
-- `rate_reserved_actions` is the unspent portion; a child start atomically
-- moves one unit to `rate_consumed_actions` under the global advisory lock.
ALTER TABLE reroute_bundles
    ADD COLUMN rate_reserved_actions INT UNSIGNED NOT NULL DEFAULT 0
        AFTER completed_actions,
    ADD COLUMN rate_consumed_actions INT UNSIGNED NOT NULL DEFAULT 0
        AFTER rate_reserved_actions,
    ADD COLUMN interrupted_at TIMESTAMP NULL DEFAULT NULL AFTER finished_at;

-- One immutable, durable row per intended sibling.  The runner may still create
-- a reroutes attempt row only when execution starts, while this table preserves
-- queued siblings across the asynchronous HTTP hand-off and controller restart.
CREATE TABLE IF NOT EXISTS reroute_bundle_actions (
    id                         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    bundle_id                  BIGINT UNSIGNED NOT NULL,
    position                   INT UNSIGNED NOT NULL,
    source_rule_action_id      BIGINT UNSIGNED NULL,
    device_id                  BIGINT UNSIGNED NOT NULL,
    template_snapshot_json     JSON NOT NULL,
    rollback_snapshot_json     JSON NULL,
    canonical_params_json      JSON NOT NULL,
    rendered_plan_json         JSON NOT NULL,
    rendered_rollback_json     JSON NULL,
    prepared_action_json       JSON NULL,
    auto_target_json           JSON NULL,
    safety_phase               ENUM('additive', 'neutral', 'destructive')
                               NOT NULL DEFAULT 'neutral',
    state                      ENUM('queued', 'running', 'succeeded', 'noop',
                                    'failed', 'uncertain', 'compensated')
                               NOT NULL DEFAULT 'queued',
    mutation_effect            ENUM('pending', 'changed', 'noop', 'unknown')
                               NOT NULL DEFAULT 'pending',
    reroute_id                 BIGINT UNSIGNED NULL,
    failure_reason             TEXT NULL,
    created_at                 TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                 TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                               ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_bundle_action_position (bundle_id, position),
    KEY idx_bundle_actions_device_state (device_id, state),
    KEY idx_bundle_actions_reroute (reroute_id),
    CONSTRAINT fk_bundle_actions_bundle FOREIGN KEY (bundle_id)
        REFERENCES reroute_bundles (id) ON DELETE CASCADE,
    CONSTRAINT fk_bundle_actions_device FOREIGN KEY (device_id)
        REFERENCES devices (id) ON DELETE RESTRICT,
    CONSTRAINT fk_bundle_actions_reroute FOREIGN KEY (reroute_id)
        REFERENCES reroutes (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Controller-wide ownership of a device's configuration channel.  There is one
-- row per device and no time-based expiry: a crash after write intent must keep
-- the device quarantined until startup recovery or an administrator resolves it.
CREATE TABLE IF NOT EXISTS device_change_windows (
    device_id       BIGINT UNSIGNED NOT NULL,
    bundle_id       BIGINT UNSIGNED NULL,
    reroute_id      BIGINT UNSIGNED NULL,
    owner_token     VARCHAR(64) NOT NULL,
    phase           ENUM('prepared', 'applying', 'compensating', 'uncertain')
                    NOT NULL DEFAULT 'prepared',
    acquired_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                    ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (device_id),
    KEY idx_device_change_window_owner (owner_token),
    KEY idx_device_change_windows_bundle (bundle_id),
    KEY idx_device_change_windows_reroute (reroute_id),
    CONSTRAINT fk_device_change_windows_device FOREIGN KEY (device_id)
        REFERENCES devices (id) ON DELETE RESTRICT,
    CONSTRAINT fk_device_change_windows_bundle FOREIGN KEY (bundle_id)
        REFERENCES reroute_bundles (id) ON DELETE RESTRICT,
    CONSTRAINT fk_device_change_windows_reroute FOREIGN KEY (reroute_id)
        REFERENCES reroutes (id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
