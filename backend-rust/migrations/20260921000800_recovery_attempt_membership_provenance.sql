-- Record only the source/device quarantine memberships created by one recovery
-- attempt. A proven-no-write terminal attempt may restore that pre-claim state;
-- memberships that existed before the claim or belong to another source remain.
CREATE TABLE recovery_attempt_device_memberships (
    recovery_bundle_id BIGINT UNSIGNED NOT NULL,
    source_bundle_id BIGINT UNSIGNED NOT NULL,
    device_id BIGINT UNSIGNED NOT NULL,
    created_by_attempt TINYINT(1) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    released_at DATETIME NULL,
    PRIMARY KEY (recovery_bundle_id, source_bundle_id, device_id),
    KEY idx_recovery_attempt_membership_device (device_id, source_bundle_id),
    CONSTRAINT fk_recovery_attempt_membership_source
        FOREIGN KEY (recovery_bundle_id, source_bundle_id)
        REFERENCES recovery_attempt_sources(recovery_bundle_id, source_bundle_id)
        ON DELETE CASCADE,
    CONSTRAINT fk_recovery_attempt_membership_device
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE RESTRICT
) ENGINE=InnoDB;
