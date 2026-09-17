-- Named action sets are definitions, never execution authority. Every execution
-- gets its own immutable, actor-bound snapshot and must pass the live gates.
CREATE TABLE IF NOT EXISTS mitigation_presets (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(191) NOT NULL,
    description TEXT NULL,
    revision BIGINT UNSIGNED NOT NULL DEFAULT 1,
    archived_at DATETIME NULL,
    created_by BIGINT UNSIGNED NULL,
    updated_by BIGINT UNSIGNED NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_mitigation_presets_name (name),
    CONSTRAINT fk_mitigation_presets_creator FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT fk_mitigation_presets_editor FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS mitigation_preset_actions (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    preset_id BIGINT UNSIGNED NOT NULL,
    reroute_template_id BIGINT UNSIGNED NOT NULL,
    device_id BIGINT UNSIGNED NOT NULL,
    params_json JSON NOT NULL,
    enabled TINYINT(1) NOT NULL DEFAULT 1,
    position INT UNSIGNED NOT NULL,
    UNIQUE KEY uq_mitigation_preset_position (preset_id, position),
    CONSTRAINT fk_mitigation_preset_action_parent FOREIGN KEY (preset_id) REFERENCES mitigation_presets(id) ON DELETE RESTRICT,
    CONSTRAINT fk_mitigation_preset_action_template FOREIGN KEY (reroute_template_id) REFERENCES reroute_templates(id) ON DELETE RESTRICT,
    CONSTRAINT fk_mitigation_preset_action_device FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS execution_plans (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    scope VARCHAR(64) NOT NULL,
    scope_id BIGINT UNSIGNED NULL,
    reason TEXT NOT NULL,
    snapshot_json JSON NOT NULL,
    plan_hash CHAR(64) NOT NULL,
    token_hash CHAR(64) NOT NULL,
    expires_at DATETIME NOT NULL,
    consumed_at DATETIME NULL,
    bundle_id BIGINT UNSIGNED NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_execution_plans_token (token_hash),
    UNIQUE KEY uq_execution_plans_bundle (bundle_id),
    KEY idx_execution_plans_actor (user_id, created_at),
    CONSTRAINT fk_execution_plans_actor FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT,
    CONSTRAINT fk_execution_plans_bundle FOREIGN KEY (bundle_id) REFERENCES reroute_bundles(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET @rrt_exists := (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'rules' AND column_name = 'actions_revision');
SET @rrt_ddl := IF(@rrt_exists = 0, 'ALTER TABLE rules ADD COLUMN actions_revision BIGINT UNSIGNED NOT NULL DEFAULT 1', 'DO 0');
PREPARE rrt_migration FROM @rrt_ddl; EXECUTE rrt_migration; DEALLOCATE PREPARE rrt_migration;

SET @rrt_exists := (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'reroute_bundles' AND column_name = 'source_json');
SET @rrt_ddl := IF(@rrt_exists = 0, 'ALTER TABLE reroute_bundles ADD COLUMN source_json JSON NULL', 'DO 0');
PREPARE rrt_migration FROM @rrt_ddl; EXECUTE rrt_migration; DEALLOCATE PREPARE rrt_migration;
