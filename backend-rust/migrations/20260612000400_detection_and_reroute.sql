-- Detection rules + the reroute engine tables.
-- See docs/detection-engine.md, docs/reroute-engine.md, docs/state-recovery.md.
--
-- SAFETY invariants encoded here:
--   * rules.automatic_reroute_enabled defaults to 0 (per-rule opt-in; the global
--     switch lives in system_settings.automatic_actions_enabled, also off);
--   * reroute_templates are the ONLY way a reroute can happen (parameter schema,
--     no free text);
--   * reroutes.state follows planned -> pending -> running -> verifying ->
--     {succeeded, failed, uncertain}; never trust "sent" as success.

CREATE TABLE IF NOT EXISTS reroute_templates (
    id                              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    name                            VARCHAR(191)    NOT NULL,
    description                     TEXT            NULL,
    provider_type                   ENUM('cloudflare', 'bgp_rtbh', 'flowspec', 'scrubber') NOT NULL,
    mode                            VARCHAR(64)     NOT NULL,
    safety_level                    ENUM('low', 'medium', 'high') NOT NULL,
    automatic_allowed               TINYINT(1)      NOT NULL DEFAULT 0,
    manual_confirmation_required    TINYINT(1)      NOT NULL DEFAULT 1,
    parameter_schema_json           JSON            NULL,
    plan_json                       JSON            NULL,
    verification_json               JSON            NULL,
    rollback_template_id            BIGINT UNSIGNED NULL,
    auto_expiry_seconds             INT UNSIGNED    NULL,
    enabled                         TINYINT(1)      NOT NULL DEFAULT 1,
    created_at                      TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                      TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_reroute_templates_name (name),
    KEY idx_reroute_templates_rollback (rollback_template_id),
    CONSTRAINT fk_reroute_templates_rollback FOREIGN KEY (rollback_template_id) REFERENCES reroute_templates (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS rules (
    id                          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    asset_id                    BIGINT UNSIGNED NOT NULL,
    name                        VARCHAR(191)    NOT NULL,
    metric                      VARCHAR(64)     NOT NULL,
    operator                    VARCHAR(16)     NOT NULL,
    threshold_value             DOUBLE          NOT NULL,
    threshold_unit              VARCHAR(32)     NULL,
    duration_seconds            INT UNSIGNED    NOT NULL DEFAULT 30,
    consecutive_samples         INT UNSIGNED    NOT NULL DEFAULT 3,
    severity                    VARCHAR(32)     NOT NULL DEFAULT 'warning',
    schedule_json               JSON            NULL,
    enabled                     TINYINT(1)      NOT NULL DEFAULT 1,
    automatic_reroute_enabled   TINYINT(1)      NOT NULL DEFAULT 0,
    reroute_template_id         BIGINT UNSIGNED NULL,
    alert_enabled               TINYINT(1)      NOT NULL DEFAULT 1,
    cooldown_seconds            INT UNSIGNED    NULL,
    created_by                  BIGINT UNSIGNED NULL,
    updated_by                  BIGINT UNSIGNED NULL,
    created_at                  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_rules_asset (asset_id),
    KEY idx_rules_template (reroute_template_id),
    CONSTRAINT fk_rules_asset FOREIGN KEY (asset_id) REFERENCES protected_assets (id) ON DELETE CASCADE,
    CONSTRAINT fk_rules_template FOREIGN KEY (reroute_template_id) REFERENCES reroute_templates (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS reroutes (
    id                      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    asset_id                BIGINT UNSIGNED NOT NULL,
    provider_id             BIGINT UNSIGNED NULL,
    rule_id                 BIGINT UNSIGNED NULL,
    reroute_template_id     BIGINT UNSIGNED NULL,
    trigger_type            ENUM('automatic', 'manual', 'rollback') NOT NULL,
    triggered_by_user_id    BIGINT UNSIGNED NULL,
    state                   ENUM('planned', 'pending', 'running', 'verifying', 'succeeded', 'failed', 'uncertain') NOT NULL DEFAULT 'planned',
    safety_level            ENUM('low', 'medium', 'high') NOT NULL,
    reason                  TEXT            NULL,
    parameters_json         JSON            NULL,
    planned_steps_json      JSON            NULL,
    started_at              TIMESTAMP       NULL DEFAULT NULL,
    finished_at             TIMESTAMP       NULL DEFAULT NULL,
    success                 TINYINT(1)      NULL,
    failure_reason          TEXT            NULL,
    verification_status     VARCHAR(32)     NULL,
    expires_at              TIMESTAMP       NULL DEFAULT NULL,
    cooldown_until          TIMESTAMP       NULL DEFAULT NULL,
    created_at              TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_reroutes_state (state),
    KEY idx_reroutes_asset_state (asset_id, state),
    KEY idx_reroutes_expires_at (expires_at),
    CONSTRAINT fk_reroutes_asset FOREIGN KEY (asset_id) REFERENCES protected_assets (id) ON DELETE CASCADE,
    CONSTRAINT fk_reroutes_provider FOREIGN KEY (provider_id) REFERENCES reroute_providers (id) ON DELETE SET NULL,
    CONSTRAINT fk_reroutes_rule FOREIGN KEY (rule_id) REFERENCES rules (id) ON DELETE SET NULL,
    CONSTRAINT fk_reroutes_template FOREIGN KEY (reroute_template_id) REFERENCES reroute_templates (id) ON DELETE SET NULL,
    CONSTRAINT fk_reroutes_user FOREIGN KEY (triggered_by_user_id) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS rule_states (
    rule_id                     BIGINT UNSIGNED NOT NULL,
    current_state               ENUM('clear', 'matching', 'firing') NOT NULL DEFAULT 'clear',
    first_matched_at            TIMESTAMP       NULL DEFAULT NULL,
    last_matched_at             TIMESTAMP       NULL DEFAULT NULL,
    last_cleared_at             TIMESTAMP       NULL DEFAULT NULL,
    consecutive_match_count     INT UNSIGNED    NOT NULL DEFAULT 0,
    last_metric_value           DOUBLE          NULL,
    last_evaluated_at           TIMESTAMP       NULL DEFAULT NULL,
    last_triggered_reroute_id   BIGINT UNSIGNED NULL,
    updated_at                  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (rule_id),
    KEY idx_rule_states_last_reroute (last_triggered_reroute_id),
    CONSTRAINT fk_rule_states_rule FOREIGN KEY (rule_id) REFERENCES rules (id) ON DELETE CASCADE,
    CONSTRAINT fk_rule_states_reroute FOREIGN KEY (last_triggered_reroute_id) REFERENCES reroutes (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS rule_events (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    rule_id         BIGINT UNSIGNED NOT NULL,
    asset_id        BIGINT UNSIGNED NOT NULL,
    event           ENUM('matched', 'fired', 'cleared') NOT NULL,
    metric_value    DOUBLE          NULL,
    sampled_at      TIMESTAMP       NULL DEFAULT NULL,
    created_at      TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_rule_events_rule_created (rule_id, created_at),
    KEY idx_rule_events_asset (asset_id),
    CONSTRAINT fk_rule_events_rule FOREIGN KEY (rule_id) REFERENCES rules (id) ON DELETE CASCADE,
    CONSTRAINT fk_rule_events_asset FOREIGN KEY (asset_id) REFERENCES protected_assets (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS reroute_steps (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    reroute_id  BIGINT UNSIGNED NOT NULL,
    step_number INT UNSIGNED    NOT NULL,
    description TEXT            NULL,
    mode        VARCHAR(64)     NULL,
    state       VARCHAR(32)     NOT NULL DEFAULT 'planned',
    PRIMARY KEY (id),
    UNIQUE KEY uq_reroute_steps_step (reroute_id, step_number),
    CONSTRAINT fk_reroute_steps_reroute FOREIGN KEY (reroute_id) REFERENCES reroutes (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS reroute_outputs (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    reroute_id  BIGINT UNSIGNED NOT NULL,
    step_number INT UNSIGNED    NOT NULL,
    request     MEDIUMTEXT      NULL,
    response    MEDIUMTEXT      NULL,
    status      VARCHAR(32)     NULL,
    started_at  TIMESTAMP       NULL DEFAULT NULL,
    finished_at TIMESTAMP       NULL DEFAULT NULL,
    created_at  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_reroute_outputs_reroute (reroute_id),
    CONSTRAINT fk_reroute_outputs_reroute FOREIGN KEY (reroute_id) REFERENCES reroutes (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS reroute_verifications (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    reroute_id  BIGINT UNSIGNED NOT NULL,
    method      VARCHAR(64)     NOT NULL,
    expected    TEXT            NULL,
    observed    TEXT            NULL,
    result      ENUM('pass', 'fail', 'uncertain') NOT NULL,
    checked_at  TIMESTAMP       NULL DEFAULT NULL,
    created_at  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_reroute_verifications_reroute (reroute_id),
    CONSTRAINT fk_reroute_verifications_reroute FOREIGN KEY (reroute_id) REFERENCES reroutes (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
