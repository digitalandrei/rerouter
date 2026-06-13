-- Rule -> action targets. A fired rule's mitigation is one or more actions, each
-- = (template, target router, params). Lets a rule fan out the same mitigation
-- to several routers (operator-selected), each with its own params (the scrubber
-- neighbor IP differs per ASR). Render-only in milestone 3; the manual executor
-- (milestone 3 stage 4) and automatic execution (milestone 4) consume these.
CREATE TABLE IF NOT EXISTS rule_actions (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    rule_id             BIGINT UNSIGNED NOT NULL,
    reroute_template_id BIGINT UNSIGNED NOT NULL,
    device_id           BIGINT UNSIGNED NOT NULL,
    params_json         JSON            NULL,
    position            INT UNSIGNED    NOT NULL DEFAULT 0,
    enabled             TINYINT(1)      NOT NULL DEFAULT 1,
    created_at          TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_rule_actions_rule (rule_id),
    CONSTRAINT fk_rule_actions_rule FOREIGN KEY (rule_id) REFERENCES rules (id) ON DELETE CASCADE,
    CONSTRAINT fk_rule_actions_template FOREIGN KEY (reroute_template_id) REFERENCES reroute_templates (id) ON DELETE CASCADE,
    CONSTRAINT fk_rule_actions_device FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
