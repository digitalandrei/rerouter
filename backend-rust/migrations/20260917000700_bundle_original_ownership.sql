-- Recovery/rollback bundle actions point at the ORIGINAL mutation they intend
-- to close. Successful inverse reroutes are never themselves new mitigation
-- ownership and must not become compensation candidates.
ALTER TABLE reroute_bundle_actions
    ADD COLUMN original_reroute_id BIGINT UNSIGNED NULL AFTER source_rule_action_id,
    ADD KEY idx_bundle_actions_original (original_reroute_id),
    ADD CONSTRAINT fk_bundle_actions_original FOREIGN KEY (original_reroute_id)
        REFERENCES reroutes (id) ON DELETE RESTRICT;
