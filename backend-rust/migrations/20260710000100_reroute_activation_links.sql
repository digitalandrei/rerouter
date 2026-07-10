-- Correlate every automatic reroute with the exact rule firing that created it,
-- and every rollback attempt with the reroute it is intended to reverse.
--
-- These links make recovery idempotent: it can use the persisted, fully-resolved
-- parameters of actions that actually succeeded and can skip an original action
-- once a verified rollback exists.

ALTER TABLE reroutes
    ADD COLUMN rule_event_id BIGINT UNSIGNED NULL AFTER rule_id,
    ADD COLUMN rollback_of_reroute_id BIGINT UNSIGNED NULL AFTER reroute_template_id,
    ADD KEY idx_reroutes_rule_event (rule_event_id),
    ADD KEY idx_reroutes_rollback_of (rollback_of_reroute_id),
    ADD CONSTRAINT fk_reroutes_rule_event
        FOREIGN KEY (rule_event_id) REFERENCES rule_events (id) ON DELETE SET NULL,
    ADD CONSTRAINT fk_reroutes_rollback_of
        FOREIGN KEY (rollback_of_reroute_id) REFERENCES reroutes (id) ON DELETE SET NULL;
