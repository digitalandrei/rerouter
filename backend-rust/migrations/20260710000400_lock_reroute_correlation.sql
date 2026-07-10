-- Safety-induced device locks belong to one uncertain reroute. Linking them
-- prevents acknowledgement from clearing an unrelated manual/device lock.

ALTER TABLE locks
    ADD COLUMN reroute_id BIGINT UNSIGNED NULL AFTER scope_ref,
    ADD KEY idx_locks_reroute (reroute_id),
    ADD CONSTRAINT fk_locks_reroute
        FOREIGN KEY (reroute_id) REFERENCES reroutes (id) ON DELETE SET NULL;
