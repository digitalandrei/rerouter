-- Keep authentication throttling and routine expiry cleanup index-backed as the
-- append-only audit/safety tables grow.

ALTER TABLE audit_logs
    ADD KEY idx_audit_logs_ip_event_created (ip_address, event_type, created_at);

ALTER TABLE cooldowns
    ADD KEY idx_cooldowns_until (`until`);
