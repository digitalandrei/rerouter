-- Standalone created_at indexes to support the retention cleanup task.
--
-- retention_cleanup deletes `WHERE created_at < now - INTERVAL ? DAY` from alerts
-- and rule_events. Both tables only have composite indexes led by another column
-- (idx_alerts_event_created / idx_rule_events_rule_created), which cannot serve a
-- bare created_at range — so without these the prune would table-scan and grow
-- more costly as the tables fill. Alerts were previously never pruned; both are
-- now bounded (default 7 days: [retention].alerts_days / rule_events_days).

ALTER TABLE alerts
    ADD KEY idx_alerts_created (created_at);

ALTER TABLE rule_events
    ADD KEY idx_rule_events_created (created_at);
