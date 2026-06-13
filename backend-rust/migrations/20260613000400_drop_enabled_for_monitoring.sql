-- Remove the per-interface "monitor" toggle entirely. Every discovered interface
-- is polled and chartable, and detection rules target interfaces directly, so the
-- flag no longer gated anything. Drop it (and its index).
ALTER TABLE device_interfaces
    DROP INDEX idx_device_interfaces_monitored,
    DROP COLUMN enabled_for_monitoring;
