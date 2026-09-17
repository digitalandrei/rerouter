-- Metric-specific evidence. A traffic sample may be valid while an independent
-- error/status walk is missing; missing flow counters are unknown, not zero.

ALTER TABLE interface_metrics_current
    ADD COLUMN in_errors_sampled_at TIMESTAMP NULL DEFAULT NULL AFTER in_errors,
    ADD COLUMN out_errors_sampled_at TIMESTAMP NULL DEFAULT NULL AFTER out_errors,
    ADD COLUMN in_discards_sampled_at TIMESTAMP NULL DEFAULT NULL AFTER in_discards,
    ADD COLUMN out_discards_sampled_at TIMESTAMP NULL DEFAULT NULL AFTER out_discards,
    ADD COLUMN in_err_rate_valid TINYINT(1) NOT NULL DEFAULT 0 AFTER in_err_rate,
    ADD COLUMN out_err_rate_valid TINYINT(1) NOT NULL DEFAULT 0 AFTER out_err_rate,
    ADD COLUMN oper_status_valid TINYINT(1) NOT NULL DEFAULT 0 AFTER oper_status;

ALTER TABLE interface_samples
    ADD COLUMN in_errors_valid TINYINT(1) NOT NULL DEFAULT 0 AFTER in_errors,
    ADD COLUMN out_errors_valid TINYINT(1) NOT NULL DEFAULT 0 AFTER out_errors,
    ADD COLUMN in_discards_valid TINYINT(1) NOT NULL DEFAULT 0 AFTER in_discards,
    ADD COLUMN out_discards_valid TINYINT(1) NOT NULL DEFAULT 0 AFTER out_discards;

ALTER TABLE flow_iface_buckets
    ADD COLUMN pkts_available TINYINT(1) NOT NULL DEFAULT 0 AFTER pkts,
    ADD COLUMN bytes_available TINYINT(1) NOT NULL DEFAULT 0 AFTER bytes;

ALTER TABLE flow_port_buckets
    ADD COLUMN pkts_available TINYINT(1) NOT NULL DEFAULT 0 AFTER pkts,
    ADD COLUMN bytes_available TINYINT(1) NOT NULL DEFAULT 0 AFTER bytes;

ALTER TABLE flow_as_buckets
    ADD COLUMN pkts_available TINYINT(1) NOT NULL DEFAULT 0 AFTER pkts,
    ADD COLUMN bytes_available TINYINT(1) NOT NULL DEFAULT 0 AFTER bytes;

ALTER TABLE flow_talker_buckets
    ADD COLUMN pkts_available TINYINT(1) NOT NULL DEFAULT 0 AFTER pkts,
    ADD COLUMN bytes_available TINYINT(1) NOT NULL DEFAULT 0 AFTER bytes;
