-- Detection rule features:
--   * Cross-interface (and cross-device) rx/tx summation: a rule can threshold
--     the SUM of a metric across a configured set of interfaces. `sum` rules have
--     NULL interface_id/device_id and list their members in rule_interfaces.
--   * Interface error-rate metrics (in_err_rate / out_err_rate, errors/sec),
--     derived in the SNMP poll like the bps/pps rates.

-- 1. Aggregation mode on rules. 'single' = the existing per-interface rule;
--    'sum' = threshold the summed metric over rule_interfaces members.
ALTER TABLE rules
    ADD COLUMN metric_aggregation ENUM('single', 'sum') NOT NULL DEFAULT 'single' AFTER metric;

-- 2. Member interfaces of a `sum` rule (may span devices). device_id is carried
--    for display/scoping; the pair (rule_id, interface_id) is unique.
CREATE TABLE IF NOT EXISTS rule_interfaces (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    rule_id       BIGINT UNSIGNED NOT NULL,
    device_id     BIGINT UNSIGNED NOT NULL,
    interface_id  BIGINT UNSIGNED NOT NULL,
    created_at    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_rule_interface (rule_id, interface_id),
    KEY idx_rule_interfaces_rule (rule_id),
    CONSTRAINT fk_rule_interfaces_rule FOREIGN KEY (rule_id) REFERENCES rules (id) ON DELETE CASCADE,
    CONSTRAINT fk_rule_interfaces_device FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE,
    CONSTRAINT fk_rule_interfaces_interface FOREIGN KEY (interface_id) REFERENCES device_interfaces (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. Derived interface error rates (errors/sec over the poll interval), computed
--    from the cumulative ifInErrors/ifOutErrors deltas. Invalidated on counter
--    wrap (rate 0), like the bps/pps rates. Read by error-rate detection rules.
ALTER TABLE interface_metrics_current
    ADD COLUMN in_err_rate  DOUBLE NOT NULL DEFAULT 0 AFTER out_discards,
    ADD COLUMN out_err_rate DOUBLE NOT NULL DEFAULT 0 AFTER in_err_rate;
