-- Per-interval error counts on interface_samples so the device-detail page can
-- chart errors in/out over the last hour alongside bps/pps. These are the DELTA
-- (errors seen during the sample interval), derived from the cumulative ifTable
-- error counters — not the cumulative value. Additive.

ALTER TABLE interface_samples
    ADD COLUMN in_errors  BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER tx_util_percent,
    ADD COLUMN out_errors BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER in_errors;
