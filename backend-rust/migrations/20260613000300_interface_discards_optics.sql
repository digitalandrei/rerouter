-- Per-interval discard deltas + transceiver optics (DOM) on the telemetry tables.
-- Optics come from CISCO-ENTITY-SENSOR-MIB (temperature °C, Tx/Rx optical power
-- dBm); they are per-port and NULL for interfaces without a transceiver.

ALTER TABLE interface_samples
    ADD COLUMN in_discards   BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER out_errors,
    ADD COLUMN out_discards  BIGINT UNSIGNED NOT NULL DEFAULT 0 AFTER in_discards,
    ADD COLUMN temp_c        DOUBLE NULL AFTER out_discards,
    ADD COLUMN tx_power_dbm  DOUBLE NULL AFTER temp_c,
    ADD COLUMN rx_power_dbm  DOUBLE NULL AFTER tx_power_dbm;

ALTER TABLE interface_metrics_current
    ADD COLUMN temp_c        DOUBLE NULL AFTER out_discards,
    ADD COLUMN tx_power_dbm  DOUBLE NULL AFTER temp_c,
    ADD COLUMN rx_power_dbm  DOUBLE NULL AFTER tx_power_dbm;
