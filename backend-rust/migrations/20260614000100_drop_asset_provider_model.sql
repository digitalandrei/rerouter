-- Drop the vestigial asset/provider model. The product is device/interface +
-- device_cli/SSH; the abstract "protected asset" + "reroute provider" layer was
-- never used by the live path (its API + adapters were already removed). This
-- removes the orphaned tables and the now-unused asset_id/provider_id columns on
-- the live tables (rules/reroutes/rule_events/alerts/alert_subscriptions/audit_logs).
-- Verified against the live schema; constraint/index names are exact.

-- 1. Drop the foreign keys from LIVE tables to the vestigial parents.
ALTER TABLE rules               DROP FOREIGN KEY fk_rules_asset;
ALTER TABLE reroutes            DROP FOREIGN KEY fk_reroutes_asset;
ALTER TABLE reroutes            DROP FOREIGN KEY fk_reroutes_provider;
ALTER TABLE rule_events         DROP FOREIGN KEY fk_rule_events_asset;
ALTER TABLE alerts              DROP FOREIGN KEY fk_alerts_asset;
ALTER TABLE alert_subscriptions DROP FOREIGN KEY fk_alert_subscriptions_asset;

-- 2. Drop the composite index (single-column indexes auto-drop with their column).
ALTER TABLE reroutes DROP INDEX idx_reroutes_asset_state;

-- 3. Drop the now-orphaned columns.
ALTER TABLE rules               DROP COLUMN asset_id;
ALTER TABLE reroutes            DROP COLUMN asset_id;
ALTER TABLE reroutes            DROP COLUMN provider_id;
ALTER TABLE rule_events         DROP COLUMN asset_id;
ALTER TABLE alerts              DROP COLUMN asset_id;
ALTER TABLE alert_subscriptions DROP COLUMN asset_id;
ALTER TABLE audit_logs          DROP COLUMN asset_id;

-- 4. Drop the vestigial tables (children of protected_assets/reroute_providers first).
DROP TABLE IF EXISTS asset_provider;
DROP TABLE IF EXISTS asset_statuses;
DROP TABLE IF EXISTS asset_metrics_current;
DROP TABLE IF EXISTS traffic_samples;
DROP TABLE IF EXISTS provider_credentials;
DROP TABLE IF EXISTS reroute_providers;
DROP TABLE IF EXISTS protected_assets;
