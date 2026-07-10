-- Device writes are gated by manage_devices. These provider/asset-era names have
-- no marker, handler, or frontend check and therefore grant no capability.
DELETE FROM permissions
WHERE name IN ('edit_asset', 'edit_provider', 'edit_credentials', 'view_credentials_metadata');
