-- SSH access for onboarded devices. Routers are enrolled with SNMP (read-only
-- telemetry) AND SSH credentials, captured now so the future reroute/remediation
-- actions (which run Cisco CLI over SSH) have what they need. SSH is NOT used in
-- observe mode — these credentials are stored, encrypted, and idle until enforce
-- mode and the SSH action engine land. See docs/device-enrollment.md.
--
-- Auth is password XOR key (operator picks one per device, "for now"). All secret
-- material is AES-256-GCM ciphertext (key from SECRETS_KEY); only ciphertext is
-- stored and none of it is ever returned by the API. Additive migration.

ALTER TABLE devices
    ADD COLUMN ssh_username                 VARCHAR(128)     NULL AFTER v3_priv_key_encrypted,
    ADD COLUMN ssh_port                     SMALLINT UNSIGNED NOT NULL DEFAULT 22 AFTER ssh_username,
    -- which credential the controller will present over SSH: password XOR key.
    ADD COLUMN ssh_auth_method              ENUM('password', 'key') NULL AFTER ssh_port,
    -- AES-256-GCM ciphertext (nullable; only one of password/key is set).
    ADD COLUMN ssh_password_encrypted       VARBINARY(1024)  NULL AFTER ssh_auth_method,
    ADD COLUMN ssh_private_key_encrypted    VARBINARY(8192)  NULL AFTER ssh_password_encrypted,
    ADD COLUMN ssh_key_passphrase_encrypted VARBINARY(1024)  NULL AFTER ssh_private_key_encrypted,
    -- pinned at enrollment; a later change fails closed (doctrine §8 SSH host
    -- verification). Stored plain (it is a public fingerprint, not a secret).
    ADD COLUMN ssh_host_fingerprint         VARCHAR(255)     NULL AFTER ssh_key_passphrase_encrypted;
