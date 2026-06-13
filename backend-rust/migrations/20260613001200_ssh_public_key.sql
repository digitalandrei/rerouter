-- Store the SSH client public key alongside the (encrypted) private key so the
-- UI can ALWAYS show it for enrollment on the router (`ip ssh pubkey-chain`).
-- The public key is not a secret — it is stored in plaintext and returned by the
-- API, unlike the private key / passphrase which stay AES-256-GCM ciphertext.
--
-- Populated when a key is generated in-app (POST /devices/{id}/ssh-generate-key)
-- or derived from a pasted private key on update. Additive, nullable migration.

ALTER TABLE devices
    ADD COLUMN ssh_public_key TEXT NULL AFTER ssh_host_fingerprint;
