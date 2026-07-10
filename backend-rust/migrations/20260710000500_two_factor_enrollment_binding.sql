-- A temporary password alone must not let its holder claim an unconfirmed
-- account's authenticator. The administrator delivers this independent,
-- high-entropy enrollment code out of band; only its SHA-256 hash is stored.

ALTER TABLE users
    ADD COLUMN two_factor_enrollment_token_hash CHAR(64) NULL
        AFTER two_factor_confirmed_at;
