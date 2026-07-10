-- Reject replay of an already accepted TOTP time step. The authentication path
-- compares and advances this counter under SELECT ... FOR UPDATE.
ALTER TABLE users
    ADD COLUMN last_totp_step BIGINT UNSIGNED NULL AFTER two_factor_enrollment_token_hash;
