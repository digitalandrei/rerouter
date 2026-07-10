-- Enforce-mode manual execution must be bound to the exact server-rendered plan
-- the operator just reviewed. Tokens are random, stored hashed, short-lived, and
-- consumed atomically once.

CREATE TABLE action_previews (
    token_hash   CHAR(64)        NOT NULL,
    user_id      BIGINT UNSIGNED NOT NULL,
    scope        VARCHAR(32)     NOT NULL,
    scope_id     BIGINT UNSIGNED NULL,
    plan_hash    CHAR(64)        NOT NULL,
    expires_at   TIMESTAMP       NOT NULL,
    used_at      TIMESTAMP       NULL DEFAULT NULL,
    created_at   TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (token_hash),
    KEY idx_action_previews_expiry (expires_at),
    CONSTRAINT fk_action_previews_user
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
