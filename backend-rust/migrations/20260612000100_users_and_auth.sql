-- Users, sessions, and explicit RBAC tables. Schema source of truth is this
-- directory (sqlx migrations); the reference description lives in
-- docs/database.md and docs/authentication.md.
--
-- users is created from scratch (the controller owns authentication):
--   * password           Argon2id PHC string
--   * two_factor_*       TOTP secret (encrypted via SECRETS_KEY), hashed
--                        single-use recovery codes, confirmation timestamp
--   * failed_login_attempts / locked_until   throttling + account lockout,
--                        keyed by email + real client IP (CF-Connecting-IP)

CREATE TABLE IF NOT EXISTS users (
    id                          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    name                        VARCHAR(191)    NOT NULL,
    email                       VARCHAR(191)    NOT NULL,
    password                    VARCHAR(255)    NOT NULL,
    two_factor_secret           TEXT            NULL,
    two_factor_recovery_codes   TEXT            NULL,
    two_factor_confirmed_at     TIMESTAMP       NULL DEFAULT NULL,
    two_factor_enforced         TINYINT(1)      NOT NULL DEFAULT 1,
    failed_login_attempts       INT UNSIGNED    NOT NULL DEFAULT 0,
    locked_until                TIMESTAMP       NULL DEFAULT NULL,
    last_login_at               TIMESTAMP       NULL DEFAULT NULL,
    last_login_ip               VARCHAR(45)     NULL,
    created_at                  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at                  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_users_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- DB-backed sessions; the cookie carries only the (signed) session token.
-- Token stored hashed so a DB read alone cannot hijack a session.
CREATE TABLE IF NOT EXISTS sessions (
    id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    token_hash      CHAR(64)        NOT NULL,
    user_id         BIGINT UNSIGNED NOT NULL,
    ip_address      VARCHAR(45)     NULL,
    user_agent      VARCHAR(512)    NULL,
    totp_verified   TINYINT(1)      NOT NULL DEFAULT 0,
    reauth_at       TIMESTAMP       NULL DEFAULT NULL,  -- fresh password+TOTP for high-safety reroutes
    last_activity_at TIMESTAMP      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at      TIMESTAMP       NOT NULL,
    created_at      TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_sessions_token_hash (token_hash),
    KEY idx_sessions_user_id (user_id),
    KEY idx_sessions_expires_at (expires_at),
    CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS roles (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    name        VARCHAR(64)     NOT NULL,
    description VARCHAR(255)    NULL,
    created_at  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_roles_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS permissions (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    name        VARCHAR(64)     NOT NULL,
    created_at  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_permissions_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS role_user (
    role_id     BIGINT UNSIGNED NOT NULL,
    user_id     BIGINT UNSIGNED NOT NULL,
    created_at  TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id, user_id),
    KEY idx_role_user_user (user_id),
    CONSTRAINT fk_role_user_role FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE,
    CONSTRAINT fk_role_user_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS permission_role (
    permission_id BIGINT UNSIGNED NOT NULL,
    role_id       BIGINT UNSIGNED NOT NULL,
    created_at    TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (permission_id, role_id),
    KEY idx_permission_role_role (role_id),
    CONSTRAINT fk_permission_role_permission FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE CASCADE,
    CONSTRAINT fk_permission_role_role FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Idempotent seeds (INSERT IGNORE keyed on the unique names).

INSERT IGNORE INTO roles (name, description) VALUES
    ('admin',    'full control, user management, dangerous-action approval'),
    ('operator', 'trigger manual reroutes, manage rules, acknowledge uncertain'),
    ('viewer',   'read-only dashboards and data'),
    ('auditor',  'read audit logs and configuration, no changes');

INSERT IGNORE INTO permissions (name) VALUES
    ('view_dashboard'),
    ('view_asset'),
    ('edit_asset'),
    ('edit_provider'),
    ('edit_credentials'),
    ('view_credentials_metadata'),
    ('edit_rules'),
    ('trigger_manual_reroute'),
    ('approve_dangerous_reroute'),
    ('acknowledge_uncertain_reroute'),
    ('manage_locks'),
    ('manage_alerts'),
    ('view_audit'),
    ('manage_users');

-- admin: every permission.
INSERT IGNORE INTO permission_role (permission_id, role_id)
SELECT p.id, r.id FROM permissions p JOIN roles r ON r.name = 'admin';

-- operator: operate the system, but no user management / credential editing.
INSERT IGNORE INTO permission_role (permission_id, role_id)
SELECT p.id, r.id FROM permissions p JOIN roles r ON r.name = 'operator'
WHERE p.name IN (
    'view_dashboard', 'view_asset', 'edit_asset', 'edit_provider',
    'view_credentials_metadata', 'edit_rules', 'trigger_manual_reroute',
    'acknowledge_uncertain_reroute', 'manage_locks', 'manage_alerts'
);

-- viewer: read-only.
INSERT IGNORE INTO permission_role (permission_id, role_id)
SELECT p.id, r.id FROM permissions p JOIN roles r ON r.name = 'viewer'
WHERE p.name IN ('view_dashboard', 'view_asset');

-- auditor: read audit logs and configuration, no changes.
INSERT IGNORE INTO permission_role (permission_id, role_id)
SELECT p.id, r.id FROM permissions p JOIN roles r ON r.name = 'auditor'
WHERE p.name IN ('view_dashboard', 'view_asset', 'view_credentials_metadata', 'view_audit');
