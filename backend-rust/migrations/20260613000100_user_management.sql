-- User management: a `superadmin` tier above `admin`, plus a `manage_devices`
-- permission that separates device ENROLLMENT from the rest of "edit" access.
--
-- Two-tier model the UI exposes:
--   superadmin : everything — incl. user management AND device enrollment.
--   admin      : full access EXCEPT user management and device enrollment;
--                CAN edit rules (and view everything, manage locks/alerts, etc.).
--
-- Additive + idempotent. The bootstrap admin (--create-admin) is a superadmin;
-- pre-existing 'admin' users are reduced to the new (narrower) admin scope.

INSERT IGNORE INTO roles (name, description) VALUES
    ('superadmin', 'full control including user management and device enrollment');

INSERT IGNORE INTO permissions (name) VALUES ('manage_devices');

-- superadmin holds every permission (current and future seeds).
INSERT IGNORE INTO permission_role (permission_id, role_id)
SELECT p.id, r.id FROM permissions p JOIN roles r ON r.name = 'superadmin';

-- admin LOSES user management and never receives device management; it keeps
-- edit_rules and everything else from the original seed.
DELETE pr FROM permission_role pr
    JOIN roles r ON r.id = pr.role_id
    JOIN permissions p ON p.id = pr.permission_id
    WHERE r.name = 'admin' AND p.name IN ('manage_users', 'manage_devices');
