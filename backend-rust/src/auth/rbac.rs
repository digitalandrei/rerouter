//! RBAC: explicit roles / permissions / role_user / permission_role tables
//! (see migrations/20260612000100_users_and_auth.sql and ../docs/security.md).
//! Roles: admin, operator, viewer, auditor. Authorization happens at the API
//! boundary in this process — there is no other tier to rely on.

use anyhow::Result;
use sqlx::MySqlPool;

use super::sessions::Session;

/// The full permission list (mirrors the `permissions` seed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    ViewDashboard,
    ViewAsset,
    EditAsset,
    EditProvider,
    EditCredentials,
    ViewCredentialsMetadata,
    EditRules,
    TriggerManualReroute,
    ApproveDangerousReroute,
    AcknowledgeUncertainReroute,
    ManageLocks,
    ManageAlerts,
    ViewAudit,
    ManageUsers,
}

impl Permission {
    pub fn as_str(self) -> &'static str {
        match self {
            Permission::ViewDashboard => "view_dashboard",
            Permission::ViewAsset => "view_asset",
            Permission::EditAsset => "edit_asset",
            Permission::EditProvider => "edit_provider",
            Permission::EditCredentials => "edit_credentials",
            Permission::ViewCredentialsMetadata => "view_credentials_metadata",
            Permission::EditRules => "edit_rules",
            Permission::TriggerManualReroute => "trigger_manual_reroute",
            Permission::ApproveDangerousReroute => "approve_dangerous_reroute",
            Permission::AcknowledgeUncertainReroute => "acknowledge_uncertain_reroute",
            Permission::ManageLocks => "manage_locks",
            Permission::ManageAlerts => "manage_alerts",
            Permission::ViewAudit => "view_audit",
            Permission::ManageUsers => "manage_users",
        }
    }
}

/// Does the session's user hold `permission` through any of their roles?
/// Handlers call this (or the wrapping extractor) BEFORE doing anything;
/// denials are audited. Deny by default.
pub async fn has_permission(_pool: &MySqlPool, _session: &Session, _permission: Permission) -> Result<bool> {
    // TODO(milestone 1): SELECT 1 FROM role_user JOIN permission_role JOIN
    // permissions ... ; small per-session cache is fine, invalidated on role
    // changes.
    Ok(false)
}

/// Re-auth freshness gate for high-safety reroutes: a recent password+TOTP
/// confirmation (sessions.reauth_at) is required IN ADDITION to the permission
/// check and the typed confirmation + reason. See ../docs/security.md.
pub fn reauth_is_fresh(session: &Session, max_age_secs: i64) -> bool {
    session
        .reauth_at
        .map(|t| (chrono::Utc::now() - t).num_seconds() <= max_age_secs)
        .unwrap_or(false)
}

// TODO(milestone 1): `RequirePermission` extractor so handlers can declare
// their permission in the signature instead of calling has_permission inline.
