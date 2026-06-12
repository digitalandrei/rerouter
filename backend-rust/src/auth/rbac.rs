//! RBAC: explicit roles / permissions / role_user / permission_role tables
//! (see migrations/20260612000100_users_and_auth.sql and ../docs/security.md).
//! Roles: admin, operator, viewer, auditor. Authorization happens at the API
//! boundary in this process — there is no other tier to rely on. Deny by default.

use anyhow::{Context, Result};
use axum::extract::FromRequestParts;
use axum::http::{request::Parts, StatusCode};
use serde_json::{json, Value};
use sqlx::MySqlPool;

use super::sessions::Session;
use crate::api::AppState;

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
/// Deny by default — any DB error returns false.
pub async fn has_permission(pool: &MySqlPool, session: &Session, permission: Permission) -> Result<bool> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM role_user ru \
         JOIN permission_role pr ON pr.role_id = ru.role_id \
         JOIN permissions p ON p.id = pr.permission_id \
         WHERE ru.user_id = ? AND p.name = ?",
    )
    .bind(session.user_id)
    .bind(permission.as_str())
    .fetch_one(pool)
    .await
    .context("checking permission")?;
    Ok(count > 0)
}

/// True if the user holds the admin role (critical-event fan-out, mode flips).
pub async fn is_admin(pool: &MySqlPool, user_id: u64) -> Result<bool> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM role_user ru JOIN roles r ON r.id = ru.role_id \
         WHERE ru.user_id = ? AND r.name = 'admin'",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .context("checking admin role")?;
    Ok(count > 0)
}

/// The roles + permissions for a user.
pub async fn roles_and_permissions(pool: &MySqlPool, user_id: u64) -> Result<(Vec<String>, Vec<String>)> {
    let roles: Vec<String> = sqlx::query_scalar(
        "SELECT r.name FROM role_user ru JOIN roles r ON r.id = ru.role_id WHERE ru.user_id = ? ORDER BY r.name",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .context("loading roles")?;

    let perms: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT p.name FROM role_user ru \
         JOIN permission_role pr ON pr.role_id = ru.role_id \
         JOIN permissions p ON p.id = pr.permission_id \
         WHERE ru.user_id = ? ORDER BY p.name",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .context("loading permissions")?;

    Ok((roles, perms))
}

/// Build the SessionUser JSON {id,email,name,roles[],permissions[]} for /me and
/// the post-2FA login response.
pub async fn load_session_user(pool: &MySqlPool, user_id: u64) -> Result<Value> {
    let (id, email, name) = sqlx::query_as::<_, (u64, String, String)>(
        "SELECT id, email, name FROM users WHERE id = ?",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .context("loading user")?;
    let (roles, permissions) = roles_and_permissions(pool, user_id).await?;
    Ok(json!({ "id": id, "email": email, "name": name, "roles": roles, "permissions": permissions }))
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

/// Generic permission-gated extractor: `RequirePermission::<EditRules>` in a
/// handler signature both authenticates (valid session) and authorizes (holds
/// the permission), rejecting with 401/403 before the body runs. The marker type
/// names the permission via the [`PermissionMarker`] trait.
pub struct RequirePermission<P: PermissionMarker> {
    pub session: Session,
    _marker: std::marker::PhantomData<P>,
}

/// Trait implemented by zero-sized marker types naming a [`Permission`].
pub trait PermissionMarker {
    const PERMISSION: Permission;
}

impl<P: PermissionMarker> FromRequestParts<AppState> for RequirePermission<P> {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let session = Session::from_request_parts(parts, state).await?;
        match has_permission(&state.pool, &session, P::PERMISSION).await {
            Ok(true) => Ok(RequirePermission { session, _marker: std::marker::PhantomData }),
            Ok(false) => Err((StatusCode::FORBIDDEN, "forbidden")),
            Err(_) => Err((StatusCode::INTERNAL_SERVER_ERROR, "authz check failed")),
        }
    }
}

/// Marker types for the permissions used by API write handlers.
pub mod markers {
    use super::{Permission, PermissionMarker};

    macro_rules! marker {
        ($name:ident => $perm:expr) => {
            pub struct $name;
            impl PermissionMarker for $name {
                const PERMISSION: Permission = $perm;
            }
        };
    }
    marker!(EditAsset => Permission::EditAsset);
    marker!(ViewAsset => Permission::ViewAsset);
    marker!(EditRules => Permission::EditRules);
    marker!(ManageAlerts => Permission::ManageAlerts);
    marker!(ManageUsers => Permission::ManageUsers);
    marker!(ManageLocks => Permission::ManageLocks);
    marker!(ViewDashboard => Permission::ViewDashboard);
    marker!(ViewAudit => Permission::ViewAudit);
}
