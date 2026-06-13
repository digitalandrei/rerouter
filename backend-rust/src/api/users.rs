//! User management — superadmin-only (`manage_users`). List/create/update/delete
//! operator accounts and reset their 2FA. Two-tier model: `superadmin` (full,
//! incl. user + device management) vs `admin` (full minus those; can edit rules).
//! See ../docs/security.md. Every change is audited.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{err, AppState};
use crate::auth::password;
use crate::auth::rbac::{markers, RequirePermission};

type JsonResp = (StatusCode, Json<Value>);

/// Roles assignable from the user-management UI.
const ASSIGNABLE_ROLES: &[&str] = &["superadmin", "admin"];

#[derive(sqlx::FromRow)]
struct UserRow {
    id: u64,
    email: String,
    name: String,
    role: Option<String>,
    twofa_enrolled: i64, // computed (1/0)
    created_at: chrono::DateTime<chrono::Utc>,
}

fn user_json(r: &UserRow) -> Value {
    json!({
        "id": r.id,
        "email": r.email,
        "name": r.name,
        "role": r.role.clone().unwrap_or_default(),
        "twofa_enrolled": r.twofa_enrolled != 0,
        "created_at": r.created_at.to_rfc3339(),
    })
}

// One role per user in this model; pick the lowest-sorted if somehow multiple.
const USER_COLS: &str = "u.id, u.email, u.name, \
    (SELECT r.name FROM role_user ru JOIN roles r ON r.id = ru.role_id \
       WHERE ru.user_id = u.id ORDER BY r.name LIMIT 1) AS role, \
    (u.two_factor_confirmed_at IS NOT NULL) AS twofa_enrolled, u.created_at";

async fn fetch_user(pool: &sqlx::MySqlPool, id: u64) -> anyhow::Result<Option<Value>> {
    let row = sqlx::query_as::<_, UserRow>(&format!("SELECT {USER_COLS} FROM users u WHERE u.id = ?"))
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row.as_ref().map(user_json))
}

/// GET /api/users — every account with its role + 2FA-enrollment state.
pub async fn list(_g: RequirePermission<markers::ManageUsers>, State(state): State<AppState>) -> JsonResp {
    match sqlx::query_as::<_, UserRow>(&format!("SELECT {USER_COLS} FROM users u ORDER BY u.email"))
        .fetch_all(&state.pool)
        .await
    {
        Ok(rows) => (StatusCode::OK, Json(json!(rows.iter().map(user_json).collect::<Vec<_>>()))),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

#[derive(Deserialize)]
pub struct CreateUser {
    email: String,
    name: String,
    role: String,
    password: String,
}

/// POST /api/users — create an account. 2FA is enrolled by the user at first login.
pub async fn create(
    g: RequirePermission<markers::ManageUsers>,
    State(state): State<AppState>,
    Json(body): Json<CreateUser>,
) -> JsonResp {
    let email = body.email.trim();
    let name = body.name.trim();
    if email.is_empty() || name.is_empty() {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "email and name are required");
    }
    if !ASSIGNABLE_ROLES.contains(&body.role.as_str()) {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "role must be superadmin or admin");
    }
    if body.password.len() < 12 {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "password must be at least 12 characters");
    }
    let phc = match password::hash(&body.password) {
        Ok(h) => h,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "hashing failed"),
    };

    let res = sqlx::query("INSERT INTO users (name, email, password, two_factor_confirmed_at) VALUES (?, ?, ?, NULL)")
        .bind(name)
        .bind(email)
        .bind(&phc)
        .execute(&state.pool)
        .await;
    let id = match res {
        Ok(r) => r.last_insert_id(),
        Err(e) if is_dup(&e) => return err(StatusCode::CONFLICT, "a user with that email already exists"),
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    if set_role(&state.pool, id, &body.role).await.is_err() {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "assigning role failed");
    }
    audit(&state.pool, g.session.user_id, "user_created", id, &format!("{email} as {}", body.role)).await;

    match fetch_user(&state.pool, id).await {
        Ok(Some(v)) => (StatusCode::CREATED, Json(v)),
        _ => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

#[derive(Deserialize)]
pub struct UpdateUser {
    name: Option<String>,
    role: Option<String>,
}

/// PUT /api/users/{id} — change name and/or role. Refuses to demote the last
/// superadmin (that would lock everyone out of user + device management).
pub async fn update(
    g: RequirePermission<markers::ManageUsers>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
    Json(body): Json<UpdateUser>,
) -> JsonResp {
    let exists: Option<u64> = sqlx::query_scalar("SELECT id FROM users WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None);
    if exists.is_none() {
        return err(StatusCode::NOT_FOUND, "user not found");
    }

    if let Some(name) = body.name.as_deref().map(str::trim) {
        if !name.is_empty() {
            let _ = sqlx::query("UPDATE users SET name = ? WHERE id = ?").bind(name).bind(id).execute(&state.pool).await;
        }
    }
    if let Some(role) = &body.role {
        if !ASSIGNABLE_ROLES.contains(&role.as_str()) {
            return err(StatusCode::UNPROCESSABLE_ENTITY, "role must be superadmin or admin");
        }
        if role != "superadmin" && is_only_superadmin(&state.pool, id).await {
            return err(StatusCode::CONFLICT, "cannot demote the last superadmin");
        }
        if set_role(&state.pool, id, role).await.is_err() {
            return err(StatusCode::INTERNAL_SERVER_ERROR, "assigning role failed");
        }
        audit(&state.pool, g.session.user_id, "user_role_changed", id, &format!("role -> {role}")).await;
    }

    match fetch_user(&state.pool, id).await {
        Ok(Some(v)) => (StatusCode::OK, Json(v)),
        _ => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

/// POST /api/users/{id}/reset-2fa — clear TOTP so the user re-enrolls at next login.
pub async fn reset_2fa(
    g: RequirePermission<markers::ManageUsers>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> JsonResp {
    let res = sqlx::query(
        "UPDATE users SET two_factor_secret = NULL, two_factor_recovery_codes = NULL, \
         two_factor_confirmed_at = NULL WHERE id = ?",
    )
    .bind(id)
    .execute(&state.pool)
    .await;
    match res {
        Ok(r) if r.rows_affected() > 0 => {
            audit(&state.pool, g.session.user_id, "user_2fa_reset", id, "TOTP cleared; re-enroll at next login").await;
            (StatusCode::OK, Json(json!({ "ok": true })))
        }
        Ok(_) => err(StatusCode::NOT_FOUND, "user not found"),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

/// DELETE /api/users/{id}. Refuses to delete yourself or the last superadmin.
pub async fn remove(
    g: RequirePermission<markers::ManageUsers>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> JsonResp {
    if id == g.session.user_id {
        return err(StatusCode::CONFLICT, "you cannot delete your own account");
    }
    if is_only_superadmin(&state.pool, id).await {
        return err(StatusCode::CONFLICT, "cannot delete the last superadmin");
    }
    let res = sqlx::query("DELETE FROM users WHERE id = ?").bind(id).execute(&state.pool).await;
    match res {
        Ok(r) if r.rows_affected() > 0 => {
            audit(&state.pool, g.session.user_id, "user_deleted", id, "account deleted").await;
            (StatusCode::OK, Json(json!({ "ok": true })))
        }
        Ok(_) => err(StatusCode::NOT_FOUND, "user not found"),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

/// Replace the user's role assignment with exactly `role` (one role per user).
async fn set_role(pool: &sqlx::MySqlPool, user_id: u64, role: &str) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM role_user WHERE user_id = ?").bind(user_id).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO role_user (role_id, user_id) SELECT id, ? FROM roles WHERE name = ?")
        .bind(user_id)
        .bind(role)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// True if `user_id` is a superadmin AND the only one — used to block the last
/// superadmin from being demoted or deleted.
async fn is_only_superadmin(pool: &sqlx::MySqlPool, user_id: u64) -> bool {
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT ru.user_id) FROM role_user ru JOIN roles r ON r.id = ru.role_id WHERE r.name = 'superadmin'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);
    if total > 1 {
        return false;
    }
    let is_sa: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM role_user ru JOIN roles r ON r.id = ru.role_id WHERE r.name = 'superadmin' AND ru.user_id = ?",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0);
    is_sa > 0
}

/// Best-effort audit row for a user-management action.
async fn audit(pool: &sqlx::MySqlPool, actor: u64, event: &str, target_id: u64, message: &str) {
    let _ = sqlx::query(
        "INSERT INTO audit_logs (actor_type, actor_user_id, event_type, entity_type, entity_id, message) \
         VALUES ('user', ?, ?, 'user', ?, ?)",
    )
    .bind(actor)
    .bind(event)
    .bind(target_id)
    .bind(message)
    .execute(pool)
    .await;
}

/// True if a sqlx error is a MySQL duplicate-key (1062 / SQLSTATE 23000).
fn is_dup(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23000"))
}
