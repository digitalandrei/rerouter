//! User management — superadmin-only (`manage_users`). List/create/update/delete
//! operator accounts and reset their 2FA. Assignable roles are `superadmin`,
//! `admin`, `operator`, `viewer`, and `auditor`.
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
const ASSIGNABLE_ROLES: &[&str] = &["superadmin", "admin", "operator", "viewer", "auditor"];

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
    let row =
        sqlx::query_as::<_, UserRow>(&format!("SELECT {USER_COLS} FROM users u WHERE u.id = ?"))
            .bind(id)
            .fetch_optional(pool)
            .await?;
    Ok(row.as_ref().map(user_json))
}

/// GET /api/users — every account with its role + 2FA-enrollment state.
pub async fn list(
    _g: RequirePermission<markers::ManageUsers>,
    State(state): State<AppState>,
) -> JsonResp {
    match sqlx::query_as::<_, UserRow>(&format!("SELECT {USER_COLS} FROM users u ORDER BY u.email"))
        .fetch_all(&state.pool)
        .await
    {
        Ok(rows) => (
            StatusCode::OK,
            Json(json!(rows.iter().map(user_json).collect::<Vec<_>>())),
        ),
        Err(e) => {
            tracing::error!(event_type = "users_list_failed", error = %e, "listing users failed");
            err(StatusCode::INTERNAL_SERVER_ERROR, "db_error")
        }
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
    let email = body.email.trim().to_lowercase();
    let name = body.name.trim();
    if email.is_empty() || name.is_empty() {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "email and name are required",
        );
    }
    if !ASSIGNABLE_ROLES.contains(&body.role.as_str()) {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "role must be superadmin, admin, operator, viewer, or auditor",
        );
    }
    if body.password.len() < 12 {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "password must be at least 12 characters",
        );
    }
    let phc = match password::hash(&body.password) {
        Ok(h) => h,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "hashing failed"),
    };
    let enrollment_code = crate::auth::sessions::generate_token();
    let enrollment_hash = crate::auth::sessions::hash_token(&enrollment_code);

    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!(event_type = "user_create_failed", error = %e, "begin failed");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error");
        }
    };
    let res = sqlx::query(
        "INSERT INTO users \
         (name, email, password, two_factor_confirmed_at, two_factor_enrollment_token_hash) \
         VALUES (?, ?, ?, NULL, ?)",
    )
    .bind(name)
    .bind(&email)
    .bind(&phc)
    .bind(&enrollment_hash)
    .execute(&mut *tx)
    .await;
    let id = match res {
        Ok(r) => r.last_insert_id(),
        Err(e) if is_dup(&e) => {
            return err(
                StatusCode::CONFLICT,
                "a user with that email already exists",
            )
        }
        Err(e) => {
            tracing::error!(event_type = "user_create_failed", error = %e, "inserting user failed");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error");
        }
    };
    let role = sqlx::query(
        "INSERT INTO role_user (role_id, user_id) SELECT id, ? FROM roles WHERE name = ?",
    )
    .bind(id)
    .bind(&body.role)
    .execute(&mut *tx)
    .await;
    match role {
        Ok(ref r) if r.rows_affected() == 1 => {}
        Ok(_) => {
            tracing::error!(event_type = "user_create_failed", role = %body.role, "role row not found");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "assigning role failed");
        }
        Err(e) => {
            tracing::error!(event_type = "user_create_failed", error = %e, "assigning role failed");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "assigning role failed");
        }
    }
    if let Err(e) = insert_audit(
        &mut tx,
        &g.session,
        "user_created",
        id,
        &format!("{email} as {}", body.role),
    )
    .await
    {
        tracing::error!(event_type = "user_create_failed", error = %e, "audit write failed");
        return err(StatusCode::INTERNAL_SERVER_ERROR, "audit_write_failed");
    }
    if let Err(e) = tx.commit().await {
        tracing::error!(event_type = "user_create_failed", error = %e, "commit failed");
        return err(StatusCode::INTERNAL_SERVER_ERROR, "audit_write_failed");
    }

    match fetch_user(&state.pool, id).await {
        Ok(Some(mut v)) => {
            v["enrollment_code"] = json!(enrollment_code);
            (StatusCode::CREATED, Json(v))
        }
        Ok(None) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
        Err(e) => {
            tracing::error!(event_type = "user_create_failed", error = %e, "reloading created user failed");
            err(StatusCode::INTERNAL_SERVER_ERROR, "db_error")
        }
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
    let name = body.name.as_deref().map(str::trim);
    if name.is_some_and(str::is_empty) {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "name must not be empty");
    }
    if let Some(role) = &body.role {
        if !ASSIGNABLE_ROLES.contains(&role.as_str()) {
            return err(
                StatusCode::UNPROCESSABLE_ENTITY,
                "role must be superadmin, admin, operator, viewer, or auditor",
            );
        }
    }

    match update_user_safely(&state.pool, id, name, body.role.as_deref(), &g.session).await {
        Ok(Some(true)) => {}
        Ok(Some(false)) => return err(StatusCode::CONFLICT, "cannot demote the last superadmin"),
        Ok(None) => return err(StatusCode::NOT_FOUND, "user not found"),
        Err(e) => {
            tracing::error!(event_type = "user_update_failed", user_id = id, error = %e, "updating user failed");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "updating user failed");
        }
    }

    match fetch_user(&state.pool, id).await {
        Ok(Some(v)) => (StatusCode::OK, Json(v)),
        Ok(None) => err(StatusCode::NOT_FOUND, "user not found"),
        Err(e) => {
            tracing::error!(event_type = "user_update_failed", user_id = id, error = %e, "reloading updated user failed");
            err(StatusCode::INTERNAL_SERVER_ERROR, "db_error")
        }
    }
}

/// POST /api/users/{id}/reset-2fa — clear TOTP so the user re-enrolls at next login.
pub async fn reset_2fa(
    g: RequirePermission<markers::ManageUsers>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> JsonResp {
    let enrollment_code = crate::auth::sessions::generate_token();
    let enrollment_hash = crate::auth::sessions::hash_token(&enrollment_code);
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!(event_type = "user_2fa_reset_failed", user_id = id, error = %e, "begin failed");
            return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error");
        }
    };
    let res = sqlx::query(
        "UPDATE users SET two_factor_secret = NULL, two_factor_recovery_codes = NULL, \
         two_factor_confirmed_at = NULL, two_factor_enrollment_token_hash = ?, \
         last_totp_step = NULL WHERE id = ?",
    )
    .bind(&enrollment_hash)
    .bind(id)
    .execute(&mut *tx)
    .await;
    match res {
        Ok(r) if r.rows_affected() > 0 => {
            let steps = async {
                sqlx::query("UPDATE sessions SET expires_at = UTC_TIMESTAMP() WHERE user_id = ?")
                    .bind(id)
                    .execute(&mut *tx)
                    .await?;
                insert_audit(
                    &mut tx,
                    &g.session,
                    "user_2fa_reset",
                    id,
                    "TOTP cleared; all sessions expired; re-enroll at next login",
                )
                .await?;
                tx.commit().await?;
                anyhow::Ok(())
            }
            .await;
            if let Err(e) = steps {
                tracing::error!(event_type = "user_2fa_reset_failed", user_id = id, error = %e, "expiring sessions / audit / commit failed");
                return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error");
            }
            (
                StatusCode::OK,
                Json(json!({ "ok": true, "enrollment_code": enrollment_code })),
            )
        }
        Ok(_) => {
            let _ = tx.rollback().await;
            err(StatusCode::NOT_FOUND, "user not found")
        }
        Err(e) => {
            tracing::error!(event_type = "user_2fa_reset_failed", user_id = id, error = %e, "clearing TOTP failed");
            let _ = tx.rollback().await;
            err(StatusCode::INTERNAL_SERVER_ERROR, "db_error")
        }
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
    match delete_user_safely(&state.pool, id, &g.session).await {
        Ok(Some(true)) => (StatusCode::OK, Json(json!({ "ok": true }))),
        Ok(Some(false)) => err(StatusCode::CONFLICT, "cannot delete the last superadmin"),
        Ok(None) => err(StatusCode::NOT_FOUND, "user not found"),
        Err(e) => {
            tracing::error!(event_type = "user_delete_failed", user_id = id, error = %e, "deleting user failed");
            err(StatusCode::INTERNAL_SERVER_ERROR, "db_error")
        }
    }
}

async fn is_only_superadmin_on(
    conn: &mut sqlx::MySqlConnection,
    user_id: u64,
) -> anyhow::Result<bool> {
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT ru.user_id) FROM role_user ru JOIN roles r ON r.id = ru.role_id WHERE r.name = 'superadmin'",
    )
    .fetch_one(&mut *conn)
    .await?;
    if total > 1 {
        return Ok(false);
    }
    let is_sa: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM role_user ru JOIN roles r ON r.id = ru.role_id WHERE r.name = 'superadmin' AND ru.user_id = ?",
    )
    .bind(user_id)
    .fetch_one(&mut *conn)
    .await?;
    Ok(is_sa > 0)
}

/// Serialize superadmin demotion with deletion so two concurrent requests cannot
/// each observe another superadmin and leave the installation ownerless.
///
/// `pub` for the DB integration tests; not part of the HTTP surface.
pub async fn update_user_safely(
    pool: &sqlx::MySqlPool,
    user_id: u64,
    name: Option<&str>,
    role: Option<&str>,
    actor: &crate::auth::sessions::Session,
) -> anyhow::Result<Option<bool>> {
    let mut conn = pool.acquire().await?;
    let got: Option<i64> = sqlx::query_scalar("SELECT GET_LOCK('rrt_superadmin_guard', 5)")
        .fetch_one(&mut *conn)
        .await?;
    anyhow::ensure!(got == Some(1), "superadmin guard busy");
    let result = update_user_locked(&mut conn, user_id, name, role, actor).await;
    release_superadmin_guard(&mut conn).await;
    result
}

/// Body of `update_user_safely`, run while holding the advisory lock.
///
/// Transaction control MUST go through sqlx's `begin()` (text-protocol `BEGIN`):
/// `sqlx::query` always uses the prepared-statement protocol, and MySQL 8.x
/// cannot prepare `START TRANSACTION` (error 1295) — only MariaDB can. A
/// `Transaction` dropped on an error path rolls back automatically.
async fn update_user_locked(
    conn: &mut sqlx::MySqlConnection,
    user_id: u64,
    name: Option<&str>,
    role: Option<&str>,
    actor: &crate::auth::sessions::Session,
) -> anyhow::Result<Option<bool>> {
    use sqlx::Connection;
    let mut tx = conn.begin().await?;
    let exists: Option<u64> = sqlx::query_scalar("SELECT id FROM users WHERE id = ? FOR UPDATE")
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
    if exists.is_none() {
        tx.rollback().await?;
        return Ok(None);
    }
    if role.is_some_and(|r| r != "superadmin") && is_only_superadmin_on(&mut tx, user_id).await? {
        tx.rollback().await?;
        return Ok(Some(false));
    }
    if let Some(name) = name {
        sqlx::query("UPDATE users SET name = ? WHERE id = ?")
            .bind(name)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        insert_audit(
            &mut tx,
            actor,
            "user_name_changed",
            user_id,
            "display name changed",
        )
        .await?;
    }
    if let Some(role) = role {
        sqlx::query("DELETE FROM role_user WHERE user_id = ?")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        let inserted = sqlx::query(
            "INSERT INTO role_user (role_id, user_id) SELECT id, ? FROM roles WHERE name = ?",
        )
        .bind(user_id)
        .bind(role)
        .execute(&mut *tx)
        .await?;
        anyhow::ensure!(inserted.rows_affected() == 1, "role not found");
        insert_audit(
            &mut tx,
            actor,
            "user_role_changed",
            user_id,
            &format!("role -> {role}"),
        )
        .await?;
    }
    tx.commit().await?;
    Ok(Some(true))
}

/// Release the advisory lock, logging (never propagating) a failure so the
/// caller's result is preserved.
async fn release_superadmin_guard(conn: &mut sqlx::MySqlConnection) {
    if let Err(e) = sqlx::query("SELECT RELEASE_LOCK('rrt_superadmin_guard')")
        .execute(conn)
        .await
    {
        tracing::error!(event_type = "superadmin_guard_release_failed", error = %e, "failed to release superadmin advisory lock");
    }
}

/// `Some(true)` deleted, `Some(false)` is the last superadmin, `None` not found.
///
/// `pub` for the DB integration tests; not part of the HTTP surface.
pub async fn delete_user_safely(
    pool: &sqlx::MySqlPool,
    user_id: u64,
    actor: &crate::auth::sessions::Session,
) -> anyhow::Result<Option<bool>> {
    let mut conn = pool.acquire().await?;
    let got: Option<i64> = sqlx::query_scalar("SELECT GET_LOCK('rrt_superadmin_guard', 5)")
        .fetch_one(&mut *conn)
        .await?;
    anyhow::ensure!(got == Some(1), "superadmin guard busy");
    let result = delete_user_locked(&mut conn, user_id, actor).await;
    release_superadmin_guard(&mut conn).await;
    result
}

/// Body of `delete_user_safely`, run while holding the advisory lock. Same
/// transaction-protocol constraint as [`update_user_locked`].
async fn delete_user_locked(
    conn: &mut sqlx::MySqlConnection,
    user_id: u64,
    actor: &crate::auth::sessions::Session,
) -> anyhow::Result<Option<bool>> {
    use sqlx::Connection;
    let mut tx = conn.begin().await?;
    let exists: Option<u64> = sqlx::query_scalar("SELECT id FROM users WHERE id = ? FOR UPDATE")
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
    if exists.is_none() {
        tx.rollback().await?;
        return Ok(None);
    }
    if is_only_superadmin_on(&mut tx, user_id).await? {
        tx.rollback().await?;
        return Ok(Some(false));
    }
    insert_audit(&mut tx, actor, "user_deleted", user_id, "account deleted").await?;
    let deleted = sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok((deleted.rows_affected() > 0).then_some(true))
}

async fn insert_audit(
    conn: &mut sqlx::MySqlConnection,
    actor: &crate::auth::sessions::Session,
    event: &str,
    target_id: u64,
    message: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO audit_logs \
         (actor_type, actor_user_id, event_type, entity_type, entity_id, message, ip_address, user_agent) \
         VALUES ('user', ?, ?, 'user', ?, ?, ?, ?)",
    )
    .bind(actor.user_id)
    .bind(event)
    .bind(target_id)
    .bind(message)
    .bind(&actor.ip_address)
    .bind(&actor.user_agent)
    .execute(conn)
    .await?;
    Ok(())
}

/// True if a sqlx error is a MySQL duplicate-key (1062 / SQLSTATE 23000).
fn is_dup(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23000"))
}
