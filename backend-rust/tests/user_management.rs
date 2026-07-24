//! User-management semantics: role update, rename, delete, the last-superadmin
//! interlock, and the audit trail — exercising `update_user_safely` /
//! `delete_user_safely`, which run inside a real transaction under the
//! `rrt_superadmin_guard` advisory lock. These paths 500'd in production on
//! MySQL 8.4 (prepared `START TRANSACTION`, error 1295); see
//! `sql_protocol_lint.rs` for the protocol guard.
//!
//! DB integration test — runs only when DATABASE_URL points at a MariaDB the
//! test may migrate + write to; skips otherwise. Cleans up its rows.

use rerouter_controller::api::users::{delete_user_safely, update_user_safely};
use rerouter_controller::auth::sessions::Session;
use rerouter_controller::db::MIGRATOR;
use sqlx::mysql::MySqlPoolOptions;
use sqlx::MySqlPool;

const SA_EMAIL: &str = "rrt-test-users-sa@example.test";
const USER_EMAIL: &str = "rrt-test-users-b@example.test";

/// Connect + migrate, or `None` when DATABASE_URL is unset (skip).
async fn pool_or_skip() -> Option<MySqlPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = MySqlPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect to DATABASE_URL");
    MIGRATOR.run(&pool).await.expect("run migrations");
    Some(pool)
}

async fn seed_user(pool: &MySqlPool, email: &str, role: &str) -> u64 {
    let id = sqlx::query("INSERT INTO users (name, email, password) VALUES (?, ?, 'x')")
        .bind(email)
        .bind(email)
        .execute(pool)
        .await
        .expect("insert test user")
        .last_insert_id();
    let assigned = sqlx::query(
        "INSERT INTO role_user (role_id, user_id) SELECT id, ? FROM roles WHERE name = ?",
    )
    .bind(id)
    .bind(role)
    .execute(pool)
    .await
    .expect("assign test role")
    .rows_affected();
    assert_eq!(assigned, 1, "role {role} must exist (seeded by migrations)");
    id
}

async fn role_of(pool: &MySqlPool, user_id: u64) -> Option<String> {
    sqlx::query_scalar(
        "SELECT r.name FROM role_user ru JOIN roles r ON r.id = ru.role_id WHERE ru.user_id = ?",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .expect("read role")
}

async fn audit_count(pool: &MySqlPool, event: &str, entity_id: u64) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_logs WHERE event_type = ? AND entity_type = 'user' AND entity_id = ?",
    )
    .bind(event)
    .bind(entity_id)
    .fetch_one(pool)
    .await
    .expect("count audit rows")
}

async fn cleanup(pool: &MySqlPool, ids: &[u64]) {
    for id in ids {
        let _ = sqlx::query("DELETE FROM audit_logs WHERE entity_type = 'user' AND entity_id = ?")
            .bind(id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id)
            .execute(pool)
            .await;
    }
}

fn actor(user_id: u64) -> Session {
    Session {
        id: 0,
        user_id,
        totp_verified: true,
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        ip_address: "127.0.0.1".into(),
        user_agent: "user_management test".into(),
    }
}

#[tokio::test]
async fn user_update_delete_and_superadmin_interlock() {
    let Some(pool) = pool_or_skip().await else {
        eprintln!("skipping: DATABASE_URL not set");
        return;
    };

    // Idempotent cleanup of leftovers from an interrupted previous run.
    for email in [SA_EMAIL, USER_EMAIL] {
        let stale: Option<u64> = sqlx::query_scalar("SELECT id FROM users WHERE email = ?")
            .bind(email)
            .fetch_optional(&pool)
            .await
            .expect("stale lookup");
        if let Some(id) = stale {
            cleanup(&pool, &[id]).await;
        }
    }

    let sa = seed_user(&pool, SA_EMAIL, "superadmin").await;
    let b = seed_user(&pool, USER_EMAIL, "admin").await;
    let act = actor(sa);

    // Rename + role change commits and leaves an audit trail.
    let updated = update_user_safely(&pool, b, Some("Renamed B"), Some("operator"), &act)
        .await
        .expect("update must not error");
    assert_eq!(updated, Some(true), "rename + role change succeeds");
    assert_eq!(role_of(&pool, b).await.as_deref(), Some("operator"));
    let name: String = sqlx::query_scalar("SELECT name FROM users WHERE id = ?")
        .bind(b)
        .fetch_one(&pool)
        .await
        .expect("read name");
    assert_eq!(name, "Renamed B");
    assert_eq!(audit_count(&pool, "user_name_changed", b).await, 1);
    assert_eq!(audit_count(&pool, "user_role_changed", b).await, 1);

    // Unknown user id -> None (and no error).
    let missing: u64 = sqlx::query_scalar::<_, Option<u64>>("SELECT MAX(id) FROM users")
        .fetch_one(&pool)
        .await
        .expect("max id")
        .unwrap_or(0)
        + 1_000_000;
    let not_found = update_user_safely(&pool, missing, Some("x"), None, &act)
        .await
        .expect("missing-user update must not error");
    assert_eq!(not_found, None);
    let not_found = delete_user_safely(&pool, missing, &act)
        .await
        .expect("missing-user delete must not error");
    assert_eq!(not_found, None);

    // Last-superadmin interlock: only deterministic when this test owns the
    // only superadmin (fresh scratch DB). Skip against a shared dev DB.
    let other_superadmins: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT ru.user_id) FROM role_user ru \
         JOIN roles r ON r.id = ru.role_id WHERE r.name = 'superadmin' AND ru.user_id <> ?",
    )
    .bind(sa)
    .fetch_one(&pool)
    .await
    .expect("count other superadmins");
    if other_superadmins == 0 {
        let demote = update_user_safely(&pool, sa, None, Some("admin"), &act)
            .await
            .expect("demote attempt must not error");
        assert_eq!(
            demote,
            Some(false),
            "demoting the last superadmin is refused"
        );
        assert_eq!(role_of(&pool, sa).await.as_deref(), Some("superadmin"));

        let delete = delete_user_safely(&pool, sa, &act)
            .await
            .expect("delete attempt must not error");
        assert_eq!(
            delete,
            Some(false),
            "deleting the last superadmin is refused"
        );
    } else {
        eprintln!(
            "skipping last-superadmin assertions: {other_superadmins} pre-existing superadmin(s)"
        );
    }

    // Deleting a regular user commits, cascades role_user, and is audited.
    let deleted = delete_user_safely(&pool, b, &act)
        .await
        .expect("delete must not error");
    assert_eq!(deleted, Some(true));
    let gone: Option<u64> = sqlx::query_scalar("SELECT id FROM users WHERE id = ?")
        .bind(b)
        .fetch_optional(&pool)
        .await
        .expect("post-delete lookup");
    assert_eq!(gone, None, "user row deleted");
    assert_eq!(role_of(&pool, b).await, None, "role_user cascaded");
    assert_eq!(audit_count(&pool, "user_deleted", b).await, 1);

    // A failed role change must roll back atomically: the rename in the same
    // call must not survive the transaction ("role not found" error path).
    let c = seed_user(&pool, USER_EMAIL, "viewer").await;
    let bogus = update_user_safely(
        &pool,
        c,
        Some("Should Not Persist"),
        Some("no_such_role"),
        &act,
    )
    .await;
    assert!(bogus.is_err(), "unknown role errors out");
    let name: String = sqlx::query_scalar("SELECT name FROM users WHERE id = ?")
        .bind(c)
        .fetch_one(&pool)
        .await
        .expect("read name after rollback");
    assert_eq!(
        name, USER_EMAIL,
        "rename rolled back with the failed role change"
    );
    assert_eq!(
        role_of(&pool, c).await.as_deref(),
        Some("viewer"),
        "role untouched"
    );
    assert_eq!(
        audit_count(&pool, "user_name_changed", c).await,
        0,
        "no audit row survives rollback"
    );

    // The advisory guard must be released even after the rollback path: a
    // follow-up update on the same pool succeeds immediately.
    let after = update_user_safely(&pool, c, Some("Second Update"), None, &act)
        .await
        .expect("guard released after error path");
    assert_eq!(after, Some(true));

    cleanup(&pool, &[sa, c]).await;
}
