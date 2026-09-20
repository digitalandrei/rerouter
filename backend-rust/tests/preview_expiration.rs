mod common;

/// The release changes prepared evidence, so neither credential store may keep
/// unused authority alive. Consumed plans remain immutable audit evidence.
#[tokio::test]
async fn release_expires_both_unused_preview_kinds_without_rewriting_consumed_evidence() {
    let db = common::test_database().await;
    let mut tx = db.begin().await.unwrap();
    let user = sqlx::query(
        "INSERT INTO users(name,email,password) VALUES('preview upgrade fixture',?,'unused')",
    )
    .bind(format!(
        "preview-upgrade-{}@example.test",
        uuid::Uuid::new_v4()
    ))
    .execute(&mut *tx)
    .await
    .unwrap()
    .last_insert_id();
    for consumed in [false, true] {
        let token = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO execution_plans(user_id,scope,reason,snapshot_json,plan_hash,token_hash,expires_at,consumed_at) VALUES(?,'manual_mitigation','upgrade fixture',?,REPEAT('a',64),SHA2(?,256),DATE_ADD(UTC_TIMESTAMP(),INTERVAL 1 HOUR),IF(?,UTC_TIMESTAMP(),NULL))")
            .bind(user).bind(r#"{"source":{"kind":"manual"},"fixture":"preserve this snapshot"}"#)
            .bind(&token).bind(consumed).execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO action_previews(token_hash,user_id,scope,plan_hash,expires_at,used_at) VALUES(SHA2(?,256),?,'manual',REPEAT('b',64),DATE_ADD(UTC_TIMESTAMP(),INTERVAL 1 HOUR),IF(?,UTC_TIMESTAMP(),NULL))")
            .bind(&token).bind(user).bind(consumed).execute(&mut *tx).await.unwrap();
    }
    let before_current: (String, String, String, String) = sqlx::query_as("SELECT CAST(expires_at AS CHAR),CAST(consumed_at AS CHAR),CAST(snapshot_json AS CHAR),token_hash FROM execution_plans WHERE user_id=? AND consumed_at IS NOT NULL")
        .bind(user).fetch_one(&mut *tx).await.unwrap();
    let before_legacy: (String, String, String) = sqlx::query_as("SELECT CAST(expires_at AS CHAR),CAST(used_at AS CHAR),token_hash FROM action_previews WHERE user_id=? AND used_at IS NOT NULL")
        .bind(user).fetch_one(&mut *tx).await.unwrap();

    let migration = include_str!("../migrations/20260921000400_expire_previews.sql");
    for _ in 0..2 {
        sqlx::raw_sql(migration).execute(&mut *tx).await.unwrap();
        let usable_current: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM execution_plans WHERE user_id=? AND consumed_at IS NULL AND expires_at>UTC_TIMESTAMP()")
            .bind(user).fetch_one(&mut *tx).await.unwrap();
        let usable_legacy: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM action_previews WHERE user_id=? AND used_at IS NULL AND expires_at>UTC_TIMESTAMP()")
            .bind(user).fetch_one(&mut *tx).await.unwrap();
        assert_eq!((usable_current, usable_legacy), (0, 0));
        let after_current = sqlx::query_as::<_, (String, String, String, String)>("SELECT CAST(expires_at AS CHAR),CAST(consumed_at AS CHAR),CAST(snapshot_json AS CHAR),token_hash FROM execution_plans WHERE user_id=? AND consumed_at IS NOT NULL")
            .bind(user).fetch_one(&mut *tx).await.unwrap();
        let after_legacy = sqlx::query_as::<_, (String, String, String)>("SELECT CAST(expires_at AS CHAR),CAST(used_at AS CHAR),token_hash FROM action_previews WHERE user_id=? AND used_at IS NOT NULL")
            .bind(user).fetch_one(&mut *tx).await.unwrap();
        assert_eq!(after_current, before_current);
        assert_eq!(after_legacy, before_legacy);
    }
    tx.rollback().await.unwrap();
}
