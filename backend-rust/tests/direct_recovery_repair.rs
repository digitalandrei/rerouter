mod common;

#[tokio::test]
async fn forward_repair_relabels_only_proven_no_write_recoveries() {
    let db = common::test_database().await;
    let pool = db.pool();
    let source = sqlx::query(
        "INSERT INTO reroute_bundles(trigger_type,state,lifecycle_state,total_actions,completed_actions,remaining_mutations) \
         VALUES('manual','succeeded','active',1,1,1)",
    )
    .execute(pool)
    .await
    .unwrap()
    .last_insert_id();

    async fn child(pool: &sqlx::MySqlPool, source: u64, settlement: &str) -> u64 {
        let id = sqlx::query(
            "INSERT INTO reroute_bundles(parent_bundle_id,trigger_type,state,total_actions,completed_actions) \
             VALUES(?,'manual','compensation_blocked',1,1)",
        )
        .bind(source)
        .execute(pool)
        .await
        .unwrap()
        .last_insert_id();
        sqlx::query(
            "INSERT INTO recovery_attempt_sources(recovery_bundle_id,source_bundle_id,claim_token,settlement,settled_at) \
             VALUES(?,?,?, ?,UTC_TIMESTAMP())",
        )
        .bind(id)
        .bind(source)
        .bind(format!("repair-{id}"))
        .bind(settlement)
        .execute(pool)
        .await
        .unwrap();
        id
    }

    let retryable = child(pool, source, "known_no_write").await;
    let blocked = child(pool, source, "blocked").await;
    let ambiguous = child(pool, source, "known_no_write").await;
    sqlx::query(
        "INSERT INTO reroutes(bundle_id,trigger_type,state,mutation_effect) VALUES(?,'rollback','uncertain','unknown')",
    )
    .bind(ambiguous)
    .execute(pool)
    .await
    .unwrap();

    sqlx::raw_sql(include_str!(
        "../migrations/20260921000700_direct_recovery_state_repair.sql"
    ))
    .execute(pool)
    .await
    .unwrap();

    let rows: Vec<(u64, String)> =
        sqlx::query_as("SELECT id,state FROM reroute_bundles WHERE id IN (?,?,?) ORDER BY id")
            .bind(retryable)
            .bind(blocked)
            .bind(ambiguous)
            .fetch_all(pool)
            .await
            .unwrap();
    assert_eq!(
        rows,
        vec![
            (retryable, "failed".into()),
            (blocked, "compensation_blocked".into()),
            (ambiguous, "compensation_blocked".into()),
        ]
    );
}
