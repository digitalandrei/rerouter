mod common;

use chrono::{DateTime, Utc};
use rerouter_controller::{config::Config, reroute::recovery};

#[tokio::test]
async fn timer_is_anchored_once_and_disabled_automation_leaves_it_pending() {
    let db = common::test_database().await;
    let pool = db.pool();
    sqlx::query("UPDATE system_settings SET `value`='observe' WHERE `key`='operating_mode'")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE system_settings SET `value`='false' WHERE `key`='automatic_actions_enabled'",
    )
    .execute(pool)
    .await
    .unwrap();
    let device = sqlx::query("INSERT INTO devices(name,hostname) VALUES(?,'192.0.2.210')")
        .bind(format!("lifecycle-{}", uuid::Uuid::new_v4()))
        .execute(pool)
        .await
        .unwrap()
        .last_insert_id();
    let bundle=sqlx::query("INSERT INTO reroute_bundles(trigger_type,state,failure_policy,total_actions,completed_actions,finished_at,source_json) \
        VALUES('manual','succeeded','abort_and_compensate',1,1,DATE_SUB(UTC_TIMESTAMP(),INTERVAL 130 SECOND),JSON_OBJECT('revert_after_seconds',120))")
        .execute(pool).await.unwrap().last_insert_id();
    let reroute=sqlx::query("INSERT INTO reroutes(bundle_id,bundle_position,device_id,trigger_type,state,mutation_effect) \
        VALUES(?,0,?,'manual','succeeded','changed')").bind(bundle).bind(device).execute(pool).await.unwrap().last_insert_id();

    recovery::schedule_if_eligible(pool, bundle).await.unwrap();
    let first: (DateTime<Utc>, DateTime<Utc>, String) = sqlx::query_as(
        "SELECT recovery_deadline,finished_at,lifecycle_state FROM reroute_bundles WHERE id=?",
    )
    .bind(bundle)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!((first.0 - first.1).num_seconds(), 120);
    recovery::schedule_if_eligible(pool, bundle).await.unwrap();
    let second: DateTime<Utc> =
        sqlx::query_scalar("SELECT recovery_deadline FROM reroute_bundles WHERE id=?")
            .bind(bundle)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(first.0, second);
    assert!(!recovery::process_one_due(pool, &Config::default())
        .await
        .unwrap());
    let claim: Option<String> =
        sqlx::query_scalar("SELECT recovery_claim_token FROM reroute_bundles WHERE id=?")
            .bind(bundle)
            .fetch_one(pool)
            .await
            .unwrap();
    assert!(claim.is_none());

    sqlx::query("DELETE FROM reroutes WHERE id=?")
        .bind(reroute)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM reroute_bundles WHERE id=?")
        .bind(bundle)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM devices WHERE id=?")
        .bind(device)
        .execute(pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn restart_releases_only_a_prestart_claim() {
    let db = common::test_database().await;
    let pool = db.pool();
    sqlx::query("UPDATE system_settings SET `value`='observe' WHERE `key`='operating_mode'")
        .execute(pool)
        .await
        .unwrap();
    let bundle=sqlx::query("INSERT INTO reroute_bundles(trigger_type,state,failure_policy,total_actions,lifecycle_state,recovery_deadline,recovery_claim_token,recovery_claimed_at) \
        VALUES('manual','succeeded','abort_and_compensate',0,'recovery_claimed',DATE_SUB(UTC_TIMESTAMP(),INTERVAL 1 SECOND),'crashed',DATE_SUB(UTC_TIMESTAMP(),INTERVAL 10 MINUTE))")
        .execute(pool).await.unwrap().last_insert_id();
    assert!(!recovery::process_one_due(pool, &Config::default())
        .await
        .unwrap());
    let row: (String, Option<String>) = sqlx::query_as(
        "SELECT lifecycle_state,recovery_claim_token FROM reroute_bundles WHERE id=?",
    )
    .bind(bundle)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(row.0, "recovery_scheduled");
    assert!(row.1.is_none());
    sqlx::query("DELETE FROM reroute_bundles WHERE id=?")
        .bind(bundle)
        .execute(pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn timer_claim_excludes_second_timer_manual_revert_and_takeover() {
    let db = common::test_database().await;
    let pool = db.pool();
    sqlx::query("UPDATE system_settings SET `value`='enforce' WHERE `key`='operating_mode'")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE system_settings SET `value`='true' WHERE `key`='automatic_actions_enabled'",
    )
    .execute(pool)
    .await
    .unwrap();
    let bundle=sqlx::query("INSERT INTO reroute_bundles(trigger_type,state,failure_policy,total_actions,lifecycle_state,recovery_deadline) VALUES('manual','succeeded','abort_and_compensate',0,'recovery_scheduled',DATE_SUB(UTC_TIMESTAMP(),INTERVAL 1 SECOND))").execute(pool).await.unwrap().last_insert_id();
    let cfg = Config::default();
    let (a, b) = tokio::join!(
        recovery::claim_one_due(pool, &cfg),
        recovery::claim_one_due(pool, &cfg)
    );
    let claims = [a.unwrap(), b.unwrap()];
    assert_eq!(claims.iter().filter(|v| v.is_some()).count(), 1);
    let takeover=sqlx::query("UPDATE reroute_bundles SET automatic_recovery_cancelled_at=UTC_TIMESTAMP() WHERE id=? AND lifecycle_state IN ('active','recovery_scheduled') AND recovery_claim_token IS NULL").bind(bundle).execute(pool).await.unwrap();
    assert_eq!(takeover.rows_affected(), 0);
    let manual=sqlx::query("UPDATE reroute_bundles SET recovery_claim_token='manual' WHERE id=? AND recovery_claim_token IS NULL AND lifecycle_state NOT IN ('recovery_claimed','recovery_running')").bind(bundle).execute(pool).await.unwrap();
    assert_eq!(manual.rows_affected(), 0);
    sqlx::query("DELETE FROM reroute_bundles WHERE id=?")
        .bind(bundle)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("UPDATE system_settings SET `value`='observe' WHERE `key`='operating_mode'")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE system_settings SET `value`='false' WHERE `key`='automatic_actions_enabled'",
    )
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn compensation_inherits_durable_automatic_origin() {
    use rerouter_controller::reroute::executor::{authority_is_unattended, ExecutionAuthorization};
    let db = common::test_database().await;
    let pool = db.pool();
    let manual=sqlx::query("INSERT INTO reroute_bundles(trigger_type,state,failure_policy,total_actions) VALUES('manual','running','abort_and_compensate',1)").execute(pool).await.unwrap().last_insert_id();
    let automatic=sqlx::query("INSERT INTO reroute_bundles(trigger_type,state,failure_policy,total_actions) VALUES('automatic','running','abort_and_compensate',1)").execute(pool).await.unwrap().last_insert_id();
    let manual_auth = ExecutionAuthorization::compensation(manual, "manual");
    let auto_auth = ExecutionAuthorization::compensation(automatic, "auto");
    assert!(
        !authority_is_unattended(pool, Some(&manual_auth)).await,
        "confirmed manual compensation remains allowed in observe"
    );
    assert!(
        authority_is_unattended(pool, Some(&auto_auth)).await,
        "automatic compensation must be blocked after mode/master disarm"
    );
    sqlx::query("DELETE FROM reroute_bundles WHERE id IN (?,?)")
        .bind(manual)
        .bind(automatic)
        .execute(pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn prewrite_timer_preparation_failure_releases_claim_for_takeover() {
    let db = common::test_database().await;
    let pool = db.pool();
    sqlx::query("UPDATE system_settings SET `value`='enforce' WHERE `key`='operating_mode'")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE system_settings SET `value`='true' WHERE `key`='automatic_actions_enabled'",
    )
    .execute(pool)
    .await
    .unwrap();
    let device = sqlx::query("INSERT INTO devices(name,hostname) VALUES(?,'192.0.2.243')")
        .bind(format!("prewrite-{}", uuid::Uuid::new_v4()))
        .execute(pool)
        .await
        .unwrap()
        .last_insert_id();
    let bundle=sqlx::query("INSERT INTO reroute_bundles(trigger_type,state,failure_policy,total_actions,completed_actions,lifecycle_state,remaining_mutations,recovery_deadline) VALUES('manual','succeeded','abort_and_compensate',1,1,'recovery_scheduled',1,DATE_SUB(UTC_TIMESTAMP(),INTERVAL 1 SECOND))").execute(pool).await.unwrap().last_insert_id();
    let reroute=sqlx::query("INSERT INTO reroutes(bundle_id,bundle_position,device_id,trigger_type,state,mutation_effect) VALUES(?,0,?,'manual','succeeded','changed')").bind(bundle).bind(device).execute(pool).await.unwrap().last_insert_id();
    assert!(recovery::process_one_due(pool, &Config::default())
        .await
        .unwrap());
    let row: (String, Option<String>) = sqlx::query_as(
        "SELECT lifecycle_state,recovery_claim_token FROM reroute_bundles WHERE id=?",
    )
    .bind(bundle)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(row.0, "active");
    assert!(row.1.is_none());
    recovery::claim_source_bundles(pool, &[bundle], "fresh-whole-plan")
        .await
        .unwrap();
    recovery::release_unstarted_source_claims(pool, &[bundle], "fresh-whole-plan", "test release")
        .await
        .unwrap();
    let takeover=sqlx::query("UPDATE reroute_bundles SET automatic_recovery_cancelled_at=UTC_TIMESTAMP() WHERE id=? AND lifecycle_state='active' AND recovery_claim_token IS NULL").bind(bundle).execute(pool).await.unwrap();
    assert_eq!(takeover.rows_affected(), 1);
    sqlx::query("DELETE FROM reroutes WHERE id=?")
        .bind(reroute)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM reroute_bundles WHERE id=?")
        .bind(bundle)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM devices WHERE id=?")
        .bind(device)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("UPDATE system_settings SET `value`='observe' WHERE `key`='operating_mode'")
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE system_settings SET `value`='false' WHERE `key`='automatic_actions_enabled'",
    )
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn automatic_rule_recovery_claim_fences_takeover_during_preparation_pause() {
    let db = common::test_database().await;
    let pool = db.pool();
    let source=sqlx::query("INSERT INTO reroute_bundles(trigger_type,state,failure_policy,total_actions,lifecycle_state,remaining_mutations) VALUES('automatic','succeeded','abort_and_compensate',1,'active',1)").execute(pool).await.unwrap().last_insert_id();
    recovery::claim_source_bundles(pool, &[source], "paused-rule-recovery")
        .await
        .unwrap();
    let takeover=sqlx::query("UPDATE reroute_bundles SET automatic_recovery_cancelled_at=UTC_TIMESTAMP() WHERE id=? AND lifecycle_state IN ('active','recovery_scheduled') AND recovery_claim_token IS NULL").bind(source).execute(pool).await.unwrap();
    assert_eq!(
        takeover.rows_affected(),
        0,
        "takeover must lose once automatic recovery owns preparation"
    );
    recovery::release_unstarted_source_claims(
        pool,
        &[source],
        "paused-rule-recovery",
        "test release before writes",
    )
    .await
    .unwrap();
    let takeover=sqlx::query("UPDATE reroute_bundles SET automatic_recovery_cancelled_at=UTC_TIMESTAMP() WHERE id=? AND lifecycle_state='active' AND recovery_claim_token IS NULL").bind(source).execute(pool).await.unwrap();
    assert_eq!(takeover.rows_affected(), 1);
    sqlx::query("DELETE FROM reroute_bundles WHERE id=?")
        .bind(source)
        .execute(pool)
        .await
        .unwrap();
}
