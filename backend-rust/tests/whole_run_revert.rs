mod common;

use axum_extra::extract::cookie::Key;
use chrono::{Duration, Utc};
use rerouter_controller::{
    api::{self, manual_mitigations},
    auth::sessions::Session,
    config::Config,
    reroute::{
        device_plan::{DeviceStateSnapshot, PreparationReader, PreparedInverse},
        preparation, templates,
    },
};
use serde_json::json;

struct CurrentOwned;
impl PreparationReader for CurrentOwned {
    fn read_one<'a>(
        &'a self,
        _: u64,
        command: &'a str,
    ) -> rerouter_controller::ssh::BoxFuture<'a, anyhow::Result<String>> {
        Box::pin(async move {
            Ok(if command.contains("running-config") {
                "ip route 203.0.113.9 255.255.255.255 Null0".into()
            } else {
                "Routing entry for 203.0.113.9/32\n * directly connected, via Null0".into()
            })
        })
    }
    fn read_many<'a>(
        &'a self,
        _: u64,
        commands: &'a [String],
    ) -> rerouter_controller::ssh::BoxFuture<'a, anyhow::Result<Vec<String>>> {
        Box::pin(async move { Ok(vec![String::new(); commands.len()]) })
    }
}
struct DriftMss;
impl PreparationReader for DriftMss {
    fn read_one<'a>(
        &'a self,
        _: u64,
        _: &'a str,
    ) -> rerouter_controller::ssh::BoxFuture<'a, anyhow::Result<String>> {
        Box::pin(async { Ok("interface Port-channel1\n ip tcp adjust-mss 1300".into()) })
    }
    fn read_many<'a>(
        &'a self,
        _: u64,
        commands: &'a [String],
    ) -> rerouter_controller::ssh::BoxFuture<'a, anyhow::Result<Vec<String>>> {
        Box::pin(async move { Ok(vec![String::new(); commands.len()]) })
    }
}
fn actor(user_id: u64) -> Session {
    Session {
        id: 1,
        user_id,
        totp_verified: true,
        expires_at: Utc::now() + Duration::hours(1),
        ip_address: "127.0.0.1".into(),
        user_agent: "test".into(),
    }
}

#[tokio::test]
async fn inverse_preview_refuses_third_state_drift() {
    use rerouter_controller::reroute::device_plan::{PreparedDeviceAction, PreparedEffect};
    let before = DeviceStateSnapshot::InterfaceMss {
        interface: "Port-channel1".into(),
        mss: Some(1400),
    };
    let restore = DeviceStateSnapshot::InterfaceMss {
        interface: "Port-channel1".into(),
        mss: None,
    };
    let mut actions = vec![PreparedDeviceAction {
        schema_version: 1,
        device_id: 1,
        template_id: 1,
        template_name: "prepared_inverse".into(),
        canonical_params: json!({}),
        verification_mode: rerouter_controller::reroute::device_plan::VerificationMode::Routing,
        commands: vec![
            "configure terminal".into(),
            "no ip tcp adjust-mss".into(),
            "end".into(),
        ],
        before: vec![before],
        after: vec![restore.clone()],
        verify: vec![restore],
        effect: PreparedEffect::Change,
        inverse: None,
        prepared_at: Utc::now(),
    }];
    assert!(
        rerouter_controller::reroute::device_plan::prepare_inverse_sequence_read_only_with_reader(
            &DriftMss,
            &mut actions
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn whole_run_revert_binds_exact_remaining_set_and_is_idempotent() {
    let db = common::test_database().await;
    let pool = db.pool();
    let user = sqlx::query("INSERT INTO users(name,email,password) VALUES('revert',?,'unused')")
        .bind(format!("revert-{}@example.test", uuid::Uuid::new_v4()))
        .execute(pool)
        .await
        .unwrap()
        .last_insert_id();
    let other = sqlx::query("INSERT INTO users(name,email,password) VALUES('other',?,'unused')")
        .bind(format!("other-{}@example.test", uuid::Uuid::new_v4()))
        .execute(pool)
        .await
        .unwrap()
        .last_insert_id();
    let device=sqlx::query("INSERT INTO devices(name,hostname,ssh_host_fingerprint) VALUES(?,'192.0.2.91','SHA256:canned')").bind(format!("revert-{}",uuid::Uuid::new_v4())).execute(pool).await.unwrap().last_insert_id();
    let tid: u64 =
        sqlx::query_scalar("SELECT id FROM reroute_templates WHERE name='null_route_prefix'")
            .fetch_one(pool)
            .await
            .unwrap();
    let template = templates::load(pool, tid).await.unwrap();
    let source=sqlx::query("INSERT INTO reroute_bundles(trigger_type,state,failure_policy,total_actions,completed_actions) VALUES('manual','succeeded','abort_and_compensate',3,3)").execute(pool).await.unwrap().last_insert_id();
    let before = vec![
        DeviceStateSnapshot::Ipv4StaticRoute {
            prefix: "203.0.113.9/32".into(),
            next_hop: "Null0".into(),
            tag: None,
            present: false,
        },
        DeviceStateSnapshot::RouteResolution {
            prefix: "203.0.113.9/32".into(),
            next_hop: "Null0".into(),
            present: false,
        },
    ];
    let after = vec![
        DeviceStateSnapshot::Ipv4StaticRoute {
            prefix: "203.0.113.9/32".into(),
            next_hop: "Null0".into(),
            tag: None,
            present: true,
        },
        DeviceStateSnapshot::RouteResolution {
            prefix: "203.0.113.9/32".into(),
            next_hop: "Null0".into(),
            present: true,
        },
    ];
    let inverse = PreparedInverse {
        verification_mode: rerouter_controller::reroute::device_plan::VerificationMode::Routing,
        expected_current: after.clone(),
        restore: before.clone(),
        commands: vec![
            "configure terminal".into(),
            "no ip route 203.0.113.9 255.255.255.255 Null0".into(),
            "end".into(),
        ],
        verify: before.clone(),
    };
    let mut originals = Vec::new();
    let mut noop_id = 0;
    for (pos, effect) in [(0, "changed"), (1, "noop"), (2, "changed")] {
        let id=sqlx::query("INSERT INTO reroutes(bundle_id,bundle_position,device_id,reroute_template_id,trigger_type,state,mutation_effect,parameters_json,template_snapshot_json,prior_state_json,after_state_json,rollback_snapshot_json) VALUES(?,?,?,?, 'manual','succeeded',?,?,?,?,?,?)").bind(source).bind(pos).bind(device).bind(tid).bind(effect).bind(sqlx::types::Json(json!({"prefix":"203.0.113.9/32"}))).bind(sqlx::types::Json(serde_json::to_value(&template).unwrap())).bind(sqlx::types::Json(serde_json::to_value(&before).unwrap())).bind(sqlx::types::Json(serde_json::to_value(&after).unwrap())).bind(sqlx::types::Json(serde_json::to_value(&inverse).unwrap())).execute(pool).await.unwrap().last_insert_id();
        if effect == "changed" {
            originals.push(id);
        } else {
            noop_id = id;
        }
    }
    sqlx::query("UPDATE reroutes SET state='uncertain',mutation_effect='unknown' WHERE id=?")
        .bind(noop_id)
        .execute(pool)
        .await
        .unwrap();
    assert!(
        rerouter_controller::reroute::recovery::owned_original_ids(pool, source)
            .await
            .is_err()
    );
    sqlx::query("UPDATE reroutes SET state='succeeded',mutation_effect='noop' WHERE id=?")
        .bind(noop_id)
        .execute(pool)
        .await
        .unwrap();
    originals.reverse();
    let actions = preparation::prepare_rollbacks(pool, &originals, "whole", false)
        .await
        .unwrap();
    assert_eq!(actions.len(), 2);
    assert!(actions[0].original_reroute_id.unwrap() > actions[1].original_reroute_id.unwrap());
    let state = api::AppState {
        pool: pool.clone(),
        config: Config::default(),
        cookie_key: Key::from(&[92; 64]),
    };
    let (failed_status,axum::Json(failed_preview))=manual_mitigations::preview_actions_with_reader(&state,&actor(user),"bundle_revert",Some(source),actions.clone(),json!({"kind":"bundle_revert","original_bundle_id":source,"original_reroute_ids":originals}),"persist failure".into(),json!({"original_bundle_id":source,"reason":"persist failure"}),None,&CurrentOwned).await;
    assert_eq!(failed_status, axum::http::StatusCode::OK);
    assert!(
        manual_mitigations::accept_plan_with_persist_failure_for_test(
            &state,
            &actor(user),
            failed_preview["plan_id"].as_u64().unwrap(),
            failed_preview["preview_token"].as_str().unwrap(),
            "bundle_revert",
            Some(source)
        )
        .await
        .is_err()
    );
    let claim: Option<String> =
        sqlx::query_scalar("SELECT recovery_claim_token FROM reroute_bundles WHERE id=?")
            .bind(source)
            .fetch_one(pool)
            .await
            .unwrap();
    assert!(
        claim.is_none(),
        "admission failure must release the parent claim"
    );
    let failed_bundle: Option<u64> =
        sqlx::query_scalar("SELECT bundle_id FROM execution_plans WHERE id=?")
            .bind(failed_preview["plan_id"].as_u64().unwrap())
            .fetch_one(pool)
            .await
            .unwrap();
    sqlx::query("DELETE FROM execution_plans WHERE id=?")
        .bind(failed_preview["plan_id"].as_u64().unwrap())
        .execute(pool)
        .await
        .unwrap();
    if let Some(id) = failed_bundle {
        sqlx::query("DELETE FROM reroute_bundles WHERE id=?")
            .bind(id)
            .execute(pool)
            .await
            .unwrap();
    }
    let (status,axum::Json(preview))=manual_mitigations::preview_actions_with_reader(&state,&actor(user),"bundle_revert",Some(source),actions,json!({"kind":"bundle_revert","original_bundle_id":source,"original_reroute_ids":originals}),"whole".into(),json!({"original_bundle_id":source,"reason":"whole"}),None,&CurrentOwned).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{preview}");
    let plan = preview["plan_id"].as_u64().unwrap();
    let token = preview["preview_token"].as_str().unwrap();
    assert!(manual_mitigations::accept_plan(
        &state,
        &actor(other),
        plan,
        token,
        "bundle_revert",
        Some(source)
    )
    .await
    .is_err());
    let accepted = manual_mitigations::accept_plan(
        &state,
        &actor(user),
        plan,
        token,
        "bundle_revert",
        Some(source),
    )
    .await
    .unwrap();
    let repeated = manual_mitigations::accept_plan(
        &state,
        &actor(user),
        plan,
        token,
        "bundle_revert",
        Some(source),
    )
    .await
    .unwrap();
    assert_eq!(accepted.bundle_id, repeated.bundle_id);
    assert!(repeated.already_accepted);

    // A second preview loses authority if the exact remaining original set
    // changes before confirmation.
    let source2=sqlx::query("INSERT INTO reroute_bundles(trigger_type,state,failure_policy,total_actions,completed_actions) VALUES('manual','succeeded','abort_and_compensate',1,1)").execute(pool).await.unwrap().last_insert_id();
    let original2=sqlx::query("INSERT INTO reroutes(bundle_id,bundle_position,device_id,reroute_template_id,trigger_type,state,mutation_effect,parameters_json,template_snapshot_json,prior_state_json,after_state_json,rollback_snapshot_json) VALUES(?,?,?,?, 'manual','succeeded','changed',?,?,?,?,?)").bind(source2).bind(0).bind(device).bind(tid).bind(sqlx::types::Json(json!({"prefix":"203.0.113.9/32"}))).bind(sqlx::types::Json(serde_json::to_value(&template).unwrap())).bind(sqlx::types::Json(serde_json::to_value(&before).unwrap())).bind(sqlx::types::Json(serde_json::to_value(&after).unwrap())).bind(sqlx::types::Json(serde_json::to_value(&inverse).unwrap())).execute(pool).await.unwrap().last_insert_id();
    let stale_actions = preparation::prepare_rollbacks(pool, &[original2], "stale", false)
        .await
        .unwrap();
    let (stale_status,axum::Json(stale))=manual_mitigations::preview_actions_with_reader(&state,&actor(user),"bundle_revert",Some(source2),stale_actions,json!({"kind":"bundle_revert","original_bundle_id":source2,"original_reroute_ids":[original2]}),"stale".into(),json!({"original_bundle_id":source2,"reason":"stale"}),None,&CurrentOwned).await;
    assert_eq!(stale_status, axum::http::StatusCode::OK, "{stale}");
    let inverse2=sqlx::query("INSERT INTO reroutes(device_id,reroute_template_id,trigger_type,state,mutation_effect,rollback_of_reroute_id) VALUES(?,?,'rollback','succeeded','changed',?)").bind(device).bind(tid).bind(original2).execute(pool).await.unwrap().last_insert_id();
    assert!(manual_mitigations::accept_plan(
        &state,
        &actor(user),
        stale["plan_id"].as_u64().unwrap(),
        stale["preview_token"].as_str().unwrap(),
        "bundle_revert",
        Some(source2)
    )
    .await
    .is_err());
    sqlx::query("DELETE FROM execution_plans WHERE id=?")
        .bind(stale["plan_id"].as_u64().unwrap())
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM reroutes WHERE id=?")
        .bind(inverse2)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM reroutes WHERE id=?")
        .bind(original2)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM reroute_bundles WHERE id=?")
        .bind(source2)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM reroute_bundle_actions WHERE bundle_id=?")
        .bind(accepted.bundle_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM execution_plans WHERE id=?")
        .bind(plan)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM reroute_bundles WHERE id=?")
        .bind(accepted.bundle_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM reroutes WHERE bundle_id=?")
        .bind(source)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM reroute_bundles WHERE id=?")
        .bind(source)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM devices WHERE id=?")
        .bind(device)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id IN (?,?)")
        .bind(user)
        .bind(other)
        .execute(pool)
        .await
        .unwrap();
}
