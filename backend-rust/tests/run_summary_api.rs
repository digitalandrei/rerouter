//! Read-only presentation contract for logical mitigation runs and dashboard
//! alert de-noising. Fixtures write only to the dedicated test schema; no SSH,
//! router, notification, or execution path is invoked.

mod common;

use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use axum::Router;
use axum_extra::extract::cookie::{Key, SignedCookieJar};
use rerouter_controller::{api, auth::sessions, config::Config};
use serde_json::{json, Value};
use sqlx::MySqlPool;
use tower::ServiceExt;

async fn viewer(pool: &MySqlPool, key: &Key) -> (u64, String, String) {
    let email = format!("run-summary-{}@example.test", uuid::Uuid::new_v4());
    let id = sqlx::query(
        "INSERT INTO users(name,email,password) VALUES('Run summary fixture',?,'unused')",
    )
    .bind(&email)
    .execute(pool)
    .await
    .unwrap()
    .last_insert_id();
    sqlx::query(
        "INSERT INTO role_user(role_id,user_id) SELECT id,? FROM roles WHERE name='viewer'",
    )
    .bind(id)
    .execute(pool)
    .await
    .unwrap();
    let (session, _) = sessions::create(pool, id, "127.0.0.1", "run-summary-test", 1)
        .await
        .unwrap();
    let token = sessions::mark_totp_verified_and_rotate(pool, session)
        .await
        .unwrap();
    let response = SignedCookieJar::new(key.clone())
        .add(sessions::build_cookie(token, time::Duration::hours(1)))
        .into_response();
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    (id, email, cookie)
}

async fn operator(pool: &MySqlPool, key: &Key) -> (u64, String) {
    let email = format!("run-dismiss-{}@example.test", uuid::Uuid::new_v4());
    let id = sqlx::query(
        "INSERT INTO users(name,email,password) VALUES('Run dismiss fixture',?,'unused')",
    )
    .bind(email)
    .execute(pool)
    .await
    .unwrap()
    .last_insert_id();
    sqlx::query(
        "INSERT INTO role_user(role_id,user_id) SELECT id,? FROM roles WHERE name='operator'",
    )
    .bind(id)
    .execute(pool)
    .await
    .unwrap();
    let (session, _) = sessions::create(pool, id, "127.0.0.1", "run-dismiss-test", 1)
        .await
        .unwrap();
    let token = sessions::mark_totp_verified_and_rotate(pool, session)
        .await
        .unwrap();
    let response = SignedCookieJar::new(key.clone())
        .add(sessions::build_cookie(token, time::Duration::hours(1)))
        .into_response();
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    (id, cookie)
}

async fn get(app: &Router, cookie: &str, path: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .header("cookie", cookie)
                .extension(ConnectInfo(
                    "127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({"raw":String::from_utf8_lossy(&bytes)})),
    )
}

async fn post(app: &Router, cookie: &str, path: &str, body: Value) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .header("cookie", cookie)
                .extension(ConnectInfo(
                    "127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
                ))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({"raw":String::from_utf8_lossy(&bytes)})),
    )
}

#[tokio::test]
async fn proven_no_write_recovery_can_be_dismissed_without_deleting_history() {
    let db = common::test_database().await;
    let pool = db.pool().clone();
    let key = Key::from(&[82_u8; 64]);
    let (user, cookie) = operator(&pool, &key).await;
    let app = api::router(api::AppState {
        pool: pool.clone(),
        config: Config::default(),
        cookie_key: key,
    });
    let source = sqlx::query("INSERT INTO reroute_bundles(trigger_type,triggered_by_user_id,state,lifecycle_state,total_actions,completed_actions,remaining_mutations,source_json) VALUES('manual',?,'succeeded','active',1,1,1,JSON_OBJECT('kind','manual'))")
        .bind(user).execute(&pool).await.unwrap().last_insert_id();
    let child = sqlx::query("INSERT INTO reroute_bundles(parent_bundle_id,trigger_type,triggered_by_user_id,state,lifecycle_state,total_actions,completed_actions,source_json,failure_reason) VALUES(?,'manual',?,'failed','inactive',1,1,JSON_OBJECT('kind','recovery'),'failed before router write')")
        .bind(source).bind(user).execute(&pool).await.unwrap().last_insert_id();
    sqlx::query("INSERT INTO recovery_attempt_sources(recovery_bundle_id,source_bundle_id,claim_token,settlement,settled_at) VALUES(?,?,?,'known_no_write',UTC_TIMESTAMP())")
        .bind(child).bind(source).bind(format!("dismiss-{child}")).execute(&pool).await.unwrap();

    let (_, before) = get(&app, &cookie, &format!("/api/reroute-bundles/{source}")).await;
    assert_eq!(before["latest_recovery_bundle_id"], child);
    assert_eq!(before["latest_recovery"]["dismiss"]["available"], true);
    let phrase = format!("DISMISS RECOVERY #{child}");
    assert_eq!(
        before["latest_recovery"]["dismiss"]["confirmation_phrase"],
        phrase
    );
    assert_eq!(
        post(
            &app,
            &cookie,
            &format!("/api/reroute-bundles/{child}/dismiss-recovery"),
            json!({"confirmation":"CONFIRM"}),
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY,
    );
    let (status, dismissed) = post(
        &app,
        &cookie,
        &format!("/api/reroute-bundles/{child}/dismiss-recovery"),
        json!({"confirmation":phrase}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{dismissed}");
    let (_, after) = get(&app, &cookie, &format!("/api/reroute-bundles/{source}")).await;
    assert_eq!(after["latest_recovery"], Value::Null);
    let (_, retained) = get(&app, &cookie, &format!("/api/reroute-bundles/{child}")).await;
    assert!(retained["source"]["dismissed_at"].is_string());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM audit_logs WHERE event_type='recovery_attempt_dismissed' AND entity_id=?")
            .bind(child).fetch_one(&pool).await.unwrap(),
        1,
    );
}

#[tokio::test]
async fn one_original_run_owns_summary_lifecycle_and_dashboard_action_events_are_optional() {
    let db = common::test_database().await;
    let pool = db.pool().clone();
    let key = Key::from(&[83_u8; 64]);
    let (user, email, cookie) = viewer(&pool, &key).await;
    let app = api::router(api::AppState {
        pool: pool.clone(),
        config: Config::default(),
        cookie_key: key,
    });
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let device = sqlx::query("INSERT INTO devices(name,hostname) VALUES(?,'192.0.2.240')")
        .bind(format!("run-summary-router-{suffix}"))
        .execute(&pool)
        .await
        .unwrap()
        .last_insert_id();
    let preset =
        sqlx::query("INSERT INTO mitigation_presets(name,created_by,updated_by) VALUES(?,?,?)")
            .bind(format!("run-summary-preset-{suffix}"))
            .bind(user)
            .bind(user)
            .execute(&pool)
            .await
            .unwrap()
            .last_insert_id();
    let source = json!({"kind":"preset","preset_id":preset,"preset_name":format!("run-summary-preset-{suffix}"),
        "preset_revision":3,"verification_mode":"configuration_only","routing_verified":false});
    let root = sqlx::query("INSERT INTO reroute_bundles(trigger_type,triggered_by_user_id,state,failure_policy,total_actions,completed_actions,lifecycle_state,remaining_mutations,source_json,started_at,finished_at) \
        VALUES('manual',?,'succeeded','abort_and_compensate',2,2,'active',2,?,UTC_TIMESTAMP(),UTC_TIMESTAMP())")
        .bind(user).bind(sqlx::types::Json(&source)).execute(&pool).await.unwrap().last_insert_id();
    let child_source = json!({"kind":"bundle_revert","original_bundle_id":root,"preset_id":preset,
        "verification_mode":"configuration_only","routing_verified":false});
    let child = sqlx::query("INSERT INTO reroute_bundles(parent_bundle_id,trigger_type,triggered_by_user_id,state,failure_policy,total_actions,completed_actions,lifecycle_state,remaining_mutations,source_json) \
        VALUES(?,'manual',?,'succeeded','abort_and_compensate',1,1,'active',1,?)")
        .bind(root).bind(user).bind(sqlx::types::Json(&child_source)).execute(&pool).await.unwrap().last_insert_id();
    sqlx::query("UPDATE reroute_bundles SET recovery_bundle_id=? WHERE id=?")
        .bind(child)
        .bind(root)
        .execute(&pool)
        .await
        .unwrap();
    // The active source run is older than the five-row recent-history window.
    // Current state must come from active_runs, not from recent_runs.
    let mut newer_inactive = Vec::new();
    for _ in 0..6 {
        newer_inactive.push(sqlx::query("INSERT INTO reroute_bundles(trigger_type,triggered_by_user_id,state,failure_policy,total_actions,completed_actions,lifecycle_state,remaining_mutations,source_json,started_at,finished_at) \
            VALUES('manual',?,'succeeded','abort_and_compensate',0,0,'inactive',0,?,UTC_TIMESTAMP(),UTC_TIMESTAMP())")
            .bind(user).bind(sqlx::types::Json(&source)).execute(&pool).await.unwrap().last_insert_id());
    }
    let changed = sqlx::query("INSERT INTO reroutes(bundle_id,bundle_position,device_id,trigger_type,state,mutation_effect,started_at,finished_at) \
        VALUES(?,0,?,'manual','succeeded','changed',UTC_TIMESTAMP(),UTC_TIMESTAMP())")
        .bind(root).bind(device).execute(&pool).await.unwrap().last_insert_id();
    let unknown = sqlx::query("INSERT INTO reroutes(bundle_id,bundle_position,device_id,trigger_type,state,mutation_effect,started_at,finished_at) \
        VALUES(?,1,?,'manual','uncertain','unknown',UTC_TIMESTAMP(),UTC_TIMESTAMP())")
        .bind(root).bind(device).execute(&pool).await.unwrap().last_insert_id();
    let standalone = sqlx::query("INSERT INTO reroutes(device_id,trigger_type,state,mutation_effect,started_at,finished_at) \
        VALUES(?,'manual','succeeded','changed',UTC_TIMESTAMP(),UTC_TIMESTAMP())")
        .bind(device).execute(&pool).await.unwrap().last_insert_id();

    let marker = format!("run-summary-{suffix}");
    for (event, reroute) in [("reroute_started", changed), ("reroute_succeeded", changed)] {
        sqlx::query("INSERT INTO alerts(event_type,severity,device_id,payload_json,dedup_key) VALUES(?,'info',?,?,?)")
            .bind(event).bind(device).bind(sqlx::types::Json(json!({"reroute_id":reroute,"marker":marker})))
            .bind(format!("{marker}:{event}:{reroute}")).execute(&pool).await.unwrap();
    }
    sqlx::query("INSERT INTO alerts(event_type,severity,device_id,payload_json,dedup_key) VALUES('reroute_succeeded','info',?,?,?)")
        .bind(device).bind(sqlx::types::Json(json!({"reroute_id":standalone,"marker":marker})))
        .bind(format!("{marker}:standalone")).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO alerts(event_type,severity,payload_json,dedup_key) VALUES('rule_fired','warning',?,?)")
        .bind(sqlx::types::Json(json!({"marker":marker}))).bind(format!("{marker}:rule"))
        .execute(&pool).await.unwrap();
    // The newest row is bundled noise. A one-row dashboard request must skip
    // it in SQL instead of paging it first and returning no useful event.
    sqlx::query("INSERT INTO alerts(event_type,severity,device_id,payload_json,dedup_key) VALUES('reroute_uncertain','critical',?,?,?)")
        .bind(device).bind(sqlx::types::Json(json!({"reroute_id":unknown,"marker":marker})))
        .bind(format!("{marker}:uncertain:{unknown}")).execute(&pool).await.unwrap();

    let (status, active) = get(
        &app,
        &cookie,
        "/api/reroute-bundles?lifecycle=active&page=1&per_page=200",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{active}");
    let active_items = active["items"].as_array().unwrap();
    let summary = active_items
        .iter()
        .find(|item| item["id"] == root)
        .expect("original active run");
    assert!(
        !active_items.iter().any(|item| item["id"] == child),
        "recovery child must not be a second active mitigation"
    );
    assert_eq!(summary["execution_state"], "succeeded");
    assert_eq!(summary["lifecycle_state"], "active");
    assert_eq!(summary["remaining_mutations"], 2);
    assert_eq!(summary["remaining_changes"], 1);
    assert_eq!(summary["unknown_effects"], 1);
    assert_eq!(summary["affected_devices"][0]["id"], device);
    assert_eq!(summary["triggered_by"], email);
    assert_eq!(summary["recovery_bundle_id"], child);
    assert_eq!(summary["verification_mode"], "configuration_only");
    assert_eq!(summary["revert"]["available"], false);
    assert!(summary["revert"]["block_reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason.as_str().unwrap_or_default().contains("unknown")));

    let (_, logical) = get(
        &app,
        &cookie,
        "/api/reroute-bundles?original_only=true&page=1&per_page=200",
    )
    .await;
    assert!(logical["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["id"] == root));
    assert!(!logical["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["id"] == child));
    let (_, detail) = get(&app, &cookie, &format!("/api/reroute-bundles/{root}")).await;
    assert!(detail["created_at"].is_string(), "{detail}");
    assert_eq!(
        detail["still_applied_reroute_ids"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let (_, preset_value) = get(&app, &cookie, &format!("/api/mitigation-presets/{preset}")).await;
    assert_eq!(
        preset_value["recent_runs"].as_array().unwrap().len(),
        5,
        "{preset_value}"
    );
    assert!(
        !preset_value["recent_runs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|run| run["bundle_id"] == root),
        "older active run is deliberately outside recent history"
    );
    assert_eq!(
        preset_value["active_runs"].as_array().unwrap().len(),
        1,
        "{preset_value}"
    );
    assert_eq!(preset_value["active_runs"][0]["bundle_id"], root);
    assert_eq!(preset_value["active_runs"][0]["remaining_mutations"], 2);
    assert!(
        !preset_value["active_runs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|run| run["bundle_id"] == child),
        "recovery child must stay nested under its source run"
    );

    let (_, raw) = get(&app, &cookie, "/api/alerts?limit=200").await;
    let raw_marker = raw["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["payload"]["marker"] == marker)
        .collect::<Vec<_>>();
    assert_eq!(
        raw_marker.len(),
        5,
        "raw alert history must remain complete"
    );
    assert_eq!(
        raw_marker
            .iter()
            .find(|row| row["payload"]["reroute_id"] == changed)
            .unwrap()["bundle_id"],
        root
    );
    let (_, dashboard) = get(
        &app,
        &cookie,
        "/api/alerts?limit=200&exclude_bundle_action_events=true",
    )
    .await;
    let dashboard_marker = dashboard["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["payload"]["marker"] == marker)
        .collect::<Vec<_>>();
    assert_eq!(
        dashboard_marker.len(),
        2,
        "only bundled per-action lifecycle events are hidden"
    );
    assert!(dashboard_marker
        .iter()
        .any(|row| row["payload"]["reroute_id"] == standalone));
    assert!(dashboard_marker
        .iter()
        .any(|row| row["event_type"] == "rule_fired"));
    let (_, one_raw) = get(&app, &cookie, "/api/alerts?limit=1").await;
    assert_eq!(one_raw["rows"][0]["event_type"], "reroute_uncertain");
    let (_, one_dashboard) = get(
        &app,
        &cookie,
        "/api/alerts?limit=1&exclude_bundled_action_lifecycle=true",
    )
    .await;
    assert_eq!(
        one_dashboard["rows"][0]["event_type"], "rule_fired",
        "filter must run before LIMIT"
    );

    sqlx::query("DELETE FROM alerts WHERE dedup_key LIKE ?")
        .bind(format!("{marker}%"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM reroutes WHERE id IN (?,?,?)")
        .bind(changed)
        .bind(unknown)
        .bind(standalone)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE reroute_bundles SET recovery_bundle_id=NULL WHERE id=?")
        .bind(root)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM reroute_bundles WHERE id=?")
        .bind(child)
        .execute(&pool)
        .await
        .unwrap();
    for id in newer_inactive {
        sqlx::query("DELETE FROM reroute_bundles WHERE id=?")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
    }
    sqlx::query("DELETE FROM reroute_bundles WHERE id=?")
        .bind(root)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM mitigation_presets WHERE id=?")
        .bind(preset)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM devices WHERE id=?")
        .bind(device)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id=?")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn latest_manual_recovery_is_derived_during_claim_and_after_settlement() {
    let db = common::test_database().await;
    let pool = db.pool().clone();
    let key = Key::from(&[84_u8; 64]);
    let (user, _, cookie) = viewer(&pool, &key).await;
    let app = api::router(api::AppState {
        pool: pool.clone(),
        config: Config::default(),
        cookie_key: key,
    });
    let source = sqlx::query("INSERT INTO reroute_bundles(trigger_type,triggered_by_user_id,state,failure_policy,total_actions,completed_actions,lifecycle_state,remaining_mutations,recovery_claim_token,source_json,started_at,finished_at) \
        VALUES('manual',?,'succeeded','abort_and_compensate',8,8,'recovery_claimed',8,'manual:test',JSON_OBJECT('kind','preset','preset_name','Recovery fixture'),UTC_TIMESTAMP(),UTC_TIMESTAMP())")
        .bind(user).execute(&pool).await.unwrap().last_insert_id();
    let older = sqlx::query("INSERT INTO reroute_bundles(parent_bundle_id,trigger_type,triggered_by_user_id,state,failure_policy,total_actions,completed_actions,lifecycle_state,remaining_mutations,source_json,started_at,finished_at,failure_reason) \
        VALUES(?,'manual',?,'failed','abort_and_compensate',8,3,'inactive',0,JSON_OBJECT('kind','bundle_revert','original_bundle_id',?),UTC_TIMESTAMP(),UTC_TIMESTAMP(),'older recovery failed')")
        .bind(source).bind(user).bind(source).execute(&pool).await.unwrap().last_insert_id();
    let newest = sqlx::query("INSERT INTO reroute_bundles(parent_bundle_id,trigger_type,triggered_by_user_id,state,failure_policy,total_actions,completed_actions,lifecycle_state,remaining_mutations,source_json,started_at) \
        VALUES(?,'manual',?,'running','abort_and_compensate',8,4,'recovery_running',0,JSON_OBJECT('kind','bundle_revert','original_bundle_id',?),UTC_TIMESTAMP())")
        .bind(source).bind(user).bind(source).execute(&pool).await.unwrap().last_insert_id();
    let unrelated = sqlx::query("INSERT INTO reroute_bundles(trigger_type,triggered_by_user_id,state,failure_policy,total_actions,completed_actions,lifecycle_state,remaining_mutations,source_json,started_at) \
        VALUES('manual',?,'running','abort_and_compensate',1,0,'recovery_running',0,JSON_OBJECT('kind','bundle_revert','original_bundle_id',?),UTC_TIMESTAMP())")
        .bind(user).bind(source).execute(&pool).await.unwrap().last_insert_id();

    let (status, claimed) = get(&app, &cookie, &format!("/api/reroute-bundles/{source}")).await;
    assert_eq!(status, StatusCode::OK, "{claimed}");
    assert_eq!(
        claimed["recovery_bundle_id"],
        Value::Null,
        "scheduler ownership column remains untouched"
    );
    assert_eq!(claimed["latest_recovery_bundle_id"], newest);
    assert_eq!(claimed["latest_recovery"]["id"], newest);
    assert_eq!(claimed["latest_recovery"]["parent_bundle_id"], source);
    assert_eq!(claimed["latest_recovery"]["state"], "running");
    assert_eq!(claimed["latest_recovery"]["completed_actions"], 4);
    assert_eq!(claimed["latest_recovery"]["total_actions"], 8);
    assert_ne!(
        claimed["latest_recovery_bundle_id"], older,
        "newest child wins"
    );
    assert_ne!(
        claimed["latest_recovery_bundle_id"], unrelated,
        "a newer bundle without parent or inverse evidence is not associated"
    );

    let (_, child) = get(&app, &cookie, &format!("/api/reroute-bundles/{newest}")).await;
    assert_eq!(child["parent_bundle_id"], source);
    assert_eq!(child["latest_recovery_bundle_id"], Value::Null);
    assert_eq!(child["latest_recovery"], Value::Null);

    let (_, active) = get(
        &app,
        &cookie,
        "/api/reroute-bundles?lifecycle=active&page=1&per_page=200",
    )
    .await;
    let active_source = active["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|run| run["id"] == source)
        .expect("claimed source remains the one active logical run");
    assert_eq!(active_source["latest_recovery_bundle_id"], newest);
    assert!(!active["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|run| run["id"] == newest || run["id"] == older));
    let (_, raw) = get(&app, &cookie, "/api/reroute-bundles").await;
    assert!(raw
        .as_array()
        .unwrap()
        .iter()
        .any(|run| run["id"] == newest));
    assert!(raw.as_array().unwrap().iter().any(|run| run["id"] == older));
    let (_, logical) = get(
        &app,
        &cookie,
        "/api/reroute-bundles?logical_only=true&page=1&per_page=200",
    )
    .await;
    assert!(logical["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|run| run["id"] == source));
    assert!(!logical["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|run| run["id"] == newest || run["id"] == older));

    sqlx::query("UPDATE reroute_bundles SET state='succeeded',completed_actions=8,lifecycle_state='inactive',finished_at=UTC_TIMESTAMP() WHERE id=?")
        .bind(newest).execute(&pool).await.unwrap();
    sqlx::query("UPDATE reroute_bundles SET lifecycle_state='inactive',remaining_mutations=0,recovery_claim_token=NULL WHERE id=?")
        .bind(source).execute(&pool).await.unwrap();
    let (_, settled) = get(&app, &cookie, &format!("/api/reroute-bundles/{source}")).await;
    assert_eq!(settled["remaining_mutations"], 0);
    assert_eq!(settled["recovery_bundle_id"], Value::Null);
    assert_eq!(settled["latest_recovery_bundle_id"], newest);
    assert_eq!(settled["latest_recovery"]["state"], "succeeded");
    assert_eq!(settled["latest_recovery"]["completed_actions"], 8);
    assert!(settled["latest_recovery"]["finished_at"].is_string());
    let (_, inactive_now) = get(
        &app,
        &cookie,
        "/api/reroute-bundles?lifecycle=active&page=1&per_page=200",
    )
    .await;
    assert!(!inactive_now["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|run| run["id"] == source));

    sqlx::query("DELETE FROM reroute_bundles WHERE id IN (?,?,?)")
        .bind(newest)
        .bind(older)
        .bind(unrelated)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM reroute_bundles WHERE id=?")
        .bind(source)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id=?")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
}
