//! Real-router authorization tests for immutable manual execution plans.
//! Fixtures have no SSH credentials, so accepted plans can create durable bundle
//! identity but can never contact a router.
mod common;

use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use axum::Router;
use axum_extra::extract::cookie::{Key, SignedCookieJar};
use chrono::{Duration, Utc};
use rerouter_controller::reroute::bundle::BundleAction;
use rerouter_controller::reroute::device_plan::{
    DeviceStateSnapshot, PreparedDeviceAction, PreparedEffect, PreparedInverse,
    PREPARED_DEVICE_ACTION_SCHEMA_VERSION,
};
use rerouter_controller::{api, auth::sessions, config::Config};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::MySqlPool;
use tower::ServiceExt;

async fn user(pool: &MySqlPool, role: &str, key: &Key) -> (u64, String) {
    let id = sqlx::query("INSERT INTO users(name,email,password) VALUES('Plan test',?,'unused')")
        .bind(format!("plan-{}@example.test", uuid::Uuid::new_v4()))
        .execute(pool)
        .await
        .unwrap()
        .last_insert_id();
    sqlx::query("INSERT INTO role_user(role_id,user_id) SELECT id,? FROM roles WHERE name=?")
        .bind(id)
        .bind(role)
        .execute(pool)
        .await
        .unwrap();
    let (session, _) = sessions::create(pool, id, "127.0.0.1", "plan-test", 1)
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

async fn request(app: &Router, cookie: &str, path: &str, body: Value) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header("cookie", cookie)
        .extension(ConnectInfo(
            "127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
        ))
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({"error":String::from_utf8_lossy(&bytes)}));
    (status, value)
}

fn hash_snapshot(snapshot: &Value) -> String {
    hex::encode(Sha256::digest(snapshot.to_string().as_bytes()))
}

fn unique_token(label: &str) -> String {
    format!("{label}-{}", uuid::Uuid::new_v4())
}

async fn insert_plan(
    pool: &MySqlPool,
    user_id: u64,
    scope: &str,
    scope_id: Option<u64>,
    snapshot: &Value,
    token: &str,
    expires_delta: Duration,
) -> u64 {
    sqlx::query(
        "INSERT INTO execution_plans \
         (user_id,scope,scope_id,reason,snapshot_json,plan_hash,token_hash,expires_at) \
         VALUES(?,?,?,?,?,?,?,?)",
    )
    .bind(user_id)
    .bind(scope)
    .bind(scope_id)
    .bind("authorization test")
    .bind(sqlx::types::Json(snapshot))
    .bind(hash_snapshot(snapshot))
    .bind(sessions::hash_token(token))
    .bind((Utc::now() + expires_delta).naive_utc())
    .execute(pool)
    .await
    .unwrap()
    .last_insert_id()
}

async fn fixture(pool: &MySqlPool) -> (u64, BundleAction, PreparedDeviceAction) {
    let device = sqlx::query("INSERT INTO devices(name,hostname) VALUES(?,'192.0.2.250')")
        .bind(format!("plan-device-{}", uuid::Uuid::new_v4()))
        .execute(pool)
        .await
        .unwrap()
        .last_insert_id();
    sqlx::query(
        "INSERT INTO device_bgp_networks(device_id,prefix,last_discovered_at) \
         VALUES(?,'192.0.2.0/24',UTC_TIMESTAMP())",
    )
    .bind(device)
    .execute(pool)
    .await
    .unwrap();
    let template = rerouter_controller::reroute::templates::load(
        pool,
        sqlx::query_scalar("SELECT id FROM reroute_templates WHERE name='null_route_prefix'")
            .fetch_one(pool)
            .await
            .unwrap(),
    )
    .await
    .unwrap();
    let before = DeviceStateSnapshot::Ipv4StaticRoute {
        prefix: "192.0.2.1/32".into(),
        next_hop: "Null0".into(),
        tag: None,
        present: false,
    };
    let after = DeviceStateSnapshot::Ipv4StaticRoute {
        prefix: "192.0.2.1/32".into(),
        next_hop: "Null0".into(),
        tag: None,
        present: true,
    };
    let prepared = PreparedDeviceAction {
        schema_version: PREPARED_DEVICE_ACTION_SCHEMA_VERSION,
        device_id: device,
        template_id: template.id,
        template_name: template.name.clone(),
        canonical_params: json!({"prefix":"192.0.2.1/32"}),
        verification_mode: rerouter_controller::reroute::device_plan::VerificationMode::Routing,
        commands: vec!["ip route 192.0.2.1 255.255.255.255 Null0".into()],
        before: vec![before.clone()],
        after: vec![after.clone()],
        verify: vec![after.clone()],
        effect: PreparedEffect::Change,
        inverse: Some(PreparedInverse {
            verification_mode: rerouter_controller::reroute::device_plan::VerificationMode::Routing,
            expected_current: vec![after],
            restore: vec![before.clone()],
            commands: vec!["no ip route 192.0.2.1 255.255.255.255 Null0".into()],
            verify: vec![before],
        }),
        prepared_at: Utc::now(),
    };
    prepared.validate().unwrap();
    let action = BundleAction {
        device_id: device,
        template,
        params: json!({"prefix":"192.0.2.1/32"}),
        reason: "authorization test".into(),
        position: 0,
        auto_target: None,
        auto_target_low_confidence: None,
        prepared: Some(prepared.clone()),
        original_reroute_id: None,
    };
    (device, action, prepared)
}

fn snapshot(action: &BundleAction, prepared: &PreparedDeviceAction, source: Value) -> Value {
    json!({
        "actions":[action],
        "device_actions":[prepared],
        "source":source,
        "reason":"authorization test",
        "request":{"actions":[],"reason":"authorization test"}
    })
}

#[tokio::test]
async fn plans_bind_actor_scope_expiry_source_and_exact_prepared_set() {
    let pool = common::test_database().await;
    sqlx::query("UPDATE system_settings SET `value`='enforce' WHERE `key`='operating_mode'")
        .execute(&*pool)
        .await
        .unwrap();
    let key = Key::from(&[91_u8; 64]);
    let (operator_a, cookie_a) = user(&pool, "operator", &key).await;
    let (operator_b, cookie_b) = user(&pool, "operator", &key).await;
    let (viewer, cookie_viewer) = user(&pool, "viewer", &key).await;
    let app = api::router(api::AppState {
        pool: (*pool).clone(),
        config: Config::default(),
        cookie_key: key,
    });
    let (_device, action, prepared) = fixture(&pool).await;
    let manual = json!({"kind":"manual","name":"Run once"});

    let token = unique_token("actor-bound-token");
    let plan = insert_plan(
        &pool,
        operator_a,
        "manual_mitigation",
        None,
        &snapshot(&action, &prepared, manual.clone()),
        &token,
        Duration::minutes(5),
    )
    .await;
    assert_eq!(
        request(
            &app,
            &cookie_b,
            "/api/manual-mitigations/apply",
            json!({"plan_id":plan,"preview_token":token})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );

    let viewer_token = unique_token("viewer-token");
    let viewer_plan = insert_plan(
        &pool,
        viewer,
        "manual_mitigation",
        None,
        &snapshot(&action, &prepared, manual.clone()),
        &viewer_token,
        Duration::minutes(5),
    )
    .await;
    assert_eq!(
        request(
            &app,
            &cookie_viewer,
            "/api/manual-mitigations/apply",
            json!({"plan_id":viewer_plan,"preview_token":viewer_token})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );

    let scoped_token = unique_token("wrong-scope-token");
    let scoped_plan = insert_plan(
        &pool,
        operator_a,
        "rule_apply",
        Some(77),
        &snapshot(&action, &prepared, manual.clone()),
        &scoped_token,
        Duration::minutes(5),
    )
    .await;
    assert_eq!(
        request(
            &app,
            &cookie_a,
            "/api/manual-mitigations/apply",
            json!({"plan_id":scoped_plan,"preview_token":scoped_token})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );

    let expired_token = unique_token("expired-token");
    let expired_plan = insert_plan(
        &pool,
        operator_a,
        "manual_mitigation",
        None,
        &snapshot(&action, &prepared, manual.clone()),
        &expired_token,
        Duration::minutes(-1),
    )
    .await;
    assert_eq!(
        request(
            &app,
            &cookie_a,
            "/api/manual-mitigations/apply",
            json!({"plan_id":expired_plan,"preview_token":expired_token})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );

    let shortened = json!({
        "actions":[action.clone()], "device_actions":[], "source":manual,
        "reason":"authorization test", "request":{}
    });
    let shortened_token = unique_token("shortened-token");
    let shortened_plan = insert_plan(
        &pool,
        operator_a,
        "manual_mitigation",
        None,
        &shortened,
        &shortened_token,
        Duration::minutes(5),
    )
    .await;
    assert_eq!(
        request(
            &app,
            &cookie_a,
            "/api/manual-mitigations/apply",
            json!({"plan_id":shortened_plan,"preview_token":shortened_token})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );

    let mut different = prepared.clone();
    different.canonical_params = json!({"prefix":"192.0.2.2/32"});
    let corrupt = json!({
        "actions":[action.clone()], "device_actions":[different],
        "source":{"kind":"manual","name":"Run once"},
        "reason":"authorization test", "request":{}
    });
    let corrupt_token = unique_token("corrupt-token");
    let corrupt_plan = insert_plan(
        &pool,
        operator_a,
        "manual_mitigation",
        None,
        &corrupt,
        &corrupt_token,
        Duration::minutes(5),
    )
    .await;
    assert_eq!(
        request(
            &app,
            &cookie_a,
            "/api/manual-mitigations/apply",
            json!({"plan_id":corrupt_plan,"preview_token":corrupt_token})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );

    // Preset identity is part of authorization, not display metadata.
    let preset = sqlx::query(
        "INSERT INTO mitigation_presets(name,revision,created_by,updated_by) VALUES(?,1,?,?)",
    )
    .bind(format!("auth-preset-{}", uuid::Uuid::new_v4()))
    .bind(operator_a)
    .bind(operator_a)
    .execute(&*pool)
    .await
    .unwrap()
    .last_insert_id();
    let stale_source =
        json!({"kind":"preset","preset_id":preset,"preset_revision":1,"preset_name":"Auth preset"});
    let stale_token = unique_token("stale-source-token");
    let stale_plan = insert_plan(
        &pool,
        operator_a,
        "manual_mitigation",
        Some(preset),
        &snapshot(&action, &prepared, stale_source),
        &stale_token,
        Duration::minutes(5),
    )
    .await;
    sqlx::query("UPDATE mitigation_presets SET revision=2 WHERE id=?")
        .bind(preset)
        .execute(&*pool)
        .await
        .unwrap();
    assert_eq!(
        request(
            &app,
            &cookie_a,
            "/api/manual-mitigations/apply",
            json!({"plan_id":stale_plan,"preview_token":stale_token})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );

    let mismatch_source =
        json!({"kind":"preset","preset_id":preset,"preset_revision":2,"preset_name":"Auth preset"});
    let mismatch_token = unique_token("mismatched-scope-id-token");
    let mismatch_plan = insert_plan(
        &pool,
        operator_a,
        "manual_mitigation",
        Some(preset + 999),
        &snapshot(&action, &prepared, mismatch_source),
        &mismatch_token,
        Duration::minutes(5),
    )
    .await;
    assert_eq!(
        request(
            &app,
            &cookie_a,
            "/api/manual-mitigations/apply",
            json!({"plan_id":mismatch_plan,"preview_token":mismatch_token})
        )
        .await
        .0,
        StatusCode::CONFLICT,
        "scope_id must equal source preset_id"
    );

    let archived_source =
        json!({"kind":"preset","preset_id":preset,"preset_revision":2,"preset_name":"Auth preset"});
    let archived_token = unique_token("archived-source-token");
    let archived_plan = insert_plan(
        &pool,
        operator_a,
        "manual_mitigation",
        Some(preset),
        &snapshot(&action, &prepared, archived_source),
        &archived_token,
        Duration::minutes(5),
    )
    .await;
    sqlx::query("UPDATE mitigation_presets SET archived_at=UTC_TIMESTAMP() WHERE id=?")
        .bind(preset)
        .execute(&*pool)
        .await
        .unwrap();
    assert_eq!(
        request(
            &app,
            &cookie_a,
            "/api/manual-mitigations/apply",
            json!({"plan_id":archived_plan,"preview_token":archived_token})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );

    // Positive confirmation returns one durable bundle identity. Replaying the
    // same actor/scope/token is idempotent and never creates a second bundle.
    let valid_token = unique_token("idempotent-token");
    let valid_plan = insert_plan(
        &pool,
        operator_a,
        "manual_mitigation",
        None,
        &snapshot(
            &action,
            &prepared,
            json!({"kind":"manual","name":"Run once"}),
        ),
        &valid_token,
        Duration::minutes(5),
    )
    .await;
    let (status, first) = request(
        &app,
        &cookie_a,
        "/api/manual-mitigations/apply",
        json!({"plan_id":valid_plan,"preview_token":valid_token}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{first}");
    let (status, second) = request(
        &app,
        &cookie_a,
        "/api/manual-mitigations/apply",
        json!({"plan_id":valid_plan,"preview_token":valid_token}),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{second}");
    assert_eq!(first["bundle_id"], second["bundle_id"]);
    let bundles: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reroute_bundles WHERE id=?")
        .bind(first["bundle_id"].as_u64().unwrap())
        .fetch_one(&*pool)
        .await
        .unwrap();
    assert_eq!(bundles, 1);
    let attempts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reroutes WHERE bundle_id=?")
        .bind(first["bundle_id"].as_u64().unwrap())
        .fetch_one(&*pool)
        .await
        .unwrap();
    assert!(
        attempts <= 1,
        "idempotent confirmation created duplicate attempts"
    );

    // Keep otherwise-unused actor visible in this test's ownership set.
    assert_ne!(operator_a, operator_b);
}
