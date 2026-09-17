//! Real router/auth/RBAC/SQL coverage; all requests remain in observe mode and
//! the fixture has no SSH credentials. No device or notification is contacted.
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

async fn user(pool: &MySqlPool, role: &str, key: &Key) -> (u64, String) {
    let id = sqlx::query("INSERT INTO users(name,email,password) VALUES('API test',?,'unused')")
        .bind(format!("api-{}@example.test", uuid::Uuid::new_v4()))
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
    let (session, _) = sessions::create(pool, id, "127.0.0.1", "integration-test", 1)
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

async fn request(
    app: &Router,
    cookie: Option<&str>,
    method: &str,
    path: &str,
    body: Value,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .extension(ConnectInfo(
            "127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
        ));
    if let Some(cookie) = cookie {
        request = request.header("cookie", cookie);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({"error":String::from_utf8_lossy(&bytes)}));
    (status, value)
}

fn draft(action: &Value) -> Value {
    json!({"id":action["id"],"reroute_template_id":action["reroute_template_id"],"device_id":action["device_id"],
        "params":action["params"],"enabled":action["enabled"],"auto_target":null})
}

#[tokio::test]
async fn presets_are_atomic_revisioned_copies_and_observe_runs_do_not_mutate_them() {
    let pool = common::test_database().await;
    sqlx::query("UPDATE system_settings SET `value`='observe' WHERE `key`='operating_mode'")
        .execute(&*pool)
        .await
        .unwrap();
    let key = Key::from(&[74_u8; 64]);
    let (operator, operator_cookie) = user(&pool, "operator", &key).await;
    let (viewer, viewer_cookie) = user(&pool, "viewer", &key).await;
    let app = api::router(api::AppState {
        pool: (*pool).clone(),
        config: Config::default(),
        cookie_key: key,
    });
    assert_eq!(
        request(&app, None, "GET", "/api/mitigation-presets", Value::Null)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(
            &app,
            Some(&viewer_cookie),
            "POST",
            "/api/mitigation-presets",
            json!({"name":"Denied","actions":[]})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(
            &app,
            Some(&viewer_cookie),
            "POST",
            "/api/manual-mitigations/preview",
            json!({"actions":[]})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let device = sqlx::query("INSERT INTO devices(name,hostname) VALUES(?,'192.0.2.254')")
        .bind(format!("manual-api-{}", uuid::Uuid::new_v4()))
        .execute(&*pool)
        .await
        .unwrap()
        .last_insert_id();
    sqlx::query("INSERT INTO device_bgp_networks(device_id,prefix,last_discovered_at) VALUES(?,'192.0.2.0/24',UTC_TIMESTAMP())")
        .bind(device).execute(&*pool).await.unwrap();
    let template: u64 =
        sqlx::query_scalar("SELECT id FROM reroute_templates WHERE name='null_route_prefix'")
            .fetch_one(&*pool)
            .await
            .unwrap();
    let original = json!([
        {"reroute_template_id":template,"device_id":device,"params":{"prefix":"192.0.2.1/32"}},
        {"reroute_template_id":template,"device_id":device,"params":{"prefix":"192.0.2.2/32"}}
    ]);
    let name = format!("Manual API {}", uuid::Uuid::new_v4());
    let (status, created) = request(
        &app,
        Some(&operator_cookie),
        "POST",
        "/api/mitigation-presets",
        json!({"name":name,"description":"Atomic test","actions":original}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let preset = created["id"].as_u64().unwrap();
    assert_eq!(created["revision"], 1);
    assert_eq!(created["actions"].as_array().unwrap().len(), 2);
    let path = format!("/api/mitigation-presets/{preset}");
    let mut invalid = original.clone();
    invalid[1]["device_id"] = json!(u32::MAX);
    assert_eq!(
        request(
            &app,
            Some(&operator_cookie),
            "PUT",
            &path,
            json!({"name":name,"revision":1,"actions":invalid})
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        request(
            &app,
            Some(&operator_cookie),
            "PUT",
            &path,
            json!({"name":name,"revision":0,"actions":original})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let (_, unchanged) = request(&app, Some(&operator_cookie), "GET", &path, Value::Null).await;
    assert_eq!(unchanged["revision"], 1);
    assert_eq!(unchanged["actions"].as_array().unwrap().len(), 2);
    let rule=sqlx::query("INSERT INTO rules(name,metric,operator,threshold_value,automatic_reroute_enabled) VALUES(?,'rx_bps','>',1,1)")
        .bind(format!("rule-copy-{}",uuid::Uuid::new_v4())).execute(&*pool).await.unwrap().last_insert_id();
    let copied: Vec<_> = created["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(draft)
        .collect();
    let (status, rule_value) = request(
        &app,
        Some(&operator_cookie),
        "PUT",
        &format!("/api/rules/{rule}/actions"),
        json!({"revision":1,"actions":copied,"preset_id":preset,"preset_revision":1}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{rule_value}");
    assert_eq!(rule_value["automatic_reroute_enabled"], false);
    assert_eq!(rule_value["actions_revision"], 2);
    let mut changed = original.clone();
    changed[0]["params"]["prefix"] = json!("192.0.2.3/32");
    let (status, updated) = request(
        &app,
        Some(&operator_cookie),
        "PUT",
        &path,
        json!({"name":name,"revision":1,"actions":changed}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_eq!(updated["revision"], 2);
    let (_, rule_unchanged) = request(
        &app,
        Some(&operator_cookie),
        "GET",
        &format!("/api/rules/{rule}"),
        Value::Null,
    )
    .await;
    assert_eq!(
        rule_unchanged["actions"][0]["params"]["prefix"],
        "192.0.2.1/32"
    );
    let mut overrides: Vec<_> = updated["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(draft)
        .collect();
    overrides[0]["params"]["prefix"] = json!("192.0.2.99/32");
    let (status,preview)=request(&app,Some(&operator_cookie),"POST","/api/manual-mitigations/preview",
        json!({"preset_id":preset,"preset_revision":2,"actions":overrides,"reason":"Preview override"})).await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert!(preview["preview_token"].is_null());
    assert!(preview["results"][0]["would_run"]["commands"]
        .to_string()
        .contains("192.0.2.99"));
    let (_, saved) = request(&app, Some(&operator_cookie), "GET", &path, Value::Null).await;
    assert_eq!(saved["actions"][0]["params"]["prefix"], "192.0.2.3/32");
    overrides.reverse();
    assert_eq!(
        request(
            &app,
            Some(&operator_cookie),
            "POST",
            "/api/manual-mitigations/preview",
            json!({"preset_id":preset,"preset_revision":2,"actions":overrides})
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    sqlx::query("INSERT INTO rule_states(rule_id,current_state) VALUES(?,'firing') ON DUPLICATE KEY UPDATE current_state='firing'")
        .bind(rule).execute(&*pool).await.unwrap();
    assert_eq!(
        request(
            &app,
            Some(&operator_cookie),
            "PUT",
            &format!("/api/rules/{rule}/actions"),
            json!({"revision":2,"actions":original})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        request(
            &app,
            Some(&operator_cookie),
            "DELETE",
            &path,
            json!({"revision":1})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        request(
            &app,
            Some(&operator_cookie),
            "DELETE",
            &path,
            json!({"revision":2})
        )
        .await
        .0,
        StatusCode::OK
    );
    let (_, rule_after_archive) = request(
        &app,
        Some(&operator_cookie),
        "GET",
        &format!("/api/rules/{rule}"),
        Value::Null,
    )
    .await;
    assert_eq!(rule_after_archive["actions"].as_array().unwrap().len(), 2);
    let reroutes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reroutes WHERE device_id=?")
        .bind(device)
        .fetch_one(&*pool)
        .await
        .unwrap();
    assert_eq!(
        reroutes, 0,
        "observe preview must never reserve or execute a reroute"
    );
    // Clear without owned changes still requires a preview and works in observe.
    assert_eq!(
        request(
            &app,
            Some(&operator_cookie),
            "POST",
            &format!("/api/rules/{rule}/clear"),
            json!({})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let (status, clear) = request(
        &app,
        Some(&operator_cookie),
        "POST",
        &format!("/api/rules/{rule}/clear"),
        json!({"dry_run":true,"reason":"Clear detection only"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{clear}");
    assert!(clear["preview_token"].is_string(), "{clear}");
    let (status, cleared) = request(
        &app,
        Some(&operator_cookie),
        "POST",
        &format!("/api/rules/{rule}/clear"),
        json!({"preview_token":clear["preview_token"],"reason":"Clear detection only"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{cleared}");
    assert_eq!(cleared["cleared"], true, "{cleared}");
    // Only fixture-owned rows are removed; operational history is protected by
    // the public API and foreign keys and is not part of test cleanup.
    sqlx::query("DELETE FROM execution_plans WHERE user_id=?")
        .bind(operator)
        .execute(&*pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM reroute_bundles WHERE rule_id=?")
        .bind(rule)
        .execute(&*pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM rules WHERE id=?")
        .bind(rule)
        .execute(&*pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM mitigation_preset_actions WHERE preset_id=?")
        .bind(preset)
        .execute(&*pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM mitigation_presets WHERE id=?")
        .bind(preset)
        .execute(&*pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM devices WHERE id=?")
        .bind(device)
        .execute(&*pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id IN (?,?)")
        .bind(operator)
        .bind(viewer)
        .execute(&*pool)
        .await
        .unwrap();
}
