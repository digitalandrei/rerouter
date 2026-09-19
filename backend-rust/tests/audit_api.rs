mod common;
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{Request, StatusCode},
    response::IntoResponse,
    Router,
};
use axum_extra::extract::cookie::{Key, SignedCookieJar};
use rerouter_controller::{api, auth::sessions, config::Config};
use serde_json::Value;
use sqlx::MySqlPool;
use tower::ServiceExt;

async fn actor(pool: &MySqlPool, role: &str, key: &Key) -> (u64, String) {
    let email = format!("audit-{}@example.test", uuid::Uuid::new_v4());
    let id =
        sqlx::query("INSERT INTO users(name,email,password) VALUES('Audit fixture',?,'unused')")
            .bind(&email)
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
    let (session, _) = sessions::create(pool, id, "127.0.0.1", "audit-test", 1)
        .await
        .unwrap();
    let token = sessions::mark_totp_verified_and_rotate(pool, session)
        .await
        .unwrap();
    let response = SignedCookieJar::new(key.clone())
        .add(sessions::build_cookie(token, time::Duration::hours(1)))
        .into_response();
    (
        id,
        response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string(),
    )
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
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn audit_filters_page_and_permission_are_enforced() {
    let db = common::test_database().await;
    let pool = db.pool().clone();
    let key = Key::from(&[91_u8; 64]);
    let (auditor, auditor_cookie) = actor(&pool, "auditor", &key).await;
    let (viewer, viewer_cookie) = actor(&pool, "viewer", &key).await;
    let marker = format!("audit_fixture_{}", uuid::Uuid::new_v4().simple());
    for n in 0..3 {
        sqlx::query("INSERT INTO audit_logs(actor_type,actor_user_id,event_type,entity_type,entity_id,message) VALUES('user',?,?,?,?,?)").bind(auditor).bind(&marker).bind("fixture_entity").bind(9000+n).bind(format!("fixture {n}")).execute(&pool).await.unwrap();
    }
    let app = api::router(api::AppState {
        pool: pool.clone(),
        config: Config::default(),
        cookie_key: key,
    });
    assert_eq!(
        get(&app, &viewer_cookie, "/api/audit?limit=1&page=1")
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let path=format!("/api/audit?action={marker}&entity=fixture_entity&actor=audit-&page=1&limit=2&after=2000-01-01T00:00");
    let (status, first) = get(&app, &auditor_cookie, &path).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["rows"].as_array().unwrap().len(), 2);
    assert_eq!(first["has_more"], true);
    let second = get(&app, &auditor_cookie, &path.replace("page=1", "page=2"))
        .await
        .1;
    assert_eq!(second["rows"].as_array().unwrap().len(), 1);
    assert_eq!(second["has_more"], false);
    sqlx::query("DELETE FROM audit_logs WHERE event_type=?")
        .bind(&marker)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id IN (?,?)")
        .bind(auditor)
        .bind(viewer)
        .execute(&pool)
        .await
        .unwrap();
}
