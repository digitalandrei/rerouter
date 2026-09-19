//! Session lifecycle coverage through independently reconstructed application routers.
//! Uses only the dedicated test schema supplied by REROUTER_TEST_DATABASE_URL.
mod common;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use axum::response::IntoResponse;
use axum::Router;
use axum_extra::extract::cookie::{Key, SignedCookieJar};
use rerouter_controller::{api, auth::sessions, config::Config};
use sqlx::MySqlPool;
use totp_rs::{Algorithm, Secret, TOTP};
use tower::ServiceExt;

async fn user(pool: &MySqlPool) -> u64 {
    sqlx::query("INSERT INTO users(name,email,password) VALUES('Session test',?,'unused')")
        .bind(format!("session-{}@example.test", uuid::Uuid::new_v4()))
        .execute(pool)
        .await
        .unwrap()
        .last_insert_id()
}

fn signed_cookie(key: &Key, token: String, lifetime: time::Duration) -> String {
    SignedCookieJar::new(key.clone())
        .add(sessions::build_cookie(token, lifetime))
        .into_response()
        .headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

fn app(pool: &MySqlPool, key: &Key) -> Router {
    api::router(api::AppState {
        pool: pool.clone(),
        config: Config::default(),
        cookie_key: key.clone(),
    })
}

async fn call(app: &Router, method: Method, cookie: &str, path: &str) -> StatusCode {
    app.clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("cookie", cookie)
                .extension(ConnectInfo(
                    "127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}

async fn post_json(
    app: &Router,
    path: &str,
    cookie: Option<&str>,
    body: serde_json::Value,
) -> (StatusCode, Option<String>) {
    let mut request = Request::builder()
        .method(Method::POST)
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
    let cookie = response
        .headers()
        .get("set-cookie")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    (response.status(), cookie)
}

fn cookie_pair(set_cookie: &str) -> String {
    set_cookie.split(';').next().unwrap().to_owned()
}
fn max_age(set_cookie: &str) -> i64 {
    set_cookie
        .split(';')
        .find_map(|part| part.trim().strip_prefix("Max-Age="))
        .unwrap()
        .parse()
        .unwrap()
}

async fn login_through_totp(
    pool: &MySqlPool,
    app: &Router,
    remember: bool,
) -> (u64, String, String) {
    const PASSWORD: &str = "test-password-which-is-never-a-live-credential";
    const SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    let email = format!("session-login-{}@example.test", uuid::Uuid::new_v4());
    let encrypted = hex::encode(rerouter_controller::crypto::seal_str(SECRET).unwrap());
    let user_id = sqlx::query("INSERT INTO users(name,email,password,two_factor_secret,two_factor_confirmed_at) VALUES('Session login test',?,?,?,UTC_TIMESTAMP())")
        .bind(&email).bind(rerouter_controller::auth::password::hash(PASSWORD).unwrap()).bind(encrypted).execute(pool).await.unwrap().last_insert_id();
    let (status, first_cookie) = post_json(
        app,
        "/api/auth/login",
        None,
        serde_json::json!({"email":email,"password":PASSWORD,"remember":remember}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let first_cookie = first_cookie.unwrap();
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        Secret::Encoded(SECRET.into()).to_bytes().unwrap(),
        Some("Rerouter".into()),
        email,
    )
    .unwrap();
    let code = totp.generate_current().unwrap();
    let (status, promoted_cookie) = post_json(
        app,
        "/api/auth/totp",
        Some(&cookie_pair(&first_cookie)),
        serde_json::json!({"code":code}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    (user_id, promoted_cookie.unwrap(), first_cookie)
}

#[tokio::test]
async fn remembered_session_survives_restart_but_not_idle_absolute_logout_or_pre2fa_boundaries() {
    let test_db = common::test_database().await;
    let pool = test_db.pool().clone();
    // Fixed non-production encryption material, scoped to this integration-test process.
    unsafe {
        std::env::set_var(
            "SECRETS_KEY",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
    };
    let key_material = [113_u8; 64];
    let first_app_key = Key::from(&key_material);
    let first_app = app(&pool, &first_app_key);
    let (remembered_user, promoted_cookie, pre2fa_set_cookie) =
        login_through_totp(&pool, &first_app, true).await;
    assert!((604_790..=604_800).contains(&max_age(&promoted_cookie)));
    assert_eq!(max_age(&pre2fa_set_cookie), 604_800);
    let remaining_hours: i64 = sqlx::query_scalar("SELECT TIMESTAMPDIFF(HOUR,UTC_TIMESTAMP(),expires_at) FROM sessions WHERE user_id=? ORDER BY id DESC LIMIT 1").bind(remembered_user).fetch_one(&pool).await.unwrap();
    assert!((167..=168).contains(&remaining_hours));
    let restarted_key = Key::from(&key_material);
    assert_eq!(
        call(
            &app(&pool, &restarted_key),
            Method::GET,
            &cookie_pair(&promoted_cookie),
            "/api/auth/me"
        )
        .await,
        StatusCode::OK
    );

    let (short_user, short_cookie, _) = login_through_totp(&pool, &first_app, false).await;
    assert!((43_190..=43_200).contains(&max_age(&short_cookie)));
    let short_hours: i64 = sqlx::query_scalar("SELECT TIMESTAMPDIFF(HOUR,UTC_TIMESTAMP(),expires_at) FROM sessions WHERE user_id=? ORDER BY id DESC LIMIT 1").bind(short_user).fetch_one(&pool).await.unwrap();
    assert!((11..=12).contains(&short_hours));

    let user_id = user(&pool).await;
    let key = Key::from(&[113_u8; 64]);

    let (session_id, _) = sessions::create(&pool, user_id, "127.0.0.1", "browser", 168)
        .await
        .unwrap();
    let token = sessions::mark_totp_verified_and_rotate(&pool, session_id)
        .await
        .unwrap();
    let cookie = signed_cookie(&key, token, time::Duration::days(7));
    assert_eq!(
        call(&app(&pool, &key), Method::GET, &cookie, "/api/auth/me").await,
        StatusCode::OK
    );

    // Reconstructing AppState/Router with the same durable pool and signing key
    // models a controller restart rather than reusing in-memory application state.
    let restarted = app(&pool, &key);
    assert_eq!(
        call(&restarted, Method::GET, &cookie, "/api/auth/me").await,
        StatusCode::OK
    );
    assert_eq!(
        call(&restarted, Method::POST, &cookie, "/api/auth/logout").await,
        StatusCode::OK
    );
    assert_eq!(
        call(&app(&pool, &key), Method::GET, &cookie, "/api/auth/me").await,
        StatusCode::UNAUTHORIZED
    );

    let (idle_id, _) = sessions::create(&pool, user_id, "127.0.0.1", "browser", 168)
        .await
        .unwrap();
    let idle_token = sessions::mark_totp_verified_and_rotate(&pool, idle_id)
        .await
        .unwrap();
    let idle_cookie = signed_cookie(&key, idle_token, time::Duration::days(7));
    sqlx::query("UPDATE sessions SET last_activity_at = DATE_SUB(UTC_TIMESTAMP(), INTERVAL 61 MINUTE) WHERE id = ?").bind(idle_id).execute(&pool).await.unwrap();
    assert_eq!(
        call(&app(&pool, &key), Method::GET, &idle_cookie, "/api/auth/me").await,
        StatusCode::UNAUTHORIZED
    );

    let (expired_id, _) = sessions::create(&pool, user_id, "127.0.0.1", "browser", 168)
        .await
        .unwrap();
    let expired_token = sessions::mark_totp_verified_and_rotate(&pool, expired_id)
        .await
        .unwrap();
    let expired_cookie = signed_cookie(&key, expired_token, time::Duration::days(7));
    sqlx::query("UPDATE sessions SET expires_at = DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 SECOND) WHERE id = ?").bind(expired_id).execute(&pool).await.unwrap();
    assert_eq!(
        call(
            &app(&pool, &key),
            Method::GET,
            &expired_cookie,
            "/api/auth/me"
        )
        .await,
        StatusCode::UNAUTHORIZED
    );

    let (_pre2fa_id, pre2fa_token) = sessions::create(&pool, user_id, "127.0.0.1", "browser", 168)
        .await
        .unwrap();
    let pre2fa_cookie = signed_cookie(&key, pre2fa_token, time::Duration::minutes(10));
    assert_eq!(
        call(
            &app(&pool, &key),
            Method::GET,
            &pre2fa_cookie,
            "/api/auth/me"
        )
        .await,
        StatusCode::UNAUTHORIZED
    );

    let browser_cookie = sessions::build_cookie("opaque".into(), time::Duration::days(7));
    assert_eq!(browser_cookie.max_age(), Some(time::Duration::days(7)));
    unsafe { std::env::remove_var("SECRETS_KEY") };
}
