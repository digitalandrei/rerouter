mod common;

use std::time::Duration;

use rerouter_controller::db::advisory::{self, LockRuntime};

#[tokio::test]
async fn nested_locks_reuse_one_scoped_session_and_release_cleanly() {
    let db = common::test_database().await;
    let runtime = LockRuntime::from_data_pool(db.pool()).await.unwrap();
    advisory::foreground_scope(runtime, async {
        let first = advisory::acquire("test:00:first").await.unwrap();
        let second = advisory::acquire("test:10:second").await.unwrap();
        second.release().await.unwrap();
        first.release().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn foreground_capacity_is_four_and_background_has_its_own_reserve() {
    let db = common::test_database().await;
    let runtime = LockRuntime::from_data_pool(db.pool()).await.unwrap();
    // Empty/read-only scopes do not consume advisory capacity.
    for _ in 0..16 {
        advisory::foreground_scope(runtime.clone(), async {})
            .await
            .unwrap();
    }
    // Escaped guards retain both their session and foreground reservation.
    let mut guards = Vec::new();
    for index in 0..4 {
        guards.push(
            advisory::foreground_scope(runtime.clone(), async move {
                advisory::acquire(&format!("test:capacity:{index}"))
                    .await
                    .unwrap()
            })
            .await
            .unwrap(),
        );
    }
    let blocked = tokio::time::timeout(
        Duration::from_millis(100),
        advisory::foreground_scope(runtime.clone(), async {
            advisory::acquire("test:capacity:fifth").await
        }),
    )
    .await;
    assert!(blocked.is_err(), "a fifth foreground operation must wait");
    advisory::background_scope(runtime, async {
        let guard = advisory::acquire("test:capacity:background").await.unwrap();
        guard.release().await.unwrap();
    })
    .await
    .unwrap();
    for guard in guards {
        guard.release().await.unwrap();
    }
}

#[tokio::test]
async fn nested_scope_reuses_runtime_and_rollback_precedes_policy() {
    let db = common::test_database().await;
    let runtime = LockRuntime::from_data_pool(db.pool()).await.unwrap();
    advisory::foreground_scope(runtime.clone(), async {
        let rollback = advisory::acquire("05:reroute:rollback:42").await.unwrap();
        advisory::foreground_scope(runtime.clone(), async {
            let fence = rerouter_controller::reroute::guard::policy_fence(db.pool())
                .await
                .unwrap();
            fence.release().await.unwrap();
        })
        .await
        .unwrap();
        rollback.release().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn nested_different_runtime_and_reused_config_pool_are_rejected() {
    let db = common::test_database().await;
    let runtime = LockRuntime::from_data_pool(db.pool()).await.unwrap();
    let other_runtime = LockRuntime::from_data_pool(db.pool()).await.unwrap();
    advisory::foreground_scope(runtime, async {
        assert!(advisory::foreground_scope(other_runtime, async {})
            .await
            .is_err());
    })
    .await
    .unwrap();

    let cfg = rerouter_controller::config::Config::default();
    cfg.advisory_runtime(db.pool()).await.unwrap();
    let other_pool = sqlx::mysql::MySqlPoolOptions::new()
        .max_connections(1)
        .connect_with(db.pool().connect_options().as_ref().clone())
        .await
        .unwrap();
    assert!(cfg.advisory_runtime(&other_pool).await.is_err());
}

#[tokio::test]
async fn unreleased_guard_discards_its_session_before_reuse() {
    let db = common::test_database().await;
    let runtime = LockRuntime::from_data_pool(db.pool()).await.unwrap();
    advisory::foreground_scope(runtime.clone(), async {
        let guard = advisory::acquire("test:discard").await.unwrap();
        drop(guard);
    })
    .await
    .unwrap();
    advisory::foreground_scope(runtime, async {
        let guard = advisory::acquire("test:discard").await.unwrap();
        guard.release().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn poisoned_idle_session_is_replaced_for_later_compensation_locks() {
    let db = common::test_database().await;
    let runtime = LockRuntime::from_data_pool(db.pool()).await.unwrap();
    advisory::foreground_scope(runtime, async {
        let refused_action_fence = advisory::acquire("10:execution:policy").await.unwrap();
        drop(refused_action_fence);

        let policy = advisory::acquire("10:execution:policy").await.unwrap();
        let rate = advisory::acquire("20:reroute:rate-global").await.unwrap();
        let device = advisory::acquire("30:reroute:device:42").await.unwrap();
        device.release().await.unwrap();
        rate.release().await.unwrap();
        policy.release().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn poisoned_session_is_not_replaced_while_an_outer_guard_is_live() {
    let db = common::test_database().await;
    let runtime = LockRuntime::from_data_pool(db.pool()).await.unwrap();
    advisory::foreground_scope(runtime, async {
        let outer = advisory::acquire("10:execution:policy").await.unwrap();
        let dropped = advisory::acquire("20:reroute:rate-global").await.unwrap();
        drop(dropped);
        assert!(advisory::acquire("30:reroute:device:42").await.is_err());
        outer.release().await.unwrap();
        let fresh = advisory::acquire("10:execution:policy").await.unwrap();
        fresh.release().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelled_acquisition_discards_session_and_releases_its_older_lock() {
    let db = common::test_database().await;
    let runtime = LockRuntime::from_data_pool(db.pool()).await.unwrap();
    let mut blocker = db.pool().acquire().await.unwrap();
    let blocked_name = rerouter_controller::db::scoped_advisory_lock_name(
        &mut blocker,
        "20:test:cancellation-blocker",
    )
    .await
    .unwrap();
    let got: Option<i64> = sqlx::query_scalar("SELECT GET_LOCK(?,0)")
        .bind(&blocked_name)
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    assert_eq!(got, Some(1));

    advisory::foreground_scope(runtime, async {
        let older = advisory::acquire("10:test:older").await.unwrap();
        let cancelled = tokio::time::timeout(
            Duration::from_millis(50),
            advisory::acquire("20:test:cancellation-blocker"),
        )
        .await;
        assert!(cancelled.is_err());
        drop(older);
        let released: Option<i64> = sqlx::query_scalar("SELECT RELEASE_LOCK(?)")
            .bind(&blocked_name)
            .fetch_one(&mut *blocker)
            .await
            .unwrap();
        assert_eq!(released, Some(1));
        let fresh = advisory::acquire("10:test:older").await.unwrap();
        fresh.release().await.unwrap();
    })
    .await
    .unwrap();
}
