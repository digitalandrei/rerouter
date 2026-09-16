//! Ordered mitigation bundles — the gate behaviour a multi-action mitigation
//! depends on (plan 015; audit finding SPEC-13).
//!
//! The defect these tests pin down: a rule's ordered action set is ONE authorized
//! activation, but the guard derived cooldowns from durable reroute history
//! without excluding the bundle's own earlier siblings. The first action's
//! `started_at` therefore throttled every later action — a 14-action mitigation
//! applied roughly one action and stopped, leaving traffic half-diverted.
//!
//! The fix must be narrow. Exempting too much would let unrelated activations
//! hammer the same device, so each "sibling is allowed" assertion below is paired
//! with a "stranger is still blocked" assertion over the very same history row.
//!
//! DB integration test — runs only when DATABASE_URL points at a MariaDB the test
//! may migrate + write to; skips otherwise. Cleans up its rows.

use rerouter_controller::config::Config;
use rerouter_controller::db::MIGRATOR;
use rerouter_controller::reroute::executor::{ActionRequest, BundleMembership};
use rerouter_controller::reroute::guard::{self, BlockReason};
use rerouter_controller::reroute::templates::{RenderedPlan, Template};
use serde_json::json;
use sqlx::mysql::MySqlPoolOptions;
use sqlx::MySqlPool;
use tokio::sync::{Mutex, OnceCell};

/// Migrate once per process. Several `#[tokio::test]`s in one binary run
/// concurrently, and concurrent migrator runs against one schema fail — which
/// surfaces as a fail-closed `i64::MAX` gate read rather than an obvious error.
static MIGRATED: OnceCell<()> = OnceCell::const_new();

/// Serializes the tests in this file. The rate-budget gates read GLOBAL counters,
/// so two of these running at once would read each other's rows.
static SERIAL: Mutex<()> = Mutex::const_new(());

async fn pool_or_skip() -> Option<MySqlPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = MySqlPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect to DATABASE_URL");
    MIGRATED
        .get_or_init(|| async {
            MIGRATOR.run(&pool).await.expect("run migrations");
        })
        .await;
    Some(pool)
}

/// Shipped nonzero cooldowns and no rate limit, so a test that blocks is blocking
/// on cooldown and nothing else.
fn cfg_with_cooldowns() -> Config {
    let mut cfg = Config::default();
    cfg.safety.same_rule_cooldown_seconds = 900;
    cfg.safety.same_device_cooldown_seconds = 300;
    cfg.safety.global_action_rate_limit_count = 0;
    cfg
}

fn template() -> Template {
    Template {
        id: 0,
        name: "bgp_advertise_add".into(),
        display_name: None,
        description: None,
        provider_type: "device_cli".into(),
        mode: "ios_ssh".into(),
        automatic_allowed: true,
        parameter_schema: json!({}),
        plan: json!({}),
        verification: json!({}),
        rollback_template_id: None,
        v6_sibling_template_id: None,
        enabled: true,
    }
}

fn request(device_id: u64, rule_id: u64, bundle: Option<BundleMembership>) -> ActionRequest {
    ActionRequest {
        device_id,
        template: template(),
        params: json!({}),
        trigger_type: "manual",
        rule_id: Some(rule_id),
        rule_event_id: None,
        rollback_of_reroute_id: None,
        user_id: None,
        actor_context: None,
        reason: Some("bundle execution test".into()),
        defer_cooldown: true,
        bundle,
    }
}

fn plan() -> RenderedPlan {
    RenderedPlan {
        template_id: 0,
        template_name: "bgp_advertise_add".into(),
        config_mode: true,
        commands: vec!["ip prefix-list PL permit 192.0.2.0/24".into()],
        verify: None,
        sequence_pending: false,
    }
}

/// Names are unique per process run. `devices.name` is UNIQUE, so a fixed name
/// would make a crashed earlier run poison every later one with a duplicate-key
/// error that looks like a product defect.
fn unique(prefix: &str) -> String {
    format!("{prefix}-{}", std::process::id())
}

/// A rule row, because `reroutes.rule_id` is a real foreign key.
async fn insert_rule(pool: &MySqlPool, name: &str) -> u64 {
    sqlx::query(
        "INSERT INTO rules (name, metric, operator, threshold_value, duration_seconds, severity) \
         VALUES (?, 'tx_bps', '>', 1000000, 60, 'high')",
    )
    .bind(name)
    .execute(pool)
    .await
    .expect("insert rule")
    .last_insert_id()
}

async fn insert_device(pool: &MySqlPool, name: &str) -> u64 {
    sqlx::query("INSERT INTO devices (name, hostname) VALUES (?, '127.0.0.1')")
        .bind(name)
        .execute(pool)
        .await
        .expect("insert device")
        .last_insert_id()
}

async fn insert_bundle(pool: &MySqlPool, rule_id: u64, total: u32) -> u64 {
    sqlx::query(
        "INSERT INTO reroute_bundles (rule_id, trigger_type, state, total_actions) \
         VALUES (?, 'manual', 'running', ?)",
    )
    .bind(rule_id)
    .bind(total)
    .execute(pool)
    .await
    .expect("insert bundle")
    .last_insert_id()
}

/// A sibling that has already STARTED — exactly the history row that used to
/// throttle the rest of its own bundle.
async fn insert_started_sibling(
    pool: &MySqlPool,
    device_id: u64,
    rule_id: u64,
    bundle_id: Option<u64>,
    position: u32,
) {
    sqlx::query(
        "INSERT INTO reroutes \
            (device_id, rule_id, bundle_id, bundle_position, trigger_type, state, started_at) \
         VALUES (?, ?, ?, ?, 'manual', 'succeeded', UTC_TIMESTAMP())",
    )
    .bind(device_id)
    .bind(rule_id)
    .bind(bundle_id)
    .bind(position)
    .execute(pool)
    .await
    .expect("insert sibling reroute");
}

async fn cleanup(pool: &MySqlPool, rule_id: u64, device_ids: &[u64]) {
    let _ = sqlx::query("DELETE FROM reroutes WHERE rule_id = ?")
        .bind(rule_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM reroute_bundles WHERE rule_id = ?")
        .bind(rule_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM rules WHERE id = ?")
        .bind(rule_id)
        .execute(pool)
        .await;
    for d in device_ids {
        let _ = sqlx::query("DELETE FROM devices WHERE id = ?")
            .bind(d)
            .execute(pool)
            .await;
    }
}

/// SPEC-13 regression. The scrubber-advertise on router B must not be throttled by
/// the withdraw the same bundle just ran on router A, and a same-device sibling
/// must pass too (the bundle fans six prefixes onto each router). Paired with the
/// strangers that must STILL be blocked by that same history row.
#[tokio::test]
async fn bundle_sibling_survives_cooldown_but_a_stranger_does_not() {
    let _serial = SERIAL.lock().await;
    let Some(pool) = pool_or_skip().await else {
        eprintln!("DATABASE_URL not set — skipping bundle execution integration test");
        return;
    };
    let cfg = cfg_with_cooldowns();

    let rule_id = insert_rule(&pool, &unique("bundle-cooldown-test")).await;
    let dev_a = insert_device(&pool, &unique("bundle-test-router-a")).await;
    let dev_b = insert_device(&pool, &unique("bundle-test-router-b")).await;
    let bundle_id = insert_bundle(&pool, rule_id, 3).await;

    // Sibling #0 already ran on router A, inside this bundle.
    insert_started_sibling(&pool, dev_a, rule_id, Some(bundle_id), 0).await;

    // Sibling #1 on router B, same bundle: passes the cooldown gates.
    let sibling = request(
        dev_b,
        rule_id,
        Some(BundleMembership {
            bundle_id,
            position: 1,
        }),
    );
    let inputs = guard::gather(&pool, &cfg, &sibling, &plan())
        .await
        .expect("gather gate inputs for the cross-device sibling");
    assert_eq!(
        inputs.rule_cooldown_until, None,
        "a bundle's own earlier sibling must not put the rule in cooldown"
    );
    assert_eq!(
        guard::decide(&inputs),
        Ok(()),
        "sibling #1 of the same authorized bundle must not be blocked by sibling #0"
    );

    // Same router as sibling #0, same bundle: also allowed.
    let same_device_sibling = request(
        dev_a,
        rule_id,
        Some(BundleMembership {
            bundle_id,
            position: 2,
        }),
    );
    let inputs = guard::gather(&pool, &cfg, &same_device_sibling, &plan())
        .await
        .expect("gather gate inputs for the same-device sibling");
    assert_eq!(
        inputs.device_cooldown_until, None,
        "a bundle's own earlier sibling must not put its device in cooldown"
    );
    assert_eq!(
        guard::decide(&inputs),
        Ok(()),
        "a same-device sibling of the same bundle must not be blocked"
    );

    // A SEPARATE activation of the same rule sees the same history and IS blocked.
    let stranger = request(dev_b, rule_id, None);
    let inputs = guard::gather(&pool, &cfg, &stranger, &plan())
        .await
        .expect("gather gate inputs for the unrelated activation");
    assert!(
        inputs.rule_cooldown_until.is_some(),
        "an unrelated activation must still see the rule cooldown from bundle history"
    );
    assert!(
        matches!(
            guard::decide(&inputs),
            Err(BlockReason::RuleCooldown { .. })
        ),
        "an activation outside the bundle must still be throttled"
    );

    // A DIFFERENT bundle is equally a stranger — the exemption is per bundle id,
    // not "any bundle".
    let other_bundle = insert_bundle(&pool, rule_id, 1).await;
    let other = request(
        dev_b,
        rule_id,
        Some(BundleMembership {
            bundle_id: other_bundle,
            position: 0,
        }),
    );
    let inputs = guard::gather(&pool, &cfg, &other, &plan())
        .await
        .expect("gather gate inputs for the other bundle");
    assert!(
        matches!(
            guard::decide(&inputs),
            Err(BlockReason::RuleCooldown { .. })
        ),
        "a different bundle must not inherit this bundle's exemption"
    );

    cleanup(&pool, rule_id, &[dev_a, dev_b]).await;
}

/// The `exclude_bundle IS NULL` arm must not swallow rows whose `bundle_id` is
/// also NULL: standalone history must keep throttling standalone actions.
#[tokio::test]
async fn standalone_history_still_throttles_a_standalone_action() {
    let _serial = SERIAL.lock().await;
    let Some(pool) = pool_or_skip().await else {
        eprintln!("DATABASE_URL not set — skipping standalone cooldown test");
        return;
    };
    let cfg = cfg_with_cooldowns();

    let rule_id = insert_rule(&pool, &unique("standalone-cooldown-test")).await;
    let dev = insert_device(&pool, &unique("standalone-test-router")).await;
    insert_started_sibling(&pool, dev, rule_id, None, 0).await;

    let req = request(dev, rule_id, None);
    let inputs = guard::gather(&pool, &cfg, &req, &plan())
        .await
        .expect("gather gate inputs");
    assert!(
        inputs.device_cooldown_until.is_some(),
        "a prior standalone action must still create a device cooldown"
    );
    assert!(
        inputs.rule_cooldown_until.is_some(),
        "a prior standalone action must still create a rule cooldown"
    );

    cleanup(&pool, rule_id, &[dev]).await;
}

/// All-or-nothing admission. A 14-action bundle against a 3-action budget is
/// refused WHOLE — the old behaviour spent the budget mid-bundle and left the
/// mitigation half-applied, which for withdraw-then-advertise is the black-hole.
#[tokio::test]
async fn oversized_bundle_is_refused_whole() {
    let _serial = SERIAL.lock().await;
    let Some(pool) = pool_or_skip().await else {
        eprintln!("DATABASE_URL not set — skipping bundle admission test");
        return;
    };
    let mut cfg = Config::default();
    cfg.safety.global_action_rate_limit_count = 3;
    // A SHORT window, so rows left behind by an earlier crashed run (or by another
    // test binary sharing this database) have already aged out and the assertions
    // turn only on what this test just inserted.
    cfg.safety.global_action_rate_limit_window_seconds = 5;

    let rule_id = insert_rule(&pool, &unique("bundle-admission-test")).await;
    let bundle_id = insert_bundle(&pool, rule_id, 14).await;

    // Refusal is robust to noise: other test binaries sharing this database can
    // only ADD to the window count, never reduce it.
    let refused = guard::admit_bundle(&pool, &cfg, bundle_id, 14).await;
    assert!(
        matches!(refused, Err(BlockReason::RateLimit { max: 3, .. })),
        "a 14-action bundle must not be admitted against a 3-action budget, got {refused:?}"
    );

    // Raising the budget deliberately is what makes it runnable — the code does
    // not quietly stretch the limit to let a bundle through. The headroom is
    // generous so a concurrent test binary's rows cannot flip this assertion.
    cfg.safety.global_action_rate_limit_count = 5_000;
    assert_eq!(
        guard::admit_bundle(&pool, &cfg, bundle_id, 14).await,
        Ok(()),
        "the same bundle must be admitted once the operator raises the budget"
    );

    cleanup(&pool, rule_id, &[]).await;
}

/// Capacity another in-flight bundle reserved but has not yet spent counts against
/// admission, so two concurrent bundles cannot both be admitted against one budget.
#[tokio::test]
async fn reserved_capacity_of_another_bundle_blocks_admission() {
    let _serial = SERIAL.lock().await;
    let Some(pool) = pool_or_skip().await else {
        eprintln!("DATABASE_URL not set — skipping bundle reservation test");
        return;
    };
    // Large absolute numbers, so the assertions turn on the RESERVATION and not on
    // how many rows a concurrently-running test binary happened to leave behind.
    let mut cfg = Config::default();
    cfg.safety.global_action_rate_limit_count = 5_000;
    // Short window — see the note in `oversized_bundle_is_refused_whole`.
    cfg.safety.global_action_rate_limit_window_seconds = 5;

    let rule_id = insert_rule(&pool, &unique("bundle-reservation-test")).await;
    // A large bundle is already running and has spent none of its budget.
    let running = insert_bundle(&pool, rule_id, 4_995).await;
    let mine = insert_bundle(&pool, rule_id, 10).await;

    // Assert on the COUNT as well as the refusal. A fail-closed read error also
    // produces `RateLimit`, with `recent` saturated at i64::MAX — that would make
    // this test pass while the reservation logic was broken.
    let refused = guard::admit_bundle(&pool, &cfg, mine, 10).await;
    match refused {
        Err(BlockReason::RateLimit { recent, .. }) => {
            assert!(
                (4_995..5_100).contains(&recent),
                "refusal must come from the other bundle's reservation (~4995), not a \
                 fail-closed read error; got recent = {recent}"
            );
        }
        other => panic!("4995 reserved + 10 requested must exceed a budget of 5000, got {other:?}"),
    }

    // Once the other bundle finishes, its reservation stops counting.
    let _ = sqlx::query("UPDATE reroute_bundles SET state = 'succeeded' WHERE id = ?")
        .bind(running)
        .execute(&pool)
        .await;
    assert_eq!(
        guard::admit_bundle(&pool, &cfg, mine, 5).await,
        Ok(()),
        "a finished bundle must release its reserved capacity"
    );

    cleanup(&pool, rule_id, &[]).await;
}
