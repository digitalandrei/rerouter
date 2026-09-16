//! Inventory drift detection + auto-disarm — the failure paths are the point.
//!
//! The single rule this feature lives or dies by: auto-disarm may fire ONLY on a
//! positive, confirmed drift signal (a CONCLUSIVE discovery read whose freshly
//! reconciled inventory positively refuses the stored parameter). Anyone able to
//! make a router return an empty, denied or failing read must not thereby be able
//! to switch off the operator's automatic mitigations.
//!
//! So the tests below assert, in order: a confirmed drift marks the action and
//! disarms ONLY `automatic_reroute_enabled` (detection and alerting survive); an
//! INCONCLUSIVE read changes nothing even though the stored value would fail; a
//! later clean audit clears the marker but never re-arms; the audit row and the
//! alert are written; a database failure changes nothing; and a rule that is
//! mid-incident is never disarmed by a discovery run that lands on top of it.
//!
//! DB integration test — runs only when DATABASE_URL points at a MariaDB/MySQL the
//! test may migrate + write to; skips otherwise. Cleans up its rows.

use rerouter_controller::db::MIGRATOR;
use rerouter_controller::reroute::inventory_audit::{audit_device, InventoryRead};
use serde_json::json;
use sqlx::mysql::MySqlPoolOptions;
use sqlx::MySqlPool;

/// The peer the action targets when the stored prefix-list no longer belongs to
/// it — the real-world drift shape (the operator moved the list to another peer).
const DRIFTED_PEER: &str = "198.51.100.8";
/// The peer the stored prefix-list really is attached to.
const GOOD_PEER: &str = "198.51.100.7";
const PREFIX_LIST: &str = "pfx-to-viva";
const ANNOUNCED: &str = "198.51.100.0/24";

async fn pool_or_skip() -> Option<MySqlPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = MySqlPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect to DATABASE_URL");
    MIGRATOR.run(&pool).await.expect("run migrations");
    Some(pool)
}

struct Fixture {
    device_id: u64,
    rule_id: u64,
    action_id: u64,
}

/// One device with two BGP peers, a freshly discovered announced prefix, and a
/// rule whose single action advertises that prefix toward `target_peer` using
/// `PREFIX_LIST`. Everything is inside the validator windows, so the ONLY thing
/// that decides drift is whether `PREFIX_LIST` is attached to `target_peer`.
async fn seed(pool: &MySqlPool, tag: &str, target_peer: &str) -> Fixture {
    let device_id = sqlx::query("INSERT INTO devices (name, hostname) VALUES (?, '203.0.113.9')")
        .bind(format!("drift-{tag}"))
        .execute(pool)
        .await
        .expect("insert device")
        .last_insert_id();

    for (addr, list) in [(GOOD_PEER, PREFIX_LIST), (DRIFTED_PEER, "pfx-elsewhere")] {
        sqlx::query(
            "INSERT INTO device_bgp_peers \
                 (device_id, peer_remote_addr, out_prefix_list, last_polled_at, \
                  route_context_discovered_at) \
             VALUES (?, ?, ?, UTC_TIMESTAMP(), UTC_TIMESTAMP())",
        )
        .bind(device_id)
        .bind(addr)
        .bind(list)
        .execute(pool)
        .await
        .expect("insert bgp peer");
    }

    sqlx::query(
        "INSERT INTO device_bgp_networks \
             (device_id, prefix, first_seen_at, last_seen_at, last_discovered_at) \
         VALUES (?, ?, UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP())",
    )
    .bind(device_id)
    .bind(ANNOUNCED)
    .execute(pool)
    .await
    .expect("insert announced prefix");

    let template_id: u64 =
        sqlx::query_scalar("SELECT id FROM reroute_templates WHERE name = 'bgp_advertise_add'")
            .fetch_one(pool)
            .await
            .expect("seeded bgp_advertise_add template");

    let rule_id = sqlx::query(
        "INSERT INTO rules (name, metric, operator, threshold_value, enabled, \
                            automatic_reroute_enabled, alert_enabled) \
         VALUES (?, 'rx_bps', '>', 1000000, 1, 1, 1)",
    )
    .bind(format!("drift-rule-{tag}"))
    .execute(pool)
    .await
    .expect("insert rule")
    .last_insert_id();

    let action_id = sqlx::query(
        "INSERT INTO rule_actions (rule_id, reroute_template_id, device_id, params_json, enabled) \
         VALUES (?, ?, ?, ?, 1)",
    )
    .bind(rule_id)
    .bind(template_id)
    .bind(device_id)
    .bind(sqlx::types::Json(json!({
        "neighbor_ip": target_peer,
        "prefix": ANNOUNCED,
        "prefix_list_name": PREFIX_LIST,
    })))
    .execute(pool)
    .await
    .expect("insert rule action");

    Fixture {
        device_id,
        rule_id,
        action_id: action_id.last_insert_id(),
    }
}

async fn cleanup(pool: &MySqlPool, f: &Fixture) {
    for (sql, id) in [
        ("DELETE FROM audit_logs WHERE entity_type = 'rule_action' AND entity_id = ?", f.action_id),
        ("DELETE FROM audit_logs WHERE entity_type = 'rule' AND entity_id = ?", f.rule_id),
        ("DELETE FROM alerts WHERE rule_id = ?", f.rule_id),
        ("DELETE FROM alerts WHERE device_id = ?", f.device_id),
        ("DELETE FROM rules WHERE id = ?", f.rule_id),
        ("DELETE FROM devices WHERE id = ?", f.device_id),
    ] {
        let _ = sqlx::query(sql).bind(id).execute(pool).await;
    }
}

/// (inventory_state, inventory_drift_reason, inventory_checked_at IS NOT NULL)
async fn action_state(pool: &MySqlPool, action_id: u64) -> (String, Option<String>, bool) {
    sqlx::query_as::<_, (String, Option<String>, Option<chrono::DateTime<chrono::Utc>>)>(
        "SELECT inventory_state, inventory_drift_reason, inventory_checked_at \
           FROM rule_actions WHERE id = ?",
    )
    .bind(action_id)
    .fetch_one(pool)
    .await
    .map(|(s, r, c)| (s, r, c.is_some()))
    .expect("read action inventory state")
}

/// (enabled, automatic_reroute_enabled, alert_enabled, auto_disarmed_at IS NOT NULL, reason)
async fn rule_state(
    pool: &MySqlPool,
    rule_id: u64,
) -> (bool, bool, bool, bool, Option<String>) {
    sqlx::query_as::<_, (bool, bool, bool, Option<chrono::DateTime<chrono::Utc>>, Option<String>)>(
        "SELECT enabled, automatic_reroute_enabled, alert_enabled, auto_disarmed_at, \
                auto_disarmed_reason FROM rules WHERE id = ?",
    )
    .bind(rule_id)
    .fetch_one(pool)
    .await
    .map(|(e, a, al, at, r)| (e, a, al, at.is_some(), r))
    .expect("read rule state")
}

async fn count(pool: &MySqlPool, sql: &str, id: u64) -> i64 {
    sqlx::query_scalar(sql)
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("count")
}

#[tokio::test]
async fn confirmed_drift_marks_the_action_and_disarms_only_automatic_execution() {
    let Some(pool) = pool_or_skip().await else {
        eprintln!("DATABASE_URL not set — skipping inventory drift audit test");
        return;
    };
    let f = seed(&pool, "confirmed", DRIFTED_PEER).await;

    let summary = audit_device(&pool, f.device_id, InventoryRead::Conclusive)
        .await
        .expect("audit runs");

    let action = action_state(&pool, f.action_id).await;
    let rule = rule_state(&pool, f.rule_id).await;
    let drift_audit = count(
        &pool,
        "SELECT COUNT(*) FROM audit_logs WHERE entity_type = 'rule_action' AND entity_id = ? \
           AND event_type = 'rule_action_inventory_drift'",
        f.action_id,
    )
    .await;
    let disarm_audit = count(
        &pool,
        "SELECT COUNT(*) FROM audit_logs WHERE entity_type = 'rule' AND entity_id = ? \
           AND event_type = 'rule_auto_disarmed'",
        f.rule_id,
    )
    .await;
    let alerts = count(
        &pool,
        "SELECT COUNT(*) FROM alerts WHERE rule_id = ? AND event_type = 'rule_auto_disarmed'",
        f.rule_id,
    )
    .await;
    cleanup(&pool, &f).await;

    assert_eq!(summary.newly_drifted, 1, "the action must be marked");
    assert_eq!(summary.rules_disarmed, 1, "the rule must be disarmed");
    assert_eq!(action.0, "drifted");
    let reason = action.1.expect("a concrete validator message is stored");
    assert!(
        reason.contains(PREFIX_LIST) && reason.contains(DRIFTED_PEER),
        "the stored reason must name the prefix-list and the peer: {reason}"
    );
    assert!(action.2, "inventory_checked_at must be stamped");

    let (enabled, automatic, alert_enabled, disarmed_at, disarm_reason) = rule;
    assert!(!automatic, "AUTOMATIC execution must be off");
    assert!(enabled, "the rule must stay enabled — it keeps detecting");
    assert!(alert_enabled, "alerting must survive the disarm");
    assert!(disarmed_at, "auto_disarmed_at must record when");
    assert!(
        disarm_reason.is_some_and(|r| r.contains(PREFIX_LIST)),
        "auto_disarmed_reason must record why"
    );

    assert_eq!(drift_audit, 1, "the drift must be audited");
    assert_eq!(disarm_audit, 1, "the disarm must be audited");
    assert_eq!(alerts, 1, "an alert must be raised");
}

#[tokio::test]
async fn an_inconclusive_read_never_marks_and_never_disarms() {
    let Some(pool) = pool_or_skip().await else {
        eprintln!("DATABASE_URL not set — skipping inventory drift audit test");
        return;
    };
    // Exactly the fixture that DOES drift above: the stored prefix-list is not on
    // the targeted peer. The only difference is that the router's read proved
    // nothing — which must be enough to change nothing.
    let f = seed(&pool, "inconclusive", DRIFTED_PEER).await;

    let summary = audit_device(
        &pool,
        f.device_id,
        InventoryRead::Inconclusive("route_map_discovery_denied"),
    )
    .await
    .expect("audit runs");

    let action = action_state(&pool, f.action_id).await;
    let rule = rule_state(&pool, f.rule_id).await;
    let audits = count(
        &pool,
        "SELECT COUNT(*) FROM audit_logs WHERE entity_type = 'rule_action' AND entity_id = ?",
        f.action_id,
    )
    .await;
    let disarm_alerts = count(
        &pool,
        "SELECT COUNT(*) FROM alerts WHERE rule_id = ? AND event_type = 'rule_auto_disarmed'",
        f.rule_id,
    )
    .await;
    cleanup(&pool, &f).await;

    assert!(summary.skipped, "an inconclusive read must skip the audit");
    assert_eq!(summary.audited, 0);
    assert_eq!(action.0, "ok", "nothing may be marked");
    assert_eq!(action.1, None);
    assert!(!action.2, "not even inventory_checked_at may move");
    assert!(rule.1, "automatic execution must still be armed");
    assert!(!rule.3, "no auto-disarm may be recorded");
    assert_eq!(audits, 0, "nothing may be audited");
    assert_eq!(disarm_alerts, 0, "no disarm alert may be raised");
}

#[tokio::test]
async fn recovery_clears_the_drift_marker_but_never_re_arms() {
    let Some(pool) = pool_or_skip().await else {
        eprintln!("DATABASE_URL not set — skipping inventory drift audit test");
        return;
    };
    // The action validates again, but the rule is still disarmed from an earlier
    // drift. Re-arming is a human act (global enable + step-up re-auth), so the
    // audit must clear the marker and stop there.
    let f = seed(&pool, "recovery", GOOD_PEER).await;
    sqlx::query(
        "UPDATE rule_actions SET inventory_state = 'drifted', \
                inventory_drift_reason = 'prefix-list was not attached to peer' WHERE id = ?",
    )
    .bind(f.action_id)
    .execute(&pool)
    .await
    .expect("pre-mark drift");
    sqlx::query(
        "UPDATE rules SET automatic_reroute_enabled = 0, auto_disarmed_at = UTC_TIMESTAMP(), \
                auto_disarmed_reason = 'routing inventory drift' WHERE id = ?",
    )
    .bind(f.rule_id)
    .execute(&pool)
    .await
    .expect("pre-disarm rule");

    let summary = audit_device(&pool, f.device_id, InventoryRead::Conclusive)
        .await
        .expect("audit runs");

    let action = action_state(&pool, f.action_id).await;
    let rule = rule_state(&pool, f.rule_id).await;
    let recovered_audit = count(
        &pool,
        "SELECT COUNT(*) FROM audit_logs WHERE entity_type = 'rule_action' AND entity_id = ? \
           AND event_type = 'rule_action_inventory_recovered'",
        f.action_id,
    )
    .await;
    cleanup(&pool, &f).await;

    assert_eq!(summary.recovered, 1);
    assert_eq!(summary.rules_disarmed, 0);
    assert_eq!(action.0, "ok", "the marker must be cleared");
    assert_eq!(action.1, None, "the reason must be cleared");
    assert!(action.2);
    assert!(
        !rule.1,
        "automatic execution must stay OFF until a human re-arms it"
    );
    assert!(rule.3, "the auto-disarm record must survive as the audit trail");
    assert_eq!(recovered_audit, 1, "the recovery must be audited");
}

#[tokio::test]
async fn a_database_failure_during_the_audit_changes_nothing() {
    let Some(pool) = pool_or_skip().await else {
        eprintln!("DATABASE_URL not set — skipping inventory drift audit test");
        return;
    };
    let f = seed(&pool, "db-error", DRIFTED_PEER).await;

    // A pool that cannot answer. Every verdict the audit could reach is
    // Indeterminate, and an indeterminate verdict must decide nothing — a database
    // hiccup that disarmed live mitigations would be a denial-of-protection bug.
    let broken = MySqlPoolOptions::new()
        .max_connections(1)
        .connect(&std::env::var("DATABASE_URL").expect("DATABASE_URL"))
        .await
        .expect("second pool");
    broken.close().await;

    let outcome = audit_device(&broken, f.device_id, InventoryRead::Conclusive).await;

    let action = action_state(&pool, f.action_id).await;
    let rule = rule_state(&pool, f.rule_id).await;
    cleanup(&pool, &f).await;

    assert!(outcome.is_err(), "the audit must surface the failure");
    assert_eq!(action.0, "ok", "nothing may be marked on a DB failure");
    assert!(!action.2);
    assert!(rule.1, "the rule must still be armed");
    assert!(!rule.3);
}

#[tokio::test]
async fn a_rule_that_is_mid_incident_is_never_disarmed() {
    let Some(pool) = pool_or_skip().await else {
        eprintln!("DATABASE_URL not set — skipping inventory drift audit test");
        return;
    };
    // Drifted parameters AND a firing rule: a discovery run landing here must not
    // switch off the mitigation that is running right now. It defers to the next run.
    let f = seed(&pool, "firing", DRIFTED_PEER).await;
    sqlx::query("INSERT INTO rule_states (rule_id, current_state) VALUES (?, 'firing')")
        .bind(f.rule_id)
        .execute(&pool)
        .await
        .expect("insert rule state");

    let summary = audit_device(&pool, f.device_id, InventoryRead::Conclusive)
        .await
        .expect("audit runs");

    let action = action_state(&pool, f.action_id).await;
    let rule = rule_state(&pool, f.rule_id).await;
    cleanup(&pool, &f).await;

    assert_eq!(summary.deferred, 1);
    assert_eq!(summary.audited, 0);
    assert_eq!(action.0, "ok");
    assert!(rule.1, "a firing rule must stay armed");
}

#[tokio::test]
async fn an_in_flight_reroute_defers_the_whole_device() {
    let Some(pool) = pool_or_skip().await else {
        eprintln!("DATABASE_URL not set — skipping inventory drift audit test");
        return;
    };
    let f = seed(&pool, "in-flight", DRIFTED_PEER).await;
    sqlx::query(
        "INSERT INTO reroutes (device_id, rule_id, trigger_type, state) \
         VALUES (?, ?, 'automatic', 'running')",
    )
    .bind(f.device_id)
    .bind(f.rule_id)
    .execute(&pool)
    .await
    .expect("insert in-flight reroute");

    let summary = audit_device(&pool, f.device_id, InventoryRead::Conclusive)
        .await
        .expect("audit runs");

    let action = action_state(&pool, f.action_id).await;
    let rule = rule_state(&pool, f.rule_id).await;
    let _ = sqlx::query("DELETE FROM reroutes WHERE device_id = ?")
        .bind(f.device_id)
        .execute(&pool)
        .await;
    cleanup(&pool, &f).await;

    assert!(summary.device_busy);
    assert_eq!(summary.audited, 0);
    assert_eq!(action.0, "ok");
    assert!(rule.1);
}

#[tokio::test]
async fn expired_routing_inventory_alerts_without_disarming() {
    let Some(pool) = pool_or_skip().await else {
        eprintln!("DATABASE_URL not set — skipping inventory drift audit test");
        return;
    };
    // Two missed discovery runs used to age the route context out in silence while
    // every dependent action started being refused at fire time. Expiry is not
    // drift — the router never said anything — so it alerts and changes nothing.
    let f = seed(&pool, "expired", GOOD_PEER).await;
    sqlx::query(
        "UPDATE device_bgp_peers \
            SET route_context_discovered_at = DATE_SUB(UTC_TIMESTAMP(), INTERVAL 100 HOUR) \
          WHERE device_id = ?",
    )
    .bind(f.device_id)
    .execute(&pool)
    .await
    .expect("age the route context");

    audit_device(
        &pool,
        f.device_id,
        InventoryRead::Inconclusive("route_map_discovery_failed"),
    )
    .await
    .expect("audit runs");

    let alerts = count(
        &pool,
        "SELECT COUNT(*) FROM alerts WHERE device_id = ? \
           AND event_type = 'routing_inventory_expired'",
        f.device_id,
    )
    .await;
    let rule = rule_state(&pool, f.rule_id).await;
    cleanup(&pool, &f).await;

    assert_eq!(alerts, 1, "expiry must page");
    assert!(rule.1, "expiry must never disarm");
    assert!(!rule.3);
}
