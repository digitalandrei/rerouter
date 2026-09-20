//! Persistence must advance on observations, not repeated scheduler evaluations.
mod common;

use chrono::{Duration, Utc};
use rerouter_controller::{
    config::Config,
    detection::engine,
    ssh::{BoxFuture, CommandResult, LockedDeviceSetPort, SshExecutor, SshOutcome},
};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};

struct DelayedReader {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    first: AtomicBool,
}
impl rerouter_controller::reroute::device_plan::PreparationReader for DelayedReader {
    fn read_one<'a>(&'a self, _: u64, command: &'a str) -> BoxFuture<'a, anyhow::Result<String>> {
        Box::pin(async move {
            if !self.first.swap(true, Ordering::SeqCst) {
                self.entered.notify_one();
                self.release.notified().await;
            }
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
    ) -> BoxFuture<'a, anyhow::Result<Vec<String>>> {
        Box::pin(async move { Ok(vec![String::new(); commands.len()]) })
    }
}
#[derive(Clone)]
struct NoWriteSsh {
    writes: Arc<AtomicUsize>,
}
impl SshExecutor for NoWriteSsh {
    async fn apply(&self, _: u64, _: &[String]) -> anyhow::Result<SshOutcome> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        anyhow::bail!("unexpected write")
    }
    async fn verify_read(&self, _: u64, _: &str) -> anyhow::Result<String> {
        Ok(String::new())
    }
    async fn apply_resolved<'a>(
        &'a self,
        _: u64,
        _: &'a str,
        _: rerouter_controller::ssh::SessionResolver<'a>,
    ) -> anyhow::Result<rerouter_controller::ssh::ResolvedApply> {
        anyhow::bail!("unexpected write")
    }
    fn lock_devices<'a>(
        &'a self,
        ids: &'a [u64],
    ) -> BoxFuture<'a, anyhow::Result<Box<dyn LockedDeviceSetPort>>> {
        let ids = ids.to_vec();
        Box::pin(async move { Ok(Box::new(NoWriteLocks { ids }) as Box<dyn LockedDeviceSetPort>) })
    }
}
struct NoWriteLocks {
    ids: Vec<u64>,
}
impl LockedDeviceSetPort for NoWriteLocks {
    fn device_ids(&self) -> Vec<u64> {
        self.ids.clone()
    }
    fn transport_identity(
        &self,
        _: u64,
    ) -> anyhow::Result<rerouter_controller::reroute::device_plan::DeviceTransportIdentity> {
        Ok(
            rerouter_controller::reroute::device_plan::DeviceTransportIdentity {
                host: "192.0.2.250".into(),
                port: 22,
                pinned_host_fingerprint: "SHA256:test".into(),
            },
        )
    }
    fn read<'a>(
        &'a mut self,
        _: u64,
        command: &'a str,
    ) -> BoxFuture<'a, anyhow::Result<CommandResult>> {
        Box::pin(async move {
            Ok(CommandResult {
                command: command.into(),
                output: String::new(),
            })
        })
    }
    fn execute<'a>(
        &'a mut self,
        _: u64,
        _: &'a [String],
    ) -> BoxFuture<'a, anyhow::Result<SshOutcome>> {
        Box::pin(async { anyhow::bail!("unexpected write") })
    }
    fn unlock_all(self: Box<Self>) -> BoxFuture<'static, anyhow::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

#[tokio::test]
async fn repeated_samples_and_stale_gaps_cannot_fire_or_clear_an_incident() {
    let pool = common::test_database().await;
    sqlx::query("UPDATE system_settings SET `value`='observe' WHERE `key`='operating_mode'")
        .execute(&*pool)
        .await
        .unwrap();
    let device =
        sqlx::query("INSERT INTO devices(name,hostname,enabled) VALUES(?,'192.0.2.250',0)")
            .bind(format!("evidence-{}", uuid::Uuid::new_v4()))
            .execute(&*pool)
            .await
            .unwrap()
            .last_insert_id();
    let interface = sqlx::query("INSERT INTO device_interfaces(device_id,if_index) VALUES(?,1)")
        .bind(device)
        .execute(&*pool)
        .await
        .unwrap()
        .last_insert_id();
    let rule=sqlx::query("INSERT INTO rules(name,device_id,interface_id,metric,operator,threshold_value,duration_seconds,consecutive_samples, \
        recovery_mode,recovery_threshold_value,recovery_consecutive_samples,automatic_reroute_enabled) \
        VALUES('Observation evidence',?,?,'rx_bps','>',100,0,3,'threshold',50,2,0)")
        .bind(device).bind(interface).execute(&*pool).await.unwrap().last_insert_id();
    let base = Utc::now() - Duration::seconds(20);
    sqlx::query("INSERT INTO interface_metrics_current(interface_id,device_id,sampled_at,valid_sample,rx_bps) VALUES(?,?,?,1,200)")
        .bind(interface).bind(device).bind(base).execute(&*pool).await.unwrap();
    let cfg = Config::default();
    for _ in 0..3 {
        assert_eq!(
            engine::evaluate_device(&pool, &cfg, device).await.unwrap(),
            0
        );
    }
    let state: (String, u32) = sqlx::query_as(
        "SELECT current_state,consecutive_match_count FROM rule_states WHERE rule_id=?",
    )
    .bind(rule)
    .fetch_one(&*pool)
    .await
    .unwrap();
    assert_eq!(state, ("matching".into(), 1));
    for tick in 1..=2 {
        sqlx::query("UPDATE interface_metrics_current SET sampled_at=? WHERE interface_id=?")
            .bind(base + Duration::seconds(tick))
            .bind(interface)
            .execute(&*pool)
            .await
            .unwrap();
        assert_eq!(
            engine::evaluate_device(&pool, &cfg, device).await.unwrap(),
            usize::from(tick == 2)
        );
    }
    // Invalid evidence resets unproved progress but must preserve a firing
    // incident; a subsequent matching sample cannot demote it to matching.
    sqlx::query("UPDATE interface_metrics_current SET valid_sample=0 WHERE interface_id=?")
        .bind(interface)
        .execute(&*pool)
        .await
        .unwrap();
    engine::evaluate_device(&pool, &cfg, device).await.unwrap();
    sqlx::query(
        "UPDATE interface_metrics_current SET valid_sample=1,sampled_at=? WHERE interface_id=?",
    )
    .bind(base + Duration::seconds(3))
    .bind(interface)
    .execute(&*pool)
    .await
    .unwrap();
    engine::evaluate_device(&pool, &cfg, device).await.unwrap();
    let current: String =
        sqlx::query_scalar("SELECT current_state FROM rule_states WHERE rule_id=?")
            .bind(rule)
            .fetch_one(&*pool)
            .await
            .unwrap();
    assert_eq!(current, "firing");
    sqlx::query("UPDATE interface_metrics_current SET sampled_at=?,rx_bps=0 WHERE interface_id=?")
        .bind(base + Duration::seconds(4))
        .bind(interface)
        .execute(&*pool)
        .await
        .unwrap();
    for _ in 0..3 {
        engine::evaluate_device(&pool, &cfg, device).await.unwrap();
    }
    let recovery: (String, u32) = sqlx::query_as(
        "SELECT current_state,recovery_consecutive FROM rule_states WHERE rule_id=?",
    )
    .bind(rule)
    .fetch_one(&*pool)
    .await
    .unwrap();
    assert_eq!(recovery, ("firing".into(), 1));
    sqlx::query("UPDATE interface_metrics_current SET sampled_at=? WHERE interface_id=?")
        .bind(base + Duration::seconds(5))
        .bind(interface)
        .execute(&*pool)
        .await
        .unwrap();
    engine::evaluate_device(&pool, &cfg, device).await.unwrap();
    let current: String =
        sqlx::query_scalar("SELECT current_state FROM rule_states WHERE rule_id=?")
            .bind(rule)
            .fetch_one(&*pool)
            .await
            .unwrap();
    assert_eq!(current, "clear");
    // A controller/stale-data gap cannot inherit a previously started window.
    let old = Utc::now() - Duration::hours(1);
    sqlx::query("UPDATE rules SET duration_seconds=60,consecutive_samples=0 WHERE id=?")
        .bind(rule)
        .execute(&*pool)
        .await
        .unwrap();
    sqlx::query("UPDATE rule_states SET current_state='matching',first_matched_at=?,last_observation_at=?,last_observation_json=? WHERE rule_id=?")
        .bind(old).bind(old).bind(sqlx::types::Json(serde_json::json!({interface.to_string():old}))).bind(rule).execute(&*pool).await.unwrap();
    sqlx::query(
        "UPDATE interface_metrics_current SET sampled_at=?,rx_bps=200 WHERE interface_id=?",
    )
    .bind(base + Duration::seconds(6))
    .bind(interface)
    .execute(&*pool)
    .await
    .unwrap();
    assert_eq!(
        engine::evaluate_device(&pool, &cfg, device).await.unwrap(),
        0
    );
    let state: (String, u32) = sqlx::query_as(
        "SELECT current_state,consecutive_match_count FROM rule_states WHERE rule_id=?",
    )
    .bind(rule)
    .fetch_one(&*pool)
    .await
    .unwrap();
    assert_eq!(state, ("matching".into(), 1));
    sqlx::query("DELETE FROM alerts WHERE rule_id=?")
        .bind(rule)
        .execute(&*pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM rules WHERE id=?")
        .bind(rule)
        .execute(&*pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM devices WHERE id=?")
        .bind(device)
        .execute(&*pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn twenty_concurrent_rule_passes_publish_each_firing_edge_once() {
    let pool = common::test_database().await;
    sqlx::query("UPDATE system_settings SET `value`='observe' WHERE `key`='operating_mode'")
        .execute(&*pool)
        .await
        .unwrap();
    let device =
        sqlx::query("INSERT INTO devices(name,hostname,enabled) VALUES(?,'192.0.2.249',0)")
            .bind(format!("concurrent-evidence-{}", uuid::Uuid::new_v4()))
            .execute(&*pool)
            .await
            .unwrap()
            .last_insert_id();
    let interface = sqlx::query("INSERT INTO device_interfaces(device_id,if_index) VALUES(?,1)")
        .bind(device)
        .execute(&*pool)
        .await
        .unwrap()
        .last_insert_id();
    sqlx::query("INSERT INTO interface_metrics_current(interface_id,device_id,sampled_at,valid_sample,rx_bps) VALUES(?,?,UTC_TIMESTAMP(),1,200)")
        .bind(interface).bind(device).execute(&*pool).await.unwrap();
    let mut rules = Vec::new();
    for index in 0..20 {
        rules.push(sqlx::query("INSERT INTO rules(name,device_id,interface_id,metric,operator,threshold_value,duration_seconds,consecutive_samples,recovery_mode,automatic_reroute_enabled) VALUES(?,?,?,'rx_bps','>',100,0,1,'manual',0)")
            .bind(format!("concurrent rule {index}")).bind(device).bind(interface).execute(&*pool).await.unwrap().last_insert_id());
    }
    let cfg = Config::default();
    let mut tasks = Vec::new();
    let load_started = std::time::Instant::now();
    for _ in 0..20 {
        let pool = pool.pool().clone();
        let cfg = cfg.clone();
        tasks.push(tokio::spawn(async move {
            let started = std::time::Instant::now();
            let fired = engine::evaluate_device(&pool, &cfg, device).await.unwrap();
            (fired, started.elapsed().as_micros() as u64)
        }));
    }
    let mut pass_latencies = Vec::new();
    for task in tasks {
        let (_, elapsed_us) = task.await.unwrap();
        pass_latencies.push(elapsed_us);
    }
    let events:i64=sqlx::query_scalar("SELECT COUNT(*) FROM rule_events WHERE rule_id IN (SELECT id FROM rules WHERE device_id=?) AND event='fired'")
        .bind(device).fetch_one(&*pool).await.unwrap();
    let alerts:i64=sqlx::query_scalar("SELECT COUNT(*) FROM alerts WHERE rule_id IN (SELECT id FROM rules WHERE device_id=?) AND event_type='rule_fired'")
        .bind(device).fetch_one(&*pool).await.unwrap();
    assert_eq!(events, 20);
    assert_eq!(alerts, 20);
    pass_latencies.sort_unstable();
    let process_high_water_kib =
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|text| {
                text.lines()
                    .find(|line| line.starts_with("VmHWM:"))
                    .and_then(|line| line.split_whitespace().nth(1))
                    .and_then(|value| value.parse::<u64>().ok())
            });
    println!(
        "HARDENING_DETECTION_LOAD {}",
        serde_json::json!({
            "rules":20,"concurrent_passes":20,"committed_firing_events":events,
            "wall_ms":load_started.elapsed().as_millis(),
            "pass_p95_ms":pass_latencies[18] as f64 / 1000.0,
            "process_high_water_kib":process_high_water_kib,
            "scope":"fixture decision persistence; no router capacity claim"
        })
    );
}

async fn delayed_condition_recovery_is_blocked(relapse: bool) {
    use rerouter_controller::reroute::{
        device_plan::{DeviceStateSnapshot, PreparedInverse, VerificationMode},
        templates,
    };
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
    let device=sqlx::query("INSERT INTO devices(name,hostname,ssh_port,ssh_host_fingerprint,enabled) VALUES(?,'192.0.2.250',22,'SHA256:test',0)")
        .bind(format!("delayed-recovery-{}",uuid::Uuid::new_v4())).execute(pool).await.unwrap().last_insert_id();
    let interface = sqlx::query("INSERT INTO device_interfaces(device_id,if_index) VALUES(?,1)")
        .bind(device)
        .execute(pool)
        .await
        .unwrap()
        .last_insert_id();
    let rule=sqlx::query("INSERT INTO rules(name,device_id,interface_id,metric,operator,threshold_value,duration_seconds,consecutive_samples,recovery_mode,recovery_consecutive_samples,automatic_reroute_enabled,automatic_revert_enabled) VALUES(?,?,?,'rx_bps','>',100,0,1,'auto',1,1,1)")
        .bind("delayed recovery").bind(device).bind(interface).execute(pool).await.unwrap().last_insert_id();
    let sampled = Utc::now() - Duration::seconds(2);
    sqlx::query("INSERT INTO interface_metrics_current(interface_id,device_id,sampled_at,valid_sample,rx_bps) VALUES(?,?,?,1,0)").bind(interface).bind(device).bind(sampled).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO rule_states(rule_id,current_state,last_observation_at,last_observation_json,last_metric_value) VALUES(?,'firing',DATE_SUB(?,INTERVAL 1 SECOND),?,200)")
        .bind(rule).bind(sampled).bind(sqlx::types::Json(serde_json::json!({interface.to_string():sampled-Duration::seconds(1)}))).execute(pool).await.unwrap();
    let source=sqlx::query("INSERT INTO reroute_bundles(rule_id,trigger_type,state,total_actions,completed_actions,remaining_mutations,lifecycle_state) VALUES(?,'automatic','succeeded',1,1,1,'active')")
        .bind(rule).execute(pool).await.unwrap().last_insert_id();
    let template_id: u64 =
        sqlx::query_scalar("SELECT id FROM reroute_templates WHERE name='null_route_prefix'")
            .fetch_one(pool)
            .await
            .unwrap();
    let template = templates::load(pool, template_id).await.unwrap();
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
        verification_mode: VerificationMode::Routing,
        expected_current: after.clone(),
        restore: before.clone(),
        commands: vec![
            "configure terminal".into(),
            "no ip route 203.0.113.9 255.255.255.255 Null0".into(),
            "end".into(),
        ],
        verify: before.clone(),
    };
    sqlx::query("INSERT INTO reroutes(device_id,bundle_id,bundle_position,rule_id,trigger_type,state,mutation_effect,template_snapshot_json,parameters_json,prior_state_json,after_state_json,rollback_snapshot_json,started_at,finished_at) VALUES(?, ?,0,?,'automatic','succeeded','changed',?,?,?,?,?,UTC_TIMESTAMP(),UTC_TIMESTAMP())")
        .bind(device).bind(source).bind(rule).bind(sqlx::types::Json(&template)).bind(sqlx::types::Json(serde_json::json!({"prefix":"203.0.113.9/32"}))).bind(sqlx::types::Json(&before)).bind(sqlx::types::Json(&after)).bind(sqlx::types::Json(&inverse)).execute(pool).await.unwrap();
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let reader = Arc::new(DelayedReader {
        entered: entered.clone(),
        release: release.clone(),
        first: AtomicBool::new(false),
    });
    let writes = Arc::new(AtomicUsize::new(0));
    let ssh = Arc::new(NoWriteSsh {
        writes: writes.clone(),
    });
    let mut cfg = Config::default();
    cfg.automatic_work_port = Some(Arc::new(engine::InjectedAutomaticWorkPort::new(
        reader, ssh,
    )));
    let entered_wait = entered.notified();
    engine::evaluate_device(pool, &cfg, device).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), entered_wait)
        .await
        .unwrap();
    let runtime = cfg.advisory_runtime(pool).await.unwrap();
    tokio::time::timeout(
        std::time::Duration::from_millis(250),
        rerouter_controller::db::advisory::foreground_scope(runtime, async {
            let fence = rerouter_controller::reroute::guard::policy_fence(pool).await?;
            fence.release().await
        }),
    )
    .await
    .expect("read-only recovery preparation must not hold the policy fence")
    .expect("foreground advisory scope")
    .expect("acquire and release policy fence");
    let published:(String,i64,i64)=sqlx::query_as("SELECT rs.current_state,(SELECT COUNT(*) FROM rule_events WHERE rule_id=? AND event='recovered_awaiting_revert'),(SELECT COUNT(*) FROM recovery_attempt_sources ras JOIN reroute_bundles b ON b.id=ras.recovery_bundle_id WHERE ras.source_bundle_id=? AND b.state='planned') FROM rule_states rs WHERE rs.rule_id=?")
        .bind(rule).bind(source).bind(rule).fetch_one(pool).await.unwrap();
    assert_eq!(published, ("recovered_awaiting_revert".into(), 1, 1));
    engine::evaluate_device(pool, &cfg, device).await.unwrap();
    let children: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM recovery_attempt_sources WHERE source_bundle_id=?",
    )
    .bind(source)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        children, 1,
        "same observation must not create a second recovery child"
    );
    if relapse {
        let relapse_at = Utc::now();
        sqlx::query(
            "UPDATE interface_metrics_current SET sampled_at=?,valid_sample=1,rx_bps=200 WHERE interface_id=?",
        )
        .bind(relapse_at)
        .bind(interface)
        .execute(pool)
        .await
        .unwrap();
        engine::evaluate_device(pool, &cfg, device).await.unwrap();
        let state: String =
            sqlx::query_scalar("SELECT current_state FROM rule_states WHERE rule_id=?")
                .bind(rule)
                .fetch_one(pool)
                .await
                .unwrap();
        assert_eq!(state, "firing", "relapse must revoke queued recovery");
    } else {
        sqlx::query(
            "UPDATE system_settings SET `value`='false' WHERE `key`='automatic_actions_enabled'",
        )
        .execute(pool)
        .await
        .unwrap();
    }
    release.notify_waiters();
    let settled = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let row: (String, Option<String>, String) = sqlx::query_as(
                "SELECT ras.settlement,source.recovery_claim_token,child.state \
                 FROM recovery_attempt_sources ras \
                 JOIN reroute_bundles source ON source.id=ras.source_bundle_id \
                 JOIN reroute_bundles child ON child.id=ras.recovery_bundle_id \
                 WHERE ras.source_bundle_id=? ORDER BY child.id DESC LIMIT 1",
            )
            .bind(source)
            .fetch_one(pool)
            .await
            .unwrap();
            if row.0 != "active" {
                break row;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(settled.0, "known_no_write");
    assert!(settled.1.is_none(), "source claim must be released");
    assert_eq!(settled.2, "failed");
    assert_eq!(writes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn recovery_publication_precedes_delayed_fake_preparation_and_disarm_blocks_writes() {
    delayed_condition_recovery_is_blocked(false).await;
}

#[tokio::test]
async fn telemetry_relapse_revokes_delayed_condition_recovery_before_write() {
    delayed_condition_recovery_is_blocked(true).await;
}

#[tokio::test]
async fn failed_firing_publication_does_not_consume_observation() {
    let db = common::test_database().await;
    let pool = db.pool();
    let device =
        sqlx::query("INSERT INTO devices(name,hostname,enabled) VALUES(?,'192.0.2.248',0)")
            .bind(format!("publication-fail-{}", uuid::Uuid::new_v4()))
            .execute(pool)
            .await
            .unwrap()
            .last_insert_id();
    let interface = sqlx::query("INSERT INTO device_interfaces(device_id,if_index) VALUES(?,1)")
        .bind(device)
        .execute(pool)
        .await
        .unwrap()
        .last_insert_id();
    let rule=sqlx::query("INSERT INTO rules(name,device_id,interface_id,metric,operator,threshold_value,duration_seconds,consecutive_samples,recovery_mode,automatic_reroute_enabled) VALUES(?,?,?,'rx_bps','>',100,0,1,'manual',0)")
        .bind("publication failure").bind(device).bind(interface).execute(pool).await.unwrap().last_insert_id();
    let sampled = Utc::now();
    sqlx::query("INSERT INTO interface_metrics_current(interface_id,device_id,sampled_at,valid_sample,rx_bps) VALUES(?,?,?,1,200)").bind(interface).bind(device).bind(sampled).execute(pool).await.unwrap();
    let mut cfg = Config::default();
    cfg.fail_automatic_decision_before_commit = true;
    assert_eq!(
        engine::evaluate_device(pool, &cfg, device).await.unwrap(),
        0
    );
    let counts:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT COUNT(*) FROM rule_events WHERE rule_id=?),(SELECT COUNT(*) FROM alerts WHERE rule_id=?),(SELECT COUNT(*) FROM rule_states WHERE rule_id=?)")
        .bind(rule).bind(rule).bind(rule).fetch_one(pool).await.unwrap();
    assert_eq!(counts, (0, 0, 0));
    cfg.fail_automatic_decision_before_commit = false;
    assert_eq!(
        engine::evaluate_device(pool, &cfg, device).await.unwrap(),
        1
    );
}
