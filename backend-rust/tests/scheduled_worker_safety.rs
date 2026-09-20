mod common;

use axum_extra::extract::cookie::Key;
use chrono::{Duration as ChronoDuration, Utc};
use rerouter_controller::{
    api::manual_mitigations,
    auth::sessions::Session,
    config::Config,
    detection::engine::InjectedAutomaticWorkPort,
    reroute::{
        self,
        device_plan::{DeviceStateSnapshot, PreparationReader, PreparedInverse, VerificationMode},
    },
    ssh::{
        BoxFuture, CommandResult, LockedDeviceSetPort, ResolvedApply, SessionResolver, SshExecutor,
        SshOutcome,
    },
};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};

struct Reader {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
    delay: AtomicBool,
    panic_once: AtomicBool,
}
impl PreparationReader for Reader {
    fn read_one<'a>(&'a self, _: u64, command: &'a str) -> BoxFuture<'a, anyhow::Result<String>> {
        Box::pin(async move {
            if self.panic_once.swap(false, Ordering::SeqCst) {
                panic!("injected preparation panic")
            }
            if self.delay.swap(false, Ordering::SeqCst) {
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
struct FakeSsh {
    writes: Arc<AtomicUsize>,
    panic_after_write: Arc<AtomicBool>,
    state: Arc<AtomicBool>,
}
impl SshExecutor for FakeSsh {
    async fn apply(&self, _: u64, _: &[String]) -> anyhow::Result<SshOutcome> {
        anyhow::bail!("bundle must use retained locks")
    }
    async fn verify_read(&self, _: u64, _: &str) -> anyhow::Result<String> {
        Ok(String::new())
    }
    async fn apply_resolved<'a>(
        &'a self,
        _: u64,
        _: &'a str,
        _: SessionResolver<'a>,
    ) -> anyhow::Result<ResolvedApply> {
        anyhow::bail!("bundle must use retained locks")
    }
    fn lock_devices<'a>(
        &'a self,
        ids: &'a [u64],
    ) -> BoxFuture<'a, anyhow::Result<Box<dyn LockedDeviceSetPort>>> {
        let locks = FakeLocks {
            ids: ids.to_vec(),
            writes: self.writes.clone(),
            panic_after_write: self.panic_after_write.clone(),
            state: self.state.clone(),
        };
        Box::pin(async move { Ok(Box::new(locks) as Box<dyn LockedDeviceSetPort>) })
    }
}
struct FakeLocks {
    ids: Vec<u64>,
    writes: Arc<AtomicUsize>,
    panic_after_write: Arc<AtomicBool>,
    state: Arc<AtomicBool>,
}
impl LockedDeviceSetPort for FakeLocks {
    fn device_ids(&self) -> Vec<u64> {
        self.ids.clone()
    }
    fn transport_identity(
        &self,
        _: u64,
    ) -> anyhow::Result<reroute::device_plan::DeviceTransportIdentity> {
        Ok(reroute::device_plan::DeviceTransportIdentity {
            host: "192.0.2.244".into(),
            port: 22,
            pinned_host_fingerprint: "SHA256:timer-fixture".into(),
        })
    }
    fn read<'a>(
        &'a mut self,
        _: u64,
        command: &'a str,
    ) -> BoxFuture<'a, anyhow::Result<CommandResult>> {
        Box::pin(async move {
            let present = self.state.load(Ordering::SeqCst);
            let output = if command.contains("running-config") {
                if present {
                    "ip route 203.0.113.9 255.255.255.255 Null0".into()
                } else {
                    String::new()
                }
            } else if present {
                "Routing entry for 203.0.113.9/32\n * directly connected, via Null0".into()
            } else {
                "% Network not in table".into()
            };
            Ok(CommandResult {
                command: command.into(),
                output,
            })
        })
    }
    fn execute<'a>(
        &'a mut self,
        _: u64,
        _: &'a [String],
    ) -> BoxFuture<'a, anyhow::Result<SshOutcome>> {
        Box::pin(async move {
            self.writes.fetch_add(1, Ordering::SeqCst);
            self.state.store(false, Ordering::SeqCst);
            if self.panic_after_write.load(Ordering::SeqCst) {
                panic!("injected panic after router write")
            };
            Ok(SshOutcome {
                results: vec![],
                fingerprint: "SHA256:timer-fixture".into(),
                pinned_now: false,
            })
        })
    }
    fn unlock_all(self: Box<Self>) -> BoxFuture<'static, anyhow::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

async fn source_fixture(pool: &sqlx::MySqlPool) -> (u64, u64) {
    sqlx::query("UPDATE system_settings SET `value`='false' WHERE `key`='global_maintenance_lock'")
        .execute(pool)
        .await
        .unwrap();
    let device=sqlx::query("INSERT INTO devices(name,hostname,ssh_port,ssh_host_fingerprint,enabled,ssh_status,last_ssh_ok_at,ssh_reachable_since) VALUES(?,'192.0.2.244',22,'SHA256:timer-fixture',1,'reachable',UTC_TIMESTAMP(),DATE_SUB(UTC_TIMESTAMP(),INTERVAL 10 MINUTE))").bind(format!("timer-worker-{}",uuid::Uuid::new_v4())).execute(pool).await.unwrap().last_insert_id();
    rerouter_controller::reroute::reachability::stamp_ssh_ok(pool, device)
        .await
        .unwrap();
    let source=sqlx::query("INSERT INTO reroute_bundles(trigger_type,state,total_actions,completed_actions,remaining_mutations,lifecycle_state,finished_at,recovery_deadline,source_json) VALUES('manual','succeeded',1,1,1,'recovery_scheduled',UTC_TIMESTAMP(),DATE_SUB(UTC_TIMESTAMP(),INTERVAL 1 SECOND),JSON_OBJECT('revert_after_seconds',60))").execute(pool).await.unwrap().last_insert_id();
    let template_id: u64 =
        sqlx::query_scalar("SELECT id FROM reroute_templates WHERE name='null_route_prefix'")
            .fetch_one(pool)
            .await
            .unwrap();
    let template = reroute::templates::load(pool, template_id).await.unwrap();
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
        verify: before,
    };
    sqlx::query("INSERT INTO reroutes(device_id,bundle_id,bundle_position,trigger_type,state,mutation_effect,template_snapshot_json,parameters_json,after_state_json,rollback_snapshot_json,started_at,finished_at) VALUES(?,?,0,'manual','succeeded','changed',?,?,?, ?,UTC_TIMESTAMP(),UTC_TIMESTAMP())")
        .bind(device).bind(source).bind(sqlx::types::Json(template)).bind(sqlx::types::Json(serde_json::json!({"prefix":"203.0.113.9/32"}))).bind(sqlx::types::Json(after)).bind(sqlx::types::Json(inverse)).execute(pool).await.unwrap();
    (source, device)
}

fn injected_config(reader: Arc<Reader>, ssh: Arc<FakeSsh>) -> Config {
    let mut cfg = Config::default();
    cfg.automatic_work_port = Some(Arc::new(InjectedAutomaticWorkPort::new(reader, ssh)));
    cfg
}

async fn wait_for<T>(
    mut read: impl FnMut() -> BoxFuture<'static, anyhow::Result<T>>,
    predicate: impl Fn(&T) -> bool,
) -> T {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let value = read().await.unwrap();
            if predicate(&value) {
                break value;
            }
            tokio::task::yield_now().await
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn direct_manual_recovery_is_durable_and_idempotent_before_router_reads() {
    let db = common::test_database().await;
    let pool = db.pool();
    let (source, _) = source_fixture(pool).await;
    let user = sqlx::query(
        "INSERT INTO users(name,email,password) VALUES('direct recovery fixture',?,'unused')",
    )
    .bind(format!(
        "direct-recovery-{}@example.test",
        uuid::Uuid::new_v4()
    ))
    .execute(pool)
    .await
    .unwrap()
    .last_insert_id();
    let actor = Session {
        id: 1,
        user_id: user,
        totp_verified: true,
        expires_at: Utc::now() + ChronoDuration::hours(1),
        ip_address: "127.0.0.1".into(),
        user_agent: "direct-recovery-test".into(),
    };

    let cfg = Config::default();
    let first = rerouter_controller::db::advisory::foreground_scope(
        cfg.advisory_runtime(pool).await.unwrap(),
        manual_mitigations::admit_direct_recovery(
            pool,
            &actor,
            source,
            "operator requested immediate revert",
            "request-one",
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let durable: (String, String, Option<String>, i64, String) = sqlx::query_as(
        "SELECT child.state,source.lifecycle_state,source.recovery_claim_token,COUNT(ras.source_bundle_id),CAST(JSON_UNQUOTE(JSON_EXTRACT(child.source_json,'$.preparation_phase')) AS CHAR) \
         FROM reroute_bundles child JOIN recovery_attempt_sources ras ON ras.recovery_bundle_id=child.id \
         JOIN reroute_bundles source ON source.id=ras.source_bundle_id WHERE child.id=? GROUP BY child.id,source.id",
    )
    .bind(first.bundle_id)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(durable.0, "planned");
    assert_eq!(durable.1, "recovery_claimed");
    assert!(durable.2.is_some());
    assert_eq!(durable.3, 1);
    assert_eq!(durable.4, "published");

    let second = rerouter_controller::db::advisory::foreground_scope(
        cfg.advisory_runtime(pool).await.unwrap(),
        manual_mitigations::admit_direct_recovery(
            pool,
            &actor,
            source,
            "a duplicate click must find the existing workflow",
            "request-two",
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(second.bundle_id, first.bundle_id);
    assert!(second.already_admitted);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM recovery_attempt_sources WHERE source_bundle_id=? AND settlement='active'")
            .bind(source)
            .fetch_one(pool)
            .await
            .unwrap(),
        1,
    );
}

#[tokio::test]
async fn direct_manual_recovery_continues_in_server_task_after_admission() {
    let db = common::test_database().await;
    let pool = db.pool();
    let (source, _) = source_fixture(pool).await;
    let user = sqlx::query(
        "INSERT INTO users(name,email,password) VALUES('direct worker fixture',?,'unused')",
    )
    .bind(format!(
        "direct-worker-{}@example.test",
        uuid::Uuid::new_v4()
    ))
    .execute(pool)
    .await
    .unwrap()
    .last_insert_id();
    let actor = Session {
        id: 1,
        user_id: user,
        totp_verified: true,
        expires_at: Utc::now() + ChronoDuration::hours(1),
        ip_address: "127.0.0.1".into(),
        user_agent: "direct-worker-test".into(),
    };
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let reader = Arc::new(Reader {
        entered: entered.clone(),
        release: release.clone(),
        delay: AtomicBool::new(true),
        panic_once: AtomicBool::new(false),
    });
    let writes = Arc::new(AtomicUsize::new(0));
    let ssh = Arc::new(FakeSsh {
        writes: writes.clone(),
        panic_after_write: Arc::new(AtomicBool::new(false)),
        state: Arc::new(AtomicBool::new(true)),
    });
    let cfg = injected_config(reader, ssh);
    let state = rerouter_controller::api::AppState {
        pool: pool.clone(),
        config: cfg.clone(),
        cookie_key: Key::from(&[87; 64]),
    };
    let admission = rerouter_controller::db::advisory::foreground_scope(
        cfg.advisory_runtime(pool).await.unwrap(),
        manual_mitigations::admit_direct_recovery(
            pool,
            &actor,
            source,
            "server-owned direct recovery",
            "server-owned-request",
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let entered_wait = entered.notified();
    manual_mitigations::spawn_direct_recovery(&state, &actor, admission);
    tokio::time::timeout(std::time::Duration::from_secs(2), entered_wait)
        .await
        .unwrap();
    let visible: (String, String, String, i64) = sqlx::query_as(
        "SELECT child.state,source.lifecycle_state,CAST(JSON_UNQUOTE(JSON_EXTRACT(child.source_json,'$.preparation_phase')) AS CHAR), \
         (SELECT COUNT(*) FROM reroutes WHERE bundle_id=child.id) FROM reroute_bundles child \
         JOIN recovery_attempt_sources ras ON ras.recovery_bundle_id=child.id \
         JOIN reroute_bundles source ON source.id=ras.source_bundle_id WHERE child.id=?",
    )
    .bind(admission.bundle_id)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(
        visible,
        (
            "planned".into(),
            "recovery_claimed".into(),
            "preparing".into(),
            0
        )
    );
    assert_eq!(writes.load(Ordering::SeqCst), 0);

    release.notify_waiters();
    let pool2 = pool.clone();
    let child_id = admission.bundle_id;
    let settled = wait_for(
        move || {
            let pool = pool2.clone();
            Box::pin(async move {
                Ok(sqlx::query_as::<_, (String, String, u32)>(
                    "SELECT child.state,source.lifecycle_state,source.remaining_mutations \
                     FROM reroute_bundles child JOIN recovery_attempt_sources ras ON ras.recovery_bundle_id=child.id \
                     JOIN reroute_bundles source ON source.id=ras.source_bundle_id WHERE child.id=?",
                )
                .bind(child_id)
                .fetch_one(&pool)
                .await?)
            })
        },
        |value| value.0 == "succeeded",
    )
    .await;
    assert_eq!(settled, ("succeeded".into(), "inactive".into(), 0));
    assert_eq!(writes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn startup_repairs_a_published_direct_recovery_as_proven_no_write() {
    let db = common::test_database().await;
    let pool = db.pool();
    let (source, _) = source_fixture(pool).await;
    let user = sqlx::query(
        "INSERT INTO users(name,email,password) VALUES('direct crash fixture',?,'unused')",
    )
    .bind(format!(
        "direct-crash-{}@example.test",
        uuid::Uuid::new_v4()
    ))
    .execute(pool)
    .await
    .unwrap()
    .last_insert_id();
    let actor = Session {
        id: 1,
        user_id: user,
        totp_verified: true,
        expires_at: Utc::now() + ChronoDuration::hours(1),
        ip_address: "127.0.0.1".into(),
        user_agent: "direct-crash-test".into(),
    };
    let cfg = Config::default();
    let admission = rerouter_controller::db::advisory::foreground_scope(
        cfg.advisory_runtime(pool).await.unwrap(),
        manual_mitigations::admit_direct_recovery(
            pool,
            &actor,
            source,
            "crash before preparation",
            "crash-before-preparation",
        ),
    )
    .await
    .unwrap()
    .unwrap();

    reroute::bundle::recover_on_startup(pool).await.unwrap();
    let repaired: (String, String, Option<String>, String) = sqlx::query_as(
        "SELECT child.state,source.lifecycle_state,source.recovery_claim_token,ras.settlement \
         FROM reroute_bundles child JOIN recovery_attempt_sources ras ON ras.recovery_bundle_id=child.id \
         JOIN reroute_bundles source ON source.id=ras.source_bundle_id WHERE child.id=?",
    )
    .bind(admission.bundle_id)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_ne!(repaired.0, "planned");
    assert_eq!(repaired.1, "active");
    assert!(repaired.2.is_none());
    assert_eq!(repaired.3, "known_no_write");
}

#[tokio::test]
async fn direct_recovery_inherits_configuration_only_scope_before_rate_admission() {
    let db = common::test_database().await;
    let pool = db.pool();
    let (source, _) = source_fixture(pool).await;
    sqlx::query("UPDATE reroute_bundles SET source_json=JSON_SET(source_json,'$.verification_mode','configuration_only','$.routing_verified',false) WHERE id=?")
        .bind(source).execute(pool).await.unwrap();
    sqlx::query("UPDATE reroutes SET rollback_snapshot_json=JSON_SET(rollback_snapshot_json,'$.verification_mode','configuration_only') WHERE bundle_id=?")
        .bind(source).execute(pool).await.unwrap();
    let user = sqlx::query(
        "INSERT INTO users(name,email,password) VALUES('direct scope fixture',?,'unused')",
    )
    .bind(format!(
        "direct-scope-{}@example.test",
        uuid::Uuid::new_v4()
    ))
    .execute(pool)
    .await
    .unwrap()
    .last_insert_id();
    let actor = Session {
        id: 1,
        user_id: user,
        totp_verified: true,
        expires_at: Utc::now() + ChronoDuration::hours(1),
        ip_address: "127.0.0.1".into(),
        user_agent: "direct-scope-test".into(),
    };
    let mut cfg = Config::default();
    cfg.safety.global_action_rate_limit_count = 0;
    let admission = rerouter_controller::db::advisory::foreground_scope(
        cfg.advisory_runtime(pool).await.unwrap(),
        manual_mitigations::admit_direct_recovery(
            pool,
            &actor,
            source,
            "configuration-only direct recovery",
            "configuration-only-request",
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let child_mode: String = sqlx::query_scalar(
        "SELECT CAST(JSON_UNQUOTE(JSON_EXTRACT(source_json,'$.verification_mode')) AS CHAR) FROM reroute_bundles WHERE id=?",
    )
    .bind(admission.bundle_id)
    .fetch_one(pool)
    .await
    .unwrap();
    assert_eq!(child_mode, "configuration_only");
    let originals: Vec<u64> = sqlx::query_scalar(
        "SELECT original_reroute_id FROM reroute_bundle_actions WHERE bundle_id=? ORDER BY position",
    )
    .bind(admission.bundle_id)
    .fetch_all(pool)
    .await
    .unwrap();
    assert!(
        originals.is_empty(),
        "admission must still precede preparation"
    );
    let originals = reroute::recovery::owned_original_ids(pool, source)
        .await
        .unwrap();
    let actions = reroute::preparation::prepare_rollbacks(pool, &originals, "scope proof", false)
        .await
        .unwrap();
    assert!(actions
        .iter()
        .all(|action| action.prepared.as_ref().unwrap().verification_mode
            == reroute::device_plan::VerificationMode::ConfigurationOnly));
    reroute::bundle::persist_actions(pool, admission.bundle_id, &actions)
        .await
        .unwrap();
    rerouter_controller::db::advisory::foreground_scope(
        cfg.advisory_runtime(pool).await.unwrap(),
        async {
            reroute::guard::admit_bundle(pool, &cfg, admission.bundle_id, actions.len() as u32)
                .await
                .map_err(|error| anyhow::anyhow!(error.to_string()))
        },
    )
    .await
    .unwrap()
    .unwrap();
    reroute::recovery::finalize_recovery_child(
        pool,
        admission.bundle_id,
        "failed",
        Some("scope regression cleanup"),
        &format!("recovery:bundle:{}", admission.bundle_id),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn delayed_timer_publishes_before_read_and_disarm_settles_without_write() {
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
    let (source, _) = source_fixture(pool).await;
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let reader = Arc::new(Reader {
        entered: entered.clone(),
        release: release.clone(),
        delay: AtomicBool::new(true),
        panic_once: AtomicBool::new(false),
    });
    let writes = Arc::new(AtomicUsize::new(0));
    let ssh = Arc::new(FakeSsh {
        writes: writes.clone(),
        panic_after_write: Arc::new(AtomicBool::new(false)),
        state: Arc::new(AtomicBool::new(true)),
    });
    let cfg = injected_config(reader, ssh);
    let entered_wait = entered.notified();
    assert!(reroute::recovery::process_one_due(pool, &cfg)
        .await
        .unwrap());
    tokio::time::timeout(std::time::Duration::from_secs(2), entered_wait)
        .await
        .unwrap();
    let published:i64=sqlx::query_scalar("SELECT COUNT(*) FROM recovery_attempt_sources ras JOIN reroute_bundles child ON child.id=ras.recovery_bundle_id WHERE ras.source_bundle_id=? AND child.state='planned' AND JSON_UNQUOTE(JSON_EXTRACT(child.source_json,'$.preparation_phase'))='preparing'").bind(source).fetch_one(pool).await.unwrap();
    assert_eq!(published, 1);
    sqlx::query(
        "UPDATE system_settings SET `value`='false' WHERE `key`='automatic_actions_enabled'",
    )
    .execute(pool)
    .await
    .unwrap();
    release.notify_waiters();
    let pool2 = pool.clone();
    let settled=wait_for(move||{let pool=pool2.clone();Box::pin(async move{Ok(sqlx::query_as::<_,(String,Option<String>)>("SELECT ras.settlement,source.recovery_claim_token FROM recovery_attempt_sources ras JOIN reroute_bundles source ON source.id=ras.source_bundle_id WHERE ras.source_bundle_id=? ORDER BY ras.recovery_bundle_id DESC LIMIT 1").bind(source).fetch_one(&pool).await?)})},|v|v.0!="active").await;
    assert_eq!(settled.0, "known_no_write");
    assert!(settled.1.is_none());
    assert_eq!(writes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn failed_atomic_timer_admission_leaves_neither_claim_nor_child() {
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
    let (source, _) = source_fixture(pool).await;
    let cfg = Config::default();
    let runtime = cfg.advisory_runtime(pool).await.unwrap();
    let result = rerouter_controller::db::advisory::background_scope(
        runtime,
        reroute::recovery::admit_one_due_with_failure(pool, &cfg, true),
    )
    .await
    .unwrap();
    assert!(result.is_err());
    let row:(Option<String>,i64)=sqlx::query_as("SELECT recovery_claim_token,(SELECT COUNT(*) FROM reroute_bundles child WHERE child.parent_bundle_id=source.id) FROM reroute_bundles source WHERE source.id=?").bind(source).fetch_one(pool).await.unwrap();
    assert!(row.0.is_none());
    assert_eq!(row.1, 0);
    sqlx::query("UPDATE reroute_bundles SET automatic_recovery_cancelled_at=UTC_TIMESTAMP(),recovery_deadline=NULL,lifecycle_state='active' WHERE id=?")
        .bind(source).execute(pool).await.unwrap();
}

#[tokio::test]
async fn panic_after_write_keeps_quarantine_and_startup_repair_is_idempotent() {
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
    let (source, _) = source_fixture(pool).await;
    let reader = Arc::new(Reader {
        entered: Arc::new(tokio::sync::Notify::new()),
        release: Arc::new(tokio::sync::Notify::new()),
        delay: AtomicBool::new(false),
        panic_once: AtomicBool::new(false),
    });
    let writes = Arc::new(AtomicUsize::new(0));
    let ssh = Arc::new(FakeSsh {
        writes: writes.clone(),
        panic_after_write: Arc::new(AtomicBool::new(true)),
        state: Arc::new(AtomicBool::new(true)),
    });
    let cfg = injected_config(reader, ssh);
    assert!(reroute::recovery::process_one_due(pool, &cfg)
        .await
        .unwrap());
    let pool2 = pool.clone();
    let lifecycle = wait_for(
        move || {
            let pool = pool2.clone();
            Box::pin(async move {
                Ok(sqlx::query_scalar::<_, String>(
                    "SELECT lifecycle_state FROM reroute_bundles WHERE id=?",
                )
                .bind(source)
                .fetch_one(&pool)
                .await?)
            })
        },
        |v| v == "recovery_blocked",
    )
    .await;
    assert_eq!(lifecycle, "recovery_blocked");
    assert!(writes.load(Ordering::SeqCst) > 0);
    reroute::state_machine::recover_on_startup(pool)
        .await
        .unwrap();
    reroute::bundle::recover_on_startup(pool).await.unwrap();
    reroute::state_machine::recover_on_startup(pool)
        .await
        .unwrap();
    reroute::bundle::recover_on_startup(pool).await.unwrap();
    let claim: Option<String> =
        sqlx::query_scalar("SELECT recovery_claim_token FROM reroute_bundles WHERE id=?")
            .bind(source)
            .fetch_one(pool)
            .await
            .unwrap();
    assert!(
        claim.is_some(),
        "ambiguous post-write recovery must remain quarantined"
    );
}

#[tokio::test]
async fn panic_before_prepare_is_known_no_write_and_queue_continues() {
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
    let (first, _) = source_fixture(pool).await;
    let reader = Arc::new(Reader {
        entered: Arc::new(tokio::sync::Notify::new()),
        release: Arc::new(tokio::sync::Notify::new()),
        delay: AtomicBool::new(false),
        panic_once: AtomicBool::new(true),
    });
    let writes = Arc::new(AtomicUsize::new(0));
    let ssh = Arc::new(FakeSsh {
        writes,
        panic_after_write: Arc::new(AtomicBool::new(false)),
        state: Arc::new(AtomicBool::new(true)),
    });
    let cfg = injected_config(reader, ssh);
    assert!(reroute::recovery::process_one_due(pool, &cfg)
        .await
        .unwrap());
    let pool2 = pool.clone();
    let settlement=wait_for(move||{let pool=pool2.clone();Box::pin(async move{Ok(sqlx::query_scalar::<_,String>("SELECT settlement FROM recovery_attempt_sources WHERE source_bundle_id=? ORDER BY recovery_bundle_id DESC LIMIT 1").bind(first).fetch_one(&pool).await?)})},|value|value!="active").await;
    assert_eq!(settlement, "known_no_write");
    let (second, _) = source_fixture(pool).await;
    assert!(reroute::recovery::process_one_due(pool, &cfg)
        .await
        .unwrap());
    let pool3 = pool.clone();
    let state = wait_for(
        move || {
            let pool = pool3.clone();
            Box::pin(async move {
                Ok(sqlx::query_scalar::<_, String>(
                    "SELECT lifecycle_state FROM reroute_bundles WHERE id=?",
                )
                .bind(second)
                .fetch_one(&pool)
                .await?)
            })
        },
        |value| value == "inactive" || value == "recovery_blocked",
    )
    .await;
    assert_eq!(
        state, "inactive",
        "queue consumer must survive a prior preparation panic"
    );
}
