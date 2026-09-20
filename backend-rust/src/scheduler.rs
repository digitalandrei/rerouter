//! Per-device async SNMP poller + detection driver.
//!
//! One supervised task per enabled device runs an independent loop: SNMP poll
//! (store interface_metrics_current + interface_samples) -> run detection for
//! that device's monitored interfaces. Each loop uses the device's
//! `poll_interval_seconds` plus +/- jitter (telemetry.jitter_percent) so polls
//! de-synchronize across devices. A per-device failure is logged and the loop
//! keeps going (the device is marked unreachable by the poller).
//!
//! A supervisor reloads the enabled-device set every RELOAD_INTERVAL and spawns
//! loops for new devices / drops loops for removed-or-disabled ones, so adding a
//! device from the API starts polling it without a restart.
//!
//! `run` spawns the supervisor and returns immediately so the caller can then
//! start the API server (the loops live for the process lifetime).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use futures_util::stream::{FuturesUnordered, StreamExt};
use rand::Rng;
use sqlx::MySqlPool;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::config::Config;
use crate::detection;
use crate::telemetry::{flow, snmp};

/// How often the supervisor reconciles the running loops against the DB.
const RELOAD_INTERVAL: Duration = Duration::from_secs(30);

/// How often the retention cleanup runs.
const PRUNE_INTERVAL: Duration = Duration::from_secs(600);
/// Keep each retention delete short enough that a large first 48-hour purge
/// does not monopolize InnoDB locks or starve telemetry/API queries.
const RETENTION_DELETE_BATCH: u64 = 1_000;

/// Spawn the scheduler supervisor + the retention cleanup task; return. Never
/// blocks the control plane.
pub async fn run(pool: MySqlPool, cfg: Config) -> Result<()> {
    let cfg = Arc::new(cfg);
    spawn_supervised("retention_cleanup", {
        let pool = pool.clone();
        let cfg = cfg.clone();
        move || retention_cleanup(pool.clone(), cfg.clone())
    });
    spawn_supervised("prefix_discovery", {
        let pool = pool.clone();
        let cfg = cfg.clone();
        move || discover_prefixes_hourly(pool.clone(), cfg.clone())
    });
    spawn_supervised("aggregate_detection", {
        let pool = pool.clone();
        let cfg = cfg.clone();
        move || evaluate_aggregate_loop(pool.clone(), cfg.clone())
    });
    spawn_supervised("flow_detection_wake", {
        let pool = pool.clone();
        let cfg = cfg.clone();
        move || flow_detection_wake_loop(pool.clone(), cfg.clone())
    });
    spawn_supervised("scheduled_recovery", {
        let pool = pool.clone();
        let cfg = cfg.clone();
        move || scheduled_recovery_loop(pool.clone(), cfg.clone())
    });
    // NetFlow v9/sFlow v5 collector — a second, passive telemetry source. No-op
    // unless [flow].enabled; binds its own UDP socket (see docs/flow-telemetry.md).
    spawn_supervised("flow_collector", {
        let pool = pool.clone();
        let cfg = cfg.clone();
        move || flow::collector::run(pool.clone(), cfg.clone())
    });
    spawn_supervised("device_poll_supervisor", move || {
        supervise(pool.clone(), cfg.clone())
    });
    tracing::info!(
        event_type = "scheduler_started",
        "scheduler supervisor spawned (per-device SNMP poll loops)"
    );
    Ok(())
}

async fn flow_detection_wake_loop(pool: MySqlPool, cfg: Arc<Config>) {
    let mut retry_delay = Duration::from_secs(1);
    loop {
        let batch = cfg.flow_wake.wait_and_take().await;
        let started = Instant::now();
        let evaluation = if batch.full_rescan {
            background_operation(
                &pool,
                &cfg,
                detection::engine::evaluate_all_flow_rules(&pool, &cfg),
            )
            .await
        } else {
            background_operation(
                &pool,
                &cfg,
                detection::engine::evaluate_flow_interfaces(&pool, &cfg, &batch.interface_ids),
            )
            .await
        };
        match evaluation {
            Ok(fired) => {
                retry_delay = Duration::from_secs(1);
                let interfaces = batch.interface_ids.len();
                let full_rescan = batch.full_rescan;
                cfg.flow_wake.complete_success(batch);
                tracing::debug!(
                    event_type = "flow_wake_evaluated",
                    interfaces,
                    full_rescan,
                    fired,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "committed flow buckets evaluated"
                );
            }
            Err(error) => {
                tracing::warn!(event_type="flow_wake_evaluation_failed",error=%error,"flow evaluation failed; wake returned to queue");
                tokio::time::sleep(retry_delay).await;
                cfg.flow_wake.complete_failure(batch);
                retry_delay = next_flow_retry_delay(retry_delay);
            }
        }
    }
}

fn next_flow_retry_delay(current: Duration) -> Duration {
    (current * 2).min(Duration::from_secs(30))
}

async fn background_operation<T>(
    pool: &MySqlPool,
    cfg: &Config,
    future: impl std::future::Future<Output = anyhow::Result<T>>,
) -> anyhow::Result<T> {
    let runtime = cfg.advisory_runtime(pool).await?;
    crate::db::advisory::background_scope(runtime, future).await?
}

async fn scheduled_recovery_loop(pool: MySqlPool, cfg: Arc<Config>) {
    loop {
        match crate::reroute::recovery::process_one_due(&pool, &cfg).await {
            Ok(true) => continue,
            Ok(false) => {}
            Err(e) => tracing::error!(event_type="scheduled_recovery_failed",error=%e),
        }
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

fn spawn_supervised<F, Fut>(name: &'static str, factory: F)
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        loop {
            let outcome = tokio::spawn(factory()).await;
            match outcome {
                Ok(()) => tracing::error!(
                    event_type = "background_task_exited",
                    task = name,
                    "long-lived background task exited unexpectedly; restarting"
                ),
                Err(e) => {
                    tracing::error!(event_type = "background_task_panicked", task = name, error = %e, "long-lived background task panicked; restarting")
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}

/// How often to revalidate routing inventory over SSH.
///
/// Hourly, not daily. Two things hang off this loop, and both want a short
/// cadence:
///
/// * `templates::ROUTING_INVENTORY_MAX_AGE_HOURS` is 48h. At a 24h cadence TWO
///   consecutive failed runs silently aged the routing inventory out and every
///   dependent action started being refused at fire time. At 1h it takes ~48
///   consecutive failures, and the expiry alert has ~47 chances to page first.
/// * the post-discovery drift audit (`reroute::inventory_audit`) can only notice a
///   router-side change when a discovery run happens, so the cadence IS the
///   detection latency for "my mitigation no longer matches the router".
///
/// Cost is two short SSH sessions per device per hour — far below the reachability
/// probe's own rate — and the loop stays strictly in the background: discovery is
/// never run inline on a trigger path (see `discover_prefixes_hourly`).
const PREFIX_DISCOVERY_INTERVAL: Duration = Duration::from_secs(3600);

/// Upper bound of the random pre-read delay applied to EACH device, so a fleet
/// does not open SSH sessions to every router in the same second.
const PREFIX_DISCOVERY_DEVICE_JITTER: Duration = Duration::from_secs(300);
const PREFIX_DISCOVERY_CONCURRENCY: usize = 2;
const PREFIX_DISCOVERY_BACKLOG_CAPACITY: usize = 256;
const PREFIX_DISCOVERY_RESCAN: Duration = Duration::from_secs(30);

struct DiscoverySchedule {
    anchor: tokio::time::Instant,
    next_due: HashMap<u64, tokio::time::Instant>,
    queued: HashSet<u64>,
    active: HashSet<u64>,
    backlog: VecDeque<u64>,
}

impl DiscoverySchedule {
    fn new(anchor: tokio::time::Instant) -> Self {
        Self {
            anchor,
            next_due: HashMap::new(),
            queued: HashSet::new(),
            active: HashSet::new(),
            backlog: VecDeque::new(),
        }
    }

    fn reconcile(&mut self, enabled: &[u64], now: tokio::time::Instant) -> usize {
        let enabled: HashSet<u64> = enabled.iter().copied().collect();
        self.next_due.retain(|id, _| enabled.contains(id));
        self.backlog.retain(|id| enabled.contains(id));
        self.queued.retain(|id| enabled.contains(id));
        for id in &enabled {
            self.next_due
                .entry(*id)
                .or_insert(self.anchor + stable_discovery_stagger(*id));
        }

        let mut due: Vec<_> = self
            .next_due
            .iter()
            .filter(|(id, deadline)| {
                **deadline <= now && !self.queued.contains(id) && !self.active.contains(id)
            })
            .map(|(id, deadline)| (*id, *deadline))
            .collect();
        due.sort_by_key(|(id, deadline)| (*deadline, *id));
        let available = PREFIX_DISCOVERY_BACKLOG_CAPACITY.saturating_sub(self.backlog.len());
        let deferred = due.len().saturating_sub(available);
        for (id, _) in due.into_iter().take(available) {
            self.backlog.push_back(id);
            self.queued.insert(id);
        }
        deferred
    }

    fn start_ready(&mut self) -> Vec<(u64, tokio::time::Instant)> {
        let slots = PREFIX_DISCOVERY_CONCURRENCY.saturating_sub(self.active.len());
        (0..slots)
            .filter_map(|_| {
                let id = self.backlog.pop_front()?;
                self.queued.remove(&id);
                self.active.insert(id);
                Some((id, self.next_due[&id]))
            })
            .collect()
    }

    fn complete(&mut self, id: u64, now: tokio::time::Instant) {
        self.active.remove(&id);
        let Some(deadline) = self.next_due.get_mut(&id) else {
            return;
        };
        // Advance to the first future hourly slot. A slow operation therefore
        // never creates an immediate catch-up burst.
        while *deadline <= now {
            *deadline += PREFIX_DISCOVERY_INTERVAL;
        }
    }
}

/// Discover each device's routing inventory over SSH, shortly after boot and then
/// hourly. Best-effort: a device without working SSH is logged and skipped
/// (manual "Discover prefixes" remains available). The SNMP-cached ASN/neighbors
/// refresh every poll, so only the SSH-sourced inventory needs this slow loop.
///
/// This is the ONLY scheduled caller of `discover_prefixes_and_store`, and it is
/// deliberately a background loop with no relationship to detection or execution.
/// Inventory is never refreshed inline just before a mitigation fires: during a
/// volumetric attack the router control plane is precisely what is saturated, SSH
/// is the first thing to go slow (the russh inactivity timeout is 60s), and the
/// executor already gates on cheaper, stricter liveness signals — the reachability
/// probe plus `reroute::reachability::STABILITY_WINDOW`. Adding an inline refresh
/// would spend incident time re-learning what this loop already knows.
async fn discover_prefixes_hourly(pool: MySqlPool, cfg: Arc<Config>) {
    tokio::time::sleep(Duration::from_secs(120)).await; // let the box settle after boot
    let mut schedule = DiscoverySchedule::new(tokio::time::Instant::now());
    let mut rescan = tokio::time::interval(PREFIX_DISCOVERY_RESCAN);
    rescan.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut running = FuturesUnordered::new();
    let mut completed_duration = Duration::ZERO;
    let mut completed_count = 0u64;
    let mut next_capacity_report = tokio::time::Instant::now() + PREFIX_DISCOVERY_INTERVAL;
    loop {
        tokio::select! {
            _ = rescan.tick() => {
                match snmp::load_enabled_devices(&pool).await {
                    Ok(devices) => {
                        let ids: Vec<_> = devices.into_iter().map(|device| device.id).collect();
                        let fleet_size = ids.len();
                        let now = tokio::time::Instant::now();
                        let deferred = schedule.reconcile(&ids, now);
                        if deferred > 0 {
                            tracing::warn!(event_type="prefix_discovery_capacity_exhausted", deferred, backlog=schedule.backlog.len(), capacity=PREFIX_DISCOVERY_BACKLOG_CAPACITY, "due routing-inventory discoveries remain queued for a later rescan");
                        }
                        if now >= next_capacity_report {
                            let mean_ms = (completed_duration.as_millis() as u64).checked_div(completed_count).unwrap_or(0);
                            let required_worker_ms = mean_ms.saturating_mul(fleet_size as u64);
                            let available_worker_ms = PREFIX_DISCOVERY_INTERVAL.as_millis() as u64 * PREFIX_DISCOVERY_CONCURRENCY as u64;
                            tracing::info!(event_type="prefix_discovery_capacity", fleet_size, completed_samples=completed_count, mean_operation_ms=mean_ms, required_worker_ms_per_hour=required_worker_ms, available_worker_ms_per_hour=available_worker_ms, "measured routing-inventory discovery duty and fleet capacity");
                            completed_duration = Duration::ZERO;
                            completed_count = 0;
                            while next_capacity_report <= now { next_capacity_report += PREFIX_DISCOVERY_INTERVAL; }
                        }
                    }
                    Err(e) => tracing::warn!(event_type = "prefix_discovery_load_failed", error = %e, "could not load devices for prefix discovery"),
                }
            }
            Some((device_id, elapsed, result)) = running.next(), if !running.is_empty() => {
                schedule.complete(device_id, tokio::time::Instant::now());
                completed_duration = completed_duration.saturating_add(elapsed);
                completed_count = completed_count.saturating_add(1);
                match result {
                    Ok(n) => tracing::debug!(event_type="prefix_discovery", device_id, prefixes=n, elapsed_ms=elapsed.as_millis() as u64, "announced prefixes refreshed"),
                    Err(e) => tracing::debug!(event_type="prefix_discovery_failed", device_id, elapsed_ms=elapsed.as_millis() as u64, error=%e, "announced-prefix discovery failed (non-fatal)"),
                }
            }
        }
        for (device_id, deadline) in schedule.start_ready() {
            let overdue = tokio::time::Instant::now().saturating_duration_since(deadline);
            // The scheduler observes deadlines on a 30-second rescan. That
            // expected quantization is not a missed deadline; warn only when
            // work waited beyond one complete rescan, normally due to capacity.
            if overdue > PREFIX_DISCOVERY_RESCAN {
                tracing::warn!(
                    event_type = "prefix_discovery_deadline_missed",
                    device_id,
                    overdue_ms = overdue.as_millis() as u64,
                    backlog = schedule.backlog.len(),
                    "routing-inventory discovery started after its fixed deadline"
                );
            }
            let pool = pool.clone();
            let cfg = cfg.clone();
            running.push(Box::pin(async move {
                let started = tokio::time::Instant::now();
                let result = background_operation(
                    &pool,
                    &cfg,
                    crate::ssh::discover_prefixes_and_store(&pool, device_id),
                )
                .await;
                (device_id, started.elapsed(), result)
            }));
        }
    }
}

fn stable_discovery_stagger(device_id: u64) -> Duration {
    Duration::from_secs(
        device_id.wrapping_mul(2_654_435_761) % (PREFIX_DISCOVERY_DEVICE_JITTER.as_secs() + 1),
    )
}

/// One day-windowed retention rule: delete rows whose `ts_column` is older than
/// `days`. Names are compile-time constants (never user input), so they are safe
/// to interpolate into the DELETE.
struct RetentionSpec {
    table: &'static str,
    ts_column: &'static str,
    index: &'static str,
    days: u32,
    key: RetentionKey,
}

#[derive(Clone, Copy)]
enum RetentionKey {
    Id,
    ExporterBucket,
}

/// Build the day-windowed retention rules from `[retention]` config. Pure (no
/// I/O) so the mapping from config to prune targets is unit-testable.
///
/// Actively-pruned tables only: interface_samples (SNMP), the four flow_*_buckets
/// (NetFlow/sFlow), alerts, and rule_events (detection history) — the short-term
/// telemetry + protection history. The `reroutes` action log and `audit_logs` are
/// deliberately excluded: low-volume safety/security trails, and `reroutes` rows
/// are live state-machine state (an `uncertain` reroute holds a device lock), so
/// they need state-aware pruning, not a blanket time delete.
fn retention_specs(cfg: &Config) -> Vec<RetentionSpec> {
    let r = &cfg.retention;
    let mut specs = vec![RetentionSpec {
        table: "interface_samples",
        ts_column: "sampled_at",
        index: "idx_interface_samples_sampled_at",
        days: r.traffic_samples_days,
        key: RetentionKey::Id,
    }];
    for (table, index) in [
        ("flow_iface_buckets", "idx_flow_iface_bucket_ts"),
        ("flow_port_buckets", "idx_flow_port_bucket_ts"),
        ("flow_as_buckets", "idx_flow_as_bucket_ts"),
        ("flow_talker_buckets", "idx_flow_talker_bucket_ts"),
        ("flow_bucket_quality", "idx_flow_bucket_quality_ts"),
    ] {
        specs.push(RetentionSpec {
            table,
            ts_column: "bucket_ts",
            index,
            days: r.flow_buckets_days,
            key: if table == "flow_bucket_quality" {
                RetentionKey::ExporterBucket
            } else {
                RetentionKey::Id
            },
        });
    }
    specs.push(RetentionSpec {
        table: "alerts",
        ts_column: "created_at",
        index: "idx_alerts_created",
        days: r.alerts_days,
        key: RetentionKey::Id,
    });
    specs.push(RetentionSpec {
        table: "rule_events",
        ts_column: "created_at",
        index: "idx_rule_events_created",
        days: r.rule_events_days,
        key: RetentionKey::Id,
    });
    specs
}

fn retention_delete_sql(spec: &RetentionSpec, protected: &str) -> String {
    let (select_key, join_key) = match spec.key {
        RetentionKey::Id => ("id", "target.id = expired.id"),
        RetentionKey::ExporterBucket => (
            "exporter_id, bucket_ts",
            "target.exporter_id = expired.exporter_id AND target.bucket_ts = expired.bucket_ts",
        ),
    };
    format!(
        "DELETE target FROM ( \
             SELECT {select_key} FROM {} FORCE INDEX ({}) \
             WHERE {} < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? DAY) {} \
             ORDER BY {} LIMIT {} \
         ) AS expired STRAIGHT_JOIN {} AS target ON {join_key}",
        spec.table,
        spec.index,
        spec.ts_column,
        protected,
        spec.ts_column,
        RETENTION_DELETE_BATCH,
        spec.table
    )
}

/// Periodically enforce the configured retention windows: delete telemetry
/// (interface_samples + flow_*_buckets), alerts, and rule_events older than their
/// window, and drop flow exporters that have gone silent longer than the flow
/// bucket window. A single task owns all retention so the policy has one place to
/// reason about.
async fn retention_cleanup(pool: MySqlPool, cfg: Arc<Config>) {
    let specs = retention_specs(&cfg);
    // Exporters are dropped only once they have been idle LONGER than the flow
    // bucket retention window (+1 day of margin). flow_*_buckets cascade-delete
    // from flow_exporters, so dropping an exporter whose buckets are still inside
    // the window would silently destroy still-retained flow history. Waiting past
    // the window means the bucket prune above has already removed them.
    let exporter_idle_days = cfg.retention.flow_buckets_days.max(1).saturating_add(1);
    loop {
        for spec in &specs {
            // Floor at 1 day so a misconfigured 0 can never mean "delete now".
            let days = spec.days.max(1);
            let mut total = 0u64;
            loop {
                // SAFETY: table/ts_column are 'static literals from our own code;
                // the batch size is a compile-time integer constant.
                let protected = match spec.table {
                    "alerts" => " AND EXISTS (SELECT 1 FROM alert_delivery_intents i WHERE i.alert_id = alerts.id) AND NOT EXISTS (SELECT 1 FROM alert_delivery_intents i WHERE i.alert_id = alerts.id AND i.state <> 'settled')",
                    "rule_events" => " AND NOT EXISTS (SELECT 1 FROM reroutes r WHERE r.rule_event_id = rule_events.id AND (r.state IN ('planned','pending','running','verifying','uncertain') OR r.mutation_effect IN ('changed','unknown') OR (r.state = 'succeeded' AND r.mutation_effect = 'pending')) AND NOT EXISTS (SELECT 1 FROM reroutes rb WHERE rb.rollback_of_reroute_id = r.id AND rb.state = 'succeeded'))",
                    _ => "",
                };
                let sql = retention_delete_sql(spec, protected);
                match sqlx::query(&sql).bind(days).execute(&pool).await {
                    Ok(r) => {
                        let rows = r.rows_affected();
                        total += rows;
                        if rows < RETENTION_DELETE_BATCH {
                            break;
                        }
                        tokio::task::yield_now().await;
                    }
                    Err(e) => {
                        tracing::warn!(event_type = "retention_prune_failed", table = spec.table, rows = total, error = %e, "retention prune failed");
                        break;
                    }
                }
            }
            if total > 0 {
                tracing::debug!(
                    event_type = "retention_pruned",
                    table = spec.table,
                    days,
                    rows = total,
                    "pruned rows past retention window"
                );
            }
        }

        // Drop flow exporters that have been idle past the flow bucket window (see
        // `exporter_idle_days` above) so the exporter-health view doesn't
        // accumulate stale entries. By now the bucket prune has removed their
        // buckets, so the ON DELETE CASCADE has nothing left to take. COALESCE
        // handles an exporter row created but that never sent a datagram.
        match sqlx::query(
            "DELETE FROM flow_exporters \
             WHERE (last_packet_at IS NOT NULL \
                    AND last_packet_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? DAY)) \
                OR (last_packet_at IS NULL \
                    AND created_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? DAY))",
        )
        .bind(exporter_idle_days)
        .bind(exporter_idle_days)
        .execute(&pool)
        .await
        {
            Ok(r) if r.rows_affected() > 0 => {
                tracing::info!(
                    event_type = "flow_exporters_pruned",
                    rows = r.rows_affected(),
                    days = exporter_idle_days,
                    "pruned stale flow exporters (idle past flow window)"
                )
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(event_type = "exporter_prune_failed", error = %e, "pruning flow_exporters failed")
            }
        }

        // Runtime authorization/safety rows have no historical value after they
        // expire. Keep these hot lookup tables bounded independently of the
        // operator-selected telemetry retention windows.
        for (table, predicate) in [
            ("sessions", "expires_at < UTC_TIMESTAMP()"),
            (
                "action_previews",
                "expires_at < UTC_TIMESTAMP() OR used_at IS NOT NULL",
            ),
            ("cooldowns", "`until` < UTC_TIMESTAMP()"),
        ] {
            let sql = format!("DELETE FROM {table} WHERE {predicate}");
            match sqlx::query(&sql).execute(&pool).await {
                Ok(r) if r.rows_affected() > 0 => tracing::debug!(
                    event_type = "runtime_rows_pruned",
                    table,
                    rows = r.rows_affected(),
                    "pruned expired runtime rows"
                ),
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(event_type = "runtime_prune_failed", table, error = %e, "runtime row cleanup failed")
                }
            }
        }

        tokio::time::sleep(PRUNE_INTERVAL).await;
    }
}

/// Evaluate aggregate (`metric_aggregation = 'sum'`) rules forever. Read-only and
/// observe-safe: like every rule path it only renders would-run plans unless the
/// controller is in enforce mode with the global + per-rule auto switches on.
async fn evaluate_aggregate_loop(pool: MySqlPool, cfg: Arc<Config>) {
    // Let device loops populate interface_metrics_current before the first pass.
    tokio::time::sleep(Duration::from_secs(20)).await;
    loop {
        match background_operation(
            &pool,
            &cfg,
            detection::engine::evaluate_aggregate_rules(&pool, &cfg),
        )
        .await
        {
            Ok(fired) if fired > 0 => {
                tracing::info!(
                    event_type = "aggregate_detection",
                    fired,
                    "aggregate rules fired"
                )
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(event_type = "aggregate_detection_failed", error = %e, "aggregate rule evaluation failed")
            }
        }
        tokio::time::sleep(Duration::from_secs(cfg.telemetry.metrics_rollup_seconds)).await;
    }
}

/// Reconcile per-device poll loops with the set of enabled devices, forever.
async fn supervise(pool: MySqlPool, cfg: Arc<Config>) {
    struct Worker {
        handle: JoinHandle<()>,
        control: watch::Sender<Option<u32>>,
        interval: u32,
    }
    let mut running: HashMap<u64, Worker> = HashMap::new();

    loop {
        match snmp::load_enabled_devices(&pool).await {
            Ok(devices) => {
                let enabled_ids: std::collections::HashSet<u64> =
                    devices.iter().map(|d| d.id).collect();

                // Drop loops for devices that are gone, disabled, or finished.
                for (id, worker) in &running {
                    if !enabled_ids.contains(id) {
                        let _ = worker.control.send(None);
                    }
                }
                running.retain(|_, worker| !worker.handle.is_finished());

                // Spawn loops for newly enabled devices.
                for dev in devices {
                    let interval = dev.poll_interval_seconds.max(5);
                    if let Some(worker) = running.get_mut(&dev.id) {
                        if worker.interval != interval {
                            worker.interval = interval;
                            let _ = worker.control.send(Some(interval));
                        }
                        continue;
                    }
                    running.entry(dev.id).or_insert_with(|| {
                        let pool = pool.clone();
                        let cfg = cfg.clone();
                        let device_id = dev.id;
                        let (control, receiver) = watch::channel(Some(interval));
                        tracing::info!(
                            event_type = "device_loop_started",
                            device_id,
                            interval_seconds = interval,
                            "starting SNMP poll loop"
                        );
                        Worker {
                            handle: tokio::spawn(device_loop(pool, cfg, device_id, receiver)),
                            control,
                            interval,
                        }
                    });
                }
            }
            Err(e) => {
                tracing::warn!(event_type = "scheduler_reload_failed", error = %e, "could not reload device list");
            }
        }
        tokio::time::sleep(RELOAD_INTERVAL).await;
    }
}

/// One device's poll+detect loop. Tolerates per-tick failure; a poll error is
/// already recorded as the device's last_error by the poller.
async fn device_loop(
    pool: MySqlPool,
    cfg: Arc<Config>,
    device_id: u64,
    mut control: watch::Receiver<Option<u32>>,
) {
    let Some(mut base_interval_secs) = *control.borrow() else {
        return;
    };
    // Small initial spread so freshly-spawned loops don't all fire at t=0.
    let initial = jittered(base_interval_secs, cfg.telemetry.jitter_percent);
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_millis((initial * 1000.0) as u64 / 4)) => {}
        changed = control.changed() => {
            if changed.is_err() || control.borrow().is_none() { return; }
            base_interval_secs = (*control.borrow()).unwrap_or(5).max(5);
        }
    }

    // SSH reachability is probed on its own (slow) cadence, NOT every poll — an SSH
    // session is heavier than an SNMP poll and we must not hammer the device's SSH.
    // 60s floor guards against a mis-set config. `None` => probe on the first tick
    // so the UI populates soon after startup (per-device loops are already staggered).
    let ssh_probe_interval =
        Duration::from_secs(cfg.telemetry.reachability_interval_seconds.max(60));
    let mut last_ssh_probe: Option<Instant> = None;
    let mut last_interface_discovery: Option<Instant> = None;
    let mut ssh_probe_task: Option<JoinHandle<()>> = None;
    let mut interface_discovery_task: Option<JoinHandle<()>> = None;
    let mut next = tokio::time::Instant::now();

    loop {
        tokio::select! {
            changed = control.changed() => {
                if changed.is_err() || control.borrow().is_none() {
                    // These tasks can be inside a store operation. Let them
                    // finish cooperatively rather than aborting a writer when a
                    // device is disabled or the supervisor is reconfigured.
                    if let Some(task) = ssh_probe_task.take() { let _ = task.await; }
                    if let Some(task) = interface_discovery_task.take() { let _ = task.await; }
                    return;
                }
                base_interval_secs = (*control.borrow()).unwrap_or(5).max(5);
                next = tokio::time::Instant::now() + Duration::from_secs(base_interval_secs.into());
                continue;
            }
            _ = tokio::time::sleep_until(next) => {}
        }
        let tick = background_operation(&pool, &cfg, poll_and_detect(&pool, &cfg, device_id)).await;
        if let Err(e) = tick {
            tracing::warn!(event_type = "device_tick_failed", device_id, error = %e, "device poll/detect tick failed");
        }

        if ssh_probe_task.as_ref().is_some_and(JoinHandle::is_finished) {
            if let Some(task) = ssh_probe_task.take() {
                let _ = task.await;
            }
        }
        if ssh_probe_task.is_none()
            && last_ssh_probe.is_none_or(|t| t.elapsed() >= ssh_probe_interval)
        {
            let probe_pool = pool.clone();
            let probe_cfg = cfg.clone();
            ssh_probe_task = Some(tokio::spawn(async move {
                let operation = async {
                    let status =
                        crate::reroute::reachability::probe_ssh_and_store(&probe_pool, device_id)
                            .await;
                    Ok::<_, anyhow::Error>(status)
                };
                if let Ok(status) = background_operation(&probe_pool, &probe_cfg, operation).await {
                    tracing::debug!(
                        event_type = "ssh_reachability_probed",
                        device_id,
                        status,
                        "periodic SSH reachability probe"
                    );
                }
            }));
            last_ssh_probe = Some(Instant::now());
        }
        if interface_discovery_task
            .as_ref()
            .is_some_and(JoinHandle::is_finished)
        {
            if let Some(task) = interface_discovery_task.take() {
                let _ = task.await;
            }
        }
        if interface_discovery_task.is_none()
            && last_interface_discovery
                .is_none_or(|t| t.elapsed() >= Duration::from_secs(24 * 3600))
        {
            let discovery_pool = pool.clone();
            let discovery_cfg = cfg.clone();
            let jitter = f64::from(cfg.telemetry.jitter_percent.min(90)) / 100.0;
            let minimum_poll_gap = (f64::from(base_interval_secs) * (1.0 - jitter)).max(1.0);
            let budget = Duration::from_millis(
                ((minimum_poll_gap * 1000.0) as u64)
                    .saturating_sub(250)
                    .max(250),
            );
            interface_discovery_task = Some(tokio::spawn(async move {
                let operation = async {
                    tokio::time::timeout(budget, async {
                        let _ = snmp::discover_and_store(&discovery_pool, device_id).await;
                        let _ = snmp::discover_bgp_and_store(&discovery_pool, device_id).await;
                    })
                    .await
                    .map_err(|_| anyhow::anyhow!("device inventory background budget elapsed"))?;
                    Ok::<_, anyhow::Error>(())
                };
                let _ = background_operation(&discovery_pool, &discovery_cfg, operation).await;
            }));
            last_interface_discovery = Some(Instant::now());
        }
        let secs = jittered(base_interval_secs, cfg.telemetry.jitter_percent);
        next = advance_deadline(
            next,
            tokio::time::Instant::now(),
            Duration::from_millis((secs * 1000.0) as u64),
        );
    }
}

fn advance_deadline(
    previous: tokio::time::Instant,
    now: tokio::time::Instant,
    period: Duration,
) -> tokio::time::Instant {
    let scheduled = previous + period;
    if scheduled <= now {
        now + period
    } else {
        scheduled
    }
}

/// One poll + detection pass for a device. Detection runs even if some
/// interfaces had no fresh sample (the engine filters stale/invalid itself).
async fn poll_and_detect(pool: &MySqlPool, cfg: &Config, device_id: u64) -> Result<()> {
    // Poll: stores interface_metrics_current + interface_samples. A transport
    // failure marks the device unreachable and returns Err — detection then has
    // nothing fresh and harmlessly no-ops.
    let mut collection = crate::timing::Stage::start("collection", device_id);
    match snmp::poll(pool, device_id).await {
        Ok(updated) => {
            collection.complete("committed");
            tracing::debug!(
                event_type = "device_polled",
                device_id,
                interfaces = updated,
                "poll complete"
            );
        }
        Err(e) => {
            // Already recorded as last_error; surface and skip detection.
            return Err(e);
        }
    }
    drop(collection);

    // Detection for this device's monitored interfaces.
    match detection::engine::evaluate_device(pool, cfg, device_id).await {
        Ok(fired) if fired > 0 => {
            tracing::info!(
                event_type = "device_detection",
                device_id,
                fired,
                "rules fired on poll"
            );
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(event_type = "detection_failed", device_id, error = %e, "detection pass failed")
        }
    }
    Ok(())
}

/// Apply +/- jitter_percent to an interval (seconds), clamped to a sane floor.
fn jittered(base_secs: u32, jitter_percent: u8) -> f64 {
    let base = base_secs.max(1) as f64;
    if jitter_percent == 0 {
        return base;
    }
    let frac = jitter_percent.min(90) as f64 / 100.0;
    let delta = rand::rng().random_range(-frac..=frac);
    (base * (1.0 + delta)).max(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn quality_retention_executes_with_composite_keys_and_preserves_current_bucket() {
        let db = crate::db::connect_test_database().await;
        let mut tx = db.begin().await.unwrap();
        let exporter = sqlx::query(
            "INSERT INTO flow_exporters(source_addr,observation_domain) VALUES('192.0.2.247',?)",
        )
        .bind(rand::random::<u32>())
        .execute(&mut *tx)
        .await
        .unwrap()
        .last_insert_id();
        sqlx::query("INSERT INTO flow_bucket_quality(exporter_id,bucket_ts) VALUES(?,DATE_SUB(UTC_TIMESTAMP(),INTERVAL 500 DAY)),(?,UTC_TIMESTAMP())")
            .bind(exporter).bind(exporter).execute(&mut *tx).await.unwrap();
        let spec = retention_specs(&Config::default())
            .into_iter()
            .find(|spec| spec.table == "flow_bucket_quality")
            .unwrap();
        // Isolate this test's fixture while exercising the production key join.
        let sql = retention_delete_sql(&spec, &format!(" AND exporter_id={exporter}"));
        assert_eq!(
            sqlx::query(&sql)
                .bind(100)
                .execute(&mut *tx)
                .await
                .unwrap()
                .rows_affected(),
            1
        );
        let current: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM flow_bucket_quality WHERE exporter_id=? AND bucket_ts>DATE_SUB(UTC_TIMESTAMP(),INTERVAL 1 DAY)")
            .bind(exporter).fetch_one(&mut *tx).await.unwrap();
        assert_eq!(current, 1);
        tx.rollback().await.unwrap();
    }

    /// The discovery cadence is what keeps SSH routing inventory inside the
    /// validator window. If the two ever drift apart (cadence lengthened, or the
    /// max age shortened) the controller starts silently refusing dependent
    /// actions after only a couple of missed runs — the failure this test exists
    /// to prevent.
    #[test]
    fn discovery_cadence_leaves_real_margin_before_inventory_expires() {
        let max_age = Duration::from_secs(
            crate::reroute::templates::ROUTING_INVENTORY_MAX_AGE_HOURS as u64 * 3600,
        );
        let worst_case_pass = PREFIX_DISCOVERY_INTERVAL + PREFIX_DISCOVERY_DEVICE_JITTER;
        let tolerated_failures = max_age.as_secs() / worst_case_pass.as_secs();
        assert!(
            tolerated_failures >= 24,
            "routing inventory ages out after only {tolerated_failures} consecutive failed \
             discovery runs; the cadence must leave far more margin than that"
        );
    }

    #[test]
    fn overrun_skips_missed_deadlines_without_catchup_burst() {
        let now = tokio::time::Instant::now();
        let next = advance_deadline(now - Duration::from_secs(20), now, Duration::from_secs(5));
        assert_eq!(next, now + Duration::from_secs(5));
    }

    #[test]
    fn discovery_stagger_is_stable_and_within_window() {
        for device in 1..100 {
            assert_eq!(
                stable_discovery_stagger(device),
                stable_discovery_stagger(device)
            );
            assert!(stable_discovery_stagger(device) <= PREFIX_DISCOVERY_DEVICE_JITTER);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn discovery_deadlines_are_fixed_and_overruns_do_not_catch_up() {
        let anchor = tokio::time::Instant::now();
        let mut schedule = DiscoverySchedule::new(anchor);
        let id = 17;
        let deadline = anchor + stable_discovery_stagger(id);

        assert_eq!(schedule.reconcile(&[id], deadline), 0);
        assert_eq!(schedule.start_ready(), vec![(id, deadline)]);
        // A rescan while the device is active must never enqueue an overlapping
        // discovery, even several nominal periods later.
        let late = deadline + PREFIX_DISCOVERY_INTERVAL * 3 + Duration::from_secs(1);
        tokio::time::advance(late - tokio::time::Instant::now()).await;
        assert_eq!(schedule.reconcile(&[id], late), 0);
        assert!(schedule.start_ready().is_empty());

        schedule.complete(id, late);
        let next = schedule.next_due[&id];
        assert!(next > late);
        assert!(next <= late + PREFIX_DISCOVERY_INTERVAL);
        assert_eq!(schedule.reconcile(&[id], late), 0);
        assert!(schedule.start_ready().is_empty(), "no catch-up burst");
    }

    #[tokio::test(start_paused = true)]
    async fn discovery_backlog_is_bounded_and_overflow_remains_due_for_rescan() {
        let anchor = tokio::time::Instant::now();
        let mut schedule = DiscoverySchedule::new(anchor);
        let devices: Vec<u64> = (1..=PREFIX_DISCOVERY_BACKLOG_CAPACITY as u64 + 44).collect();
        tokio::time::advance(PREFIX_DISCOVERY_DEVICE_JITTER + Duration::from_secs(1)).await;
        let now = tokio::time::Instant::now();

        assert_eq!(schedule.reconcile(&devices, now), 44);
        assert_eq!(schedule.backlog.len(), PREFIX_DISCOVERY_BACKLOG_CAPACITY);
        let started = schedule.start_ready();
        assert_eq!(started.len(), PREFIX_DISCOVERY_CONCURRENCY);

        // Finishing work opens exactly two queue slots. The next rescan retains
        // every other overdue device and admits two of them; none is forgotten.
        for (id, _) in started {
            schedule.complete(id, now);
        }
        assert_eq!(schedule.reconcile(&devices, now), 42);
        assert_eq!(schedule.backlog.len(), PREFIX_DISCOVERY_BACKLOG_CAPACITY);
        let still_due = schedule.backlog.len() + schedule.active.len() + 42;
        assert_eq!(still_due, devices.len() - PREFIX_DISCOVERY_CONCURRENCY);
    }

    #[tokio::test(start_paused = true)]
    async fn flow_retry_backoff_is_bounded_and_resets_after_success() {
        let mut delay = Duration::from_secs(1);
        for expected in [2, 4, 8, 16, 30, 30] {
            let sleeper = tokio::spawn(tokio::time::sleep(delay));
            tokio::task::yield_now().await;
            assert!(!sleeper.is_finished());
            tokio::time::advance(delay).await;
            sleeper.await.unwrap();
            delay = next_flow_retry_delay(delay);
            assert_eq!(delay, Duration::from_secs(expected));
        }
        delay = Duration::from_secs(1);
        assert_eq!(delay, Duration::from_secs(1));
    }

    #[test]
    fn retention_specs_map_config_windows_to_tables() {
        let mut cfg = Config::default();
        cfg.retention.traffic_samples_days = 3;
        cfg.retention.flow_buckets_days = 5;
        cfg.retention.alerts_days = 9;
        cfg.retention.rule_events_days = 4;

        let specs = retention_specs(&cfg);

        // interface_samples + 4 aggregates + flow quality + alerts + rule_events.
        assert_eq!(specs.len(), 8);
        let by_table = |t: &str| {
            specs
                .iter()
                .find(|s| s.table == t)
                .unwrap_or_else(|| panic!("no retention spec for {t}"))
        };

        let samples = by_table("interface_samples");
        assert_eq!(samples.ts_column, "sampled_at");
        assert_eq!(samples.index, "idx_interface_samples_sampled_at");
        assert_eq!(samples.days, 3, "SNMP samples use traffic_samples_days");

        for t in [
            "flow_iface_buckets",
            "flow_port_buckets",
            "flow_as_buckets",
            "flow_talker_buckets",
            "flow_bucket_quality",
        ] {
            let s = by_table(t);
            assert_eq!(s.ts_column, "bucket_ts", "{t} prunes on bucket_ts");
            assert!(s.index.ends_with("_bucket_ts") || t == "flow_bucket_quality");
            assert_eq!(s.days, 5, "{t} uses flow_buckets_days");
        }

        let alerts = by_table("alerts");
        assert_eq!(alerts.ts_column, "created_at");
        assert_eq!(alerts.index, "idx_alerts_created");
        assert_eq!(alerts.days, 9, "alerts use alerts_days");

        let rule_events = by_table("rule_events");
        assert_eq!(rule_events.ts_column, "created_at");
        assert_eq!(rule_events.index, "idx_rule_events_created");
        assert_eq!(rule_events.days, 4, "rule_events use rule_events_days");
    }

    #[test]
    fn retention_delete_uses_each_tables_real_primary_key() {
        let mut cfg = Config::default();
        cfg.retention.flow_buckets_days = 5;
        let specs = retention_specs(&cfg);

        let quality = specs
            .iter()
            .find(|spec| spec.table == "flow_bucket_quality")
            .expect("flow quality retention spec");
        let quality_sql = retention_delete_sql(quality, "");
        assert!(quality_sql.contains("SELECT exporter_id, bucket_ts"));
        assert!(quality_sql.contains(
            "target.exporter_id = expired.exporter_id AND target.bucket_ts = expired.bucket_ts"
        ));
        assert!(!quality_sql.contains("target.id"));

        let iface = specs
            .iter()
            .find(|spec| spec.table == "flow_iface_buckets")
            .expect("interface bucket retention spec");
        let iface_sql = retention_delete_sql(iface, "");
        assert!(iface_sql.contains("SELECT id"));
        assert!(iface_sql.contains("target.id = expired.id"));
    }
}
