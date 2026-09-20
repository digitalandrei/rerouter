//! Bounded, cancellation-safe MariaDB advisory-lock sessions.

use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use anyhow::{Context, Result};
use sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions};
use sqlx::{pool::PoolConnection, Executor, MySql, MySqlPool};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

const LOCK_SESSIONS: u32 = 8;
const FOREGROUND_SLOTS: usize = 4;
const BACKGROUND_SLOTS: usize = 4;
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);
const QUERY_TIMEOUT: Duration = Duration::from_secs(7);

tokio::task_local! {
    static OPERATION: Operation;
}

#[derive(Clone, Copy, Debug)]
pub enum WorkClass {
    Foreground,
    Background,
}

pub struct LockRuntime {
    pool: MySqlPool,
    foreground: Arc<Semaphore>,
    background: Arc<Semaphore>,
    namespace: String,
    source_options: Arc<MySqlConnectOptions>,
}

impl std::fmt::Debug for LockRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LockRuntime")
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl LockRuntime {
    pub async fn from_data_pool(data_pool: &MySqlPool) -> Result<Arc<Self>> {
        let source_options = data_pool.connect_options();
        let options: MySqlConnectOptions = source_options.as_ref().clone();
        let pool = MySqlPoolOptions::new()
            .max_connections(LOCK_SESSIONS)
            .acquire_timeout(ACQUIRE_TIMEOUT)
            .after_connect(|conn, _| {
                Box::pin(async move {
                    conn.execute("SET time_zone = '+00:00'").await?;
                    Ok(())
                })
            })
            .connect_with(options)
            .await
            .context("connecting bounded advisory-lock pool")?;
        let namespace: String = sqlx::query_scalar("SELECT DATABASE()")
            .fetch_one(&pool)
            .await
            .context("reading advisory-lock database namespace")?;
        Ok(Arc::new(Self {
            pool,
            foreground: Arc::new(Semaphore::new(FOREGROUND_SLOTS)),
            background: Arc::new(Semaphore::new(BACKGROUND_SLOTS)),
            namespace,
            source_options,
        }))
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn is_source_pool(&self, data_pool: &MySqlPool) -> bool {
        Arc::ptr_eq(&self.source_options, &data_pool.connect_options())
    }

    fn operation(self: &Arc<Self>, class: WorkClass) -> Operation {
        Operation {
            inner: Arc::new(OperationInner {
                runtime: self.clone(),
                class,
                session: Mutex::new(None),
            }),
        }
    }
}

pub async fn foreground_scope<F: std::future::Future>(
    runtime: Arc<LockRuntime>,
    future: F,
) -> Result<F::Output> {
    scope(runtime, WorkClass::Foreground, future).await
}

pub async fn background_scope<F: std::future::Future>(
    runtime: Arc<LockRuntime>,
    future: F,
) -> Result<F::Output> {
    scope(runtime, WorkClass::Background, future).await
}

async fn scope<F: std::future::Future>(
    runtime: Arc<LockRuntime>,
    class: WorkClass,
    future: F,
) -> Result<F::Output> {
    if let Ok(current) = OPERATION.try_with(|operation| operation.inner.clone()) {
        anyhow::ensure!(
            Arc::ptr_eq(&current.runtime, &runtime),
            "cannot nest advisory scopes from different runtimes"
        );
        return Ok(future.await);
    }
    Ok(OPERATION.scope(runtime.operation(class), future).await)
}

struct Operation {
    inner: Arc<OperationInner>,
}

struct OperationInner {
    runtime: Arc<LockRuntime>,
    class: WorkClass,
    session: Mutex<Option<Arc<Session>>>,
}

impl OperationInner {
    async fn session(&self) -> Result<Arc<Session>> {
        let mut slot = self.session.lock().await;
        if let Some(session) = slot.as_ref() {
            if !session.poisoned.load(Ordering::Acquire) {
                return Ok(session.clone());
            }
            anyhow::ensure!(
                session.active_guards.load(Ordering::Acquire) == 0
                    && session.inflight_acquisitions.load(Ordering::Acquire) == 0
                    && Arc::strong_count(session) == 1,
                "advisory-lock session is poisoned while a lock guard or acquisition is still live"
            );
            let poisoned = slot.take().expect("session checked above");
            drop(poisoned);
        }
        let semaphore = match self.class {
            WorkClass::Foreground => &self.runtime.foreground,
            WorkClass::Background => &self.runtime.background,
        };
        let permit = tokio::time::timeout(ACQUIRE_TIMEOUT, semaphore.clone().acquire_owned())
            .await
            .context("timed out waiting for advisory-lock work capacity")?
            .context("advisory-lock runtime is shutting down")?;
        let conn = tokio::time::timeout(ACQUIRE_TIMEOUT, self.runtime.pool.acquire())
            .await
            .context("timed out acquiring advisory-lock session")??;
        let session = Arc::new(Session {
            inner: Mutex::new(SessionInner {
                conn: Some(conn),
                held: BTreeMap::new(),
            }),
            poisoned: AtomicBool::new(false),
            active_guards: AtomicUsize::new(0),
            inflight_acquisitions: AtomicUsize::new(0),
            _permit: permit,
        });
        *slot = Some(session.clone());
        Ok(session)
    }
}

struct SessionInner {
    conn: Option<PoolConnection<MySql>>,
    held: BTreeMap<String, usize>,
}

struct Session {
    inner: Mutex<SessionInner>,
    poisoned: AtomicBool,
    active_guards: AtomicUsize,
    inflight_acquisitions: AtomicUsize,
    _permit: OwnedSemaphorePermit,
}

impl Session {
    fn poison(&self) {
        self.poisoned.store(true, Ordering::Release);
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let inner = self.inner.get_mut();
        if self.poisoned.load(Ordering::Acquire) || !inner.held.is_empty() {
            if let Some(conn) = inner.conn.as_mut() {
                conn.close_on_drop();
            }
        }
    }
}

pub struct AdvisoryGuard {
    session: Arc<Session>,
    logical_label: String,
    lock_name: String,
    released: bool,
}

impl AdvisoryGuard {
    pub async fn release(mut self) -> Result<()> {
        let mut inner = self.session.inner.lock().await;
        let conn = inner
            .conn
            .as_mut()
            .context("advisory-lock session is unavailable")?;
        let released = tokio::time::timeout(
            QUERY_TIMEOUT,
            sqlx::query_scalar::<_, Option<i64>>("SELECT RELEASE_LOCK(?)")
                .bind(&self.lock_name)
                .fetch_one(&mut **conn),
        )
        .await;
        match released {
            Ok(Ok(Some(1))) => {
                if let Some(count) = inner.held.get_mut(&self.logical_label) {
                    *count -= 1;
                    if *count == 0 {
                        inner.held.remove(&self.logical_label);
                    }
                }
                self.session.active_guards.fetch_sub(1, Ordering::AcqRel);
                self.released = true;
                Ok(())
            }
            Ok(Ok(other)) => {
                self.session.poison();
                anyhow::bail!("advisory lock release was not owned: {other:?}")
            }
            Ok(Err(error)) => {
                self.session.poison();
                Err(error).context("releasing advisory lock")
            }
            Err(_) => {
                self.session.poison();
                anyhow::bail!("timed out releasing advisory lock")
            }
        }
    }
}

impl Drop for AdvisoryGuard {
    fn drop(&mut self) {
        if !self.released {
            self.session.poison();
            self.session.active_guards.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

pub async fn acquire(logical_label: &str) -> Result<AdvisoryGuard> {
    let operation = OPERATION
        .try_with(|operation| operation.inner.clone())
        .map_err(|_| {
            anyhow::anyhow!(
                "advisory lock requested outside an explicit foreground/background operation"
            )
        })?;
    async move {
        let session = operation.session().await?;
        anyhow::ensure!(
            !session.poisoned.load(Ordering::Acquire),
            "advisory-lock session was poisoned by an incomplete acquisition or release"
        );
        let mut inner = session.inner.lock().await;
        if let Some(last) = inner.held.keys().next_back() {
            anyhow::ensure!(
                logical_label >= last.as_str() || inner.held.contains_key(logical_label),
                "advisory locks must be acquired in consistent lexical order"
            );
        }
        struct AcquireArm {
            session: Arc<Session>,
            disarmed: bool,
        }
        impl AcquireArm {
            fn disarm(&mut self) {
                self.disarmed = true;
                self.session
                    .inflight_acquisitions
                    .fetch_sub(1, Ordering::AcqRel);
            }
        }
        impl Drop for AcquireArm {
            fn drop(&mut self) {
                if !self.disarmed {
                    self.session.poison();
                    self.session
                        .inflight_acquisitions
                        .fetch_sub(1, Ordering::AcqRel);
                }
            }
        }
        session.inflight_acquisitions.fetch_add(1, Ordering::AcqRel);
        let mut arm = AcquireArm {
            session: session.clone(),
            disarmed: false,
        };
        let conn = inner
            .conn
            .as_mut()
            .context("advisory-lock session is unavailable")?;
        let lock_name = super::scoped_advisory_lock_name(conn, logical_label).await?;
        let acquired = tokio::time::timeout(
            QUERY_TIMEOUT,
            sqlx::query_scalar::<_, Option<i64>>("SELECT GET_LOCK(?, 5)")
                .bind(&lock_name)
                .fetch_one(&mut **conn),
        )
        .await;
        match acquired {
            Ok(Ok(Some(1))) => {
                *inner.held.entry(logical_label.to_string()).or_insert(0) += 1;
                session.active_guards.fetch_add(1, Ordering::AcqRel);
                arm.disarm();
            }
            Ok(Ok(other)) => {
                session.poison();
                anyhow::bail!("timed out acquiring advisory lock: {other:?}")
            }
            Ok(Err(error)) => {
                session.poison();
                return Err(error).context("acquiring advisory lock");
            }
            Err(_) => {
                session.poison();
                anyhow::bail!("timed out acquiring advisory lock query");
            }
        }
        drop(inner);
        drop(arm);
        Ok(AdvisoryGuard {
            session,
            logical_label: logical_label.to_string(),
            lock_name,
            released: false,
        })
    }
    .await
}
