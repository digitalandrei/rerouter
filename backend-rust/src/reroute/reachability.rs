//! Device reachability for mitigations — the "can we mitigate this device right
//! now?" decision that gates a reroute (see [`super::executor`]).
//!
//! A reroute pushes config over SSH, so the AUTHORITATIVE signal is: can SSH run the
//! commands a reroute needs, at privileged EXEC? We probe it with the SAME
//! command-access checks as the Settings "Check access" panel ([`ssh::ssh_probe`] →
//! [`ssh::probe_capabilities`]: connect → auth → privileged-EXEC → the config reads +
//! a no-op `configure terminal`, changing nothing), classified into three states:
//!
//! * `reachable` — answered at `#` AND every command-access check passed; usable for
//!   a reroute.
//! * `no_privilege` — SSH connected + authenticated but the account can't do the work:
//!   it landed at `>` (not privilege 15), OR it reached `#` but was denied a required
//!   command (a restrictive privilege level / parser view). An actionable config fix,
//!   not a connectivity problem — but NOT usable for a reroute. `last_ssh_error` names
//!   the exact denied commands.
//! * `unreachable` — could not connect / authenticate / reach a prompt.
//!
//! To avoid re-probing a device we just talked to — and to avoid tripping the
//! device's SSH connection throttle — a successful SSH contact within
//! [`RECENCY_WINDOW`] counts as reachable without opening a new session.
//! `devices.last_ssh_ok_at` is stamped only on a `reachable` outcome (a real
//! privileged success) — by this probe and by every successful reroute push.
//!
//! Stability: beyond "reachable right now", AUTOMATIC mitigations require the
//! device to have been continuously reachable for [`STABILITY_WINDOW`] — so a
//! just-recovered or flapping device is not auto-acted upon. `ssh_reachable_since`
//! tracks when SSH became (and stayed) reachable; it is cleared on any non-reachable
//! probe and on controller startup. Manual reroutes are NOT stability-gated (the
//! operator may act during the window, with a UI warning); they still require SSH
//! reachable via the normal gate.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::MySqlPool;

use crate::ssh::{self, SshReach};

/// A successful SSH contact newer than this satisfies the gate without re-probing
/// (honors the operator's "sau în ultimul minut a răspuns" rule).
pub const RECENCY_WINDOW: Duration = Duration::from_secs(60);

/// A device must be continuously SSH-reachable at least this long before AUTOMATIC
/// mitigations targeting it resume ("up for at least 5 minutes after being
/// reachable / after app restart").
pub const STABILITY_WINDOW: Duration = Duration::from_secs(300);

/// Persisted SSH reachability states (also the `devices.ssh_status` values).
pub const STATUS_REACHABLE: &str = "reachable";
pub const STATUS_NO_PRIVILEGE: &str = "no_privilege";
pub const STATUS_UNREACHABLE: &str = "unreachable";

static PROCESS_SUCCESSES: OnceLock<Mutex<HashMap<u64, Instant>>> = OnceLock::new();

fn recent_process_success(device_id: u64) -> bool {
    let map = PROCESS_SUCCESSES.get_or_init(|| Mutex::new(HashMap::new()));
    let guard = map.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    guard
        .get(&device_id)
        .is_some_and(|at| at.elapsed() < RECENCY_WINDOW)
}

fn set_process_success(device_id: u64, reachable: bool) {
    let map = PROCESS_SUCCESSES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = map.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if reachable {
        guard.insert(device_id, Instant::now());
    } else {
        guard.remove(&device_id);
    }
}

/// The reachability decision for a device.
#[derive(Debug, Clone, Serialize)]
pub struct Reachability {
    /// SSH is usable for a reroute (answered at privileged EXEC, or a real contact
    /// within `RECENCY_WINDOW`). THIS is what gates a reroute. `no_privilege` and
    /// `unreachable` are both `false`.
    pub ssh_ok: bool,
    /// The classified SSH state: `reachable` | `no_privilege` | `unreachable`.
    pub ssh_status: &'static str,
    /// Reachable AND continuously so for `STABILITY_WINDOW`. AUTOMATIC mitigations
    /// require this; manual reroutes do not (they only require `ssh_ok`).
    pub stable: bool,
    /// True when `ssh_ok` was satisfied by a recent contact rather than a fresh probe.
    pub via_recency: bool,
    /// When SSH last answered at privileged EXEC (the recency source), if known.
    pub last_ssh_ok_at: Option<DateTime<Utc>>,
    /// When SSH became (and has stayed) reachable — the stability clock.
    pub ssh_reachable_since: Option<DateTime<Utc>>,
    /// The probe's message when not reachable, for the UI/logs. Never secrets.
    pub ssh_error: Option<String>,
}

/// PURE stability test: is the device reachable AND has it been continuously so for
/// `STABILITY_WINDOW`? A NULL/future `ssh_reachable_since`, or a non-reachable
/// status, is NOT stable. Unit-tested.
pub fn device_stable(
    ssh_status: &str,
    ssh_reachable_since: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> bool {
    if ssh_status != STATUS_REACHABLE {
        return false;
    }
    match ssh_reachable_since {
        Some(t) => {
            let secs = now.signed_duration_since(t).num_seconds();
            secs >= 0 && (secs as u64) >= STABILITY_WINDOW.as_secs()
        }
        None => false,
    }
}

/// PURE recency test: is a last-known-good SSH contact still fresh enough to skip
/// the probe? A timestamp in the future (clock skew) or unknown is treated as not
/// recent, so we fall through to a live probe — the safe direction. Unit-tested.
pub fn recent_enough(last_ssh_ok_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    match last_ssh_ok_at {
        Some(t) => {
            let secs = now.signed_duration_since(t).num_seconds();
            secs >= 0 && (secs as u64) < RECENCY_WINDOW.as_secs()
        }
        None => false,
    }
}

/// Decide reachability for a mitigation on `device_id`. SSH is authoritative: pass
/// on a recent privileged contact, otherwise run a live liveness probe and record
/// the classified outcome.
pub async fn reachable_for_mitigation(pool: &MySqlPool, device_id: u64) -> Reachability {
    let (persisted_status, last_ssh_ok_at, since): (
        String,
        Option<DateTime<Utc>>,
        Option<DateTime<Utc>>,
    ) = sqlx::query_as(
        "SELECT ssh_status, last_ssh_ok_at, ssh_reachable_since FROM devices WHERE id = ?",
    )
    .bind(device_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .unwrap_or_else(|| (STATUS_UNREACHABLE.into(), None, None));

    let now = Utc::now();
    if persisted_status == STATUS_REACHABLE
        && recent_enough(last_ssh_ok_at, now)
        && recent_process_success(device_id)
    {
        return Reachability {
            ssh_ok: true,
            ssh_status: STATUS_REACHABLE,
            stable: device_stable(STATUS_REACHABLE, since, now),
            via_recency: true,
            last_ssh_ok_at,
            ssh_reachable_since: since,
            ssh_error: None,
        };
    }

    // Live SSH liveness probe (no commands), classified.
    match ssh::ssh_probe(pool, device_id).await {
        SshReach::Privileged => {
            if let Err(e) = stamp_ssh_status(pool, device_id, STATUS_REACHABLE, None).await {
                return Reachability {
                    ssh_ok: false,
                    ssh_status: STATUS_UNREACHABLE,
                    stable: false,
                    via_recency: false,
                    last_ssh_ok_at,
                    ssh_reachable_since: None,
                    ssh_error: Some(format!("could not persist SSH reachability: {e}")),
                };
            }
            // The stamp sets ssh_reachable_since only if it was NULL; a device that
            // was already reachable keeps its original since (so it can be stable).
            let since_after = since.or(Some(now));
            Reachability {
                ssh_ok: true,
                ssh_status: STATUS_REACHABLE,
                stable: device_stable(STATUS_REACHABLE, since_after, now),
                via_recency: false,
                last_ssh_ok_at: Some(now),
                ssh_reachable_since: since_after,
                ssh_error: None,
            }
        }
        // Both privilege problems (user-EXEC login, or '#' but a required command
        // denied) land here: SSH works, the account can't do the work → not mitigatable.
        SshReach::UserExec(msg) | SshReach::Restricted(msg) => {
            if let Err(e) = stamp_ssh_status(pool, device_id, STATUS_NO_PRIVILEGE, Some(&msg)).await
            {
                tracing::warn!(event_type = "ssh_negative_status_write_failed", device_id, status = STATUS_NO_PRIVILEGE, error = %e, "could not persist negative SSH reachability");
            }
            Reachability {
                ssh_ok: false,
                ssh_status: STATUS_NO_PRIVILEGE,
                stable: false,
                via_recency: false,
                last_ssh_ok_at,
                ssh_reachable_since: None,
                ssh_error: Some(msg),
            }
        }
        SshReach::Unreachable(msg) => {
            if let Err(e) = stamp_ssh_status(pool, device_id, STATUS_UNREACHABLE, Some(&msg)).await
            {
                tracing::warn!(event_type = "ssh_negative_status_write_failed", device_id, status = STATUS_UNREACHABLE, error = %e, "could not persist negative SSH reachability");
            }
            Reachability {
                ssh_ok: false,
                ssh_status: STATUS_UNREACHABLE,
                stable: false,
                via_recency: false,
                last_ssh_ok_at,
                ssh_reachable_since: None,
                ssh_error: Some(msg),
            }
        }
    }
}

/// Persist an SSH probe outcome on `device_id`. On `reachable`: stamps
/// `last_ssh_ok_at`, clears the error, and STARTS the stability clock
/// (`ssh_reachable_since = COALESCE(ssh_reachable_since, now)` — only if it was
/// NULL, so a device that stays reachable keeps its original since). Otherwise:
/// records `last_ssh_error` and CLEARS the stability clock (`ssh_reachable_since =
/// NULL`), leaving `last_ssh_ok_at` (which means "last time SSH answered"). Best-effort.
pub async fn stamp_ssh_status(
    pool: &MySqlPool,
    device_id: u64,
    status: &str,
    err: Option<&str>,
) -> anyhow::Result<()> {
    if status == STATUS_REACHABLE {
        sqlx::query(
            "UPDATE devices SET ssh_status = ?, last_ssh_error = NULL, last_ssh_ok_at = UTC_TIMESTAMP(), \
             ssh_reachable_since = COALESCE(ssh_reachable_since, UTC_TIMESTAMP()) WHERE id = ?",
        )
        .bind(status)
        .bind(device_id)
        .execute(pool)
        .await?;
        set_process_success(device_id, true);
    } else {
        // Clear the process-local fast path before attempting persistence. Even
        // if the DB write fails, a freshly observed negative result can never be
        // masked by the previous minute's successful contact.
        set_process_success(device_id, false);
        sqlx::query(
            "UPDATE devices SET ssh_status = ?, last_ssh_error = ?, ssh_reachable_since = NULL WHERE id = ?",
        )
        .bind(status)
        .bind(err)
        .bind(device_id)
        .execute(pool)
        .await?;
    }
    Ok(())
}

/// Reset every device's stability clock (`ssh_reachable_since = NULL`). Called once
/// on controller startup so a device must be freshly re-confirmed SSH-reachable for
/// `STABILITY_WINDOW` before AUTOMATIC mitigations resume after a restart.
pub async fn reset_stability(pool: &MySqlPool) -> anyhow::Result<()> {
    if let Some(cache) = PROCESS_SUCCESSES.get() {
        cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }
    sqlx::query("UPDATE devices SET ssh_reachable_since = NULL")
        .execute(pool)
        .await?;
    Ok(())
}

/// Record that SSH just answered at privileged EXEC on `device_id` (e.g. a
/// successful reroute push) — keeps the recency window warm and marks the device
/// reachable.
pub async fn stamp_ssh_ok(pool: &MySqlPool, device_id: u64) -> anyhow::Result<()> {
    stamp_ssh_status(pool, device_id, STATUS_REACHABLE, None).await
}

/// Periodic SSH reachability probe (the poll loop calls this every
/// `reachability_interval_seconds`). Runs the command-access checks
/// ([`ssh::probe_capabilities`], changing nothing), classifies the outcome, and
/// stores `ssh_status` (+ `last_ssh_ok_at` on `reachable`, `last_ssh_error` naming
/// any denied commands otherwise) so the UI shows a definite state and the reroute
/// gate's recency window is kept warm. Returns the resulting status for logging.
pub async fn probe_ssh_and_store(pool: &MySqlPool, device_id: u64) -> &'static str {
    let (status, err): (&'static str, Option<String>) = match ssh::ssh_probe(pool, device_id).await
    {
        SshReach::Privileged => (STATUS_REACHABLE, None),
        SshReach::UserExec(m) | SshReach::Restricted(m) => (STATUS_NO_PRIVILEGE, Some(m)),
        SshReach::Unreachable(m) => (STATUS_UNREACHABLE, Some(m)),
    };
    if let Err(e) = stamp_ssh_status(pool, device_id, status, err.as_deref()).await {
        tracing::error!(event_type = "ssh_status_persist_failed", device_id, error = %e, "could not persist SSH probe outcome");
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;

    #[test]
    fn recency_window_gates_probe_skip() {
        let now = Utc::now();
        // A contact 30s ago is recent enough to skip the probe.
        assert!(recent_enough(Some(now - ChronoDuration::seconds(30)), now));
        // Exactly at / past the 60s window is NOT recent (re-probe).
        assert!(!recent_enough(Some(now - ChronoDuration::seconds(60)), now));
        assert!(!recent_enough(
            Some(now - ChronoDuration::seconds(120)),
            now
        ));
        // Never-contacted -> not recent.
        assert!(!recent_enough(None, now));
        // Future timestamp (clock skew) -> treated as not recent (safe: re-probe).
        assert!(!recent_enough(Some(now + ChronoDuration::seconds(10)), now));
    }

    #[test]
    fn stability_requires_reachable_for_the_full_window() {
        let now = Utc::now();
        // Reachable for 5 min+ -> stable (auto mitigations resume).
        assert!(device_stable(
            STATUS_REACHABLE,
            Some(now - ChronoDuration::seconds(300)),
            now
        ));
        assert!(device_stable(
            STATUS_REACHABLE,
            Some(now - ChronoDuration::seconds(600)),
            now
        ));
        // Reachable but only just (<5 min) -> NOT stable (auto held).
        assert!(!device_stable(
            STATUS_REACHABLE,
            Some(now - ChronoDuration::seconds(299)),
            now
        ));
        assert!(!device_stable(STATUS_REACHABLE, Some(now), now));
        // Reachable but no clock (shouldn't happen) -> not stable.
        assert!(!device_stable(STATUS_REACHABLE, None, now));
        // Not reachable -> never stable, regardless of the clock.
        assert!(!device_stable(
            STATUS_NO_PRIVILEGE,
            Some(now - ChronoDuration::seconds(3600)),
            now
        ));
        assert!(!device_stable(
            STATUS_UNREACHABLE,
            Some(now - ChronoDuration::seconds(3600)),
            now
        ));
    }
}
