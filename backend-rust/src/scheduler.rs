//! Per-asset async scheduler + shared collectors. Avoids one giant loop; uses
//! jitter to de-synchronize polling across assets. See ../docs/architecture.md.

use anyhow::Result;
use sqlx::MySqlPool;

use crate::config::Config;

pub async fn run(_pool: MySqlPool, _cfg: Config) -> Result<()> {
    // TODO(milestone 1):
    //   - spawn shared flow collector + BGP feed + Cloudflare poller
    //   - spawn one task per enabled asset:
    //       reachability -> normalize metrics -> evaluate rules ->
    //       (gated) reroute scheduling
    //   - apply jitter_percent to each interval
    tracing::info!(event_type = "scheduler_started", "scheduler spawned (skeleton)");
    Ok(())
}
