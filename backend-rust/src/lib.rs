//! Rerouter controller library crate.
//!
//! The binary (`src/main.rs`) is a thin entrypoint over this library so the
//! modules are also reachable from integration tests under `tests/` (rate-math
//! and crypto round-trip tests need the telemetry + crypto modules without a
//! live device or database).
//!
//! See ../docs/architecture.md for the system overview.

pub mod alerts;
pub mod api;
pub mod auth;
pub mod config;
pub mod crypto;
pub mod db;
pub mod detection;
pub mod install;
pub mod reroute;
pub mod scheduler;
pub mod ssh;
pub mod telemetry;
#[cfg(feature = "embed-ui")]
pub mod ui;
