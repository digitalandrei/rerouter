//! Rerouter controller library crate.
//!
//! The binary (`src/main.rs`) is a thin entrypoint over this library so the
//! modules are also reachable from integration tests under `tests/` (rate-math
//! and crypto round-trip tests need the telemetry + crypto modules without a
//! live device or database).
//!
//! See ../docs/architecture.md for the system overview.

pub mod config;
pub mod crypto;
pub mod db;
pub mod auth;
pub mod alerts;
pub mod telemetry;
pub mod detection;
pub mod reroute;
pub mod providers;
pub mod api;
pub mod scheduler;
pub mod install;
#[cfg(feature = "embed-ui")]
pub mod ui;
