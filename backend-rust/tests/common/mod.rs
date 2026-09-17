//! Shared fail-loud database harness for integration tests.

/// Connect to the explicitly configured disposable schema. This deliberately
/// panics rather than skipping: `cargo test --all-targets` must never report
/// green while DB-backed safety coverage did not run.
pub async fn test_database() -> rerouter_controller::db::TestDatabase {
    rerouter_controller::db::connect_test_database().await
}
