//! Route-shape smoke test.
//!
//! The real router is built inside `api::serve`, which also binds a listener, so
//! it cannot be constructed in a unit test. But the failure mode worth guarding
//! is cheap to reproduce: `matchit` PANICS at router construction when two routes
//! put differently-named parameters in the same position, and that panic would
//! take the controller down at startup rather than at compile time.
//!
//! These are the `/api/rules/...` shapes the real router registers, including the
//! reorder route added for ordered mitigation bundles (plan 015), where a literal
//! segment (`reorder`) shares a position with a parameter (`{action_id}`).

use axum::routing::{delete, get, post};
use axum::Router;

async fn noop() -> &'static str {
    "ok"
}

#[test]
fn rules_route_shapes_do_not_conflict() {
    // Panics on conflict; reaching the assertion is the test.
    let app: Router = Router::new()
        .route("/api/rules", get(noop).post(noop))
        .route("/api/rules/{id}", get(noop).put(noop).delete(noop))
        .route("/api/rules/{id}/clear", post(noop))
        .route("/api/rules/{id}/apply", post(noop))
        .route("/api/rules/{id}/actions", post(noop))
        .route("/api/rules/{rule_id}/actions/{action_id}", delete(noop))
        .route("/api/rules/{rule_id}/actions/reorder", post(noop))
        .route("/api/reroute-bundles/{id}", get(noop));

    // Use the value so the builder is not optimized away.
    let _ = app.into_make_service();
}
