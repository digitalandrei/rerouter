//! Reroute endpoints: GET /api/reroutes, POST /api/reroutes/manual,
//! /api/reroutes/{id}/cancel, /api/reroutes/{id}/acknowledge-uncertain.
//!
//! Authorization is enforced HERE (session + RBAC + re-auth), not by a web
//! tier — this process is the security boundary. Manual triggers re-check all
//! safety gates and require trigger_manual_reroute plus a reason; high-safety
//! templates additionally require a FRESH password+TOTP re-auth
//! (POST /api/auth/reauth, rbac::reauth_is_fresh) and a typed confirmation of
//! the exact target. The SPA renders the exact reroute preview returned by the
//! plan step. TODO(milestone 3).

use axum::http::StatusCode;
use axum::Json;
use serde_json::Value;

use super::not_implemented;

pub async fn list() -> (StatusCode, Json<Value>) {
    not_implemented()
}

/// POST /api/reroutes/manual — plan + execute a template-based reroute.
/// Gates re-checked at execution time regardless of what the UI showed.
pub async fn manual() -> (StatusCode, Json<Value>) {
    // TODO(milestone 3): Session extractor + rbac::has_permission(
    // TriggerManualReroute) + (high safety) rbac::reauth_is_fresh + typed
    // confirmation + reason -> executor::evaluate_gates -> execute.
    not_implemented()
}

/// POST /api/reroutes/{id}/cancel — cancel a planned/pending reroute.
pub async fn cancel() -> (StatusCode, Json<Value>) {
    not_implemented()
}

/// POST /api/reroutes/{id}/acknowledge-uncertain — admin/operator resolves an
/// `uncertain` reroute (acknowledge_uncertain_reroute) and clears the safety
/// lock created on crash/ambiguity. Always audited.
pub async fn acknowledge_uncertain() -> (StatusCode, Json<Value>) {
    not_implemented()
}
