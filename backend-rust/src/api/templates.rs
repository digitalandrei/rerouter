//! Reroute template catalog (read-only) + parameter render/preview.
//!
//! Templates are the allowlisted, parameterized mitigations — the only thing a
//! reroute can run (see ../reroute/templates.rs). These endpoints let the SPA
//! list templates, inspect a template's schema, and render exact commands for a
//! given parameter set WITHOUT executing anything (the preview the operator
//! confirms before a manual reroute). Reads require `view_asset`.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{err, AppState};
use crate::auth::rbac::{markers, RequirePermission};
use crate::reroute::templates;

type JsonResp = (StatusCode, Json<Value>);

fn template_json(t: &templates::Template) -> Value {
    json!({
        "id": t.id,
        "name": t.name,
        "description": t.description,
        "provider_type": t.provider_type,
        "mode": t.mode,
        "manual_confirmation_required": t.manual_confirmation_required,
        "automatic_allowed": t.automatic_allowed,
        "parameter_schema": t.parameter_schema,
        "plan": t.plan,
        "verification": t.verification,
        "rollback_template_id": t.rollback_template_id,
        "auto_expiry_seconds": t.auto_expiry_seconds,
        "enabled": t.enabled,
    })
}

/// GET /api/templates — the full template catalog.
pub async fn list(_g: RequirePermission<markers::ViewAsset>, State(state): State<AppState>) -> JsonResp {
    match templates::load_all(&state.pool).await {
        Ok(ts) => {
            let out: Vec<Value> = ts.iter().map(template_json).collect();
            (StatusCode::OK, Json(json!(out)))
        }
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

/// GET /api/templates/{id}.
pub async fn show(
    _g: RequirePermission<markers::ViewAsset>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> JsonResp {
    match templates::load(&state.pool, id).await {
        Ok(t) => (StatusCode::OK, Json(template_json(&t))),
        Err(_) => err(StatusCode::NOT_FOUND, "template not found"),
    }
}

#[derive(Debug, Deserialize)]
pub struct RenderBody {
    #[serde(default)]
    params: Value,
}

/// POST /api/templates/{id}/render — render the exact commands for the given
/// parameters. PURE PREVIEW: nothing is executed and no SSH session opens. A
/// validation error is a clean 200 `{ok:false,error}` so the SPA can show it.
pub async fn render(
    _g: RequirePermission<markers::ViewAsset>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
    Json(body): Json<RenderBody>,
) -> JsonResp {
    let t = match templates::load(&state.pool, id).await {
        Ok(t) => t,
        Err(_) => return err(StatusCode::NOT_FOUND, "template not found"),
    };
    match templates::render(&t, &body.params) {
        Ok(plan) => (StatusCode::OK, Json(json!({ "ok": true, "plan": plan }))),
        Err(e) => (StatusCode::OK, Json(json!({ "ok": false, "error": e.to_string() }))),
    }
}
