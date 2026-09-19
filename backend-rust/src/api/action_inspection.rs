//! Authority-free, read-only whole-set preparation and inspection.

use super::{err, AppState};
use crate::auth::rbac::{markers, RequirePermission};
use crate::reroute::{device_plan::PrepareInput, preparation::ActionDraft};
use axum::{extract::State, http::StatusCode, Json};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InspectRequest {
    pub actions: Vec<ActionDraft>,
}

pub async fn inspect(
    _g: RequirePermission<markers::ViewAsset>,
    State(state): State<AppState>,
    Json(body): Json<InspectRequest>,
) -> (StatusCode, Json<Value>) {
    if body.actions.is_empty() || body.actions.len() > 256 {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "an action set must contain 1..=256 actions",
        );
    }
    let mut inputs = Vec::new();
    for (index, draft) in body.actions.iter().enumerate().filter(|(_, a)| a.enabled) {
        if draft.auto_target.is_some() {
            return err(
                StatusCode::UNPROCESSABLE_ENTITY,
                &format!("action {} requires a concrete manual target", index + 1),
            );
        }
        let template =
            match crate::reroute::templates::load(&state.pool, draft.reroute_template_id).await {
                Ok(v) => v,
                Err(e) => {
                    return err(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        &format!("action {}: {e}", index + 1),
                    )
                }
            };
        let params = match crate::reroute::templates::canonicalize_inventory_params(
            &state.pool,
            draft.device_id,
            &template,
            &draft.params,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                return err(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    &format!("action {}: {e}", index + 1),
                )
            }
        };
        inputs.push(PrepareInput {
            device_id: draft.device_id,
            template_id: template.id,
            template_name: template.name,
            canonical_params: params,
        });
    }
    let prepared =
        match crate::reroute::device_plan::prepare_actions_read_only(&state.pool, &inputs).await {
            Ok(v) => v,
            Err(e) => return err(StatusCode::CONFLICT, &e.to_string()),
        };
    let devices = match crate::reroute::projection::project_action_set(&prepared) {
        Ok(value) => value,
        Err(error) => return err(StatusCode::CONFLICT, &error.to_string()),
    };
    (
        StatusCode::OK,
        Json(json!({"devices":devices,"blockers":[],"prepared_actions":prepared})),
    )
}
