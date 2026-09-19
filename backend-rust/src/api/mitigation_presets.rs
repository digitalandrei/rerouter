//! Shared, named mitigation definitions. Saving never arms or executes a rule.
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{MySqlConnection, MySqlPool};

use super::{audit_mutation_on, err, AppState};
use crate::auth::rbac::{markers, RequirePermission};
use crate::reroute::preparation::{validate_drafts, ActionDraft};

type JsonResp = (StatusCode, Json<Value>);

#[derive(sqlx::FromRow)]
struct PresetRow {
    id: u64,
    name: String,
    description: Option<String>,
    revision: u64,
    archived_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct PresetActionRow {
    id: u64,
    reroute_template_id: u64,
    device_id: u64,
    params_json: sqlx::types::Json<Value>,
    enabled: bool,
    position: u32,
    template_name: String,
    template_display_name: Option<String>,
    device_name: String,
}

pub(crate) async fn load_actions(pool: &MySqlPool, id: u64) -> anyhow::Result<Vec<ActionDraft>> {
    Ok(
        sqlx::query_as::<_, (u64, u64, u64, sqlx::types::Json<Value>, bool)>(
            "SELECT id, reroute_template_id, device_id, params_json, enabled \
         FROM mitigation_preset_actions WHERE preset_id = ? ORDER BY position, id",
        )
        .bind(id)
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(
            |(id, reroute_template_id, device_id, params, enabled)| ActionDraft {
                id: Some(id),
                reroute_template_id,
                device_id,
                params: params.0,
                enabled,
                auto_target: None,
            },
        )
        .collect(),
    )
}

pub(crate) async fn fetch(
    pool: &MySqlPool,
    id: u64,
    _detailed: bool,
) -> anyhow::Result<Option<Value>> {
    let row = sqlx::query_as::<_, PresetRow>(
        "SELECT id, name, description, revision, archived_at, created_at, updated_at \
         FROM mitigation_presets WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let actions = sqlx::query_as::<_, PresetActionRow>(
        "SELECT a.id, a.reroute_template_id, a.device_id, a.params_json, a.enabled, a.position, \
                t.name AS template_name, t.display_name AS template_display_name, d.name AS device_name \
         FROM mitigation_preset_actions a JOIN reroute_templates t ON t.id = a.reroute_template_id \
         JOIN devices d ON d.id = a.device_id WHERE a.preset_id = ? ORDER BY a.position, a.id",
    ).bind(id).fetch_all(pool).await?;
    let drafts: Vec<ActionDraft> = actions
        .iter()
        .map(|a| ActionDraft {
            id: Some(a.id),
            reroute_template_id: a.reroute_template_id,
            device_id: a.device_id,
            params: a.params_json.0.clone(),
            enabled: a.enabled,
            auto_target: None,
        })
        .collect();
    let (definition_status, validation_error) = if drafts.is_empty() {
        ("draft", None)
    } else if row.archived_at.is_none() {
        match validate_drafts(pool, &drafts, false).await {
            Ok(_) => ("ready", None),
            Err(e) => ("needs_setup", Some(format!("{e:#}"))),
        }
    } else {
        ("needs_setup", None)
    };
    let recent_runs = super::run_summaries::recent_for_preset(pool, id, 5).await?;
    let active_runs = super::run_summaries::active_for_preset(pool, id).await?;
    Ok(Some(json!({
        "id": row.id, "name": row.name, "description": row.description,
        "revision": row.revision, "archived_at": row.archived_at,
        "created_at": row.created_at, "updated_at": row.updated_at,
        "definition_status": definition_status,
        "validation_status": definition_status, "validation_error": validation_error,
        "actions": actions.into_iter().map(|a| json!({
            "id": a.id, "reroute_template_id": a.reroute_template_id,
            "template_name": a.template_name, "template_display_name": a.template_display_name,
            "device_id": a.device_id, "device_name": a.device_name,
            "params": a.params_json.0, "enabled": a.enabled, "position": a.position,
            "auto_target": null,
        })).collect::<Vec<_>>(),
        // Keep bundle_id for old clients; every other field is the same shared
        // logical-run summary returned by /api/reroute-bundles.
        "recent_runs": recent_runs.into_iter().map(|mut run| {
            run["bundle_id"] = run["id"].clone();
            run
        }).collect::<Vec<_>>(),
        "active_runs": active_runs.into_iter().map(|mut run| {
            run["bundle_id"] = run["id"].clone();
            run
        }).collect::<Vec<_>>(),
    })))
}

/// Read-only operator diagnostic using the same readiness computation as the API.
pub async fn readiness(pool: &MySqlPool, id: u64) -> anyhow::Result<Option<Value>> {
    Ok(fetch(pool, id, true).await?.map(|value| {
        json!({
            "id": value["id"],
            "name": value["name"],
            "status": value["definition_status"],
            "validation_error": value["validation_error"],
        })
    }))
}

#[derive(Default, Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    include_archived: bool,
}

pub async fn list(
    _g: RequirePermission<markers::ViewAsset>,
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> JsonResp {
    let ids = sqlx::query_scalar::<_, u64>(
        "SELECT id FROM mitigation_presets WHERE (? = 1 OR archived_at IS NULL) ORDER BY name, id LIMIT 500",
    ).bind(query.include_archived).fetch_all(&state.pool).await;
    let Ok(ids) = ids else {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error");
    };
    let mut rows = Vec::with_capacity(ids.len());
    for id in ids {
        match fetch(&state.pool, id, false).await {
            Ok(Some(row)) => rows.push(row),
            Ok(None) => {}
            Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
        }
    }
    (StatusCode::OK, Json(json!(rows)))
}

pub async fn show(
    _g: RequirePermission<markers::ViewAsset>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> JsonResp {
    match fetch(&state.pool, id, true).await {
        Ok(Some(row)) => (StatusCode::OK, Json(row)),
        Ok(None) => err(StatusCode::NOT_FOUND, "mitigation template not found"),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SaveBody {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    revision: Option<u64>,
    actions: Vec<ActionDraft>,
}

fn validate_name(body: &SaveBody) -> Result<(), &'static str> {
    if body.name.trim().is_empty() || body.name.trim().chars().count() > 191 {
        return Err("name must contain 1–191 characters");
    }
    if body
        .description
        .as_ref()
        .is_some_and(|v| v.chars().count() > 4000)
    {
        return Err("description must not exceed 4000 characters");
    }
    Ok(())
}

async fn write_actions(
    conn: &mut MySqlConnection,
    id: u64,
    actions: &[ActionDraft],
) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM mitigation_preset_actions WHERE preset_id = ?")
        .bind(id)
        .execute(&mut *conn)
        .await?;
    for (position, a) in actions.iter().enumerate() {
        sqlx::query("INSERT INTO mitigation_preset_actions \
            (preset_id, reroute_template_id, device_id, params_json, enabled, position) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(id).bind(a.reroute_template_id).bind(a.device_id).bind(sqlx::types::Json(&a.params))
            .bind(a.enabled).bind(position as u32).execute(&mut *conn).await?;
    }
    Ok(())
}

pub async fn create(
    g: RequirePermission<markers::EditRules>,
    State(state): State<AppState>,
    Json(body): Json<SaveBody>,
) -> JsonResp {
    save(&state, &g.session, None, body).await
}

pub async fn update(
    g: RequirePermission<markers::EditRules>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
    Json(body): Json<SaveBody>,
) -> JsonResp {
    save(&state, &g.session, Some(id), body).await
}

async fn save(
    state: &AppState,
    session: &crate::auth::sessions::Session,
    id: Option<u64>,
    body: SaveBody,
) -> JsonResp {
    if let Err(message) = validate_name(&body) {
        return err(StatusCode::UNPROCESSABLE_ENTITY, message);
    }
    if body.actions.len() > 256 {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "a mitigation may contain at most 256 actions",
        );
    }
    // A saved definition is allowed to be an incomplete draft. Its identities
    // must still be real foreign keys; full parameter, policy, order and
    // inventory validation happens when reporting readiness and again before
    // every run. Never discard an invalid sibling while saving.
    for (position, action) in body.actions.iter().enumerate() {
        let template: Option<u64> =
            match sqlx::query_scalar("SELECT id FROM reroute_templates WHERE id = ?")
                .bind(action.reroute_template_id)
                .fetch_optional(&state.pool)
                .await
            {
                Ok(value) => value,
                Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
            };
        let device: Option<u64> = match sqlx::query_scalar("SELECT id FROM devices WHERE id = ?")
            .bind(action.device_id)
            .fetch_optional(&state.pool)
            .await
        {
            Ok(value) => value,
            Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
        };
        if template.is_none() || device.is_none() {
            return err(
                StatusCode::UNPROCESSABLE_ENTITY,
                &format!(
                    "action {} references an unavailable template or router",
                    position + 1
                ),
            );
        }
    }
    let actions = body.actions;
    let Ok(mut tx) = state.pool.begin().await else {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error");
    };
    let updating = id.is_some();
    let saved_id = if let Some(id) = id {
        let row = sqlx::query_as::<_, (u64, Option<DateTime<Utc>>)>(
            "SELECT revision, archived_at FROM mitigation_presets WHERE id = ? FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await;
        match row {
            Ok(Some((revision, None))) if Some(revision) == body.revision => {}
            Ok(Some(_)) => {
                return err(
                    StatusCode::CONFLICT,
                    "template_changed_or_archived; reload before saving",
                )
            }
            Ok(None) => return err(StatusCode::NOT_FOUND, "mitigation template not found"),
            Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
        }
        let result = sqlx::query("UPDATE mitigation_presets SET name = ?, description = ?, revision = revision + 1, updated_by = ? WHERE id = ?")
            .bind(body.name.trim()).bind(body.description.as_deref().map(str::trim)).bind(session.user_id).bind(id).execute(&mut *tx).await;
        if let Err(e) = result {
            return write_error(e);
        }
        id
    } else {
        match sqlx::query("INSERT INTO mitigation_presets (name, description, created_by, updated_by) VALUES (?, ?, ?, ?)")
            .bind(body.name.trim()).bind(body.description.as_deref().map(str::trim)).bind(session.user_id).bind(session.user_id).execute(&mut *tx).await {
            Ok(result) => result.last_insert_id(), Err(e) => return write_error(e),
        }
    };
    if write_actions(&mut tx, saved_id, &actions).await.is_err()
        || audit_mutation_on(
            &mut tx,
            session,
            if updating {
                "mitigation_preset_updated"
            } else {
                "mitigation_preset_created"
            },
            "mitigation_preset",
            saved_id,
            &format!(
                "saved '{}' with {} ordered actions",
                body.name.trim(),
                actions.len()
            ),
        )
        .await
        .is_err()
    {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "save_failed; no changes were committed",
        );
    }
    if tx.commit().await.is_err() {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "save_commit_unknown; reload before retrying",
        );
    }
    match fetch(&state.pool, saved_id, false).await {
        Ok(Some(row)) => (
            if updating {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            },
            Json(row),
        ),
        _ => err(StatusCode::INTERNAL_SERVER_ERROR, "saved_but_reload_failed"),
    }
}

fn write_error(e: sqlx::Error) -> JsonResp {
    if e.as_database_error()
        .is_some_and(|e| e.is_unique_violation())
    {
        err(
            StatusCode::CONFLICT,
            "a mitigation template with that name already exists",
        )
    } else {
        err(StatusCode::INTERNAL_SERVER_ERROR, "db_error")
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveBody {
    revision: u64,
}

pub async fn archive(
    g: RequirePermission<markers::EditRules>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
    Json(body): Json<ArchiveBody>,
) -> JsonResp {
    let Ok(mut tx) = state.pool.begin().await else {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error");
    };
    let result = sqlx::query("UPDATE mitigation_presets SET archived_at = UTC_TIMESTAMP(), revision = revision + 1, updated_by = ? WHERE id = ? AND revision = ? AND archived_at IS NULL")
        .bind(g.session.user_id).bind(id).bind(body.revision).execute(&mut *tx).await;
    match result {
        Ok(r) if r.rows_affected() == 1 => {}
        Ok(_) => {
            return err(
                StatusCode::CONFLICT,
                "template_changed_or_archived; reload before archiving",
            )
        }
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
    if audit_mutation_on(
        &mut tx,
        &g.session,
        "mitigation_preset_archived",
        "mitigation_preset",
        id,
        "archived saved mitigation; copied rules and execution history are preserved",
    )
    .await
    .is_err()
        || tx.commit().await.is_err()
    {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "archive_failed; reload to reconcile",
        );
    }
    (StatusCode::OK, Json(json!({"ok":true,"archived":true})))
}
