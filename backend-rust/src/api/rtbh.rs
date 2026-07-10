//! Global RTBH community catalog. Each entry is a blackhole community (standard
//! `X:Y` or large `X:Y:Z`) plus the route tag the routers' RTBH redistribute
//! route-map matches to set it. The blackhole templates pick from this list.
//! Reads require `view_asset`; writes require `manage_devices` (infra config).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{err, AppState};
use crate::auth::rbac::{markers, RequirePermission};

type JsonResp = (StatusCode, Json<Value>);

/// Build the catalog response (ordered by tag). Guard-free so handlers can reuse it.
async fn fetch_list(pool: &sqlx::MySqlPool) -> JsonResp {
    let rows = sqlx::query_as::<_, (u64, String, String, String, u32)>(
        "SELECT id, label, kind, community, tag FROM rtbh_communities ORDER BY tag",
    )
    .fetch_all(pool)
    .await;
    match rows {
        Ok(rows) => {
            let out: Vec<Value> = rows
                .into_iter()
                .map(|(id, label, kind, community, tag)| {
                    json!({ "id": id, "label": label, "kind": kind, "community": community, "tag": tag })
                })
                .collect();
            (StatusCode::OK, Json(json!(out)))
        }
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

/// GET /api/rtbh-communities — the global list.
pub async fn list(
    _g: RequirePermission<markers::ViewAsset>,
    State(state): State<AppState>,
) -> JsonResp {
    fetch_list(&state.pool).await
}

#[derive(Debug, Deserialize)]
pub struct RtbhBody {
    label: String,
    #[serde(default)]
    kind: Option<String>,
    community: String,
    tag: u32,
}

/// Validate a community string as standard (`A:B`) or large (`A:B:C`), all
/// numeric. Returns the inferred kind.
fn validate_community(community: &str, kind: Option<&str>) -> Result<&'static str, &'static str> {
    let parts: Vec<&str> = community.split(':').collect();
    let all_numeric = parts
        .iter()
        .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
    if !all_numeric {
        return Err("community must be numeric, like 65000:666 or 65000:0:666");
    }
    let inferred = match parts.len() {
        2 => "standard",
        3 => "large",
        _ => return Err("community must be standard (A:B) or large (A:B:C)"),
    };
    if let Some(k) = kind {
        if !k.is_empty() && k != inferred {
            return Err("kind does not match the community format");
        }
    }
    Ok(inferred)
}

/// POST /api/rtbh-communities — add a community. `manage_devices` only.
pub async fn create(
    g: RequirePermission<markers::ManageDevices>,
    State(state): State<AppState>,
    Json(body): Json<RtbhBody>,
) -> JsonResp {
    if body.label.trim().is_empty() {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "label is required");
    }
    if body.tag == 0 {
        return err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "tag must be a non-zero route tag",
        );
    }
    let kind = match validate_community(body.community.trim(), body.kind.as_deref()) {
        Ok(k) => k,
        Err(m) => return err(StatusCode::UNPROCESSABLE_ENTITY, m),
    };

    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    let res = sqlx::query(
        "INSERT INTO rtbh_communities (label, kind, community, tag, created_by) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(body.label.trim())
    .bind(kind)
    .bind(body.community.trim())
    .bind(body.tag)
    .bind(g.session.user_id)
    .execute(&mut *tx)
    .await;
    match res {
        Ok(r) => {
            let id = r.last_insert_id();
            if super::audit_mutation_on(
                &mut tx,
                &g.session,
                "rtbh_community_created",
                "rtbh_community",
                id,
                "RTBH community added",
            )
            .await
            .is_err()
                || tx.commit().await.is_err()
            {
                return err(StatusCode::INTERNAL_SERVER_ERROR, "audit_write_failed");
            }
            fetch_list(&state.pool).await
        }
        Err(e) if matches!(&e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23000")) => {
            err(StatusCode::CONFLICT, "that route tag is already in use")
        }
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

/// DELETE /api/rtbh-communities/{id}. `manage_devices` only.
pub async fn remove(
    g: RequirePermission<markers::ManageDevices>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> JsonResp {
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    match sqlx::query("DELETE FROM rtbh_communities WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await
    {
        Ok(r) if r.rows_affected() > 0 => {
            if super::audit_mutation_on(
                &mut tx,
                &g.session,
                "rtbh_community_deleted",
                "rtbh_community",
                id,
                "RTBH community deleted",
            )
            .await
            .is_err()
                || tx.commit().await.is_err()
            {
                return err(StatusCode::INTERNAL_SERVER_ERROR, "audit_write_failed");
            }
            (StatusCode::OK, Json(json!({ "ok": true })))
        }
        Ok(_) => err(StatusCode::NOT_FOUND, "not found"),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}
