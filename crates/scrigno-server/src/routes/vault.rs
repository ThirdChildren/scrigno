//! `/v1/vault` and `/v1/vault/keyslots/*` — §3.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use sqlx::types::chrono::Utc;
use uuid::Uuid;

use crate::AppState;
use crate::error::ApiError;
use crate::json_extractor::Json as BoundedJson;
use crate::models::{CreateVaultRequest, Keyslot, NewKeyslot, Vault};

/// `GET /v1/vault` -> `200 Vault` / `404 vault_not_initialised`.
pub async fn get_vault(State(state): State<AppState>) -> Result<Response, ApiError> {
    let Some(vault_row) = sqlx::query!("SELECT id, created_at FROM vault LIMIT 1")
        .fetch_optional(&state.db)
        .await?
    else {
        return Err(ApiError::VaultNotInitialised);
    };

    let keyslots = sqlx::query_as!(
        Keyslot,
        r#"SELECT id, kind, kdf, wrapped_mk, created_at FROM keyslot
           WHERE vault_id = $1 ORDER BY created_at ASC"#,
        vault_row.id
    )
    .fetch_all(&state.db)
    .await?;

    let vault = Vault {
        id: vault_row.id,
        created_at: vault_row.created_at,
        keyslots,
    };
    Ok((StatusCode::OK, Json(vault)).into_response())
}

/// `POST /v1/vault` -> `201 Vault` / `409 vault_exists`. First device only.
pub async fn create_vault(
    State(state): State<AppState>,
    BoundedJson(body): BoundedJson<CreateVaultRequest>,
) -> Result<Response, ApiError> {
    body.keyslot.validate()?;

    let mut tx = state.db.begin().await?;

    let existing = sqlx::query!("SELECT id FROM vault LIMIT 1")
        .fetch_optional(&mut *tx)
        .await?;
    if existing.is_some() {
        return Err(ApiError::VaultExists);
    }

    let created_at = Utc::now();
    sqlx::query!(
        "INSERT INTO vault (id, created_at) VALUES ($1, $2)",
        body.id,
        created_at
    )
    .execute(&mut *tx)
    .await?;

    let keyslot_created_at = Utc::now();
    sqlx::query!(
        r#"INSERT INTO keyslot (id, vault_id, kind, kdf, wrapped_mk, created_at)
           VALUES ($1, $2, $3, $4, $5, $6)"#,
        body.keyslot.id,
        body.id,
        body.keyslot.kind,
        body.keyslot.kdf,
        body.keyslot.wrapped_mk,
        keyslot_created_at
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    let vault = Vault {
        id: body.id,
        created_at,
        keyslots: vec![Keyslot {
            id: body.keyslot.id,
            kind: body.keyslot.kind,
            kdf: body.keyslot.kdf,
            wrapped_mk: body.keyslot.wrapped_mk,
            created_at: keyslot_created_at,
        }],
    };
    Ok((StatusCode::CREATED, Json(vault)).into_response())
}

/// `POST /v1/vault/keyslots` -> `201 Keyslot`.
pub async fn add_keyslot(
    State(state): State<AppState>,
    BoundedJson(body): BoundedJson<NewKeyslot>,
) -> Result<Response, ApiError> {
    body.validate()?;

    let Some(vault_row) = sqlx::query!("SELECT id FROM vault LIMIT 1")
        .fetch_optional(&state.db)
        .await?
    else {
        return Err(ApiError::VaultNotInitialised);
    };

    let created_at = Utc::now();
    sqlx::query!(
        r#"INSERT INTO keyslot (id, vault_id, kind, kdf, wrapped_mk, created_at)
           VALUES ($1, $2, $3, $4, $5, $6)"#,
        body.id,
        vault_row.id,
        body.kind,
        body.kdf,
        body.wrapped_mk,
        created_at
    )
    .execute(&state.db)
    .await?;

    let keyslot = Keyslot {
        id: body.id,
        kind: body.kind,
        kdf: body.kdf,
        wrapped_mk: body.wrapped_mk,
        created_at,
    };
    Ok((StatusCode::CREATED, Json(keyslot)).into_response())
}

/// `DELETE /v1/vault/keyslots/{id}` -> `204` / `409 last_keyslot`. Never deletes the last slot.
pub async fn delete_keyslot(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let Some(vault_row) = sqlx::query!("SELECT id FROM vault LIMIT 1")
        .fetch_optional(&state.db)
        .await?
    else {
        return Err(ApiError::VaultNotInitialised);
    };

    let mut tx = state.db.begin().await?;

    let count = sqlx::query_scalar!(
        "SELECT count(*) FROM keyslot WHERE vault_id = $1",
        vault_row.id
    )
    .fetch_one(&mut *tx)
    .await?
    .unwrap_or(0);

    if count <= 1 {
        return Err(ApiError::LastKeyslot);
    }

    let result = sqlx::query!(
        "DELETE FROM keyslot WHERE id = $1 AND vault_id = $2",
        id,
        vault_row.id
    )
    .execute(&mut *tx)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }

    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}
