//! `/v1/docs/{id}` — §3.
//!
//! Optimistic concurrency is enforced with a single atomic, conditional `UPDATE ... WHERE
//! version = $if_match` (or `INSERT ... ON CONFLICT DO NOTHING` for the create case) rather than
//! "read version, compare in Rust, then write": the latter has a read-modify-write race between
//! two concurrent `PUT`s on the same document that a transaction alone doesn't close under
//! Postgres's default `READ COMMITTED` isolation. The conditional statement lets Postgres's own
//! row-level locking make the check-and-write atomic.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use sqlx::types::chrono::Utc;
use uuid::Uuid;

use crate::AppState;
use crate::error::ApiError;
use crate::json_extractor::Json as BoundedJson;
use crate::models::{DocumentRecord, PutDocRequest};

/// `GET /v1/docs/{id}` -> `200 DocumentRecord` / `404`.
pub async fn get_doc(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let record = fetch(&state, id).await?.ok_or(ApiError::NotFound)?;
    Ok((StatusCode::OK, Json(record)).into_response())
}

/// `PUT /v1/docs/{id}` — header `If-Match: <version>` (`0` = create).
///
/// `201`/`200 DocumentRecord`; `412 version_mismatch` with the current record in the body when
/// the document exists but `If-Match` is stale; `404 blob_not_found` if `blob_id` doesn't point
/// at an already-uploaded blob.
pub async fn put_doc(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    BoundedJson(body): BoundedJson<PutDocRequest>,
) -> Result<Response, ApiError> {
    let if_match = require_if_match(&headers)?;

    let Some(vault_row) = sqlx::query!("SELECT id FROM vault LIMIT 1")
        .fetch_optional(&state.db)
        .await?
    else {
        return Err(ApiError::VaultNotInitialised);
    };

    let mut tx = state.db.begin().await?;

    let blob_exists = sqlx::query!(
        "SELECT id FROM blob WHERE id = $1 AND vault_id = $2",
        body.blob_id,
        vault_row.id
    )
    .fetch_optional(&mut *tx)
    .await?
    .is_some();
    if !blob_exists {
        return Err(ApiError::BlobNotFound);
    }

    let updated_at = Utc::now();

    if if_match == 0 {
        let inserted = sqlx::query_as!(
            DocumentRecord,
            r#"
            INSERT INTO document (id, vault_id, version, blob_id, blob_size, enc_meta, deleted, server_seq, updated_at)
            VALUES ($1, $2, 1, $3, $4, $5, false, nextval('document_change_seq'), $6)
            ON CONFLICT (id) DO NOTHING
            RETURNING id, version, blob_id, blob_size, enc_meta, deleted, server_seq, updated_at
            "#,
            id,
            vault_row.id,
            body.blob_id,
            body.blob_size,
            body.enc_meta,
            updated_at
        )
        .fetch_optional(&mut *tx)
        .await?;

        return if let Some(record) = inserted {
            tx.commit().await?;
            Ok((StatusCode::CREATED, Json(record)).into_response())
        } else {
            // Someone beat us to creating this id: fetch the current record for the 412 body.
            let current = fetch_tx(&mut tx, id).await?;
            tx.commit().await?;
            Err(version_mismatch(id, current))
        };
    }

    let updated = sqlx::query_as!(
        DocumentRecord,
        r#"
        UPDATE document SET
            version = $2,
            blob_id = $3,
            blob_size = $4,
            enc_meta = $5,
            deleted = false,
            server_seq = nextval('document_change_seq'),
            updated_at = $6
        WHERE id = $1 AND version = $7
        RETURNING id, version, blob_id, blob_size, enc_meta, deleted, server_seq, updated_at
        "#,
        id,
        if_match + 1,
        body.blob_id,
        body.blob_size,
        body.enc_meta,
        updated_at,
        if_match
    )
    .fetch_optional(&mut *tx)
    .await?;

    if let Some(record) = updated {
        tx.commit().await?;
        Ok((StatusCode::OK, Json(record)).into_response())
    } else {
        let current = fetch_tx(&mut tx, id).await?;
        tx.commit().await?;
        Err(version_mismatch(id, current))
    }
}

/// `DELETE /v1/docs/{id}` — header `If-Match`. `200 DocumentRecord` (tombstone, `enc_meta` kept,
/// `blob_id` cleared) / `412` on mismatch / `404` if the document has never existed.
pub async fn delete_doc(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let if_match = require_if_match(&headers)?;

    let mut tx = state.db.begin().await?;

    let updated_at = Utc::now();
    let updated = sqlx::query_as!(
        DocumentRecord,
        r#"
        UPDATE document SET
            version = $2,
            blob_id = NULL,
            blob_size = 0,
            deleted = true,
            server_seq = nextval('document_change_seq'),
            updated_at = $3
        WHERE id = $1 AND version = $4
        RETURNING id, version, blob_id, blob_size, enc_meta, deleted, server_seq, updated_at
        "#,
        id,
        if_match + 1,
        updated_at,
        if_match
    )
    .fetch_optional(&mut *tx)
    .await?;

    if let Some(record) = updated {
        tx.commit().await?;
        Ok((StatusCode::OK, Json(record)).into_response())
    } else {
        let current = fetch_tx(&mut tx, id).await?;
        tx.commit().await?;
        if let Some(doc) = current {
            Err(ApiError::VersionMismatch(Box::new(doc)))
        } else {
            Err(ApiError::NotFound)
        }
    }
}

async fn fetch(state: &AppState, id: Uuid) -> Result<Option<DocumentRecord>, ApiError> {
    let record = sqlx::query_as!(
        DocumentRecord,
        r#"SELECT id, version, blob_id, blob_size, enc_meta, deleted, server_seq, updated_at
           FROM document WHERE id = $1"#,
        id
    )
    .fetch_optional(&state.db)
    .await?;
    Ok(record)
}

async fn fetch_tx(
    tx: &mut sqlx::PgConnection,
    id: Uuid,
) -> Result<Option<DocumentRecord>, ApiError> {
    let record = sqlx::query_as!(
        DocumentRecord,
        r#"SELECT id, version, blob_id, blob_size, enc_meta, deleted, server_seq, updated_at
           FROM document WHERE id = $1"#,
        id
    )
    .fetch_optional(tx)
    .await?;
    Ok(record)
}

/// Builds the `412 version_mismatch` error for the create path (`If-Match: 0`), where `current`
/// is `None` only in the vanishingly unlikely case the conflicting row was deleted again between
/// our `INSERT ... ON CONFLICT DO NOTHING` and the follow-up `SELECT` (still inside the same
/// transaction, so this should not happen in practice, but a sentinel "doesn't exist" record is a
/// safer fallback than panicking).
fn version_mismatch(id: Uuid, current: Option<DocumentRecord>) -> ApiError {
    ApiError::VersionMismatch(Box::new(current.unwrap_or(DocumentRecord {
        id,
        version: 0,
        blob_id: None,
        blob_size: 0,
        enc_meta: Vec::new(),
        deleted: false,
        server_seq: 0,
        updated_at: Utc::now(),
    })))
}

/// Parses the `If-Match` header directly as `i32`: `document.version` is `integer` in Postgres,
/// so there is no valid `If-Match` value that wouldn't fit (and `0` is the create sentinel).
fn require_if_match(headers: &HeaderMap) -> Result<i32, ApiError> {
    let raw = headers
        .get("if-match")
        .ok_or_else(|| ApiError::BadRequest("If-Match header is required".to_string()))?;
    let text = raw
        .to_str()
        .map_err(|_| ApiError::BadRequest("If-Match header is not valid UTF-8".to_string()))?;
    text.trim()
        .parse::<i32>()
        .ok()
        .filter(|v| *v >= 0)
        .ok_or_else(|| ApiError::BadRequest("If-Match must be a non-negative integer".to_string()))
}
