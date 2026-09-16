//! `/v1/blobs/{id}` — §3.
//!
//! Both directions stream: `PUT` reads the request body one chunk at a time, hashing with
//! SHA-256 as it goes and forwarding buffered chunks to `object_store`'s multipart upload; `GET`
//! streams the object (or a byte range of it) straight from `object_store` into the response
//! body. Neither ever calls `axum::body::to_bytes` or otherwise buffers the whole blob in memory.

use axum::Json;
use axum::body::Body;
use axum::extract::{Path, Request, State};
use axum::http::header::{ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG, RANGE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use object_store::path::Path as StorePath;
use object_store::{GetOptions, MultipartUpload, ObjectStore, ObjectStoreExt};
use sha2::{Digest, Sha256};
use sqlx::types::chrono::Utc;
use uuid::Uuid;

use crate::AppState;
use crate::error::ApiError;
use crate::models::BlobPutResponse;

/// Chunks are buffered up to this size before being handed to `object_store` as one multipart
/// part, so a 150 MiB upload results in tens of parts rather than thousands of tiny writes (one
/// per TCP-sized read from the client), while still keeping peak memory in the low single-digit
/// MiB.
const PART_BUFFER_BYTES: usize = 8 * 1024 * 1024;

/// `PUT /v1/blobs/{id}` — raw body, `Content-Length` required.
///
/// `201 { id, size, sha256 }`; `200` if an identical blob already exists under this id; `409
/// blob_mismatch` if one exists with different content; `413` if the declared or actual size
/// exceeds `SCRIGNO_MAX_BLOB_BYTES`.
pub async fn put_blob(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    req: Request,
) -> Result<Response, ApiError> {
    let Some(vault_row) = sqlx::query!("SELECT id FROM vault LIMIT 1")
        .fetch_optional(&state.db)
        .await?
    else {
        return Err(ApiError::VaultNotInitialised);
    };

    let content_length = headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or_else(|| ApiError::BadRequest("Content-Length header is required".to_string()))?;

    // Enforce the limit *before* reading a single byte of the body (§: "Enforce Content-Length
    // and SCRIGNO_MAX_BLOB_BYTES before reading").
    if content_length > state.max_blob_bytes {
        return Err(ApiError::PayloadTooLarge);
    }

    let object_path = StorePath::from(format!("{}/{id}", vault_row.id));
    let mut upload = state.store.put_multipart(&object_path).await?;

    let outcome = stream_into_upload(req, upload.as_mut(), state.max_blob_bytes).await;

    let (total, digest) = match outcome {
        Ok(result) => result,
        Err(error) => {
            // Best-effort cleanup of the partial upload; the DB was never touched so there is
            // nothing else to roll back.
            let _ = upload.abort().await;
            return Err(error);
        }
    };

    if total != content_length {
        let _ = upload.abort().await;
        return Err(ApiError::BadRequest(
            "actual body size did not match Content-Length".to_string(),
        ));
    }

    let sha256 = digest.to_vec();
    let sha256_hex = to_hex(&sha256);

    let existing = sqlx::query!(
        "SELECT size, sha256 FROM blob WHERE id = $1 AND vault_id = $2",
        id,
        vault_row.id
    )
    .fetch_optional(&state.db)
    .await?;

    #[allow(clippy::cast_possible_wrap)]
    let total_signed = total as i64;

    match existing {
        None => {
            // Genuinely new blob: publish the staged upload and record it.
            upload.complete().await?;
            sqlx::query!(
                "INSERT INTO blob (id, vault_id, size, sha256, created_at) VALUES ($1, $2, $3, $4, $5)",
                id,
                vault_row.id,
                total_signed,
                sha256,
                Utc::now()
            )
            .execute(&state.db)
            .await?;
            Ok((
                StatusCode::CREATED,
                Json(BlobPutResponse {
                    id,
                    size: total_signed,
                    sha256: sha256_hex,
                }),
            )
                .into_response())
        }
        Some(row) if row.size == total_signed && row.sha256 == sha256 => {
            // Idempotent re-upload of the exact same content: discard the redundant write, the
            // object on disk (written the first time) is already correct.
            let _ = upload.abort().await;
            Ok((
                StatusCode::OK,
                Json(BlobPutResponse {
                    id,
                    size: row.size,
                    sha256: to_hex(&row.sha256),
                }),
            )
                .into_response())
        }
        Some(_) => {
            // Same id, different content: never overwrite what's already stored under it.
            let _ = upload.abort().await;
            Err(ApiError::BlobMismatch)
        }
    }
}

/// Drains `req`'s body, buffering up to [`PART_BUFFER_BYTES`] before handing chunks to `upload`,
/// hashing every byte as it arrives. Aborts as soon as more than `max_bytes` have been seen,
/// without buffering the excess.
async fn stream_into_upload(
    req: Request,
    upload: &mut dyn MultipartUpload,
    max_bytes: u64,
) -> Result<(u64, [u8; 32]), ApiError> {
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    let mut buffer: Vec<u8> = Vec::with_capacity(PART_BUFFER_BYTES);

    let mut stream = req.into_body().into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            tracing::error!(%error, "error reading blob upload body");
            ApiError::BadRequest("error reading request body".to_string())
        })?;

        total = total
            .checked_add(chunk.len() as u64)
            .ok_or(ApiError::PayloadTooLarge)?;
        if total > max_bytes {
            return Err(ApiError::PayloadTooLarge);
        }

        hasher.update(&chunk);
        buffer.extend_from_slice(&chunk);
        if buffer.len() >= PART_BUFFER_BYTES {
            let part = std::mem::replace(&mut buffer, Vec::with_capacity(PART_BUFFER_BYTES));
            upload.put_part(part.into()).await?;
        }
    }

    if !buffer.is_empty() {
        upload.put_part(buffer.into()).await?;
    }

    Ok((total, hasher.finalize().into()))
}

/// `GET /v1/blobs/{id}` — optional `Range` header -> `200`/`206` stream, `ETag: "<sha256 hex>"`.
pub async fn get_blob(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let Some(vault_row) = sqlx::query!("SELECT id FROM vault LIMIT 1")
        .fetch_optional(&state.db)
        .await?
    else {
        return Err(ApiError::NotFound);
    };

    let row = sqlx::query!(
        "SELECT size, sha256 FROM blob WHERE id = $1 AND vault_id = $2",
        id,
        vault_row.id
    )
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)?;

    #[allow(clippy::cast_sign_loss)]
    let size = row.size.max(0) as u64;
    let sha256_hex = to_hex(&row.sha256);
    let object_path = StorePath::from(format!("{}/{id}", vault_row.id));

    let mut status = StatusCode::OK;
    let mut store_range = None;
    let mut content_range_header = None;
    let mut content_length = size;

    if let Some(raw_range) = headers.get(RANGE).and_then(|v| v.to_str().ok()) {
        match parse_range(raw_range, size) {
            Some(Ok((start, end_inclusive))) => {
                status = StatusCode::PARTIAL_CONTENT;
                content_length = end_inclusive - start + 1;
                content_range_header = Some(format!("bytes {start}-{end_inclusive}/{size}"));
                store_range = Some(object_store::GetRange::Bounded(start..end_inclusive + 1));
            }
            Some(Err(())) => return Err(ApiError::RangeNotSatisfiable { size }),
            // Malformed Range header: fall back to returning the full object.
            None => {}
        }
    }

    let get_result = state
        .store
        .get_opts(
            &object_path,
            GetOptions {
                range: store_range,
                ..Default::default()
            },
        )
        .await?;

    let stream = get_result
        .into_stream()
        .map(|chunk| chunk.map_err(|error| std::io::Error::other(error.to_string())));
    let body = Body::from_stream(stream);

    let mut builder = Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/octet-stream")
        .header(CONTENT_LENGTH, content_length.to_string())
        .header(ETAG, format!("\"{sha256_hex}\""))
        .header(ACCEPT_RANGES, "bytes");
    if let Some(content_range) = content_range_header {
        builder = builder.header(CONTENT_RANGE, content_range);
    }

    builder
        .body(body)
        .map_err(|error| ApiError::Internal(Box::new(error)))
}

/// Parses a single-range `Range: bytes=start-end` / `bytes=start-` / `bytes=-suffix` header.
///
/// Returns `None` for anything not resembling a single byte-range (multi-range, malformed
/// syntax): callers should treat that as "no Range header" and return the full object. Returns
/// `Some(Err(()))` when the range is syntactically a byte-range but unsatisfiable (start at or
/// past the end of the object), which the caller maps to `416`.
fn parse_range(header: &str, size: u64) -> Option<Result<(u64, u64), ()>> {
    let spec = header.strip_prefix("bytes=")?;
    if spec.contains(',') {
        // Multi-range requests are not supported; fall back to a full response.
        return None;
    }
    let (start_str, end_str) = spec.split_once('-')?;

    if start_str.is_empty() {
        // Suffix range: last `end_str` bytes.
        let suffix_len: u64 = end_str.parse().ok()?;
        if suffix_len == 0 || size == 0 {
            return Some(Err(()));
        }
        let start = size.saturating_sub(suffix_len);
        return Some(Ok((start, size - 1)));
    }

    let start: u64 = start_str.parse().ok()?;
    if start >= size {
        return Some(Err(()));
    }
    let end = if end_str.is_empty() {
        size - 1
    } else {
        end_str.parse::<u64>().ok()?.min(size - 1)
    };
    if end < start {
        return Some(Err(()));
    }
    Some(Ok((start, end)))
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}
