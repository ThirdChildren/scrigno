//! A `Json<T>` extractor bounded to 1 MiB (§3: "Limits: JSON bodies 1 MiB"), returning our own
//! `ApiError` envelope on both "too large" and "malformed" instead of axum's default rejection
//! bodies, so every error response on `/v1/*` has the same `{ "error": { "code", "message" } }`
//! shape.
//!
//! `axum::body::to_bytes(body, limit)` is safe to use here (unlike on the blob routes): the limit
//! is a small, fixed 1 MiB, so worst case we buffer 1 MiB, nowhere near the streaming/RAM
//! constraints that apply to blob uploads.

use axum::extract::{FromRequest, Request};
use axum::response::{IntoResponse, Response};
use serde::de::DeserializeOwned;

use crate::error::ApiError;

/// Maximum JSON body size, per §3.
pub const MAX_JSON_BYTES: usize = 1024 * 1024;

pub struct Json<T>(pub T);

impl<S, T> FromRequest<S> for Json<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = Response;

    async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
        if let Some(len) = content_length(&req)
            && len > MAX_JSON_BYTES
        {
            return Err(ApiError::PayloadTooLarge.into_response());
        }

        let body = req.into_body();
        let bytes = axum::body::to_bytes(body, MAX_JSON_BYTES)
            .await
            .map_err(|_| {
                // `to_bytes` fails either because the declared/actual length exceeds `limit` or
                // because of a lower-level body read error; either way we cannot tell them apart
                // here, so treat both as "too large" since that's the overwhelmingly likely cause
                // and keeps the client-facing error stable.
                ApiError::PayloadTooLarge.into_response()
            })?;

        serde_json::from_slice(&bytes).map(Json).map_err(|error| {
            ApiError::BadRequest(format!("invalid JSON body: {error}")).into_response()
        })
    }
}

fn content_length(req: &Request) -> Option<usize> {
    req.headers()
        .get(axum::http::header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}
