//! `ApiError` — the single error type every handler returns.
//!
//! Maps to `{ "error": { "code", "message" } }` per `docs/ARCHITECTURE.md §3`, with the one
//! documented exception: `412 version_mismatch` returns the current `DocumentRecord` as the
//! response body instead of the error envelope (§3: "412 `version_mismatch` with current record
//! in body"), so a conflicting client can act on it directly without a second round trip.
//!
//! Internal details (SQL errors, filesystem paths, `object_store` errors) are logged with
//! `tracing::error!` and never reach the client; the client only ever sees a stable `code` and a
//! generic message.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::models::DocumentRecord;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("unauthorized")]
    Unauthorized,

    #[error("vault not initialised")]
    VaultNotInitialised,

    #[error("vault already exists")]
    VaultExists,

    #[error("cannot delete the last keyslot")]
    LastKeyslot,

    #[error("not found")]
    NotFound,

    #[error("version mismatch")]
    VersionMismatch(Box<DocumentRecord>),

    #[error("blob not found")]
    BlobNotFound,

    #[error("blob already exists with different content")]
    BlobMismatch,

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("payload too large")]
    PayloadTooLarge,

    /// Not part of §3's documented table, but standard HTTP semantics for an unsatisfiable
    /// `Range` header (e.g. `start` at or past the end of the object).
    #[error("range not satisfiable for a body of {size} bytes")]
    RangeNotSatisfiable { size: u64 },

    #[error("internal error")]
    Internal(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl ApiError {
    fn code(&self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::VaultNotInitialised => "vault_not_initialised",
            Self::VaultExists => "vault_exists",
            Self::LastKeyslot => "last_keyslot",
            Self::NotFound => "not_found",
            Self::VersionMismatch(_) => "version_mismatch",
            Self::BlobNotFound => "blob_not_found",
            Self::BlobMismatch => "blob_mismatch",
            Self::BadRequest(_) => "bad_request",
            Self::PayloadTooLarge => "payload_too_large",
            Self::RangeNotSatisfiable { .. } => "range_not_satisfiable",
            Self::Internal(_) => "internal_error",
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::VaultNotInitialised | Self::NotFound | Self::BlobNotFound => {
                StatusCode::NOT_FOUND
            }
            Self::VaultExists | Self::LastKeyslot | Self::BlobMismatch => StatusCode::CONFLICT,
            Self::VersionMismatch(_) => StatusCode::PRECONDITION_FAILED,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::RangeNotSatisfiable { .. } => StatusCode::RANGE_NOT_SATISFIABLE,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: ErrorInner,
}

#[derive(Serialize)]
struct ErrorInner {
    code: &'static str,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let Self::Unauthorized = self {
            // §3: "Missing or wrong -> 401 with empty body."
            return StatusCode::UNAUTHORIZED.into_response();
        }

        if let Self::Internal(source) = &self {
            tracing::error!(error = %source, "internal error");
        }

        let status = self.status();

        // §3's one documented exception to the error envelope.
        if let Self::VersionMismatch(current) = self {
            return (status, Json(current)).into_response();
        }

        let message = match &self {
            Self::Internal(_) => "an internal error occurred".to_string(),
            other => other.to_string(),
        };
        let body = ErrorBody {
            error: ErrorInner {
                code: self.code(),
                message,
            },
        };
        (status, Json(body)).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        Self::Internal(Box::new(error))
    }
}

impl From<object_store::Error> for ApiError {
    fn from(error: object_store::Error) -> Self {
        Self::Internal(Box::new(error))
    }
}
