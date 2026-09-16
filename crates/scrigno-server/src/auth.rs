//! Auth middleware (constant-time bearer token compare) and request-id middleware.
//!
//! Both are applied only to the `/v1/*` sub-router in `routes::router` -- `/healthz` stays
//! public and outside both.

use axum::extract::{Request, State};
use axum::http::header::{AUTHORIZATION, HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use subtle::ConstantTimeEq;
use tracing::Instrument;
use uuid::Uuid;

use crate::AppState;
use crate::error::ApiError;

const BEARER_PREFIX: &str = "Bearer ";

/// Rejects any `/v1/*` request whose `Authorization` header doesn't carry the exact configured
/// bearer token. Constant-time compare (`subtle::ConstantTimeEq`) so a wrong-but-close token
/// doesn't leak how close it was via timing. Missing or wrong -> `401` with an empty body (§3).
pub async fn require_token(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let provided = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix(BEARER_PREFIX));

    let authorized = match provided {
        Some(token) => bool::from(token.as_bytes().ct_eq(&state.api_token)),
        None => false,
    };

    if !authorized {
        return ApiError::Unauthorized.into_response();
    }

    next.run(req).await
}

/// A per-request id, generated fresh for every request and attached to the tracing span that
/// wraps the rest of the middleware stack (including `TraceLayer`'s own request/response log
/// lines) and echoed back as `X-Request-Id`. Never logs the token or any request/response body.
pub async fn request_id(mut req: Request, next: Next) -> Response {
    let id = Uuid::now_v7();
    req.extensions_mut().insert(RequestId(id));

    let span = tracing::info_span!("request", request_id = %id);
    async move {
        let mut response = next.run(req).await;
        if let Ok(value) = HeaderValue::from_str(&id.to_string()) {
            response
                .headers_mut()
                .insert(HeaderName::from_static("x-request-id"), value);
        }
        response
    }
    .instrument(span)
    .await
}

#[derive(Debug, Clone, Copy)]
pub struct RequestId(pub Uuid);
