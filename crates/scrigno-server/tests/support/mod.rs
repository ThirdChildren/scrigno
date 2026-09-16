//! Shared test scaffolding: builds a real [`scrigno_server::AppState`] (against a `#[sqlx::test]`
//! Postgres database and a real `LocalFileSystem` blob store rooted at a throwaway temp
//! directory) and the corresponding router, without going through `Config::from_env()`.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::http::{Request, Response, StatusCode};
use object_store::ObjectStore;
use object_store::local::LocalFileSystem;
use scrigno_server::AppState;
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

/// A token long enough to satisfy the same 32-char floor `Config::from_env` enforces (tests
/// bypass `Config::from_env`, but keeping this realistic avoids the test setup diverging from
/// what a real deployment looks like).
pub const TOKEN: &str = "test-token-0123456789abcdef0123456789";

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_temp_dir() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    std::env::temp_dir().join(format!(
        "scrigno-server-test-{}-{nanos}-{n}",
        std::process::id()
    ))
}

/// Builds a router backed by `pool`, a fresh temp-dir blob store, [`TOKEN`] as the bearer token,
/// and a generous 10 MiB blob size limit.
#[allow(dead_code)]
pub fn app(pool: PgPool) -> Router {
    app_with_limit(pool, 10 * 1024 * 1024)
}

/// Same as [`app`] but with a caller-chosen `SCRIGNO_MAX_BLOB_BYTES` equivalent, for the 413 test.
#[allow(dead_code)]
pub fn app_with_limit(pool: PgPool, max_blob_bytes: u64) -> Router {
    build(pool, max_blob_bytes).0
}

/// Builds both the router and the [`AppState`] it was built from (so tests that need to reach
/// into the same blob store directly -- e.g. the GC test -- can, instead of duplicating a second,
/// disconnected store).
#[allow(dead_code)]
pub fn build(pool: PgPool, max_blob_bytes: u64) -> (Router, AppState) {
    let dir = unique_temp_dir();
    std::fs::create_dir_all(&dir).expect("create temp blob dir for test");
    let store: Arc<dyn ObjectStore> =
        Arc::new(LocalFileSystem::new_with_prefix(&dir).expect("construct LocalFileSystem"));

    let state = AppState {
        db: pool,
        store,
        api_token: Arc::from(TOKEN.as_bytes()),
        max_blob_bytes,
    };

    (scrigno_server::routes::router(state.clone()), state)
}

/// Sends `req` through `router` in one shot and returns the response.
pub async fn send(router: &Router, req: Request<Body>) -> Response<Body> {
    router
        .clone()
        .oneshot(req)
        .await
        .expect("router is infallible as a tower Service")
}

/// Collects a (small, test-only) response body into `Bytes`. Never use this pattern in
/// production handler code for blob bodies -- it's fine here because test bodies are tiny.
#[allow(dead_code)]
pub async fn body_bytes(response: Response<Body>) -> Bytes {
    axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read response body")
}

#[allow(dead_code)]
pub async fn body_json<T: serde::de::DeserializeOwned>(response: Response<Body>) -> T {
    let bytes = body_bytes(response).await;
    serde_json::from_slice(&bytes).expect("response body is valid JSON")
}

#[allow(dead_code)]
pub fn authed(method: &str, uri: &str) -> axum::http::request::Builder {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {TOKEN}"))
}

/// Builds a valid random `wrapped_mk` payload (opaque to the server: any non-empty bytes do).
#[allow(dead_code)]
pub fn fake_wrapped_mk() -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode([7u8; 73])
}

#[allow(dead_code)]
pub fn fake_enc_meta() -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(b"opaque-ciphertext-meta")
}

#[allow(dead_code)]
pub fn assert_status(response: &Response<Body>, expected: StatusCode) {
    assert_eq!(
        response.status(),
        expected,
        "unexpected status (body not shown, may not be UTF-8/JSON)"
    );
}

/// Creates the (singleton) vault with one passphrase keyslot and returns its id. Panics (via
/// `assert_eq!`) if vault creation doesn't return `201`.
#[allow(dead_code)]
pub async fn create_vault(router: &Router) -> Uuid {
    let vault_id = Uuid::now_v7();
    let body = json!({
        "id": vault_id,
        "keyslot": {
            "id": Uuid::now_v7(),
            "kind": "passphrase",
            "kdf": { "alg": "argon2id" },
            "wrapped_mk": fake_wrapped_mk(),
        }
    });
    let response = send(
        router,
        authed("POST", "/v1/vault")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    vault_id
}

/// Uploads `content` as blob `id` and returns the response (caller asserts on it).
#[allow(dead_code)]
pub async fn put_blob(router: &Router, id: Uuid, content: &[u8]) -> Response<Body> {
    send(
        router,
        authed("PUT", &format!("/v1/blobs/{id}"))
            .header("content-length", content.len().to_string())
            .body(Body::from(content.to_vec()))
            .unwrap(),
    )
    .await
}
