mod support;

use axum::body::Body;
use axum::http::StatusCode;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[sqlx::test(migrations = "./migrations")]
async fn upload_reports_correct_size_and_sha(pool: PgPool) {
    let router = support::app(pool);
    support::create_vault(&router).await;

    let id = Uuid::now_v7();
    let content: &[u8] = b"hello, this is ciphertext as far as the server is concerned";
    let expected_sha = hex(&Sha256::digest(content));

    let response = support::put_blob(&router, id, content).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body: serde_json::Value = support::body_json(response).await;
    assert_eq!(body["id"], id.to_string());
    assert_eq!(body["size"], content.len());
    assert_eq!(body["sha256"], expected_sha);
}

#[sqlx::test(migrations = "./migrations")]
async fn re_uploading_identical_content_is_idempotent(pool: PgPool) {
    let router = support::app(pool);
    support::create_vault(&router).await;

    let id = Uuid::now_v7();
    let content: &[u8] = b"same bytes both times";

    let first = support::put_blob(&router, id, content).await;
    assert_eq!(first.status(), StatusCode::CREATED);
    let first_body: serde_json::Value = support::body_json(first).await;

    let second = support::put_blob(&router, id, content).await;
    assert_eq!(second.status(), StatusCode::OK);
    let second_body: serde_json::Value = support::body_json(second).await;

    assert_eq!(first_body["sha256"], second_body["sha256"]);
    assert_eq!(first_body["size"], second_body["size"]);
}

#[sqlx::test(migrations = "./migrations")]
async fn re_uploading_different_content_under_same_id_is_409(pool: PgPool) {
    let router = support::app(pool);
    support::create_vault(&router).await;

    let id = Uuid::now_v7();
    let first = support::put_blob(&router, id, b"original content").await;
    assert_eq!(first.status(), StatusCode::CREATED);

    let second = support::put_blob(&router, id, b"different content!!").await;
    assert_eq!(second.status(), StatusCode::CONFLICT);
    let body: serde_json::Value = support::body_json(second).await;
    assert_eq!(body["error"]["code"], "blob_mismatch");
}

#[sqlx::test(migrations = "./migrations")]
async fn oversized_upload_is_413(pool: PgPool) {
    // A tiny 16-byte limit makes the test fast while still exercising the real streaming path.
    let router = support::app_with_limit(pool, 16);
    support::create_vault(&router).await;

    let id = Uuid::now_v7();
    let content = vec![0x42u8; 1024];
    let response = support::send(
        &router,
        support::authed("PUT", &format!("/v1/blobs/{id}"))
            .header("content-length", content.len().to_string())
            .body(Body::from(content))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body: serde_json::Value = support::body_json(response).await;
    assert_eq!(body["error"]["code"], "payload_too_large");
}

#[sqlx::test(migrations = "./migrations")]
async fn declared_content_length_over_limit_is_rejected_before_reading(pool: PgPool) {
    let router = support::app_with_limit(pool, 16);
    support::create_vault(&router).await;

    let id = Uuid::now_v7();
    // Declare a huge Content-Length but never actually send that much body: if the server were
    // reading before checking, this would hang; it must reject immediately.
    let response = support::send(
        &router,
        support::authed("PUT", &format!("/v1/blobs/{id}"))
            .header("content-length", "999999999")
            .body(Body::from(vec![0u8; 4]))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[sqlx::test(migrations = "./migrations")]
async fn body_larger_than_a_lying_content_length_is_413(pool: PgPool) {
    // Exercises the *mid-stream* over-budget check in `stream_into_upload`, as opposed to the
    // fast-path check against the declared `Content-Length` header: the header under-declares,
    // but the actual body -- still under the configured limit here -- would be fine size-wise;
    // what must trip the limit is streamed bytes exceeding `max_blob_bytes`, independent of what
    // was declared.
    let router = support::app_with_limit(pool, 16);
    support::create_vault(&router).await;

    let id = Uuid::now_v7();
    let chunk = axum::body::Bytes::from(vec![0x41u8; 64]);
    let stream = futures_util::stream::iter(vec![Ok::<_, std::io::Error>(chunk)]);
    let response = support::send(
        &router,
        support::authed("PUT", &format!("/v1/blobs/{id}"))
            .header("content-length", "8") // lies: actual body is 64 bytes
            .body(Body::from_stream(stream))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[sqlx::test(migrations = "./migrations")]
async fn missing_content_length_is_bad_request(pool: PgPool) {
    let router = support::app(pool);
    support::create_vault(&router).await;

    let id = Uuid::now_v7();
    let response = support::send(
        &router,
        support::authed("PUT", &format!("/v1/blobs/{id}"))
            .body(Body::from(vec![1u8, 2, 3]))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "./migrations")]
async fn get_missing_blob_is_404(pool: PgPool) {
    let router = support::app(pool);
    support::create_vault(&router).await;

    let response = support::send(
        &router,
        support::authed("GET", &format!("/v1/blobs/{}", Uuid::now_v7()))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn get_full_blob_roundtrips_and_sets_etag(pool: PgPool) {
    let router = support::app(pool);
    support::create_vault(&router).await;

    let id = Uuid::now_v7();
    let content: &[u8] = b"0123456789abcdefghij";
    let put = support::put_blob(&router, id, content).await;
    assert_eq!(put.status(), StatusCode::CREATED);
    let expected_sha = hex(&Sha256::digest(content));

    let response = support::send(
        &router,
        support::authed("GET", &format!("/v1/blobs/{id}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let etag = response
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    assert_eq!(etag, format!("\"{expected_sha}\""));
    let body = support::body_bytes(response).await;
    assert_eq!(&body[..], content);
}

#[sqlx::test(migrations = "./migrations")]
async fn get_blob_with_range_returns_206_and_the_right_slice(pool: PgPool) {
    let router = support::app(pool);
    support::create_vault(&router).await;

    let id = Uuid::now_v7();
    let content: &[u8] = b"0123456789abcdefghij"; // 20 bytes
    let put = support::put_blob(&router, id, content).await;
    assert_eq!(put.status(), StatusCode::CREATED);

    let response = support::send(
        &router,
        support::authed("GET", &format!("/v1/blobs/{id}"))
            .header("range", "bytes=5-9")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    let content_range = response
        .headers()
        .get("content-range")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();
    assert_eq!(content_range, "bytes 5-9/20");
    let body = support::body_bytes(response).await;
    assert_eq!(&body[..], &content[5..=9]);
}

#[sqlx::test(migrations = "./migrations")]
async fn get_blob_with_unsatisfiable_range_is_416(pool: PgPool) {
    let router = support::app(pool);
    support::create_vault(&router).await;

    let id = Uuid::now_v7();
    let content: &[u8] = b"short";
    let put = support::put_blob(&router, id, content).await;
    assert_eq!(put.status(), StatusCode::CREATED);

    let response = support::send(
        &router,
        support::authed("GET", &format!("/v1/blobs/{id}"))
            .header("range", "bytes=100-200")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
}
