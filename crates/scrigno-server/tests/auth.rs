mod support;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn healthz_is_public(pool: PgPool) {
    let router = support::app(pool);
    let response = support::send(
        &router,
        Request::builder()
            .uri("/healthz")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[sqlx::test(migrations = "./migrations")]
async fn v1_without_token_is_401(pool: PgPool) {
    let router = support::app(pool);
    let response = support::send(
        &router,
        Request::builder()
            .uri("/v1/vault")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = support::body_bytes(response).await;
    assert!(body.is_empty(), "§3: 401 must have an empty body");
}

#[sqlx::test(migrations = "./migrations")]
async fn v1_with_wrong_token_is_401(pool: PgPool) {
    let router = support::app(pool);
    let response = support::send(
        &router,
        Request::builder()
            .uri("/v1/vault")
            .header("authorization", "Bearer not-the-right-token")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "./migrations")]
async fn v1_with_malformed_header_is_401(pool: PgPool) {
    let router = support::app(pool);
    let response = support::send(
        &router,
        Request::builder()
            .uri("/v1/vault")
            .header("authorization", support::TOKEN) // missing "Bearer " prefix
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "./migrations")]
async fn v1_with_correct_token_is_not_401(pool: PgPool) {
    let router = support::app(pool);
    let response = support::send(
        &router,
        support::authed("GET", "/v1/vault")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    // Not 401 -- vault doesn't exist yet, so this is 404, proving auth passed.
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
