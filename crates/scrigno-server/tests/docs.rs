mod support;

use axum::body::Body;
use axum::http::StatusCode;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

async fn put_doc(
    router: &axum::Router,
    id: Uuid,
    if_match: &str,
    blob_id: Uuid,
) -> axum::http::Response<Body> {
    let body = json!({
        "blob_id": blob_id,
        "blob_size": 42,
        "enc_meta": support::fake_enc_meta(),
    });
    support::send(
        router,
        support::authed("PUT", &format!("/v1/docs/{id}"))
            .header("if-match", if_match)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await
}

#[sqlx::test(migrations = "./migrations")]
async fn create_doc_with_if_match_zero(pool: PgPool) {
    let router = support::app(pool);
    support::create_vault(&router).await;
    let blob_id = Uuid::now_v7();
    let upload = support::put_blob(&router, blob_id, b"blob content").await;
    assert_eq!(upload.status(), StatusCode::CREATED);

    let doc_id = Uuid::now_v7();
    let response = put_doc(&router, doc_id, "0", blob_id).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let record: serde_json::Value = support::body_json(response).await;
    assert_eq!(record["version"], 1);
    assert_eq!(record["blob_id"], blob_id.to_string());
    assert_eq!(record["deleted"], false);
}

#[sqlx::test(migrations = "./migrations")]
async fn update_doc_with_correct_if_match(pool: PgPool) {
    let router = support::app(pool);
    support::create_vault(&router).await;
    let blob_id = Uuid::now_v7();
    support::put_blob(&router, blob_id, b"v1").await;
    let blob_id_2 = Uuid::now_v7();
    support::put_blob(&router, blob_id_2, b"v2").await;

    let doc_id = Uuid::now_v7();
    let created = put_doc(&router, doc_id, "0", blob_id).await;
    assert_eq!(created.status(), StatusCode::CREATED);

    let updated = put_doc(&router, doc_id, "1", blob_id_2).await;
    assert_eq!(updated.status(), StatusCode::OK);
    let record: serde_json::Value = support::body_json(updated).await;
    assert_eq!(record["version"], 2);
    assert_eq!(record["blob_id"], blob_id_2.to_string());
}

#[sqlx::test(migrations = "./migrations")]
async fn stale_if_match_is_412_with_current_record(pool: PgPool) {
    let router = support::app(pool);
    support::create_vault(&router).await;
    let blob_id = Uuid::now_v7();
    support::put_blob(&router, blob_id, b"v1").await;

    let doc_id = Uuid::now_v7();
    let created = put_doc(&router, doc_id, "0", blob_id).await;
    assert_eq!(created.status(), StatusCode::CREATED);

    // Stale If-Match: server is at version 1, client claims 0 again.
    let response = put_doc(&router, doc_id, "0", blob_id).await;
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    let record: serde_json::Value = support::body_json(response).await;
    // §3: the 412 body *is* the current DocumentRecord, not an error envelope.
    assert_eq!(record["version"], 1);
    assert_eq!(record["id"], doc_id.to_string());
}

#[sqlx::test(migrations = "./migrations")]
async fn put_doc_with_unknown_blob_is_404_blob_not_found(pool: PgPool) {
    let router = support::app(pool);
    support::create_vault(&router).await;

    let doc_id = Uuid::now_v7();
    let response = put_doc(&router, doc_id, "0", Uuid::now_v7()).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body: serde_json::Value = support::body_json(response).await;
    assert_eq!(body["error"]["code"], "blob_not_found");
}

#[sqlx::test(migrations = "./migrations")]
async fn get_unknown_doc_is_404(pool: PgPool) {
    let router = support::app(pool);
    support::create_vault(&router).await;

    let response = support::send(
        &router,
        support::authed("GET", &format!("/v1/docs/{}", Uuid::now_v7()))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn delete_doc_tombstones_and_keeps_enc_meta(pool: PgPool) {
    let router = support::app(pool);
    support::create_vault(&router).await;
    let blob_id = Uuid::now_v7();
    support::put_blob(&router, blob_id, b"content").await;

    let doc_id = Uuid::now_v7();
    let created = put_doc(&router, doc_id, "0", blob_id).await;
    let created_record: serde_json::Value = support::body_json(created).await;
    let enc_meta = created_record["enc_meta"].clone();

    let response = support::send(
        &router,
        support::authed("DELETE", &format!("/v1/docs/{doc_id}"))
            .header("if-match", "1")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let record: serde_json::Value = support::body_json(response).await;
    assert_eq!(record["deleted"], true);
    assert_eq!(record["blob_id"], serde_json::Value::Null);
    assert_eq!(record["version"], 2);
    assert_eq!(
        record["enc_meta"], enc_meta,
        "tombstone must keep the last enc_meta"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn delete_doc_with_stale_if_match_is_412(pool: PgPool) {
    let router = support::app(pool);
    support::create_vault(&router).await;
    let blob_id = Uuid::now_v7();
    support::put_blob(&router, blob_id, b"content").await;

    let doc_id = Uuid::now_v7();
    put_doc(&router, doc_id, "0", blob_id).await;

    let response = support::send(
        &router,
        support::authed("DELETE", &format!("/v1/docs/{doc_id}"))
            .header("if-match", "0")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
}

#[sqlx::test(migrations = "./migrations")]
async fn delete_unknown_doc_is_404(pool: PgPool) {
    let router = support::app(pool);
    support::create_vault(&router).await;

    let response = support::send(
        &router,
        support::authed("DELETE", &format!("/v1/docs/{}", Uuid::now_v7()))
            .header("if-match", "0")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn put_doc_missing_if_match_is_bad_request(pool: PgPool) {
    let router = support::app(pool);
    support::create_vault(&router).await;
    let blob_id = Uuid::now_v7();
    support::put_blob(&router, blob_id, b"content").await;

    let doc_id = Uuid::now_v7();
    let body = json!({ "blob_id": blob_id, "blob_size": 7, "enc_meta": support::fake_enc_meta() });
    let response = support::send(
        &router,
        support::authed("PUT", &format!("/v1/docs/{doc_id}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
