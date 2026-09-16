mod support;

use axum::body::Body;
use axum::http::StatusCode;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

async fn create_doc(router: &axum::Router, index: usize) -> Uuid {
    let blob_id = Uuid::now_v7();
    let content = format!("content-{index}").into_bytes();
    let upload = support::put_blob(router, blob_id, &content).await;
    assert_eq!(upload.status(), StatusCode::CREATED);

    let doc_id = Uuid::now_v7();
    let body = json!({ "blob_id": blob_id, "blob_size": content.len(), "enc_meta": support::fake_enc_meta() });
    let response = support::send(
        router,
        support::authed("PUT", &format!("/v1/docs/{doc_id}"))
            .header("if-match", "0")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    doc_id
}

#[sqlx::test(migrations = "./migrations")]
async fn changes_are_paginated_in_server_seq_order(pool: PgPool) {
    let router = support::app(pool);
    support::create_vault(&router).await;

    let mut ids = Vec::new();
    for i in 0..5 {
        ids.push(create_doc(&router, i).await);
    }

    // Page 1: limit=2.
    let response = support::send(
        &router,
        support::authed("GET", "/v1/changes?since=0&limit=2")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let page1: serde_json::Value = support::body_json(response).await;
    let items1 = page1["items"].as_array().unwrap();
    assert_eq!(items1.len(), 2);
    assert!(page1["has_more"].as_bool().unwrap());
    assert_eq!(items1[0]["id"], ids[0].to_string());
    assert_eq!(items1[1]["id"], ids[1].to_string());
    let next_since = page1["next_since"].as_i64().unwrap();

    // Page 2.
    let response = support::send(
        &router,
        support::authed("GET", &format!("/v1/changes?since={next_since}&limit=2"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let page2: serde_json::Value = support::body_json(response).await;
    let items2 = page2["items"].as_array().unwrap();
    assert_eq!(items2.len(), 2);
    assert!(page2["has_more"].as_bool().unwrap());
    assert_eq!(items2[0]["id"], ids[2].to_string());
    assert_eq!(items2[1]["id"], ids[3].to_string());
    let next_since2 = page2["next_since"].as_i64().unwrap();

    // Page 3: last item, has_more must now be false.
    let response = support::send(
        &router,
        support::authed("GET", &format!("/v1/changes?since={next_since2}&limit=2"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let page3: serde_json::Value = support::body_json(response).await;
    let items3 = page3["items"].as_array().unwrap();
    assert_eq!(items3.len(), 1);
    assert!(!page3["has_more"].as_bool().unwrap());
    assert_eq!(items3[0]["id"], ids[4].to_string());
}

#[sqlx::test(migrations = "./migrations")]
async fn changes_include_tombstones(pool: PgPool) {
    let router = support::app(pool);
    support::create_vault(&router).await;
    let doc_id = create_doc(&router, 0).await;

    let response = support::send(
        &router,
        support::authed("DELETE", &format!("/v1/docs/{doc_id}"))
            .header("if-match", "1")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let response = support::send(
        &router,
        support::authed("GET", "/v1/changes?since=0&limit=500")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let page: serde_json::Value = support::body_json(response).await;
    let items = page["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], doc_id.to_string());
    assert_eq!(items[0]["deleted"], true);
    assert_eq!(items[0]["blob_id"], serde_json::Value::Null);
}

#[sqlx::test(migrations = "./migrations")]
async fn limit_over_500_is_bad_request(pool: PgPool) {
    let router = support::app(pool);
    support::create_vault(&router).await;

    let response = support::send(
        &router,
        support::authed("GET", "/v1/changes?limit=501")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
