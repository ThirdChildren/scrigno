mod support;

use axum::body::Body;
use axum::http::StatusCode;
use object_store::ObjectStoreExt;
use object_store::path::Path as StorePath;
use scrigno_server::gc;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

/// Directly exercises `gc::sweep` against a database whose `blob` rows have been backdated, since
/// waiting 24h in a test is not an option. `sweep` itself doesn't know or care how `created_at`
/// got to be old -- it just queries it -- so backdating via a raw `UPDATE` after upload is a
/// faithful way to test the "older than 24h" half of the eligibility rule without reaching into
/// GC-specific test-only code paths.
#[sqlx::test(migrations = "./migrations")]
async fn gc_deletes_only_unreferenced_and_old_blobs(pool: PgPool) {
    let (router, state) = support::build(pool.clone(), 10 * 1024 * 1024);
    let vault_id = support::create_vault(&router).await;

    // 1. Unreferenced, old -> must be deleted (DB row and on-disk object).
    let old_unreferenced = Uuid::now_v7();
    support::put_blob(&router, old_unreferenced, b"old and unused").await;

    // 2. Unreferenced, fresh -> must survive (grace period for in-flight uploads).
    let fresh_unreferenced = Uuid::now_v7();
    support::put_blob(&router, fresh_unreferenced, b"fresh and unused").await;

    // 3. Referenced by a live document, old -> must survive.
    let old_referenced = Uuid::now_v7();
    support::put_blob(&router, old_referenced, b"old but referenced").await;
    let doc_id = Uuid::now_v7();
    let body =
        json!({ "blob_id": old_referenced, "blob_size": 1, "enc_meta": support::fake_enc_meta() });
    let response = support::send(
        &router,
        support::authed("PUT", &format!("/v1/docs/{doc_id}"))
            .header("if-match", "0")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    // Backdate the two "old" blobs past the 24h grace period.
    for id in [old_unreferenced, old_referenced] {
        sqlx::query!(
            "UPDATE blob SET created_at = now() - interval '48 hours' WHERE id = $1",
            id
        )
        .execute(&pool)
        .await
        .unwrap();
    }

    let deleted = gc::sweep(&pool, state.store.as_ref()).await.unwrap();
    assert_eq!(
        deleted, 1,
        "exactly the old+unreferenced blob should be collected"
    );

    let remaining: Vec<Uuid> = sqlx::query_scalar!("SELECT id FROM blob ORDER BY id")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert!(!remaining.contains(&old_unreferenced));
    assert!(remaining.contains(&fresh_unreferenced));
    assert!(remaining.contains(&old_referenced));

    // The object itself must be gone from the store too, not just the DB row.
    let path = StorePath::from(format!("{vault_id}/{old_unreferenced}"));
    assert!(state.store.get(&path).await.is_err());

    // The surviving blobs' objects must still be readable.
    let path = StorePath::from(format!("{vault_id}/{fresh_unreferenced}"));
    assert!(state.store.get(&path).await.is_ok());
}

#[sqlx::test(migrations = "./migrations")]
async fn gc_sweep_with_nothing_to_do_is_a_no_op(pool: PgPool) {
    let (_router, state) = support::build(pool.clone(), 10 * 1024 * 1024);
    let deleted = gc::sweep(&pool, state.store.as_ref()).await.unwrap();
    assert_eq!(deleted, 0);
}
