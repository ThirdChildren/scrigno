mod support;

use axum::body::Body;
use axum::http::StatusCode;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn create_then_get_vault(pool: PgPool) {
    let router = support::app(pool);
    let vault_id = Uuid::now_v7();
    let keyslot_id = Uuid::now_v7();

    let body = json!({
        "id": vault_id,
        "keyslot": {
            "id": keyslot_id,
            "kind": "passphrase",
            "kdf": { "alg": "argon2id", "m_kib": 65536, "t": 3, "p": 1, "salt": "abcd" },
            "wrapped_mk": support::fake_wrapped_mk(),
        }
    });

    let response = support::send(
        &router,
        support::authed("POST", "/v1/vault")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let created: serde_json::Value = support::body_json(response).await;
    assert_eq!(created["id"], vault_id.to_string());
    assert_eq!(created["keyslots"].as_array().unwrap().len(), 1);

    let response = support::send(
        &router,
        support::authed("GET", "/v1/vault")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let fetched: serde_json::Value = support::body_json(response).await;
    assert_eq!(fetched["id"], vault_id.to_string());
    assert_eq!(fetched["keyslots"][0]["id"], keyslot_id.to_string());
    // The server must round-trip wrapped_mk opaquely, byte for byte.
    assert_eq!(
        fetched["keyslots"][0]["wrapped_mk"],
        support::fake_wrapped_mk()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn vault_not_initialised_is_404(pool: PgPool) {
    let router = support::app(pool);
    let response = support::send(
        &router,
        support::authed("GET", "/v1/vault")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body: serde_json::Value = support::body_json(response).await;
    assert_eq!(body["error"]["code"], "vault_not_initialised");
}

#[sqlx::test(migrations = "./migrations")]
async fn creating_a_second_vault_is_409(pool: PgPool) {
    let router = support::app(pool);
    let make_body = || {
        json!({
            "id": Uuid::now_v7(),
            "keyslot": {
                "id": Uuid::now_v7(),
                "kind": "passphrase",
                "kdf": { "alg": "argon2id" },
                "wrapped_mk": support::fake_wrapped_mk(),
            }
        })
    };

    let first = support::send(
        &router,
        support::authed("POST", "/v1/vault")
            .header("content-type", "application/json")
            .body(Body::from(make_body().to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(first.status(), StatusCode::CREATED);

    let second = support::send(
        &router,
        support::authed("POST", "/v1/vault")
            .header("content-type", "application/json")
            .body(Body::from(make_body().to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(second.status(), StatusCode::CONFLICT);
    let body: serde_json::Value = support::body_json(second).await;
    assert_eq!(body["error"]["code"], "vault_exists");
}

#[sqlx::test(migrations = "./migrations")]
async fn add_keyslot_then_delete(pool: PgPool) {
    let router = support::app(pool);
    support::create_vault(&router).await;

    let second_id = Uuid::now_v7();
    let response = support::send(
        &router,
        support::authed("POST", "/v1/vault/keyslots")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "id": second_id,
                    "kind": "recovery",
                    "kdf": { "alg": "argon2id" },
                    "wrapped_mk": support::fake_wrapped_mk(),
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    // Two keyslots now: deleting one should succeed.
    let response = support::send(
        &router,
        support::authed("DELETE", &format!("/v1/vault/keyslots/{second_id}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[sqlx::test(migrations = "./migrations")]
async fn deleting_the_last_keyslot_is_409(pool: PgPool) {
    let router = support::app(pool);
    support::create_vault(&router).await;

    let vault_response = support::send(
        &router,
        support::authed("GET", "/v1/vault")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let vault: serde_json::Value = support::body_json(vault_response).await;
    let only_keyslot_id = vault["keyslots"][0]["id"].as_str().unwrap();

    let response = support::send(
        &router,
        support::authed("DELETE", &format!("/v1/vault/keyslots/{only_keyslot_id}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body: serde_json::Value = support::body_json(response).await;
    assert_eq!(body["error"]["code"], "last_keyslot");
}
