//! HTTP routes: `GET /healthz` (public) plus the authenticated `/v1/*` surface from §3.

mod blobs;
mod changes;
mod docs;
mod vault;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Json;
use axum::routing::{delete, get, post, put};
use axum::{Router, middleware};
use serde::Serialize;
use sqlx::PgPool;

use crate::AppState;
use crate::auth;

pub fn router(state: AppState) -> Router {
    let v1 = Router::new()
        .route("/vault", get(vault::get_vault).post(vault::create_vault))
        .route("/vault/keyslots", post(vault::add_keyslot))
        .route("/vault/keyslots/{id}", delete(vault::delete_keyslot))
        .route("/changes", get(changes::list_changes))
        .route(
            "/docs/{id}",
            get(docs::get_doc)
                .put(docs::put_doc)
                .delete(docs::delete_doc),
        )
        .route("/blobs/{id}", put(blobs::put_blob).get(blobs::get_blob))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_token,
        ));

    Router::new()
        .route("/healthz", get(healthz))
        .nest("/v1", v1)
        .with_state(state)
}

#[derive(Serialize)]
struct HealthBody {
    status: &'static str,
    db: &'static str,
}

/// `GET /healthz` — no auth. Proves the process is up and can reach Postgres.
async fn healthz(State(state): State<AppState>) -> (StatusCode, Json<HealthBody>) {
    match check_db(&state.db).await {
        Ok(()) => (
            StatusCode::OK,
            Json(HealthBody {
                status: "ok",
                db: "ok",
            }),
        ),
        Err(error) => {
            tracing::error!(%error, "healthz: database check failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(HealthBody {
                    status: "ok",
                    db: "error",
                }),
            )
        }
    }
}

async fn check_db(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(pool)
        .await?;
    Ok(())
}
