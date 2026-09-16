//! HTTP routes.
//!
//! M0 only has the unauthenticated healthcheck; `/v1/*` endpoints land in M2.

use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use serde::Serialize;
use sqlx::PgPool;

use crate::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
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
