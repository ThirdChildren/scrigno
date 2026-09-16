//! Scrigno server binary — see `src/lib.rs` for the crate-level overview.

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use object_store::ObjectStore;
use object_store::local::LocalFileSystem;
use scrigno_server::config::Config;
use scrigno_server::{AppState, auth, gc, routes};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "server exited with error");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;

    tracing::info!(bind = %config.bind, "starting scrigno-server");

    let pool: PgPool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await?;

    tokio::fs::create_dir_all(&config.blob_dir).await?;
    let store: Arc<dyn ObjectStore> = Arc::new(LocalFileSystem::new_with_prefix(&config.blob_dir)?);

    let state = AppState {
        db: pool,
        store,
        api_token: Arc::from(config.api_token.as_bytes()),
        max_blob_bytes: config.max_blob_bytes,
    };

    gc::spawn(state.clone(), Duration::from_secs(config.gc_interval_secs));

    let app = routes::router(state)
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn(auth::request_id));

    let listener = tokio::net::TcpListener::bind(&config.bind).await?;
    tracing::info!(bind = %config.bind, "listening");

    axum::serve(listener, app).await?;

    Ok(())
}
