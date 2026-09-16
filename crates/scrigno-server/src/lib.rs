//! Scrigno server — dumb, honest ciphertext storage.
//!
//! Split into a library (this crate root) and a thin `main.rs` binary so integration tests can
//! build an [`AppState`] + [`routes::router`] directly against a `#[sqlx::test]` database without
//! going through `Config::from_env()` / a real TCP listener.

pub mod auth;
pub mod config;
pub mod error;
pub mod gc;
pub mod json_extractor;
pub mod models;
pub mod routes;

use std::fmt;
use std::sync::Arc;

use object_store::ObjectStore;
use sqlx::PgPool;

/// Shared application state, cloned into each request handler.
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub store: Arc<dyn ObjectStore>,
    /// The configured `SCRIGNO_API_TOKEN`, as raw bytes, compared in constant time.
    pub api_token: Arc<[u8]>,
    pub max_blob_bytes: u64,
}

// Manual, redacting `Debug` so a future `{:?}`/test-convenience use of `AppState` can't start
// printing `api_token` just because someone adds `#[derive(Debug)]` without thinking about it.
impl fmt::Debug for AppState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppState")
            .field("db", &"PgPool")
            .field("store", &"Arc<dyn ObjectStore>")
            .field("api_token", &"<redacted>")
            .field("max_blob_bytes", &self.max_blob_bytes)
            .finish()
    }
}
