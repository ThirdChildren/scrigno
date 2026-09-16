//! Server configuration loaded from environment variables.
//!
//! M0 only needs the database connection and the bind address; `SCRIGNO_BLOB_DIR` is read (so a
//! missing/misconfigured value fails fast) but not yet used — blob storage lands in M2.

use std::env;

/// Default bind address when `SCRIGNO_BIND` is not set.
const DEFAULT_BIND: &str = "127.0.0.1:8787";

/// Errors that can occur while assembling [`Config`] from the process environment.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required environment variable {0}")]
    Missing(&'static str),
    #[error("invalid value for {name}: {message}")]
    Invalid { name: &'static str, message: String },
}

/// Server configuration, assembled once at startup.
#[derive(Debug, Clone)]
pub struct Config {
    /// Postgres connection string (`SCRIGNO_DATABASE_URL`).
    pub database_url: String,
    /// Address to bind the HTTP listener to (`SCRIGNO_BIND`, default `127.0.0.1:8787`).
    pub bind: String,
    /// Root directory for blob storage (`SCRIGNO_BLOB_DIR`). Unused until M2.
    #[allow(dead_code)]
    pub blob_dir: String,
}

impl Config {
    /// Load configuration from environment variables, failing fast with a descriptive error if
    /// anything required is missing or malformed.
    pub fn from_env() -> Result<Self, ConfigError> {
        let database_url = required("SCRIGNO_DATABASE_URL")?;
        let blob_dir = required("SCRIGNO_BLOB_DIR")?;
        let bind = env::var("SCRIGNO_BIND").unwrap_or_else(|_| DEFAULT_BIND.to_string());

        if bind.parse::<std::net::SocketAddr>().is_err() {
            return Err(ConfigError::Invalid {
                name: "SCRIGNO_BIND",
                message: format!("`{bind}` is not a valid socket address"),
            });
        }

        Ok(Self {
            database_url,
            bind,
            blob_dir,
        })
    }
}

fn required(name: &'static str) -> Result<String, ConfigError> {
    match env::var(name) {
        Ok(value) if !value.is_empty() => Ok(value),
        _ => Err(ConfigError::Missing(name)),
    }
}
