//! Server configuration loaded from environment variables.

use std::env;

/// Default bind address when `SCRIGNO_BIND` is not set.
const DEFAULT_BIND: &str = "127.0.0.1:8787";

/// Default `SCRIGNO_MAX_BLOB_BYTES` (200 MiB), matching `.env.example`.
const DEFAULT_MAX_BLOB_BYTES: u64 = 209_715_200;

/// Default `SCRIGNO_GC_INTERVAL_SECS` (one hour).
const DEFAULT_GC_INTERVAL_SECS: u64 = 3600;

/// Minimum acceptable length for `SCRIGNO_API_TOKEN`.
const MIN_TOKEN_LEN: usize = 32;

/// Errors that can occur while assembling [`Config`] from the process environment.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required environment variable {0}")]
    Missing(&'static str),
    #[error("invalid value for {name}: {message}")]
    Invalid { name: &'static str, message: String },
}

/// Server configuration, assembled once at startup.
#[derive(Clone)]
pub struct Config {
    /// Postgres connection string (`SCRIGNO_DATABASE_URL`).
    pub database_url: String,
    /// Address to bind the HTTP listener to (`SCRIGNO_BIND`, default `127.0.0.1:8787`).
    pub bind: String,
    /// Root directory for blob storage (`SCRIGNO_BLOB_DIR`).
    pub blob_dir: String,
    /// Bearer token every client must present on `/v1/*` (`SCRIGNO_API_TOKEN`).
    pub api_token: String,
    /// Maximum accepted blob upload size in bytes (`SCRIGNO_MAX_BLOB_BYTES`, default 200 MiB).
    pub max_blob_bytes: u64,
    /// Interval between blob GC sweeps, in seconds (`SCRIGNO_GC_INTERVAL_SECS`, default 3600).
    pub gc_interval_secs: u64,
}

// Manual Debug impl: never print the token, even in a `{:?}` of the config (e.g. in a panic
// message or an accidental `tracing::debug!(?config)`).
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("database_url", &"<redacted>")
            .field("bind", &self.bind)
            .field("blob_dir", &self.blob_dir)
            .field("api_token", &"<redacted>")
            .field("max_blob_bytes", &self.max_blob_bytes)
            .field("gc_interval_secs", &self.gc_interval_secs)
            .finish()
    }
}

impl Config {
    /// Load configuration from environment variables, failing fast with a descriptive error if
    /// anything required is missing or malformed.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if a required variable is missing, `SCRIGNO_API_TOKEN` is
    /// shorter than 32 characters, or any value fails to parse.
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

        let api_token = required("SCRIGNO_API_TOKEN")?;
        if api_token.len() < MIN_TOKEN_LEN {
            return Err(ConfigError::Invalid {
                name: "SCRIGNO_API_TOKEN",
                message: format!("must be at least {MIN_TOKEN_LEN} characters"),
            });
        }

        let max_blob_bytes = optional_u64("SCRIGNO_MAX_BLOB_BYTES", DEFAULT_MAX_BLOB_BYTES)?;
        let gc_interval_secs = optional_u64("SCRIGNO_GC_INTERVAL_SECS", DEFAULT_GC_INTERVAL_SECS)?;

        Ok(Self {
            database_url,
            bind,
            blob_dir,
            api_token,
            max_blob_bytes,
            gc_interval_secs,
        })
    }
}

fn required(name: &'static str) -> Result<String, ConfigError> {
    match env::var(name) {
        Ok(value) if !value.is_empty() => Ok(value),
        _ => Err(ConfigError::Missing(name)),
    }
}

fn optional_u64(name: &'static str, default: u64) -> Result<u64, ConfigError> {
    match env::var(name) {
        Ok(value) if !value.is_empty() => value.parse::<u64>().map_err(|_| ConfigError::Invalid {
            name,
            message: format!("`{value}` is not a valid non-negative integer"),
        }),
        _ => Ok(default),
    }
}
