//! Local, plaintext persistence of the server URL, bearer token, and auto-lock setting.
//!
//! `docs/ARCHITECTURE.md §7` describes `server_url`/`token` as living in the SQLite `kv` table.
//! `scrigno-client` persists `server_url` there but **deliberately does not persist the bearer
//! token** (each caller re-supplies it — a reasonable choice for a stateless CLI tool, per that
//! crate's own docs on `Vault::unlock`). Reopening that cross-crate design decision mid-milestone
//! is out of scope here, so this Tauri-app layer persists `server_url` + `token` itself, in a
//! small JSON file under `app_data_dir` — **not** inside `scrigno-client`'s own SQLite file. This
//! is a deliberate, documented deviation from §7's literal "stored in the kv table" wording;
//! functionally equivalent: still local-only, never sent anywhere but to the configured server.
//! Written once on `vault_create`/`vault_join`, read on every subsequent `vault_unlock`.
//!
//! Sensitivity: this file's contents are the same class as the token itself
//! (`docs/CRYPTO.md §6` — "not part of the confidentiality design ... if it leaks, an attacker
//! can delete/add ciphertext but cannot read anything"). Plaintext-on-disk is an accepted
//! trade-off; this module must never log its contents.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::types::AppError;

const CONFIG_FILE_NAME: &str = "config.json";

/// Default auto-lock timeout, in minutes (`docs/CRYPTO.md §5.2`).
pub const DEFAULT_AUTO_LOCK_MINUTES: u32 = 5;
/// Lower bound of the configurable auto-lock range (`docs/CRYPTO.md §5.2`: "configurable 1–30").
pub const MIN_AUTO_LOCK_MINUTES: u32 = 1;
/// Upper bound of the configurable auto-lock range.
pub const MAX_AUTO_LOCK_MINUTES: u32 = 30;

/// Persisted app-layer configuration. Never contains MK/DEK/KEK/passphrase — only the bearer
/// token, which `docs/CRYPTO.md §6` explicitly scopes out of the confidentiality design.
///
/// Deliberately **not** `#[derive(Debug)]`: `token` is a bearer credential and `server_url` can
/// carry embedded auth info (`CLAUDE.md`: "never log ... tokens"). No `Debug` impl means a stray
/// `tracing::debug!("{:?}", cfg)` fails to compile instead of silently leaking it later.
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct AppConfig {
    pub server_url: String,
    pub token: String,
    #[serde(default = "default_auto_lock_minutes")]
    pub auto_lock_minutes: u32,
}

fn default_auto_lock_minutes() -> u32 {
    DEFAULT_AUTO_LOCK_MINUTES
}

fn config_path(data_dir: &Path) -> PathBuf {
    data_dir.join(CONFIG_FILE_NAME)
}

/// Reads the config file if it exists and parses cleanly. `None` for a fresh data dir, or one
/// whose config file is missing/corrupt (never panics, never logs the bytes read).
pub(crate) fn load(data_dir: &Path) -> Option<AppConfig> {
    let bytes = std::fs::read(config_path(data_dir)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Writes the config file (creating or overwriting it). Never logs `config`'s contents.
///
/// # Errors
/// [`AppError`] with code `config_error` if the file can't be serialized or written.
pub(crate) fn save(data_dir: &Path, config: &AppConfig) -> Result<(), AppError> {
    let bytes = serde_json::to_vec(config).map_err(|_| AppError::config_error())?;
    std::fs::create_dir_all(data_dir).map_err(|_| AppError::config_error())?;
    let path = config_path(data_dir);
    std::fs::write(&path, bytes).map_err(|_| AppError::config_error())?;
    restrict_permissions(&path)
}

/// Restricts the config file to owner-only read/write (`0600`). The file holds the bearer token
/// in plaintext (see module docs); a leaked token only lets an attacker vandalize the vault
/// (`docs/CRYPTO.md §6`), but there is no reason to leave it group/world-readable when a one-line
/// fix closes that gap — matches the precedent `docs/CRYPTO.md §5.2` sets for the (M5)
/// device-secret file. No-op on non-Unix platforms (no equivalent bit to set).
#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<(), AppError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|_| AppError::config_error())
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<(), AppError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory under the OS temp dir, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "scrigno-tauri-configtest-{label}-{}",
                uuid::Uuid::now_v7()
            ));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn load_returns_none_for_a_fresh_data_dir() {
        let dir = TempDir::new("fresh");
        assert!(load(&dir.0).is_none());
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = TempDir::new("roundtrip");
        let cfg = AppConfig {
            server_url: "http://127.0.0.1:8787".to_string(),
            token: "dev-token".to_string(),
            auto_lock_minutes: 10,
        };
        save(&dir.0, &cfg).expect("save should succeed");

        let loaded = load(&dir.0).expect("load should find the just-saved config");
        assert_eq!(loaded.server_url, cfg.server_url);
        assert_eq!(loaded.token, cfg.token);
        assert_eq!(loaded.auto_lock_minutes, cfg.auto_lock_minutes);
    }

    #[cfg(unix)]
    #[test]
    fn save_sets_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new("perms");
        let cfg = AppConfig {
            server_url: "http://127.0.0.1:8787".to_string(),
            token: "dev-token".to_string(),
            auto_lock_minutes: 10,
        };
        save(&dir.0, &cfg).expect("save should succeed");

        let mode = std::fs::metadata(config_path(&dir.0))
            .expect("stat config file")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn load_returns_none_for_corrupt_json() {
        let dir = TempDir::new("corrupt");
        std::fs::write(config_path(&dir.0), b"not json").expect("write corrupt file");
        assert!(load(&dir.0).is_none());
    }
}
