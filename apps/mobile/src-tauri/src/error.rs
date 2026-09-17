//! Maps `scrigno_client::ClientError` (and this crate's own Tauri-layer failure modes) to
//! `types::AppError`'s `{ code, message }`. `CLAUDE.md`: "map `ClientError` to `AppError { code,
//! message }`... `code` from a fixed list the UI can translate... never leak internal paths, SQL
//! or key material".
//!
//! # `ClientError` → `AppError.code` mapping
//!
//! | `ClientError` variant | `code` |
//! |---|---|
//! | `Network` | `network_error` |
//! | `Unauthorized` | `unauthorized` |
//! | `Locked` | `vault_locked` |
//! | `WrongPassphrase` | `wrong_passphrase` |
//! | `Contention` | `sync_contention` |
//! | `ServerRollback` | `server_rollback` |
//! | `Storage` | `storage_error` |
//! | `Crypto` | `crypto_error` |
//! | `VaultExists` | `vault_exists` |
//! | `VaultNotInitialised` | `vault_not_initialised` |
//! | `NotFound` | `not_found` |
//! | `InvalidInput` | `invalid_input` |
//! | `ServerContract` | `server_contract_error` |
//!
//! Plus Tauri-layer-only codes, none of which carry a path/SQL/key material:
//! `quick_unlock_unavailable`, `already_unlocked`, `no_saved_credentials`, `config_error`,
//! `io_error`, `invalid_request`, `not_implemented`, `internal_error`.

use scrigno_client::ClientError;

use crate::types::AppError;

impl AppError {
    pub(crate) fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
        }
    }

    /// `vault_unlock_quick` on desktop (`docs/ARCHITECTURE.md §6`): no Stronghold/biometric
    /// device unlock store exists yet (that's M5). Always returned on this platform — a runtime
    /// feature-detection result (`CLAUDE.md`: "feature-detect on desktop"), not a compile-time
    /// `#[cfg]`, since the same binary should one day report this differently once M5 lands.
    pub(crate) fn quick_unlock_unavailable() -> Self {
        Self::new(
            "quick_unlock_unavailable",
            "quick unlock is not available on this platform",
        )
    }

    /// A command that needs an unlocked vault (master key in memory) was called while
    /// locked/uninitialised.
    pub(crate) fn not_unlocked() -> Self {
        Self::new("vault_locked", "the vault is locked")
    }

    /// `vault_create`/`vault_join` called while a vault is already unlocked in this process.
    pub(crate) fn already_unlocked() -> Self {
        Self::new(
            "already_unlocked",
            "a vault is already unlocked in this session",
        )
    }

    /// `vault_unlock` called with no locally persisted server URL/token
    /// (`crate::config::load` returned `None`) — the data dir was never bootstrapped via
    /// `vault_create`/`vault_join` on this device, or the local config file is missing/corrupt.
    pub(crate) fn no_saved_credentials() -> Self {
        Self::new(
            "no_saved_credentials",
            "no server URL or token saved for this device; set up the vault again",
        )
    }

    /// The local app-layer config file (`server_url`/`token`/`auto_lock_minutes`,
    /// `crate::config`) could not be read or written. Never includes the path or contents.
    pub(crate) fn config_error() -> Self {
        Self::new(
            "config_error",
            "could not read or write local configuration",
        )
    }

    /// A local file (`doc_add_from_path`) could not be opened/read. Never includes the path.
    pub(crate) fn io_error() -> Self {
        Self::new("io_error", "could not read the selected file")
    }

    /// `doc_add_bytes`'s `x-scrigno-meta` header was missing, not valid UTF-8, not the expected
    /// JSON shape, or the request body was not raw bytes.
    pub(crate) fn invalid_request() -> Self {
        Self::new("invalid_request", "malformed request")
    }

    /// A supplied value failed basic structural validation (e.g. `id` not a valid UUID, an
    /// auto-lock value out of range) before ever reaching `scrigno-client`.
    pub(crate) fn invalid_input(message: impl Into<String>) -> Self {
        Self::new("invalid_input", message)
    }

    /// A command not implemented on this platform/milestone (`doc_share`, deferred to M5 per
    /// `docs/ROADMAP.md`).
    pub(crate) fn not_implemented() -> Self {
        Self::new("not_implemented", "not implemented yet")
    }

    /// The in-memory vault slot (`state::AppState::slot`) was unexpectedly empty. Should be
    /// unreachable: every command path that `.take()`s it always puts something back, including
    /// on error (`state::AppState::reopen_locked`). Signals a bug, not user error.
    pub(crate) fn internal_state() -> Self {
        Self::new(
            "internal_error",
            "internal state error, please restart the app",
        )
    }
}

impl From<ClientError> for AppError {
    fn from(err: ClientError) -> Self {
        let code = match err {
            ClientError::Network => "network_error",
            ClientError::Unauthorized => "unauthorized",
            ClientError::Locked => "vault_locked",
            ClientError::WrongPassphrase => "wrong_passphrase",
            ClientError::Contention => "sync_contention",
            ClientError::ServerRollback => "server_rollback",
            ClientError::Storage => "storage_error",
            ClientError::Crypto => "crypto_error",
            ClientError::VaultExists => "vault_exists",
            ClientError::VaultNotInitialised => "vault_not_initialised",
            ClientError::NotFound => "not_found",
            ClientError::InvalidInput => "invalid_input",
            ClientError::ServerContract => "server_contract_error",
        };
        // `ClientError`'s `Display` is already documented (`crates/scrigno-client/src/error.rs`)
        // as safe to show verbatim: no paths, SQL, or key material in any variant's message.
        Self::new(code, err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_client_error_variant_maps_to_a_stable_non_empty_code() {
        let variants = [
            ClientError::Network,
            ClientError::Unauthorized,
            ClientError::Locked,
            ClientError::WrongPassphrase,
            ClientError::Contention,
            ClientError::ServerRollback,
            ClientError::Storage,
            ClientError::Crypto,
            ClientError::VaultExists,
            ClientError::VaultNotInitialised,
            ClientError::NotFound,
            ClientError::InvalidInput,
            ClientError::ServerContract,
        ];
        for variant in variants {
            let message = variant.to_string();
            let app_err = AppError::from(variant);
            assert!(!app_err.code.is_empty());
            assert_eq!(app_err.message, message);
        }
    }

    #[test]
    fn helper_constructors_never_embed_a_path_looking_string() {
        let errors = [
            AppError::quick_unlock_unavailable(),
            AppError::not_unlocked(),
            AppError::already_unlocked(),
            AppError::no_saved_credentials(),
            AppError::config_error(),
            AppError::io_error(),
            AppError::invalid_request(),
            AppError::not_implemented(),
            AppError::internal_state(),
        ];
        for err in errors {
            assert!(!err.code.is_empty());
            assert!(!err.message.contains('/'));
            assert!(!err.message.contains('\\'));
        }
    }
}
