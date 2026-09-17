//! Types shared with the frontend over `tauri::ipc` (JSON) and, for this fixed subset, exported
//! to TypeScript via `ts-rs` (`docs/ARCHITECTURE.md §6`: "Types shared with TS: ... `Settings`,
//! `AppError`, `VaultStatus`"). `DocSummary`/`SyncReport`/`SyncWarning` are already exported by
//! `scrigno-client` itself into `apps/mobile/src/bindings/`.
//!
//! `DocMeta` (`scrigno_core::meta::DocMeta`, `doc_get_meta`'s return type) is **not** exported by
//! anyone yet: `scrigno-core` doesn't have `ts-rs` wired in at all, and adding it there is out of
//! this crate's scope (`crates/*` is read-only for `tauri-mobile`). `doc_get_meta` still works at
//! runtime (the type derives `serde::Serialize`, which is all IPC needs), but the frontend has no
//! generated TS type for it yet — see this milestone's report for the follow-up.

use serde::{Deserialize, Serialize};

/// `{ code, message }`: the error shape every Tauri command returns (`CLAUDE.md`: "`AppError`
/// serializes to `{ code, message }` with `code` from a fixed list the UI can translate").
///
/// `code` is stable, machine-readable, and the thing the UI should switch/translate on (Italian
/// strings live in `apps/mobile/src/i18n/it.ts`, never hard-coded in Rust). `message` is an
/// English, non-sensitive detail string (never a path, SQL, or key material) — a reasonable
/// fallback/log line, not meant to be shown to the user verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-export", ts(export_to = "../src/bindings/"))]
pub struct AppError {
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.message, self.code)
    }
}

impl std::error::Error for AppError {}

/// `vault_status`'s return type (`docs/ARCHITECTURE.md §6`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-export", ts(export_to = "../src/bindings/"))]
#[serde(rename_all = "lowercase")]
pub enum VaultStatus {
    /// No data dir has been bound to a vault yet (`Vault::is_initialised() == false`).
    Uninitialised,
    /// Bound to a vault (`create`/`join` has run on this device, or on a copy of this store), but
    /// the master key is not currently in memory.
    Locked,
    /// The master key is in memory.
    Unlocked,
}

/// `settings_get`/`settings_set`'s payload (`docs/ARCHITECTURE.md §6`).
///
/// `server_url` is read-only after the vault is created/joined (`docs/ARCHITECTURE.md §7`):
/// `commands::settings_set` silently ignores an attempt to change it rather than erroring, so a
/// caller that round-trips `settings_get`'s output through `settings_set` unchanged never fails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts-export", ts(export_to = "../src/bindings/"))]
pub struct Settings {
    /// Inactivity timeout in minutes before the vault auto-locks (`docs/CRYPTO.md §5.2`), 1–30,
    /// default 5.
    pub auto_lock_minutes: u32,
    /// Local blob cache size limit in MiB (`docs/ARCHITECTURE.md §4`), default 512. Only
    /// changeable while unlocked (backed by `UnlockedVault::set_cache_limit_mb`).
    pub cache_limit_mb: i64,
    /// The server URL entered at setup. Read-only after `vault_create`/`vault_join`.
    pub server_url: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_json_round_trips() {
        let settings = Settings {
            auto_lock_minutes: 7,
            cache_limit_mb: 1024,
            server_url: "http://127.0.0.1:8787".to_string(),
        };
        let json = serde_json::to_string(&settings).expect("serialize");
        let back: Settings = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, settings);
    }

    #[test]
    fn vault_status_serializes_as_lowercase_strings() {
        assert_eq!(
            serde_json::to_string(&VaultStatus::Uninitialised).unwrap(),
            "\"uninitialised\""
        );
        assert_eq!(
            serde_json::to_string(&VaultStatus::Locked).unwrap(),
            "\"locked\""
        );
        assert_eq!(
            serde_json::to_string(&VaultStatus::Unlocked).unwrap(),
            "\"unlocked\""
        );
    }

    #[test]
    fn app_error_json_round_trips() {
        let err = AppError {
            code: "not_found".to_string(),
            message: "document not found".to_string(),
        };
        let json = serde_json::to_string(&err).expect("serialize");
        let back: AppError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, err);
    }
}

#[cfg(all(test, feature = "ts-export"))]
mod ts_export_tests {
    use super::*;

    /// Exports every `ts-rs`-derived type owned by this crate to `apps/mobile/src/bindings/`
    /// (`cargo test --features ts-export export_bindings`, run from `apps/mobile/src-tauri/`;
    /// `just bindings` at the repo root runs this too). Mirrors `scrigno-client`'s own
    /// `export_bindings` test (`crates/scrigno-client/src/lib.rs`): `cargo test`'s cwd is this
    /// crate's manifest directory (`apps/mobile/src-tauri/`), and each type's `export_to` is
    /// already relative to that — so `Config`'s own output dir must be the empty/current-dir base
    /// rather than `ts-rs`'s own default (`./bindings`), which would land these one directory too
    /// deep.
    #[test]
    fn export_bindings() {
        let cfg = ts_rs::Config::new().with_out_dir(".");
        <AppError as ts_rs::TS>::export(&cfg).expect("export AppError bindings");
        <VaultStatus as ts_rs::TS>::export(&cfg).expect("export VaultStatus bindings");
        <Settings as ts_rs::TS>::export(&cfg).expect("export Settings bindings");
    }
}
