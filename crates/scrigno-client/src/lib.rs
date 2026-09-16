//! HTTP client, local SQLite store, and sync engine for Scrigno. This is the **only** crate with
//! network access and local persistence: it calls `scrigno-core` for every cryptographic
//! operation and never re-implements any of it. See `docs/ARCHITECTURE.md §4` (local store) and
//! `§5` (sync algorithm) for the normative spec this crate implements.
//!
//! # Public API
//! One async type, in two states modelled by the type system: [`Vault`] (locked — local store
//! open, no master key in memory) and [`UnlockedVault`] (master key in memory; every
//! crypto-touching operation lives here). Both the `scrigno-cli` binary and the future Tauri
//! commands (`apps/mobile/src-tauri`, milestone M4) are thin wrappers over this type — if a
//! capability doesn't exist here, it doesn't belong in either front end.
//!
//! ```no_run
//! # async fn example() -> Result<(), scrigno_client::ClientError> {
//! use secrecy::SecretString;
//! use std::path::Path;
//!
//! let locked = scrigno_client::Vault::open(Path::new("/tmp/scrigno-example"))?;
//! let passphrase = SecretString::from("correct horse battery staple".to_string());
//! let token = SecretString::from("dev-token".to_string());
//! let mut vault = locked
//!     .create("http://127.0.0.1:8787", token, &passphrase)
//!     .await?;
//! let _summary = vault
//!     .add(
//!         std::io::Cursor::new(b"hello".to_vec()),
//!         "Titolo".to_string(),
//!         vec![],
//!         String::new(),
//!         "text/plain".to_string(),
//!         "hello.txt".to_string(),
//!     )
//!     .await?;
//! let _report = vault.sync().await?;
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

mod error;
mod http;
mod store;
mod sync;
mod types;
mod vault;
mod wire;

pub use error::{ClientError, Result};
pub use types::{DocSummary, SyncReport, SyncWarning};
pub use vault::{UnlockedVault, Vault, debug_raw_changes};

#[cfg(all(test, feature = "ts-export"))]
mod ts_export_tests {
    use super::*;

    /// Exports every `ts-rs`-derived type in this crate's public API to
    /// `apps/mobile/src/bindings/` (run via `just bindings` /
    /// `cargo test -p scrigno-client --features ts-export export_bindings`).
    ///
    /// `cargo test` runs with the crate's own manifest directory
    /// (`crates/scrigno-client/`) as the current directory, and each type's `#[ts(export_to =
    /// "../../apps/mobile/src/bindings/")]` is already relative to that directory — so the
    /// `Config`'s own output dir must be the empty/"current dir" base (ts-rs's own default,
    /// `./bindings`, would instead land these one level too deep).
    #[test]
    fn export_bindings() {
        let cfg = ts_rs::Config::new().with_out_dir(".");
        <DocSummary as ts_rs::TS>::export(&cfg).expect("export DocSummary bindings");
        <SyncWarning as ts_rs::TS>::export(&cfg).expect("export SyncWarning bindings");
        <SyncReport as ts_rs::TS>::export(&cfg).expect("export SyncReport bindings");
    }
}
