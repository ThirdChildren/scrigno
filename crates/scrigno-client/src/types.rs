//! Types this crate's public API returns that are also useful to the eventual UI.
//!
//! `#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]` types are exported to
//! `apps/mobile/src/bindings/` by the `export_bindings` test in `src/lib.rs` (run via
//! `just bindings`). Ids and timestamps are plain `String` here (not `uuid::Uuid` /
//! `chrono::DateTime`) to keep the TS-exported shape identical to `docs/ARCHITECTURE.md §3`'s
//! own TS block (`id: string`, `created_at: string`, …) without pulling in extra `ts-rs`
//! feature flags for a handful of fields.
//!
//! Deliberately `ts(export_to = "...")` **without** `ts(export)`: the latter would also generate
//! its own per-type `#[test] fn export_bindings_<type>()` using `ts_rs::Config::from_env()`
//! (default output dir `./bindings`, i.e. relative to `crate::CARGO_MANIFEST_DIR/bindings`) —
//! landing one directory level off from the path this crate's own `export_bindings` test in
//! `src/lib.rs` uses (see that test's doc comment). Keeping only `export_to` still gives every
//! type a correct `output_path()` for the explicit `TS::export(&cfg)` calls there, with a single
//! source of truth for where bindings land.

use serde::{Deserialize, Serialize};

/// A client-owned projection of one document: the decrypted [`scrigno_core::meta::DocMeta`]
/// fields (minus `thumb` — per `docs/ARCHITECTURE.md §6`'s `docs_list` note, the thumbnail is
/// fetched separately on demand) plus local sync bookkeeping the UI/CLI needs to render a list
/// and know what will happen on the next `sync()`.
///
/// Rebuilt entirely in memory from `enc_meta` on unlock ([`crate::vault::Vault::unlock`]);
/// never persisted in decrypted form (`docs/CRYPTO.md §5.3`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts-export",
    ts(export_to = "../../apps/mobile/src/bindings/")
)]
pub struct DocSummary {
    /// Document id (`UUIDv7`), as a string.
    pub id: String,
    /// User-chosen title.
    pub title: String,
    /// User-chosen tags.
    pub tags: Vec<String>,
    /// Free-text note.
    pub note: String,
    /// MIME type of the underlying blob.
    pub mime: String,
    /// Plaintext size in bytes.
    pub size: i64,
    /// Hex-encoded BLAKE3 hash of the plaintext.
    pub content_hash: String,
    /// Original file name as chosen by the user.
    pub original_name: String,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
    /// The local row's version. Equal to `base_version` when the row is not `dirty`.
    pub version: i64,
    /// `true` if this row has a local change not yet pushed to the server.
    pub dirty: bool,
    /// `true` if the blob must always be kept in the local cache (never LRU-evicted).
    pub keep_offline: bool,
    /// Size in bytes of the encrypted blob on the server (ciphertext size, not `size`).
    pub blob_size: i64,
    /// `true` if the blob's ciphertext is currently present in the local cache.
    pub cached: bool,
}

/// One non-fatal condition observed during a [`crate::vault::UnlockedVault::sync`] call. Never
/// pre-localized to Italian in this crate (CLAUDE.md: UI strings live in
/// `apps/mobile/src/i18n/it.ts`, never hard-coded in Rust); the UI maps `kind`/fields to a
/// phrase at render time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts-export",
    ts(export_to = "../../apps/mobile/src/bindings/")
)]
#[serde(tag = "kind")]
pub enum SyncWarning {
    /// A change record's `server_seq` was behind the local cursor: the server's change history
    /// went backwards, most likely restored from an earlier backup (`docs/CRYPTO.md §7`).
    ServerRollback {
        /// The document id the out-of-order record was for.
        doc_id: String,
        /// The local cursor at the time the record was observed.
        cursor: i64,
        /// The record's own `server_seq`, which was `<= cursor`.
        server_seq: i64,
    },
}

/// Outcome of one [`crate::vault::UnlockedVault::sync`] call.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "ts-export", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts-export",
    ts(export_to = "../../apps/mobile/src/bindings/")
)]
pub struct SyncReport {
    /// Number of remote change records applied locally (including conflict copies created).
    pub pulled: u32,
    /// Number of local dirty rows successfully pushed to the server.
    pub pushed: u32,
    /// Number of conflict copies created during this call.
    pub conflicts: u32,
    /// Non-fatal warnings observed during this call.
    pub warnings: Vec<SyncWarning>,
}
