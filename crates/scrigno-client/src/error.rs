//! [`ClientError`]: the single error type returned by every public `scrigno-client` API.
//!
//! Every variant carries a fixed, non-sensitive message (no paths, SQL, key material, tokens or
//! passphrases — CLAUDE.md: "Never leak internal paths, SQL or key material in error messages").
//! The Tauri layer (M4) maps these 1:1 to Italian strings for the UI; the CLI (this milestone)
//! prints the `Display` text directly, which is why it must already be safe to show verbatim.

use thiserror::Error;

/// Errors produced by `scrigno-client`.
#[derive(Debug, Error)]
pub enum ClientError {
    /// A network request failed: connection refused/timed out, DNS failure, TLS error, or the
    /// server was unreachable. Never carries the URL or any response body.
    #[error("network error")]
    Network,

    /// The server rejected the request's bearer token (`401`).
    #[error("unauthorized")]
    Unauthorized,

    /// The vault is locked (no master key in memory). Reserved primarily for callers that hold a
    /// long-lived `Vault` across a lock/unlock cycle (the Tauri layer, M4) and attempt an
    /// operation while `Mutex<Option<UnlockedVault>>` is `None`; the CLI's type-state `Vault` /
    /// `UnlockedVault` split makes this unreachable at compile time within this crate itself.
    #[error("vault is locked")]
    Locked,

    /// The supplied passphrase does not unwrap the stored (or server-side) master key.
    #[error("wrong passphrase")]
    WrongPassphrase,

    /// Sync hit `412 version_mismatch` on the same document three rounds in a row (§5): another
    /// device is writing to the same document faster than this one can catch up.
    #[error("too many conflicting updates from another device, try syncing again shortly")]
    Contention,

    /// A change record's `server_seq` went backwards relative to the local cursor — the server
    /// was rolled back to an earlier backup (`docs/CRYPTO.md` §7's partial-rollback detection).
    /// The default `sync()` algorithm treats this as non-fatal and reports it via
    /// [`crate::types::SyncWarning`] instead of returning this variant; it exists so a caller
    /// that needs strict handling (or the Tauri layer surfacing a distinct error path) has a
    /// stable variant to match on.
    #[error("the server's change history went backwards (possible rollback)")]
    ServerRollback,

    /// The local SQLite store or blob cache could not be read/written (corrupt file, permission
    /// error, disk full, unexpected schema). Never includes the file path or SQL text.
    #[error("local storage error")]
    Storage,

    /// A `scrigno-core` cryptographic operation failed for a reason other than a wrong
    /// passphrase: a tampered/corrupt envelope, an unsupported format version, or an internal
    /// primitive failure.
    #[error("cryptographic operation failed")]
    Crypto,

    /// `Vault::create` was called against a server that already has a vault (`409 vault_exists`).
    #[error("a vault already exists on this server")]
    VaultExists,

    /// `Vault::join` was called against a server with no vault yet (`404 vault_not_initialised`).
    #[error("no vault has been created on this server yet")]
    VaultNotInitialised,

    /// The requested document id does not exist locally or on the server.
    #[error("document not found")]
    NotFound,

    /// Caller-supplied input was structurally invalid (e.g. an empty title, a malformed id).
    #[error("invalid input")]
    InvalidInput,

    /// The server responded with a shape or status this client does not understand. Signals a
    /// client/server contract mismatch rather than a transient failure.
    #[error("unexpected server response")]
    ServerContract,
}

/// Convenience alias used throughout this crate.
pub type Result<T> = std::result::Result<T, ClientError>;

impl From<rusqlite::Error> for ClientError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Storage
    }
}

impl From<std::io::Error> for ClientError {
    fn from(_: std::io::Error) -> Self {
        Self::Storage
    }
}

impl From<scrigno_core::Error> for ClientError {
    fn from(_: scrigno_core::Error) -> Self {
        // Authentication failures are `Crypto` by default (a tampered/corrupt envelope):
        // callers that need to distinguish "wrong passphrase" specifically (unwrapping the
        // master key from a keyslot) do so explicitly at the call site, see
        // `vault::mk_from_keyslot`, rather than through this blanket conversion — most
        // `Error::Authentication` occurrences in this crate (opening `EncMeta`, unwrapping a
        // document DEK) mean "corrupt local/server data", not "wrong passphrase".
        Self::Crypto
    }
}
