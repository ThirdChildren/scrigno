//! Error types for `scrigno-core`.
//!
//! Every variant carries a fixed, non-sensitive message: no key material, plaintext,
//! passphrase, or parsed-but-unverified data ever appears in a `Display`/`Debug` impl, per
//! `docs/CRYPTO.md` §9 ("no plaintext or key in any … error message").

use thiserror::Error;

/// Errors produced by `scrigno-core`.
///
/// Deliberately data-free: every variant is a fixed message, so it is always safe to log or
/// return to a caller verbatim without risking a key, passphrase, or plaintext leaking into a
/// log line or an HTTP error body.
#[derive(Debug, Error, PartialEq, Eq, Clone, Copy)]
pub enum Error {
    /// The `version` byte of a parsed envelope is not one this crate understands. Checked
    /// before any other part of the input is interpreted.
    #[error("unsupported format version")]
    UnsupportedVersion,

    /// The input could not be parsed: wrong length, truncated, or otherwise structurally
    /// invalid. Returned instead of panicking on any out-of-range slice.
    #[error("malformed input")]
    Malformed,

    /// AEAD authentication failed: wrong key, tampered ciphertext/tag/nonce, or associated
    /// data (AAD) that does not match the record the ciphertext was sealed for.
    #[error("authentication failed")]
    Authentication,

    /// Argon2id parameters requested for a *new* keyslot are below the enforced security
    /// floor (m=19456 KiB, t=2, p=1 — CRYPTO.md §3). Parameters read back from an existing
    /// keyslot are never checked against this floor, so raising it later never breaks an
    /// existing vault.
    #[error("kdf parameters are below the minimum security floor")]
    KdfParamsTooWeak,

    /// The Argon2id parameters themselves are structurally invalid (e.g. zero threads, or an
    /// output length Argon2 refuses), independent of the security-floor check above.
    #[error("invalid kdf parameters")]
    InvalidKdfParams,

    /// A recovery code failed to parse: wrong length once decoded, or an invalid character.
    #[error("invalid recovery code")]
    InvalidRecoveryCode,

    /// An underlying primitive (the OS RNG, the AEAD cipher, or `serde_json`) reported an
    /// error that should not be reachable through this crate's public API in ordinary use
    /// (e.g. `OsRng` failing, or STREAM counter exhaustion after more than 2^32 chunks).
    /// Propagated rather than panicking, per this crate's no-panic-on-any-input policy.
    #[error("internal cryptographic operation failed")]
    Internal,
}
