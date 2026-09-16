//! Pure crypto and domain types for Scrigno. No I/O, no network, no async.
//! See `docs/CRYPTO.md` for the normative spec this crate implements.
//!
//! The only part of this crate that touches `std::io` at all is [`blob`], and only as the
//! `std::io::{Read, Write}` adapter boundary its own module doc describes: it wraps a
//! caller-supplied reader/writer and never opens a file, a socket, or spawns a thread itself.
//! Every other module is pure `bytes in, bytes/types out`.
//!
//! # Layout
//! - [`ids`] — typed `VaultId`/`DocId`/`KeyslotId` newtypes over `Uuid`.
//! - [`keys`] — the three 256-bit key types (`MasterKey`, `Dek`, `Kek`): zeroizing, no
//!   `Clone`, no byte-revealing `Debug`.
//! - [`kdf`] — Argon2id parameters and derivation (`docs/CRYPTO.md` §3).
//! - [`wrap`] — the 73-byte `WrappedKey` envelope (`docs/CRYPTO.md` §4.1).
//! - [`keyslot`] — the `Keyslot` JSON record (`docs/CRYPTO.md` §4.2).
//! - [`meta`] — `DocMeta`/`EncMeta`, encrypted document metadata (`docs/CRYPTO.md` §4.3).
//! - [`blob`] — streaming encrypted file content, the `SCRG` format (`docs/CRYPTO.md` §4.4).
//! - [`recovery`] — recovery code generation/parsing (`docs/CRYPTO.md` §3).
//! - [`error`] — the crate's single `Error` enum.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod codec;
mod rng;

pub mod blob;
pub mod error;
pub mod ids;
pub mod kdf;
pub mod keys;
pub mod keyslot;
pub mod meta;
pub mod recovery;
pub mod wrap;

pub use error::Error;
