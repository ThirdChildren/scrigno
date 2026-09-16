//! `WrappedKey`: the 73-byte envelope used both to wrap the master key under a
//! passphrase/recovery KEK, and to wrap a per-document DEK under the master key.
//! See `docs/CRYPTO.md` §4.1.
//!
//! Two distinct AAD variants exist (MK-under-KEK vs. DEK-under-MK); to make it impossible to
//! call one with the wrong AAD, this module exposes four separate functions
//! ([`wrap_mk`]/[`unwrap_mk`]/[`wrap_dek`]/[`unwrap_dek`]) instead of one generic
//! `wrap_key`/`unwrap_key` pair with an AAD parameter a caller could get wrong.

use aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Key as ChaKey, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::codec::{base64_decode, base64_encode};
use crate::error::Error;
use crate::ids::{DocId, KeyslotId, VaultId};
use crate::keys::{Dek, Kek, MasterKey};
use crate::rng::fill_random;

const VERSION: u8 = 0x01;
const NONCE_LEN: usize = 24;
const CIPHERTEXT_LEN: usize = 48; // 32-byte key + 16-byte Poly1305 tag
/// Total wire length of a `WrappedKey`: `1 (version) + 24 (nonce) + 48 (ciphertext)`.
pub const WRAPPED_KEY_LEN: usize = 1 + NONCE_LEN + CIPHERTEXT_LEN;

const MK_AAD_PREFIX: &[u8] = b"scrigno/mk/v1";
const DEK_AAD_PREFIX: &[u8] = b"scrigno/dek/v1";

/// A 32-byte key sealed with XChaCha20-Poly1305, either a `MasterKey` under a `Kek` or a `Dek`
/// under a `MasterKey`. See `docs/CRYPTO.md` §4.1 for the exact byte layout. Serializes to/from
/// JSON as a standard base64 string (`docs/CRYPTO.md` §4.2's `"wrapped_mk"` field).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedKey {
    nonce: [u8; NONCE_LEN],
    ciphertext: [u8; CIPHERTEXT_LEN],
}

impl WrappedKey {
    /// Encodes to the raw 73-byte wire format: `version(1) || nonce(24) || ciphertext(48)`.
    #[must_use]
    pub fn as_bytes(&self) -> [u8; WRAPPED_KEY_LEN] {
        let mut out = [0u8; WRAPPED_KEY_LEN];
        out[0] = VERSION;
        out[1..=NONCE_LEN].copy_from_slice(&self.nonce);
        out[1 + NONCE_LEN..].copy_from_slice(&self.ciphertext);
        out
    }

    /// Parses a `WrappedKey` from exactly 73 bytes.
    ///
    /// Checks the version byte first (cheap, via the first byte only), then the exact total
    /// length, before slicing anything else — never panics on malformed input, per this
    /// crate's parsing rule.
    ///
    /// # Errors
    /// [`Error::UnsupportedVersion`] if the first byte isn't `0x01`; [`Error::Malformed`] if
    /// the input isn't exactly 73 bytes or is empty.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        match bytes.first() {
            Some(&VERSION) => {}
            Some(_) => return Err(Error::UnsupportedVersion),
            None => return Err(Error::Malformed),
        }
        if bytes.len() != WRAPPED_KEY_LEN {
            return Err(Error::Malformed);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[1..=NONCE_LEN]);
        let mut ciphertext = [0u8; CIPHERTEXT_LEN];
        ciphertext.copy_from_slice(&bytes[1 + NONCE_LEN..]);
        Ok(Self { nonce, ciphertext })
    }
}

impl Serialize for WrappedKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64_encode(&self.as_bytes()))
    }
}

impl<'de> Deserialize<'de> for WrappedKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = base64_decode(&s).ok_or_else(|| serde::de::Error::custom("invalid base64"))?;
        WrappedKey::from_slice(&bytes).map_err(|_| serde::de::Error::custom("invalid wrapped key"))
    }
}

/// Wraps the vault's master key under a KEK derived from a passphrase or recovery code.
/// AAD: `b"scrigno/mk/v1" || vault_id (16 B) || keyslot_id (16 B)` (`docs/CRYPTO.md` §4.1).
///
/// # Errors
/// [`Error::Internal`] if `OsRng` or the underlying AEAD cipher reports a failure (should not
/// happen in practice, but is propagated rather than panicking).
pub fn wrap_mk(
    kek: &Kek,
    vault_id: VaultId,
    keyslot_id: KeyslotId,
    mk: &MasterKey,
) -> Result<WrappedKey, Error> {
    let aad = mk_aad(vault_id, keyslot_id);
    seal(kek.as_bytes(), &aad, mk.as_bytes())
}

/// Unwraps a vault's master key from its keyslot.
///
/// `vault_id` and `keyslot_id` must come from the caller's own record of which keyslot this
/// is, never parsed out of the (unauthenticated) `wrapped` bytes themselves.
///
/// # Errors
/// [`Error::Authentication`] if `kek`, `vault_id` or `keyslot_id` don't match what the key was
/// wrapped for, or the ciphertext/nonce/tag was tampered with. [`Error::UnsupportedVersion`] /
/// [`Error::Malformed`] if `wrapped` is not a well-formed `WrappedKey`.
pub fn unwrap_mk(
    kek: &Kek,
    vault_id: VaultId,
    keyslot_id: KeyslotId,
    wrapped: &WrappedKey,
) -> Result<MasterKey, Error> {
    let aad = mk_aad(vault_id, keyslot_id);
    let bytes = open(kek.as_bytes(), &aad, wrapped)?;
    Ok(MasterKey::from_bytes(bytes))
}

/// Wraps a document's DEK under the vault's master key.
/// AAD: `b"scrigno/dek/v1" || doc_id (16 B)` (`docs/CRYPTO.md` §4.1).
///
/// # Errors
/// [`Error::Internal`] if `OsRng` or the underlying AEAD cipher reports a failure.
pub fn wrap_dek(mk: &MasterKey, doc_id: DocId, dek: &Dek) -> Result<WrappedKey, Error> {
    let aad = dek_aad(doc_id);
    seal(mk.as_bytes(), &aad, dek.as_bytes())
}

/// Unwraps a document's DEK.
///
/// `doc_id` must come from the caller's own document record, never parsed out of the
/// (unauthenticated) `wrapped` bytes themselves.
///
/// # Errors
/// [`Error::Authentication`] if `mk` or `doc_id` don't match what the key was wrapped for, or
/// the ciphertext/nonce/tag was tampered with. [`Error::UnsupportedVersion`] /
/// [`Error::Malformed`] if `wrapped` is not a well-formed `WrappedKey`.
pub fn unwrap_dek(mk: &MasterKey, doc_id: DocId, wrapped: &WrappedKey) -> Result<Dek, Error> {
    let aad = dek_aad(doc_id);
    let bytes = open(mk.as_bytes(), &aad, wrapped)?;
    Ok(Dek::from_bytes(bytes))
}

/// Test-only, deterministic variant of [`wrap_mk`] that takes an explicit nonce instead of one
/// from `OsRng`, so fixed test vectors are reproducible. Not reachable from production code.
#[cfg(test)]
pub(crate) fn wrap_mk_for_test(
    kek: &Kek,
    vault_id: VaultId,
    keyslot_id: KeyslotId,
    mk: &MasterKey,
    nonce: [u8; NONCE_LEN],
) -> WrappedKey {
    let aad = mk_aad(vault_id, keyslot_id);
    seal_with_nonce(kek.as_bytes(), &aad, mk.as_bytes(), nonce).expect("deterministic test seal")
}

/// Test-only, deterministic variant of [`wrap_dek`]. See [`wrap_mk_for_test`].
#[cfg(test)]
pub(crate) fn wrap_dek_for_test(
    mk: &MasterKey,
    doc_id: DocId,
    dek: &Dek,
    nonce: [u8; NONCE_LEN],
) -> WrappedKey {
    let aad = dek_aad(doc_id);
    seal_with_nonce(mk.as_bytes(), &aad, dek.as_bytes(), nonce).expect("deterministic test seal")
}

fn mk_aad(vault_id: VaultId, keyslot_id: KeyslotId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(MK_AAD_PREFIX.len() + 32);
    aad.extend_from_slice(MK_AAD_PREFIX);
    aad.extend_from_slice(&vault_id.as_bytes());
    aad.extend_from_slice(&keyslot_id.as_bytes());
    aad
}

fn dek_aad(doc_id: DocId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(DEK_AAD_PREFIX.len() + 16);
    aad.extend_from_slice(DEK_AAD_PREFIX);
    aad.extend_from_slice(&doc_id.as_bytes());
    aad
}

fn seal(key_bytes: &[u8; 32], aad: &[u8], plaintext: &[u8; 32]) -> Result<WrappedKey, Error> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    fill_random(&mut nonce_bytes)?;
    seal_with_nonce(key_bytes, aad, plaintext, nonce_bytes)
}

/// Same as [`seal`], but with a caller-supplied nonce instead of one from `OsRng`.
///
/// Only reachable from production code via [`seal`] (which always generates the nonce
/// itself); the only other caller is the `#[cfg(test)]` fixed-vector machinery below, per
/// `docs/CRYPTO.md` §8 ("production code has no way to supply a nonce").
fn seal_with_nonce(
    key_bytes: &[u8; 32],
    aad: &[u8],
    plaintext: &[u8; 32],
    nonce_bytes: [u8; NONCE_LEN],
) -> Result<WrappedKey, Error> {
    let cipher = XChaCha20Poly1305::new(&ChaKey::from(*key_bytes));
    let nonce = XNonce::from(nonce_bytes);

    // `buffer` holds the raw MK/DEK plaintext until `encrypt_in_place` overwrites it with
    // ciphertext; `Zeroizing` scrubs it on every exit path, including an early return on
    // encryption failure, per CLAUDE.md's "zeroize every buffer that held key material".
    let mut buffer: Zeroizing<Vec<u8>> = Zeroizing::new(plaintext.to_vec());
    cipher
        .encrypt_in_place(&nonce, aad, &mut *buffer)
        .map_err(|_| Error::Internal)?;
    if buffer.len() != CIPHERTEXT_LEN {
        return Err(Error::Internal);
    }
    let mut ciphertext = [0u8; CIPHERTEXT_LEN];
    ciphertext.copy_from_slice(&buffer);

    Ok(WrappedKey {
        nonce: nonce_bytes,
        ciphertext,
    })
}

fn open(key_bytes: &[u8; 32], aad: &[u8], wrapped: &WrappedKey) -> Result<[u8; 32], Error> {
    let cipher = XChaCha20Poly1305::new(&ChaKey::from(*key_bytes));
    let nonce = XNonce::from(wrapped.nonce);

    // `buffer` holds the raw unwrapped MK/DEK plaintext after a successful decrypt; `Zeroizing`
    // scrubs it on every exit path (including auth failure) once its bytes have been copied
    // into `plaintext` below, per CLAUDE.md's "zeroize every buffer that held key material".
    let mut buffer: Zeroizing<Vec<u8>> = Zeroizing::new(wrapped.ciphertext.to_vec());
    cipher
        .decrypt_in_place(&nonce, aad, &mut *buffer)
        .map_err(|_| Error::Authentication)?;
    if buffer.len() != 32 {
        return Err(Error::Internal);
    }
    let mut plaintext = [0u8; 32];
    plaintext.copy_from_slice(&buffer);
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> (VaultId, KeyslotId, DocId) {
        (
            VaultId::generate(),
            KeyslotId::generate(),
            DocId::generate(),
        )
    }

    #[test]
    fn mk_round_trips() {
        let (vault_id, keyslot_id, _) = ids();
        let kek = Kek::from_bytes_for_test([7u8; 32]);
        let mk = MasterKey::from_bytes_for_test([9u8; 32]);

        let wrapped = wrap_mk(&kek, vault_id, keyslot_id, &mk).unwrap();
        let unwrapped = unwrap_mk(&kek, vault_id, keyslot_id, &wrapped).unwrap();
        assert_eq!(unwrapped.as_bytes(), mk.as_bytes());
    }

    #[test]
    fn dek_round_trips() {
        let (_, _, doc_id) = ids();
        let mk = MasterKey::from_bytes_for_test([1u8; 32]);
        let dek = Dek::from_bytes_for_test([2u8; 32]);

        let wrapped = wrap_dek(&mk, doc_id, &dek).unwrap();
        let unwrapped = unwrap_dek(&mk, doc_id, &wrapped).unwrap();
        assert_eq!(unwrapped.as_bytes(), dek.as_bytes());
    }

    #[test]
    fn tamper_nonce_byte_fails_auth() {
        let (vault_id, keyslot_id, _) = ids();
        let kek = Kek::from_bytes_for_test([7u8; 32]);
        let mk = MasterKey::from_bytes_for_test([9u8; 32]);
        let mut wrapped = wrap_mk(&kek, vault_id, keyslot_id, &mk).unwrap();
        wrapped.nonce[0] ^= 0xff;
        assert_eq!(
            unwrap_mk(&kek, vault_id, keyslot_id, &wrapped).unwrap_err(),
            Error::Authentication
        );
    }

    #[test]
    fn tamper_ciphertext_byte_fails_auth() {
        let (vault_id, keyslot_id, _) = ids();
        let kek = Kek::from_bytes_for_test([7u8; 32]);
        let mk = MasterKey::from_bytes_for_test([9u8; 32]);
        let mut wrapped = wrap_mk(&kek, vault_id, keyslot_id, &mk).unwrap();
        wrapped.ciphertext[0] ^= 0xff;
        assert_eq!(
            unwrap_mk(&kek, vault_id, keyslot_id, &wrapped).unwrap_err(),
            Error::Authentication
        );
    }

    #[test]
    fn tamper_tag_byte_fails_auth() {
        let (vault_id, keyslot_id, _) = ids();
        let kek = Kek::from_bytes_for_test([7u8; 32]);
        let mk = MasterKey::from_bytes_for_test([9u8; 32]);
        let mut wrapped = wrap_mk(&kek, vault_id, keyslot_id, &mk).unwrap();
        let last = wrapped.ciphertext.len() - 1;
        wrapped.ciphertext[last] ^= 0xff;
        assert_eq!(
            unwrap_mk(&kek, vault_id, keyslot_id, &wrapped).unwrap_err(),
            Error::Authentication
        );
    }

    #[test]
    fn tamper_vault_id_fails_auth() {
        let (vault_id, keyslot_id, _) = ids();
        let other_vault = VaultId::generate();
        let kek = Kek::from_bytes_for_test([7u8; 32]);
        let mk = MasterKey::from_bytes_for_test([9u8; 32]);
        let wrapped = wrap_mk(&kek, vault_id, keyslot_id, &mk).unwrap();
        assert_eq!(
            unwrap_mk(&kek, other_vault, keyslot_id, &wrapped).unwrap_err(),
            Error::Authentication
        );
    }

    #[test]
    fn tamper_keyslot_id_fails_auth() {
        let (vault_id, keyslot_id, _) = ids();
        let other_slot = KeyslotId::generate();
        let kek = Kek::from_bytes_for_test([7u8; 32]);
        let mk = MasterKey::from_bytes_for_test([9u8; 32]);
        let wrapped = wrap_mk(&kek, vault_id, keyslot_id, &mk).unwrap();
        assert_eq!(
            unwrap_mk(&kek, vault_id, other_slot, &wrapped).unwrap_err(),
            Error::Authentication
        );
    }

    #[test]
    fn tamper_doc_id_fails_auth_for_dek() {
        let (_, _, doc_id) = ids();
        let other_doc = DocId::generate();
        let mk = MasterKey::from_bytes_for_test([1u8; 32]);
        let dek = Dek::from_bytes_for_test([2u8; 32]);
        let wrapped = wrap_dek(&mk, doc_id, &dek).unwrap();
        assert_eq!(
            unwrap_dek(&mk, other_doc, &wrapped).unwrap_err(),
            Error::Authentication
        );
    }

    #[test]
    fn from_slice_rejects_bad_version() {
        let mut bytes = [0u8; WRAPPED_KEY_LEN];
        bytes[0] = 0x02;
        assert_eq!(
            WrappedKey::from_slice(&bytes).unwrap_err(),
            Error::UnsupportedVersion
        );
    }

    #[test]
    fn from_slice_rejects_empty_and_wrong_length() {
        assert_eq!(WrappedKey::from_slice(&[]).unwrap_err(), Error::Malformed);
        let mut short = vec![VERSION];
        short.extend_from_slice(&[0u8; 10]);
        assert_eq!(
            WrappedKey::from_slice(&short).unwrap_err(),
            Error::Malformed
        );
    }

    #[test]
    fn json_round_trip_is_base64() {
        let (vault_id, keyslot_id, _) = ids();
        let kek = Kek::from_bytes_for_test([7u8; 32]);
        let mk = MasterKey::from_bytes_for_test([9u8; 32]);
        let wrapped = wrap_mk(&kek, vault_id, keyslot_id, &mk).unwrap();

        let json = serde_json::to_string(&wrapped).unwrap();
        assert!(json.starts_with('"') && json.ends_with('"'));
        let back: WrappedKey = serde_json::from_str(&json).unwrap();
        assert_eq!(back, wrapped);
    }

    /// Loads `tests/vectors/wrapped_key.json` (docs/CRYPTO.md §8) and checks that
    /// [`wrap_mk_for_test`] with the pinned inputs reproduces the exact committed ciphertext
    /// byte-for-byte, and that unwrapping it (via the normal, non-test [`unwrap_mk`]) recovers
    /// the expected master key.
    #[test]
    fn fixed_vector_wrapped_key() {
        let manifest: serde_json::Value =
            serde_json::from_str(include_str!("../tests/vectors/wrapped_key.json")).unwrap();

        let kek = Kek::from_bytes_for_test(from_hex_32(manifest["kek_hex"].as_str().unwrap()));
        let mk_bytes = from_hex_32(manifest["master_key_hex"].as_str().unwrap());
        let mk = MasterKey::from_bytes_for_test(mk_bytes);
        let vault_id = VaultId::from_uuid(
            uuid::Uuid::parse_str(manifest["vault_id"].as_str().unwrap()).unwrap(),
        );
        let keyslot_id = KeyslotId::from_uuid(
            uuid::Uuid::parse_str(manifest["keyslot_id"].as_str().unwrap()).unwrap(),
        );
        let nonce = from_hex_n::<NONCE_LEN>(manifest["nonce_hex"].as_str().unwrap());
        let expected = from_hex_vec(manifest["wrapped_key_hex"].as_str().unwrap());

        let wrapped = wrap_mk_for_test(&kek, vault_id, keyslot_id, &mk, nonce);
        assert_eq!(wrapped.as_bytes().to_vec(), expected);

        let unwrapped = unwrap_mk(&kek, vault_id, keyslot_id, &wrapped).unwrap();
        assert_eq!(unwrapped.as_bytes(), &mk_bytes);
    }

    fn from_hex_vec(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn from_hex_32(s: &str) -> [u8; 32] {
        let v = from_hex_vec(s);
        v.try_into().unwrap()
    }

    fn from_hex_n<const N: usize>(s: &str) -> [u8; N] {
        let v = from_hex_vec(s);
        v.try_into().unwrap_or_else(|_| panic!("wrong hex length"))
    }
}
