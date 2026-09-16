//! `EncMeta`: encrypted document metadata. See `docs/CRYPTO.md` §4.3.

use aead::{AeadInOut, KeyInit};
use chacha20poly1305::{Key as ChaKey, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::ids::DocId;
use crate::keys::MasterKey;
use crate::rng::fill_random;

const VERSION: u8 = 0x01;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = 1 + NONCE_LEN;
const TAG_LEN: usize = 16;
const AAD_PREFIX: &[u8] = b"scrigno/meta/v1";

/// Plaintext document metadata, sealed as [`EncMeta`] under the vault's master key.
///
/// Field order is the canonical JSON order from `docs/CRYPTO.md` §4.3 — **do not reorder
/// fields**: `serde_json` serializes struct fields in declaration order (not alphabetically),
/// and that declaration order is exactly what "canonical JSON" means for this format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocMeta {
    /// Metadata schema version.
    pub v: u32,
    /// User-chosen document title.
    pub title: String,
    /// User-chosen tags.
    pub tags: Vec<String>,
    /// Free-text note.
    pub note: String,
    /// MIME type of the underlying blob.
    pub mime: String,
    /// Plaintext size in bytes of the underlying blob.
    pub size: u64,
    /// Hex-encoded BLAKE3 hash of the plaintext blob (client-side dedup/integrity check).
    pub content_hash: String,
    /// The original file name as chosen by the user, kept for display/export.
    pub original_name: String,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
    /// Base64-encoded JPEG thumbnail (≤ 24 KiB), generated on-device, or `None`. This crate
    /// treats the base64 string as opaque; it never decodes or re-encodes the thumbnail bytes.
    pub thumb: Option<String>,
}

/// An encrypted [`DocMeta`] envelope: `version(1) || nonce(24) || ciphertext`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncMeta(Vec<u8>);

impl EncMeta {
    /// Raw wire bytes: `version(1) || nonce(24) || ciphertext(n+16)`.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Parses an `EncMeta` envelope from raw bytes *without* decrypting it (that requires
    /// [`open`] and the master key). Checks the version byte first, then the minimum length,
    /// before touching anything else — never panics on malformed input.
    ///
    /// # Errors
    /// [`Error::UnsupportedVersion`] if the first byte isn't `0x01`; [`Error::Malformed`] if
    /// the input is empty or shorter than a header plus AEAD tag.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        match bytes.first() {
            Some(&VERSION) => {}
            Some(_) => return Err(Error::UnsupportedVersion),
            None => return Err(Error::Malformed),
        }
        if bytes.len() < HEADER_LEN + TAG_LEN {
            return Err(Error::Malformed);
        }
        Ok(Self(bytes.to_vec()))
    }
}

/// Encrypts `meta` as canonical JSON under the vault's master key, bound to `doc_id` and
/// `doc_version` via AAD so a compromised server (or cache) cannot silently attach an older
/// `meta` to a newer record (`docs/CRYPTO.md` §4.3).
///
/// # Errors
/// [`Error::Internal`] if `OsRng`, JSON serialization, or the AEAD cipher reports a failure.
pub fn seal(
    mk: &MasterKey,
    doc_id: DocId,
    doc_version: u32,
    meta: &DocMeta,
) -> Result<EncMeta, Error> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    fill_random(&mut nonce_bytes)?;
    seal_with_nonce(mk, doc_id, doc_version, meta, nonce_bytes)
}

/// Test-only, deterministic variant of [`seal`] that takes an explicit nonce instead of one
/// from `OsRng`, so fixed test vectors are reproducible. Not reachable from production code
/// (`docs/CRYPTO.md` §8).
#[cfg(test)]
pub(crate) fn seal_for_test(
    mk: &MasterKey,
    doc_id: DocId,
    doc_version: u32,
    meta: &DocMeta,
    nonce: [u8; NONCE_LEN],
) -> EncMeta {
    seal_with_nonce(mk, doc_id, doc_version, meta, nonce).expect("deterministic test seal")
}

fn seal_with_nonce(
    mk: &MasterKey,
    doc_id: DocId,
    doc_version: u32,
    meta: &DocMeta,
    nonce_bytes: [u8; NONCE_LEN],
) -> Result<EncMeta, Error> {
    // `buffer` holds the plaintext DocMeta JSON (title/tags/note) until `encrypt_in_place`
    // overwrites it with ciphertext; `Zeroizing` scrubs it on every exit path, including an
    // early return on encryption failure, per CLAUDE.md's "zeroize every buffer that held ...
    // plaintext".
    let mut buffer: Zeroizing<Vec<u8>> =
        Zeroizing::new(serde_json::to_vec(meta).map_err(|_| Error::Internal)?);

    let cipher = XChaCha20Poly1305::new(&ChaKey::from(*mk.as_bytes()));
    let nonce = XNonce::from(nonce_bytes);
    let aad = build_aad(doc_id, doc_version);

    cipher
        .encrypt_in_place(&nonce, &aad, &mut *buffer)
        .map_err(|_| Error::Internal)?;

    let mut out = Vec::with_capacity(HEADER_LEN + buffer.len());
    out.push(VERSION);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&buffer);
    Ok(EncMeta(out))
}

/// Decrypts and parses an `EncMeta` envelope.
///
/// `doc_id` and `doc_version` must come from the caller's own document record — never parsed
/// out of unauthenticated input — and must match what the metadata was sealed for, or
/// authentication fails.
///
/// # Errors
/// [`Error::UnsupportedVersion`] / [`Error::Malformed`] for a structurally invalid envelope.
/// [`Error::Authentication`] if decryption fails: wrong key, tampered bytes, or a mismatched
/// `doc_id`/`doc_version`.
pub fn open(
    mk: &MasterKey,
    doc_id: DocId,
    doc_version: u32,
    enc: &EncMeta,
) -> Result<DocMeta, Error> {
    // `enc` was already validated by `EncMeta::from_bytes`/`seal`, but re-check defensively:
    // this function must never panic even if that invariant is violated by a future refactor.
    if enc.0.len() < HEADER_LEN + TAG_LEN {
        return Err(Error::Malformed);
    }
    match enc.0.first() {
        Some(&VERSION) => {}
        Some(_) => return Err(Error::UnsupportedVersion),
        None => return Err(Error::Malformed),
    }

    let mut nonce_bytes = [0u8; NONCE_LEN];
    nonce_bytes.copy_from_slice(&enc.0[1..HEADER_LEN]);
    // `buffer` holds the decrypted DocMeta JSON (title/tags/note) after a successful decrypt;
    // `Zeroizing` scrubs it on every exit path (including auth/parse failure), per CLAUDE.md's
    // "zeroize every buffer that held ... plaintext".
    let mut buffer: Zeroizing<Vec<u8>> = Zeroizing::new(enc.0[HEADER_LEN..].to_vec());

    let cipher = XChaCha20Poly1305::new(&ChaKey::from(*mk.as_bytes()));
    let nonce = XNonce::from(nonce_bytes);
    let aad = build_aad(doc_id, doc_version);

    cipher
        .decrypt_in_place(&nonce, &aad, &mut *buffer)
        .map_err(|_| Error::Authentication)?;

    serde_json::from_slice(&buffer).map_err(|_| Error::Malformed)
}

fn build_aad(doc_id: DocId, doc_version: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_PREFIX.len() + 16 + 4);
    aad.extend_from_slice(AAD_PREFIX);
    aad.extend_from_slice(&doc_id.as_bytes());
    aad.extend_from_slice(&doc_version.to_be_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_meta() -> DocMeta {
        DocMeta {
            v: 1,
            title: "Carta d'identità".to_owned(),
            tags: vec!["identità".to_owned(), "personale".to_owned()],
            note: "scade 2031".to_owned(),
            mime: "application/pdf".to_owned(),
            size: 183_422,
            content_hash: "deadbeef".to_owned(),
            original_name: "scan.pdf".to_owned(),
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            thumb: None,
        }
    }

    #[test]
    fn round_trips() {
        let mk = MasterKey::from_bytes_for_test([1u8; 32]);
        let doc_id = DocId::generate();
        let meta = sample_meta();

        let enc = seal(&mk, doc_id, 3, &meta).unwrap();
        let back = open(&mk, doc_id, 3, &enc).unwrap();
        assert_eq!(back, meta);
    }

    #[test]
    fn canonical_json_field_order() {
        let meta = sample_meta();
        let json = serde_json::to_string(&meta).unwrap();
        let order = [
            "\"v\"",
            "\"title\"",
            "\"tags\"",
            "\"note\"",
            "\"mime\"",
            "\"size\"",
            "\"content_hash\"",
            "\"original_name\"",
            "\"created_at\"",
            "\"thumb\"",
        ];
        let mut last = 0usize;
        for key in order {
            let idx = json.find(key).expect("key present");
            assert!(idx >= last, "field {key} out of canonical order");
            last = idx;
        }
    }

    #[test]
    fn tamper_version_byte_rejected() {
        let mk = MasterKey::from_bytes_for_test([1u8; 32]);
        let doc_id = DocId::generate();
        let mut enc = seal(&mk, doc_id, 1, &sample_meta()).unwrap();
        enc.0[0] = 0x02;
        assert_eq!(
            open(&mk, doc_id, 1, &enc).unwrap_err(),
            Error::UnsupportedVersion
        );
    }

    #[test]
    fn tamper_nonce_byte_fails_auth() {
        let mk = MasterKey::from_bytes_for_test([1u8; 32]);
        let doc_id = DocId::generate();
        let mut enc = seal(&mk, doc_id, 1, &sample_meta()).unwrap();
        enc.0[1] ^= 0xff;
        assert_eq!(
            open(&mk, doc_id, 1, &enc).unwrap_err(),
            Error::Authentication
        );
    }

    #[test]
    fn tamper_ciphertext_byte_fails_auth() {
        let mk = MasterKey::from_bytes_for_test([1u8; 32]);
        let doc_id = DocId::generate();
        let mut enc = seal(&mk, doc_id, 1, &sample_meta()).unwrap();
        let idx = enc.0.len() - 1;
        enc.0[idx] ^= 0xff;
        assert_eq!(
            open(&mk, doc_id, 1, &enc).unwrap_err(),
            Error::Authentication
        );
    }

    #[test]
    fn tamper_doc_id_fails_auth() {
        let mk = MasterKey::from_bytes_for_test([1u8; 32]);
        let doc_id = DocId::generate();
        let other = DocId::generate();
        let enc = seal(&mk, doc_id, 1, &sample_meta()).unwrap();
        assert_eq!(
            open(&mk, other, 1, &enc).unwrap_err(),
            Error::Authentication
        );
    }

    #[test]
    fn tamper_doc_version_fails_auth() {
        let mk = MasterKey::from_bytes_for_test([1u8; 32]);
        let doc_id = DocId::generate();
        let enc = seal(&mk, doc_id, 1, &sample_meta()).unwrap();
        assert_eq!(
            open(&mk, doc_id, 2, &enc).unwrap_err(),
            Error::Authentication
        );
    }

    #[test]
    fn from_bytes_rejects_empty_and_short_input() {
        assert_eq!(EncMeta::from_bytes(&[]).unwrap_err(), Error::Malformed);
        assert_eq!(
            EncMeta::from_bytes(&[VERSION, 0, 0]).unwrap_err(),
            Error::Malformed
        );
    }

    #[test]
    fn from_bytes_rejects_bad_version() {
        let bytes = vec![0x99u8; HEADER_LEN + TAG_LEN];
        assert_eq!(
            EncMeta::from_bytes(&bytes).unwrap_err(),
            Error::UnsupportedVersion
        );
    }

    /// Loads `tests/vectors/enc_meta.json` (docs/CRYPTO.md §8) and checks that
    /// [`seal_for_test`] with the pinned inputs reproduces the exact committed ciphertext
    /// byte-for-byte, and that opening it (via the normal, non-test [`open`]) recovers the
    /// expected `DocMeta`.
    #[test]
    fn fixed_vector_enc_meta() {
        let manifest: serde_json::Value =
            serde_json::from_str(include_str!("../tests/vectors/enc_meta.json")).unwrap();

        let mk = MasterKey::from_bytes_for_test(from_hex_32(
            manifest["master_key_hex"].as_str().unwrap(),
        ));
        let doc_id =
            DocId::from_uuid(uuid::Uuid::parse_str(manifest["doc_id"].as_str().unwrap()).unwrap());
        let doc_version = u32::try_from(manifest["doc_version"].as_u64().unwrap()).unwrap();
        let nonce = from_hex_n::<NONCE_LEN>(manifest["nonce_hex"].as_str().unwrap());
        let meta: DocMeta = serde_json::from_str(manifest["meta_json"].as_str().unwrap()).unwrap();
        let expected = from_hex_vec(manifest["enc_meta_hex"].as_str().unwrap());

        let enc = seal_for_test(&mk, doc_id, doc_version, &meta, nonce);
        assert_eq!(enc.as_bytes(), expected.as_slice());

        let opened = open(&mk, doc_id, doc_version, &enc).unwrap();
        assert_eq!(opened, meta);
    }

    fn from_hex_vec(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn from_hex_32(s: &str) -> [u8; 32] {
        from_hex_vec(s).try_into().unwrap()
    }

    fn from_hex_n<const N: usize>(s: &str) -> [u8; N] {
        from_hex_vec(s)
            .try_into()
            .unwrap_or_else(|_| panic!("wrong hex length"))
    }
}
