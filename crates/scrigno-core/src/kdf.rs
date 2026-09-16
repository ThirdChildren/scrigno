//! Argon2id key derivation: turns a passphrase (or recovery code, treated identically) plus
//! stored parameters into a [`Kek`]. See `docs/CRYPTO.md` §3.

use argon2::{Algorithm, Argon2, Params, Version};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::codec::{base64_decode, base64_encode};
use crate::error::Error;
use crate::keys::Kek;
use crate::rng::fill_random;

/// Default memory cost (KiB) for a new `passphrase`/`recovery` keyslot (`docs/CRYPTO.md` §3).
pub const DEFAULT_M_KIB: u32 = 65536;
/// Default iteration count for a new keyslot.
pub const DEFAULT_T: u32 = 3;
/// Default parallelism for a new keyslot.
pub const DEFAULT_P: u32 = 1;

/// OWASP-minimum memory cost (KiB) enforced when *creating* a new keyslot.
pub const FLOOR_M_KIB: u32 = 19456;
/// OWASP-minimum iteration count enforced when creating a new keyslot.
pub const FLOOR_T: u32 = 2;
/// OWASP-minimum parallelism enforced when creating a new keyslot.
pub const FLOOR_P: u32 = 1;

const SALT_LEN: usize = 16;
const KEK_LEN: usize = 32;

/// A keyslot's 16-byte Argon2id salt.
///
/// Not secret (Argon2 salts are meant to be public and unique, not hidden), so unlike the key
/// types in [`crate::keys`] this derives `Clone`/`Debug`/(de)serialization freely. Serializes
/// to/from JSON as a standard base64 string (`docs/CRYPTO.md` §4.2's `"salt"` field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Salt([u8; SALT_LEN]);

impl Salt {
    /// Generates a fresh random salt for a brand-new keyslot.
    ///
    /// # Errors
    /// Returns [`Error::Internal`] if `OsRng` fails.
    pub fn generate() -> Result<Self, Error> {
        let mut bytes = [0u8; SALT_LEN];
        fill_random(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// Wraps existing salt bytes (e.g. loaded from a stored keyslot).
    #[must_use]
    pub fn from_bytes(bytes: [u8; SALT_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw salt bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SALT_LEN] {
        &self.0
    }
}

impl Serialize for Salt {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64_encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Salt {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = base64_decode(&s).ok_or_else(|| serde::de::Error::custom("invalid base64"))?;
        if bytes.len() != SALT_LEN {
            return Err(serde::de::Error::custom("salt must be 16 bytes"));
        }
        let mut out = [0u8; SALT_LEN];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }
}

/// The Argon2 variant in use. Only `Argon2id` exists today (`docs/CRYPTO.md` §1); a typed enum
/// keeps the JSON shape stable if a future variant is ever added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KdfAlgorithm {
    /// Argon2id, the only algorithm this crate implements.
    Argon2id,
}

/// Stored, versionable Argon2id parameters for one keyslot (`docs/CRYPTO.md` §4.2's `kdf`
/// object).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// KDF algorithm; always `argon2id` for now.
    pub alg: KdfAlgorithm,
    /// Memory cost in KiB.
    pub m_kib: u32,
    /// Iteration count.
    pub t: u32,
    /// Parallelism (threads/lanes).
    pub p: u32,
    /// The 16-byte salt used for this derivation.
    pub salt: Salt,
}

impl KdfParams {
    /// Builds parameters for a **brand-new** keyslot: generates a fresh random salt and
    /// enforces the OWASP-minimum floor. This is the *only* place the floor is checked —
    /// [`derive_kek`] itself accepts whatever parameters it is given, so raising the floor
    /// later never breaks a vault created under the old one (`docs/CRYPTO.md` §3).
    ///
    /// # Errors
    /// [`Error::KdfParamsTooWeak`] if `m_kib`, `t` or `p` are below the floor.
    /// [`Error::Internal`] if `OsRng` fails while generating the salt.
    pub fn generate_for_new_slot(m_kib: u32, t: u32, p: u32) -> Result<Self, Error> {
        if m_kib < FLOOR_M_KIB || t < FLOOR_T || p < FLOOR_P {
            return Err(Error::KdfParamsTooWeak);
        }
        Ok(Self {
            alg: KdfAlgorithm::Argon2id,
            m_kib,
            t,
            p,
            salt: Salt::generate()?,
        })
    }

    /// Convenience: [`generate_for_new_slot`](Self::generate_for_new_slot) with the
    /// recommended defaults from `docs/CRYPTO.md` §3 (m=64 MiB, t=3, p=1).
    ///
    /// # Errors
    /// [`Error::Internal`] if `OsRng` fails while generating the salt.
    pub fn generate_default() -> Result<Self, Error> {
        Self::generate_for_new_slot(DEFAULT_M_KIB, DEFAULT_T, DEFAULT_P)
    }
}

/// Derives a [`Kek`] from a passphrase (or recovery code, treated identically as raw KDF
/// input) using Argon2id with the given, already-stored parameters.
///
/// No floor is enforced here: on unlock the vault must honour whatever parameters the keyslot
/// was created with, even if the floor is raised later (`docs/CRYPTO.md` §3). Use
/// [`KdfParams::generate_for_new_slot`] when *creating* a slot instead.
///
/// # Errors
/// [`Error::InvalidKdfParams`] if the stored parameters are structurally invalid for Argon2
/// (e.g. `p == 0`, which cannot happen via `generate_for_new_slot` but could arrive from an
/// untrusted stored record). [`Error::Internal`] if Argon2 itself fails.
pub fn derive_kek(passphrase: &SecretString, params: &KdfParams) -> Result<Kek, Error> {
    let argon2_params = Params::new(params.m_kib, params.t, params.p, Some(KEK_LEN))
        .map_err(|_| Error::InvalidKdfParams)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    // Zeroizing from the moment Argon2 fills it: `out` is `[u8; KEK_LEN]`, which is `Copy`, so
    // without this wrapper the raw KEK bytes handed to `Kek::from_bytes` by value would leave an
    // unzeroized copy sitting in this stack frame after the function returns (the same buffer-
    // hygiene bug fixed in `wrap.rs`/`meta.rs`/`blob.rs` after the M1 review). `Zeroizing::drop`
    // scrubs this frame's copy on every exit path, including the early `?` return above.
    let mut out = Zeroizing::new([0u8; KEK_LEN]);
    argon2
        .hash_password_into(
            passphrase.expose_secret().as_bytes(),
            params.salt.as_bytes(),
            &mut *out,
        )
        .map_err(|_| Error::Internal)?;
    Ok(Kek::from_bytes(*out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passphrase(s: &str) -> SecretString {
        SecretString::from(s.to_owned())
    }

    #[test]
    fn create_floor_rejects_weak_params() {
        assert_eq!(
            KdfParams::generate_for_new_slot(1024, 1, 1).unwrap_err(),
            Error::KdfParamsTooWeak
        );
        assert_eq!(
            KdfParams::generate_for_new_slot(FLOOR_M_KIB, 1, 1).unwrap_err(),
            Error::KdfParamsTooWeak
        );
    }

    #[test]
    fn create_floor_accepts_floor_exactly() {
        let params = KdfParams::generate_for_new_slot(FLOOR_M_KIB, FLOOR_T, FLOOR_P).unwrap();
        assert_eq!(params.m_kib, FLOOR_M_KIB);
    }

    #[test]
    fn derive_kek_is_deterministic_for_same_inputs() {
        let params = KdfParams {
            alg: KdfAlgorithm::Argon2id,
            m_kib: FLOOR_M_KIB,
            t: FLOOR_T,
            p: FLOOR_P,
            salt: Salt::from_bytes([1u8; 16]),
        };
        let a = derive_kek(&passphrase("correct horse battery staple"), &params).unwrap();
        let b = derive_kek(&passphrase("correct horse battery staple"), &params).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn derive_kek_differs_for_different_passphrase_or_salt() {
        let params_a = KdfParams {
            alg: KdfAlgorithm::Argon2id,
            m_kib: FLOOR_M_KIB,
            t: FLOOR_T,
            p: FLOOR_P,
            salt: Salt::from_bytes([1u8; 16]),
        };
        let mut params_b = params_a.clone();
        params_b.salt = Salt::from_bytes([2u8; 16]);

        let a = derive_kek(&passphrase("hunter2"), &params_a).unwrap();
        let b = derive_kek(&passphrase("hunter3"), &params_a).unwrap();
        let c = derive_kek(&passphrase("hunter2"), &params_b).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_ne!(a.as_bytes(), c.as_bytes());
    }

    #[test]
    fn derive_kek_unlock_accepts_below_floor_params() {
        // On unlock, whatever params are stored must be honoured, even below today's floor.
        let params = KdfParams {
            alg: KdfAlgorithm::Argon2id,
            m_kib: 8 * 1024,
            t: 1,
            p: 1,
            salt: Salt::from_bytes([3u8; 16]),
        };
        assert!(derive_kek(&passphrase("legacy"), &params).is_ok());
    }

    #[test]
    fn salt_json_round_trip() {
        let salt = Salt::from_bytes([9u8; 16]);
        let json = serde_json::to_string(&salt).unwrap();
        let back: Salt = serde_json::from_str(&json).unwrap();
        assert_eq!(back, salt);
    }
}
