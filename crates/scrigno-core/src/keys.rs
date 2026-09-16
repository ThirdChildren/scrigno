//! 256-bit symmetric key types: [`MasterKey`], [`Dek`], [`Kek`].
//!
//! All three hold their bytes in a `Zeroizing<[u8; 32]>` so the buffer is wiped on drop. None
//! of them implement `Clone` (a key can't accidentally be duplicated and outlive its intended
//! scope) or a `Debug` that prints bytes (`{:?}` in a log line is always safe). Bytes are only
//! ever exposed via a crate-private accessor consumed by the AEAD calls in [`crate::wrap`],
//! [`crate::meta`] and [`crate::blob`] — there is no public API to read out or inject raw key
//! bytes in production code, per `docs/CRYPTO.md` §9.

use core::fmt;

use zeroize::Zeroizing;

use crate::error::Error;
use crate::rng::fill_random;

macro_rules! secret_key_type {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        pub struct $name(Zeroizing<[u8; 32]>);

        impl $name {
            /// Wraps 32 raw bytes as a key. Crate-internal only: used after `OsRng`
            /// generation or after a successful AEAD unwrap, never to let a caller inject
            /// arbitrary bytes as a key.
            pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(Zeroizing::new(bytes))
            }

            /// Borrows the raw key bytes for an AEAD call inside this crate.
            pub(crate) fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(REDACTED)"))
            }
        }

        #[cfg(test)]
        impl $name {
            /// Test-only constructor that pins the key bytes, so fixed test vectors are
            /// reproducible. Not reachable from any production code path: production code
            /// only ever obtains a key via `generate()` or by unwrapping/deriving one.
            pub(crate) fn from_bytes_for_test(bytes: [u8; 32]) -> Self {
                Self::from_bytes(bytes)
            }
        }
    };
}

secret_key_type!(
    MasterKey,
    "The 256-bit master key (MK) for a vault: unwraps every document's `Dek` and encrypts \
     every `EncMeta`. Exists in memory only while the vault is unlocked (`docs/CRYPTO.md` §2)."
);
secret_key_type!(
    Dek,
    "A 256-bit per-document data-encryption key (DEK). Every document has its own, so \
     compromising one DEK exposes exactly one file (`docs/CRYPTO.md` §2)."
);
secret_key_type!(
    Kek,
    "A 256-bit key-encryption key (KEK) derived from a passphrase or recovery code via \
     Argon2id (`crate::kdf::derive_kek`). Only ever used to wrap/unwrap a `MasterKey`."
);

impl MasterKey {
    /// Generates a fresh master key using `OsRng`. Called once per vault, at creation time.
    ///
    /// # Errors
    /// Returns [`Error::Internal`] if `OsRng` fails.
    pub fn generate() -> Result<Self, Error> {
        Ok(Self::from_bytes(random_key_bytes()?))
    }
}

impl Dek {
    /// Generates a fresh per-document data-encryption key using `OsRng`.
    ///
    /// # Errors
    /// Returns [`Error::Internal`] if `OsRng` fails.
    pub fn generate() -> Result<Self, Error> {
        Ok(Self::from_bytes(random_key_bytes()?))
    }
}

fn random_key_bytes() -> Result<[u8; 32], Error> {
    let mut bytes = [0u8; 32];
    fill_random(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::{Dek, MasterKey};

    #[test]
    fn debug_never_prints_key_bytes() {
        let mk = MasterKey::from_bytes_for_test([0x42; 32]);
        let debug = format!("{mk:?}");
        assert_eq!(debug, "MasterKey(REDACTED)");
        assert!(!debug.contains("42"));
    }

    #[test]
    fn generate_produces_distinct_keys() {
        let a = MasterKey::generate().expect("OsRng available in tests");
        let b = MasterKey::generate().expect("OsRng available in tests");
        assert_ne!(a.as_bytes(), b.as_bytes());
        let d = Dek::generate().expect("OsRng available in tests");
        assert_ne!(a.as_bytes(), d.as_bytes());
    }
}
