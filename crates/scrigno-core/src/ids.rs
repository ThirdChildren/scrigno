//! Typed identifiers used throughout the crypto formats.
//!
//! These are thin `Uuid` newtypes so that AAD-building code can never accidentally swap a
//! `doc_id` for a `vault_id` (or vice versa) — the type checker catches it at compile time.
//! Per `docs/CRYPTO.md` §9, values passed into this crate's sealing/opening functions must
//! come from the caller's own typed record, never parsed out of unauthenticated input.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! uuid_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Wraps an existing UUID (e.g. one loaded from storage or received over the wire).
            #[must_use]
            pub fn from_uuid(id: Uuid) -> Self {
                Self(id)
            }

            /// Generates a new time-ordered `UUIDv7` identifier, per `CLAUDE.md`'s ID policy.
            #[must_use]
            pub fn generate() -> Self {
                Self(Uuid::now_v7())
            }

            /// Returns the underlying UUID.
            #[must_use]
            pub fn as_uuid(&self) -> Uuid {
                self.0
            }

            /// The 16 raw bytes of the UUID, as used in AAD construction.
            pub(crate) fn as_bytes(self) -> [u8; 16] {
                *self.0.as_bytes()
            }
        }

        impl From<Uuid> for $name {
            fn from(id: Uuid) -> Self {
                Self(id)
            }
        }
    };
}

uuid_id!(
    VaultId,
    "Identifies a vault. Part of the AAD when wrapping the master key (`docs/CRYPTO.md` §4.1)."
);
uuid_id!(
    DocId,
    "Identifies a document. Part of the AAD for its `EncMeta` and `Blob` (`docs/CRYPTO.md` §4.3, §4.4)."
);
uuid_id!(
    KeyslotId,
    "Identifies a keyslot. Part of the AAD when wrapping the master key (`docs/CRYPTO.md` §4.1)."
);

#[cfg(test)]
mod tests {
    use super::{DocId, VaultId};
    use uuid::Uuid;

    #[test]
    fn generate_produces_distinct_ids() {
        assert_ne!(VaultId::generate(), VaultId::generate());
    }

    #[test]
    fn round_trips_through_uuid() {
        let uuid = Uuid::now_v7();
        let id = DocId::from_uuid(uuid);
        assert_eq!(id.as_uuid(), uuid);
    }
}
