//! [`Keyslot`]: the JSON record stored on the server and locally, wrapping the master key
//! under one passphrase or recovery secret's KEK. See `docs/CRYPTO.md` §4.2.
//!
//! The server stores this verbatim and never interprets `wrapped_mk`.

use serde::{Deserialize, Serialize};

use crate::ids::KeyslotId;
use crate::kdf::KdfParams;
use crate::wrap::WrappedKey;

/// What secret a keyslot's KEK was derived from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyslotKind {
    /// Wrapped under a KEK derived from the user's passphrase.
    Passphrase,
    /// Wrapped under a KEK derived from a one-time recovery code (`docs/CRYPTO.md` §3,
    /// optional, added in a later milestone).
    Recovery,
}

/// One way to unlock a vault: a [`WrappedKey`] (the master key, wrapped under this slot's
/// KEK) plus the Argon2id parameters needed to re-derive that KEK from the corresponding
/// secret (`docs/CRYPTO.md` §4.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keyslot {
    /// This keyslot's identifier; also part of the AAD the master key was wrapped under.
    pub id: KeyslotId,
    /// Whether this slot is unlocked with a passphrase or a recovery code.
    pub kind: KeyslotKind,
    /// Argon2id parameters used to derive this slot's KEK.
    pub kdf: KdfParams,
    /// The master key, wrapped under this slot's KEK (`crate::wrap::wrap_mk`).
    pub wrapped_mk: WrappedKey,
    /// RFC 3339 creation timestamp.
    pub created_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::VaultId;
    use crate::keys::{Kek, MasterKey};
    use crate::wrap::wrap_mk;

    #[test]
    fn json_round_trip() {
        let vault_id = VaultId::generate();
        let keyslot_id = KeyslotId::generate();
        let kek = Kek::from_bytes_for_test([5u8; 32]);
        let mk = MasterKey::from_bytes_for_test([6u8; 32]);
        let wrapped_mk = wrap_mk(&kek, vault_id, keyslot_id, &mk).unwrap();

        let slot = Keyslot {
            id: keyslot_id,
            kind: KeyslotKind::Passphrase,
            kdf: KdfParams::generate_for_new_slot(19456, 2, 1).unwrap(),
            wrapped_mk,
            created_at: "2026-01-01T00:00:00Z".to_owned(),
        };

        let json = serde_json::to_string(&slot).unwrap();
        assert!(json.contains("\"kind\":\"passphrase\""));
        assert!(json.contains("\"alg\":\"argon2id\""));

        let back: Keyslot = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, slot.id);
        assert_eq!(back.wrapped_mk, slot.wrapped_mk);
    }
}
