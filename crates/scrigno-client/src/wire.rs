//! JSON wire types mirroring `crates/scrigno-server/src/models.rs` / `docs/ARCHITECTURE.md §3`.
//!
//! Deliberately **not** shared with `scrigno-server` (different crate, different trust
//! boundary): this module only needs to (de)serialize the same JSON shapes, not the server's own
//! validation logic. Every `bytea`/base64 field (`enc_meta`, `wrapped_mk`) is opaque here too —
//! this crate only encodes/decodes it as bytes, `scrigno-core` is the only place that interprets
//! the plaintext underneath.

use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize, Serializer};
use uuid::Uuid;

/// Base64 (standard alphabet, padded) serde helper, matching the server's own `models::b64`.
mod b64 {
    use super::{STANDARD, Serializer};
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let raw = String::deserialize(deserializer)?;
        STANDARD
            .decode(raw.as_bytes())
            .map_err(|e| serde::de::Error::custom(format!("invalid base64: {e}")))
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct VaultWire {
    pub id: Uuid,
    #[allow(dead_code)] // kept for shape-completeness; unused fields are fine on a DTO
    pub created_at: String,
    pub keyslots: Vec<KeyslotWire>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct KeyslotWire {
    pub id: Uuid,
    pub kind: String,
    pub kdf: serde_json::Value,
    #[serde(with = "b64")]
    pub wrapped_mk: Vec<u8>,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct NewKeyslotWire {
    pub id: Uuid,
    pub kind: &'static str,
    pub kdf: serde_json::Value,
    #[serde(with = "b64")]
    pub wrapped_mk: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CreateVaultWire {
    pub id: Uuid,
    pub keyslot: NewKeyslotWire,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct DocumentRecordWire {
    pub id: Uuid,
    pub version: i64,
    pub blob_id: Option<Uuid>,
    pub blob_size: i64,
    #[serde(with = "b64")]
    pub enc_meta: Vec<u8>,
    pub deleted: bool,
    pub server_seq: i64,
    #[allow(dead_code)]
    pub updated_at: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct PutDocWire {
    pub blob_id: Uuid,
    pub blob_size: i64,
    #[serde(with = "b64")]
    pub enc_meta: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ChangesPageWire {
    pub items: Vec<DocumentRecordWire>,
    pub next_since: i64,
    pub has_more: bool,
}

/// Only `sha256` is read (to verify against what this client actually streamed uploading — see
/// `HttpClient::put_blob`); `id`/`size` are part of the response shape but this client already
/// knows both from the request it just made, so they aren't declared here (unknown JSON fields
/// deserialize fine without `deny_unknown_fields`).
#[derive(Debug, Deserialize)]
pub(crate) struct BlobPutResponseWire {
    pub sha256: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ErrorBodyWire {
    pub error: ErrorInnerWire,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ErrorInnerWire {
    pub code: String,
    #[allow(dead_code)]
    pub message: String,
}
