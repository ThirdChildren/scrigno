//! Wire types mirroring `docs/ARCHITECTURE.md §2` (DB rows) and `§3` (JSON shapes).
//!
//! Every `bytea` column (`enc_meta`, `wrapped_mk`, `sha256`) is opaque to this crate: we only
//! validate that it is well-formed base64 of some length, never its contents. That is the whole
//! point of a zero-knowledge server.

use serde::{Deserialize, Serialize};
use sqlx::types::chrono::{DateTime, Utc};
use uuid::Uuid;

/// RFC 3339 serde helper for `DateTime<Utc>` fields.
///
/// `sqlx`'s `chrono` feature re-exports `chrono::DateTime` (so `Decode`/`Encode` against
/// Postgres `timestamptz` work) but does not turn on `chrono`'s own `serde` cargo feature, so
/// `DateTime<Utc>` has no `Serialize`/`Deserialize` impl here. Rather than reaching for a new
/// dependency or a workspace feature-flag change, this is a small hand-written `to_rfc3339` /
/// `parse_from_rfc3339` bridge using only what's already available.
pub mod rfc3339 {
    use serde::{Deserialize, Deserializer, Serializer};
    use sqlx::types::chrono::{DateTime, Utc};

    /// # Errors
    ///
    /// Propagates any error the underlying `Serializer` returns.
    pub fn serialize<S: Serializer>(
        value: &DateTime<Utc>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_rfc3339())
    }

    /// # Errors
    ///
    /// Fails if the JSON value isn't a string, or isn't a valid RFC 3339 timestamp.
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<DateTime<Utc>, D::Error> {
        let raw = String::deserialize(deserializer)?;
        DateTime::parse_from_rfc3339(&raw)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|error| {
                serde::de::Error::custom(format!("invalid RFC3339 timestamp: {error}"))
            })
    }
}

/// Base64 (standard alphabet, padded) serde helper for `Vec<u8>` fields, per §3: "Base64 in JSON
/// is standard alphabet with padding."
pub mod b64 {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    /// # Errors
    ///
    /// Propagates any error the underlying `Serializer` returns.
    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    /// # Errors
    ///
    /// Fails if the JSON value isn't a string, or isn't valid standard-alphabet padded base64.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let raw = String::deserialize(deserializer)?;
        STANDARD
            .decode(raw.as_bytes())
            .map_err(|error| serde::de::Error::custom(format!("invalid base64: {error}")))
    }
}

/// `GET /v1/vault` / `POST /v1/vault` response body.
#[derive(Debug, Serialize)]
pub struct Vault {
    pub id: Uuid,
    #[serde(with = "rfc3339")]
    pub created_at: DateTime<Utc>,
    pub keyslots: Vec<Keyslot>,
}

/// A keyslot as returned to clients (no `vault_id`: there is only one vault).
#[derive(Debug, Serialize)]
pub struct Keyslot {
    pub id: Uuid,
    pub kind: String,
    pub kdf: serde_json::Value,
    #[serde(with = "b64")]
    pub wrapped_mk: Vec<u8>,
    #[serde(with = "rfc3339")]
    pub created_at: DateTime<Utc>,
}

/// Body of `POST /v1/vault` and `POST /v1/vault/keyslots`: a keyslot the client already
/// generated (id included -- ids are always client-generated, never invented by the server).
#[derive(Debug, Deserialize)]
pub struct NewKeyslot {
    pub id: Uuid,
    pub kind: String,
    pub kdf: serde_json::Value,
    #[serde(with = "b64")]
    pub wrapped_mk: Vec<u8>,
}

impl NewKeyslot {
    /// Shape-only validation: `kind` must be one of the two values the `keyslot.kind` CHECK
    /// constraint allows (this is enforced again at the DB layer regardless), and `wrapped_mk`
    /// must not be empty. Never inspects `kdf`'s or `wrapped_mk`'s *contents*.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::ApiError::BadRequest`] if any shape check fails.
    pub fn validate(&self) -> Result<(), crate::error::ApiError> {
        if self.kind != "passphrase" && self.kind != "recovery" {
            return Err(crate::error::ApiError::BadRequest(
                "keyslot.kind must be \"passphrase\" or \"recovery\"".to_string(),
            ));
        }
        if self.wrapped_mk.is_empty() {
            return Err(crate::error::ApiError::BadRequest(
                "keyslot.wrapped_mk must not be empty".to_string(),
            ));
        }
        if !self.kdf.is_object() {
            return Err(crate::error::ApiError::BadRequest(
                "keyslot.kdf must be a JSON object".to_string(),
            ));
        }
        Ok(())
    }
}

/// Body of `POST /v1/vault`.
#[derive(Debug, Deserialize)]
pub struct CreateVaultRequest {
    pub id: Uuid,
    pub keyslot: NewKeyslot,
}

/// `DocumentRecord`, per §3's TS block.
#[derive(Debug, Clone, Serialize)]
pub struct DocumentRecord {
    pub id: Uuid,
    pub version: i32,
    pub blob_id: Option<Uuid>,
    pub blob_size: i64,
    #[serde(with = "b64")]
    pub enc_meta: Vec<u8>,
    pub deleted: bool,
    pub server_seq: i64,
    #[serde(with = "rfc3339")]
    pub updated_at: DateTime<Utc>,
}

/// Body of `PUT /v1/docs/{id}`.
#[derive(Debug, Deserialize)]
pub struct PutDocRequest {
    pub blob_id: Uuid,
    pub blob_size: i64,
    #[serde(with = "b64")]
    pub enc_meta: Vec<u8>,
}

/// `GET /v1/changes` response body.
#[derive(Debug, Serialize)]
pub struct ChangesPage {
    pub items: Vec<DocumentRecord>,
    pub next_since: i64,
    pub has_more: bool,
}

/// `PUT /v1/blobs/{id}` response body (both the `201` and the idempotent `200` case).
#[derive(Debug, Serialize)]
pub struct BlobPutResponse {
    pub id: Uuid,
    pub size: i64,
    pub sha256: String,
}
