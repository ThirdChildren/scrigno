//! [`Vault`] (locked) / [`UnlockedVault`]: the crate's public API surface.
//!
//! **Locked/unlocked is modelled in the type system**, per this milestone's brief: `Vault` never
//! holds a [`MasterKey`]; only [`UnlockedVault`] does, and every operation that needs the master
//! key is an inherent method on `UnlockedVault`. `Vault::unlock`/`create`/`join` consume the
//! locked value and return an `UnlockedVault`; `UnlockedVault::lock` consumes the unlocked value,
//! zeroizes the key (via `MasterKey`'s own `Drop`), and returns a fresh `Vault`. A caller cannot
//! call an unlocked-only method on a locked vault — it doesn't compile.
//!
//! [`crate::error::ClientError::Locked`] is not reachable from this state machine's *happy* path;
//! it exists for a caller that holds `Option<UnlockedVault>` across a lock/unlock cycle (the
//! Tauri layer, M4) and needs a stable error to return when that option is `None` — and, in this
//! crate, for [`Vault::unlock`] called on a data dir that has never been bound to a vault (see
//! its docs).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use secrecy::SecretString;
use uuid::Uuid;
use zeroize::Zeroize;

use scrigno_core::ids::{DocId, KeyslotId, VaultId};
use scrigno_core::kdf::{KdfParams, derive_kek};
#[cfg(test)]
use scrigno_core::keys::Dek;
use scrigno_core::keys::MasterKey;
use scrigno_core::keyslot::{Keyslot, KeyslotKind};
use scrigno_core::meta::DocMeta;
use scrigno_core::{blob, meta, recovery, wrap};

use crate::error::{ClientError, Result};
use crate::http::HttpClient;
use crate::store::{DocumentRow, Store};
use crate::types::DocSummary;
use crate::wire::KeyslotWire;

const KV_VAULT_ID: &str = "vault_id";
const KV_SERVER_URL: &str = "server_url";
pub(crate) const KV_CURSOR: &str = "cursor";
const KV_KEYSLOT_ID: &str = "keyslot_id_in_use";
const KV_KEYSLOT_JSON: &str = "keyslot_json";
const KV_DEVICE_ID: &str = "device_id";
const KV_CACHE_LIMIT_MB: &str = "cache_limit_mb";
const DEFAULT_CACHE_LIMIT_MB: i64 = 512;

/// A vault whose local SQLite store is open but whose master key is **not** in memory.
pub struct Vault {
    pub(crate) store: Store,
}

/// A vault whose master key is in memory. Every crypto-touching operation lives here.
pub struct UnlockedVault {
    pub(crate) store: Store,
    pub(crate) vault_id: VaultId,
    pub(crate) mk: MasterKey,
    pub(crate) http: HttpClient,
    pub(crate) index: Vec<DocSummary>,
    /// Ids of documents that failed to decrypt while rebuilding `index` at [`Vault::unlock`]
    /// time (corrupt/tampered `enc_meta`, or a document affected by a since-fixed bug — see
    /// [`rebuild_index`]) and were therefore skipped rather than aborting the whole unlock.
    /// Never populated anywhere else. `docs/ARCHITECTURE.md`/the Tauri layer can surface this so
    /// an unreadable document doesn't just silently vanish from `list()` with no explanation.
    pub(crate) unreadable_at_unlock: Vec<String>,
}

impl Vault {
    /// Opens (creating if absent) the local SQLite store at `data_dir`. Does not touch the
    /// network and does not require a passphrase — this only proves the local store is usable.
    ///
    /// # Errors
    /// [`ClientError::Storage`] if the directory or database file can't be created/opened.
    pub fn open(data_dir: &Path) -> Result<Self> {
        Ok(Self {
            store: Store::open(data_dir)?,
        })
    }

    /// `true` if this data dir has already been bound to a vault (via [`Self::create`] or
    /// [`Self::join`]) — i.e. [`Self::unlock`] can be attempted. Used by the CLI's `status`
    /// command.
    ///
    /// # Errors
    /// [`ClientError::Storage`] if the local database can't be read.
    pub fn is_initialised(&self) -> Result<bool> {
        Ok(self.store.kv_get(KV_VAULT_ID)?.is_some())
    }

    /// Bootstraps a brand-new vault: generates a master key and a first `passphrase` keyslot,
    /// registers it with the server (`POST /v1/vault`), and persists just enough locally
    /// (`docs/CRYPTO.md §5.1`) that a later [`Self::unlock`] never needs the network again.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] if this data dir is already bound to a vault.
    /// [`ClientError::VaultExists`] if the server already has one. [`ClientError::Network`] /
    /// [`ClientError::Unauthorized`] for transport/auth failures.
    pub async fn create(
        self,
        server_url: &str,
        token: SecretString,
        passphrase: &SecretString,
    ) -> Result<UnlockedVault> {
        if self.store.kv_get(KV_VAULT_ID)?.is_some() {
            return Err(ClientError::InvalidInput);
        }

        let vault_id = VaultId::generate();
        let mk = MasterKey::generate()?;
        let (keyslot_id, kdf, wrapped_mk, new_keyslot) =
            build_new_keyslot(passphrase, vault_id, &mk, "passphrase")?;

        let http = HttpClient::new(server_url, token)?;
        let response = http.create_vault(vault_id.as_uuid(), new_keyslot).await?;
        let server_slot = response
            .keyslots
            .into_iter()
            .find(|s| s.id == keyslot_id.as_uuid())
            .ok_or(ClientError::ServerContract)?;

        let keyslot = Keyslot {
            id: keyslot_id,
            kind: KeyslotKind::Passphrase,
            kdf,
            wrapped_mk,
            created_at: server_slot.created_at,
        };

        persist_bootstrap(&self.store, vault_id, &keyslot, server_url)?;

        Ok(UnlockedVault {
            store: self.store,
            vault_id,
            mk,
            http,
            index: Vec::new(),
            unreadable_at_unlock: Vec::new(),
        })
    }

    /// Joins an existing vault from a second device: fetches it (`GET /v1/vault`), picks a
    /// `passphrase` keyslot, derives its KEK and unwraps the master key.
    ///
    /// # Errors
    /// [`ClientError::InvalidInput`] if this data dir is already bound to a vault, or the server
    /// vault has no `passphrase` keyslot. [`ClientError::VaultNotInitialised`] if the server has
    /// no vault yet. [`ClientError::WrongPassphrase`] if the passphrase doesn't unwrap the master
    /// key under the chosen slot.
    pub async fn join(
        self,
        server_url: &str,
        token: SecretString,
        passphrase: &SecretString,
    ) -> Result<UnlockedVault> {
        if self.store.kv_get(KV_VAULT_ID)?.is_some() {
            return Err(ClientError::InvalidInput);
        }

        let http = HttpClient::new(server_url, token)?;
        let remote = http.get_vault().await?;
        let vault_id = VaultId::from_uuid(remote.id);

        let slot = remote
            .keyslots
            .iter()
            .find(|s| s.kind == "passphrase")
            .ok_or(ClientError::InvalidInput)?;

        let (keyslot, mk) = unwrap_with_slot(passphrase, vault_id, slot)?;

        persist_bootstrap(&self.store, vault_id, &keyslot, server_url)?;

        Ok(UnlockedVault {
            store: self.store,
            vault_id,
            mk,
            http,
            index: Vec::new(),
            unreadable_at_unlock: Vec::new(),
        })
    }

    /// Unlocks a vault previously bound to this data dir (via [`Self::create`]/[`Self::join`] on
    /// this device, or a copy of this store): re-derives the KEK from `passphrase` against the
    /// locally-stored keyslot and unwraps the master key. Entirely local — no network round trip
    /// (`docs/ARCHITECTURE.md §4`'s in-memory index is rebuilt from `enc_meta` here too).
    ///
    /// `token`/`server_url_override` are only used lazily, by [`UnlockedVault::sync`] and by
    /// [`UnlockedVault::open`] when a requested blob isn't in the local cache; this method itself
    /// never touches the network.
    ///
    /// # Errors
    /// [`ClientError::Locked`] if this data dir has never been bound to a vault (nothing to
    /// unlock — run `create`/`join` first). [`ClientError::WrongPassphrase`] if `passphrase`
    /// doesn't unwrap the stored master key.
    pub fn unlock(
        self,
        passphrase: &SecretString,
        token: SecretString,
        server_url_override: Option<&str>,
    ) -> Result<UnlockedVault> {
        let vault_id_str = self.store.kv_get(KV_VAULT_ID)?.ok_or(ClientError::Locked)?;
        let vault_id =
            VaultId::from_uuid(Uuid::parse_str(&vault_id_str).map_err(|_| ClientError::Storage)?);
        let keyslot_json = self
            .store
            .kv_get(KV_KEYSLOT_JSON)?
            .ok_or(ClientError::Locked)?;
        let keyslot: Keyslot =
            serde_json::from_str(&keyslot_json).map_err(|_| ClientError::Storage)?;

        let kek = derive_kek(passphrase, &keyslot.kdf)?;
        let mk = wrap::unwrap_mk(&kek, vault_id, keyslot.id, &keyslot.wrapped_mk)
            .map_err(|_| ClientError::WrongPassphrase)?;

        let server_url = match server_url_override {
            Some(url) => {
                self.store.kv_set(KV_SERVER_URL, url)?;
                url.to_string()
            }
            None => self
                .store
                .kv_get(KV_SERVER_URL)?
                .ok_or(ClientError::Locked)?,
        };
        let http = HttpClient::new(&server_url, token)?;
        let (index, unreadable_at_unlock) = rebuild_index(&self.store, &mk)?;

        Ok(UnlockedVault {
            store: self.store,
            vault_id,
            mk,
            http,
            index,
            unreadable_at_unlock,
        })
    }
}

/// Fetches `GET /v1/changes` and returns the **raw** JSON (`enc_meta` left as opaque base64,
/// nothing decrypted) — backs the CLI's `changes --raw` debug command. Does not require a local
/// vault at all, only a server URL and a token, by design (a support/debug tool).
///
/// # Errors
/// Network/auth errors as usual; never a crypto error, since nothing here is decrypted.
pub async fn debug_raw_changes(
    server_url: &str,
    token: SecretString,
    since: i64,
    limit: i64,
) -> Result<serde_json::Value> {
    let http = HttpClient::new(server_url, token)?;
    http.get_changes_raw(since, limit).await
}

fn unwrap_with_slot(
    passphrase: &SecretString,
    vault_id: VaultId,
    slot: &KeyslotWire,
) -> Result<(Keyslot, MasterKey)> {
    let kdf: KdfParams =
        serde_json::from_value(slot.kdf.clone()).map_err(|_| ClientError::ServerContract)?;
    let wrapped_mk =
        wrap::WrappedKey::from_slice(&slot.wrapped_mk).map_err(|_| ClientError::ServerContract)?;
    let keyslot_id = KeyslotId::from_uuid(slot.id);

    let kek = derive_kek(passphrase, &kdf)?;
    let mk = wrap::unwrap_mk(&kek, vault_id, keyslot_id, &wrapped_mk)
        .map_err(|_| ClientError::WrongPassphrase)?;

    let keyslot = Keyslot {
        id: keyslot_id,
        kind: if slot.kind == "recovery" {
            KeyslotKind::Recovery
        } else {
            KeyslotKind::Passphrase
        },
        kdf,
        wrapped_mk,
        created_at: slot.created_at.clone(),
    };
    Ok((keyslot, mk))
}

/// Builds a brand-new keyslot for `secret` (a passphrase or a recovery code — both are treated
/// identically as raw Argon2id input, `docs/CRYPTO.md` §3): a fresh [`KeyslotId`], KDF params at
/// the create-time floor ([`KdfParams::generate_default`]), and `mk` wrapped under the derived
/// KEK ([`wrap::wrap_mk`]). Shared by [`Vault::create`]'s initial `passphrase` keyslot and
/// [`UnlockedVault::add_recovery_keyslot`]'s `recovery` keyslot — the only difference between the
/// two call sites is the input secret and the `kind` string, so both get identical treatment for
/// everything else (KDF params policy, wrap AAD, wire shape).
///
/// Returns the pieces the two call sites need: the new slot's id/KDF params/wrapped key (to build
/// a local [`Keyslot`] once the server has confirmed it), plus the ready-to-POST
/// [`crate::wire::NewKeyslotWire`].
fn build_new_keyslot(
    secret: &SecretString,
    vault_id: VaultId,
    mk: &MasterKey,
    kind: &'static str,
) -> Result<(
    KeyslotId,
    KdfParams,
    wrap::WrappedKey,
    crate::wire::NewKeyslotWire,
)> {
    let keyslot_id = KeyslotId::generate();
    let kdf = KdfParams::generate_default()?;
    let kek = derive_kek(secret, &kdf)?;
    let wrapped_mk = wrap::wrap_mk(&kek, vault_id, keyslot_id, mk)?;
    let wire = crate::wire::NewKeyslotWire {
        id: keyslot_id.as_uuid(),
        kind,
        kdf: serde_json::to_value(&kdf).map_err(|_| ClientError::Crypto)?,
        wrapped_mk: wrapped_mk.as_bytes().to_vec(),
    };
    Ok((keyslot_id, kdf, wrapped_mk, wire))
}

fn persist_bootstrap(
    store: &Store,
    vault_id: VaultId,
    keyslot: &Keyslot,
    server_url: &str,
) -> Result<()> {
    store.kv_set(KV_VAULT_ID, &vault_id.as_uuid().to_string())?;
    store.kv_set(KV_SERVER_URL, server_url)?;
    store.kv_set(KV_KEYSLOT_ID, &keyslot.id.as_uuid().to_string())?;
    store.kv_set(
        KV_KEYSLOT_JSON,
        &serde_json::to_string(keyslot).map_err(|_| ClientError::Storage)?,
    )?;
    store.kv_set(KV_CURSOR, "0")?;
    store.kv_set(KV_DEVICE_ID, &Uuid::now_v7().to_string())?;
    store.kv_set(KV_CACHE_LIMIT_MB, &DEFAULT_CACHE_LIMIT_MB.to_string())?;
    Ok(())
}

/// Rebuilds the in-memory index from every non-tombstoned local row, decrypting each row's
/// `enc_meta`. A single document that fails to decrypt (corrupt/tampered `enc_meta`, or one hit
/// by a since-fixed local bug) is **skipped, not fatal** — `unlock()` must succeed even if one
/// document is unreadable, so that one bad document can never lock a user out of the entire
/// vault. Returns the index plus the ids of any documents that were skipped this way; only a
/// local-storage failure (listing rows at all) is still propagated as an `Err`.
fn rebuild_index(store: &Store, mk: &MasterKey) -> Result<(Vec<DocSummary>, Vec<String>)> {
    let mut out = Vec::new();
    let mut skipped = Vec::new();
    for row in store.list_documents()? {
        if row.deleted {
            continue;
        }
        if let Ok(summary) = row_to_summary(store, mk, &row) {
            out.push(summary);
        } else {
            // Never log the ciphertext/plaintext/key material — only that this id's metadata
            // could not be authenticated.
            tracing::warn!(doc_id = %row.id, "skipping document: enc_meta failed to decrypt");
            skipped.push(row.id.to_string());
        }
    }
    Ok((out, skipped))
}

pub(crate) fn row_to_summary(
    store: &Store,
    mk: &MasterKey,
    row: &DocumentRow,
) -> Result<DocSummary> {
    let doc_id = DocId::from_uuid(row.id);
    let doc_version = doc_version_of(row);
    let enc = meta::EncMeta::from_bytes(&row.enc_meta).map_err(|_| ClientError::Crypto)?;
    let plain = meta::open(mk, doc_id, doc_version, &enc)?;
    let cached = match row.blob_id {
        Some(blob_id) => store.cache_get(blob_id)?.is_some(),
        None => false,
    };
    Ok(doc_meta_to_summary(row, &plain, cached))
}

/// This crate's local `document.version` is stored as `i64` (SQLite's native integer type); the
/// wire/AAD form is `u32` (`docs/CRYPTO.md §4.3`). Versions never realistically approach
/// `u32::MAX`, so a saturating conversion (rather than a panicking one) is a safe, simple choice.
pub(crate) fn doc_version_of(row: &DocumentRow) -> u32 {
    u32::try_from(row.version).unwrap_or(u32::MAX)
}

pub(crate) fn doc_meta_to_summary(row: &DocumentRow, meta: &DocMeta, cached: bool) -> DocSummary {
    let size = i64::try_from(meta.size).unwrap_or(i64::MAX);
    DocSummary {
        id: row.id.to_string(),
        title: meta.title.clone(),
        tags: meta.tags.clone(),
        note: meta.note.clone(),
        mime: meta.mime.clone(),
        size,
        content_hash: meta.content_hash.clone(),
        original_name: meta.original_name.clone(),
        created_at: meta.created_at.clone(),
        version: row.version,
        dirty: row.dirty,
        keep_offline: row.keep_offline,
        blob_size: row.blob_size,
        cached,
    }
}

/// Current UTC time as an RFC 3339 string (no sub-second component needed at this resolution).
pub(crate) fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

/// Longest side, in pixels, of a generated thumbnail (`docs/CRYPTO.md` §4.3). Images already
/// smaller than this in both dimensions are left at their original size (no upscaling).
const THUMB_MAX_DIMENSION: u32 = 256;

/// Hard cap on the base64-encoded thumbnail, matching `docs/CRYPTO.md` §4.3's "`thumb`: base64
/// JPEG ≤ 24 KiB".
const THUMB_MAX_BYTES: usize = 24 * 1024;

/// JPEG quality levels tried, highest first, until the encoded size fits [`THUMB_MAX_BYTES`].
/// At [`THUMB_MAX_DIMENSION`] = 256px, quality 70 already comfortably clears the cap for
/// ordinary photos; the lower steps are a safety margin for busy/high-entropy images so the cap
/// is met reliably rather than merely "usually".
const THUMB_JPEG_QUALITIES: [u8; 4] = [70, 55, 40, 25];

/// Best-effort thumbnail generation for `DocMeta.thumb` (`docs/CRYPTO.md` §4.3): decodes `bytes`
/// as an image, downsizes it to at most [`THUMB_MAX_DIMENSION`] px on the longest side, and
/// re-encodes as JPEG, trying progressively lower quality until the base64-encoded result fits
/// [`THUMB_MAX_BYTES`].
///
/// Returns `None` (never an error) if `bytes` can't be decoded as an image despite the caller's
/// `image/*` mime claim, or if no quality level in [`THUMB_JPEG_QUALITIES`] gets the encoded
/// thumbnail under the cap — a document is never refused just because its thumbnail didn't pan
/// out. Never logs the image bytes or anything derived from them (CLAUDE.md: never log content).
fn generate_thumbnail(bytes: &[u8]) -> Option<String> {
    let img = image::load_from_memory(bytes).ok()?;

    let resized = if img.width() > THUMB_MAX_DIMENSION || img.height() > THUMB_MAX_DIMENSION {
        img.resize(
            THUMB_MAX_DIMENSION,
            THUMB_MAX_DIMENSION,
            image::imageops::FilterType::Lanczos3,
        )
    } else {
        img
    };
    // JPEG has no alpha channel; drop it explicitly rather than let the encoder reject it.
    let rgb = resized.to_rgb8();

    for quality in THUMB_JPEG_QUALITIES {
        let mut jpeg_bytes = Vec::new();
        let jpeg_encoder =
            image::codecs::jpeg::JpegEncoder::new_with_quality(&mut jpeg_bytes, quality);
        if rgb.write_with_encoder(jpeg_encoder).is_err() {
            continue;
        }
        let b64 = BASE64.encode(&jpeg_bytes);
        if b64.len() <= THUMB_MAX_BYTES {
            return Some(b64);
        }
    }
    None
}

/// The user-editable `DocMeta` fields plus the local-only `keep_offline` flag, grouped into one
/// struct so [`UnlockedVault::encrypt_new_document`] takes a reasonable number of arguments.
pub(crate) struct NewDocFields {
    pub title: String,
    pub tags: Vec<String>,
    pub note: String,
    pub mime: String,
    pub original_name: String,
    pub keep_offline: bool,
}

/// A [`Write`] adapter that hashes (BLAKE3) and counts every byte written through it, so
/// [`UnlockedVault::add`] can compute `DocMeta::content_hash`/`size` in the same pass that
/// streams plaintext into [`blob::Encryptor`], without a second read of the input.
struct HashingWriter<W: Write> {
    inner: W,
    hasher: blake3::Hasher,
    count: u64,
}

impl<W: Write> HashingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: blake3::Hasher::new(),
            count: 0,
        }
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.count += u64::try_from(n).unwrap_or(u64::MAX);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl UnlockedVault {
    /// Zeroizes the master key (via [`MasterKey`]'s own `Drop`), scrubs the decrypted plaintext
    /// (`title`/`tags`/`note`/`original_name`) held in `self.index` for the whole unlocked
    /// session, and returns a locked [`Vault`] over the same local store.
    ///
    /// `self.index` is a plain, `ts-rs`-exported DTO ([`DocSummary`]) — deriving `Zeroize` on it
    /// would tie a public serialization type to an internal memory-hygiene concern, so this
    /// scrubs each entry's plaintext fields in place instead (`docs/CRYPTO.md §5.2`: auto-lock
    /// exists to shrink the in-memory-plaintext window, not just drop the `Vec` and hope the
    /// allocator zeroes it).
    #[must_use]
    pub fn lock(mut self) -> Vault {
        for doc in &mut self.index {
            doc.title.zeroize();
            doc.tags.zeroize();
            doc.note.zeroize();
            doc.original_name.zeroize();
        }
        self.index.clear();
        Vault { store: self.store }
    }

    /// This vault's id.
    #[must_use]
    pub fn vault_id(&self) -> Uuid {
        self.vault_id.as_uuid()
    }

    /// Generates a brand-new recovery code ([`recovery::generate_code`]), wraps the already
    /// in-memory master key under a KEK derived from it (same create-time KDF params policy as
    /// the initial `passphrase` keyslot — both go through [`build_new_keyslot`]), and registers
    /// the resulting `recovery` keyslot with the server (`POST /v1/vault/keyslots`).
    ///
    /// Returns the recovery code as plaintext — the **only** time it is ever available in
    /// plaintext (`docs/CRYPTO.md` §3: "Stored nowhere in plaintext"). This method never logs or
    /// persists it anywhere; the caller (the eventual Tauri command → UI, per `docs/ROADMAP.md`
    /// M4's "recovery code shown once") is solely responsible for displaying it to the user
    /// exactly once and never caching it.
    ///
    /// # Errors
    /// [`ClientError::Crypto`] if code generation, KDF or wrapping fails (should not happen in
    /// ordinary operation). [`ClientError::Network`] / [`ClientError::Unauthorized`] for
    /// transport/auth failures registering the slot with the server.
    pub async fn add_recovery_keyslot(&mut self) -> Result<String> {
        let code = recovery::generate_code().map_err(|_| ClientError::Crypto)?;
        let secret = SecretString::from(code.clone());
        let (_keyslot_id, _kdf, _wrapped_mk, new_keyslot) =
            build_new_keyslot(&secret, self.vault_id, &self.mk, "recovery")?;
        self.http.add_keyslot(new_keyslot).await?;
        Ok(code)
    }

    /// The in-memory document index, rebuilt on unlock and kept up to date by every mutating
    /// method on this type. Excludes tombstoned (deleted) documents.
    #[must_use]
    pub fn list(&self) -> Vec<DocSummary> {
        self.index.clone()
    }

    /// Ids (as strings) of documents that existed locally at unlock time but whose `enc_meta`
    /// failed to decrypt, so they were skipped and are **not** present in [`Self::list`]. Empty
    /// in the ordinary case. Lets a caller (CLI/Tauri layer) tell the user "N documents could
    /// not be read" instead of those documents silently vanishing with no explanation — see
    /// [`rebuild_index`]'s doc comment for why unlock doesn't just fail instead.
    #[must_use]
    pub fn unreadable_documents(&self) -> &[String] {
        &self.unreadable_at_unlock
    }

    /// Returns the full decrypted [`DocMeta`] for document `id`, including `thumb` — which
    /// [`DocSummary`] (and thus [`Self::list`]) deliberately omits per
    /// `docs/ARCHITECTURE.md §6` (the thumbnail is fetched separately, on demand). Re-opens and
    /// decrypts `enc_meta` fresh from the store rather than from `self.index` (which only holds
    /// `DocSummary`s, without `thumb`) — the same per-document step [`Vault::unlock`]'s index
    /// rebuild performs for every document, just for this one id. Backs the Tauri layer's
    /// `doc_get_meta` and `doc_thumb` commands.
    ///
    /// # Errors
    /// [`ClientError::NotFound`] if `id` doesn't exist or is a tombstone.
    pub fn get_meta(&self, id: Uuid) -> Result<DocMeta> {
        let row = self.store.get_document(id)?.ok_or(ClientError::NotFound)?;
        if row.deleted {
            return Err(ClientError::NotFound);
        }
        let doc_id = DocId::from_uuid(row.id);
        let doc_version = doc_version_of(&row);
        let enc = meta::EncMeta::from_bytes(&row.enc_meta).map_err(|_| ClientError::Crypto)?;
        Ok(meta::open(&self.mk, doc_id, doc_version, &enc)?)
    }

    /// Encrypts `reader`'s content as a brand-new document: streams it through
    /// [`blob::Encryptor`] into a temp file in the local blob cache, computes `size`/BLAKE3
    /// `content_hash` in the same pass, then atomically (temp-write, rename, then one DB
    /// transaction) records the new `document` + `blob_cache` rows, `dirty` and not yet on the
    /// server (`docs/ARCHITECTURE.md §5`'s "blob first" ordering is naturally satisfied: nothing
    /// is pushed to the server until the next `sync()`).
    ///
    /// # Errors
    /// [`ClientError::Storage`] on a local I/O failure. [`ClientError::Crypto`] if encryption
    /// itself fails (should not happen in ordinary operation).
    // This particular method never awaits (it is pure local I/O), but every mutating `Vault`
    // operation is `async` by design (per this milestone's brief: "one async type") so the CLI
    // and the future Tauri commands can treat the whole surface uniformly, including the ones
    // that do need the network (`sync`, and `open` on a cache miss).
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)]
    pub async fn add(
        &mut self,
        reader: impl Read,
        title: String,
        tags: Vec<String>,
        note: String,
        mime: String,
        original_name: String,
    ) -> Result<DocSummary> {
        let doc_id = DocId::generate();
        let fields = NewDocFields {
            title,
            tags,
            note,
            mime,
            original_name,
            keep_offline: false,
        };
        let (row, doc_meta) = self.encrypt_new_document(doc_id, reader, fields)?;
        let summary = doc_meta_to_summary(&row, &doc_meta, true);
        self.index.push(summary.clone());
        Ok(summary)
    }

    /// Shared by [`Self::add`] and the sync engine's conflict-copy creation
    /// (`docs/ARCHITECTURE.md §5`): encrypts `reader`'s content under a brand-new `doc_id` and
    /// atomically records it as a new, `dirty`, never-yet-pushed (`base_version = 0`) document.
    /// Does **not** touch `self.index` — callers push the resulting summary themselves. Purely
    /// local (no `.await`s): the network side of "adding a document" only happens later, at the
    /// next `sync()`.
    ///
    /// **Streaming vs. buffering.** For every mime except `image/*`, `reader` is streamed
    /// through [`blob::Encryptor`] in one pass via `std::io::copy` and never buffered whole —
    /// deliberate, for the 150 MiB-blob streaming-RSS budget (`docs/ROADMAP.md` M2). For
    /// `image/*` mimes, `docs/CRYPTO.md` §4.3's `DocMeta.thumb` needs the fully decoded image,
    /// and the `image` crate has no streaming decode API that also lets this method re-emit the
    /// original bytes for encryption afterwards. So images only are a scoped, deliberate
    /// exception: the whole `reader` is buffered into memory once (`read_to_end`), a thumbnail
    /// is decoded from that buffer (best-effort — see [`generate_thumbnail`]), and then the same
    /// buffer is fed through the identical encryption path via `io::Cursor`. This is bounded,
    /// ordinary work: documents added this way are individual photos/scans (M5's acceptance
    /// criterion is "12 MP photo, <5s end-to-end"), not the multi-hundred-MB blobs the streaming
    /// design exists for.
    ///
    /// # Errors
    /// [`ClientError::Storage`] on a local I/O failure. [`ClientError::Crypto`] if encryption
    /// itself fails (should not happen in ordinary operation).
    pub(crate) fn encrypt_new_document(
        &mut self,
        doc_id: DocId,
        mut reader: impl Read,
        fields: NewDocFields,
    ) -> Result<(DocumentRow, DocMeta)> {
        let NewDocFields {
            title,
            tags,
            note,
            mime,
            original_name,
            keep_offline,
        } = fields;

        let blob_id = Uuid::now_v7();
        let blobs_dir = self.store.blobs_dir();
        let tmp_path = blobs_dir.join(format!(".tmp-{}", Uuid::now_v7()));
        let final_path = blobs_dir.join(blob_id.to_string());

        let file = std::fs::File::create(&tmp_path)?;
        let hashing = HashingWriter::new(file);
        let mut enc = blob::Encryptor::new(hashing, &self.mk, doc_id)?;

        let thumb = if mime.starts_with("image/") {
            let mut buf = Vec::new();
            reader.read_to_end(&mut buf)?;
            let thumb = generate_thumbnail(&buf);
            std::io::copy(&mut std::io::Cursor::new(buf), &mut enc)?;
            thumb
        } else {
            std::io::copy(&mut reader, &mut enc)?;
            None
        };

        let hashing = enc.finish()?;
        hashing.inner.sync_all()?;
        let plain_size = hashing.count;
        let content_hash = hashing.hasher.finalize().to_hex().to_string();

        std::fs::rename(&tmp_path, &final_path)?;
        let ciphertext_len = i64::try_from(std::fs::metadata(&final_path)?.len())
            .map_err(|_| ClientError::Storage)?;

        let doc_meta = DocMeta {
            v: 1,
            title,
            tags,
            note,
            mime,
            size: plain_size,
            content_hash,
            original_name,
            created_at: now_rfc3339(),
            thumb,
        };
        let enc_meta = meta::seal(&self.mk, doc_id, 1, &doc_meta)?;

        let row = DocumentRow {
            id: doc_id.as_uuid(),
            version: 1,
            base_version: 0,
            blob_id: Some(blob_id),
            blob_size: ciphertext_len,
            enc_meta: enc_meta.as_bytes().to_vec(),
            deleted: false,
            dirty: true,
            keep_offline,
            updated_at: now_rfc3339(),
        };

        let conn = self.store.conn();
        let tx = conn.transaction()?;
        Store::upsert_document(&tx, &row)?;
        Store::cache_put(&tx, blob_id, &final_path, ciphertext_len, &row.updated_at)?;
        tx.commit()?;
        self.evict_cache_over_limit()?;

        Ok((row, doc_meta))
    }

    /// Evicts least-recently-used cached blobs (§4: "never evicting `keep_offline` blobs or
    /// dirty documents") until the cache is back under `cache_limit_mb` (default 512, stored in
    /// `kv` — see [`Self::cache_limit_mb`]/the CLI's ability to change it via the local store).
    fn evict_cache_over_limit(&mut self) -> Result<()> {
        let limit_bytes = self.cache_limit_mb()? * 1024 * 1024;
        let mut total = self.store.cache_total_size()?;
        if total <= limit_bytes {
            return Ok(());
        }
        for row in self.store.cache_evictable_by_lru()? {
            if total <= limit_bytes {
                break;
            }
            if self.store.cache_remove(row.blob_id)?.is_some() {
                let _ = std::fs::remove_file(&row.path);
                total -= row.size;
                self.refresh_cached_flag_by_blob(row.blob_id)?;
            }
        }
        Ok(())
    }

    /// `DocSummary` doesn't carry `blob_id` (it's local bookkeeping, not decrypted metadata), so
    /// refreshing its `cached` flag after an eviction means finding the owning document row(s)
    /// first. Cheap at CLI/M3 scale (bounded document counts).
    fn refresh_cached_flag_by_blob(&mut self, blob_id: Uuid) -> Result<()> {
        for row in self.store.list_documents()? {
            if row.blob_id == Some(blob_id) {
                self.refresh_cached_flag(row.id)?;
            }
        }
        Ok(())
    }

    /// The configured local blob cache size limit in MiB (`kv` key `cache_limit_mb`, default
    /// [`DEFAULT_CACHE_LIMIT_MB`]). Reflects whatever [`Self::set_cache_limit_mb`] last wrote,
    /// or the default if that has never been called — backs the Tauri layer's `settings_get`
    /// command (`docs/ARCHITECTURE.md §6`).
    ///
    /// # Errors
    /// [`ClientError::Storage`] if the local database can't be read.
    pub fn cache_limit_mb(&self) -> Result<i64> {
        Ok(self
            .store
            .kv_get(KV_CACHE_LIMIT_MB)?
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_CACHE_LIMIT_MB))
    }

    /// Sets the local cache size limit in MiB. `M4`'s Settings UI is the eventual caller; the
    /// CLI has no dedicated subcommand for this in M3.
    ///
    /// # Errors
    /// [`ClientError::Storage`] if the local database can't be written.
    pub fn set_cache_limit_mb(&mut self, mb: i64) -> Result<()> {
        self.store.kv_set(KV_CACHE_LIMIT_MB, &mb.to_string())?;
        self.evict_cache_over_limit()
    }

    /// Streams the decrypted content of document `id` into `writer`. Downloads the blob first
    /// (verifying its `ETag`) if it isn't already in the local cache.
    ///
    /// # Errors
    /// [`ClientError::NotFound`] if `id` doesn't exist (or is a tombstone). Network/storage/crypto
    /// errors otherwise.
    pub async fn open(&mut self, id: Uuid, mut writer: impl Write) -> Result<()> {
        let row = self.store.get_document(id)?.ok_or(ClientError::NotFound)?;
        if row.deleted {
            return Err(ClientError::NotFound);
        }
        let blob_id = row.blob_id.ok_or(ClientError::NotFound)?;

        let path = self.ensure_cached(blob_id, None).await?;
        self.refresh_cached_flag(id)?;

        let file = std::fs::File::open(&path)?;
        let doc_id = DocId::from_uuid(row.id);
        let mut dec = blob::Decryptor::new(file, &self.mk, doc_id)?;
        std::io::copy(&mut dec, &mut writer)?;
        self.store.cache_touch(blob_id, &now_rfc3339())?;
        Ok(())
    }

    /// Ensures `blob_id`'s ciphertext is present in the local cache, downloading and verifying
    /// it if not. Returns the cached file's path.
    pub(crate) async fn ensure_cached(
        &mut self,
        blob_id: Uuid,
        progress: Option<&mut crate::http::ProgressFn<'_>>,
    ) -> Result<PathBuf> {
        if let Some(row) = self.store.cache_get(blob_id)?
            && row.path.exists()
        {
            return Ok(row.path);
        }
        let blobs_dir = self.store.blobs_dir();
        let tmp_path = blobs_dir.join(format!(".tmp-{}", Uuid::now_v7()));
        let final_path = blobs_dir.join(blob_id.to_string());
        let (size, _sha) = self
            .http
            .get_blob_to_file(blob_id, &tmp_path, progress)
            .await?;
        std::fs::rename(&tmp_path, &final_path)?;
        let now = now_rfc3339();
        let conn = self.store.conn();
        let tx = conn.transaction()?;
        Store::cache_put(&tx, blob_id, &final_path, size, &now)?;
        tx.commit()?;
        self.evict_cache_over_limit()?;
        Ok(final_path)
    }

    /// Replaces `id`'s title/tags/note, bumping its local version and re-sealing `enc_meta`
    /// (bound to the new version — `docs/CRYPTO.md §4.3`). Marks the row `dirty`.
    ///
    /// # Errors
    /// [`ClientError::NotFound`] if `id` doesn't exist or is a tombstone.
    pub fn update_meta(
        &mut self,
        id: Uuid,
        title: String,
        tags: Vec<String>,
        note: String,
    ) -> Result<DocSummary> {
        let mut row = self.store.get_document(id)?.ok_or(ClientError::NotFound)?;
        if row.deleted {
            return Err(ClientError::NotFound);
        }
        let current = self
            .index
            .iter()
            .find(|s| s.id == id.to_string())
            .cloned()
            .ok_or(ClientError::NotFound)?;

        // Not `row.version += 1`: the server always assigns exactly `If-Match(base_version) + 1`
        // on the next successful push (`sync.rs::push_once`), no matter how many local edits
        // happened first. Re-sealing at `base_version + 1` every time (so a second/third local
        // edit before a sync re-targets the *same* version rather than stacking on top of the
        // previous edit's version) keeps `row.version` and `enc_meta`'s AAD-bound version
        // (`docs/CRYPTO.md §4.3`) permanently in agreement with what the server will actually
        // assign. See the regression test `update_meta_twice_before_sync_stays_decryptable`.
        row.version = row.base_version + 1;
        row.dirty = true;
        row.updated_at = now_rfc3339();

        let doc_meta = DocMeta {
            v: 1,
            title,
            tags,
            note,
            mime: current.mime,
            size: u64::try_from(current.size).unwrap_or(0),
            content_hash: current.content_hash,
            original_name: current.original_name,
            created_at: current.created_at,
            thumb: None,
        };
        let doc_id = DocId::from_uuid(id);
        let doc_version = doc_version_of(&row);
        let enc_meta = meta::seal(&self.mk, doc_id, doc_version, &doc_meta)?;
        row.enc_meta = enc_meta.as_bytes().to_vec();

        Store::upsert_document(self.store.conn(), &row)?;

        let cached = match row.blob_id {
            Some(blob_id) => self.store.cache_get(blob_id)?.is_some(),
            None => false,
        };
        let summary = doc_meta_to_summary(&row, &doc_meta, cached);
        if let Some(slot) = self.index.iter_mut().find(|s| s.id == id.to_string()) {
            *slot = summary.clone();
        }
        Ok(summary)
    }

    /// Tombstones document `id`: keeps its last metadata (resealed under the bumped version, so
    /// other devices can still show what was deleted), clears its blob reference, marks it
    /// `dirty`. Mirrors the server's own tombstone semantics (`docs/ARCHITECTURE.md §3`).
    ///
    /// # Errors
    /// [`ClientError::NotFound`] if `id` doesn't exist or is already a tombstone.
    pub fn delete(&mut self, id: Uuid) -> Result<()> {
        let mut row = self.store.get_document(id)?.ok_or(ClientError::NotFound)?;
        if row.deleted {
            return Err(ClientError::NotFound);
        }
        let current = self
            .index
            .iter()
            .find(|s| s.id == id.to_string())
            .cloned()
            .ok_or(ClientError::NotFound)?;

        // Same reasoning as `update_meta`: always reseal at `base_version + 1`, the exact
        // version the server will assign on the next push, never a running local counter.
        row.version = row.base_version + 1;
        row.dirty = true;
        row.deleted = true;
        row.blob_id = None;
        row.blob_size = 0;
        row.updated_at = now_rfc3339();

        let doc_meta = DocMeta {
            v: 1,
            title: current.title,
            tags: current.tags,
            note: current.note,
            mime: current.mime,
            size: u64::try_from(current.size).unwrap_or(0),
            content_hash: current.content_hash,
            original_name: current.original_name,
            created_at: current.created_at,
            thumb: None,
        };
        let doc_id = DocId::from_uuid(id);
        let doc_version = doc_version_of(&row);
        let enc_meta = meta::seal(&self.mk, doc_id, doc_version, &doc_meta)?;
        row.enc_meta = enc_meta.as_bytes().to_vec();

        Store::upsert_document(self.store.conn(), &row)?;
        self.index.retain(|s| s.id != id.to_string());
        Ok(())
    }

    /// Flips the local-only `keep_offline` flag. Never touches `version`/`dirty`/`enc_meta` — it
    /// is not part of the synced document record (`docs/ARCHITECTURE.md §4`).
    ///
    /// # Errors
    /// [`ClientError::NotFound`] if `id` doesn't exist.
    pub fn set_keep_offline(&mut self, id: Uuid, keep_offline: bool) -> Result<()> {
        let mut row = self.store.get_document(id)?.ok_or(ClientError::NotFound)?;
        row.keep_offline = keep_offline;
        Store::upsert_document(self.store.conn(), &row)?;
        if let Some(slot) = self.index.iter_mut().find(|s| s.id == id.to_string()) {
            slot.keep_offline = keep_offline;
        }
        Ok(())
    }

    pub(crate) fn refresh_cached_flag(&mut self, id: Uuid) -> Result<()> {
        if let Some(row) = self.store.get_document(id)? {
            let cached = match row.blob_id {
                Some(blob_id) => self.store.cache_get(blob_id)?.is_some(),
                None => false,
            };
            if let Some(slot) = self.index.iter_mut().find(|s| s.id == id.to_string()) {
                slot.cached = cached;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory under the OS temp dir, removed on drop — same pattern as `store.rs`'s test
    /// module.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "scrigno-client-vaulttest-{label}-{}",
                Uuid::now_v7()
            ));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Builds an `UnlockedVault` over a fresh local store without any network round trip —
    /// `encrypt_new_document` is purely local, so no server/wiremock is needed to exercise it.
    fn test_vault(label: &str) -> (TempDir, UnlockedVault) {
        let dir = TempDir::new(label);
        let store = Store::open(dir.path()).expect("open store");
        let mk = MasterKey::generate().expect("generate master key");
        let http = HttpClient::new(
            "http://127.0.0.1:1",
            SecretString::from("test-token".to_string()),
        )
        .expect("build http client");
        let vault = UnlockedVault {
            store,
            vault_id: VaultId::generate(),
            mk,
            http,
            index: Vec::new(),
            unreadable_at_unlock: Vec::new(),
        };
        (dir, vault)
    }

    /// A tiny solid-color PNG, generated with the `image` crate itself rather than a committed
    /// fixture.
    fn sample_png() -> Vec<u8> {
        let img = image::RgbImage::from_pixel(64, 64, image::Rgb([200, 80, 40]));
        let mut buf = Vec::new();
        image::DynamicImage::ImageRgb8(img)
            .write_to(&mut std::io::Cursor::new(&mut buf), image::ImageFormat::Png)
            .expect("encode sample png");
        buf
    }

    #[test]
    fn add_image_document_gets_a_thumbnail() {
        let (_dir, mut vault) = test_vault("thumb-image");
        let fields = NewDocFields {
            title: "Foto".to_string(),
            tags: vec![],
            note: String::new(),
            mime: "image/png".to_string(),
            original_name: "foto.png".to_string(),
            keep_offline: false,
        };

        let (_row, doc_meta) = vault
            .encrypt_new_document(
                DocId::generate(),
                std::io::Cursor::new(sample_png()),
                fields,
            )
            .expect("encrypt_new_document");

        let thumb = doc_meta
            .thumb
            .expect("expected a thumbnail for an image/* mime");
        assert!(
            thumb.len() <= THUMB_MAX_BYTES,
            "thumbnail base64 exceeds the 24 KiB cap: {} bytes",
            thumb.len()
        );
        let jpeg_bytes = BASE64
            .decode(thumb.as_bytes())
            .expect("thumb is valid base64");
        // Confirms the decoded bytes really are a JPEG, not just base64 noise.
        image::load_from_memory_with_format(&jpeg_bytes, image::ImageFormat::Jpeg)
            .expect("thumbnail bytes decode as JPEG");
    }

    #[test]
    fn add_non_image_document_has_no_thumbnail() {
        let (_dir, mut vault) = test_vault("thumb-non-image");
        let fields = NewDocFields {
            title: "Documento".to_string(),
            tags: vec![],
            note: String::new(),
            mime: "application/pdf".to_string(),
            original_name: "documento.pdf".to_string(),
            keep_offline: false,
        };

        let (_row, doc_meta) = vault
            .encrypt_new_document(
                DocId::generate(),
                std::io::Cursor::new(b"%PDF-1.4 not a real pdf".to_vec()),
                fields,
            )
            .expect("encrypt_new_document");

        assert_eq!(doc_meta.thumb, None);
    }

    #[test]
    fn get_meta_returns_full_doc_meta_including_thumb() {
        let (_dir, mut vault) = test_vault("get-meta-image");
        let fields = NewDocFields {
            title: "Foto".to_string(),
            tags: vec!["vacanze".to_string()],
            note: "una nota".to_string(),
            mime: "image/png".to_string(),
            original_name: "foto.png".to_string(),
            keep_offline: false,
        };
        let doc_id = DocId::generate();
        let (row, doc_meta) = vault
            .encrypt_new_document(doc_id, std::io::Cursor::new(sample_png()), fields)
            .expect("encrypt_new_document");

        let fetched = vault
            .get_meta(row.id)
            .expect("get_meta should find the just-added document");

        assert_eq!(fetched.title, doc_meta.title);
        assert_eq!(fetched.tags, doc_meta.tags);
        assert_eq!(fetched.note, doc_meta.note);
        assert_eq!(fetched.mime, doc_meta.mime);
        assert_eq!(fetched.size, doc_meta.size);
        assert_eq!(fetched.content_hash, doc_meta.content_hash);
        assert_eq!(fetched.original_name, doc_meta.original_name);
        assert_eq!(fetched.created_at, doc_meta.created_at);
        // The whole point of `get_meta` over `list()`/`DocSummary`: `thumb` survives.
        assert!(
            fetched.thumb.is_some(),
            "expected a thumbnail to round-trip"
        );
        assert_eq!(fetched.thumb, doc_meta.thumb);
    }

    #[test]
    fn get_meta_not_found_for_unknown_id() {
        let (_dir, vault) = test_vault("get-meta-missing");
        let err = vault
            .get_meta(Uuid::now_v7())
            .expect_err("unknown id should be NotFound");
        assert!(matches!(err, ClientError::NotFound));
    }

    #[test]
    fn cache_limit_mb_defaults_then_reflects_set_cache_limit_mb() {
        let (_dir, mut vault) = test_vault("cache-limit");

        let default = vault
            .cache_limit_mb()
            .expect("cache_limit_mb should read the default before any explicit set");
        assert_eq!(default, DEFAULT_CACHE_LIMIT_MB);

        vault
            .set_cache_limit_mb(1024)
            .expect("set_cache_limit_mb should succeed");
        let updated = vault
            .cache_limit_mb()
            .expect("cache_limit_mb should read back the new value");
        assert_eq!(updated, 1024);
    }

    /// Same as [`test_vault`], but pointed at `base_url` instead of an unreachable address —
    /// needed by [`add_recovery_keyslot_round_trips_through_unlock`], which requires a real
    /// (mocked) `/v1/vault/keyslots` endpoint to POST to.
    fn test_vault_with_server(label: &str, base_url: &str) -> (TempDir, UnlockedVault) {
        let dir = TempDir::new(label);
        let store = Store::open(dir.path()).expect("open store");
        let mk = MasterKey::generate().expect("generate master key");
        let http = HttpClient::new(base_url, SecretString::from("test-token".to_string()))
            .expect("build http client");
        let vault = UnlockedVault {
            store,
            vault_id: VaultId::generate(),
            mk,
            http,
            index: Vec::new(),
            unreadable_at_unlock: Vec::new(),
        };
        (dir, vault)
    }

    /// `add_recovery_keyslot` on an unlocked vault: (1) returns a plaintext code that is a
    /// valid, parseable Crockford Base32 recovery code (`scrigno_core::recovery::parse_code`);
    /// (2) actually POSTs a `recovery`-kind keyslot to `/v1/vault/keyslots` (mocked here with
    /// `wiremock`, same style as the crate's `tests/sync.rs`); and (3) — the important
    /// round-trip check — simulating an "unlock with the recovery code" against exactly what was
    /// sent to the server (deriving a KEK from the returned code via the same KDF params, then
    /// unwrapping the sent `wrapped_mk`) recovers the *same* master key bytes the vault was
    /// created with.
    #[tokio::test]
    async fn add_recovery_keyslot_round_trips_through_unlock() {
        use std::sync::{Arc, Mutex};

        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, Request, ResponseTemplate};

        let captured: Arc<Mutex<Option<serde_json::Value>>> = Arc::new(Mutex::new(None));
        let captured_for_mock = captured.clone();

        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/vault/keyslots"))
            .respond_with(move |req: &Request| {
                let body: serde_json::Value =
                    serde_json::from_slice(&req.body).expect("request body is valid JSON");
                *captured_for_mock.lock().expect("lock captured body") = Some(body.clone());
                ResponseTemplate::new(201).set_body_json(serde_json::json!({
                    "id": body["id"],
                    "kind": body["kind"],
                    "kdf": body["kdf"],
                    "wrapped_mk": body["wrapped_mk"],
                    "created_at": "2026-01-01T00:00:00Z",
                }))
            })
            .mount(&mock_server)
            .await;

        let (_dir, mut vault) = test_vault_with_server("recovery-roundtrip", &mock_server.uri());
        let vault_id = vault.vault_id;

        let code = vault
            .add_recovery_keyslot()
            .await
            .expect("add_recovery_keyslot should succeed against the mocked server");

        // (1) The returned code must be a valid, parseable Crockford Base32 recovery code.
        recovery::parse_code(&code)
            .expect("returned code should be parseable by recovery::parse_code");

        // (2) The server actually received a `recovery`-kind keyslot.
        let sent = captured
            .lock()
            .expect("lock captured body")
            .clone()
            .expect("mock server should have received exactly one POST");
        assert_eq!(sent["kind"], "recovery");

        // (3) Round trip: re-derive the KEK from the plaintext code the same way an "unlock with
        // recovery" flow would, and unwrap exactly the `wrapped_mk` that was sent to the server.
        let kdf: KdfParams =
            serde_json::from_value(sent["kdf"].clone()).expect("kdf field deserializes");
        let wrapped_mk_bytes = BASE64
            .decode(
                sent["wrapped_mk"]
                    .as_str()
                    .expect("wrapped_mk is a base64 string"),
            )
            .expect("wrapped_mk decodes as base64");
        let wrapped_mk =
            wrap::WrappedKey::from_slice(&wrapped_mk_bytes).expect("wrapped_mk is well-formed");
        let keyslot_id = KeyslotId::from_uuid(
            Uuid::parse_str(sent["id"].as_str().expect("id is a string"))
                .expect("id is a valid uuid"),
        );

        let recovery_secret = SecretString::from(code);
        let kek = derive_kek(&recovery_secret, &kdf).expect("derive_kek from recovery code");
        let recovered_mk = wrap::unwrap_mk(&kek, vault_id, keyslot_id, &wrapped_mk)
            .expect("unwrap_mk with the recovery-derived KEK should succeed");

        // `MasterKey` exposes no public accessor for its raw bytes outside `scrigno-core`
        // (docs/CRYPTO.md §9), so "same master key" is checked via AEAD authentication instead:
        // a fresh DEK wrapped under the vault's *real* master key only unwraps successfully
        // under `recovered_mk` if its bytes are identical to the original.
        let doc_id = DocId::generate();
        let probe_dek = Dek::generate().expect("generate probe dek");
        let wrapped_dek =
            wrap::wrap_dek(&vault.mk, doc_id, &probe_dek).expect("wrap probe dek under real mk");
        wrap::unwrap_dek(&recovered_mk, doc_id, &wrapped_dek).expect(
            "recovery-derived master key should unwrap data wrapped under the real master key",
        );

        // Negative control: an unrelated master key must NOT unwrap the same envelope — proves
        // the assertion above is actually exercising key equality, not vacuously passing.
        let unrelated_mk = MasterKey::generate().expect("generate unrelated mk");
        assert!(
            wrap::unwrap_dek(&unrelated_mk, doc_id, &wrapped_dek).is_err(),
            "an unrelated master key should not unwrap the probe envelope"
        );
    }
}
