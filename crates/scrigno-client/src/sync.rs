//! The sync engine: `UnlockedVault::sync()`, implementing `docs/ARCHITECTURE.md §5` exactly.
//!
//! Idempotent and resumable at any step: every local mutation (`apply_pulled_record`,
//! `encrypt_new_document`, one row's push) either fully commits (via one SQLite transaction or a
//! single atomic `UPDATE`) or doesn't happen at all, and the pull cursor is only advanced (and
//! persisted) after an entire page has been fully applied — so re-running `sync()` after a crash
//! at any point simply redoes (cheaply, idempotently) whatever didn't finish, per this
//! milestone's "kill mid-upload, re-run sync, it converges" acceptance criterion.

use uuid::Uuid;

use scrigno_core::blob;
use scrigno_core::ids::DocId;

use crate::error::Result;
use crate::http::PutOutcome;
use crate::store::{DocumentRow, Store};
use crate::types::{SyncReport, SyncWarning};
use crate::vault::{self, UnlockedVault};
use crate::wire::{DocumentRecordWire, PutDocWire};

/// Page size for `GET /v1/changes` (server caps at 500).
const PAGE_LIMIT: i64 = 200;
/// §5: "412 → go back to step 1 (bounded: 3 rounds, then return `SyncError::Contention`)."
const MAX_ROUNDS: u32 = 3;

impl UnlockedVault {
    /// Runs one full sync: pull, push (retrying on `412` up to [`MAX_ROUNDS`] total rounds),
    /// then prefetch `keep_offline` blobs missing from the cache.
    ///
    /// # Errors
    /// [`crate::error::ClientError::Contention`] if the same document keeps losing the
    /// optimistic-concurrency race for [`MAX_ROUNDS`] rounds in a row. Network/storage/crypto
    /// errors otherwise. A [`SyncWarning::ServerRollback`] does **not** fail the call — it is
    /// reported in the returned [`SyncReport`] instead (§5: "continue").
    pub async fn sync(&mut self) -> Result<SyncReport> {
        let mut report = SyncReport::default();

        for _round in 0..MAX_ROUNDS {
            let (pulled, conflicts, warnings) = self.pull().await?;
            report.pulled += pulled;
            report.conflicts += conflicts;
            report.warnings.extend(warnings);

            let (pushed, had_conflict) = self.push_once().await?;
            report.pushed += pushed;

            if !had_conflict {
                self.prefetch_keep_offline().await?;
                return Ok(report);
            }
        }
        Err(crate::error::ClientError::Contention)
    }

    /// §5 step 1: `GET /v1/changes?since=cursor` until `has_more == false`.
    async fn pull(&mut self) -> Result<(u32, u32, Vec<SyncWarning>)> {
        let mut pulled = 0u32;
        let mut conflicts = 0u32;
        let mut warnings = Vec::new();

        let mut cursor: i64 = self
            .store
            .kv_get(vault::KV_CURSOR)?
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        loop {
            let page = self.http.get_changes(cursor, PAGE_LIMIT).await?;

            for item in &page.items {
                if item.server_seq < cursor {
                    warnings.push(SyncWarning::ServerRollback {
                        doc_id: item.id.to_string(),
                        cursor,
                        server_seq: item.server_seq,
                    });
                }

                let existing = self.store.get_document(item.id)?;

                // Three cases, per `docs/ARCHITECTURE.md §5`:
                //   (a) local row missing, or present and clean (`!dirty`) → safe to overwrite.
                //   (b) `dirty` and `item.version > base_version` → real conflict: the server
                //       has moved past what our pending edit was based on. Keep the server
                //       record as-is for this id, spin the local edit off into a new
                //       conflict-copy document.
                //   (c) `dirty` and `item.version <= base_version` → the server has *not* moved
                //       past our edit's base: this is either our own prior state coming back
                //       around (the pull cursor catching up to a record this same device already
                //       pushed) or a genuine server rollback (already warned about above). Either
                //       way there is nothing to reconcile — the pending edit is still valid and
                //       must be left untouched so `push_once()` pushes it normally. Overwriting
                //       here would silently discard the dirty edit with no conflict copy and no
                //       error (the bug this comment block exists to prevent regressing).
                match existing {
                    Some(row) if row.dirty && item.version > row.base_version => {
                        let old_summary = self
                            .index
                            .iter()
                            .find(|s| s.id == item.id.to_string())
                            .cloned();
                        self.apply_pulled_record(item)?;
                        self.create_conflict_copy(&row, old_summary).await?;
                        conflicts += 1;
                    }
                    Some(row) if row.dirty => {
                        // Case (c): leave the local dirty row untouched.
                    }
                    _ => {
                        self.apply_pulled_record(item)?;
                    }
                }
                pulled += 1;
            }

            cursor = page.next_since;
            self.store.kv_set(vault::KV_CURSOR, &cursor.to_string())?;
            if !page.has_more {
                break;
            }
        }

        Ok((pulled, conflicts, warnings))
    }

    /// Overwrites (or inserts) the local row for `item.id` with the server's record: this is the
    /// "local row missing or `dirty == 0` → overwrite" branch of §5, and — called after the
    /// conflict-copy has captured the local change — also how the "keep the server record as-is
    /// for this id" half of the conflict branch is applied.
    fn apply_pulled_record(&mut self, item: &DocumentRecordWire) -> Result<()> {
        let existing = self.store.get_document(item.id)?;

        // "drop cached blob if `blob_id` changed": the old ciphertext, encrypted for this
        // `doc_id`, is worthless once the row points at a different blob.
        if let Some(old_blob) = existing.as_ref().and_then(|old| old.blob_id)
            && Some(old_blob) != item.blob_id
            && let Some(path) = self.store.cache_remove(old_blob)?
        {
            let _ = std::fs::remove_file(path);
        }

        let keep_offline = existing.as_ref().is_some_and(|r| r.keep_offline);
        let row = DocumentRow {
            id: item.id,
            version: item.version,
            base_version: item.version,
            blob_id: item.blob_id,
            blob_size: item.blob_size,
            enc_meta: item.enc_meta.clone(),
            deleted: item.deleted,
            dirty: false,
            keep_offline,
            updated_at: vault::now_rfc3339(),
        };
        Store::upsert_document(self.store.conn(), &row)?;

        self.index.retain(|s| s.id != item.id.to_string());
        if !row.deleted {
            let summary = vault::row_to_summary(&self.store, &self.mk, &row)?;
            self.index.push(summary);
        }
        Ok(())
    }

    /// §5's conflict branch, second half: "re-create the local change as a *new* document (new
    /// `UUIDv7`, meta title suffixed with ` (copia in conflitto <date>)`), dirty."
    ///
    /// `old_row`/`old_summary` are the local row/decrypted-summary **as they were before**
    /// [`Self::apply_pulled_record`] overwrote them with the server's record. A blob is bound to
    /// the `doc_id` it was encrypted for (`docs/CRYPTO.md §4.4`), so preserving the content under
    /// a fresh id requires decrypting the old blob and re-encrypting it under the new one — not
    /// just copying a row.
    ///
    /// No-op if `old_row` was itself a tombstone (a pending local delete has no content to
    /// preserve): the newer server-side edit simply wins, which loses no file content (only an
    /// abandoned local delete intent).
    async fn create_conflict_copy(
        &mut self,
        old_row: &DocumentRow,
        old_summary: Option<crate::types::DocSummary>,
    ) -> Result<()> {
        if old_row.deleted {
            return Ok(());
        }
        let Some(old_summary) = old_summary else {
            return Ok(());
        };
        let Some(old_blob_id) = old_row.blob_id else {
            return Ok(());
        };

        let old_doc_id = DocId::from_uuid(old_row.id);
        let cached_path = self.ensure_cached(old_blob_id, None).await?;
        let file = std::fs::File::open(&cached_path)?;
        let dec = blob::Decryptor::new(file, &self.mk, old_doc_id)?;

        let new_doc_id = DocId::generate();
        let title = format!(
            "{} (copia in conflitto {})",
            old_summary.title,
            today_date()
        );

        let fields = vault::NewDocFields {
            title,
            tags: old_summary.tags,
            note: old_summary.note,
            mime: old_summary.mime,
            original_name: old_summary.original_name,
            keep_offline: old_row.keep_offline,
        };
        let (row, doc_meta) = self.encrypt_new_document(new_doc_id, dec, fields)?;

        let summary = vault::doc_meta_to_summary(&row, &doc_meta, true);
        self.index.push(summary);
        Ok(())
    }

    /// §5 step 2: pushes every `dirty` row, oldest `updated_at` first. Returns `(pushed_count,
    /// any_412_seen)`.
    async fn push_once(&mut self) -> Result<(u32, bool)> {
        let mut pushed = 0u32;
        let mut had_conflict = false;

        let dirty_ids: Vec<Uuid> = Store::list_dirty_documents(self.store.conn())?
            .into_iter()
            .map(|r| r.id)
            .collect();

        for id in dirty_ids {
            let Some(mut row) = self.store.get_document(id)? else {
                continue;
            };
            if !row.dirty {
                // Already resolved by an earlier iteration this round (e.g. it was the target
                // of a conflict-copy overwrite in `pull()`).
                continue;
            }

            let outcome = if row.deleted {
                self.http.delete_doc(id, row.base_version).await?
            } else {
                let Some(blob_id) = row.blob_id else {
                    // A non-deleted row with no blob is not a state this crate ever produces.
                    continue;
                };
                // "if the blob is new (not yet on the server)": true exactly when this row has
                // never been successfully pushed before (`base_version == 0`) — every path that
                // sets a `blob_id` on an already-synced row (there is none in this crate's API)
                // would need the same treatment, but `update_meta`/`delete` never change it.
                if row.base_version == 0 {
                    let path = self.store.blobs_dir().join(blob_id.to_string());
                    self.http.put_blob(blob_id, &path, None).await?;
                }
                let body = PutDocWire {
                    blob_id,
                    blob_size: row.blob_size,
                    enc_meta: row.enc_meta.clone(),
                };
                self.http.put_doc(id, row.base_version, &body).await?
            };

            match outcome {
                PutOutcome::Applied(record) => {
                    row.dirty = false;
                    row.base_version = record.version;
                    row.version = record.version;
                    row.blob_id = record.blob_id;
                    row.blob_size = record.blob_size;
                    row.deleted = record.deleted;
                    Store::upsert_document(self.store.conn(), &row)?;
                    if let Some(slot) = self.index.iter_mut().find(|s| s.id == id.to_string()) {
                        slot.dirty = false;
                        slot.version = row.version;
                    }
                    pushed += 1;
                }
                PutOutcome::Conflict => {
                    had_conflict = true;
                }
            }
        }

        Ok((pushed, had_conflict))
    }

    /// §5 step 3: download blobs for `keep_offline` rows missing from the cache.
    async fn prefetch_keep_offline(&mut self) -> Result<()> {
        let rows: Vec<DocumentRow> = self
            .store
            .list_documents()?
            .into_iter()
            .filter(|r| r.keep_offline && !r.deleted)
            .collect();

        for row in rows {
            if let Some(blob_id) = row.blob_id
                && self.store.cache_get(blob_id)?.is_none()
            {
                self.ensure_cached(blob_id, None).await?;
                self.refresh_cached_flag(row.id)?;
            }
        }
        Ok(())
    }
}

/// Today's date (UTC), `YYYY-MM-DD`, for the conflict-copy title suffix.
fn today_date() -> String {
    let now = vault::now_rfc3339();
    now.get(0..10).unwrap_or(&now).to_string()
}
