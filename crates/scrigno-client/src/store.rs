//! Local SQLite store: one file per data dir, schema per `docs/ARCHITECTURE.md §4`.
//!
//! `rusqlite` directly (no ORM — the schema is three small tables). WAL mode. Schema version is
//! tracked via the `user_version` pragma so future milestones can add migrations without a
//! dedicated migrations table.
//!
//! Deviation from §4 (documented, see `crate` docs): the `kv` table additionally stores
//! `keyslot_json` (the full `Keyslot` JSON this device unlocks with) so `Vault::unlock` can
//! re-derive the master key **fully offline**, without a round trip to `GET /v1/vault`. §4 only
//! lists `keyslot_id_in_use`, which is not enough on its own to derive a KEK (the `kdf` params
//! and `wrapped_mk` are also needed).

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

use crate::error::{ClientError, Result};

const SCHEMA_VERSION: i32 = 1;
const DB_FILE_NAME: &str = "vault.sqlite3";
const BLOBS_DIR_NAME: &str = "blobs";

/// One row of the local `document` table (§4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DocumentRow {
    pub id: Uuid,
    pub version: i64,
    pub base_version: i64,
    pub blob_id: Option<Uuid>,
    pub blob_size: i64,
    pub enc_meta: Vec<u8>,
    pub deleted: bool,
    pub dirty: bool,
    pub keep_offline: bool,
    pub updated_at: String,
}

/// One row of the local `blob_cache` table (§4). `last_access` drives `ORDER BY` in the LRU
/// eviction query but isn't otherwise read by Rust code, so it isn't a field here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CacheRow {
    pub blob_id: Uuid,
    pub path: PathBuf,
    pub size: i64,
}

/// Owns the SQLite connection and the `<data_dir>/blobs/` cache directory.
pub(crate) struct Store {
    conn: Connection,
    data_dir: PathBuf,
}

impl Store {
    /// Opens (creating if absent) `<data_dir>/vault.sqlite3`, enables WAL mode, and applies the
    /// schema if this is a fresh database.
    pub fn open(data_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        std::fs::create_dir_all(data_dir.join(BLOBS_DIR_NAME))?;

        let conn = Connection::open(data_dir.join(DB_FILE_NAME))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        let mut store = Self {
            conn,
            data_dir: data_dir.to_path_buf(),
        };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&mut self) -> Result<()> {
        let current: i32 = self
            .conn
            .pragma_query_value(None, "user_version", |row| row.get(0))?;
        if current >= SCHEMA_VERSION {
            return Ok(());
        }
        self.conn.execute_batch(
            "BEGIN;
             CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS document (
               id            TEXT PRIMARY KEY,
               version       INTEGER NOT NULL,
               base_version  INTEGER NOT NULL,
               blob_id       TEXT,
               blob_size     INTEGER NOT NULL DEFAULT 0,
               enc_meta      BLOB NOT NULL,
               deleted       INTEGER NOT NULL DEFAULT 0,
               dirty         INTEGER NOT NULL DEFAULT 0,
               keep_offline  INTEGER NOT NULL DEFAULT 0,
               updated_at    TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS blob_cache (
               blob_id      TEXT PRIMARY KEY,
               path         TEXT NOT NULL,
               size         INTEGER NOT NULL,
               last_access  TEXT NOT NULL
             );
             COMMIT;",
        )?;
        self.conn
            .pragma_update(None, "user_version", SCHEMA_VERSION)?;
        Ok(())
    }

    /// The `<data_dir>/blobs/` directory ciphertext blobs are cached in.
    pub fn blobs_dir(&self) -> PathBuf {
        self.data_dir.join(BLOBS_DIR_NAME)
    }

    /// Direct access to the connection, for callers (the sync engine) that need a hand-rolled
    /// transaction spanning several of this module's operations.
    pub fn conn(&mut self) -> &mut Connection {
        &mut self.conn
    }

    // ---------------------------------------------------------------- kv ---------------------

    pub fn kv_get(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM kv WHERE key = ?1", params![key], |r| {
                r.get(0)
            })
            .optional()?)
    }

    pub fn kv_set(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO kv (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    // ---------------------------------------------------------- document ---------------------

    pub fn upsert_document(conn: &Connection, row: &DocumentRow) -> Result<()> {
        conn.execute(
            "INSERT INTO document
               (id, version, base_version, blob_id, blob_size, enc_meta, deleted, dirty, keep_offline, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(id) DO UPDATE SET
               version = excluded.version,
               base_version = excluded.base_version,
               blob_id = excluded.blob_id,
               blob_size = excluded.blob_size,
               enc_meta = excluded.enc_meta,
               deleted = excluded.deleted,
               dirty = excluded.dirty,
               keep_offline = excluded.keep_offline,
               updated_at = excluded.updated_at",
            params![
                row.id.to_string(),
                row.version,
                row.base_version,
                row.blob_id.map(|b| b.to_string()),
                row.blob_size,
                row.enc_meta,
                row.deleted,
                row.dirty,
                row.keep_offline,
                row.updated_at,
            ],
        )?;
        Ok(())
    }

    pub fn get_document(&self, id: Uuid) -> Result<Option<DocumentRow>> {
        self.conn
            .query_row(
                "SELECT id, version, base_version, blob_id, blob_size, enc_meta, deleted, dirty, keep_offline, updated_at
                 FROM document WHERE id = ?1",
                params![id.to_string()],
                Self::row_to_document,
            )
            .optional()
            .map_err(ClientError::from)
    }

    pub fn list_documents(&self) -> Result<Vec<DocumentRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, version, base_version, blob_id, blob_size, enc_meta, deleted, dirty, keep_offline, updated_at
             FROM document ORDER BY updated_at ASC",
        )?;
        let rows = stmt
            .query_map([], Self::row_to_document)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn list_dirty_documents(conn: &Connection) -> Result<Vec<DocumentRow>> {
        let mut stmt = conn.prepare(
            "SELECT id, version, base_version, blob_id, blob_size, enc_meta, deleted, dirty, keep_offline, updated_at
             FROM document WHERE dirty = 1 ORDER BY updated_at ASC",
        )?;
        let rows = stmt
            .query_map([], Self::row_to_document)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    fn row_to_document(r: &rusqlite::Row<'_>) -> rusqlite::Result<DocumentRow> {
        let id: String = r.get(0)?;
        let blob_id: Option<String> = r.get(3)?;
        Ok(DocumentRow {
            id: Uuid::parse_str(&id).unwrap_or_default(),
            version: r.get(1)?,
            base_version: r.get(2)?,
            blob_id: blob_id.and_then(|s| Uuid::parse_str(&s).ok()),
            blob_size: r.get(4)?,
            enc_meta: r.get(5)?,
            deleted: r.get(6)?,
            dirty: r.get(7)?,
            keep_offline: r.get(8)?,
            updated_at: r.get(9)?,
        })
    }

    // --------------------------------------------------------- blob cache --------------------

    pub fn cache_get(&self, blob_id: Uuid) -> Result<Option<CacheRow>> {
        self.conn
            .query_row(
                "SELECT blob_id, path, size, last_access FROM blob_cache WHERE blob_id = ?1",
                params![blob_id.to_string()],
                Self::row_to_cache,
            )
            .optional()
            .map_err(ClientError::from)
    }

    pub fn cache_put(
        conn: &Connection,
        blob_id: Uuid,
        path: &Path,
        size: i64,
        now: &str,
    ) -> Result<()> {
        conn.execute(
            "INSERT INTO blob_cache (blob_id, path, size, last_access) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(blob_id) DO UPDATE SET path = excluded.path, size = excluded.size, last_access = excluded.last_access",
            params![blob_id.to_string(), path.to_string_lossy(), size, now],
        )?;
        Ok(())
    }

    pub fn cache_touch(&self, blob_id: Uuid, now: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE blob_cache SET last_access = ?2 WHERE blob_id = ?1",
            params![blob_id.to_string(), now],
        )?;
        Ok(())
    }

    /// Removes a cache row and returns its file path (caller deletes the file), if it existed.
    pub fn cache_remove(&self, blob_id: Uuid) -> Result<Option<PathBuf>> {
        let row = self.cache_get(blob_id)?;
        if row.is_some() {
            self.conn.execute(
                "DELETE FROM blob_cache WHERE blob_id = ?1",
                params![blob_id.to_string()],
            )?;
        }
        Ok(row.map(|r| r.path))
    }

    pub fn cache_total_size(&self) -> Result<i64> {
        Ok(self
            .conn
            .query_row("SELECT COALESCE(SUM(size), 0) FROM blob_cache", [], |r| {
                r.get(0)
            })?)
    }

    /// Cached blobs eligible for LRU eviction: not referenced by a `keep_offline` or `dirty`
    /// document row, oldest `last_access` first (§4: "never evicting `keep_offline` blobs or
    /// dirty documents").
    pub fn cache_evictable_by_lru(&self) -> Result<Vec<CacheRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT bc.blob_id, bc.path, bc.size, bc.last_access
             FROM blob_cache bc
             WHERE NOT EXISTS (
               SELECT 1 FROM document d
               WHERE d.blob_id = bc.blob_id AND (d.keep_offline = 1 OR d.dirty = 1)
             )
             ORDER BY bc.last_access ASC",
        )?;
        let rows = stmt
            .query_map([], Self::row_to_cache)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    fn row_to_cache(r: &rusqlite::Row<'_>) -> rusqlite::Result<CacheRow> {
        let blob_id: String = r.get(0)?;
        let path: String = r.get(1)?;
        Ok(CacheRow {
            blob_id: Uuid::parse_str(&blob_id).unwrap_or_default(),
            path: PathBuf::from(path),
            size: r.get(2)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory under the OS temp dir, removed on drop. Not `tempfile` (not a workspace
    /// dependency, and this crate only needs this in tests): a unique name is enough since
    /// nothing else on the machine races to create the exact same path.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("scrigno-client-test-{label}-{}", Uuid::now_v7()));
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

    fn sample_row(id: Uuid) -> DocumentRow {
        DocumentRow {
            id,
            version: 1,
            base_version: 0,
            blob_id: Some(Uuid::now_v7()),
            blob_size: 42,
            enc_meta: vec![1, 2, 3],
            deleted: false,
            dirty: true,
            keep_offline: false,
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn open_creates_schema_and_is_idempotent() {
        let dir = TempDir::new("open");
        let store = Store::open(dir.path()).expect("open");
        drop(store);
        // Re-opening an already-initialised store must not error or reset anything.
        let store = Store::open(dir.path()).expect("re-open");
        assert!(store.list_documents().expect("list").is_empty());
        assert!(dir.path().join(BLOBS_DIR_NAME).is_dir());
    }

    #[test]
    fn kv_roundtrip_and_overwrite() {
        let dir = TempDir::new("kv");
        let store = Store::open(dir.path()).expect("open");
        assert_eq!(store.kv_get("missing").expect("get"), None);

        store.kv_set("server_url", "http://a").expect("set");
        assert_eq!(
            store.kv_get("server_url").expect("get"),
            Some("http://a".to_string())
        );

        store.kv_set("server_url", "http://b").expect("overwrite");
        assert_eq!(
            store.kv_get("server_url").expect("get"),
            Some("http://b".to_string())
        );
    }

    #[test]
    fn document_upsert_get_list_roundtrip() {
        let dir = TempDir::new("doc");
        let mut store = Store::open(dir.path()).expect("open");
        let id = Uuid::now_v7();
        let row = sample_row(id);

        Store::upsert_document(store.conn(), &row).expect("insert");
        let fetched = store.get_document(id).expect("get").expect("present");
        assert_eq!(fetched.version, 1);
        assert_eq!(fetched.enc_meta, vec![1, 2, 3]);
        assert!(fetched.dirty);

        let mut updated = fetched;
        updated.version = 2;
        updated.dirty = false;
        Store::upsert_document(store.conn(), &updated).expect("update via upsert");

        let all = store.list_documents().expect("list");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].version, 2);
        assert!(!all[0].dirty);
    }

    #[test]
    fn list_dirty_documents_filters_correctly() {
        let dir = TempDir::new("dirty");
        let mut store = Store::open(dir.path()).expect("open");
        let mut clean = sample_row(Uuid::now_v7());
        clean.dirty = false;
        let dirty = sample_row(Uuid::now_v7());

        Store::upsert_document(store.conn(), &clean).expect("insert clean");
        Store::upsert_document(store.conn(), &dirty).expect("insert dirty");

        let dirty_rows = Store::list_dirty_documents(store.conn()).expect("list dirty");
        assert_eq!(dirty_rows.len(), 1);
        assert_eq!(dirty_rows[0].id, dirty.id);
    }

    /// Crash-safety: a transaction that is dropped without `commit()` (simulating the process
    /// being killed between the blob rename and the commit, per `vault::encrypt_new_document`'s
    /// own doc comment) must leave **no trace** — neither the `document` row nor the
    /// `blob_cache` row it would have written.
    #[test]
    fn uncommitted_transaction_leaves_no_trace() {
        let dir = TempDir::new("crash");
        let mut store = Store::open(dir.path()).expect("open");
        let id = Uuid::now_v7();
        let blob_id = Uuid::now_v7();
        let row = sample_row(id);

        {
            let conn = store.conn();
            let tx = conn.transaction().expect("begin tx");
            Store::upsert_document(&tx, &row).expect("insert in tx");
            Store::cache_put(&tx, blob_id, Path::new("/tmp/whatever"), 10, "now")
                .expect("cache_put in tx");
            // Deliberately dropped instead of `tx.commit()`: rusqlite rolls back on drop.
        }

        assert_eq!(store.get_document(id).expect("get"), None);
        assert_eq!(store.cache_get(blob_id).expect("cache_get"), None);
    }

    /// The mirror-image case: a transaction that *does* commit must make both writes visible
    /// (the atomicity CLAUDE.md requires for "insert document row + move blob into cache").
    #[test]
    fn committed_transaction_makes_both_writes_visible() {
        let dir = TempDir::new("commit");
        let mut store = Store::open(dir.path()).expect("open");
        let id = Uuid::now_v7();
        let blob_id = Uuid::now_v7();
        let row = sample_row(id);

        {
            let conn = store.conn();
            let tx = conn.transaction().expect("begin tx");
            Store::upsert_document(&tx, &row).expect("insert in tx");
            Store::cache_put(&tx, blob_id, Path::new("/tmp/whatever"), 10, "now")
                .expect("cache_put in tx");
            tx.commit().expect("commit");
        }

        assert!(store.get_document(id).expect("get").is_some());
        assert!(store.cache_get(blob_id).expect("cache_get").is_some());
    }

    #[test]
    fn cache_remove_returns_path_and_deletes_row() {
        let dir = TempDir::new("cache-remove");
        let mut store = Store::open(dir.path()).expect("open");
        let blob_id = Uuid::now_v7();
        Store::cache_put(store.conn(), blob_id, Path::new("/tmp/x"), 5, "now").expect("put");

        let removed = store.cache_remove(blob_id).expect("remove");
        assert_eq!(removed, Some(PathBuf::from("/tmp/x")));
        assert_eq!(store.cache_get(blob_id).expect("get"), None);
        assert_eq!(store.cache_remove(blob_id).expect("remove again"), None);
    }

    #[test]
    fn cache_total_size_sums_all_rows() {
        let dir = TempDir::new("cache-size");
        let mut store = Store::open(dir.path()).expect("open");
        assert_eq!(store.cache_total_size().expect("size"), 0);

        Store::cache_put(
            store.conn(),
            Uuid::now_v7(),
            Path::new("/tmp/a"),
            100,
            "now",
        )
        .expect("put a");
        Store::cache_put(
            store.conn(),
            Uuid::now_v7(),
            Path::new("/tmp/b"),
            250,
            "now",
        )
        .expect("put b");
        assert_eq!(store.cache_total_size().expect("size"), 350);
    }

    #[test]
    fn cache_evictable_by_lru_excludes_keep_offline_and_dirty() {
        let dir = TempDir::new("lru");
        let mut store = Store::open(dir.path()).expect("open");

        let evictable_blob = Uuid::now_v7();
        let keep_offline_blob = Uuid::now_v7();
        let dirty_blob = Uuid::now_v7();
        let orphan_blob = Uuid::now_v7();

        for (blob_id, last_access) in [
            (evictable_blob, "2026-01-01T00:00:00Z"),
            (keep_offline_blob, "2025-01-01T00:00:00Z"),
            (dirty_blob, "2025-01-01T00:00:00Z"),
            (orphan_blob, "2025-06-01T00:00:00Z"),
        ] {
            Store::cache_put(store.conn(), blob_id, Path::new("/tmp/b"), 1, last_access)
                .expect("cache_put");
        }

        let mut evictable_row = sample_row(Uuid::now_v7());
        evictable_row.blob_id = Some(evictable_blob);
        evictable_row.dirty = false;
        evictable_row.keep_offline = false;

        let mut keep_offline_row = sample_row(Uuid::now_v7());
        keep_offline_row.blob_id = Some(keep_offline_blob);
        keep_offline_row.dirty = false;
        keep_offline_row.keep_offline = true;

        let mut dirty_row = sample_row(Uuid::now_v7());
        dirty_row.blob_id = Some(dirty_blob);
        dirty_row.dirty = true;
        dirty_row.keep_offline = false;

        // `orphan_blob` has no owning document row at all (e.g. left behind by a superseded
        // `blob_id` after a pull) — still evictable.

        for row in [&evictable_row, &keep_offline_row, &dirty_row] {
            Store::upsert_document(store.conn(), row).expect("insert doc");
        }

        let evictable: Vec<Uuid> = store
            .cache_evictable_by_lru()
            .expect("evictable")
            .into_iter()
            .map(|r| r.blob_id)
            .collect();

        assert!(evictable.contains(&evictable_blob));
        assert!(evictable.contains(&orphan_blob));
        assert!(!evictable.contains(&keep_offline_blob));
        assert!(!evictable.contains(&dirty_blob));
    }
}
