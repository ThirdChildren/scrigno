//! wiremock tests for the sync engine (`docs/ARCHITECTURE.md §5`), per CLAUDE.md's testing
//! policy: clean pull, clean push, conflict → conflict copy, 412 retry, resume after an
//! interrupted upload, contention after 3 rounds, and rollback detection.
//!
//! These are black-box tests against `scrigno-client`'s public API only (an integration test
//! crate can't reach `pub(crate)` items) driven against a small in-process fake `/v1/*` server
//! (`FakeState`, below) rather than the real `scrigno-server` — `wiremock` intercepts the HTTP
//! calls `scrigno-client` makes and a handful of `Respond` closures implement just enough of
//! `docs/ARCHITECTURE.md §3`'s contract (optimistic concurrency on `PUT`/`DELETE /v1/docs/{id}`,
//! the `412` body shape, blob content-addressed storage) to exercise the sync algorithm
//! faithfully. Two-device scenarios use two real `Vault`s (`create` + `join`) against the same
//! fake backend so both genuinely share one master key, exactly as on real devices — this is
//! what lets the conflict test decrypt a "remote" record for real, without fabricating
//! ciphertext.

use std::collections::HashMap;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use secrecy::SecretString;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

use scrigno_client::{ClientError, Vault};

// --------------------------------------------------------------- test scaffolding -------------

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "scrigno-client-synctest-{label}-{}",
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

fn token() -> SecretString {
    SecretString::from("test-token".to_string())
}

fn passphrase() -> SecretString {
    SecretString::from("correct horse battery staple".to_string())
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[derive(Clone)]
struct DocRecord {
    id: Uuid,
    version: i64,
    blob_id: Option<Uuid>,
    blob_size: i64,
    enc_meta_b64: String,
    deleted: bool,
    server_seq: i64,
    updated_at: String,
}

impl DocRecord {
    fn to_json(&self) -> serde_json::Value {
        json!({
            "id": self.id,
            "version": self.version,
            "blob_id": self.blob_id,
            "blob_size": self.blob_size,
            "enc_meta": self.enc_meta_b64,
            "deleted": self.deleted,
            "server_seq": self.server_seq,
            "updated_at": self.updated_at,
        })
    }
}

/// The state of our fake `/v1/*` backend, mutated both by mocked HTTP handlers (normal traffic)
/// and directly by test bodies (to inject the races/failures each scenario needs).
#[derive(Default)]
struct FakeState {
    vault_id: Uuid,
    keyslot: Option<serde_json::Value>,
    docs: HashMap<Uuid, DocRecord>,
    blobs: HashMap<Uuid, (i64, String, Vec<u8>)>,
    seq: i64,
    /// Remaining forced `412`s for a given doc id, regardless of the real `If-Match` value.
    force_412: HashMap<Uuid, u32>,
    /// Remaining forced `500`s for **any** blob `PUT` (not keyed by blob id: the test that uses
    /// this doesn't know the client-generated blob id up front, only the document id).
    force_blob_fail: u32,
    /// When set, the next `GET /v1/changes` call returns exactly this page (bypassing the
    /// normal `server_seq > since` filter) and then clears itself. Used by the rollback test.
    force_next_changes: Option<(Vec<DocRecord>, i64, bool)>,
}

type Shared = Arc<Mutex<FakeState>>;

fn doc_id_from_path(req: &Request) -> Uuid {
    let raw = req.url.path().rsplit('/').next().unwrap_or_default();
    Uuid::parse_str(raw).unwrap_or_default()
}

// One function registering all 7 `/v1/*` mock endpoints together (rather than splitting into
// several helper functions) so the whole fake backend's behaviour is visible in one place.
#[allow(clippy::too_many_lines)]
async fn fake_server() -> (MockServer, Shared) {
    let mock_server = MockServer::start().await;
    let state: Shared = Arc::new(Mutex::new(FakeState::default()));

    // POST /v1/vault
    {
        let state = state.clone();
        Mock::given(method("POST"))
            .and(path("/v1/vault"))
            .respond_with(move |req: &Request| {
                let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
                let mut st = state.lock().unwrap();
                let id = body["id"].as_str().unwrap().to_string();
                let mut keyslot = body["keyslot"].clone();
                keyslot["created_at"] = json!("2026-01-01T00:00:00Z");
                st.vault_id = Uuid::parse_str(&id).unwrap();
                st.keyslot = Some(keyslot.clone());
                ResponseTemplate::new(201).set_body_json(json!({
                    "id": id,
                    "created_at": "2026-01-01T00:00:00Z",
                    "keyslots": [keyslot],
                }))
            })
            .mount(&mock_server)
            .await;
    }

    // GET /v1/vault
    {
        let state = state.clone();
        Mock::given(method("GET"))
            .and(path("/v1/vault"))
            .respond_with(move |_req: &Request| {
                let st = state.lock().unwrap();
                match &st.keyslot {
                    Some(ks) => ResponseTemplate::new(200).set_body_json(json!({
                        "id": st.vault_id,
                        "created_at": "2026-01-01T00:00:00Z",
                        "keyslots": [ks],
                    })),
                    None => ResponseTemplate::new(404).set_body_json(json!({
                        "error": {"code": "vault_not_initialised", "message": "no vault"}
                    })),
                }
            })
            .mount(&mock_server)
            .await;
    }

    // GET /v1/changes
    {
        let state = state.clone();
        Mock::given(method("GET"))
            .and(path("/v1/changes"))
            .respond_with(move |req: &Request| {
                let since: i64 = req
                    .url
                    .query_pairs()
                    .find(|(k, _)| k == "since")
                    .and_then(|(_, v)| v.parse().ok())
                    .unwrap_or(0);
                let mut st = state.lock().unwrap();

                if let Some((items, next_since, has_more)) = st.force_next_changes.take() {
                    let body = json!({
                        "items": items.iter().map(DocRecord::to_json).collect::<Vec<_>>(),
                        "next_since": next_since,
                        "has_more": has_more,
                    });
                    return ResponseTemplate::new(200).set_body_json(body);
                }

                let mut items: Vec<DocRecord> = st
                    .docs
                    .values()
                    .filter(|d| d.server_seq > since)
                    .cloned()
                    .collect();
                items.sort_by_key(|d| d.server_seq);
                let next_since = items.last().map_or(since, |d| d.server_seq);
                let body = json!({
                    "items": items.iter().map(DocRecord::to_json).collect::<Vec<_>>(),
                    "next_since": next_since,
                    "has_more": false,
                });
                ResponseTemplate::new(200).set_body_json(body)
            })
            .mount(&mock_server)
            .await;
    }

    // PUT /v1/docs/{id}
    {
        let state = state.clone();
        Mock::given(method("PUT"))
            .and(path_regex(r"^/v1/docs/[0-9a-fA-F-]+$"))
            .respond_with(move |req: &Request| {
                let id = doc_id_from_path(req);
                let if_match: i64 = req
                    .headers
                    .get("if-match")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
                let mut st = state.lock().unwrap();

                if let Some(remaining) = st.force_412.get_mut(&id)
                    && *remaining > 0
                {
                    *remaining -= 1;
                    let fabricated = json!({
                        "id": id, "version": if_match.max(1), "blob_id": null,
                        "blob_size": 0, "enc_meta": "", "deleted": false,
                        "server_seq": 0, "updated_at": "2026-01-01T00:00:00Z",
                    });
                    return ResponseTemplate::new(412).set_body_json(fabricated);
                }

                let current_version = st.docs.get(&id).map_or(0, |d| d.version);
                if current_version != if_match {
                    let body = st.docs.get(&id).map_or_else(
                        || {
                            json!({
                                "id": id, "version": 0, "blob_id": null, "blob_size": 0,
                                "enc_meta": "", "deleted": false, "server_seq": 0,
                                "updated_at": "2026-01-01T00:00:00Z",
                            })
                        },
                        DocRecord::to_json,
                    );
                    return ResponseTemplate::new(412).set_body_json(body);
                }

                st.seq += 1;
                let seq = st.seq;
                let blob_id = body["blob_id"]
                    .as_str()
                    .and_then(|s| Uuid::parse_str(s).ok());
                let record = DocRecord {
                    id,
                    version: if_match + 1,
                    blob_id,
                    blob_size: body["blob_size"].as_i64().unwrap_or(0),
                    enc_meta_b64: body["enc_meta"].as_str().unwrap_or("").to_string(),
                    deleted: false,
                    server_seq: seq,
                    updated_at: "2026-01-01T00:00:00Z".to_string(),
                };
                st.docs.insert(id, record.clone());
                let status = if if_match == 0 { 201 } else { 200 };
                ResponseTemplate::new(status).set_body_json(record.to_json())
            })
            .mount(&mock_server)
            .await;
    }

    // DELETE /v1/docs/{id}
    {
        let state = state.clone();
        Mock::given(method("DELETE"))
            .and(path_regex(r"^/v1/docs/[0-9a-fA-F-]+$"))
            .respond_with(move |req: &Request| {
                let id = doc_id_from_path(req);
                let if_match: i64 = req
                    .headers
                    .get("if-match")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                let mut st = state.lock().unwrap();

                let current_version = st.docs.get(&id).map_or(0, |d| d.version);
                if current_version != if_match || !st.docs.contains_key(&id) {
                    let body = st.docs.get(&id).map_or_else(
                        || {
                            json!({
                                "id": id, "version": 0, "blob_id": null, "blob_size": 0,
                                "enc_meta": "", "deleted": false, "server_seq": 0,
                                "updated_at": "2026-01-01T00:00:00Z",
                            })
                        },
                        DocRecord::to_json,
                    );
                    return ResponseTemplate::new(412).set_body_json(body);
                }

                st.seq += 1;
                let seq = st.seq;
                let existing = st.docs.get(&id).cloned().expect("checked above");
                let record = DocRecord {
                    id,
                    version: if_match + 1,
                    blob_id: None,
                    blob_size: 0,
                    enc_meta_b64: existing.enc_meta_b64,
                    deleted: true,
                    server_seq: seq,
                    updated_at: "2026-01-01T00:00:00Z".to_string(),
                };
                st.docs.insert(id, record.clone());
                ResponseTemplate::new(200).set_body_json(record.to_json())
            })
            .mount(&mock_server)
            .await;
    }

    // PUT /v1/blobs/{id}
    {
        let state = state.clone();
        Mock::given(method("PUT"))
            .and(path_regex(r"^/v1/blobs/[0-9a-fA-F-]+$"))
            .respond_with(move |req: &Request| {
                let id = doc_id_from_path(req);
                let mut st = state.lock().unwrap();

                if st.force_blob_fail > 0 {
                    st.force_blob_fail -= 1;
                    return ResponseTemplate::new(500);
                }

                let bytes = req.body.clone();
                let mut hasher = Sha256::new();
                hasher.update(&bytes);
                let sha_hex = hex_encode(&hasher.finalize());
                let size = i64::try_from(bytes.len()).unwrap_or(0);
                let is_new = !st.blobs.contains_key(&id);
                st.blobs.insert(id, (size, sha_hex.clone(), bytes));
                let status = if is_new { 201 } else { 200 };
                ResponseTemplate::new(status)
                    .set_body_json(json!({"id": id, "size": size, "sha256": sha_hex}))
            })
            .mount(&mock_server)
            .await;
    }

    // GET /v1/blobs/{id}
    {
        let state = state.clone();
        Mock::given(method("GET"))
            .and(path_regex(r"^/v1/blobs/[0-9a-fA-F-]+$"))
            .respond_with(move |req: &Request| {
                let id = doc_id_from_path(req);
                let st = state.lock().unwrap();
                match st.blobs.get(&id) {
                    Some((_size, sha, bytes)) => ResponseTemplate::new(200)
                        .insert_header("ETag", format!("\"{sha}\""))
                        .set_body_bytes(bytes.clone()),
                    None => ResponseTemplate::new(404).set_body_json(json!({
                        "error": {"code": "not_found", "message": "no such blob"}
                    })),
                }
            })
            .mount(&mock_server)
            .await;
    }

    (mock_server, state)
}

// -------------------------------------------------------------------------- tests -------------

/// Clean push: a brand-new local document, `sync()`d against an empty server, ends up recorded
/// there with matching ciphertext.
#[tokio::test]
async fn clean_push() {
    let (server, state) = fake_server().await;
    let dir = TempDir::new("push");

    let mut vault = Vault::open(dir.path())
        .expect("open")
        .create(&server.uri(), token(), &passphrase())
        .await
        .expect("create");

    let summary = vault
        .add(
            Cursor::new(b"hello scrigno".to_vec()),
            "Titolo".to_string(),
            vec!["tag".to_string()],
            "nota".to_string(),
            "text/plain".to_string(),
            "hello.txt".to_string(),
        )
        .await
        .expect("add");
    assert!(summary.dirty);

    let report = vault.sync().await.expect("sync");
    assert_eq!(report.pushed, 1);
    assert_eq!(report.pulled, 0);
    assert_eq!(report.conflicts, 0);
    assert!(report.warnings.is_empty());

    let list = vault.list();
    assert_eq!(list.len(), 1);
    assert!(!list[0].dirty);

    let st = state.lock().unwrap();
    assert_eq!(st.docs.len(), 1);
    let doc = st.docs.values().next().expect("one doc");
    assert_eq!(doc.version, 1);
    let blob_id = doc.blob_id.expect("blob id");
    let (_, _, bytes) = st.blobs.get(&blob_id).expect("blob uploaded");
    assert!(!bytes.is_empty(), "ciphertext was actually uploaded");
}

/// Clean pull: device B joins the same vault device A created and pushed a document to, and
/// `sync()` alone (no local changes on B) pulls and decrypts it correctly.
#[tokio::test]
async fn clean_pull() {
    let (server, _state) = fake_server().await;
    let dir_a = TempDir::new("pull-a");
    let dir_b = TempDir::new("pull-b");

    let mut vault_a = Vault::open(dir_a.path())
        .expect("open a")
        .create(&server.uri(), token(), &passphrase())
        .await
        .expect("create");
    vault_a
        .add(
            Cursor::new(b"shared content".to_vec()),
            "Documento condiviso".to_string(),
            vec![],
            String::new(),
            "text/plain".to_string(),
            "shared.txt".to_string(),
        )
        .await
        .expect("add on a");
    vault_a.sync().await.expect("sync a");

    let mut vault_b = Vault::open(dir_b.path())
        .expect("open b")
        .join(&server.uri(), token(), &passphrase())
        .await
        .expect("join");

    let report = vault_b.sync().await.expect("sync b");
    assert_eq!(report.pulled, 1);
    assert_eq!(report.pushed, 0);
    assert_eq!(report.conflicts, 0);

    let list = vault_b.list();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].title, "Documento condiviso");
    assert!(!list[0].dirty);
}

/// Conflict → conflict copy: both devices edit the same document while offline from each other;
/// B pushes first, then A's `sync()` must turn A's still-pending edit into a new, dirty
/// conflict-copy document (title-suffixed) instead of silently overwriting or discarding it.
#[tokio::test]
async fn conflict_creates_conflict_copy() {
    let (server, state) = fake_server().await;
    let dir_a = TempDir::new("conflict-a");
    let dir_b = TempDir::new("conflict-b");

    let mut vault_a = Vault::open(dir_a.path())
        .expect("open a")
        .create(&server.uri(), token(), &passphrase())
        .await
        .expect("create");
    let original = vault_a
        .add(
            Cursor::new(b"v1 content".to_vec()),
            "Originale".to_string(),
            vec![],
            String::new(),
            "text/plain".to_string(),
            "orig.txt".to_string(),
        )
        .await
        .expect("add on a");
    vault_a.sync().await.expect("initial sync a");

    let mut vault_b = Vault::open(dir_b.path())
        .expect("open b")
        .join(&server.uri(), token(), &passphrase())
        .await
        .expect("join");
    vault_b.sync().await.expect("initial sync b");

    let doc_id: Uuid = original.id.parse().expect("uuid");

    // A edits locally but does not sync yet.
    vault_a
        .update_meta(doc_id, "Titolo di A".to_string(), vec![], String::new())
        .expect("update on a");

    // B edits the same document and syncs first, so the server now has a newer version than
    // what A's local `base_version` still reflects.
    vault_b
        .update_meta(doc_id, "Titolo di B".to_string(), vec![], String::new())
        .expect("update on b");
    vault_b.sync().await.expect("sync b pushes its edit");

    let report = vault_a.sync().await.expect("sync a hits the conflict");
    assert_eq!(report.conflicts, 1, "exactly one conflict copy");
    // The conflict copy is itself `dirty` the moment it's created during `pull()`, so the same
    // `sync()` call's `push()` half immediately uploads it too (a fresh doc id can't conflict).
    assert_eq!(
        report.pushed, 1,
        "the new conflict copy gets pushed in the same round"
    );

    let list = vault_a.list();
    assert_eq!(
        list.len(),
        2,
        "original (now B's title) + one conflict copy"
    );

    let server_side = list
        .iter()
        .find(|d| d.id == doc_id.to_string())
        .expect("original id still present");
    assert_eq!(server_side.title, "Titolo di B");
    assert!(!server_side.dirty);

    let copy = list
        .iter()
        .find(|d| d.id != doc_id.to_string())
        .expect("conflict copy present");
    assert!(copy.title.starts_with("Titolo di A"));
    assert!(copy.title.contains("copia in conflitto"));
    assert!(
        !copy.dirty,
        "conflict copy already pushed within the same sync() call"
    );

    // Strongest check: the conflict copy's blob itself round-trips byte-exact under its new
    // `doc_id` (exercises the AAD rebinding in `encrypt_new_document`, not just the title).
    let copy_id: Uuid = copy.id.parse().expect("uuid");
    let mut copy_content = Vec::new();
    vault_a
        .open(copy_id, &mut copy_content)
        .await
        .expect("open conflict copy blob");
    assert_eq!(
        copy_content, b"v1 content",
        "conflict copy blob content must decrypt byte-exact under the new doc_id"
    );

    // No data was lost: both versions are recoverable, on both the server (B's edit, id
    // unchanged) and locally (A's edit, as the new conflict-copy document, also now on the
    // server under its own new id).
    let st = state.lock().unwrap();
    assert_eq!(st.docs.len(), 2);
}

/// `412` on the first push attempt, success on retry (§5: "412 → go back to step 1").
#[tokio::test]
async fn conflict_412_then_retry_succeeds() {
    let (server, state) = fake_server().await;
    let dir = TempDir::new("412-retry");

    let mut vault = Vault::open(dir.path())
        .expect("open")
        .create(&server.uri(), token(), &passphrase())
        .await
        .expect("create");
    let summary = vault
        .add(
            Cursor::new(b"retry me".to_vec()),
            "Da riprovare".to_string(),
            vec![],
            String::new(),
            "text/plain".to_string(),
            "retry.txt".to_string(),
        )
        .await
        .expect("add");
    let doc_id: Uuid = summary.id.parse().expect("uuid");

    state.lock().unwrap().force_412.insert(doc_id, 1);

    let report = vault
        .sync()
        .await
        .expect("sync should recover from one 412");
    assert_eq!(report.pushed, 1);

    let list = vault.list();
    assert!(!list[0].dirty);
    assert_eq!(state.lock().unwrap().docs.len(), 1);
}

/// The same document keeps losing the optimistic-concurrency race for all 3 rounds →
/// `SyncError::Contention` (§5: "bounded: 3 rounds, then return `SyncError::Contention`").
#[tokio::test]
async fn contention_after_three_rounds_is_an_error() {
    let (server, state) = fake_server().await;
    let dir = TempDir::new("contention");

    let mut vault = Vault::open(dir.path())
        .expect("open")
        .create(&server.uri(), token(), &passphrase())
        .await
        .expect("create");
    let summary = vault
        .add(
            Cursor::new(b"never lands".to_vec()),
            "Mai sincronizzato".to_string(),
            vec![],
            String::new(),
            "text/plain".to_string(),
            "never.txt".to_string(),
        )
        .await
        .expect("add");
    let doc_id: Uuid = summary.id.parse().expect("uuid");

    // Always 412, no matter how many rounds sync() tries.
    state.lock().unwrap().force_412.insert(doc_id, u32::MAX);

    let result = vault.sync().await;
    assert!(matches!(result, Err(ClientError::Contention)));

    // The row is still dirty locally: nothing was lost.
    let list = vault.list();
    assert!(list[0].dirty);
}

/// A `server_seq` behind the local cursor is reported as a [`scrigno_client::SyncWarning`] and
/// does **not** fail the call (§5: "continue").
#[tokio::test]
async fn server_rollback_is_reported_as_a_warning() {
    let (server, state) = fake_server().await;
    let dir = TempDir::new("rollback");

    let mut vault = Vault::open(dir.path())
        .expect("open")
        .create(&server.uri(), token(), &passphrase())
        .await
        .expect("create");
    let summary = vault
        .add(
            Cursor::new(b"rollback content".to_vec()),
            "Documento".to_string(),
            vec![],
            String::new(),
            "text/plain".to_string(),
            "doc.txt".to_string(),
        )
        .await
        .expect("add");
    vault
        .sync()
        .await
        .expect("initial sync pushes the document");
    // The first `sync()`'s own pull ran *before* the push (§5 step 1 precedes step 2), so it
    // saw an empty change feed and left the local cursor at 0 even though the push that
    // followed just advanced the server to `server_seq = 1`. A second, ordinary sync (nothing
    // dirty left, so this is a clean pull of our own just-pushed record) catches the cursor up
    // to 1, so the rollback below is unambiguous.
    let after = vault
        .sync()
        .await
        .expect("second sync catches the cursor up");
    assert_eq!(after.pulled, 1);

    let doc_id: Uuid = summary.id.parse().expect("uuid");
    let real_record = {
        let st = state.lock().unwrap();
        st.docs.get(&doc_id).cloned().expect("pushed record")
    };

    // Simulate the server being restored from an earlier backup: the very next page replays the
    // same (still-valid, still-decryptable) record but with a `server_seq` behind our cursor.
    let mut rolled_back = real_record;
    rolled_back.server_seq = 0;
    state.lock().unwrap().force_next_changes = Some((vec![rolled_back], 0, false));

    let report = vault
        .sync()
        .await
        .expect("rollback is a warning, not an error");
    assert_eq!(report.warnings.len(), 1);
    match &report.warnings[0] {
        scrigno_client::SyncWarning::ServerRollback {
            doc_id: warned_id, ..
        } => assert_eq!(*warned_id, doc_id.to_string()),
    }
}

/// Resume after an interrupted blob upload: the first `sync()` call fails outright because the
/// blob upload never lands (simulating the process being killed mid-upload — the local `dirty`
/// row and its cached blob file are untouched); a second `sync()` call picks the same row back
/// up and converges.
#[tokio::test]
async fn resume_after_interrupted_upload() {
    let (server, state) = fake_server().await;
    let dir = TempDir::new("interrupted");

    let mut vault = Vault::open(dir.path())
        .expect("open")
        .create(&server.uri(), token(), &passphrase())
        .await
        .expect("create");
    let summary = vault
        .add(
            Cursor::new(vec![0xABu8; 4096]),
            "File grande".to_string(),
            vec![],
            String::new(),
            "application/octet-stream".to_string(),
            "big.bin".to_string(),
        )
        .await
        .expect("add");
    let _doc_id: Uuid = summary.id.parse().expect("uuid");

    // Fail every attempt within this crate's own internal retry budget for the blob PUT, so the
    // first `sync()` call gives up with a hard error rather than self-healing silently.
    state.lock().unwrap().force_blob_fail = 10;

    let first = vault.sync().await;
    assert!(first.is_err(), "first sync must fail: upload never lands");
    assert!(
        vault.list()[0].dirty,
        "row is still dirty after the failed attempt"
    );

    // "Kill and restart": allow the upload through now.
    state.lock().unwrap().force_blob_fail = 0;

    let second = vault.sync().await.expect("second sync converges");
    assert_eq!(second.pushed, 1);
    assert!(!vault.list()[0].dirty);
    assert_eq!(state.lock().unwrap().docs.len(), 1);
}

/// Regression test for the version-drift bug: calling `update_meta` **twice** on the same
/// document before ever running `sync()` used to permanently corrupt it. Root cause: each edit
/// bumped `row.version` by 1 and sealed `enc_meta`'s AAD at that bumped value, but the server
/// always assigns exactly `If-Match(base_version) + 1` on the next push — so after N local edits
/// the stored `enc_meta` was bound to a version number the row could never actually reach,
/// making it permanently undecryptable (surfacing as a `Crypto` error on every future
/// `unlock()`'s index rebuild). The fix reseals every local edit at `base_version + 1`, so
/// repeated edits before a sync simply keep re-targeting the one version the server will
/// actually assign, with the last edit winning.
///
/// This test failed on the pre-fix code (confirmed manually: `row.version += 1` in both
/// `update_meta`/`delete` reproduces exactly this) and passes after the fix.
#[tokio::test]
async fn update_meta_twice_before_sync_stays_decryptable() {
    let (server, _state) = fake_server().await;
    let dir = TempDir::new("double-edit");

    let mut vault = Vault::open(dir.path())
        .expect("open")
        .create(&server.uri(), token(), &passphrase())
        .await
        .expect("create");

    let summary = vault
        .add(
            Cursor::new(b"hello scrigno".to_vec()),
            "Titolo".to_string(),
            vec![],
            String::new(),
            "text/plain".to_string(),
            "hello.txt".to_string(),
        )
        .await
        .expect("add");
    let id = Uuid::parse_str(&summary.id).expect("parse id");

    // Two local edits, with **no sync in between** — exactly the sequence from the bug report
    // (`base_version` stays 0 the whole time; only a single subsequent `sync()` call pushes).
    vault
        .update_meta(id, "Modifica 1".to_string(), vec![], String::new())
        .expect("first update_meta");
    vault
        .update_meta(id, "Modifica 2".to_string(), vec![], String::new())
        .expect("second update_meta");

    vault.sync().await.expect("sync after both edits");

    // Simulate a fresh `unlock()` (e.g. the app restarting): reopen the local store from
    // scratch rather than reusing the in-memory `UnlockedVault`, so this genuinely exercises
    // `rebuild_index`'s decrypt-from-disk path, not just in-memory state.
    drop(vault);
    let reopened = Vault::open(dir.path())
        .expect("reopen")
        .unlock(&passphrase(), token(), None)
        .expect(
            "unlock must succeed: a single document must never be able to lock out the \
             whole vault",
        );

    assert!(
        reopened.unreadable_documents().is_empty(),
        "the document should decrypt cleanly after the fix, not be skipped as unreadable: {:?}",
        reopened.unreadable_documents()
    );
    let list = reopened.list();
    assert_eq!(list.len(), 1, "the document must still be listed");
    assert_eq!(
        list[0].title, "Modifica 2",
        "the second (last) local edit before sync should win"
    );
}

/// `rebuild_index` hardening: a document whose stored `enc_meta` fails to decrypt (corrupted on
/// disk, tampered, or — pre-fix — a casualty of the version-drift bug above) must be skipped,
/// not allowed to abort `unlock()` for the whole vault. A healthy sibling document must still
/// unlock and list normally, and the skipped document's id must be reported via
/// `UnlockedVault::unreadable_documents()` rather than silently vanishing.
#[tokio::test]
async fn unlock_skips_one_corrupted_document_but_still_succeeds() {
    let (server, _state) = fake_server().await;
    let dir = TempDir::new("corrupt-doc");

    let mut vault = Vault::open(dir.path())
        .expect("open")
        .create(&server.uri(), token(), &passphrase())
        .await
        .expect("create");

    let healthy = vault
        .add(
            Cursor::new(b"healthy content".to_vec()),
            "Documento sano".to_string(),
            vec![],
            String::new(),
            "text/plain".to_string(),
            "healthy.txt".to_string(),
        )
        .await
        .expect("add healthy");

    let corrupted = vault
        .add(
            Cursor::new(b"soon to be corrupted".to_vec()),
            "Documento corrotto".to_string(),
            vec![],
            String::new(),
            "text/plain".to_string(),
            "corrupt.txt".to_string(),
        )
        .await
        .expect("add corrupted");

    vault.sync().await.expect("sync");
    drop(vault);

    // Flip the last byte of the corrupted document's stored `enc_meta` directly in the local
    // SQLite store — simulating on-disk corruption/tampering (or leftover damage from the
    // version-drift bug fixed above) without needing to reproduce that bug end-to-end.
    {
        let conn = rusqlite::Connection::open(dir.path().join("vault.sqlite3"))
            .expect("open sqlite directly");
        let mut enc_meta: Vec<u8> = conn
            .query_row(
                "SELECT enc_meta FROM document WHERE id = ?1",
                rusqlite::params![corrupted.id],
                |r| r.get(0),
            )
            .expect("read enc_meta");
        let last = enc_meta.len() - 1;
        enc_meta[last] ^= 0xFF;
        conn.execute(
            "UPDATE document SET enc_meta = ?1 WHERE id = ?2",
            rusqlite::params![enc_meta, corrupted.id],
        )
        .expect("corrupt enc_meta");
    }

    let reopened = Vault::open(dir.path())
        .expect("reopen")
        .unlock(&passphrase(), token(), None)
        .expect("unlock must succeed even with one corrupted document");

    assert_eq!(
        reopened.unreadable_documents(),
        std::slice::from_ref(&corrupted.id),
        "the corrupted document should be reported as skipped"
    );
    let list = reopened.list();
    assert_eq!(list.len(), 1, "only the healthy document should be listed");
    assert_eq!(list[0].id, healthy.id);
    assert_eq!(list[0].title, "Documento sano");
}

/// Regression test for the "own prior state" silent-revert bug: `pull()`'s conflict check used
/// to have only two cases (`dirty && version > base_version` → conflict, everything else →
/// unconditional overwrite), missing the third case where a dirty local row's edit is *not* a
/// conflict (`item.version <= base_version`) but must still be left alone rather than overwritten.
///
/// This happens in completely ordinary use, without a second device: `sync()` pulls before it
/// pushes (`docs/ARCHITECTURE.md §5`), so a brand-new document's first `sync()` pushes it (its
/// own pull phase ran too early to see it) and only advances the pull cursor *past* it on some
/// later pull. Concretely: add a doc → `sync()` (push lands it at `version = 1`, `dirty = false`,
/// but the cursor doesn't yet cover its `server_seq` since the pull phase ran first) → edit the
/// title (`dirty = true`, `base_version` still 1) → `sync()` again: this call's pull phase now
/// sees the doc's own record from the first push, at `item.version == 1 == base_version`. That's
/// not `>`, so pre-fix this fell into the `else` branch and `apply_pulled_record` overwrote the
/// dirty row with the stale server copy, silently discarding the pending title edit with no
/// conflict copy and no error.
///
/// Confirmed to fail on the pre-fix two-case `is_conflict` branch (reverting the fix to the
/// binary check reproduces exactly this) and pass after adding the missing third case.
#[tokio::test]
async fn own_record_pulled_back_does_not_revert_pending_edit() {
    let (server, _state) = fake_server().await;
    let dir = TempDir::new("own-record-revert");

    let mut vault = Vault::open(dir.path())
        .expect("open")
        .create(&server.uri(), token(), &passphrase())
        .await
        .expect("create");

    let summary = vault
        .add(
            Cursor::new(b"hello scrigno".to_vec()),
            "Titolo originale".to_string(),
            vec![],
            String::new(),
            "text/plain".to_string(),
            "hello.txt".to_string(),
        )
        .await
        .expect("add");
    let id = Uuid::parse_str(&summary.id).expect("parse id");

    // First sync: pushes the new document (pull phase ran too early to see it).
    let first = vault.sync().await.expect("first sync pushes the doc");
    assert_eq!(first.pushed, 1);
    assert!(!vault.list()[0].dirty);

    // Edit the title, but don't sync yet: dirty again, base_version still 1.
    vault
        .update_meta(id, "Titolo modificato".to_string(), vec![], String::new())
        .expect("update_meta");
    assert!(vault.list()[0].dirty);

    // Second sync: its pull phase now catches up to the doc's own record from the first push
    // (item.version == 1 == base_version — not a conflict, but also not safe to overwrite).
    let second = vault.sync().await.expect("second sync");
    assert_eq!(
        second.conflicts, 0,
        "this is not a real conflict: the server never moved past our edit's base"
    );

    // Reopen from scratch (fresh `unlock()`) so this genuinely re-decrypts `enc_meta` from disk
    // rather than trusting any in-memory state that might have survived unrelated to the bug.
    drop(vault);
    let reopened = Vault::open(dir.path())
        .expect("reopen")
        .unlock(&passphrase(), token(), None)
        .expect("unlock");

    let list = reopened.list();
    assert_eq!(list.len(), 1);
    assert_eq!(
        list[0].title, "Titolo modificato",
        "the pending edit must survive a second sync(), not be silently reverted to the \
         pre-edit title pulled back from the server"
    );
}
