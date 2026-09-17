# Scrigno — architecture

Companion to `CRYPTO.md` (which wins on any crypto question). This file is the contract between
the crates; change it in the same commit as the code that changes the behaviour.

## 1. Components

```
┌─────────────────────────── device ───────────────────────────┐        ┌────── homeserver / dev machine ──────┐
│ React UI ──IPC──▶ Tauri commands ──▶ scrigno-client ──HTTPS──▶│        │ nginx (prod only) ─▶ scrigno-server  │
│  (no keys)        (src-tauri)         │      │                │        │                        │       │      │
│                                       │      └─ scrigno-core  │        │                   Postgres   blobs   │
│                                 SQLite index + ciphertext cache│        │                              (FS/S3) │
└───────────────────────────────────────────────────────────────┘        └──────────────────────────────────────┘
                 scrigno-cli = same client + core, driven from a terminal (tests, e2e, scripting)
```

- `scrigno-core`: pure functions and types. Input bytes → output bytes. Fully testable without a
  server or a device.
- `scrigno-client`: owns the **local store** and the **sync engine**; exposes an async `Vault`
  API used identically by the Tauri commands and by the CLI.
- `scrigno-server`: dumb, honest storage with optimistic concurrency and a change feed.
- `scrigno-cli`: `scrigno --data-dir <dir> <command>`; one data dir = one "device".

## 2. Server data model (Postgres)

Single vault per deployment for now (a `vault` table with at most one row keeps the door open).

```sql
CREATE TABLE vault (
  id          uuid PRIMARY KEY,
  singleton   boolean NOT NULL DEFAULT true UNIQUE CHECK (singleton),
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE keyslot (
  id          uuid PRIMARY KEY,
  vault_id    uuid NOT NULL REFERENCES vault(id) ON DELETE CASCADE,
  kind        text NOT NULL CHECK (kind IN ('passphrase','recovery')),
  kdf         jsonb NOT NULL,          -- {alg, m_kib, t, p, salt}
  wrapped_mk  bytea NOT NULL,          -- 73 bytes, opaque
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE SEQUENCE document_change_seq;

CREATE TABLE document (
  id          uuid PRIMARY KEY,                       -- client-generated UUIDv7
  vault_id    uuid NOT NULL REFERENCES vault(id) ON DELETE CASCADE,
  version     integer NOT NULL CHECK (version >= 1),
  blob_id     uuid REFERENCES blob(id),               -- NULL only for tombstones
  blob_size   bigint NOT NULL DEFAULT 0,
  enc_meta    bytea NOT NULL,                         -- opaque, see CRYPTO.md 4.3
  deleted     boolean NOT NULL DEFAULT false,
  server_seq  bigint NOT NULL UNIQUE,                 -- nextval on every write
  updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE blob (
  id          uuid PRIMARY KEY,                       -- client-generated
  vault_id    uuid NOT NULL REFERENCES vault(id) ON DELETE CASCADE,
  size        bigint NOT NULL,
  sha256      bytea NOT NULL,                         -- of the ciphertext
  created_at  timestamptz NOT NULL DEFAULT now()
);
```

Blob GC: a background task (every hour) deletes `blob` rows (and objects) not referenced by any
non-deleted `document` and older than 24 h. Tombstones are kept forever (they are tiny).

Blob storage: `object_store::local::LocalFileSystem` rooted at `SCRIGNO_BLOB_DIR`, key
`<vault_id>/<blob_id>`. Swapping to S3/MinIO = one config change, no code change.

## 3. HTTP API (v1)

- Auth: `Authorization: Bearer <SCRIGNO_API_TOKEN>` on every route except `/healthz`. Missing or
  wrong → `401` with empty body. Constant-time compare.
- JSON bodies `application/json`; blobs `application/octet-stream`.
- Errors: `{ "error": { "code": "…", "message": "…" } }`; `code` is stable and machine-readable,
  with one documented exception: `412 version_mismatch` returns the current `DocumentRecord`
  itself as the body (not wrapped in the error envelope), so a conflicting client can act on it
  without a second round trip. Codes used: the per-endpoint ones in the table below, plus these
  generic ones any route can return: `unauthorized` (401), `not_found` (404, e.g. `GET`/`DELETE`
  on an id that has never existed), `bad_request` (400, malformed header/body/query),
  `range_not_satisfiable` (416, `GET /v1/blobs/{id}` with an out-of-bounds `Range`),
  `payload_too_large` (413), `internal_error` (500, never includes SQL/paths/internal detail).
- Limits: JSON bodies 1 MiB; blob upload `SCRIGNO_MAX_BLOB_BYTES` (default 200 MiB) → `413`.
- Base64 in JSON is standard alphabet with padding.

| Method & path | Request | Response | Notes |
|---|---|---|---|
| `GET /healthz` | — | `200 {"status":"ok","db":"ok"}` | no auth; used by compose healthcheck and nginx |
| `GET /v1/vault` | — | `200 Vault` / `404 vault_not_initialised` | |
| `POST /v1/vault` | `{ "id": uuid, "keyslot": Keyslot }` | `201 Vault` / `409 vault_exists` | first device |
| `POST /v1/vault/keyslots` | `Keyslot` | `201 Keyslot` | add passphrase/recovery slot |
| `DELETE /v1/vault/keyslots/{id}` | — | `204` / `409 last_keyslot` | never delete the last slot |
| `GET /v1/changes?since=<seq>&limit=<n≤500>` | — | `200 { "items": [DocumentRecord], "next_since": seq, "has_more": bool }` | ordered by `server_seq`; includes tombstones |
| `GET /v1/docs/{id}` | — | `200 DocumentRecord` / `404` | |
| `PUT /v1/docs/{id}` | header `If-Match: <version>` (0 = create); body `{ "blob_id", "blob_size", "enc_meta" }` | `201`/`200 DocumentRecord`; `412 version_mismatch` with current record in body; `404 blob_not_found` | server sets `version = If-Match + 1`, new `server_seq` |
| `DELETE /v1/docs/{id}` | header `If-Match` | `200 DocumentRecord` (tombstone) / `412` | tombstone keeps last `enc_meta` so other devices can show what was deleted |
| `PUT /v1/blobs/{id}` | raw body, `Content-Length` required | `201 { "id", "size", "sha256" }`; `200` if identical blob exists; `409 blob_mismatch` if exists with different sha | streamed to store; never buffered whole in memory |
| `GET /v1/blobs/{id}` | optional `Range` | `200`/`206` stream, `ETag: "<sha256 hex>"` | |

```ts
type Vault = { id: string; created_at: string; keyslots: Keyslot[] };
type Keyslot = {
  id: string; kind: "passphrase" | "recovery"; kdf: KdfParams;
  wrapped_mk: string /* base64 */; created_at: string;
};
type DocumentRecord = {
  id: string; version: number; blob_id: string | null; blob_size: number;
  enc_meta: string /* base64 */; deleted: boolean; server_seq: number; updated_at: string;
};
```

`POST /v1/vault` and `POST /v1/vault/keyslots` accept a `Keyslot`-shaped body (`created_at` is
ignored if present -- the server always sets it). `id` is client-generated like every other id.
The server validates `Keyslot`/`DocumentRecord` fields only for shape (valid uuid/base64/non-empty,
`kind` one of the two allowed values, `kdf` is a JSON object) and never interprets `kdf`,
`wrapped_mk` or `enc_meta` beyond that -- they are opaque to it by design.

Write order on the client is always **blob first, then document**, so a document never points at
a missing blob. Interrupted uploads leave an orphan blob that GC collects.

## 4. Client local store (SQLite, one file per data dir)

```sql
CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
  -- server_url, vault_id, cursor (last server_seq applied), keyslot_id_in_use, device_id

CREATE TABLE document (
  id            TEXT PRIMARY KEY,
  version       INTEGER NOT NULL,          -- version this row represents
  base_version  INTEGER NOT NULL,          -- last version confirmed by the server (If-Match value)
  blob_id       TEXT,
  blob_size     INTEGER NOT NULL DEFAULT 0,
  enc_meta      BLOB NOT NULL,
  deleted       INTEGER NOT NULL DEFAULT 0,
  dirty         INTEGER NOT NULL DEFAULT 0, -- local change not yet pushed
  keep_offline  INTEGER NOT NULL DEFAULT 0,
  updated_at    TEXT NOT NULL
);

CREATE TABLE blob_cache (
  blob_id      TEXT PRIMARY KEY,
  path         TEXT NOT NULL,               -- <data_dir>/blobs/<blob_id>
  size         INTEGER NOT NULL,
  last_access  TEXT NOT NULL
);
```

Decrypted metadata is **not** stored; the in-memory index (`Vec<DocSummary>`) is rebuilt from
`enc_meta` on unlock (fast: one AEAD open per document). Cache eviction: LRU when the cache
exceeds `cache_limit_mb` (default 512), never evicting `keep_offline` blobs or dirty documents.

## 5. Sync algorithm

`sync()` is idempotent and safe to call at any time (app foreground, pull-to-refresh, after a
local change, CLI). Steps:

1. **Pull** — `GET /v1/changes?since=cursor` until `has_more == false`. For each record:
   - local row missing or `dirty == 0` → overwrite row (`base_version = version`), drop cached
     blob if `blob_id` changed;
   - local row `dirty == 1` and `record.version > base_version` → **conflict**: keep the server
     record as-is for this id, re-create the local change as a *new* document (new UUIDv7, meta
     title suffixed with ` (copia in conflitto <date>)`), dirty. No data is ever lost silently.
   - local row `dirty == 1` and `record.version <= base_version` → **not** a conflict: the server
     hasn't moved past what the pending edit was based on. This is normal — pull runs before push
     (step 1 before step 2), so a document's own just-pushed record can be seen again by a later
     pull once the cursor catches up to it, or the server may genuinely have rolled back (see
     below). Either way, leave the local row untouched (`dirty`, `enc_meta`, `version` unchanged)
     so step 2 pushes the pending edit normally; do **not** overwrite it with the server record.
   - advance `cursor` after each page. If a record has `server_seq < cursor` the server was
     rolled back → surface `SyncWarning::ServerRollback`, continue.
2. **Push** — for each `dirty` row in `updated_at` order:
   - if the blob is new (not yet on the server) → `PUT /v1/blobs/{blob_id}`, verify returned sha;
   - `PUT /v1/docs/{id}` (or `DELETE`) with `If-Match: base_version`;
   - `200/201` → `dirty = 0`, `base_version = version = response.version`;
   - `412` → go back to step 1 (bounded: 3 rounds, then return `SyncError::Contention`).
3. **Prefetch** — download blobs for `keep_offline` rows missing from the cache.

Everything in one `Vault::sync()` call returning a `SyncReport { pulled, pushed, conflicts,
warnings }` that the UI shows verbatim in Italian.

## 6. Tauri command surface (`apps/mobile/src-tauri`)

All commands are thin: parse args → call `scrigno-client` → map errors to `AppError`. State:
`tauri::State<AppState>` holding `Mutex<Option<UnlockedVault>>` plus the auto-lock timer.

| Command | Args | Returns | Notes |
|---|---|---|---|
| `vault_status` | — | `"uninitialised" \| "locked" \| "unlocked"` | |
| `vault_create` | `server_url, token, passphrase` | `()` | first device |
| `vault_join` | `server_url, token, passphrase` | `()` | second device |
| `vault_unlock` | `passphrase` | `()` | |
| `vault_unlock_quick` | — | `()` | biometric / device store; `Err(code="quick_unlock_unavailable")` on desktop |
| `vault_lock` | — | `()` | zeroizes MK |
| `vault_add_recovery_code` | — | `String` | new recovery keyslot; return value is the plaintext code, **shown once**, never cached/re-fetchable/logged |
| `docs_list` | — | `DocSummary[]` | decrypted meta minus `thumb` |
| `doc_thumb` | `id` | binary | JPEG bytes from meta, or empty |
| `doc_get_meta` | `id` | `DocMeta` | |
| `doc_add_from_path` | `path, title, tags, note` | `DocSummary` | path from dialog plugin; Android `content://` handled by fs plugin |
| `doc_add_bytes` | raw body + header `x-scrigno-meta` (JSON `{title,tags,note,mime,original_name}`) | `DocSummary` | for `<input type=file capture>`; `tauri::ipc::Request` |
| `doc_open` | `id` | binary (`tauri::ipc::Response`) | decrypts to memory; caller revokes object URL on close |
| `doc_share` | `id` | `()` | writes plaintext to cache dir, opens share sheet, deletes after |
| `doc_update_meta` | `id, title, tags, note` | `DocSummary` | bumps version, dirty |
| `doc_set_keep_offline` | `id, bool` | `()` | |
| `doc_delete` | `id` | `()` | tombstone, dirty |
| `sync_now` | — | `SyncReport` | |
| `settings_get` / `settings_set` | `Settings` | | auto-lock minutes, cache limit, server url (read-only after init) |

Events emitted to the frontend: `vault-locked` (auto-lock fired), `sync-progress { phase, done, total }`.

Types shared with TS (`ts-rs`): `DocSummary`, `DocMeta`, `SyncReport`, `Settings`, `AppError`,
`VaultStatus`.

## 7. Configuration

Server (env, all prefixed `SCRIGNO_`): `DATABASE_URL`, `API_TOKEN` (required, rejected at startup
if shorter than 32 characters), `BLOB_DIR`, `BIND` (default `0.0.0.0:8787`), `MAX_BLOB_BYTES`
(default 200 MiB), `GC_INTERVAL_SECS` (default 3600). Plus `RUST_LOG`.

Client/app: `server_url` and `token` entered once in the setup screen. As of M4, `scrigno-client`'s
own SQLite `kv` store deliberately never persists the token (each caller re-supplies it — a
decision made for `scrigno-cli`'s stateless-invocation model in M3 and kept for the desktop app
rather than reopened mid-milestone); the Tauri app instead persists `{server_url, token,
auto_lock_minutes}` in its own plaintext `<app_data_dir>/config.json` (`apps/mobile/src-tauri/src/
config.rs`), written with `0600` permissions on Unix. This is the same sensitivity class
`docs/CRYPTO.md` §6 already assigns the token ("if it leaks, an attacker can delete or add
ciphertext but cannot read anything"). MK persistence via Stronghold is M5 (quick unlock); M4 has
no quick unlock, so MK is never written to disk at all — re-derived from the passphrase on every
`vault_unlock`. Dev defaults suggested by the UI: `http://127.0.0.1:8787` on desktop,
`http://10.0.2.2:8787` on the Android emulator.
