# Scrigno — roadmap

Work proceeds milestone by milestone. A milestone is done when every acceptance criterion holds
and `just check` is green.

**Status:** M0–M4 are done (desktop app works end to end). Order from here is deliberate:
Android first (the whole point is the APK), then deploy (so the app gets used daily and real
bugs surface early), then the two features that differentiate Scrigno — the fascicolo (small,
high value) and on-device OCR + search (bigger, riskier, last). See `CLAUDE.md` → Positioning.

## M0 — Scaffold (no features) ✅ done

Tasks
- Cargo workspace with `crates/scrigno-core`, `scrigno-client`, `scrigno-server`, `scrigno-cli`
  (empty `lib.rs`/`main.rs`, shared `[workspace.dependencies]`, `[workspace.lints]` with clippy
  pedantic subset).
- `apps/mobile`: `pnpm create tauri-app` (React + TypeScript), Tailwind v4, TanStack Query,
  Vitest, ESLint + Prettier; `src-tauri` as a **separate** Cargo project depending on
  `../../../crates/scrigno-client` by path. Identifier `xyz.stefanoleto.scrigno`.
- Server binary starts, connects to Postgres, runs migrations (empty migration allowed), serves
  `/healthz`. Dockerfile builds. `compose --profile full up` gives a healthy `/healthz`.
- `justfile` recipes all run (even if trivially).
- `.gitignore`, `.env.example`, `README.md` (two paragraphs + pointer to `just`).

Acceptance
- `just check` green on a clean clone with `.env` present.
- `curl localhost:8787/healthz` → `{"status":"ok","db":"ok"}` both via `just server` and `just up`.
- `just app` opens a window showing "Scrigno" and the vault status `uninitialised` (hard-coded is fine).

## M1 — Core crypto ✅ done

Tasks (`core-crypto`, then `crypto-reviewer`)
- Types: `VaultId`, `DocId`, `KeyslotId` (newtypes over `Uuid`), `MasterKey`, `Dek`, `Kek`
  (zeroizing, no Debug/Clone), `DocMeta`, `Keyslot`, `KdfParams`.
- `kdf::derive_kek(passphrase, params) -> Kek`; floor check on create.
- `wrap::wrap_key / unwrap_key` producing/consuming the 73-byte `WrappedKey`.
- `meta::seal / open` for `EncMeta` with AAD `(doc_id, doc_version)`.
- `blob::Encryptor` (streaming writer: `Write` adapter) and `blob::Decryptor` (streaming reader:
  `Read` adapter) implementing the `SCRG` format with 1 MiB segments.
- `recovery::generate_code / parse_code` (Crockford Base32).
- Test vectors under `tests/vectors/`, proptests, tamper tests.

Acceptance
- 100 % of public API documented; `cargo doc -p scrigno-core --no-deps` has no warnings.
- Encrypting and decrypting a 50 MiB file streams with < 8 MiB peak RSS in a test.
- `crypto-reviewer` reports no Critical findings.

## M2 — Server ✅ done

Tasks (`backend-server`)
- Migrations for the schema in `ARCHITECTURE.md §2`.
- Auth middleware (constant-time), request-id + tracing middleware, body limits.
- All endpoints of `§3`; streaming blob upload with sha256 computed on the fly; `Range` support.
- GC task.
- `#[sqlx::test]` per behaviour listed in `CLAUDE.md` testing policy.

Acceptance
- Integration tests green against compose Postgres.
- Uploading a 150 MiB blob keeps server RSS under 100 MiB (streamed).
- `docker compose --profile full up --build` works from a clean checkout with `SQLX_OFFLINE`.

## M3 — Client + CLI + e2e ✅ done

Tasks (`sync-client`)
- `scrigno-client::Vault`: `create`, `join`, `unlock`, `lock`, `add`, `list`, `open` (streaming to
  a `Write`), `update_meta`, `delete`, `sync`, `set_keep_offline`. Local store per `§4`, sync per
  `§5`. `wiremock` tests for the sync engine.
- `scrigno-cli` with subcommands mirroring the above plus `status` and `changes --raw` (debug).
  Passphrase via `--passphrase-file` or interactive prompt (never as an argument in `ps`).
- `scripts/e2e.sh`: builds CLI, starts compose (`just db` + `just server` in background or the
  `full` profile), runs the two-device scenario from `CLAUDE.md`, exits non-zero on any mismatch.
- `ts-rs` export of shared types into `apps/mobile/src/bindings/` (feature `ts-export`).

Acceptance
- `just e2e` passes twice in a row (idempotence) and after `just reset-db` + re-run.
- Killing the CLI mid-upload (`timeout 1 scrigno add big.pdf`) then re-running `sync` converges.

## M4 — Desktop app (Tauri + React) ✅ done

Tasks (`tauri-mobile` for `src-tauri`, `frontend-ui` for `src`)
- Commands from `§6`, `AppState` with auto-lock, events.
- Screens: **Setup** (create / join, server URL, token, passphrase + confirm, recovery code shown
  once), **Unlock**, **Vault** (grid of thumbnails, search over decrypted titles/tags in memory,
  filter by tag), **Document** (viewer for PDF and images, meta edit, share, delete,
  keep-offline toggle), **Settings** (auto-lock, cache size, add recovery code, change passphrase,
  lock completely, about), **Sync banner** (last sync, conflicts, rollback warning).
- Viewer: images via object URL from binary IPC; PDF via `pdf.js` bundled locally (no CDN).
- Thumbnails generated on device (Rust side with `image` for images; first page render for PDF
  can wait for M5 — placeholder icon is acceptable).

Acceptance
- Full manual flow on desktop against `just up`: setup → add 3 files (PDF, JPG, PNG) → lock →
  unlock → open each → edit title → delete one → second data dir joins and sees the same state.
- Vitest covers unlock flow and list rendering.

## M5 — Android

Tasks (`tauri-mobile`, `frontend-ui`)
- `pnpm tauri android init`; commit `gen/android`; `usesCleartextTraffic` in the **debug**
  manifest only; release signing via `keystore.properties` (gitignored), `keytool` command in
  the README.
- Camera capture through `<input type="file" accept="image/*" capture="environment">`; verify
  Tauri's file chooser works on Android, else fall back to the dialog plugin. Downscale photos on
  device to ≤ 3000 px on the long side before encryption (a 12 MP scan of a card is waste).
- Quick unlock: `CRYPTO.md §5.2` option 1 if the current `tauri-plugin-biometric` supports
  keystore-bound crypto, otherwise option 2 with the UX disclaimer and a `TODO(m5)` for a Kotlin
  plugin.
- Share sheet via the opener/share plugin; plaintext temp file deleted afterwards.
- Lifecycle: lock on background > 30 s, sync on foreground, handle process death while a large
  upload is in flight (resume via sync, never lose the dirty row).
- Server URL screen shows `http://10.0.2.2:8787` as emulator hint; LAN IP for a real phone.

Acceptance
- `just apk` produces a signed APK that installs on the owner's phone and passes the M4 manual
  flow over Wi-Fi against the dev machine (`SCRIGNO_PUBLISH_HOST=0.0.0.0`).
- Camera → encrypted → synced → visible on desktop in < 5 s for a 12 MP photo.
- APK size reported in the README (target: < 15 MB before OCR models).

## M6 — Deploy on the homeserver

Tasks (`infra-deploy`; the owner runs the commands on the VM)
- `deploy/README.md`: `/opt/scrigno` on `debian-docker`, `docker compose --profile full up -d`,
  nginx vhost from `deploy/nginx-scrigno.conf.example`, certbot, AdGuard DNS rewrite for the
  subdomain, optional WireGuard-only `allow` block.
- Backups: `deploy/backup.sh` (nightly `pg_dump -Fc` + rsync of the blobs volume to
  `/mnt/ironwolf/backups/scrigno/<date>/`, 30-day retention), `deploy/restore.sh`, cron line.
- App: release build points at `https://scrigno.stefanoleto.xyz`; no cleartext in release.
- Server: add a `--healthcheck` flag or keep curl in the image (infra decides, backend implements).

Acceptance
- Phone on mobile data (no VPN) syncs with the homeserver over HTTPS.
- Restore drill: wipe compose volumes, restore from backup, the app opens every document.
- One week of daily use by the owner without a data-loss bug; anything found becomes an issue
  fixed before M7.

## M7 — Fascicolo: document kinds, expiry, reminders

Tasks (`ocr-search` for `scrigno-index`, `sync-client` for `Vault` API, `tauri-mobile`,
`frontend-ui`; `crypto-reviewer` at the end because `DocMeta` changes)
- `crates/scrigno-index`: `kinds` module implementing `docs/FASCICOLO.md` — `KindInfo` list,
  `compute_expiry(kind, issued_at, holder_age?) -> Option<Date>`, reminder policy. Pure, unit
  tested against the table in the doc.
- `DocMeta` gains `kind`, `issued_at`, `expires_at`, `remind_days` (`CRYPTO.md §4.3`,
  compatibility rule respected; old vaults must open unchanged — add a test that opens an M4
  fixture).
- `Vault::set_kind`, commands `doc_set_kind`, `docs_expiring`, `kinds_list`; CLI `kind` and
  `expiring` subcommands; e2e extended with one expiring document.
- Reminders via `tauri-plugin-notification` scheduled on Android, check-on-start on desktop.
  Generic text, no title before unlock.
- UI: kind picker in the add/edit screen (proposes expiry date, editable), "In scadenza"
  section at the top of the vault, badge on expiring cards, Settings → reminder defaults.

Acceptance
- Tagging a photo as *patente* with `issued_at` proposes `expires_at` = +10 years (or the
  age-dependent value) and a reminder fires on the phone at the configured day (test with a
  1-minute override in debug builds).
- All documents from M4/M6 still open; `docs_list` unchanged for documents without a kind.

## M8 — On-device OCR and full-text search

Tasks (`ocr-search` first, then `sync-client`, `tauri-mobile`, `frontend-ui`, `crypto-reviewer`)
- **Accuracy gate before anything else:** `ocr-search` builds a bench in `scrigno-index` with
  10 real-world-like fixtures (photos of cards/letters, one scanned PDF, one text PDF — synthetic
  or owner-provided, never committed if real) and measures `ocrs` word accuracy on Italian text.
  Gate: ≥ 85 % on clean captures. Fail → stop and report; the fallback is ML Kit through a Kotlin
  plugin (Android only, desktop keeps `ocrs`), decided by the owner.
- `scrigno-index::ocr`: `ocr_image(bytes) -> OcrResult` with `ocrs`; `ocr_pdf_text(bytes)` with
  `pdf-extract`; deskew/contrast pre-processing with `image`/`imageproc` if it moves the gate.
  Models downloaded once into `app_data_dir/models` (with checksums), not bundled in the APK.
- `scrigno-index::search`: tokeniser (lowercase, NFKD, strip diacritics, split on non-alnum,
  keep numbers intact for codici fiscali/targhe/IBAN), inverted index with prefix matching and
  phrase search, highlight ranges. Benchmark: 1 000 docs × 4 KiB OCR text indexed < 300 ms.
- `Vault::run_ocr`, `Vault::search`, `Vault::reindex`; commands `doc_run_ocr`, `docs_search`,
  `docs_reindex`; event `ocr-progress`; CLI `ocr`, `search`, `reindex`.
- PDF pages without a text layer: the UI renders pages with pdf.js to PNG and posts them to
  `doc_run_ocr` (raw body); cap at 20 pages per document.
- `EncMeta` padding to 4 KiB multiples (`CRYPTO.md §7`), `ocr_text` cap 64 KiB, zeroize the
  plaintext buffers handed to OCR.
- UI: search bar over the vault with highlights, "Testo riconosciuto" panel in the document
  view (editable, so bad OCR can be fixed by hand), Settings → "Riconosci testo automaticamente
  quando aggiungo un documento" (default on), "Riconosci tutto ora" with progress.

Acceptance
- On the owner's phone, adding a photo of a document runs OCR in the background and the
  document is findable by a word from its body within 10 s, with the app still responsive.
- Searching "codice fiscale" over a 200-document vault returns in < 50 ms after unlock.
- `crypto-reviewer` confirms: OCR text never touches disk in plaintext, index dropped on lock,
  no OCR-related logging of content.

## Later / ideas (not scheduled)

Blob size padding, per-device tokens with revocation, document versions history, Android
share-target ("Invia a Scrigno"), home-screen widget for expiring documents, import from
Paperless-ngx export (decrypt-free: it is plaintext on their side), iOS.
