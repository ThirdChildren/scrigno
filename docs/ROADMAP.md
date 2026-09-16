# Scrigno — roadmap

Work proceeds milestone by milestone. A milestone is done when every acceptance criterion holds
and `just check` is green. Do not start UI work (M4) before the CLI e2e (M3) passes: the UI is a
skin over a system that must already work.

## M0 — Scaffold (no features)

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

## M1 — Core crypto

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

## M2 — Server

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

## M3 — Client + CLI + e2e

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

## M4 — Desktop app (Tauri + React)

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
- `pnpm tauri android init`; commit `gen/android`; debug manifest with `usesCleartextTraffic`
  (debug only); release signing via `keystore.properties` (gitignored) documented in README.
- Camera capture through `<input type="file" accept="image/*" capture="environment">`; verify
  Tauri's file chooser works, else fall back to the dialog plugin.
- Quick unlock: implement `CRYPTO.md §5.2` option 1 if the current `tauri-plugin-biometric`
  supports keystore-bound crypto; otherwise option 2 with the UX disclaimer, and open a
  `TODO(m5)` for a Kotlin plugin.
- Share sheet via opener/share plugin; plaintext temp file deleted afterwards.
- Background/foreground handling: lock on background > 30 s, sync on foreground.

Acceptance
- `just apk` produces a signed APK that installs on the owner's phone and passes the M4 manual
  flow against the dev machine over Wi-Fi (`SCRIGNO_PUBLISH_HOST=0.0.0.0`).
- Adding a photo from the camera of a 12 MP image takes < 5 s end-to-end on the phone.

## M6 — Deploy on the homeserver

Tasks (`infra-deploy`)
- `deploy/README.md`: copy `compose.yaml` + `.env` to `/opt/scrigno` on the `debian-docker` VM,
  `docker compose --profile full up -d`, nginx vhost `scrigno.stefanoleto.xyz` from
  `deploy/nginx-scrigno.conf.example` (`client_max_body_size 210m`, `proxy_request_buffering
  off`), certbot, AdGuard DNS rewrite for the subdomain, WireGuard-only access as an option
  (nginx `allow` rules).
- Backups: nightly `pg_dump` + rsync of the blob volume to the IronWolf, retention 30 days;
  restore procedure tested once.
- App: point a fresh install at the public URL (HTTPS), remove cleartext from release.

Acceptance
- Phone on mobile data (no VPN) syncs with the homeserver over HTTPS.
- Restore drill: wipe compose volumes, restore from backup, app still opens every document.

## Later / ideas (not scheduled)

Blob size padding, per-device tokens with revocation, document versions history, OCR on device,
Android share-target ("Invia a Scrigno"), widgets, iOS.
