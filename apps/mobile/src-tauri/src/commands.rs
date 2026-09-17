//! Tauri command surface (`docs/ARCHITECTURE.md §6`). Every command is thin: deserialize → call
//! `scrigno_client::Vault`/`UnlockedVault` → map `ClientError` to [`AppError`]. No business
//! logic, no crypto, no SQL lives here.

use std::io::Cursor;
use std::str::FromStr as _;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tauri::ipc::{InvokeBody, Request, Response};
use tauri::{AppHandle, Emitter, State};
use uuid::Uuid;

use scrigno_client::{ClientError, DocSummary, SyncReport};
use scrigno_core::meta::DocMeta;

use crate::config::{self, AppConfig, MAX_AUTO_LOCK_MINUTES, MIN_AUTO_LOCK_MINUTES};
use crate::state::{AppState, VaultSlot};
use crate::types::{AppError, Settings, VaultStatus};

/// Matches `scrigno-client`'s own `DEFAULT_CACHE_LIMIT_MB` (`crates/scrigno-client/src/vault.rs`,
/// private to that crate) — used here only as a display fallback while the vault is locked (the
/// real value, `UnlockedVault::cache_limit_mb`, is only readable once unlocked).
const DEFAULT_CACHE_LIMIT_MB: i64 = 512;

/// Dev default suggested by the setup UI (`docs/ARCHITECTURE.md §7`), used only as a
/// `settings_get` display fallback before any vault has ever been created/joined on this device.
const DEFAULT_SERVER_URL: &str = "http://127.0.0.1:8787";

fn parse_uuid(id: &str) -> Result<Uuid, AppError> {
    Uuid::parse_str(id).map_err(|_| AppError::invalid_input("invalid document id"))
}

/// `Settings::quick_unlock_enabled` (`docs/CRYPTO.md §5.2`): real enrollment status on Android,
/// always `false` on desktop (no quick-unlock concept there — see `vault_unlock_quick`'s desktop
/// stub).
#[cfg(mobile)]
fn quick_unlock_enabled(data_dir: &std::path::Path) -> bool {
    crate::quick_unlock::is_enabled(data_dir)
}

#[cfg(not(mobile))]
fn quick_unlock_enabled(_data_dir: &std::path::Path) -> bool {
    false
}

// ---------------------------------------------------------------- vault lifecycle -------------

#[tauri::command]
pub async fn vault_status(state: State<'_, AppState>) -> Result<VaultStatus, AppError> {
    let guard = state.slot.lock().await;
    match guard.as_ref() {
        Some(VaultSlot::Unlocked(_)) => Ok(VaultStatus::Unlocked),
        Some(VaultSlot::Locked(v)) => {
            if v.is_initialised().map_err(AppError::from)? {
                Ok(VaultStatus::Locked)
            } else {
                Ok(VaultStatus::Uninitialised)
            }
        }
        None => Err(AppError::internal_state()),
    }
}

#[tauri::command]
pub async fn vault_create(
    state: State<'_, AppState>,
    server_url: String,
    token: String,
    passphrase: String,
) -> Result<(), AppError> {
    let mut guard = state.slot.lock().await;
    let current = guard.take().ok_or_else(AppError::internal_state)?;
    let locked = match current {
        VaultSlot::Locked(v) => v,
        VaultSlot::Unlocked(u) => {
            *guard = Some(VaultSlot::Unlocked(u));
            return Err(AppError::already_unlocked());
        }
    };

    let passphrase_secret = SecretString::from(passphrase);
    let token_secret = SecretString::from(token.clone());

    match locked
        .create(&server_url, token_secret, &passphrase_secret)
        .await
    {
        Ok(unlocked) => {
            let auto_lock_minutes = *state.auto_lock_minutes.lock().await;
            let save_result = config::save(
                &state.data_dir,
                &AppConfig {
                    server_url,
                    token,
                    auto_lock_minutes,
                },
            );
            *guard = Some(VaultSlot::Unlocked(unlocked));
            drop(guard);
            state.touch_activity().await;
            #[cfg(mobile)]
            {
                // Best-effort (`crate::quick_unlock`'s own docs): keeps the 7-day re-auth window
                // correct from the very first unlock, even before the user opts into quick
                // unlock. Never surfaced as an error — this is bookkeeping, not the vault itself.
                let _ = crate::quick_unlock::record_passphrase_auth(&state.data_dir);
            }
            // The vault itself is created and unlocked at this point even if persisting our
            // local server_url/token file failed; surface the failure so the UI can warn the
            // user they may need to unlock manually again (see `config` module docs).
            save_result
        }
        Err(err) => {
            *guard = state.reopen_locked();
            Err(AppError::from(err))
        }
    }
}

#[tauri::command]
pub async fn vault_join(
    state: State<'_, AppState>,
    server_url: String,
    token: String,
    passphrase: String,
) -> Result<(), AppError> {
    let mut guard = state.slot.lock().await;
    let current = guard.take().ok_or_else(AppError::internal_state)?;
    let locked = match current {
        VaultSlot::Locked(v) => v,
        VaultSlot::Unlocked(u) => {
            *guard = Some(VaultSlot::Unlocked(u));
            return Err(AppError::already_unlocked());
        }
    };

    let passphrase_secret = SecretString::from(passphrase);
    let token_secret = SecretString::from(token.clone());

    match locked
        .join(&server_url, token_secret, &passphrase_secret)
        .await
    {
        Ok(unlocked) => {
            let auto_lock_minutes = *state.auto_lock_minutes.lock().await;
            let save_result = config::save(
                &state.data_dir,
                &AppConfig {
                    server_url,
                    token,
                    auto_lock_minutes,
                },
            );
            *guard = Some(VaultSlot::Unlocked(unlocked));
            drop(guard);
            state.touch_activity().await;
            #[cfg(mobile)]
            {
                let _ = crate::quick_unlock::record_passphrase_auth(&state.data_dir);
            }
            save_result
        }
        Err(err) => {
            *guard = state.reopen_locked();
            Err(AppError::from(err))
        }
    }
}

#[tauri::command]
pub async fn vault_unlock(state: State<'_, AppState>, passphrase: String) -> Result<(), AppError> {
    let mut guard = state.slot.lock().await;
    let current = guard.take().ok_or_else(AppError::internal_state)?;
    let locked = match current {
        VaultSlot::Locked(v) => v,
        // Idempotent no-op: already unlocked.
        VaultSlot::Unlocked(u) => {
            *guard = Some(VaultSlot::Unlocked(u));
            return Ok(());
        }
    };

    let cfg = match config::load(&state.data_dir) {
        Some(c) => c,
        None => {
            *guard = Some(VaultSlot::Locked(locked));
            return Err(AppError::no_saved_credentials());
        }
    };

    let passphrase_secret = SecretString::from(passphrase);
    let token_secret = SecretString::from(cfg.token);

    match locked.unlock(&passphrase_secret, token_secret, None) {
        Ok(unlocked) => {
            *guard = Some(VaultSlot::Unlocked(unlocked));
            drop(guard);
            state.touch_activity().await;
            #[cfg(mobile)]
            {
                let _ = crate::quick_unlock::record_passphrase_auth(&state.data_dir);
            }
            Ok(())
        }
        Err(err) => {
            *guard = state.reopen_locked();
            Err(AppError::from(err))
        }
    }
}

/// Always unavailable on desktop (`docs/ARCHITECTURE.md §6`): no Stronghold/biometric device
/// unlock store exists yet. See [`AppError::quick_unlock_unavailable`]. The real Android
/// implementation is below, `#[cfg(mobile)]`.
#[cfg(not(mobile))]
#[tauri::command]
pub fn vault_unlock_quick(_reason: String) -> Result<(), AppError> {
    Err(AppError::quick_unlock_unavailable())
}

/// Android only (`docs/CRYPTO.md §5.2`, `crate::quick_unlock`): gates reading the stored
/// passphrase behind a biometric prompt and, on success, unlocks exactly like [`vault_unlock`]
/// (same state-machine shape — see that command's comments, not repeated here).
///
/// `reason` is the OS biometric-prompt text and is Italian UI copy (`CLAUDE.md`: UI strings live
/// in `apps/mobile/src/i18n/it.ts`) — the frontend must supply it; this command never hardcodes
/// user-facing text.
///
/// # Errors
/// [`AppError::quick_unlock_unavailable`] if not enrolled (including: fresh install, since a
/// reinstall has no `quick_unlock_secret`/`vault.stronghold` files). Otherwise as
/// [`AppError::quick_unlock_reauth_required`] once the 7-day window / failed-attempt count fires,
/// or [`AppError::biometric_failed`] for a single cancelled/failed prompt.
#[cfg(mobile)]
#[tauri::command]
pub async fn vault_unlock_quick(
    app: AppHandle,
    state: State<'_, AppState>,
    reason: String,
) -> Result<(), AppError> {
    use tauri_plugin_biometric::BiometricExt as _;

    let mut guard = state.slot.lock().await;
    let current = guard.take().ok_or_else(AppError::internal_state)?;
    let locked = match current {
        VaultSlot::Locked(v) => v,
        // Idempotent no-op: already unlocked, same as `vault_unlock`.
        VaultSlot::Unlocked(u) => {
            *guard = Some(VaultSlot::Unlocked(u));
            return Ok(());
        }
    };

    let cfg = match config::load(&state.data_dir) {
        Some(c) => c,
        None => {
            *guard = Some(VaultSlot::Locked(locked));
            return Err(AppError::no_saved_credentials());
        }
    };

    let passphrase_secret = match crate::quick_unlock::load_passphrase(&state.data_dir) {
        Ok(p) => p,
        Err(err) => {
            *guard = Some(VaultSlot::Locked(locked));
            return Err(err);
        }
    };

    if app
        .biometric()
        .authenticate(reason, tauri_plugin_biometric::AuthOptions::default())
        .is_err()
    {
        // Never log the underlying plugin error: it can echo the OS-provided prompt text back
        // (`CLAUDE.md`: no user-facing/UI content in logs).
        let _ = crate::quick_unlock::record_failed_biometric_attempt(&state.data_dir);
        *guard = Some(VaultSlot::Locked(locked));
        return Err(AppError::biometric_failed());
    }

    let token_secret = SecretString::from(cfg.token);
    match locked.unlock(&passphrase_secret, token_secret, None) {
        Ok(unlocked) => {
            *guard = Some(VaultSlot::Unlocked(unlocked));
            drop(guard);
            state.touch_activity().await;
            // Deliberately not `record_passphrase_auth`: quick unlock is not a passphrase
            // authentication, and must not extend the 7-day window on its own (see
            // `crate::quick_unlock`'s module docs) or a single passphrase entry could keep quick
            // unlock alive forever.
            Ok(())
        }
        Err(err) => {
            *guard = state.reopen_locked();
            Err(AppError::from(err))
        }
    }
}

/// Enrols quick unlock (`docs/CRYPTO.md §5.2`): always unavailable on desktop, same shape as
/// [`vault_unlock_quick`]'s desktop stub.
#[cfg(not(mobile))]
#[tauri::command]
pub fn vault_enable_quick_unlock(_passphrase: String) -> Result<(), AppError> {
    Err(AppError::quick_unlock_unavailable())
}

/// Android only: stores `passphrase` in the quick-unlock Stronghold snapshot
/// (`crate::quick_unlock::enable`). Requires the vault to already be unlocked in this session —
/// not because the passphrase is read from there (it never is, see `crate::quick_unlock`'s module
/// docs), but because enrolling quick unlock while locked/uninitialised makes no sense as a UX
/// (there is nothing yet to skip typing the passphrase for).
#[cfg(mobile)]
#[tauri::command]
pub async fn vault_enable_quick_unlock(
    state: State<'_, AppState>,
    passphrase: String,
) -> Result<(), AppError> {
    let guard = state.slot.lock().await;
    if !matches!(guard.as_ref(), Some(VaultSlot::Unlocked(_))) {
        return Err(AppError::not_unlocked());
    }
    drop(guard);

    let passphrase_secret = SecretString::from(passphrase);
    crate::quick_unlock::enable(&state.data_dir, &passphrase_secret)?;
    state.touch_activity().await;
    Ok(())
}

/// "Forget quick unlock": wipes the Stronghold snapshot and device secret
/// (`crate::quick_unlock::forget`), distinct from [`vault_lock`] — see that function's doc
/// comment and `crate::quick_unlock::forget`'s. Always `Ok(())` on desktop (nothing to forget,
/// and calling it unconditionally from "Blocca completamente" must never fail there).
#[cfg(not(mobile))]
#[tauri::command]
pub fn vault_forget_quick_unlock() -> Result<(), AppError> {
    Ok(())
}

#[cfg(mobile)]
#[tauri::command]
pub async fn vault_forget_quick_unlock(state: State<'_, AppState>) -> Result<(), AppError> {
    crate::quick_unlock::forget(&state.data_dir)
}

/// Zeroizes the in-memory master key only. On Android, this **does not** touch the quick-unlock
/// Stronghold snapshot (`crate::quick_unlock`) — a plain lock (auto-lock, background-lock, or a
/// manual "lock now" button) is meant to still be reopenable with a biometric prompt afterwards.
/// "Blocca completamente" needs both this command **and** [`vault_forget_quick_unlock`]; wiring
/// only this one leaves quick unlock enrolled, which contradicts what "completamente" promises
/// (`docs/CRYPTO.md §5.2` requires a full passphrase re-auth after that specific action) — see
/// this milestone's report for the required frontend change.
#[tauri::command]
pub async fn vault_lock(state: State<'_, AppState>) -> Result<(), AppError> {
    let mut guard = state.slot.lock().await;
    let current = guard.take().ok_or_else(AppError::internal_state)?;
    *guard = Some(match current {
        VaultSlot::Unlocked(u) => VaultSlot::Locked(u.lock()),
        // Idempotent no-op: already locked.
        VaultSlot::Locked(v) => VaultSlot::Locked(v),
    });
    Ok(())
}

/// Generates a new recovery code, wraps the master key under it, and registers the resulting
/// keyslot with the server (`scrigno_client::UnlockedVault::add_recovery_keyslot`;
/// `docs/CRYPTO.md §3`, `docs/ROADMAP.md` M4 Setup/Settings screens).
///
/// # Security — read before wiring this into the UI
///
/// The returned `String` is the **plaintext recovery code, shown exactly once**. Nothing on the
/// device or the server ever stores it in plaintext again (`docs/CRYPTO.md §3`: "shown once",
/// "stored nowhere in plaintext") — only its Argon2id-derived KEK wraps the master key, server
/// side, and that wrapped blob is useless without the code. The frontend must:
/// - display it once, in a "copy/write this down" UI, and never persist it (no `localStorage`,
///   no IndexedDB, no re-fetch — there is no `vault_get_recovery_code` and there never will be);
/// - never pass it to `tracing`/`console.log`/crash reporting;
/// - treat a lost code exactly like a lost passphrase: unrecoverable, a new one must be
///   generated (that just adds another keyslot; it doesn't invalidate old ones — see
///   `docs/CRYPTO.md §3` if that needs to change).
///
/// Requires the vault to be unlocked (the master key must be in memory to wrap it under the new
/// recovery KEK); maps to [`AppError::not_unlocked`] otherwise, same as every other
/// `UnlockedVault`-backed command.
#[tauri::command]
pub async fn vault_add_recovery_code(state: State<'_, AppState>) -> Result<String, AppError> {
    let mut guard = state.slot.lock().await;
    let Some(VaultSlot::Unlocked(u)) = guard.as_mut() else {
        return Err(AppError::not_unlocked());
    };
    let code = u.add_recovery_keyslot().await.map_err(AppError::from)?;
    drop(guard);
    state.touch_activity().await;
    Ok(code)
}

// ---------------------------------------------------------------- documents --------------------

#[tauri::command]
pub async fn docs_list(state: State<'_, AppState>) -> Result<Vec<DocSummary>, AppError> {
    let guard = state.slot.lock().await;
    let Some(VaultSlot::Unlocked(u)) = guard.as_ref() else {
        return Err(AppError::not_unlocked());
    };
    let list = u.list();
    drop(guard);
    state.touch_activity().await;
    Ok(list)
}

/// JPEG bytes decoded from `DocMeta.thumb`'s base64, or an empty body if the document has no
/// thumbnail (`docs/ARCHITECTURE.md §6`).
#[tauri::command]
pub async fn doc_thumb(state: State<'_, AppState>, id: String) -> Result<Response, AppError> {
    let doc_id = parse_uuid(&id)?;
    let guard = state.slot.lock().await;
    let Some(VaultSlot::Unlocked(u)) = guard.as_ref() else {
        return Err(AppError::not_unlocked());
    };
    let meta = u.get_meta(doc_id).map_err(AppError::from)?;
    drop(guard);
    state.touch_activity().await;

    let bytes = match meta.thumb {
        Some(b64) => BASE64
            .decode(b64.as_bytes())
            .map_err(|_| AppError::from(ClientError::Crypto))?,
        None => Vec::new(),
    };
    Ok(Response::new(bytes))
}

#[tauri::command]
pub async fn doc_get_meta(state: State<'_, AppState>, id: String) -> Result<DocMeta, AppError> {
    let doc_id = parse_uuid(&id)?;
    let guard = state.slot.lock().await;
    let Some(VaultSlot::Unlocked(u)) = guard.as_ref() else {
        return Err(AppError::not_unlocked());
    };
    let meta = u.get_meta(doc_id).map_err(AppError::from)?;
    drop(guard);
    state.touch_activity().await;
    Ok(meta)
}

/// `path` from the dialog plugin's picker: a regular filesystem path on desktop, but on Android
/// often an opaque `content://` URI (`docs/ARCHITECTURE.md §6`: "Android `content://` handled by
/// fs plugin"). `std::fs::File::open` cannot open a `content://` string at all — it isn't a
/// filesystem path, there's nothing on disk at that literal string. `AppHandle::fs()`
/// (`tauri_plugin_fs::FsExt`) resolves both uniformly: plain `std::fs` on desktop, and Android's
/// native `ContentResolver` (`getFileDescriptor`) for `content://`, via the same `Fs::open` call
/// on every platform — so no `#[cfg(mobile)]` branch is needed here at all. Used only from this
/// Rust command, never exposed to the webview — no `fs:*` permission is granted in
/// `capabilities/default.json` (JSON has no comments to explain that there, hence this one)
/// since nothing ever calls it over IPC; the ACL only gates the webview's `invoke()` calls.
#[tauri::command]
pub async fn doc_add_from_path(
    app: AppHandle,
    state: State<'_, AppState>,
    path: String,
    title: String,
    tags: Vec<String>,
    note: String,
) -> Result<DocSummary, AppError> {
    use tauri_plugin_fs::{FilePath, FsExt as _, OpenOptions};

    // `FilePath::from_str` is `Infallible`: a bare `content://...`/`file://...` string parses as
    // `FilePath::Url`, anything else (a plain OS path, on any platform) as `FilePath::Path`.
    let file_path = match FilePath::from_str(&path) {
        Ok(fp) => fp,
        Err(never) => match never {},
    };
    let mut open_options = OpenOptions::new();
    open_options.read(true);
    let file = app
        .fs()
        .open(file_path, open_options)
        .map_err(|_| AppError::io_error())?;

    // Best-effort mime/filename guess from the raw string — works for a normal path on every
    // platform; for a `content://` URI (typically no file extension in the URI itself) this
    // falls back to `application/octet-stream`/`"document"`, same as it always has. A richer
    // guess (from the content resolver's own metadata) would need a command signature change —
    // left for `frontend-ui` to request if it matters in practice.
    let path_buf = std::path::PathBuf::from(&path);
    let mime = mime_guess::from_path(&path_buf)
        .first_or_octet_stream()
        .essence_str()
        .to_string();
    let original_name = path_buf
        .file_name()
        .and_then(|n| n.to_str())
        .map(str::to_string)
        .unwrap_or_else(|| "document".to_string());

    let mut guard = state.slot.lock().await;
    let Some(VaultSlot::Unlocked(u)) = guard.as_mut() else {
        return Err(AppError::not_unlocked());
    };
    let summary = u
        .add(file, title, tags, note, mime, original_name)
        .await
        .map_err(AppError::from)?;
    drop(guard);
    state.touch_activity().await;
    Ok(summary)
}

/// Metadata carried in the `x-scrigno-meta` header of a `doc_add_bytes` request
/// (`docs/ARCHITECTURE.md §6`).
///
/// Deliberately **not** `#[derive(Debug)]`: `title`/`tags`/`note`/`original_name` are user
/// plaintext (`CLAUDE.md`: "never log titles, file names..."). No `Debug` impl means a stray
/// `tracing::debug!("{:?}", meta)` fails to compile instead of silently leaking it later.
#[derive(Deserialize)]
struct AddBytesMeta {
    title: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    note: String,
    mime: String,
    original_name: String,
}

/// For the `<input type="file" capture>` flow (mobile-only UX, `docs/ARCHITECTURE.md §6`); the
/// command itself works on any platform that can send a raw-bytes IPC request.
#[tauri::command]
pub async fn doc_add_bytes(
    state: State<'_, AppState>,
    request: Request<'_>,
) -> Result<DocSummary, AppError> {
    let bytes = match request.body() {
        InvokeBody::Raw(bytes) => bytes.clone(),
        InvokeBody::Json(_) => return Err(AppError::invalid_request()),
    };
    let header = request
        .headers()
        .get("x-scrigno-meta")
        .ok_or_else(AppError::invalid_request)?
        .to_str()
        .map_err(|_| AppError::invalid_request())?;
    let meta: AddBytesMeta =
        serde_json::from_str(header).map_err(|_| AppError::invalid_request())?;

    let mut guard = state.slot.lock().await;
    let Some(VaultSlot::Unlocked(u)) = guard.as_mut() else {
        return Err(AppError::not_unlocked());
    };
    let summary = u
        .add(
            Cursor::new(bytes),
            meta.title,
            meta.tags,
            meta.note,
            meta.mime,
            meta.original_name,
        )
        .await
        .map_err(AppError::from)?;
    drop(guard);
    state.touch_activity().await;
    Ok(summary)
}

/// Decrypts document `id` to memory and returns it as a binary IPC response. The caller (frontend)
/// is responsible for revoking any object URL created from it on close
/// (`docs/ARCHITECTURE.md §6`).
///
/// Buffers the whole decrypted document in memory before responding — `tauri::ipc::Response`
/// doesn't offer a chunked/streaming body in this Tauri version, so this milestone accepts that
/// simplification (documents are individual files, not the multi-hundred-MB blobs
/// `scrigno-client`'s own streaming design targets for local disk I/O).
#[tauri::command]
pub async fn doc_open(state: State<'_, AppState>, id: String) -> Result<Response, AppError> {
    let doc_id = parse_uuid(&id)?;
    let mut guard = state.slot.lock().await;
    let Some(VaultSlot::Unlocked(u)) = guard.as_mut() else {
        return Err(AppError::not_unlocked());
    };
    let mut buf = Vec::new();
    u.open(doc_id, &mut buf).await.map_err(AppError::from)?;
    drop(guard);
    state.touch_activity().await;
    Ok(Response::new(buf))
}

/// Desktop: share sheets are a mobile-native concept (`docs/ROADMAP.md` scopes this to M5,
/// Android); the real implementation is below, `#[cfg(mobile)]`.
#[cfg(not(mobile))]
#[tauri::command]
pub async fn doc_share(_state: State<'_, AppState>, _id: String) -> Result<(), AppError> {
    Err(AppError::not_implemented())
}

/// Prefix for the plaintext temp files `doc_share` writes to `app_cache_dir()`
/// (`docs/CRYPTO.md §5.3`: "Sharing/exporting a document to another app writes a plaintext copy
/// to the app's cache dir and deletes it as soon as the share sheet returns"). Also used by
/// [`cleanup_stale_share_files`] to recognise and sweep leftovers from a previous process that
/// died before its own 60 s cleanup timer fired.
#[cfg(mobile)]
const SHARE_FILE_PREFIX: &str = "scrigno-share-";

/// How long a shared plaintext temp file is allowed to live before [`doc_share`] deletes it
/// itself. `tauri_plugin_opener::Opener::open_path` (Android) starts the "open with" intent and
/// returns immediately — it does not wait for the chooser/viewer to close, so "as soon as the
/// share sheet returns" (`docs/CRYPTO.md §5.3`) is not something this plugin lets us observe.
/// 60 s is a documented, deliberate compromise: long enough for the user to pick an app and for
/// that app to have opened/copied the bytes it needs, short enough that a plaintext copy never
/// sits on disk for long. See [`cleanup_stale_share_files`] for the process-death case (this
/// timer is itself in-memory and does not survive the app being killed).
#[cfg(mobile)]
const SHARE_FILE_LIFETIME: std::time::Duration = std::time::Duration::from_secs(60);

/// Deletes any leftover `doc_share` temp file from a previous run of the app (i.e. the process
/// died, or was killed by Android, before its own 60 s cleanup task got to run — see
/// [`SHARE_FILE_LIFETIME`]'s docs). Called once at startup (`lib.rs`'s `setup`, mobile only);
/// best-effort, errors are swallowed — a missing/unreadable cache dir is not fatal to startup.
#[cfg(mobile)]
pub(crate) fn cleanup_stale_share_files(app: &AppHandle) {
    use tauri::Manager as _;

    let Ok(cache_dir) = app.path().app_cache_dir() else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(&cache_dir) else {
        return;
    };
    for entry in entries.flatten() {
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(SHARE_FILE_PREFIX))
        {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Writes `contents` to a brand-new file at `path`, created at mode `0600` via the `open` call's
/// own mode argument rather than `std::fs::write` followed by a separate `set_permissions` —
/// atomic with respect to permissions, so no other app on the device can observe this plaintext
/// share file at default/umask permissions in the window between creation and chmod. `mobile`
/// targets (Android, iOS) are both Unix, so `OpenOptionsExt::mode` is always available here.
#[cfg(mobile)]
fn write_plaintext_restricted(path: &std::path::Path, contents: &[u8]) -> Result<(), AppError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| AppError::io_error())?;
    file.write_all(contents).map_err(|_| AppError::io_error())
}

/// Android only: decrypts document `id` to a plaintext temp file in the app's cache dir and opens
/// it with the OS "open with" picker (`tauri_plugin_opener`), deleting the file after
/// [`SHARE_FILE_LIFETIME`] (see that constant's docs for why a fixed timeout rather than "when
/// the share sheet returns").
///
/// # A judgment call on what "share sheet" means here
/// `tauri-plugin-opener`'s own docs (checked this milestone) state Android/iOS "always opens
/// using default program" — i.e. `Intent.ACTION_VIEW` against the FileProvider `content://` URI,
/// which only ever presents Android's app-disambiguation chooser when *more than one* app is
/// registered as a viewer for that MIME type, and even then it is "apri con" (open with a single
/// app), not "condividi con" (`Intent.ACTION_SEND` + `Intent.createChooser`, which can also target
/// messaging/mail/cloud apps that only register as `ACTION_SEND` receivers, not `ACTION_VIEW`
/// viewers). A true multi-target share sheet needs a small custom Kotlin plugin building that
/// `ACTION_SEND` intent — `TODO(m5)`: not written this milestone (no such plugin exists in the
/// current Tauri plugin ecosystem; `tauri-plugin-opener` is the closest available primitive and
/// is what's wired here).
///
/// The already-generated `AndroidManifest.xml`'s `FileProvider` (`${applicationId}.fileprovider`,
/// declared by `tauri android init` itself, not added by this milestone) is exactly what makes
/// `open_path` able to hand out a `content://` URI for a file under the cache dir in the first
/// place — required on API 24+ per `docs/ROADMAP.md`'s own note; `file_paths.xml`'s
/// `cache-path name="my_cache_images" path="."` entry (also pre-generated) already covers
/// `app_cache_dir()`.
///
/// **`tauri-plugin-opener`'s Android `open` command does not build that `content://` URI for
/// you** — checked its Kotlin source this milestone (`OpenerPlugin.kt`): it does exactly
/// `Intent(ACTION_VIEW, args.url.toUri())`, i.e. whatever string we pass is parsed as a URI
/// as-is. Passing a bare filesystem path would parse as a scheme-less URI (unusable in an
/// `ACTION_VIEW` intent); passing a `file://` URI would throw `FileUriExposedException` on a
/// `targetSdk` this high (API 24+, `android:targetSdk = 36` here) when handed to another app. So
/// this command builds the `content://` URI itself, following `FileProvider`'s own documented,
/// deterministic construction (`content://<authority>/<paths.xml name>/<path relative to that
/// root>`) rather than calling into `androidx.core.content.FileProvider` from Kotlin — there is
/// no Rust-callable hook for that, and writing one would mean a custom Kotlin plugin for this
/// alone. `<authority>` is `${applicationId}.fileprovider` in the manifest; `app.config().identifier`
/// is the same string Tauri used to generate `applicationId` at `android init` time, so this
/// only drifts if `gen/android` isn't regenerated after changing `tauri.conf.json`'s
/// `identifier` — already a general Tauri Android caveat, not new here.
#[cfg(mobile)]
#[tauri::command]
pub async fn doc_share(
    app: AppHandle,
    state: State<'_, AppState>,
    id: String,
) -> Result<(), AppError> {
    use tauri::Manager as _;
    use tauri_plugin_opener::OpenerExt as _;
    use zeroize::Zeroize as _;

    let doc_id = parse_uuid(&id)?;
    let mut guard = state.slot.lock().await;
    let Some(VaultSlot::Unlocked(u)) = guard.as_mut() else {
        return Err(AppError::not_unlocked());
    };
    let meta = u.get_meta(doc_id).map_err(AppError::from)?;
    let mut plaintext = Vec::new();
    u.open(doc_id, &mut plaintext)
        .await
        .map_err(AppError::from)?;
    drop(guard);
    state.touch_activity().await;

    let cache_dir = app
        .path()
        .app_cache_dir()
        .map_err(|_| AppError::io_error())?;
    std::fs::create_dir_all(&cache_dir).map_err(|_| AppError::io_error())?;

    let ext = mime_guess::get_mime_extensions_str(&meta.mime)
        .and_then(|exts| exts.first())
        .copied()
        .unwrap_or("bin");
    let share_path = cache_dir.join(format!("{SHARE_FILE_PREFIX}{doc_id}.{ext}"));

    // Created at mode `0600` via `open`'s own mode argument rather than `fs::write` + a
    // follow-up `set_permissions`, so there is no window where this plaintext copy sits at
    // default/umask permissions before being tightened.
    let write_result = write_plaintext_restricted(&share_path, &plaintext);
    plaintext.zeroize();
    write_result?;

    let file_name = share_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    // See this function's doc comment: Android needs the FileProvider `content://` form built
    // by hand; anywhere else a plain `file://` URL is fine (and is what the opener plugin's
    // desktop/iOS sides actually expect — passing a bare path also works on desktop in
    // practice, but a URL is the documented, portable input for `open_path`).
    #[cfg(target_os = "android")]
    let share_uri = format!(
        "content://{}.fileprovider/my_cache_images/{file_name}",
        app.config().identifier
    );
    #[cfg(not(target_os = "android"))]
    let share_uri = format!("file://{}", share_path.display());

    let open_result = app
        .opener()
        .open_path(share_uri, None::<&str>)
        .map_err(|_| AppError::io_error());

    let cleanup_path = share_path.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(SHARE_FILE_LIFETIME).await;
        let _ = std::fs::remove_file(&cleanup_path);
    });

    open_result
}

#[tauri::command]
pub async fn doc_update_meta(
    state: State<'_, AppState>,
    id: String,
    title: String,
    tags: Vec<String>,
    note: String,
) -> Result<DocSummary, AppError> {
    let doc_id = parse_uuid(&id)?;
    let mut guard = state.slot.lock().await;
    let Some(VaultSlot::Unlocked(u)) = guard.as_mut() else {
        return Err(AppError::not_unlocked());
    };
    let summary = u
        .update_meta(doc_id, title, tags, note)
        .map_err(AppError::from)?;
    drop(guard);
    state.touch_activity().await;
    Ok(summary)
}

#[tauri::command]
pub async fn doc_set_keep_offline(
    state: State<'_, AppState>,
    id: String,
    keep_offline: bool,
) -> Result<(), AppError> {
    let doc_id = parse_uuid(&id)?;
    let mut guard = state.slot.lock().await;
    let Some(VaultSlot::Unlocked(u)) = guard.as_mut() else {
        return Err(AppError::not_unlocked());
    };
    u.set_keep_offline(doc_id, keep_offline)
        .map_err(AppError::from)?;
    drop(guard);
    state.touch_activity().await;
    Ok(())
}

#[tauri::command]
pub async fn doc_delete(state: State<'_, AppState>, id: String) -> Result<(), AppError> {
    let doc_id = parse_uuid(&id)?;
    let mut guard = state.slot.lock().await;
    let Some(VaultSlot::Unlocked(u)) = guard.as_mut() else {
        return Err(AppError::not_unlocked());
    };
    u.delete(doc_id).map_err(AppError::from)?;
    drop(guard);
    state.touch_activity().await;
    Ok(())
}

// ---------------------------------------------------------------- sync -------------------------

/// `sync-progress` event payload (`docs/ARCHITECTURE.md §6`: `{ phase, done, total }`).
///
/// `scrigno-client`'s `UnlockedVault::sync` returns one [`SyncReport`] at the end with no
/// progress callback hook, so genuine granular progress isn't available without a client-API
/// change that is out of scope here. This emits a reasonable start/end pair around the call
/// instead; the returned `SyncReport` is the real result the frontend shows. A documented
/// simplification, not deeper progress plumbing.
#[derive(Debug, Clone, Serialize)]
struct SyncProgress {
    phase: &'static str,
    done: u32,
    total: u32,
}

#[tauri::command]
pub async fn sync_now(app: AppHandle, state: State<'_, AppState>) -> Result<SyncReport, AppError> {
    let _ = app.emit(
        "sync-progress",
        SyncProgress {
            phase: "syncing",
            done: 0,
            total: 0,
        },
    );

    let mut guard = state.slot.lock().await;
    let Some(VaultSlot::Unlocked(u)) = guard.as_mut() else {
        return Err(AppError::not_unlocked());
    };
    let report = u.sync().await.map_err(AppError::from)?;
    drop(guard);
    state.touch_activity().await;

    let total = report.pulled + report.pushed;
    let _ = app.emit(
        "sync-progress",
        SyncProgress {
            phase: "done",
            done: total,
            total,
        },
    );
    Ok(report)
}

// ---------------------------------------------------------------- settings ---------------------

#[tauri::command]
pub async fn settings_get(state: State<'_, AppState>) -> Result<Settings, AppError> {
    let auto_lock_minutes = *state.auto_lock_minutes.lock().await;

    let guard = state.slot.lock().await;
    let cache_limit_mb = match guard.as_ref() {
        Some(VaultSlot::Unlocked(u)) => u.cache_limit_mb().map_err(AppError::from)?,
        // Best-effort: the real value lives behind the master key (`UnlockedVault::cache_limit_mb`).
        _ => DEFAULT_CACHE_LIMIT_MB,
    };
    drop(guard);

    let server_url = config::load(&state.data_dir)
        .map(|c| c.server_url)
        .unwrap_or_else(|| DEFAULT_SERVER_URL.to_string());

    Ok(Settings {
        auto_lock_minutes,
        cache_limit_mb,
        server_url,
        quick_unlock_enabled: quick_unlock_enabled(&state.data_dir),
    })
}

/// Applies `auto_lock_minutes` (clamped to 1–30) and `cache_limit_mb`; silently ignores
/// `settings.server_url` (read-only after `vault_create`/`vault_join`, per
/// `docs/ARCHITECTURE.md §7` — a round trip of `settings_get`'s own output through this command
/// should never fail just because the caller echoed the current `server_url` back).
///
/// Requires the vault to be unlocked: `cache_limit_mb` only exists on `UnlockedVault`
/// (`scrigno-client`), and `docs/ROADMAP.md` places the Settings screen inside the main,
/// post-unlock app.
#[tauri::command]
pub async fn settings_set(
    state: State<'_, AppState>,
    settings: Settings,
) -> Result<Settings, AppError> {
    let mut guard = state.slot.lock().await;
    let Some(VaultSlot::Unlocked(u)) = guard.as_mut() else {
        return Err(AppError::not_unlocked());
    };
    u.set_cache_limit_mb(settings.cache_limit_mb)
        .map_err(AppError::from)?;
    let cache_limit_mb = u.cache_limit_mb().map_err(AppError::from)?;
    drop(guard);

    let clamped_minutes = settings
        .auto_lock_minutes
        .clamp(MIN_AUTO_LOCK_MINUTES, MAX_AUTO_LOCK_MINUTES);
    *state.auto_lock_minutes.lock().await = clamped_minutes;
    state.touch_activity().await;

    if let Some(mut cfg) = config::load(&state.data_dir) {
        cfg.auto_lock_minutes = clamped_minutes;
        config::save(&state.data_dir, &cfg)?;
    }

    let server_url = config::load(&state.data_dir)
        .map(|c| c.server_url)
        .unwrap_or_else(|| DEFAULT_SERVER_URL.to_string());

    Ok(Settings {
        auto_lock_minutes: clamped_minutes,
        cache_limit_mb,
        server_url,
        quick_unlock_enabled: quick_unlock_enabled(&state.data_dir),
    })
}

#[cfg(all(test, not(mobile)))]
mod tests {
    use super::*;

    /// Desktop has no quick-unlock concept (`crate::quick_unlock` is `#[cfg(mobile)]` entirely),
    /// so `Settings::quick_unlock_enabled` — sourced from this helper in both `settings_get` and
    /// `settings_set` — must always be `false` there, regardless of what's on disk at `data_dir`.
    #[test]
    fn quick_unlock_enabled_is_always_false_on_desktop() {
        assert!(!quick_unlock_enabled(std::path::Path::new(
            "/nonexistent/does-not-matter"
        )));
    }
}
