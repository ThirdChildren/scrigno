//! Tauri command surface (`docs/ARCHITECTURE.md §6`). Every command is thin: deserialize → call
//! `scrigno_client::Vault`/`UnlockedVault` → map `ClientError` to [`AppError`]. No business
//! logic, no crypto, no SQL lives here.

use std::io::Cursor;

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
            Ok(())
        }
        Err(err) => {
            *guard = state.reopen_locked();
            Err(AppError::from(err))
        }
    }
}

/// Always unavailable on desktop (`docs/ARCHITECTURE.md §6`): no Stronghold/biometric device
/// unlock store exists yet — that is M5. See [`AppError::quick_unlock_unavailable`].
#[tauri::command]
pub fn vault_unlock_quick() -> Result<(), AppError> {
    Err(AppError::quick_unlock_unavailable())
}

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

#[tauri::command]
pub async fn doc_add_from_path(
    state: State<'_, AppState>,
    path: String,
    title: String,
    tags: Vec<String>,
    note: String,
) -> Result<DocSummary, AppError> {
    let file_path = std::path::PathBuf::from(&path);
    let file = std::fs::File::open(&file_path).map_err(|_| AppError::io_error())?;
    let mime = mime_guess::from_path(&file_path)
        .first_or_octet_stream()
        .essence_str()
        .to_string();
    let original_name = file_path
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

/// Not implemented this milestone: `docs/ROADMAP.md` explicitly assigns "share sheet via opener/
/// share plugin; plaintext temp file deleted afterwards" to M5. Registered (rather than omitted)
/// so the frontend gets a clear, stable error instead of "command not found" if it's wired up
/// ahead of that milestone.
#[tauri::command]
pub async fn doc_share(_state: State<'_, AppState>, _id: String) -> Result<(), AppError> {
    Err(AppError::not_implemented())
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
    })
}
