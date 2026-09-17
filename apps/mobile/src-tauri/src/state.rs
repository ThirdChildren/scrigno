//! `AppState`: the vault's in-memory state across IPC calls, plus the inactivity auto-lock timer
//! (`docs/CRYPTO.md §5.2`, desktop scope only — see [`spawn_auto_lock`]'s doc comment).

use std::path::PathBuf;
use std::time::{Duration, Instant};

use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::Mutex;

use scrigno_client::{UnlockedVault, Vault};

use crate::config::{self, DEFAULT_AUTO_LOCK_MINUTES};
use crate::types::AppError;

/// How often the background auto-lock task wakes up to check elapsed inactivity. Small enough
/// that the configured 1–30 minute timeout is honoured within a few seconds; cheap enough to run
/// forever in the background.
const AUTO_LOCK_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// The vault's local store, in one of two states.
///
/// `docs/ARCHITECTURE.md §6`'s three-way `VaultStatus` (`uninitialised`/`locked`/`unlocked`) is
/// deliberately **not** mirrored 1:1 here: `Locked` and `Uninitialised` are both "a bound `Vault`
/// with no master key in memory" at the type level — `Vault::is_initialised()` (already on the
/// type, not invented for this milestone) tells them apart when `commands::vault_status` needs
/// to. This also means this state intentionally differs from `docs/ARCHITECTURE.md §6`'s literal
/// `Mutex<Option<UnlockedVault>>` wording: a `Locked` variant keeps the already-open `Vault` (and
/// its local SQLite store) around instead of dropping it and calling `Vault::open` again on every
/// command — `vault_status`/`vault_unlock` need a live `Vault` whether or not a master key is in
/// memory yet, and reopening the local store on every poll would be wasteful.
pub(crate) enum VaultSlot {
    Locked(Vault),
    Unlocked(UnlockedVault),
}

/// Tauri-managed state (`tauri::State<AppState>`).
///
/// `slot` is `Mutex<Option<VaultSlot>>` rather than `Mutex<VaultSlot>` so commands that consume a
/// `Vault`/`UnlockedVault` by value (`Vault::create`/`join`/`unlock`, `UnlockedVault::lock`) can
/// `.take()` it out, operate, and put a new value back — including reopening a fresh `Locked`
/// slot via [`Self::reopen_locked`] if the consuming call itself errors (`Vault::create`/`join`/
/// `unlock` all consume `self` even on failure, so there is nothing to "give back" on the error
/// path other than a freshly reopened store).
///
/// `tokio::sync::Mutex` (not `std::sync::Mutex`) throughout: several commands hold the guard
/// across an `.await` (`UnlockedVault::add`/`open`/`sync` are all async), which is unsound with a
/// std mutex guard.
pub struct AppState {
    pub(crate) slot: Mutex<Option<VaultSlot>>,
    pub(crate) last_activity: Mutex<Instant>,
    pub(crate) auto_lock_minutes: Mutex<u32>,
    pub(crate) data_dir: PathBuf,
}

impl AppState {
    /// Opens the local store at `data_dir` (creating it if this is the first run) and loads the
    /// persisted auto-lock setting (`crate::config`), if any, defaulting to
    /// [`DEFAULT_AUTO_LOCK_MINUTES`] otherwise.
    ///
    /// # Errors
    /// [`AppError`] (mapped from [`scrigno_client::ClientError`]) if the local store can't be
    /// opened (corrupt file, permission error, disk full).
    pub(crate) fn open(data_dir: PathBuf) -> Result<Self, AppError> {
        let vault = Vault::open(&data_dir).map_err(AppError::from)?;
        let auto_lock_minutes = config::load(&data_dir)
            .map(|c| c.auto_lock_minutes)
            .unwrap_or(DEFAULT_AUTO_LOCK_MINUTES);
        Ok(Self {
            slot: Mutex::new(Some(VaultSlot::Locked(vault))),
            last_activity: Mutex::new(Instant::now()),
            auto_lock_minutes: Mutex::new(auto_lock_minutes),
            data_dir,
        })
    }

    /// Re-opens a fresh `Locked` slot over the same data dir. Used after a consuming call
    /// (`Vault::create`/`join`/`unlock`) fails and drops the `Vault` it took ownership of, so the
    /// state machine has something valid to put back instead of being left empty. `None` only in
    /// the (essentially unreachable in practice) case where even a fresh `Vault::open` fails
    /// immediately after a previous one succeeded on the same path — callers treat that as
    /// [`AppError::internal_state`] on the *next* command, since there is nothing better to do
    /// here without silently swallowing the error that caused the reopen in the first place.
    pub(crate) fn reopen_locked(&self) -> Option<VaultSlot> {
        Vault::open(&self.data_dir).ok().map(VaultSlot::Locked)
    }

    pub(crate) async fn touch_activity(&self) {
        *self.last_activity.lock().await = Instant::now();
    }
}

/// Spawns the inactivity auto-lock background task (`docs/CRYPTO.md §5.2`).
///
/// **Scope for M4 (desktop):** only the inactivity-timeout half is implemented — "MK is zeroized
/// from memory after 5 minutes of inactivity (configurable 1–30)". The other half of §5.2 ("and
/// whenever the app goes to background for more than 30 s") is mobile-specific (foreground/
/// background lifecycle events) and is explicitly deferred to M5; desktop has no equivalent
/// background/foreground signal, so faking it here would be a behaviour the UI can't act on
/// correctly.
///
/// Polls every [`AUTO_LOCK_POLL_INTERVAL`]; when elapsed inactivity meets or exceeds the
/// configured timeout, takes the `Unlocked` slot out, calls `.lock()` on it (zeroizing the master
/// key via `MasterKey`'s own `Drop`, inside `scrigno-client`), puts a `Locked` slot back, and
/// emits `vault-locked` to the frontend. A no-op every tick while already `Locked`/
/// `Uninitialised`.
pub(crate) fn spawn_auto_lock(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(AUTO_LOCK_POLL_INTERVAL).await;
            let state = app.state::<AppState>();

            let minutes = *state.auto_lock_minutes.lock().await;
            let elapsed = state.last_activity.lock().await.elapsed();
            if elapsed < Duration::from_secs(u64::from(minutes) * 60) {
                continue;
            }

            let mut guard = state.slot.lock().await;
            if !matches!(guard.as_ref(), Some(VaultSlot::Unlocked(_))) {
                continue;
            }
            let Some(VaultSlot::Unlocked(unlocked)) = guard.take() else {
                unreachable!("just matched Some(VaultSlot::Unlocked(_)) above");
            };
            *guard = Some(VaultSlot::Locked(unlocked.lock()));
            drop(guard);

            let _ = app.emit("vault-locked", ());
        }
    });
}
