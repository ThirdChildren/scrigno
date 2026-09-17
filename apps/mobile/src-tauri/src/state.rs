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

/// `docs/CRYPTO.md §5.2`: "whenever the app goes to background for more than 30 s" (Android
/// only — see [`AppState::background_since`] and `crate::lifecycle`, which is the only thing
/// that ever sets this field; on desktop it stays `None` forever and this constant is dead
/// weight, not a behaviour change).
const BACKGROUND_LOCK_THRESHOLD: Duration = Duration::from_secs(30);

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
    /// Set by `crate::lifecycle` (Android only) when the app's main window loses focus, cleared
    /// when it regains focus; `None` means "currently foregrounded" (or, on desktop, "always" —
    /// nothing ever sets this field there). Read by [`spawn_auto_lock`] alongside
    /// `last_activity` — `docs/CRYPTO.md §5.2` treats "backgrounded > 30 s" and "5 minutes
    /// inactive" as two independent triggers for the same zeroize-MK action, so one poll loop
    /// checks both rather than running two near-identical tasks.
    pub(crate) background_since: Mutex<Option<Instant>>,
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
            background_since: Mutex::new(None),
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

/// Spawns the auto-lock background task (`docs/CRYPTO.md §5.2`): two independent triggers,
/// checked on every poll, either of which zeroizes the master key —
/// - **inactivity**: no command has touched `last_activity` for the configured 1–30 minute
///   timeout (desktop and mobile);
/// - **backgrounded** (mobile only, M5): the app's main window has been unfocused for more than
///   [`BACKGROUND_LOCK_THRESHOLD`] — `AppState::background_since` is only ever set by
///   `crate::lifecycle`'s window-focus handler (mobile-only, not compiled/registered on
///   desktop), so this is a genuine no-op on desktop: the field stays `None` forever there and
///   `backgrounded` below is always `false`.
///
/// Polls every [`AUTO_LOCK_POLL_INTERVAL`]; when either trigger fires, takes the `Unlocked` slot
/// out, calls `.lock()` on it (zeroizing the master key via `MasterKey`'s own `Drop`, inside
/// `scrigno-client`), puts a `Locked` slot back, and emits `vault-locked` to the frontend. A
/// no-op every tick while already `Locked`/`Uninitialised`.
///
/// This only ever drops the **in-memory** master key. It does not touch the Android quick-unlock
/// Stronghold snapshot (`crate::quick_unlock`) — by design, so a background/inactivity auto-lock
/// stays unlockable again via a biometric prompt; only the explicit "Blocca completamente" action
/// (`commands::vault_forget_quick_unlock`, called by the frontend alongside `vault_lock`) wipes
/// that.
pub(crate) fn spawn_auto_lock(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(AUTO_LOCK_POLL_INTERVAL).await;
            let state = app.state::<AppState>();

            let minutes = *state.auto_lock_minutes.lock().await;
            let inactive = state.last_activity.lock().await.elapsed()
                >= Duration::from_secs(u64::from(minutes) * 60);
            let backgrounded = state
                .background_since
                .lock()
                .await
                .map(|since| since.elapsed() >= BACKGROUND_LOCK_THRESHOLD)
                .unwrap_or(false);
            if !inactive && !backgrounded {
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
