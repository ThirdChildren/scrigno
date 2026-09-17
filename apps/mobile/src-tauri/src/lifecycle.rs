//! Android foreground/background lifecycle (`docs/CRYPTO.md §5.2`, `docs/ROADMAP.md` M5):
//! "lock on background > 30 s, sync on foreground". Entirely `#[cfg(mobile)]` — desktop has no
//! equivalent signal and none of this is registered there (see `lib.rs`'s `setup`).
//!
//! # How background/foreground is detected
//!
//! Tauri 2's generic `RunEvent` has no documented Android-specific "app paused"/"app resumed"
//! variant at the time of writing (checked `docs.rs`/`v2.tauri.app` for this milestone — neither
//! covers it). What Tauri *does* document, cross-platform, is
//! [`tauri::WindowEvent::Focused(bool)`], and losing/gaining focus on the single main window is
//! the commonly used proxy for backgrounding on Android in the Tauri community (there is no
//! second window competing for focus in this app, so "unfocused" reliably means "not the
//! foreground app" rather than "a dialog opened"). **This is a judgment call, not something
//! verified on a device or emulator in this environment** (no AVD/hardware acceleration, no
//! physical phone attached — see this milestone's report) — flagged for manual verification on
//! the owner's phone before relying on it.
//!
//! # Who triggers what
//!
//! - Losing focus records `Instant::now()` into `AppState::background_since`;
//!   `state::spawn_auto_lock`'s existing poll loop is the thing that actually zeroizes the master
//!   key once 30 s have passed — this module only ever *records*, it never locks directly, so
//!   there is exactly one place (`spawn_auto_lock`) that emits `vault-locked` and touches the
//!   vault slot's `Mutex`.
//! - Gaining focus clears `background_since` and, if the vault is currently unlocked, calls
//!   `commands::sync_now` directly (Rust owns this trigger, not an event the frontend has to
//!   listen for and act on — one less thing `frontend-ui` needs to wire up, and it reuses the
//!   exact same thin command the manual "sync now" UI action already calls, including its
//!   `sync-progress` events). If the vault is locked, there is nothing to sync yet; the frontend
//!   already triggers a sync after every successful unlock (unchanged from M4).

use std::time::Instant;

use tauri::{AppHandle, Manager};

use crate::commands;
use crate::state::{AppState, VaultSlot};

pub(crate) fn register(app: &tauri::App) {
    let Some(window) = app.get_webview_window("main") else {
        // Should not happen (the main window is declared in `tauri.conf.json`), but a missing
        // window is not a reason to fail startup over a lifecycle nicety.
        return;
    };
    let handle = app.handle().clone();

    window.on_window_event(move |event| {
        let tauri::WindowEvent::Focused(focused) = event else {
            return;
        };
        let handle = handle.clone();
        let focused = *focused;
        tauri::async_runtime::spawn(async move { on_focus_changed(handle, focused).await });
    });
}

async fn on_focus_changed(app: AppHandle, focused: bool) {
    let state = app.state::<AppState>();

    if !focused {
        *state.background_since.lock().await = Some(Instant::now());
        return;
    }

    *state.background_since.lock().await = None;

    let is_unlocked = {
        let guard = state.slot.lock().await;
        matches!(guard.as_ref(), Some(VaultSlot::Unlocked(_)))
    };
    if is_unlocked {
        // Best-effort: a foreground sync failing (offline, server down) is not a reason to
        // surface an error dialog the user didn't ask for — the sync banner already shows the
        // last successful sync time, and the next manual/foreground sync will retry.
        let _ = commands::sync_now(app.clone(), app.state::<AppState>()).await;
    }
}
