//! Tauri command surface for Scrigno. See `docs/ARCHITECTURE.md` §6.
//!
//! Commands are thin: deserialize → call `scrigno_client::Vault`/`UnlockedVault` → map
//! `ClientError` to `AppError`. No business logic, no crypto, no SQL lives here — see
//! `commands.rs`. `state.rs` holds `AppState` (the vault slot + auto-lock timer),
//! `config.rs` persists the server URL/token locally (`docs/ARCHITECTURE.md §7`, a documented
//! deviation — see that module's docs), `types.rs`/`error.rs` are the `AppError`/`VaultStatus`/
//! `Settings` types shared with TS and the `ClientError` → `AppError` mapping.

mod commands;
mod config;
mod error;
mod state;
mod types;

use tauri::Manager;

use state::AppState;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    if let Err(err) = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            // Desktop-only data dir for M4; Android's own path resolution is M5.
            let data_dir = app.path().app_data_dir()?;
            let state = AppState::open(data_dir)?;
            app.manage(state);
            state::spawn_auto_lock(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::vault_status,
            commands::vault_create,
            commands::vault_join,
            commands::vault_unlock,
            commands::vault_unlock_quick,
            commands::vault_lock,
            commands::vault_add_recovery_code,
            commands::docs_list,
            commands::doc_thumb,
            commands::doc_get_meta,
            commands::doc_add_from_path,
            commands::doc_add_bytes,
            commands::doc_open,
            commands::doc_share,
            commands::doc_update_meta,
            commands::doc_set_keep_offline,
            commands::doc_delete,
            commands::sync_now,
            commands::settings_get,
            commands::settings_set,
        ])
        .run(tauri::generate_context!())
    {
        eprintln!("fatal: tauri application exited with an error: {err}");
        std::process::exit(1);
    }
}
