//! Tauri command surface for Scrigno. See `docs/ARCHITECTURE.md` §6.
//!
//! M0: scaffold only, no commands yet.

// Path dependency on the client crate is wired up now so the Cargo graph is
// correct from M0 onward; real usage (`scrigno_client::Vault`) starts in M3.
use scrigno_client as _;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    if let Err(err) = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .run(tauri::generate_context!())
    {
        eprintln!("fatal: tauri application exited with an error: {err}");
        std::process::exit(1);
    }
}
