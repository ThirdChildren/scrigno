//! Quick unlock (`docs/CRYPTO.md §5.2`) — Android only, this whole module is `#[cfg(mobile)]`.
//!
//! # Which option of `CRYPTO.md §5.2` this implements, and why
//!
//! `CRYPTO.md` lists two places for the "device secret" that protects the Stronghold snapshot:
//! 1. Android Keystore-backed key, `setUserAuthenticationRequired(true)`, unlockable only after
//!    a successful biometric check *at the hardware/OS level*.
//! 2. Fallback: device secret in an app-private file with restrictive permissions; the biometric
//!    prompt is then UX gating only.
//!
//! Checked against `tauri-plugin-biometric` 2.3's own docs/source (`docs.rs`, the plugin
//! workspace on GitHub) as of this milestone: it exposes exactly one operation,
//! `Biometric::authenticate(reason, options) -> Result<()>`, a yes/no prompt with no
//! `CryptoObject`/Android Keystore integration of any kind. Option 1 is not reachable without
//! writing a small custom Kotlin plugin (a Keystore key created with a `KeyGenParameterSpec` that
//! sets `setUserAuthenticationRequired(true)`, and a `BiometricPrompt.CryptoObject` wrapping
//! it — `androidx.biometric` + `java.security.KeyStore("AndroidKeyStore")` on the native side).
//! **`TODO(m5)`: that plugin doesn't exist yet; this module implements option 2** and the
//! biometric prompt below is documented UX gating only, per `CRYPTO.md`'s own requirement to
//! disclose that in the app's settings screen — `frontend-ui` must surface this (see this
//! milestone's report).
//!
//! # What is actually stored in Stronghold, and why it's the passphrase and not the raw MK
//!
//! `CRYPTO.md §5.2` says "MK is stored in a Stronghold snapshot". `scrigno-client`'s public API
//! has no entry point that turns a raw master key back into an [`scrigno_client::UnlockedVault`]:
//! [`scrigno_client::Vault::unlock`] only accepts a passphrase (it re-derives the KEK from the
//! locally-stored keyslot, unwraps MK, and rebuilds the in-memory document index from
//! `enc_meta` — none of that is skippable from outside the crate), and `UnlockedVault`'s fields
//! are private. Adding an MK-based unlock entry point is a `scrigno-client` change
//! (`crates/scrigno-client` is `sync-client`'s area, out of scope for `tauri-mobile`).
//!
//! Until that lands, this module stores the **passphrase** itself inside the Stronghold-protected
//! store and calls the existing `Vault::unlock` with it — the same "a device secret gates access
//! to something that unwraps the vault" shape `CRYPTO.md` describes, just a different secret
//! behind that gate. The protection level is the same class as storing the MK would be (both are
//! encrypted at rest under Argon2id-derived-from-the-device-secret via Stronghold's snapshot
//! format, and both are only as safe as the device-secret file); the passphrase additionally lets
//! whoever reads it re-derive the KEK directly rather than needing the wrapped-MK keyslot too,
//! which the MK alone would not. **Flagged for `crypto-reviewer` and `sync-client`**: see this
//! milestone's report. `TODO(m5)`: once `scrigno-client` exposes an MK-based unlock entry point,
//! switch this module to store raw MK bytes instead and drop the passphrase-in-Stronghold design.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::rngs::OsRng;
use rand::TryRngCore;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tauri_plugin_stronghold::stronghold::Stronghold;
use zeroize::Zeroize;

use crate::types::AppError;

/// App-private file holding the 32-byte random device secret (`CRYPTO.md §5.2` option 2:
/// "device secret in an app-private file with restrictive permissions"). Android's own
/// per-app-UID sandboxing already keeps `app_data_dir` private to this app; the `0600`
/// permissions set atomically at creation in [`write_new_restricted`] are defence in depth,
/// matching `config.rs`'s precedent for the token file.
const DEVICE_SECRET_FILE: &str = "quick_unlock_secret";
/// `CRYPTO.md §5.2`: "MK is stored in a Stronghold snapshot (`tauri-plugin-stronghold`) at
/// `<app_data_dir>/vault.stronghold`" — same path, see the module docs above for what is
/// actually stored in it this milestone.
const STRONGHOLD_FILE: &str = "vault.stronghold";
/// Non-secret quick-unlock bookkeeping (last passphrase auth timestamp, failed biometric attempt
/// count) — plain JSON, not part of the Stronghold snapshot.
const META_FILE: &str = "quick_unlock.json";
const STRONGHOLD_CLIENT: &[u8] = b"scrigno-quick-unlock";
const STORE_KEY_PASSPHRASE: &str = "passphrase";

/// `CRYPTO.md §5.2`: "Re-authentication with the passphrase is required: after 7 days...".
const REAUTH_MAX_AGE_SECS: u64 = 7 * 24 * 3600;
/// `CRYPTO.md §5.2`: "...after 5 failed biometric attempts".
const MAX_FAILED_ATTEMPTS: u32 = 5;

fn device_secret_path(data_dir: &Path) -> PathBuf {
    data_dir.join(DEVICE_SECRET_FILE)
}

fn stronghold_path(data_dir: &Path) -> PathBuf {
    data_dir.join(STRONGHOLD_FILE)
}

fn meta_path(data_dir: &Path) -> PathBuf {
    data_dir.join(META_FILE)
}

/// Deliberately **not** `#[derive(Debug)]`: nothing sensitive lives here (a count and a Unix
/// timestamp), but there is no reason to make a stray `{:?}` easy either — matches this crate's
/// convention for anything persisted (`config::AppConfig`).
#[derive(Default, Serialize, Deserialize)]
struct QuickUnlockMeta {
    #[serde(default)]
    last_passphrase_auth_unix: Option<u64>,
    #[serde(default)]
    failed_biometric_attempts: u32,
}

fn load_meta(data_dir: &Path) -> QuickUnlockMeta {
    std::fs::read(meta_path(data_dir))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn save_meta(data_dir: &Path, meta: &QuickUnlockMeta) -> Result<(), AppError> {
    let bytes = serde_json::to_vec(meta).map_err(|_| AppError::config_error())?;
    std::fs::write(meta_path(data_dir), bytes).map_err(|_| AppError::config_error())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Reads the existing device secret, or generates and persists a fresh 32-byte random one
/// (`rand::rngs::OsRng`, matching `CLAUDE.md`'s "Randomness: `OsRng` only").
fn load_or_create_device_secret(data_dir: &Path) -> Result<Vec<u8>, AppError> {
    let path = device_secret_path(data_dir);
    if let Ok(bytes) = std::fs::read(&path) {
        if bytes.len() == 32 {
            return Ok(bytes);
        }
    }
    let mut secret = vec![0u8; 32];
    // `rand_core` 0.9's `OsRng` only implements the fallible `TryRngCore` (it can, in principle,
    // fail early in boot or on a misconfigured system) — not the infallible `RngCore`.
    OsRng
        .try_fill_bytes(&mut secret)
        .map_err(|_| AppError::config_error())?;
    write_new_restricted(&path, &secret)?;
    Ok(secret)
}

/// Creates `path` at mode `0600` atomically (the `open` call itself carries the mode, so there is
/// no window between file creation and permission-tightening for another process/app on the same
/// device to read it) and writes `contents` to it. Replaces the previous `std::fs::write` +
/// `restrict` two-step, which briefly left the file at the default/umask permissions.
#[cfg(unix)]
fn write_new_restricted(path: &Path, contents: &[u8]) -> Result<(), AppError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| AppError::config_error())?;
    file.write_all(contents)
        .map_err(|_| AppError::config_error())
}

#[cfg(not(unix))]
fn write_new_restricted(path: &Path, contents: &[u8]) -> Result<(), AppError> {
    std::fs::write(path, contents).map_err(|_| AppError::config_error())
}

/// Opens (or creates, if this is the first enrolment) the Stronghold snapshot at
/// `<data_dir>/vault.stronghold`, keyed by `device_secret`. Every call reloads the snapshot from
/// disk fresh — `tauri_plugin_stronghold::stronghold::Stronghold` holds no state across calls in
/// this module (no long-lived managed state, unlike the plugin's own JS-facing command surface,
/// which we deliberately don't register — see the module docs).
fn open_stronghold(data_dir: &Path, device_secret: Vec<u8>) -> Result<Stronghold, AppError> {
    Stronghold::new(stronghold_path(data_dir), device_secret).map_err(|_| AppError::config_error())
}

/// `true` once [`enable`] has run and hasn't since been undone by [`forget`] (a full 7-day/
/// 5-failed-attempt expiry also calls `forget`, so this doubles as "still valid" — [`load_passphrase`]
/// still checks the actual expiry before trusting it, since a check-then-act race here is
/// harmless: worst case one extra, cheap Stronghold open that then fails).
pub(crate) fn is_enabled(data_dir: &Path) -> bool {
    device_secret_path(data_dir).exists() && stronghold_path(data_dir).exists()
}

/// Enrols quick unlock: stores `passphrase` in the Stronghold snapshot (creating it if this is
/// the first time) and resets the 7-day/failed-attempt counters. Called from
/// `commands::vault_enable_quick_unlock`, which requires the vault to already be unlocked in this
/// session — but the plaintext passphrase itself is only ever available transiently as a command
/// argument (never retained across calls), so the frontend must ask the user to type it again to
/// enrol, even though the vault is already open. That's a deliberate re-confirmation, not an
/// oversight.
pub(crate) fn enable(data_dir: &Path, passphrase: &SecretString) -> Result<(), AppError> {
    let secret = load_or_create_device_secret(data_dir)?;
    let stronghold = open_stronghold(data_dir, secret)?;
    let client = stronghold
        .create_client(STRONGHOLD_CLIENT.to_vec())
        .or_else(|_| stronghold.load_client(STRONGHOLD_CLIENT.to_vec()))
        .map_err(|_| AppError::config_error())?;

    let mut bytes = passphrase.expose_secret().as_bytes().to_vec();
    let insert_result = client
        .store()
        .insert(
            STORE_KEY_PASSPHRASE.as_bytes().to_vec(),
            bytes.clone(),
            None,
        )
        .map(|_| ())
        .map_err(|_| AppError::config_error());
    bytes.zeroize();
    insert_result?;

    stronghold.save().map_err(|_| AppError::config_error())?;
    record_passphrase_auth(data_dir)
}

/// Records that a real passphrase authentication just happened: resets the 7-day re-auth window
/// and the failed-biometric-attempt counter. Called from `commands::vault_unlock`/`vault_create`/
/// `vault_join` on mobile on every success (regardless of whether quick unlock is enabled yet) so
/// the window is already correct the moment the user later opts in.
pub(crate) fn record_passphrase_auth(data_dir: &Path) -> Result<(), AppError> {
    let mut meta = load_meta(data_dir);
    meta.last_passphrase_auth_unix = Some(now_unix());
    meta.failed_biometric_attempts = 0;
    save_meta(data_dir, &meta)
}

/// Wipes the device secret, the Stronghold snapshot and the bookkeeping file — quick unlock is
/// unavailable until [`enable`] runs again from a full passphrase unlock. Idempotent (a missing
/// file is not an error).
///
/// Distinct on purpose from `commands::vault_lock`, which only zeroizes the in-memory master key
/// (`state::AppState`): dropping just that would leave the Stronghold-persisted passphrase
/// readable by the next biometric prompt, defeating "Blocca completamente"'s intent
/// (`CRYPTO.md §5.2`: re-auth with the passphrase is required after that action). `frontend-ui`
/// must wire "Blocca completamente" to call **both** `vault_lock` and
/// `vault_forget_quick_unlock` — see this milestone's report.
pub(crate) fn forget(data_dir: &Path) -> Result<(), AppError> {
    let _ = std::fs::remove_file(device_secret_path(data_dir));
    let _ = std::fs::remove_file(stronghold_path(data_dir));
    let _ = std::fs::remove_file(meta_path(data_dir));
    Ok(())
}

/// Reads the stored passphrase back out, after checking the re-auth triggers that don't involve
/// the biometric prompt itself (time, attempt count). Reinstall is covered implicitly: a fresh
/// install has no `quick_unlock_secret`/`vault.stronghold` files, so [`is_enabled`] is already
/// `false` and this returns [`AppError::quick_unlock_unavailable`] before touching anything else.
///
/// The biometric prompt is the caller's responsibility (`commands::vault_unlock_quick`) — this
/// function only gates on state already on disk and performs the Stronghold read.
pub(crate) fn load_passphrase(data_dir: &Path) -> Result<SecretString, AppError> {
    if !is_enabled(data_dir) {
        return Err(AppError::quick_unlock_unavailable());
    }

    let meta = load_meta(data_dir);
    let age_ok = meta
        .last_passphrase_auth_unix
        .map(|t| now_unix().saturating_sub(t) < REAUTH_MAX_AGE_SECS)
        .unwrap_or(false);
    if !age_ok || meta.failed_biometric_attempts >= MAX_FAILED_ATTEMPTS {
        forget(data_dir)?;
        return Err(AppError::quick_unlock_reauth_required());
    }

    let secret = load_or_create_device_secret(data_dir)?;
    let stronghold = open_stronghold(data_dir, secret)?;
    let client = stronghold
        .load_client(STRONGHOLD_CLIENT.to_vec())
        .map_err(|_| AppError::quick_unlock_unavailable())?;
    let mut bytes = client
        .store()
        .get(STORE_KEY_PASSPHRASE.as_bytes())
        .map_err(|_| AppError::quick_unlock_unavailable())?
        .ok_or_else(AppError::quick_unlock_unavailable)?;

    // Validate with `str::from_utf8` (borrows `bytes`, no clone) so the only copy of the
    // passphrase bytes is `bytes` itself, which is always zeroized below regardless of outcome —
    // `String::from_utf8` on a clone would leave a second, un-zeroized copy inside the
    // `FromUtf8Error` on the invalid-UTF-8 path.
    let passphrase = match std::str::from_utf8(&bytes) {
        Ok(s) => Ok(s.to_owned()),
        Err(_) => Err(AppError::quick_unlock_unavailable()),
    };
    bytes.zeroize();
    Ok(SecretString::from(passphrase?))
}

/// Records one failed biometric prompt; wipes quick unlock entirely once
/// [`MAX_FAILED_ATTEMPTS`] is reached (`CRYPTO.md §5.2`). Best-effort: a failure to persist the
/// counter is swallowed by the caller (`commands::vault_unlock_quick`) rather than surfaced,
/// since the biometric failure itself is already the error the user sees.
pub(crate) fn record_failed_biometric_attempt(data_dir: &Path) -> Result<(), AppError> {
    let mut meta = load_meta(data_dir);
    meta.failed_biometric_attempts += 1;
    let attempts = meta.failed_biometric_attempts;
    save_meta(data_dir, &meta)?;
    if attempts >= MAX_FAILED_ATTEMPTS {
        forget(data_dir)?;
    }
    Ok(())
}
