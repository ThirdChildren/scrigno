// Typed IPC wrappers, one per Tauri command (`docs/ARCHITECTURE.md §6`). Components never call
// `invoke()` directly — everything sensitive crosses through here so there is exactly one place
// that knows the command surface, the argument-casing rule below, and how binary responses become
// `Blob`s.
//
// Argument casing: `#[tauri::command]` defaults to `ArgumentCase::Camel` (verified against the
// vendored `tauri-macros` source, `rename_all` is not set on any command in `commands.rs`), so
// multi-word Rust parameter names must be sent camelCased from JS (`server_url` -> `serverUrl`,
// `keep_offline` -> `keepOffline`). Nested struct payloads (e.g. `Settings`) are unaffected: their
// field names are controlled by `serde::Deserialize` on the Rust struct, not this macro, and none
// of `Settings`'s fields carry a `#[serde(rename...)]`, so those stay snake_case as declared.
import { invoke } from "@tauri-apps/api/core";

import type { AppError } from "../bindings/AppError";
import type { DocMeta } from "../bindings/DocMeta";
import type { DocSummary } from "../bindings/DocSummary";
import type { Settings } from "../bindings/Settings";
import type { SyncReport } from "../bindings/SyncReport";
import type { VaultStatus } from "../bindings/VaultStatus";

export type { AppError, DocMeta, DocSummary, Settings, SyncReport, VaultStatus };

/** Narrows an `invoke()` rejection to the `{ code, message }` shape every command rejects with. */
export function isAppError(err: unknown): err is AppError {
  return (
    typeof err === "object" &&
    err !== null &&
    "code" in err &&
    typeof (err as { code: unknown }).code === "string"
  );
}

// ---------------------------------------------------------------- vault lifecycle -------------

export const vaultStatus = () => invoke<VaultStatus>("vault_status");

export const vaultCreate = (args: { serverUrl: string; token: string; passphrase: string }) =>
  invoke<void>("vault_create", args);

export const vaultJoin = (args: { serverUrl: string; token: string; passphrase: string }) =>
  invoke<void>("vault_join", args);

export const vaultUnlock = (args: { passphrase: string }) => invoke<void>("vault_unlock", args);

/**
 * `reason` is the Italian biometric-prompt text shown by the OS — this wrapper never hardcodes
 * it, the caller supplies it (`docs/ARCHITECTURE.md §6`). Always rejects with
 * `quick_unlock_unavailable` on desktop and on Android when quick unlock isn't enrolled; see
 * `AppError` codes `quick_unlock_reauth_required`/`biometric_failed` for the other Android
 * failure modes.
 */
export const vaultUnlockQuick = (reason: string) =>
  invoke<void>("vault_unlock_quick", { reason });

/**
 * Enrols quick unlock (`docs/CRYPTO.md §5.2`): re-confirms the passphrase and stores it behind
 * the Android device-secret-protected store. Requires the vault to already be unlocked in this
 * session. Android only; rejects with `quick_unlock_unavailable` on desktop.
 */
export const vaultEnableQuickUnlock = (passphrase: string) =>
  invoke<void>("vault_enable_quick_unlock", { passphrase });

/**
 * Un-enrols quick unlock (wipes the Android device secret + Stronghold snapshot). No-op
 * `Ok(())` on desktop. Callers implementing "Blocca completamente" must call this **alongside**
 * `vaultLock`, never `vaultLock` alone (`docs/ARCHITECTURE.md §6`).
 */
export const vaultForgetQuickUnlock = () => invoke<void>("vault_forget_quick_unlock");

export const vaultLock = () => invoke<void>("vault_lock");

/**
 * Returns the plaintext recovery code, shown exactly once. Callers must not persist it anywhere
 * (no `localStorage`, no query cache beyond the reveal screen's own component state) and must
 * discard it from state as soon as the reveal screen is dismissed.
 */
export const vaultAddRecoveryCode = () => invoke<string>("vault_add_recovery_code");

// ---------------------------------------------------------------- documents --------------------

export const docsList = () => invoke<DocSummary[]>("docs_list");

export const docGetMeta = (id: string) => invoke<DocMeta>("doc_get_meta", { id });

/**
 * JPEG bytes as a `Blob`, or `null` if the document has no thumbnail (empty response body —
 * `docs/ARCHITECTURE.md §6`). `doc_thumb` is a `tauri::ipc::Response` command, which resolves to
 * an `ArrayBuffer` in JS (Tauri 2's documented binary-response convention).
 */
export async function docThumb(id: string): Promise<Blob | null> {
  const buf = await invoke<ArrayBuffer>("doc_thumb", { id });
  if (!buf || buf.byteLength === 0) return null;
  return new Blob([buf], { type: "image/jpeg" });
}

/** Decrypted document bytes as a `Blob` of the given MIME type (from `DocMeta.mime`). */
export async function docOpen(id: string, mime: string): Promise<Blob> {
  const buf = await invoke<ArrayBuffer>("doc_open", { id });
  return new Blob([buf], { type: mime });
}

export const docAddFromPath = (args: {
  path: string;
  title: string;
  tags: string[];
  note: string;
}) => invoke<DocSummary>("doc_add_from_path", args);

export const docUpdateMeta = (args: {
  id: string;
  title: string;
  tags: string[];
  note: string;
}) => invoke<DocSummary>("doc_update_meta", args);

export const docSetKeepOffline = (args: { id: string; keepOffline: boolean }) =>
  invoke<void>("doc_set_keep_offline", args);

export const docDelete = (id: string) => invoke<void>("doc_delete", { id });

/**
 * Android only: writes a plaintext temp file and opens it via the OS "open with" picker,
 * deleting the file ~60 s later (`docs/ARCHITECTURE.md §6`). Rejects with `not_implemented` on
 * desktop — same as any other command failure, show the mapped Italian message.
 */
export const docShare = (id: string) => invoke<void>("doc_share", { id });

/**
 * Raw-bytes upload for the `<input type="file" capture>` flow (`docs/ARCHITECTURE.md §6`):
 * `doc_add_bytes` reads the metadata from the `x-scrigno-meta` header and the document body from
 * the raw request body, not from a JSON payload — this is the one command that does not go
 * through the usual `invoke(cmd, argsObject)` shape.
 */
export const docAddBytes = (args: {
  bytes: ArrayBuffer;
  title: string;
  tags: string[];
  note: string;
  mime: string;
  originalName: string;
}) => {
  const meta = JSON.stringify({
    title: args.title,
    tags: args.tags,
    note: args.note,
    mime: args.mime,
    original_name: args.originalName,
  });
  return invoke<DocSummary>("doc_add_bytes", args.bytes, {
    headers: { "x-scrigno-meta": meta },
  });
};

// ---------------------------------------------------------------- sync -------------------------

export const syncNow = () => invoke<SyncReport>("sync_now");

// ---------------------------------------------------------------- settings ---------------------

export const settingsGet = () => invoke<Settings>("settings_get");

export const settingsSet = (settings: Settings) =>
  invoke<Settings>("settings_set", { settings });
