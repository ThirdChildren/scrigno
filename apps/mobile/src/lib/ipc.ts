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

/** Feature-detected by the caller (`docs/ROADMAP.md` M4: desktop has no quick unlock yet). */
export const vaultUnlockQuick = () => invoke<void>("vault_unlock_quick");

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

// ---------------------------------------------------------------- sync -------------------------

export const syncNow = () => invoke<SyncReport>("sync_now");

// ---------------------------------------------------------------- settings ---------------------

export const settingsGet = () => invoke<Settings>("settings_get");

export const settingsSet = (settings: Settings) =>
  invoke<Settings>("settings_set", { settings });
