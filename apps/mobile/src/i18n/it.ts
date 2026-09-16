// Italian UI strings. No user-facing text is hard-coded in components — see CLAUDE.md.
export const it = {
  appName: "Scrigno",
  vaultStatus: {
    // Mirrors the `vault_status` Tauri command's return values (docs/ARCHITECTURE.md §6).
    uninitialised: "non inizializzato",
    locked: "bloccato",
    unlocked: "sbloccato",
  },
} as const;
