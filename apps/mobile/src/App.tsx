import { it } from "./i18n/it";

function App() {
  // M0 scaffold: vault status is hard-coded. It will come from the
  // `vault_status` Tauri command starting M1 (docs/ARCHITECTURE.md §6).
  const vaultStatus: "uninitialised" | "locked" | "unlocked" = "uninitialised";

  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-4 bg-neutral-950 text-neutral-100">
      <h1 className="text-4xl font-semibold">{it.appName}</h1>
      <p className="text-neutral-400">{it.vaultStatus[vaultStatus]}</p>
    </main>
  );
}

export default App;
